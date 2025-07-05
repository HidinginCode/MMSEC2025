import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import socket
import os
import ipaddress
from collections import defaultdict
from tqdm import tqdm

# ------------------ KONFIGURATION -------------------
PCAP_FILE = '../Browsers/Ungoogled_Chromium/Network/UG-Chromium-UBlock-10min.pcapng'
HOST_IPV4 = '192.168.178.109'
HOST_IPV6 = '2003:d2:bf2b:dd00:a1b4:2082:a669:c5cb'
ANALYSIS_NAME = 'ungoogled-chromium-ublock'
MAX_PACKETS = None

OUTPUT_DIR = os.path.join('../analysis', ANALYSIS_NAME)

HOME_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('fd00::/8'),
    ipaddress.ip_network('fe80::/10')
]
# ----------------------------------------------------

def is_home_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in HOME_NETWORKS)
    except ValueError:
        return False

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def analyze_packets(capture, ip_version, local_host_ip, hostname_map):
    recv_counts = defaultdict(int)
    sent_counts = defaultdict(int)
    proto_per_ip = defaultdict(lambda: defaultdict(int))
    ip_set = set()

    for pkt in tqdm(capture, desc=f"Analysiere {ip_version.upper()}"):
        try:
            if ip_version == 'ipv4' and hasattr(pkt, 'ip'):
                src = pkt.ip.src
                dst = pkt.ip.dst
            elif ip_version == 'ipv6' and hasattr(pkt, 'ipv6'):
                src = pkt.ipv6.src
                dst = pkt.ipv6.dst
            else:
                continue

            if local_host_ip not in (src, dst):
                continue

            other_ip = dst if src == local_host_ip else src
            if is_home_ip(other_ip):
                continue

            proto = pkt.highest_layer
            sent_counts[src] += 1
            recv_counts[dst] += 1
            proto_per_ip[src][proto] += 1
            proto_per_ip[dst][proto] += 1
            ip_set.add(other_ip)

            # DNS-Antworten mitschneiden
            if 'DNS' in pkt:
                dns = pkt.dns
                if hasattr(dns, 'a') and hasattr(dns, 'qry_name'):
                    hostname_map[dns.a] = dns.qry_name
                if hasattr(dns, 'aaaa') and hasattr(dns, 'qry_name'):
                    hostname_map[dns.aaaa] = dns.qry_name

        except AttributeError:
            continue

    return recv_counts, sent_counts, proto_per_ip, ip_set

def make_label(ip, host_ip, hostname_map):
    if ip == host_ip:
        return f"*HOST* {ip}"
    label = hostname_map.get(ip)
    if not label:
        label = resolve_hostname(ip)
    if not label:
        return ip
    return f"{label} ({ip})"

def plot_pie(data_dict, title, filename, host_ip, hostname_map):
    if not data_dict:
        return
    df = pd.DataFrame(data_dict.items(), columns=['IP', 'Anzahl'])
    df = df.sort_values(by='Anzahl', ascending=False)
    labels = [make_label(ip, host_ip, hostname_map) for ip in df['IP']]
    plt.figure(figsize=(16, 8))
    plt.pie(df['Anzahl'], labels=labels, autopct='%1.1f%%')
    plt.title(title)
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def plot_stacked_bar(recv, sent, filename, host_ip, hostname_map):
    if not recv:
        return
    ips = list(recv.keys())
    labels = [make_label(ip, host_ip, hostname_map) for ip in ips]
    recv_vals = [recv[ip] for ip in ips]
    sent_vals = [sent.get(ip, 0) for ip in ips]
    plt.figure(figsize=(16, 8))
    x = range(len(ips))
    plt.bar(x, recv_vals, label='Empfangen')
    plt.bar(x, sent_vals, bottom=recv_vals, label='Gesendet')
    plt.xticks(x, labels, rotation=45, ha='right', fontsize=8)
    plt.legend()
    plt.title('Paketanzahl pro IP')
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def plot_protocols(proto_per_ip, filename, host_ip, hostname_map):
    if not proto_per_ip:
        return
    all_protocols = sorted(set(p for ip in proto_per_ip for p in proto_per_ip[ip]))
    ips = list(proto_per_ip.keys())
    labels = [make_label(ip, host_ip, hostname_map) for ip in ips]
    bottom = defaultdict(int)
    plt.figure(figsize=(16, 8))
    for proto in all_protocols:
        heights = [proto_per_ip[ip].get(proto, 0) for ip in ips]
        plt.bar(labels, heights, bottom=[bottom[ip] for ip in ips], label=proto)
        for i, h in enumerate(heights):
            bottom[ips[i]] += h
    plt.xticks(rotation=45, ha='right', fontsize=8)
    plt.legend()
    plt.title('Protokollverwendung pro IP')
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def export_cname_table(ip_set, recv_counts, sent_counts, filename, hostname_map):
    cname_data = []
    for ip in tqdm(ip_set, desc="Reverse DNS"):
        hostname = hostname_map.get(ip) or resolve_hostname(ip)
        cname_data.append({
            'IP': ip,
            'CNAME': hostname,
            'Gesendet': sent_counts.get(ip, 0),
            'Empfangen': recv_counts.get(ip, 0)
        })
    df = pd.DataFrame(cname_data)
    df.to_csv(filename, index=False)

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("[*] Lade PCAP-Datei...")
    cap = pyshark.FileCapture(PCAP_FILE, only_summaries=False)
    if MAX_PACKETS:
        cap = list(cap)[:MAX_PACKETS]

    cap_ipv4 = (pkt for pkt in cap if hasattr(pkt, 'ip'))
    cap_ipv6 = (pkt for pkt in cap if hasattr(pkt, 'ipv6'))

    hostname_map = {}

    runs = [
        ('ipv4', cap_ipv4, HOST_IPV4),
        ('ipv6', cap_ipv6, HOST_IPV6)
    ]

    for version, stream, host_ip in runs:
        if not host_ip:
            continue
        recv, sent, proto, ip_set = analyze_packets(stream, version, host_ip, hostname_map)
        suffix = f"_{version}"
        plot_pie({ip: recv[ip] for ip in ip_set}, f'Empfangene Pakete ({version.upper()})',
                 os.path.join(OUTPUT_DIR, f'empfangene_pakete{suffix}.png'), host_ip, hostname_map)
        plot_pie({ip: sent[ip] for ip in ip_set}, f'Gesendete Pakete ({version.upper()})',
                 os.path.join(OUTPUT_DIR, f'gesendete_pakete{suffix}.png'), host_ip, hostname_map)
        plot_stacked_bar(recv, sent, os.path.join(OUTPUT_DIR, f'paketanzahl_pro_ip{suffix}.png'),
                         host_ip, hostname_map)
        plot_protocols(proto, os.path.join(OUTPUT_DIR, f'protokolle_pro_ip{suffix}.png'),
                       host_ip, hostname_map)
        export_cname_table(ip_set, recv, sent,
                           os.path.join(OUTPUT_DIR, f'ip_cname_tabelle{suffix}.csv'),
                           hostname_map)

    print(f"Analyse abgeschlossen. Ergebnisse gespeichert in: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
