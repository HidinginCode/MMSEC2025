import pyshark
import socket
import ipaddress
from collections import Counter, defaultdict

# === KONFIGURATION ===
pcap_file = 'chromium-10min.pcapng'
home_networks = ['192.168.0.0/16', '10.0.0.0/8', 'fd00::/8']  # Heimnetzwerke

# === FUNKTIONEN ===
def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in home_networks:
            if ip_obj in ipaddress.ip_network(net):
                return True
    except ValueError:
        pass
    return False

def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def analyze_pcap(pcap_path):
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    stats = {
        'ipv4_packets': 0,
        'ipv6_packets': 0,
        'protocols': Counter(),
        'external_ips': Counter(),
    }
    resolved_hosts = {}

    for pkt in cap:
        try:
            if 'IP' in pkt:
                stats['ipv4_packets'] += 1
                src = pkt.ip.src
                dst = pkt.ip.dst
            elif 'IPv6' in pkt:
                stats['ipv6_packets'] += 1
                src = pkt.ipv6.src
                dst = pkt.ipv6.dst
            else:
                continue

            proto = pkt.highest_layer
            stats['protocols'][proto] += 1

            for ip in [src, dst]:
                if not is_private_ip(ip):
                    stats['external_ips'][ip] += 1
                    if ip not in resolved_hosts:
                        resolved_hosts[ip] = resolve_ip(ip)

        except AttributeError:
            continue

    return stats, resolved_hosts

def print_stats(stats, resolved):
    print("Netzwerkstatistik:")
    print(f"IPv4-Pakete: {stats['ipv4_packets']}")
    print(f"IPv6-Pakete: {stats['ipv6_packets']}")
    print("\n🔝 Top-Protokolle:")
    for proto, count in stats['protocols'].most_common(10):
        print(f"  {proto}: {count} Pakete")

    print("\n🌍 Externe IP-Adressen (Top 10):")
    for ip, count in stats['external_ips'].most_common(10):
        resolved_name = resolved[ip] or 'Unbekannt'
        print(f"  {ip} ({resolved_name}): {count} Pakete")

# === AUSFÜHRUNG ===
if __name__ == '__main__':
    stats, resolved = analyze_pcap(pcap_file)
    print_stats(stats, resolved)