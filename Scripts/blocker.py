import pyshark
import subprocess
import os
import csv
import getpass
import socket
import ipaddress
import json
from datetime import datetime

BLOCKLIST_FILE = 'blocklist.csv'
OPENSNITCH_EXPORT_FILE = 'opensnitch_blocklist.json'
INTERFACE = 'enp0s3'

sudo_password = None
opensnitch_rules = []

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    finally:
        s.close()

WHITELIST_IPS = {
    get_local_ip(), "127.0.0.1", "::1"
}

INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

CLOUDFLARE_NETS = [
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("131.0.72.0/22"),
    ipaddress.ip_network("2400:cb00::/32"),
    ipaddress.ip_network("2606:4700::/32"),
    ipaddress.ip_network("2803:f800::/32"),
    ipaddress.ip_network("2405:b500::/32"),
    ipaddress.ip_network("2405:8100::/32"),
    ipaddress.ip_network("2a06:98c0::/29"),
    ipaddress.ip_network("2c0f:f248::/32")
]

def is_in_allowed_ranges(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in INTERNAL_NETS + CLOUDFLARE_NETS:
            if ip in net:
                return True
    except ValueError:
        pass
    return False

def start_chromium():
    chrome_cmd = "/usr/local/bin/chrome --ssl-version-max=tls1.2"
    print(f"[+] Starte Chromium: {chrome_cmd}")
    subprocess.Popen(chrome_cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def init_blocklist_csv():
    if not os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, 'w', newline='') as f:
            csv.writer(f).writerow(['Zeitstempel', 'Quell-IP', 'Protokoll'])

def is_ip_already_blocked(ip):
    if not os.path.exists(BLOCKLIST_FILE):
        return False
    with open(BLOCKLIST_FILE, 'r') as f:
        return ip in f.read()

def log_blocked_ip(ip, reason):
    if not is_ip_already_blocked(ip):
        with open(BLOCKLIST_FILE, 'a', newline='') as f:
            csv.writer(f).writerow([datetime.now().isoformat(), ip, reason])

def add_opensnitch_rule(ip, reason):
    global opensnitch_rules
    if any(rule.get("value") == ip for rule in opensnitch_rules):
        return
    rule = {
        "name": f"Block {ip}",
        "enabled": True,
        "action": "deny",
        "duration": "always",
        "operator": "equal",
        "field": "dst.ip",
        "value": ip,
        "protocol": "any",
        "log": True,
        "description": f"Automatisch geblockt: {reason}"
    }
    opensnitch_rules.append(rule)

def export_opensnitch_rules():
    if not opensnitch_rules:
        return
    with open(OPENSNITCH_EXPORT_FILE, 'w') as f:
        json.dump(opensnitch_rules, f, indent=4)
    print(f"[+] OpenSnitch-Regeln exportiert nach: {OPENSNITCH_EXPORT_FILE}")

def block_ip(ip, reason, is_ipv6=False):
    if ip in WHITELIST_IPS or is_in_allowed_ranges(ip):
        print(f"[ALLOW   - TRUSTED] {ip} ({'IPv6' if is_ipv6 else 'IPv4'})")
        return

    tool = 'ip6tables' if is_ipv6 else 'iptables'
    check_cmd = ['sudo', '-S', tool, '-C', 'INPUT', '-s', ip, '-j', 'DROP']
    add_cmd = ['sudo', '-S', tool, '-A', 'INPUT', '-s', ip, '-j', 'DROP']

    try:
        check = subprocess.run(check_cmd, input=sudo_password + '\n', text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check.returncode == 0:
            print(f"[SKIP    - ALREADY BLOCKED] {ip} ({'IPv6' if is_ipv6 else 'IPv4'})")
            return

        print(f"[BLOCKED - {reason}] {ip} ({'IPv6' if is_ipv6 else 'IPv4'})")
        add = subprocess.run(add_cmd, input=sudo_password + '\n', text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if add.returncode == 0:
            log_blocked_ip(ip, reason)
            add_opensnitch_rule(ip, reason)
        else:
            print(f"[ERROR] {tool} fehlgeschlagen: {add.stderr.strip()}")
    except Exception as e:
        print(f"[ERROR] Ausnahme beim Blockieren: {e}")

def detect_and_block():
    print(f"[+] Starte Paketmitschnitt auf Schnittstelle: {INTERFACE}")
    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        display_filter=(
            'tcp.flags.syn == 1 and tcp.flags.ack == 0 or '
            'tls.handshake.type == 1 or '
            'tls.record.content_type == 23 or '
            'udp.port == 443 or '
            'icmpv6'
        )
    )

    start_chromium()

    try:
        for packet in capture.sniff_continuously():
            try:
                if 'IP' in packet:
                    src_ip = packet.ip.src
                    ip_version = "IPv4"
                    is_ipv6 = False
                elif 'IPv6' in packet:
                    src_ip = packet.ipv6.src
                    ip_version = "IPv6"
                    is_ipv6 = True
                else:
                    continue

                if src_ip in WHITELIST_IPS or is_in_allowed_ranges(src_ip):
                    print(f"[ALLOW   - TRUSTED] {src_ip} ({ip_version})")
                    continue

                if 'TCP' in packet and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                    block_ip(src_ip, "TCP SYN", is_ipv6)

                elif 'TLS' in packet:
                    if hasattr(packet.tls, 'handshake_type') and packet.tls.handshake_type == '1':
                        block_ip(src_ip, "TLS ClientHello", is_ipv6)
                    elif hasattr(packet.tls, 'record_content_type') and packet.tls.record_content_type == '23':
                        block_ip(src_ip, "TLS Application Data", is_ipv6)

                elif 'UDP' in packet and (packet.udp.dstport == '443' or packet.udp.srcport == '443'):
                    block_ip(src_ip, "QUIC UDP 443", is_ipv6)

                elif 'ICMPv6' in packet:
                    icmp_type = int(packet.icmpv6.type)
                    if icmp_type in (135, 136):
                        print(f"[ALLOW   - ICMPv6 ND {icmp_type}] {src_ip} ({ip_version})")
                        continue
                    block_ip(src_ip, f"ICMPv6 Typ {icmp_type}", is_ipv6)

                else:
                    print(f"[ALLOW   - OTHER] {src_ip} ({ip_version})")

            except AttributeError:
                continue
    except KeyboardInterrupt:
        print("\n[!] Mitschnitt beendet.")
        export_opensnitch_rules()

if __name__ == "__main__":
    sudo_password = getpass.getpass("Bitte sudo-Passwort eingeben: ")
    init_blocklist_csv()
    detect_and_block()
