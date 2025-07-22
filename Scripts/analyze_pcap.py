import pyshark
from collections import defaultdict
import sys

if len(sys.argv) != 3:
    print("Usage: python analyze_pcap.py <pcap_file> <target_ip>")
    sys.exit(1)

pcap_file = sys.argv[1]
target_ip = sys.argv[2]

# === Ergebnisvariablen ===
packet_count = 0
sent_packets = 0
received_packets = 0
tls_packets = 0  # NEU: TLS-Zähler
protocols = set()
tcp_handshakes = []
ip_counter = defaultdict(int)
tcp_connections = set()
tcp_streams = {}

# === Analyse starten ===
print(f"Analysiere Datei: {pcap_file}")
capture = pyshark.FileCapture(pcap_file, display_filter=f"ip.addr == {target_ip}", use_json=True)

for pkt in capture:
    try:
        packet_count += 1
        proto = pkt.highest_layer
        protocols.add(proto)

        # NEU: TLS-Paket zählen
        if proto == 'TLS':
            tls_packets += 1

        src = pkt.ip.src
        dst = pkt.ip.dst
        ip_counter[dst if src == target_ip else src] += 1

        if src == target_ip:
            sent_packets += 1
        if dst == target_ip:
            received_packets += 1

        if 'TCP' in pkt:
            tcp = pkt.tcp
            stream = tcp.stream
            flags = tcp.flags
            connection_id = (pkt.ip.src, tcp.srcport, pkt.ip.dst, tcp.dstport)
            tcp_connections.add(connection_id)

            if stream not in tcp_streams:
                tcp_streams[stream] = {
                    'syn': False,
                    'syn_ack': False,
                    'ack': False,
                    'info': connection_id
                }

            # 1. SYN vom Client
            if tcp.flags_syn == '1' and tcp.flags_ack == '0':
                tcp_streams[stream]['syn'] = True

            # 2. SYN-ACK vom Server
            elif tcp.flags_syn == '1' and tcp.flags_ack == '1':
                tcp_streams[stream]['syn_ack'] = True

            # 3. ACK vom Client (ohne SYN)
            elif tcp.flags_ack == '1' and tcp.flags_syn == '0':
                tcp_streams[stream]['ack'] = True

    except AttributeError:
        continue

# Handshakes auswerten
for stream, data in tcp_streams.items():
    if data['syn'] and data['syn_ack'] and data['ack']:
        tcp_handshakes.append(data['info'])

# === Ausgabe ===
print("\n--- Analyse-Ergebnisse ---")
print(f"Gesamtpakete mit {target_ip}: {packet_count}")
print(f"  Davon gesendet: {sent_packets}")
print(f"  Davon empfangen: {received_packets}")
print(f"Verwendete Protokolle: {', '.join(sorted(protocols))}")
print(f"Anzahl TCP-Verbindungen: {len(tcp_connections)}")
print(f"Erkannte TCP-Handshakes: {len(tcp_handshakes)}")

# NEU: TLS-Ausgabe
print(f"Anzahl TLS-Pakete: {tls_packets}")
if packet_count > 0:
    print(f"Anteil TLS: {tls_packets / packet_count * 100:.2f} %")
else:
    print("Keine Pakete gefunden.")

print("\nTop-Ziel-/Quell-IPs:")
for ip, count in sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"  {ip}: {count} Pakete")

print("\nBeispielhafte TCP-Verbindungen (max. 5):")
for conn in list(tcp_connections)[:5]:
    print(f"  {conn[0]}:{conn[1]}  ➝  {conn[2]}:{conn[3]}")

capture.close()