#!/usr/bin/env python3
import csv
from collections import defaultdict, Counter

CSV_PATH = r"E:\MMSECStuff\MMSEC\1debianCloneVMFreshMullvad\testReal\testexport.csv"  # change if needed

def analyze_protocols(csv_path: str) -> None:
    protocol_counts = Counter()
    protocol_lengths_bytes = defaultdict(int)

    with open(csv_path, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            protocol = row["Protocol"]
            try:
                length = int(row["Length"])
            except ValueError:
                continue  

            protocol_counts[protocol] += 1
            protocol_lengths_bytes[protocol] += length

    total_packets = sum(protocol_counts.values())
    total_bytes = sum(protocol_lengths_bytes.values())
    print(f"protocol frequency by packets (total packets = {total_packets})")
    for proto, count in protocol_counts.most_common():
        share = count * 100 / total_packets
        print(f"  {proto:10}: {count:7d} packets  ({share:5.1f} %)")

    print(f"\n amount of byter per protocol (total bytes = {total_bytes})")
    for proto, byte in sorted(protocol_lengths_bytes.items(),
                             key=lambda x: x[1],
                             reverse=True):
        share = byte * 100 / total_bytes
        print(f"  {proto:10}: {byte:10d} bytes   ({share:5.1f} %)")
        
if __name__ == "__main__":
    analyze_protocols(CSV_PATH)
