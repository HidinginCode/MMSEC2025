#!/usr/bin/env python3
import csv
from collections import defaultdict
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

csv_path = Path(r"E:\MMSECStuff\MMSEC\1debianCloneVMFreshMullvad\testReal\testexport.csv")
host_ip = "10.0.2.15"
direction = "both"      
logarithmic_scaling_bool = True     

def empty_stats():
    return defaultdict(lambda: defaultdict(lambda: {
        "packets_out": 0, "bytes_out": 0,
        "packets_in":  0, "bytes_in":  0,
    }))

def parser_csv(path: Path, host_ip: str) -> defaultdict:
    stats = empty_stats()
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            proto, length = row["Protocol"], int(row["Length"])
            source, destination = row["Source"], row["Destination"]

            if source == host_ip and destination != host_ip:       
                d = stats[destination][proto]
                d["packets_out"]  += 1
                d["bytes_out"] += length
            elif destination == host_ip and source != host_ip:     
                d = stats[source][proto]
                d["packets_in"]   += 1
                d["bytes_in"]  += length
    return stats

def summarize_prot(ips_total):
    summary = {}
    for dir_key in ("out", "in", "both"):
        pBytes = defaultdict(int)
        for per_ip in ips_total[dir_key].values():
            for proto, bytes_temp in per_ip.items():
                pBytes[proto] += bytes_temp

        summe = sum(pBytes.values()) or 1            
        p_percent = {p: b * 100 / summe
                         for p, b in pBytes.items()}
        summary[dir_key] = {"bytes": pBytes,
                            "percent": p_percent,
                            "Summ": summe}
    return summary


def print_prot_summary(summary, dir_key):
    title = {"out": "Outgoing", "in": "Incoming", "both": "Combined"}[dir_key]
    data  = summary[dir_key]
    rows  = sorted(data["bytes"].items(), key=lambda kv: kv[1], reverse=True)

    print(f"\n== {title} traffic by protocol ==")
    print(f"{'Protocoll':<12} {'Bytes':>15} {'percentage':>8}")
    print("-" * 36)
    for p, b in rows:
        print(f"{p:<14} {b:16,} {data['percent'][p]:7.1f}%")
    print("-" * 36)
    print(f"{'Summ':<12} {data['Summ']:15,} 100.0%")


def create_totals(stats):
    totals = {"out": {}, "in": {}, "both": {}}
    p_set = set()

    for ip, p_dictioonary in stats.items():
        out = {p: d["bytes_out"] for p, d in p_dictioonary.items() if d["bytes_out"]}
        in_ = {p: d["bytes_in"]  for p, d in p_dictioonary.items() if d["bytes_in"]}
        if out:  totals["out"][ip]  = out
        if in_:  totals["in"][ip]   = in_
        if out or in_:
            both = {p: out.get(p, 0) + in_.get(p, 0) for p in set(out)|set(in_)}
            totals["both"][ip] = both
            p_set.update(both)
    return totals, sorted(p_set)

def print_table(stats):
    hdr = (f"{'IP':<16} {'protcol':<10} {'Packtes out':<12} {'Bytes out':<12} "
           f"{'Packtes in':<12} {'Bytes in':<12} {'Packtes total':<12} {'Bytes total':<14}")
    print("\n" + hdr)
    print("-" * len(hdr))

    for ip, prot_dict in stats.items():
        for prot, d in prot_dict.items():
            packets_out, bytes_out = d["packets_out"], d["bytes_out"]
            packets_in,  bytes_in  = d["packets_in"],  d["bytes_in"]

            if direction == "out"  and packets_out == 0: continue
            if direction == "in"   and packets_in  == 0: continue
            total_pk  = packets_out + packets_in
            total_by  = bytes_out + bytes_in
            if direction == "both" and total_pk == 0: continue

            print(f"{ip:<17} {prot:<10} {packets_out:10} {bytes_out:12} "
                  f"{packets_in:12} {bytes_in:12} {total_pk:12} {total_by:14}")

def print_table_mix(direction_key, ip_totals):
    title = {"out": "Outgoing", "in": "Incoming", "both": "Combined"}[direction_key]
    data = ip_totals[direction_key]
    if not data:
        return

    rows = []
    for ip in sorted(data, key=lambda p: sum(data[p].values()), reverse=True):
        pb = data[ip]
        total = sum(pb.values())
        if total == 0:
            continue
        contents = sorted(pb.items(), key=lambda kv: kv[1], reverse=True)
        rows.append((
            ip,
            ", ".join(p for p, _ in contents),
            ", ".join(f"{v:,}" for _, v in contents),
            ", ".join(f"{v/total:5.1%}" for _, v in contents)
        ))

    breite = [max(len(x[i]) for x in rows + [hdr])
              for i, hdr in enumerate(("IP", "protocol", "Bytes", "Percentages"))]

    print(f"\n== {title} byte mix per ip ==")
    header = " │ ".join(h.ljust(w) for h, w in zip(("IP", "protocol", "Bytes", "Percentages"), breite))
    print(header)
    print("─" * len(header))
    for r in rows:
        print(" │ ".join(val.ljust(w) for val, w in zip(r, breite)))
      
def plot_mix(direction_key: str, ax):
    titles = {"out": "Outgoing", "in": "Incoming", "both": "Combined"}[direction_key]
    data = ip_total[direction_key]

    ip = [p for p in ip_global_order if p in data]
    percentages = {proto: [] for proto in prot_g}

    for p in ip:
        Summe = sum(data[p].values()) or 1
        for proto in prot_g:
            percentages[proto].append(100 * data[p].get(proto, 0) / Summe)

    in_ = np.arange(len(ip))
    bottom = np.zeros(len(ip))
    for proto in prot_g:
        ax.bar(in_, percentages[proto], bottom=bottom, label=proto)
        bottom += np.array(percentages[proto])

    ax.set_xticks(in_)
    ax.set_xticklabels(ip, rotation=75, ha="right", fontsize=7)
    ax.set_ylabel("percentages of bytes (%)")
    ax.set_title(f"{titles} protocol stack")
    ax.set_ylim(0, 100)
  

def plot_mix_abs(direction_key: str, ax, *, log_scale=False):
    titles = {"out": "Outgoing", "in": "Incoming", "both": "Combined"}[direction_key]
    data = ip_total[direction_key]

    ip = [p for p in ip_global_order if p in data]
    share = {prot: [] for prot in prot_g}
    for p in ip:
        for prot in prot_g:
            share[prot].append(data[p].get(prot, 0))

    i = np.arange(len(ip))
    if log_scale:
        min_pos = min((v for d in data.values() for v in d.values() if v), default=1)
        bottom = np.full(len(ip), max(min_pos / 10, 1.), dtype=float)
        ax.set_yscale("log", base=10)
        ax.set_ylabel("bytes (log10)")
    else:
        bottom = np.zeros(len(ip))
        ax.set_ylabel("bytes")

    for prot in prot_g:
        heights = np.array(share[prot], dtype=float)
        if log_scale and not heights.any():
            continue
        ax.bar(i, heights, bottom=bottom, label=prot)
        bottom += heights

    ax.set_xticks(i)
    ax.set_xticklabels(ip, rotation=75, ha="right", fontsize=7)
    ax.yaxis.set_major_formatter(mtick.FuncFormatter(lambda x, _: f"{int(x):,}"))
    ax.set_title(f"{titles} protocol volume")


statistics = parser_csv(csv_path, host_ip)
ip_total, prot_g = create_totals(statistics)

ip_global_order = sorted(ip_total["both"],
                    key=lambda p: sum(ip_total["both"][p].values()),
                    reverse=True)

summary = summarize_prot(ip_total)      
for k in ("out", "in", "both"):                     
    print_prot_summary(summary, k)
    
print_table(statistics)
for k in ("out", "in", "both"):
    print_table_mix(k, ip_total)

figuer_stuff, axes = plt.subplots(1, 3, figsize=(18, 6), sharey=True)

for k, ax in zip(("out", "in", "both"), axes):
    plot_mix(k, ax)
    
handles, labels = axes[0].get_legend_handles_labels()
figuer_stuff.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 1.1),
               ncol=len(labels), fontsize="small", title="Protocol")
figuer_stuff.tight_layout(rect=[0, 0, 1, 1])

figuere_abs, axes = plt.subplots(1, 3, figsize=(18, 6))
for k, ax in zip(("out", "in", "both"), axes):
    plot_mix_abs(k, ax, log_scale=logarithmic_scaling_bool)
figuere_abs.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 1.05),
               ncol=len(labels), fontsize="small", title="Protocol")
figuere_abs.tight_layout(rect=[0, 0, 1, 0.95])

plt.show()
