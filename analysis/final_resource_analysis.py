#!/usr/bin/env python3

import csv
import statistics
from pathlib import Path

ROOT = Path.home() / "iot-xdp-study"
REGISTRY = ROOT / "experiments/processed/audit/experiment_registry.csv"
OUTDIR = ROOT / "experiments/processed/final"
OUTDIR.mkdir(parents=True, exist_ok=True)

def load_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

def delta_rate(rows, counter):
    if len(rows) < 2:
        return None
    first = float(rows[0][counter])
    last = float(rows[-1][counter])
    t0 = float(rows[0]["elapsed_seconds"])
    t1 = float(rows[-1]["elapsed_seconds"])
    dt = t1 - t0
    if dt <= 0:
        return None
    return (last - first) / dt

def mean_float(rows, field):
    vals = [float(r[field]) for r in rows]
    return statistics.mean(vals) if vals else None

def max_float(rows, field):
    vals = [float(r[field]) for r in rows]
    return max(vals) if vals else None

def read_manifest(path):
    result = {}
    if not path.exists():
        return result
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            result[k] = v
    return result

runs = []

with open(REGISTRY, newline="") as f:
    for row in csv.DictReader(f):
        if (
            row["use_in_results"] == "yes"
            and row["category"] in {"overhead", "comparator", "scalability"}
        ):
            runs.append(row)

per_run = []

for item in runs:
    run_id = item["run_id"]
    resource = ROOT / "experiments/raw" / run_id / "resource.csv"
    manifest_path = ROOT / "experiments/logs" / run_id / "manifest.txt"
    manifest = read_manifest(manifest_path)

    if not resource.exists():
        print("WARNING: missing resource.csv:", run_id)
        continue

    rows = load_csv(resource)

    cpu_mean = mean_float(rows, "cpu_percent")
    cpu_max = max_float(rows, "cpu_percent")
    mem_mean_mb = mean_float(rows, "memory_used_kb") / 1024.0
    mem_max_mb = max_float(rows, "memory_used_kb") / 1024.0

    rx_pps = delta_rate(rows, "rx_packets")
    tx_pps = delta_rate(rows, "tx_packets")
    rx_Bps = delta_rate(rows, "rx_bytes")
    tx_Bps = delta_rate(rows, "tx_bytes")

    rx_drop_delta = int(rows[-1]["rx_dropped"]) - int(rows[0]["rx_dropped"])
    rx_error_delta = int(rows[-1]["rx_errors"]) - int(rows[0]["rx_errors"])
    tx_drop_delta = int(rows[-1]["tx_dropped"]) - int(rows[0]["tx_dropped"])
    tx_error_delta = int(rows[-1]["tx_errors"]) - int(rows[0]["tx_errors"])

    per_run.append({
        "run_id": run_id,
        "category": item["category"],
        "role": item["role"],
        "samples": len(rows),
        "cpu_mean_percent": cpu_mean,
        "cpu_max_percent": cpu_max,
        "memory_mean_mb": mem_mean_mb,
        "memory_max_mb": mem_max_mb,
        "rx_pps": rx_pps,
        "tx_pps": tx_pps,
        "rx_kbps": (rx_Bps * 8 / 1000.0) if rx_Bps is not None else None,
        "tx_kbps": (tx_Bps * 8 / 1000.0) if tx_Bps is not None else None,
        "rx_drop_delta": rx_drop_delta,
        "rx_error_delta": rx_error_delta,
        "tx_drop_delta": tx_drop_delta,
        "tx_error_delta": tx_error_delta,
        "udp_drop_packets": manifest.get("udp_drop_packets", ""),
        "tcp_syn_drop_packets": manifest.get("tcp_syn_drop_packets", ""),
        "icmp_drop_packets": manifest.get("icmp_drop_packets", ""),
        "comparator_validation": manifest.get("comparator_validation", ""),
    })

OUT1 = OUTDIR / "resource_per_run.csv"
fields = list(per_run[0].keys())

with open(OUT1, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(per_run)

def condition_name(role):
    if role.startswith("NO_DEFENSE"):
        return "NO_DEFENSE"
    if role.startswith("TELEMETRY_"):
        return "TELEMETRY_ONLY"
    if role.startswith("FULL_"):
        return "FULL"
    if role.startswith("IPTABLES_"):
        return "IPTABLES"
    if role.startswith("NFTABLES_"):
        return "NFTABLES"
    if role == "COMPACT_SOURCE_CHURN":
        return "LRU_SOURCE_CHURN"
    return role

groups = {}

for row in per_run:
    condition = condition_name(row["role"])
    groups.setdefault(condition, []).append(row)

aggregate = []

numeric_fields = [
    "cpu_mean_percent",
    "cpu_max_percent",
    "memory_mean_mb",
    "memory_max_mb",
    "rx_pps",
    "tx_pps",
    "rx_kbps",
    "tx_kbps",
]

for condition, rows in groups.items():
    result = {"condition": condition, "runs": len(rows)}

    for field in numeric_fields:
        vals = [
            float(r[field])
            for r in rows
            if r[field] not in ("", None)
        ]

        result[field + "_mean"] = statistics.mean(vals) if vals else None
        result[field + "_sd"] = statistics.stdev(vals) if len(vals) >= 2 else 0.0

    result["interface_drop_error_free_runs"] = sum(
        r["rx_drop_delta"] == 0
        and r["rx_error_delta"] == 0
        and r["tx_drop_delta"] == 0
        and r["tx_error_delta"] == 0
        for r in rows
    )

    aggregate.append(result)

OUT2 = OUTDIR / "resource_by_condition.csv"
fields2 = list(aggregate[0].keys())

with open(OUT2, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields2)
    writer.writeheader()
    writer.writerows(aggregate)

comp = [r for r in per_run if r["category"] == "comparator"]
counter_rows = []

for condition in ["IPTABLES", "NFTABLES"]:
    rows = [r for r in comp if condition_name(r["role"]) == condition]

    for proto, field in [
        ("UDP", "udp_drop_packets"),
        ("TCP_SYN", "tcp_syn_drop_packets"),
        ("ICMP", "icmp_drop_packets"),
    ]:
        vals = [
            int(r[field])
            for r in rows
            if str(r[field]).strip() != ""
        ]

        counter_rows.append({
            "comparator": condition,
            "protocol_class": proto,
            "runs": len(vals),
            "mean_drop_packets": statistics.mean(vals) if vals else None,
            "sd_drop_packets": statistics.stdev(vals) if len(vals) >= 2 else 0.0,
            "min_drop_packets": min(vals) if vals else None,
            "max_drop_packets": max(vals) if vals else None,
        })

OUT3 = OUTDIR / "comparator_drop_summary.csv"
fields3 = list(counter_rows[0].keys())

with open(OUT3, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields3)
    writer.writeheader()
    writer.writerows(counter_rows)

print("Wrote:", OUT1)
print("Wrote:", OUT2)
print("Wrote:", OUT3)
print("Resource runs processed:", len(per_run))
