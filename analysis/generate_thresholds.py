import csv
from pathlib import Path

BASE = (
    Path.home()
    / "iot-xdp-study"
    / "experiments"
    / "processed"
    / "baselines"
)

INPUT_FILE = (
    BASE
    / "statistics"
    / "baseline_statistics.csv"
)

OUTPUT_FILE = (
    BASE
    / "statistics"
    / "candidate_thresholds.csv"
)

K_VALUES = [3, 4, 5, 6]

# One packet in a 10-second window = 0.1 PPS.
DELTA_PPS = 0.1

rows = []

with INPUT_FILE.open(newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        median = float(row["pps_median"])
        mad = float(row["pps_mad"])
        p99 = float(row["pps_p99"])
        observed_max = float(row["pps_max"])

        for k in K_VALUES:
            mad_threshold = median + k * mad
            fallback_threshold = p99 + DELTA_PPS
            candidate_threshold = max(
                mad_threshold,
                fallback_threshold
            )

            rows.append({
                "workload": row["workload"],
                "source_ip": row["source_ip"],
                "protocol_class": row["protocol_class"],
                "sample_count": row["sample_count"],
                "pps_median": f"{median:.6f}",
                "pps_mad": f"{mad:.6f}",
                "pps_p99": f"{p99:.6f}",
                "observed_max_pps": f"{observed_max:.6f}",
                "k": k,
                "delta_pps": f"{DELTA_PPS:.6f}",
                "mad_threshold": f"{mad_threshold:.6f}",
                "fallback_threshold": f"{fallback_threshold:.6f}",
                "candidate_threshold_pps": f"{candidate_threshold:.6f}",
            })

fieldnames = [
    "workload",
    "source_ip",
    "protocol_class",
    "sample_count",
    "pps_median",
    "pps_mad",
    "pps_p99",
    "observed_max_pps",
    "k",
    "delta_pps",
    "mad_threshold",
    "fallback_threshold",
    "candidate_threshold_pps",
]

with OUTPUT_FILE.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print("Candidate threshold table generated:")
print(OUTPUT_FILE)
print()
print(
    "IMPORTANT: These thresholds are candidates "
    "and require validation against legitimate "
    "and attack traffic."
)
