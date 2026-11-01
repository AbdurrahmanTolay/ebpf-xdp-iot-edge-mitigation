# Workload-Aware Protocol-Specific eBPF/XDP Mitigation for Resource-Constrained IoT Edge Gateways

This repository contains the implementation and reproducibility artifacts for the manuscript:

**Abdurrahman Tolay and Hüsamettim Osmanoğlu, “Workload-Aware Protocol-Specific eBPF/XDP Mitigation for Resource-Constrained IoT Edge Gateways.”**

The study evaluates a bounded, source-IPv4/protocol telemetry and reversible PASS/DROP enforcement design on a Raspberry Pi 4 using **generic XDP (XDP_SKB)**.

## What is included

- evaluated XDP and userspace-controller source;
- legitimate MQTT, CoAP, HTTP, and ICMP calibration outputs;
- the frozen 28-run experiment registry;
- processed functional-validation and resource summaries;
- iptables/nftables reference results;
- analysis and threshold-generation scripts;
- a complete frozen supplementary archive under `supplementary/`.

## Evidence scope

The manuscript reports:

- **12 controlled functional runs** producing **18 protocol/run instances**;
- workload-derived thresholds of **0.6 PPS (UDP)**, **0.6 PPS (TCP SYN)**, and **1.1 PPS (ICMP)**;
- **9 legitimate-workload resource runs**;
- **6 static comparator runs**;
- **1 compact ten-source telemetry/state-validation run**.

The reported **18/18** result is functional consistency under the tested conditions, **not** formal detection accuracy.

The resource measurements characterize the evaluated lightweight legitimate workload, **not** high-rate attack overhead.

The evaluated userspace controller applies policy decisions to **one configured profiled source at a time**. The ten-source experiment validates telemetry/state visibility only; it does **not** establish independent multi-source mitigation or map-capacity saturation.

The study does not establish line-rate capacity, native-XDP performance, formal false-positive/false-negative rates, exact containment latency, application QoS under attack, energy efficiency, IPv6 behavior, or full-map saturation.

## Repository structure

- `implementation/` — evaluated XDP and controller source.
- `analysis/` — scripts used for threshold and result processing.
- `evidence/` — frozen registry and key processed outputs used by the manuscript.
- `supplementary/` — complete reviewer reproducibility archive.
- `REPRODUCIBILITY.md` — artifact-to-manuscript mapping and interpretation notes.
- `CITATION.cff` — citation metadata.

## Platform

The measured gateway was a Raspberry Pi 4 Model B using `eth0` and the `bcmgenet` driver. Driver-mode XDP attachment was rejected, so the reported results use **generic XDP (XDP_SKB)**.

## Reproducibility

Start with `REPRODUCIBILITY.md` and `evidence/experiment_registry.csv`.

The complete frozen package is also provided as:

`supplementary/Tolay_Osmanoglu_IoTJ_Supplementary_Reproducibility.zip`

This repository is intended to support transparent peer review and reproducibility inspection of the evidence reported in the manuscript. It deliberately excludes unvalidated experimental extensions and manuscript-development workspaces.

## Authors

- **Abdurrahman Tolay** — ORCID: 0009-0000-8855-6799
- **Hüsamettim Osmanoğlu** — ORCID: 0000-0002-1027-2945

Corresponding author: Abdurrahman Tolay — abdurrahman.tolay@alu.istinye.edu.tr
