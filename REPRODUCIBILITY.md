# Reproducibility guide

This repository supports the manuscript **“Workload-Aware Protocol-Specific eBPF/XDP Mitigation for Resource-Constrained IoT Edge Gateways.”**

## Authoritative run registry

The reported study uses the frozen inclusion list in:

`evidence/experiment_registry.csv`

It contains 28 included runs:

- 12 controlled functional XDP runs;
- 9 legitimate-workload resource runs;
- 6 static iptables/nftables comparator runs;
- 1 compact multi-source telemetry/state-validation run.

## Manuscript mapping

- Threshold calibration / Table II / Figure 2: calibration outputs and scripts in the complete supplementary archive.
- Controlled functional validation / Tables V–VI: `evidence/functional_per_run.csv` and `evidence/functional_by_protocol.csv`.
- Legitimate-workload resource evaluation / Table VII / Figure 5: `evidence/resource_by_condition.csv`.
- Static comparator references / Tables IV and VIII: `evidence/comparator_drop_summary.csv`.
- Compact ten-source telemetry/state validation / Table IX: evidence is retained in the complete supplementary archive.
- High-level frozen values: `evidence/results_summary.txt`.

## Complete artifact package

The complete frozen reviewer archive is uploaded separately to IEEE as **Supplementary Material for Review**. It contains the evaluated implementation source, raw and processed evidence, controller/event logs, threshold scripts, resource-analysis scripts, workload notes, comparator notes, and a SHA-256 manifest.

This public repository intentionally exposes the principal evaluated code, frozen run registry, key processed outputs, and analysis scripts in a browsable form.

## Interpretation boundaries

The repository supports only the evidence-bounded claims in the manuscript:

- 18/18 is functional consistency under the tested conditions, not formal detection accuracy.
- Controller DROP samples represent policy state, not packet-drop volume.
- Resource measurements characterize the evaluated lightweight legitimate workload, not attack-load overhead.
- The evaluated controller makes policy decisions for one configured profiled source at a time.
- The ten-source run establishes telemetry/state visibility at the tested cardinality only.
- No claim is made for line-rate capacity, native-XDP performance, formal FPR/FNR, exact containment latency, attack-time application QoS, energy consumption, IPv6, or full-map saturation.

Unvalidated Stage 2 extensions are intentionally excluded.
