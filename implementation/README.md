# Evaluated implementation

This directory contains the principal code paths used by the completed Raspberry Pi study.

- `xdp/xdp_policy_mitigation.c` — generic-XDP telemetry and source/protocol PASS/DROP enforcement.
- `controller/adaptive_policy_controller_timestamped.c` — userspace controller that merges per-CPU telemetry, reconstructs the ten-second logical window, applies workload-derived thresholds, and updates the policy map for one configured profiled source.

The measured platform used Raspberry Pi 4 `eth0` with the `bcmgenet` driver. Driver-mode XDP attachment was rejected, so the reported study uses **generic XDP (XDP_SKB)**.

The complete implementation history and helper utilities are included in the frozen supplementary archive submitted with the manuscript. Unvalidated Stage 2 extensions are deliberately excluded from this public repository.
