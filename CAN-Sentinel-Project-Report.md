# CAN-Sentinel: Automotive ECU Intrusion Detection System

## Executive summary
CAN-Sentinel is a research/demo pipeline for inspecting offline CAN 2.0B logs and reproducible synthetic traffic. It combines deterministic protocol/rate rules with Isolation Forest and Random Forest scores, emits JSON Lines forensic alerts, and calculates standard IDS metrics. Synthetic results are not evidence of real-vehicle performance.

## Architecture
`Synthetic traffic / CSV -> validation + causal features -> deterministic rules + ML ensemble -> JSONL forensic alerts -> Streamlit dashboard / evaluator`

## Attack scenarios
- **DoS:** repeated dominant-priority arbitration ID `0x000`, generated at 10x the configured baseline rate.
- **Fuzzy:** randomized 11-bit IDs (`0x000`–`0x7FF`) and random eight-byte payloads.
- **Spoofing:** implausible high engine-speed payloads on `0x316`.

## Vulnerability assessment
| Finding | Severity | Potential impact | Recommended action |
|---|---|---|---|
| Classical CAN has no sender authentication | Critical | Compromised nodes can impersonate ECU IDs | Enforce gateway boundaries; evaluate CANsec where supported; protect keys |
| High-priority bus availability exposure | High | Priority flooding can delay lower-priority frames | Gateway rate limiting, deadline monitoring, segmented networks, fail-safe testing |
| Static ID/rate assumptions | High | False positives and missed vehicle-specific activity | Create OEM-approved allowlists and timing envelopes from validated traces |
| Synthetic-only model training | High | Results may not generalize to ECUs or unseen attack families | Collect authorized captures; use vehicle/route/attack-family holdouts |
| No authenticated provenance for input logs | Medium | Log alteration or misattribution | Secure collection, clocks, access controls, and signed export manifests |
| Python host-side latency is not deterministic | Medium | Cannot claim hard real-time or sub-millisecond guarantees | Profile target hardware; bound workloads and queues; safety-review deployment |

## Metrics and limitations
The evaluator reports accuracy, precision, recall, F1, false-positive rate, ROC-AUC, mean latency, and p95 latency. Metrics vary by generated seed, threshold, machine, runtime load, and scenario. Example synthetic benchmarks must not be represented as production vehicle validation. This project is a prototype, not a certified automotive security product.
