# CAN-Sentinel: Automotive ECU Intrusion Detection System

## Executive summary
CAN-Sentinel is an educational Python prototype for offline Classical CAN log inspection and deterministic synthetic traffic generation. It validates and normalizes frame data, extracts causal features, applies rolling-window rules and a synthetic-trained Isolation Forest / Random Forest score, creates JSONL alerts, and evaluates labeled traces. It does not connect to a CAN interface or transmit frames; it is not production-ready or safety-certified.

## Architecture
`Synthetic scenario / authorized CSV → validation and chronological normalization → causal per-frame features → deterministic rules + ML risk score → fused frame decision → JSONL alerts → dashboard and evaluator`

## Attack demonstrations
- **DoS:** identifier `0x000` at one tenth the baseline period (10x generator frame rate).
- **Fuzzy:** randomized standard identifiers `0x000`–`0x7FF` and random eight-byte payloads.
- **RPM spoof:** implausible example RPM values using ID `0x316`.

All traffic is generated in memory. Nothing transmits on a vehicle network.

## Vulnerability assessment
| Finding | Severity | Potential impact | Mitigation / next step |
|---|---|---|---|
| Classical CAN sender identity is not cryptographically authenticated | Critical | A compromised node may impersonate ECU IDs | Use secure gateway controls; evaluate CANsec where supported; protect trust boundaries and keys |
| Bus availability can be degraded through priority abuse | High | High-priority traffic can delay lower-priority frames | Monitor deadlines, segment networks, evaluate gateway rate controls, validate safe failure behavior |
| Demonstration thresholds are not vehicle-specific | High | Legitimate frames may be falsely alerted or abnormal behavior missed | Derive policies from approved OEM requirements and representative authorized traces |
| Synthetic ML training distribution | High | Results may not transfer to real ECUs, vehicles, or unseen attacks | Use independent authorized captures and hold out vehicles/sessions/attack families |
| Heuristic ML score is not calibrated | High | Threshold metrics can be misinterpreted as deployment probabilities | Calibrate only with held-out representative validation data; report operating points and uncertainty |
| Local JSONL lacks integrity protection | Medium | Alerts can be altered, lost, or misattributed | Secure collection, storage, clocks, access control, retention, and signed exports |
| Host-side detector latency is variable | Medium | No hard-real-time or sub-millisecond guarantee | Profile on target hardware and review bounded operation before deployment |

## Evaluation interpretation
Accuracy, precision, recall, F1, false-positive rate, and confusion matrix use the fused frame decision (any deterministic rule or ML threshold alert). ROC-AUC ranks the ML score alone and requires labeled examples from both classes. The 0–1 ML score is heuristic—not a calibrated probability. Timing is measured before alert construction and disk I/O. Synthetic sample results do not establish real-vehicle performance.

## Safe-use statement
Use only generated traffic or data you are authorized to analyze. Do not connect the demo to public-road vehicles or transmit crafted frames. Future hardware integration would require explicit authorization, isolated test benches, safety approval, and separate security and hazard reviews.
