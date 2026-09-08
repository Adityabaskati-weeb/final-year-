# ML Pipeline

## Feature contract

`source-window-v1`, five seconds, exact ordered fields:
packets_per_second, bytes_per_second, packet_count, mean_bytes, std_bytes, syn_fraction, rst_fraction, ack_fraction, udp_fraction, unique_destination_ports, unique_source_ports, mean_gap, std_gap.

Source/destination IPs, labels, timestamps and device IDs are metadata, not predictors. Numeric inputs must be finite and nonnegative. Tree models do not need scaling here. Capture and PCAP training both use the same Packet/Windows/vector implementation. No heuristic mapping to Kitsune or Edge-IIoT fields occurs.

## Synthetic demonstration

`python -m ml.train --demo` generates 10 independent seeded sessions per class, six windows each. Seven sessions/class train (210 windows); three test (90). This checks implementation behavior on a known generator distribution, not unseen real attacks. Perfect metrics are unsurprising. Dataset class labels describe packet patterns only, not payload-confirmed attacks.

## Real training

1. Position capture where both the monitored sensor and lab test source are observable. Record ordinary activity at varied rates and at different times. Record authorized bounded test scenarios separately; keep an experiment log.
2. `python scripts/record_session.py --interface "INTERFACE_ID" --target 192.168.1.20 --seconds 180 --output runtime/captures/normal-01.pcap`
3. Build a JSON array manifest. Every PCAP must have a distinct hash and session ID, a label, targets, notes and train/test split. At least two independent sessions per class in **each** split and 20 completed windows per PCAP are required. Use more and hold out devices/days; the minimum is not evidence of generalization.

```json
[
  {"pcap":"captures/normal-01.pcap","session":"day1-normal-01","split":"train","label":"normal","targets":["192.168.1.20"],"notes":"Untouched sensor, private lab, ordinary telemetry"}
]
```

The single-entry example is intentionally insufficient to train. Add independently collected normal/attack sessions for both splits.

4. `python -m ml.train --manifest runtime/labelled-sessions.json --output runtime/live-model`
5. Set LIVE_MODEL_PATH to the resulting trusted local model.joblib and restart. No model upload API is exposed: joblib can execute code and must be trusted.

The export gate requires test recall >=0.8 and false-positive rate <=0.05 at fixed threshold 0.8. Evaluation includes binary accuracy, precision, recall, F1/F2, ROC-AUC, average precision (reported separately from trapezoidal PR area), confusion matrix, multiclass report, session IDs, file hashes and median/p95 inference latency. Threshold 0.8 is fixed rather than tuned on test data. If tuning, create a separate validation split; never tune using test metrics.

Session overlap and identical-PCAP checks cannot prove the absence of correlated near-duplicates or mislabeled recordings. Human data provenance review remains necessary. A failed training run writes its report but does not replace a previous model; do not interpret an older artifact as the failed run's result. Independent devices, natural background traffic, load tests and real false-positive measurements remain mandatory before enabling automatic live blocking.

SHAP is not implemented. Displayed reasons are largest deviations from normal training medians; they are not causal feature contributions. Probabilities are not calibrated. Brute-force credentials, malformed application requests, SQL injection and botnet identity cannot be reliably inferred from these 13 fields.
