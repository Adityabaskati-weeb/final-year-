# Published iot-audit candidate

Audited and integrated on 2026-09-09 from [emanuelepiodebernardis/iot-audit](https://github.com/emanuelepiodebernardis/iot-audit).

## Why this repository was selected

It is the only inspected candidate that exposes a complete, committed binary model artifact together with its preprocessing pipeline. The selected artifact is the published `binary_lightgbm.joblib` from the repository's `models` directory. The upstream project describes TON-IoT training, unified flow engineering, and ESP32-C3 hardware benchmarking. This makes it a useful reproducible candidate, not proof that the model is already valid for our ESP32.

The Iretha IoT-23 repository remains a useful Zeek and dataset reference, but it does not publish a complete reusable model bundle. The other inspected repositories either require unavailable external artifacts or use a different feature schema.

## Artifact and schema

Local path:

`runtime/iot-audit-pretrained/binary_lightgbm.joblib`

SHA-256:

`3d113987cbaf696aef336aa398a3ce17d07a34a97473dc06f2399d232fb5d3f0`

The serialized object is a scikit-learn `Pipeline` with `preprocessor` and `model` steps. It expects these 13 fields in this order:

```text
bytes_total, bytes_src, bytes_dst, pkts_total, byte_asymmetry,
pkt_asymmetry, payload_mean_fwd, payload_mean_bwd, flow_duration_sec,
flow_rate, proto_unified, service_unified, conn_state_unified
```

The adapter derives these fields only from complete Zeek connection records. It does not fabricate values from USB sensor readings. The artifact was serialized with scikit-learn 1.8.0 and currently loads under 1.6.1 with a compatibility warning; this is recorded in the model status.

## Reproduce the local result

```powershell
C:\Python313\python.exe scripts/evaluate_iot_audit_candidate.py
```

The command evaluates the candidate against the held-out real IoT-23 test captures and writes `runtime/iot-audit-pretrained/evaluation.json`.

Current result on 3,720 compatible IoT-23 test flows:

| Metric | Result |
|---|---:|
| Accuracy | 9.97% |
| Precision | 0.62% |
| Attack recall | 91.30% |
| F1 | 1.24% |
| False-positive rate | 90.53% |
| ROC AUC | 0.134 |

This is severe domain shift: the model is trained for TON-IoT-style unified flows, while the evaluation is IoT-23. It is therefore intentionally marked `offline_only`, `live_validated: false`, and `response_eligible: false`. It must not drive ESP32 alerts, hardware actuators, or firewall blocking.

## Promotion rule

To make this candidate usable for live detection, retrain or calibrate it on real captures from the intended deployment network, retain the same extractor for training and inference, evaluate on independent captures, and complete labelled ESP32 lab validation. The dashboard shows the candidate and its provenance, but the existing live safety gate remains unchanged.

References: [model directory](https://github.com/emanuelepiodebernardis/iot-audit/tree/main/models), [unified feature engineering](https://github.com/emanuelepiodebernardis/iot-audit/blob/main/section_310_unified_feature_engineering.py), [hardware benchmarks](https://github.com/emanuelepiodebernardis/iot-audit#physical-hardware-benchmarks).
