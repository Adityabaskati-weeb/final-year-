# Updated IoT Work

Real IoT-23 connection-log training and recorded-data analysis, with a gated Zeek live-ingestion path. The synthetic generator and 13-feature source-window model have been removed from the active application.

## Current result

A Random Forest was actually trained on nine official IoT-23 captures. The corrected untouched-holdout evaluation achieved 80.10% accuracy, **34.38% attack recall**, 1.17% precision and 19.60% false-positive rate (11 detected attacks, 21 missed, 933 false alarms). It FAILED the evaluation gate and remains restricted to recorded analysis. The separate lab model described below is the only live-approved binary path, and is explicitly limited to the registered ESP32, Wi-Fi topology and matching extractor. This is not a working general-purpose attack detector yet.

The local lab path is now operational as a separate, narrow model: 158 untouched flows from the connected ESP32 lab sessions (108 normal, 50 bounded private probe flows) achieved 100% recall and 0% false-positive rate, then passed hash-linked promotion evidence. This result applies only to the registered device, this Wi-Fi topology, and the `scapy-lab-flow-v1` extractor; it is not evidence for arbitrary IoT attacks or attack-family attribution.

## Capability Matrix

### Can be performed now

- Capture real TCP/UDP network flows involving an explicitly registered private ESP32 through Npcap/Scapy on Windows, or ingest compatible Zeek connection logs.
- Extract the same 11 network-flow fields used during model training.
- Run the promoted real lab Random Forest and classify the current lab traffic as `normal` or `malicious`.
- Attribute the documented bounded TCP probe as `tcp_connection_probe`.
- Attribute a separately observed bounded UDP probe as `udp_probe`; the included probe command is never run automatically.
- Show live traffic, detections, alerts, sensor telemetry and response state in the dashboard.
- Send an authenticated security status to the ESP32 so the OLED, LED and buzzer can indicate an alert; the hardware alarm test is available for wiring verification.
- Record a dry-run or host-firewall response decision with an expiry and protected-device safeguards.
- Train and validate an optional attack-family model after collecting multiple labelled families with the same extractor.

### Cannot be claimed or performed by this repository yet

- It is not a universal IoT detector for arbitrary devices, routers or wireless clients.
- The current live model does not reliably classify DDoS, Mirai, SQL injection, ARP spoofing, brute force or other families from arbitrary traffic.
- It does not inspect encrypted payloads or sensor temperature values to prove a cyberattack.
- A host firewall on the monitoring laptop cannot block a separate Wi-Fi client that reaches the ESP32 directly through the router.
- The default `FIREWALL_MODE=dry-run` does not claim that an operating-system or gateway rule was installed.
- The failed IoT-23 candidate is not enabled for live protection: its held-out attack recall was 34.38% and its false-positive rate was 19.60%.
- The current 331-flow ESP32 lab corpus is too small to support general multi-device or multi-family accuracy claims.

## Improvements Required For A Protected Multi-Device System

1. Capture normal traffic from multiple owned sensor types, firmware versions and separate days.
2. Capture independently labelled private-lab sessions for each attack family using the same flow extractor.
3. Keep device/day/capture-disjoint train, validation and test partitions, then validate on a device excluded from training.
4. Promote the binary model first, then validate and promote the optional multiclass family model.
5. Place enforcement at the Wi-Fi gateway/AP, or route the lab sensor through a controlled gateway with a separate attack source.
6. Verify block effectiveness with before/after connectivity tests, TTL expiry and preserved packet evidence.
7. Enable active firewall mode only after the private topology and rollback procedure are verified.

The project intentionally fails closed: insufficient evidence produces `unknown`, `protected` or `dry_run` instead of a fabricated attack label or an unsafe block.

## Run

```powershell
python -m pip install -r requirements.txt
Copy-Item config/lab_targets.example.yaml config/lab_targets.yaml
python scripts/download_iot23.py
python -m ml.train --manifest runtime/iot23/manifest.json --output runtime/iot23-model-v2-20260909
python run_project.py --build --model runtime/iot23-model-v2-20260909/model.joblib
```

Open http://127.0.0.1:8020. Startup neither fabricates data nor starts capture automatically. Download/training are separate, explicit operations. Select Recorded IoT-23 to analyze an actual downloaded capture; these are historical records, not live traffic or an attack launched at the sensor.

The shown model already exists locally; skip training to run it. Retraining requires a NEW output directory and corresponding --model path so old evidence is never overwritten.

## Components

- FastAPI, SQLite, React, authenticated device telemetry.
- Shared 11-field Zeek connection schema for training and inference.
- Official-download manifest, SHA-256 verification, capture-disjoint train/validation/test splits.
- Numeric imputation, categorical one-hot encoding, Random Forest; validation-only threshold selection.
- Authenticated Zeek JSON ingestion, local JSON log tailing, or an explicit Scapy/Npcap adapter that aggregates observed packets for registered private lab devices. The adapter records its extractor identity and does not turn sensor values into attack labels.
- Separate historical/live provenance; recorded analysis cannot trigger hardware or firewall actions.
- Dry-run host firewall adapters retained. These do not protect a separate ESP32 behind the same Wi-Fi router.

Legacy ignored runtime files may still exist locally but are not loaded as the current model. Old synthetic database rows are excluded from current views. Kitsune/Edge-IIoT models are not interchangeable with this schema.

## Hardware and remaining work

USB supplies power/programming; network detection needs visible ESP32 network traffic. The current Windows laptop can capture the connected ESP32's traffic because Npcap sees both endpoints on the active Wi-Fi adapter. This is limited to the registered device and this lab topology; it is not a claim that the laptop can observe every Wi-Fi client.

The authenticated ESP32 telemetry path is operational for the registered lab board. The current lab setup accepts the existing firmware on `10.81.27.229` through the compatibility listener on port `8010`; the updated sketch uses port `8020` and sends a boot ID. Telemetry confirms sensor connectivity and readings, but sensor values are not attack labels.

The Live network toolbar includes **Hardware alarm test**. It sends a clearly labelled, short actuator test to the registered board so the OLED, LED and buzzer can be checked. It is not a cyberattack and does not create a model detection or firewall event.

An explicit Scapy/Npcap capture source is now available locally and the promoted lab model is selected through the ignored local `.env`. The live dashboard classifies the matching ESP32 traffic with a validated binary decision; the documented bounded TCP probe is additionally attributed as `tcp_connection_probe`. This is lab attribution, not a general multi-class attack-family model. The original IoT-23 candidate remains failed and unpromoted. Expand to independent devices, days, ports and attack families before claiming general protection.

See [ML pipeline](docs/ML_PIPELINE.md), [architecture](docs/ARCHITECTURE.md), [hardware/demo](docs/DEMO.md), [security](docs/SECURITY.md), and [acceptance status](docs/AUDIT.md).

For the device-specific training recipe, live detection scope, repository comparison and the gateway-blocking limitation, see [device training and live scope](docs/DEVICE_TRAINING_AND_LIVE_SCOPE.md).

The selected published-model candidate is documented in [iot-audit candidate](docs/IOT_AUDIT_CANDIDATE.md). It is loaded and hash-verified for offline evaluation only; its TON-IoT training domain is not interchangeable with IoT-23 or live ESP32 traffic.

The external reference is reproducible without committing a binary model: run `python scripts/fetch_iot_audit_model.py` to download the pinned upstream artifact and verify its SHA-256, then run `python scripts/evaluate_iot_audit_candidate.py`. Generate the presentation/audit claim ledger with `python scripts/build_credibility_report.py --output runtime/credibility/report.json --markdown runtime/credibility/report.md`; see [credibility and external reference](docs/CREDIBILITY.md). The ledger deliberately separates external offline evidence, ESP32 live scope, attack-family readiness and gateway enforcement.

Continuation: [recovery audit](docs/CURRENT_STATE_AUDIT.md), [lab runbook](docs/LAB_RUNBOOK.md), [evidence export](docs/EVIDENCE.md), [repository comparison](docs/GITHUB_MODEL_AUDIT.md), [pretrained-model audit](docs/UPSTREAM_PRETRAINED_MODEL_AUDIT.md).

```powershell
python -m unittest discover -s tests -v
```

Docker is optional and unverified; mount real data/model artifacts into runtime. Never load untrusted joblib files.
