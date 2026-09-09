# Device Training And Live Scope

## Decision

The working demo should use the connected ESP32 as a **networked device**, not as a source of temperature labels. The cyber detector trains on connection behavior observed on the network. Temperature, humidity, OLED state, LED state and buzzer state remain telemetry and actuator signals; they are not attack features.

The current production path is:

```text
ESP32 Wi-Fi traffic
  -> Npcap/Scapy lab flow extractor
  -> zeek-conn-v1 fields
  -> promoted binary Random Forest
  -> normal / attack
  -> documented lab attribution, when supported
  -> protected response record or gateway block
```

The current promoted ESP32 model is intentionally narrow. It was trained from real captures of the registered board and validated on separate sessions. It can support the bounded lab probe demonstration, but it is not a pretrained universal IoT detector and it does not yet provide a reliable 15-class attack-family prediction.

## What The Live Detector Can See

The shared `zeek-conn-v1` contract contains:

- flow duration;
- origin and response byte/packet counts;
- origin and response IP-byte counts;
- missed bytes;
- transport protocol, service and connection state.

The flow metadata also retains source/destination IPs and ports for device scoping and response policy. These are not model predictors. This is the same general layer exposed by Zeek `conn.log`, which records connection endpoints, protocol, service, duration, bytes, packets and connection state from live or stored traffic: [Zeek conn.log reference](https://docs.zeek.org/en/current/reference/logs/conn.html).

With the current Windows adapter, the live path can identify a registered ESP32's abnormal TCP/UDP connection pattern. It cannot inspect encrypted payloads, prove what an HTTP request contains, read the sensor's internal state, or observe every Wi-Fi client. It currently does not provide reliable ICMP/ARP or general wireless-monitor-mode visibility.

The current lab attribution is deliberately conservative:

- benign flow -> `normal`;
- binary malicious flow matching the documented bounded TCP probe -> `tcp_connection_probe` with `lab_attribution`;
- other malicious flow -> `unknown_attack_pattern` until a separately validated family classifier exists.

That means the project can honestly demonstrate **ESP32 network attack detection**, but it must not claim that the present model identifies DDoS, SQL injection, Mirai, ARP spoofing or other families from arbitrary live traffic.

## How To Train For More Sensor Devices

Use the same capture and inference extractor for every device. A model trained on temperature/humidity or on one device's IP address will not generalize to another sensor.

### 1. Define the device inventory

Give each board a stable identifier, for example `esp32-lab-1`, `esp32-lab-2` or `camera-lab-1`. Record firmware version, transport, destination services and network topology. Do not use the IP address as the device identity because DHCP can change it.

### 2. Capture independent normal sessions

Capture at least several sessions on different days and after reconnects. Keep capture IDs unique and split by capture, not by random rows. For example:

```powershell
python scripts/capture_lab_flows.py `
  --interface "Intel(R) Wi-Fi 6 AX200 160MHz" `
  --target 10.81.27.229 `
  --device-id esp32-lab-1 `
  --label normal `
  --split train `
  --capture-id esp32-1-normal-day1 `
  --seconds 300 `
  --output runtime/lab-captures/esp32-1-normal-day1.jsonl `
  --lab-config config/lab_targets.yaml
```

Repeat with new capture IDs for validation and test. Do the same for each additional device. The recorder is passive; it does not launch traffic.

### 3. Capture controlled private-lab attack phases

Run only an authorized, bounded experiment against the registered device or an isolated lab gateway. Label the phase using the attack type observed in the experiment:

```powershell
python scripts/capture_lab_flows.py `
  --interface "Intel(R) Wi-Fi 6 AX200 160MHz" `
  --target 10.81.27.229 `
  --device-id esp32-lab-1 `
  --label attack `
  --attack-type tcp_connection_probe `
  --split test `
  --capture-id esp32-1-probe-test1 `
  --seconds 60 `
  --output runtime/lab-captures/esp32-1-probe-test1.jsonl `
  --lab-config config/lab_targets.yaml
```

The operator supplies this label from the experiment plan. The recorder does not infer it. Do not call a normal telemetry session an attack merely because a model score is high.

### 4. Build and train

```powershell
python scripts/build_lab_manifest.py `
  --input-dir runtime/lab-captures `
  --output runtime/lab-captures/manifest.json

python -m ml.train `
  --manifest runtime/lab-captures/manifest.json `
  --output runtime/lab-model-next
```

The binary model should be promoted only after held-out device/session tests pass. Keep one device or capture group entirely outside training to measure generalization. The current gates require high attack recall and low false-positive rate; live promotion also requires independent live evidence.

When at least two attack families have been captured, train and validate the optional family model:

```powershell
python -m ml.train_attack_type `
  --manifest runtime/lab-captures/manifest.json `
  --output runtime/lab-attack-type-next

python scripts/validate_attack_type_model.py `
  --model runtime/lab-attack-type-next/model.joblib `
  --manifest runtime/lab-captures/manifest.json `
  --output runtime/lab-attack-type-next/validation.json

python scripts/promote_attack_type_model.py `
  --model runtime/lab-attack-type-next/model.joblib `
  --validation runtime/lab-attack-type-next/validation.json
```

Only after promotion should `.env` point `ATTACK_TYPE_MODEL_PATH` at that artifact and the backend be restarted. Until then, the family model is intentionally unavailable and the binary detector remains the live decision-maker.

### 5. Add multiclass only after the binary gate passes

`attack_type` is now stored in each capture and its manifest so a later classifier can use it. Do not train a multiclass model from one probe class or from labels inherited from a dataset whose feature schema differs from the live extractor. Each attack family needs independent captures, benign controls, and a held-out device/session test.

Useful families for future controlled work include connection probing, denial-of-service patterns, spoofing, brute force and web/application attacks. Public CIC-IoT2023 documentation lists examples across DDoS, DoS, brute force, spoofing, reconnaissance, web-based attacks and Mirai: [CIC-IoT2023 dataset description](https://www.unb.ca/cic/datasets/iotdataset-2023.html). Those labels are useful for planning, but their published feature files are not automatically compatible with this live extractor.

## What Existing Repositories Are Useful For

No inspected repository provides a trustworthy drop-in pretrained artifact for this project's exact ESP32 traffic, current extractor and response gates. Reusing a model without matching preprocessing and feature schema would produce a plausible-looking but invalid result.

- [Iretha IoT-23 classification](https://github.com/Iretha/IoT23-network-traffic-anomalies-classification): useful labelled flow extraction and scenario workflow; use as a data/evaluation reference, not as a live artifact.
- [ML-project-IOT-IDS](https://github.com/lynnazz3/ML-project-IOT-IDS): useful FastAPI/multiclass/drift ideas, but its reported pipeline expects 52 features and reports a 12.8% false-positive rate; it is not compatible with this 11-field live contract.
- [RealTimeNIDS](https://github.com/otuemre/RealTimeNIDS): useful warning that offline scores can fail controlled live traffic because of distribution shift, scaling and threshold differences.
- [feature-thesis-emanuele](https://github.com/emanuelepiodebernardis/feature-thesis-emanuele): useful reference for binary/multiclass evaluation and embedded ESP32 benchmarking, but its trained features and artifacts must not be loaded into this service without a schema match.

The current implementation follows the strongest common lesson from these projects: identical extraction for training and live inference, capture/device-disjoint evaluation, and explicit rejection of unsupported live claims.

## Blocking Reality

Detection and blocking are separate. The laptop can record and classify traffic involving the registered ESP32. A host firewall on the same laptop cannot reliably block another Wi-Fi client from reaching the ESP32 directly. The current `protected` response is therefore correct when the collector laptop is also the observed source: it preserves telemetry and records that an automated block was intentionally not applied.

For a real block demonstration, place the enforcement point at the Wi-Fi gateway/AP or route the ESP32 through a lab gateway with a separate attacker source. Keep `FIREWALL_MODE=dry-run` until the topology and rollback procedure are tested.

## Honest Presentation Claim

> The system detects abnormal network-flow behavior of a registered ESP32 in an isolated lab using a real-data, schema-matched binary model. It can attribute the demonstrated bounded probe pattern, records unsupported families as unknown, and does not claim universal IoT attack classification or gateway blocking until those components are independently validated.
