# Real Lab Acceptance

## Preconditions

Confirm the sensor's CURRENT Wi-Fi IP from Serial Monitor. Configure that exact private IP and device_id in config/lab_targets.yaml. Default is empty, so no target is authorized. Never use an old IP without checking ownership. Register the same IP/device ID in the dashboard. Configure the matching telemetry token privately; do not commit secrets.h or .env.

Current environment check: Windows Npcap interfaces are available and the connected ESP32 was observed exchanging TCP packets with this laptop. USB does not provide network flows. The local Scapy adapter is intentionally limited to registered private lab targets; it is not a general Wi-Fi monitor.

## Local live capture

Set `SCAPY_CAPTURE_INTERFACE` to the exact Npcap interface name, restart the backend, register the ESP32's current private IP, choose **Live Npcap** in the dashboard, and click **Start capture**. The dashboard then stores real packet-derived flow records. A normal row with `prediction: unknown` is expected until a model is independently validated and promoted.

For a labelled session, use the recorder only after configuring the same current device IP in `config/lab_targets.yaml`:

```powershell
python scripts/capture_lab_flows.py --interface "ACTUAL_NPCAP_INTERFACE" --target CURRENT_SENSOR_IP --port 8010 --label normal --split train --capture-id train-normal-01 --seconds 120 --output evidence/lab-flows/train-normal-01.jsonl
```

Repeat for explicitly observed normal and controlled lab-attack phases. The recorder is passive and never launches traffic; only assign `attack` when an independently documented experiment was actually running against the owned private target.

For a bounded, allowlisted TCP connection phase against the current owned device, capture only the probe port in a separate session and run this while that capture is active:

```powershell
python scripts/bounded_lab_probe.py --target CURRENT_SENSOR_IP --port 80 --connections 25 --interval-ms 100
```

This is a small lab probe for repeatable evidence, not a public-network attack tool. Keep the target in the private allowlist and stop the capture after the phase.

## Passive evidence capture

From the project directory:

```powershell
python scripts/check_environment.py
python scripts/record_session.py --list-interfaces
python scripts/record_session.py --interface "ACTUAL_NPCAP_INTERFACE_ID" --target CURRENT_SENSOR_IP --seconds 60 --output evidence/session-01/capture.pcap
```

The recorder is passive, target-filtered, bounded to 600 seconds / 100,000 packets. It reports an empty capture as incomplete, not success. It emits capture.pcap.json with time, target, count and SHA-256. It does not assign attack labels; keep an independently observed experiment log. Configure no public target. No attack generator is bundled or automatically executed.

## Real extraction on Linux with Zeek

Transfer the genuine PCAP to your own Linux collector, install project dependencies and Zeek, then:

```sh
python scripts/zeek_from_pcap.py --pcap /absolute/path/capture.pcap --output evidence/session-01/zeek
```

Output directory must be new. The script invokes actual Zeek, validates emitted conn.log fields, and records input hash, extractor version and arguments. It does not inject packets onto a network or mark historical records live. Empty/invalid extraction fails rather than padding fields. No successful physical capture/conversion is claimed until run against the actual setup.

For live logging/forwarding use docs/DEMO.md. A new connection log is needed after starting monitoring because tailing starts at EOF.

## Firmware

The preserved pin mapping is unchanged. Updated source adds boot IDs to reject replay of prior sessions and shows unavailable readings as --, not zero. It has NOT been compiled/uploaded on the board in this continuation. Existing firmware without boot_id works while sequence/uptime are monotonic; after reboot it requires explicit re-registration or the updated firmware. New boot sessions retire the old ID; a reboot not distinguishable by lower uptime also requires re-registration. Keep TLS/isolated-lab transport: shared HTTP tokens do not defend against a compromised credential.

## Model promotion

Candidate training does not automatically enable live predictions. Use `build_lab_manifest.py` for capture-disjoint train/validation/test files, then `python -m ml.train` to create a `real_lab_capture` candidate. Run `validate_lab_model.py` on independent test sessions and `promote_lab_model.py` only if the exact model hash, schema, extractor and evidence meet the gates. Minimum checked counts are 20 attack and 100 normal samples, recall >=0.8 and FPR <=0.05; these are minimum gates, not proof of generalization. Training still leaves live protection disabled. No promotion record is created for a failed/unverified model. Do not hand-edit flags to pretend validation occurred. Promotion records are trusted local configuration, not cryptographic certification of truth.

For legacy malicious capture metadata without an explicit family label, pass `--default-attack-type` with the label from the controlled experiment plan, for example `--default-attack-type tcp_connection_probe`. Do not use `unknown` as a training family. New captures should carry `attack_type` metadata when recorded.

## Firewall acceptance

States are dry_run, block_requested, block_applied, block_failed and released. block_applied means OS command success only. verified is false until independent connectivity evidence exists; no endpoint fabricates verification. Scope is host, never gateway. No block_verified record currently exists. Legacy blocked rows are displayed as unverified applied rules.

Actual ESP32 protection requires an explicitly configured gateway in the attack path, before/after connectivity tests, recovery/TTL verification and preserved PCAP evidence. This topology is not configured here. Do not enable active rules to compensate for missing visibility or a failed model. Coordinate the isolated lab target, attack source, gateway and experiment limits before any real attack.

The current acceptance path is therefore: real packets from the private lab sensor are captured by Npcap, the promoted binary model marks the bounded TCP probe as malicious, the application labels it `tcp_connection_probe`, and the response engine requests a host block. Because the current probe originates from the same laptop running the collector, that source is deliberately recorded as `protected` instead of blocked. Use a second private lab machine as the attack source to demonstrate an actual host-level block without disconnecting the collector or sensor telemetry.
