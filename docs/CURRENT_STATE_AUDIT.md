# Recovery Audit - 2026-09-09

## State found on resume

The working tree contained uncommitted replacement of the synthetic 13-feature pipeline with official IoT-23/Zeek training. These changes were preserved, not reset. FastAPI, React, WebSockets, SQLite, firmware wiring and host firewall adapters remain.

Ten existing tests passed on resume; Vite production build passed with a nonfatal large-chunk warning. The prior new backend ran on 8021 because an older backend occupied 8020. Health/status and recorded-data analysis had passed. Do not confuse the old process with the new implementation.

## Working real components

- Nine official labelled IoT-23 logs, source URLs and SHA-256 manifest in runtime/iot23.
- Actually fitted Random Forest and report in runtime/iot23-model. Candidate inference works on recorded records.
- Capture-disjoint train/validation/test, train-only imputation/encoding, validation-selected threshold, exact-overlap checks.
- Authenticated HTTP telemetry route and preserved ESP32 firmware (DHT11 GPIO4, OLED I2C21/22, LED15, buzzer19). No physical upload or hardware response was verified on resume.
- Authenticated completed-Zeek-flow ingestion, explicit start/stop, freshness/device checks. Local JSON tail starts at EOF.
- Windows Scapy sees Npcap interfaces; active Wi-Fi laptop address is 192.168.31.138 at inspection. Addresses can change.

## Failed / missing

- Candidate held-out recall 0/20, FPR 283/3197, accuracy 90.58%. This is failed evaluation, not deployment readiness.
- Zeek and tshark executables were not found. Npcap availability alone does not produce Zeek-compatible features.
- No current physical device registered in the new runtime; current sensor Wi-Fi IP requested. No serial port was observed by the registry check. Hardware connectivity is unverified, not simulated.
- No verified gateway topology, real block verification or end-to-end physical alarm experiment. Host firewall cannot protect off-path sensors.

## Synthetic / dry-run status

Active synthetic generator, training command and simulation routes were removed. Old ignored runtime files may remain but are excluded from current views/model loading. Unit fixtures are tests only. Dry-run firewall records are administrative simulations, not proof of blocked traffic; they must never be exported as verified attack evidence.

## Previous IoT-23 work

Found C:/Users/baska/hpx-1/iot-ai-cyber-attack-detection/artifacts and src/iot_ids. Retained in place. Its model manifest reports validation recall/F2 zero, train F2 1, and a different engineered schema with history/port-bucket fields. Original dataset_root points to a missing ml system/data location. A demo profile here may mean a real-data subset, not fabricated rows; provenance must be checked separately. Existing artifacts are not a verified drop-in fix. Preserve its capture-level methodology as reference, not its reported training score as validation.

## Architecture retained

Official logs -> shared Zeek fields -> fitted preprocessing/RF -> recorded analysis.

Real sensor network -> external real Zeek collector -> same fields -> validation gate -> live decision -> telemetry response/dashboard. Current gate remains closed (UNKNOWN).

## Work in this continuation

Per-capture/false-negative metrics, source-traceable evidence export, repository audit, bounded real-PCAP collection/conversion tooling and environment diagnostics are implemented. Unavailable hardware, Zeek and gateway steps remain explicitly incomplete. No attacks or firewall changes are authorized against unconfirmed IP addresses.

## Verified after continuation

19 tests passed and frontend rebuilt. Updated backend is running on 8020 with explicit v2 model selection. Actual v2 training on untouched holdouts: recall 34.375%, precision 1.165%, FPR 19.597%, confusion [[3828,933],[21,11]]. Still FAILED. Historical artifacts preserved.

Exported 237 genuine recorded connections with model/source hashes, JSON, flow/features parquet and Markdown report under evidence/iot23-recorded-20260909. Missing PCAP and block verification are explicit. No live attack was run.

Follow-up diagnostics found COM3. The current board is reachable at the registered private address 10.81.27.229 and telemetry is accepted through the compatibility listener. The Windows Wi-Fi adapter captures bidirectional ESP32 traffic through the explicit `scapy-lab-flow-v1` path. The original IoT-23 model remains failed; a separate lab-scoped model was trained and hash-promoted only after independent normal/probe sessions. Updated firmware source is prepared but not uploaded; model-driven OLED/LED/buzzer response still needs direct serial verification.
