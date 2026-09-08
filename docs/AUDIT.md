# Audit and Delivery Record

## Existing project inspection

Reviewed the newer improvised-cyber-attack backend entry point, device monitor/capture design, shared flow extractor, live trainer/inference code, model wrappers, database, tests, README/live-training guidance, frontend package configuration and ESP32 sketch. Inspected the original project's model wrappers, dataset documentation, notebook/file inventory and model locations. This was a code/data-contract audit, not re-execution of every original notebook or proof that every documented dataset had been trained.

Findings: original Kitsune wrapper uses 116 input fields, Edge-IIoT expects its named-column schema; neither matches live ESP32 packet features. The newer aggregate live path used a different 12-field device window and did not establish attacker-source identity suitable for blocking. Old near-perfect notebook metrics are not evidence of live generalization. The newer README correctly stated that no validated live model was installed. Retaining incompatible artifacts would obscure that gap.

## Selective reuse

Copied only the ESP32 sketch; retained DHT/OLED/LED/buzzer wiring, bounded alert pulses and telemetry field contract. Updated endpoint configuration and exact response-header status parsing. Preserved the useful concepts of explicit capture, registry, fixed-window features, shared preprocessing, session-based evaluation and honest UNKNOWN status. Did not copy secrets, databases, old alerts, model weights or old dependency folders.

Rewrote backend service, source-keyed 13-field extractor, trainer, strict model loader, response adapters, authenticated API, SQLite records, synthetic scenario generator and dashboard. Kept FastAPI/React/scikit-learn/Scapy because they already suit the problem; removed legacy autoencoder/wrapper UI and SQLAlchemy complexity from the new project. Chose Random Forest over a new deep-learning dependency for small tabular features, reproducibility and practical latency.

## Implemented acceptance scope

Offline regression suite covers feature order/nonfinite input, Scapy parsing, model provenance, leakage rejection, protected addresses, dry-run dedup/expiry, adapter command generation, failed-active-state semantics, API authorization, registry duplicate handling, WS snapshots, telemetry authentication/replay, and model-to-simulated-block behavior.

The initial training run used 210 synthetic train and 90 synthetic test windows. Binary confusion matrix [[18,0],[0,72]], all reported binary classification metrics 1.0, inference median about 5.94ms and p95 6.60ms on this laptop. Generated runtime report is authoritative for subsequent runs. This is a pipeline sanity result, not real-world validation.

## Not claimed complete

Local verification: production Vite build passed (one non-fatal bundle-size warning), 12 regression tests passed, and `scripts/verify_demo.py` verified the running HTTP server through rejection of later simulated traffic. Browser inspection at 1440x900 and 390x844 confirmed rendered dashboard/timeline views; no browser error logs were reported. Default run remains loopback-only and dry-run. No GitHub remote was created or code published.

- Real sensor capture visibility, uploaded firmware, physical OLED/buzzer/LED response.
- Validated real-PCAP model; multiple sensor/device generalization.
- Gateway/bridge forwarding enforcement that protects another device.
- Actual OS firewall installation/effect verification and crash-independent expiry.
- Payload-level brute-force, malformed-message or botnet attribution; SHAP/calibration.
- Production authentication/TLS, automatic retention, high-throughput load validation.
- Docker runtime verification (recipe provided).

Prioritize physical connection and passive recordings next, then independent real-label evaluation and hardware feedback. Add gateway enforcement only after verifying routing and management protections. Keep the synthetic demo available as a separate regression/presentation mode throughout.
