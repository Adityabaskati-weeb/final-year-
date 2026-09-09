# Architecture

Training: official labelled IoT-23 logs -> shared Zeek schema -> capture-disjoint splits -> train-only preprocessing -> Random Forest -> validation threshold -> independent test report -> candidate artifact.

Recorded analysis: downloaded log -> shared schema -> candidate -> historical results -> SQLite -> REST/WebSocket -> dashboard. It never sends attack traffic or controls a physical device.

Live: visible network traffic -> either an external Zeek collector or the explicit Scapy/Npcap lab adapter -> completed flow records -> freshness/device checks -> shared schema -> validation gate -> binary decision -> documented lab attribution -> dashboard/telemetry response. The promoted lab model can attribute the bounded TCP connection probe used in the acceptance test; other malicious flows remain `unknown_attack_pattern` until a compatible multiclass model is trained and validated.

Telemetry: ESP32 -> authenticated HTTP readings -> storage/status response -> firmware display. Sensor values do not become network attack labels.

Start capture is explicit. Local Zeek tailing starts at EOF, skips historical content and waits for completed lines. Scapy capture applies a host filter to registered device IPs and flushes flows after a short idle period or on stop. Duplicate connection IDs/timestamps are suppressed. Completed-flow logging introduces detection latency; long-running connections may not appear immediately.

Host firewall response is dry-run by default. A source that is the collector laptop, gateway or registered sensor is recorded as `protected` and is never blocked because doing so would destroy telemetry and/or the monitoring path. A real block requires a separate attack source or an explicitly configured gateway; gateway forwarding enforcement and end-to-end real sensor protection have not been implemented/validated.

API documentation is served at /docs. Key routes: /api/system/status, /api/captures, /api/analysis/start, /api/analysis/stop, /api/zeek/flows, plus existing device/telemetry/monitoring routes. Synthetic simulation routes have been removed.
