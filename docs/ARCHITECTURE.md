# Architecture

Single-process FastAPI owns the SQLite database, capture lifecycle and response engine. Packet callbacks only enqueue validated packet metadata into a 2,048-entry queue. The worker drains it and flushes completed windows even when traffic stops. It records dropped packets/windows. Capture is manual and restricted to registered physical destination IPs. A normal Wi-Fi client cannot see arbitrary peer traffic; use a lab mirror/gateway for that visibility.

`features.py` groups source/destination/protocol in fixed five-second windows. Counters and moments bound per-window memory, with at most 4,096 active keys and capped distinct port sets. Raw sensor values are not mixed into packet features. `detection.py` requires the exact feature contract, provenance, sklearn version and a passed evaluation report. No missing features are zero-filled.

`service.py` persists every classified window in traffic and malicious windows in detections. Alerts are suppressed for 30 seconds per origin/source/target. Response needs two consecutive five-second qualifying windows. Risk is rounded attack probability times 100, not a calibrated measure of damage. A type is the highest-scoring learned attack class, not a signature-confirmed exploit.

`firewall.py` handles protected IPs, dry-run, rule idempotence, TTL and release. Demo/live namespaces are separate. Partial OS failures remain `cleanup_required`, never successful blocks. Crash-persisted active intents need cleanup; graceful shutdown attempts removal. OS rules do not have an independent TTL watchdog if the process crashes: follow SECURITY.md.

SQLite stores JSON records in devices/readings/traffic/detections/alerts/blocks/events/models tables with indexed timestamps. Model readiness/report is loaded from the versioned artifact. Dashboard traffic and alert views are the latest 200 records of the current server session; history and block state persist. These are not total historical counters. Automatic database retention is not enabled: archive data periodically for long-running use.

## API

GET `/health`, `/api/system/status`, `/api/interfaces`, `/api/models`, `/api/devices`, `/api/readings`, `/api/traffic`, `/api/alerts`, `/api/detections`, `/api/blocklist`, `/api/history`.

POST `/api/devices`, `/api/telemetry`, `/api/firewall/block`, `/api/firewall/unblock`, `/api/simulation/start`, `/api/simulation/stop`, `/api/monitoring/start`, `/api/monitoring/stop`.

WS `/ws/events`: first send `{"token":""}` (or configured admin token), then receive full one-second snapshots. Reconnection replaces client state rather than duplicating alerts. Tokens are not sent in query strings.

Without an admin token, management access is loopback-only. Setting ADMIN_TOKEN requires Bearer authorization for management REST and token authentication for WS. Sensor telemetry uses a separate X-IoT-Token, source-IP registration and sequence checking. HTTP is suitable only for an isolated trusted lab; use TLS and per-device identities for deployment.
