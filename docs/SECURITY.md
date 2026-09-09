# Security Boundaries

Use only networks/devices you own or have permission to monitor. Recorded IoT-23 analysis sends no attack traffic and cannot trigger firewall or sensor alarms.

Use ADMIN_TOKEN for non-loopback administration, IOT_TELEMETRY_TOKEN for device telemetry and ZEEK_INGEST_TOKEN for collector ingestion. Keep secrets outside source control. Use HTTPS or an isolated trusted lab for transport. Treat collector credentials as privileged: forged flow records could influence decisions once live validation is enabled.

Joblib is executable serialization. Load only trusted locally trained artifacts. Model schema, provenance and sklearn version checks are compatibility checks, not proof of safety or accuracy.

The original IoT-23 candidate failed evaluation and remains restricted to recorded analysis. The separately promoted model is limited to the labelled private lab capture and matching `scapy-lab-flow-v1` extractor. Missing telemetry or unavailable ML must not be represented as a confirmed attack. A malicious live flow outside the documented TCP probe pattern remains `unknown_attack_pattern`, not a guessed attack family.

Firewall defaults to dry-run. Active host rules require explicit configuration/acknowledgement and protected addresses. A host firewall does not protect a separate sensor from traffic that never passes through that host. Gateway enforcement remains unimplemented. Test rule expiry/recovery independently before any active deployment.

Logs contain network metadata. Keep downloaded datasets and runtime artifacts out of public commits and follow dataset licensing/attribution requirements.
