# Security and Enforcement Scope

Default FIREWALL_MODE=dry-run. Demo blocks always remain simulated, including when active mode is configured. The demo packet source is an in-memory object, not a real attacker.

## Active host rules

Only enable on an authorized disposable lab host. Set FIREWALL_MODE=active, ACTIVE_FIREWALL_ACK=HOST_ONLY_CONFIRMED, ADMIN_TOKEN and PROTECTED_IPS containing the host, gateway, sensor controller and trusted management addresses. Local interfaces/gateways are also discovered and registered sensors protected. Verify that discovery includes every management address, especially IPv6 and VPN routes, before enabling. Elevated OS privileges are required; the demo does not request them.

Windows uses validated IP literals in fixed PowerShell commands and two uniquely named New-NetFirewallRule rules (inbound/outbound). Linux uses iptables/ip6tables INPUT source and OUTPUT destination rules with application-owned comments and existence checks. Neither flushes existing rules. Both adapters protect only the backend host, not peer IoT devices or forwarded traffic.

Two adjacent qualifying malicious windows are required for automatic block; default probability >=0.9, risk>=85, TTL120s. Detection threshold is 0.8. Manual rules are explicit dashboard/API actions. Registered sensor addresses, loopback, multicast, link-local, host and protected gateway addresses cannot be blocked. This deliberately prevents automatic isolation of a registered compromised sensor: use a separately designed quarantine policy for that use case.

Rule intent is persisted before commands execute. Partial failure is `cleanup_required`; inspect/remove application-owned rules before considering it resolved. Expiry is application-driven and graceful shutdown attempts cleanup. If the process is killed, restart it to expire/remove rules, or manually remove only `updated-iot-*` rules/comments after inspection. This is not a crash-independent firewall TTL system. Restart does not prove OS rules still exist; inspect the actual firewall when using active mode.

Active adapters are command-generation/mock tested only, **not verified by changing this machine's firewall**. Successful OS command execution is not independent packet-delivery verification. Packet spoofing and NAT undermine source attribution; do not automatically block unreviewed public production traffic.

## Access and data

Management API is local-only without ADMIN_TOKEN. Configure a strong token for remote use. Browser origin and Host checks reduce cross-site requests; do not expose the demo publicly. The telemetry token is shared, not per-device cryptographic identity. Sequence checks are best-effort replay resistance and permit reset on reduced uptime; use signed messages with boot nonces for stronger replay protection. TLS, device-specific keys, rate limiting and reverse-proxy hardening are remaining production work.

PCAPs and IP-address logs may contain sensitive metadata. Capture only authorized devices, restrict runtime directory access, limit recordings and archive/delete data according to your lab policy. No arbitrary shell command, packet sender, model upload or external attack target endpoint is exposed.
