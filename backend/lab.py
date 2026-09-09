"""Explicit private lab target authorization; no discovery or active probing."""
import ipaddress
from pathlib import Path
import yaml

PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def authorized_target(path, target):
    address = ipaddress.ip_address(target)
    if not any(address in network for network in PRIVATE):
        raise ValueError("Only explicitly configured RFC1918/ULA lab targets are allowed")
    config = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    entries = config.get("targets") if isinstance(config, dict) else None
    if not isinstance(entries, list):
        raise ValueError("Lab configuration must contain a targets list")
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("device_id") or "ip" not in entry:
            raise ValueError("Invalid lab target entry")
        if ipaddress.ip_address(entry["ip"]) == address:
            return str(address)
    raise ValueError("Target is not explicitly allowlisted; confirm its current device ownership first")
