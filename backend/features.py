"""Shared IoT-23 TSV / Zeek JSON connection contract. No packet approximations."""
import ipaddress
import json
import math

SCHEMA = "zeek-conn-v1"
NUMERIC = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "orig_ip_bytes",
           "resp_pkts", "resp_ip_bytes", "missed_bytes"]
CATEGORICAL = ["proto", "service", "conn_state"]
FEATURES = NUMERIC + CATEGORICAL
MISSING = (None, "", "-", "(empty)")


def features(record):
    record = {"duration": None, "orig_bytes": None, "resp_bytes": None, "service": None, **record}
    missing = set(FEATURES) - set(record)
    if missing:
        raise ValueError("Missing Zeek fields: " + ", ".join(sorted(missing)))
    result = {}
    for name in NUMERIC:
        value = record[name]
        if value in MISSING:
            result[name] = None
        else:
            value = float(value)
            if not math.isfinite(value) or value < 0:
                raise ValueError("Invalid numeric Zeek field: " + name)
            result[name] = value
    for name in CATEGORICAL:
        value = record[name]
        if value in MISSING:
            value = "unknown"
        if not isinstance(value, str) or len(value) > 80:
            raise ValueError("Invalid categorical Zeek field: " + name)
        result[name] = value
    return result


def connection(record):
    values = features(record)
    ts = float(record["ts"])
    if not math.isfinite(ts) or ts < 0:
        raise ValueError("Invalid connection timestamp")
    uid = str(record["uid"])
    if not uid or len(uid) > 128:
        raise ValueError("Invalid connection UID")
    ports = {}
    for key in ("id.orig_p", "id.resp_p"):
        port = int(record[key])
        if not 0 <= port <= 65535:
            raise ValueError("Invalid port")
        ports[key] = port
    return dict(uid=uid, started_at=ts, ended_at=ts + (values["duration"] or 0),
                source_ip=str(ipaddress.ip_address(record["id.orig_h"])),
                destination_ip=str(ipaddress.ip_address(record["id.resp_h"])),
                source_port=ports["id.orig_p"], destination_port=ports["id.resp_p"],
                protocol=values["proto"], features=values)


def binary_label(record):
    label = str(record.get("label", "")).lower()
    if label == "benign":
        return "normal"
    if label == "malicious":
        return "attack"
    raise ValueError("Unknown/missing ground-truth label")


class LogParser:
    def __init__(self):
        self.fields = None

    def parse(self, line):
        if line.startswith("#separator "):
            if line.split(" ", 1)[1].strip() != r"\x09":
                raise ValueError("Only standard Zeek tab-separated logs supported")
            return None
        if line.startswith("#fields"):
            self.fields = line.rstrip("\r\n").split("\t")[1:]
            if self.fields and "label" in self.fields[-1] and " " in self.fields[-1]:
                self.fields = self.fields[:-1] + self.fields[-1].split()
            return None
        if not line.strip() or line.startswith("#"):
            return None
        if line.lstrip().startswith("{"):
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("Expected Zeek JSON object")
            return row
        if not self.fields:
            raise ValueError("TSV log missing #fields header")
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) != len(self.fields) and len(parts) == len(self.fields) - 2:
            parts = parts[:-1] + parts[-1].split()
        if len(parts) != len(self.fields):
            raise ValueError("Zeek TSV column count mismatch")
        return dict(zip(self.fields, parts))


def read_log(path):
    parser = LogParser()
    with open(path, encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            try:
                row = parser.parse(line)
                if row is not None:
                    yield row
            except (ValueError, KeyError) as error:
                raise ValueError(f"{path}:{number}: {error}") from error
