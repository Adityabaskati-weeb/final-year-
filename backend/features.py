"""Same bounded source/destination window schema for PCAP, live capture and demo."""
from dataclasses import dataclass
import ipaddress
import math

SCHEMA = "source-window-v1"
SECONDS = 5
FEATURES = ["packets_per_second", "bytes_per_second", "packet_count", "mean_bytes",
            "std_bytes", "syn_fraction", "rst_fraction", "ack_fraction", "udp_fraction",
            "unique_destination_ports", "unique_source_ports", "mean_gap", "std_gap"]


@dataclass(frozen=True)
class Packet:
    timestamp: float
    source: str
    destination: str
    source_port: int = 0
    destination_port: int = 0
    protocol: str = "TCP"
    size: int = 60
    flags: int = 0

    def __post_init__(self):
        for address in (self.source, self.destination):
            ipaddress.ip_address(address)
        if not math.isfinite(self.timestamp) or self.timestamp < 0 or not 0 <= self.size <= 1048576:
            raise ValueError("Invalid timestamp or packet size")
        if any(not 0 <= port <= 65535 for port in (self.source_port, self.destination_port)):
            raise ValueError("Invalid port")
        if self.protocol not in {"TCP", "UDP", "ICMP", "OTHER"}:
            raise ValueError("Unsupported protocol")

    @classmethod
    def from_scapy(cls, packet):
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        ip = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip is None:
            return None
        transport = packet.getlayer(TCP) or packet.getlayer(UDP)
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if int(getattr(ip, "proto", getattr(ip, "nh", 0))) in (1, 58) else "OTHER"
        return cls(float(packet.time), str(ip.src), str(ip.dst),
                   int(transport.sport) if transport else 0, int(transport.dport) if transport else 0,
                   protocol, len(bytes(ip)), int(packet[TCP].flags) if TCP in packet else 0)


class Windows:
    def __init__(self, max_flows=4096):
        self.rows = {}
        self.max_flows = max_flows
        self.dropped = 0
        self.watermark = -1.0

    def push(self, packet):
        if packet.timestamp < self.watermark:
            self.dropped += 1
            return []
        finished = self.flush(packet.timestamp)
        start = math.floor(packet.timestamp / SECONDS) * SECONDS
        key = (packet.source, packet.destination, packet.protocol)
        if key not in self.rows and len(self.rows) >= self.max_flows:
            self.dropped += 1
            return finished
        row = self.rows.setdefault(key, dict(start=start, n=0, total=0, total2=0,
            syn=0, rst=0, ack=0, udp=0, sport=set(), dport=set(), gap=0, gap2=0, last=packet.timestamp))
        gap = max(0, packet.timestamp - row["last"]) if row["n"] else 0
        row["n"] += 1
        row["total"] += packet.size
        row["total2"] += packet.size ** 2
        for name, bit in (("syn", 2), ("rst", 4), ("ack", 16)):
            row[name] += int(bool(packet.flags & bit))
        row["udp"] += packet.protocol == "UDP"
        for name, port in (("sport", packet.source_port), ("dport", packet.destination_port)):
            if len(row[name]) < 256:
                row[name].add(port)
        row["gap"] += gap
        row["gap2"] += gap ** 2
        row["last"] = packet.timestamp
        return finished

    def flush(self, now):
        self.watermark = max(self.watermark, math.floor(now / SECONDS) * SECONDS)
        finished = []
        for key, row in list(self.rows.items()):
            if row["start"] + SECONDS > now:
                continue
            n, total = row["n"], row["total"]
            gap_n = max(1, n - 1)
            mean, gap = total / n, row["gap"] / gap_n
            values = [n / SECONDS, total / SECONDS, n, mean,
                      math.sqrt(max(0, row["total2"] / n - mean ** 2)),
                      row["syn"] / n, row["rst"] / n, row["ack"] / n, row["udp"] / n,
                      len(row["dport"]), len(row["sport"]), gap,
                      math.sqrt(max(0, row["gap2"] / gap_n - gap ** 2))]
            finished.append(dict(source_ip=key[0], destination_ip=key[1], protocol=key[2],
                                 window_start=row["start"], features=dict(zip(FEATURES, values))))
            del self.rows[key]
        return finished


def vector(features):
    if set(features) != set(FEATURES):
        raise ValueError("Missing or extra features; exact schema required")
    values = [float(features[key]) for key in FEATURES]
    if any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("Features must be finite non-negative numbers")
    return values
