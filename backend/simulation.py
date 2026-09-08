"""Synthetic packet objects only. No sockets, raw sends, external targets or exploits."""
import random
from .features import Packet, SECONDS, Windows

SCENARIOS = ("normal", "port_scan", "connection_flood", "udp_burst", "connection_retry")
TARGET = "10.77.0.20"
SOURCE = "10.77.0.55"


def packets(scenario, start, seed, source=SOURCE, target=TARGET):
    if scenario not in SCENARIOS:
        raise ValueError("Unknown lab scenario")
    rng = random.Random(seed)
    count = rng.randint(5, 35) if scenario == "normal" else rng.randint(70, 160)
    if scenario in {"connection_flood", "udp_burst"}:
        count = rng.randint(240, 480)
    times = sorted(start + rng.uniform(0.01, SECONDS - 0.01) for _ in range(count))
    fixed_port = rng.choice([80, 443, 1883, 8080])
    for index, timestamp in enumerate(times):
        flags = 16 if scenario == "normal" else 2
        if scenario == "connection_retry":
            flags = 4 if index % 2 else 2
        protocol = "UDP" if scenario == "udp_burst" else "TCP"
        yield Packet(timestamp, source, target,
                     rng.randint(30000, 60000) if scenario != "normal" else 41000,
                     index + 1 if scenario == "port_scan" else fixed_port,
                     protocol, rng.randint(60, 220) if scenario != "udp_burst" else rng.randint(400, 1200), flags)


def dataset(seed=42, sessions_per_class=10):
    rows = []
    for class_index, scenario in enumerate(SCENARIOS):
        for session in range(sessions_per_class):
            group = f"{scenario}-{session}"
            extractor = Windows()
            for window in range(6):
                start = (class_index * 10000 + session * 100 + window) * SECONDS
                for packet in packets(scenario, start, seed + class_index * 100000 + session * 100 + window):
                    extractor.push(packet)
                for row in extractor.flush(start + SECONDS):
                    rows.append({**row, "label": scenario, "session": group,
                                 "split": "test" if session >= sessions_per_class - 3 else "train"})
    return rows
