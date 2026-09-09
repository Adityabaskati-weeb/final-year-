"""Tail completed Zeek JSON connections; never manufacture flow fields."""
import json
from pathlib import Path


class Tail:
    def __init__(self, path):
        self.path = Path(path)
        stat = self.path.stat()
        self.identity = (stat.st_dev, stat.st_ino)
        self.offset = stat.st_size  # A live start must not replay historical records.
        self.pending = b""

    def poll(self):
        stat = self.path.stat()
        identity = (stat.st_dev, stat.st_ino)
        if identity != self.identity or stat.st_size < self.offset:
            self.identity, self.offset, self.pending = identity, 0, b""
        with self.path.open("rb") as file:
            file.seek(self.offset)
            chunk = file.read(262144)
            self.offset = file.tell()
        self.pending += chunk
        lines = self.pending.split(b"\n")
        self.pending = lines.pop()
        if len(self.pending) > 1_000_000:
            raise ValueError("Oversize Zeek JSON line")
        result = []
        for line in lines:
            if line.strip():
                result.append(json.loads(line))
        return result
