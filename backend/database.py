import json
import sqlite3
import threading
import time
import uuid


class Store:
    TABLES = {"devices", "readings", "traffic", "detections", "alerts", "blocks", "events", "models"}

    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        for table in self.TABLES:
            self.db.execute(f"CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, ts REAL, data TEXT)")
            self.db.execute(f"CREATE INDEX IF NOT EXISTS ix_{table}_ts ON {table}(ts)")
        self.db.commit()

    def put(self, table, row):
        if table not in self.TABLES:
            raise ValueError("Unknown collection")
        row = {"id": str(uuid.uuid4()), "timestamp": time.time(), **row}
        with self.lock:
            self.db.execute(f"INSERT OR REPLACE INTO {table} VALUES (?,?,?)",
                            (row["id"], row["timestamp"], json.dumps(row, allow_nan=False)))
            self.db.commit()
        return row

    def rows(self, table, limit=200, since=0):
        if table not in self.TABLES:
            raise ValueError("Unknown collection")
        with self.lock:
            rows = self.db.execute(f"SELECT data FROM {table} WHERE ts>=? ORDER BY ts DESC LIMIT ?",
                                   (since, limit)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get(self, table, key):
        if table not in self.TABLES:
            raise ValueError("Unknown collection")
        with self.lock:
            row = self.db.execute(f"SELECT data FROM {table} WHERE id=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def close(self):
        self.db.close()
