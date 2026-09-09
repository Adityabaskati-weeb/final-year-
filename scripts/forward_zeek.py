"""Forward new JSON conn.log lines from an authorized Zeek collector."""
import argparse
import os
from pathlib import Path
import sys
import time
import httpx
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.zeek import Tail

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True)
    parser.add_argument("--server", default="http://127.0.0.1:8020")
    args = parser.parse_args()
    token = os.environ.get("ZEEK_INGEST_TOKEN")
    if not token:
        parser.error("Set ZEEK_INGEST_TOKEN in the collector environment")
    tail = Tail(args.log)
    with httpx.Client(timeout=10, headers={"X-Zeek-Token": token}) as client:
        while True:
            rows = tail.poll()
            for start in range(0, len(rows), 100):
                batch = rows[start:start+100]
                for attempt in range(3):
                    try:
                        response = client.post(args.server.rstrip("/") + "/api/zeek/flows", json={"records": batch})
                        response.raise_for_status()
                        print(response.json(), flush=True)
                        break
                    except httpx.HTTPError:
                        if attempt == 2:
                            raise
                        time.sleep(1)
            time.sleep(.25)
