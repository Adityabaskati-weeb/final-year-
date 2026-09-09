"""Audit the claims a local model artifact can support."""
import argparse
import json
from pathlib import Path
import sys

import joblib

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.scope import summarize_sources


def audit(path):
    path = Path(path).resolve()
    bundle = joblib.load(path)
    report = bundle.get("report", {})
    provenance = bundle.get("provenance", report.get("provenance", "unknown"))
    sources = report.get("sources", [])
    data_quality = report.get("data_quality") or summarize_sources(sources, provenance)
    task = bundle.get("task", report.get("task", "binary"))

    if task == "attack_type":
        decision = "attack-family model is not live-ready until independent live validation and promotion"
    elif provenance == "real_lab_capture" and data_quality["deployment_scope"] == "registered_device_only":
        decision = "binary live candidate is limited to the registered device/topology"
    elif provenance == "real_iot23":
        decision = "offline dataset model only; no ESP32/live claim"
    else:
        decision = "manual review required"

    return {
        "model": str(path),
        "task": task,
        "schema": bundle.get("schema"),
        "provenance": provenance,
        "eligible": report.get("eligible"),
        "live_validated": report.get("live_validated"),
        "data_quality": data_quality,
        "decision": decision,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.model), indent=2))
