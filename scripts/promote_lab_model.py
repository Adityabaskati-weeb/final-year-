"""Create promotion evidence for a model after an independent lab validation passes."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.features import SCHEMA


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--validation", type=Path, required=True)
    args = parser.parse_args()
    bundle = __import__("joblib").load(args.model)
    validation_bytes = args.validation.read_bytes()
    validation = json.loads(validation_bytes)
    model_sha = hashlib.sha256(args.model.read_bytes()).hexdigest()
    if bundle.get("provenance") != "real_lab_capture" or not bundle["report"].get("eligible"):
        raise ValueError("Only an eligible real_lab_capture model can be promoted")
    if validation.get("provenance") != "labelled_lab_capture" or validation.get("model_sha256") != model_sha:
        raise ValueError("Validation provenance or model hash does not match")
    if validation.get("schema") != SCHEMA or validation.get("independent_sessions") is not True:
        raise ValueError("Independent schema-compatible validation is required")
    if validation.get("attack_samples", 0) < 20 or validation.get("normal_samples", 0) < 100:
        raise ValueError("Minimum validation sample gate is not met")
    if validation.get("recall", 0) < 0.8 or validation.get("false_positive_rate", 1) > 0.05:
        raise ValueError("Validation quality gate is not met")
    config = json.dumps(validation.get("extractor_config", {}), sort_keys=True).encode("utf-8")
    promotion = {
        "model_sha256": model_sha,
        "schema": SCHEMA,
        "extractor_version": validation["extractor_version"],
        "extractor_config_sha256": hashlib.sha256(config).hexdigest(),
        "evidence_file": args.validation.name,
        "evidence_sha256": hashlib.sha256(validation_bytes).hexdigest(),
        "promoted_at": __import__("time").time(),
        "scope": "registered private lab device and matching packet extractor only",
    }
    output = args.model.with_name("promotion.json")
    output.write_text(json.dumps(promotion, indent=2), encoding="utf-8")
    print(json.dumps(promotion, indent=2))


if __name__ == "__main__":
    main()
