"""Promote a multiclass model only after independent same-schema validation."""
import argparse
import hashlib
import json
from pathlib import Path
import time

from backend.features import SCHEMA


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--validation", type=Path, required=True)
    args = parser.parse_args()
    import joblib
    bundle = joblib.load(args.model)
    validation_bytes = args.validation.read_bytes()
    validation = json.loads(validation_bytes)
    model_hash = hashlib.sha256(args.model.read_bytes()).hexdigest()
    classes = set(bundle["model"].classes_)
    if (bundle.get("schema") != SCHEMA or bundle.get("task") != "attack_type"
            or bundle.get("provenance") != "real_lab_capture" or "normal" not in classes or len(classes) < 3):
        raise ValueError("Only a schema-matched real_lab_capture attack-family model can be promoted")
    if (validation.get("task") != "attack_type" or validation.get("schema") != SCHEMA
            or validation.get("model_sha256") != model_hash
            or validation.get("independent_sessions") is not True
            or validation.get("macro_f1", 0) < 0.8):
        raise ValueError("Independent multiclass validation gate is not met")
    promotion = {"model_sha256": model_hash, "schema": SCHEMA, "task": "attack_type",
                 "evidence_file": args.validation.name,
                 "evidence_sha256": hashlib.sha256(validation_bytes).hexdigest(),
                 "promoted_at": time.time(),
                 "scope": "registered private lab devices and matching packet extractor only"}
    args.model.with_name("promotion.json").write_text(json.dumps(promotion, indent=2), encoding="utf-8")
    print(json.dumps(promotion, indent=2))


if __name__ == "__main__":
    main()
