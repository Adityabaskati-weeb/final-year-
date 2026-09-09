"""Optional live attack-family model with strict artifact validation."""
from pathlib import Path
import hashlib
import json
import warnings

import joblib
import numpy as np
import sklearn

from .features import FEATURES, SCHEMA, features


class AttackFamilyDetector:
    def __init__(self, path):
        self.bundle = None
        self.model_sha256 = None
        self.error = "No promoted attack-family model installed"
        if not path or not Path(path).is_file():
            return
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                bundle = joblib.load(path)
            report = bundle["report"]
            classes = set(bundle["model"].classes_)
            if (bundle.get("schema") != SCHEMA or bundle.get("features") != FEATURES
                    or bundle.get("provenance") != "real_lab_capture"
                    or bundle.get("task") != "attack_type"
                    or bundle.get("sklearn_version") != sklearn.__version__
                    or "normal" not in classes or len(classes) < 3
                    or report.get("task") != "attack_type"
                    or type(report.get("eligible")) is not bool
                    or type(report.get("live_validated")) is not bool):
                raise ValueError("Attack-family model contract mismatch")
            if not self._promotion(Path(path)):
                raise ValueError("Attack-family model has no verified live promotion evidence")
            self.bundle = bundle
            with Path(path).open("rb") as stream:
                self.model_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
            self.error = None
        except Exception as error:
            self.error = str(error)

    @staticmethod
    def _promotion(path):
        try:
            promotion = json.loads(path.with_name("promotion.json").read_text(encoding="utf-8"))
            with path.open("rb") as stream:
                model_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            if promotion.get("model_sha256") != model_hash or promotion.get("task") != "attack_type":
                return False
            evidence = (path.parent / promotion["evidence_file"]).resolve()
            if not evidence.is_relative_to(path.parent.resolve()):
                return False
            raw = evidence.read_bytes()
            validation = json.loads(raw)
            return (hashlib.sha256(raw).hexdigest() == promotion.get("evidence_sha256")
                    and validation.get("task") == "attack_type"
                    and validation.get("model_sha256") == model_hash
                    and validation.get("schema") == SCHEMA
                    and validation.get("independent_sessions") is True
                    and validation.get("macro_f1", 0) >= 0.8)
        except (OSError, ValueError, KeyError, TypeError):
            return False

    def status(self):
        report = self.bundle["report"] if self.bundle else None
        return {"ready": self.bundle is not None, "error": self.error, "schema": SCHEMA,
                "task": "attack_type", "model_sha256": self.model_sha256,
                "response_eligible": self.bundle is not None,
                "live_validated": self.bundle is not None,
                "report": report,
                "expected_extractors": sorted((report or {}).get("data_quality", {}).get("extractors", []))}

    def compatible_extractor(self, extractor):
        if not self.bundle or not isinstance(extractor, str):
            return False
        report = self.bundle["report"]
        quality = report.get("data_quality", {})
        return extractor in set(quality.get("extractors", []))

    def predict(self, raw):
        if not self.bundle:
            return None
        values = features(raw)
        array = np.array([[np.nan if values[name] is None else values[name] for name in FEATURES]], dtype=object)
        probabilities = self.bundle["model"].predict_proba(array)[0]
        index = int(np.argmax(probabilities))
        return str(self.bundle["model"].classes_[index]), float(probabilities[index])
