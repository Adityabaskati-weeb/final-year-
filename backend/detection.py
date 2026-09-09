from pathlib import Path
import hashlib
import json
import math
import warnings
import joblib
import numpy as np
import sklearn
from .features import FEATURES, SCHEMA, features


class Detector:
    def __init__(self, path):
        self.bundle = None
        self.promotion_verified = False
        self.model_sha256 = None
        self.error = "No real-data Zeek model installed"
        if not path or not Path(path).is_file():
            return
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                bundle = joblib.load(path)
            if (bundle["schema"] != SCHEMA or bundle["features"] != FEATURES
                    or bundle["provenance"] not in {"real_iot23", "real_lab_capture"}
                    or bundle["sklearn_version"] != sklearn.__version__
                    or set(bundle["model"].classes_) != {"attack", "normal"}):
                raise ValueError("Model feature schema, provenance or sklearn version mismatch")
            report = bundle["report"]
            threshold = report["threshold"]
            if (type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1
                    or type(report.get("eligible")) is not bool or type(report.get("live_validated")) is not bool):
                raise ValueError("Invalid typed model report or threshold")
            self.bundle, self.error = bundle, None
            with Path(path).open("rb") as stream:
                self.model_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
            self.promotion_verified = self._promotion(Path(path))
        except Exception as error:
            self.error = str(error)

    def _promotion(self, path):
        # A locally trusted evidence record is required in addition to model flags.
        try:
            promotion = json.loads(path.with_name("promotion.json").read_text(encoding="utf-8"))
            with path.open("rb") as stream:
                if promotion["model_sha256"] != hashlib.file_digest(stream, "sha256").hexdigest():
                    return False
            evidence = path.parent / promotion["evidence_file"]
            if not evidence.resolve().is_relative_to(path.parent.resolve()):
                return False
            raw = evidence.read_bytes()
            if hashlib.sha256(raw).hexdigest() != promotion["evidence_sha256"]:
                return False
            validation = json.loads(raw)
            return bool(self.bundle and self.bundle.get("provenance") == "real_lab_capture"
                        and promotion.get("schema") == SCHEMA and promotion.get("extractor_version")
                        and promotion.get("extractor_config_sha256")
                        and validation.get("provenance") == "labelled_lab_capture"
                        and validation.get("model_sha256") == promotion["model_sha256"]
                        and validation.get("schema") == SCHEMA
                        and validation.get("independent_sessions") is True
                        and type(validation.get("attack_samples")) is int and validation["attack_samples"] >= 20
                        and type(validation.get("normal_samples")) is int and validation["normal_samples"] >= 100
                        and type(validation.get("recall")) in (int, float) and .8 <= validation["recall"] <= 1
                        and type(validation.get("false_positive_rate")) in (int, float) and 0 <= validation["false_positive_rate"] <= .05)
        except (OSError, ValueError, KeyError, TypeError):
            return False

    def status(self):
        provenance = self.bundle.get("provenance", "real_iot23") if self.bundle else "real_iot23"
        return dict(ready=self.bundle is not None, error=self.error, schema=SCHEMA,
                    model_sha256=self.model_sha256,
                    provenance=provenance, report=self.bundle["report"] if self.bundle else None,
                    promotion_verified=self.promotion_verified,
                    live_validated=bool(self.bundle and (self.bundle["report"].get("live_validated") is True
                                                         or self.promotion_verified)),
                    response_eligible=bool(self.bundle and self.bundle["report"].get("eligible") is True
                                           and self.promotion_verified))

    def predict(self, raw):
        values = features(raw)
        if not self.bundle:
            return dict(prediction="unknown", attack_type="unknown", confidence=None,
                        attack_probability=None, risk_score=None, reasons=[self.error])
        array = np.array([[np.nan if values[name] is None else values[name] for name in FEATURES]], dtype=object)
        model = self.bundle["model"]
        score = float(model.predict_proba(array)[0][list(model.classes_).index("attack")])
        attack = score >= self.bundle["report"]["threshold"]
        return dict(prediction="malicious" if attack else "benign", attack_type="unspecified" if attack else "normal",
                    confidence=score if attack else 1-score, attack_probability=score, risk_score=round(score*100),
                    reasons=[f"IoT-23 binary classifier: attack probability {score:.3f}",
                             "No attack-family classification or causal explanation is provided"],
                    model_scope=self.bundle["report"]["scope"])
