from pathlib import Path
import warnings
import joblib
import sklearn
from .features import FEATURES, SCHEMA, SECONDS, vector


class Detector:
    def __init__(self, path, provenance):
        self.bundle = None
        self.error = "No compatible model installed"
        self.provenance = provenance
        if not path or not Path(path).is_file():
            return
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                bundle = joblib.load(path)
            if (bundle["schema"] != SCHEMA or bundle["features"] != FEATURES
                    or bundle["window_seconds"] != SECONDS or bundle["provenance"] != provenance
                    or bundle["sklearn_version"] != sklearn.__version__ or not bundle["report"]["eligible"]):
                raise ValueError("Model schema, provenance, version or evaluation gate mismatch")
            if "normal" not in bundle["model"].classes_:
                raise ValueError("Missing normal class")
            self.bundle, self.error = bundle, None
        except Exception as error:
            self.error = str(error)

    def status(self):
        return {"ready": self.bundle is not None, "error": self.error, "provenance": self.provenance,
                "schema": SCHEMA, "report": self.bundle["report"] if self.bundle else None}

    def predict(self, features, threshold):
        values = vector(features)
        if self.bundle is None:
            return dict(prediction="unknown", attack_type="unknown", confidence=0,
                        attack_probability=0, risk_score=0, reasons=[self.error])
        model = self.bundle["model"]
        probabilities = model.predict_proba([values])[0]
        classes = list(model.classes_)
        attack_probability = float(1 - probabilities[classes.index("normal")])
        attack = attack_probability >= threshold
        candidates = [(float(probabilities[i]), label) for i, label in enumerate(classes) if label != "normal"]
        category_confidence, category = max(candidates)
        deviations = sorted(((abs(value - baseline) / (abs(baseline) + 1), key, value, baseline)
                             for key, value, baseline in zip(FEATURES, values, self.bundle["normal_median"])), reverse=True)
        reasons = [f"{key}={value:.2f}; training normal median={baseline:.2f}"
                   for _, key, value, baseline in deviations[:3]]
        return dict(prediction="malicious" if attack else "benign", attack_type=category if attack else "normal",
                    confidence=attack_probability if attack else 1 - attack_probability,
                    category_confidence=category_confidence if attack else 1 - attack_probability,
                    attack_probability=attack_probability, risk_score=round(attack_probability * 100),
                    reasons=reasons, explanation_method="Deviation from normal median; not SHAP or causal attribution")
