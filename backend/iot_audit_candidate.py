"""Isolated loader for the published iot-audit binary pipeline.

This candidate is intentionally separate from the promoted IoT-23 detector. The
upstream artifact was trained on TON-IoT's unified flow representation, so
loading it does not prove that it is valid for live ESP32 traffic.
"""

from __future__ import annotations

import hashlib
import re
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.pipeline import Pipeline

from .features import features as validate_zeek_features


SCHEMA = "iot-audit-ton-unified-v1"
ARTIFACT_SHA256 = "3d113987cbaf696aef336aa398a3ce17d07a34a97473dc06f2399d232fb5d3f0"
NUMERIC_FEATURES = [
    "bytes_total",
    "bytes_src",
    "bytes_dst",
    "pkts_total",
    "byte_asymmetry",
    "pkt_asymmetry",
    "payload_mean_fwd",
    "payload_mean_bwd",
    "flow_duration_sec",
    "flow_rate",
]
CATEGORICAL_FEATURES = ["proto_unified", "service_unified", "conn_state_unified"]
FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _log1p(value: float) -> float:
    return float(np.log1p(max(value, 0.0)))


def _safe_div(numerator: float, denominator: float) -> float:
    return 0.0 if denominator == 0 else float(numerator / denominator)


def _proto(value: str) -> str:
    normalized = str(value).strip().lower()
    return {"6": "tcp", "17": "udp", "1": "icmp"}.get(normalized, normalized if normalized in {"tcp", "udp", "icmp"} else "other")


def _feature_row(record: dict) -> dict:
    """Convert one genuine Zeek connection into the upstream feature contract."""
    values = validate_zeek_features(record)
    required = ("duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")
    missing = [name for name in required if values.get(name) is None]
    if missing:
        raise ValueError("Cannot derive iot-audit features from missing Zeek fields: " + ", ".join(missing))

    duration = float(values["duration"])
    orig_bytes = float(values["orig_bytes"])
    resp_bytes = float(values["resp_bytes"])
    orig_pkts = float(values["orig_pkts"])
    resp_pkts = float(values["resp_pkts"])
    total_bytes = orig_bytes + resp_bytes
    total_pkts = orig_pkts + resp_pkts

    # This mirrors iot-audit's TON builder. Service and connection state are
    # fixed to the upstream trained category because its fitted encoder only
    # contains the "other" category.
    row = {
        "bytes_total": _log1p(total_bytes),
        "bytes_src": _log1p(orig_bytes),
        "bytes_dst": _log1p(resp_bytes),
        "pkts_total": _log1p(total_pkts),
        "byte_asymmetry": _safe_div(orig_bytes - resp_bytes, total_bytes),
        "pkt_asymmetry": _safe_div(orig_pkts - resp_pkts, total_pkts),
        "payload_mean_fwd": _log1p(_safe_div(orig_bytes, orig_pkts)),
        "payload_mean_bwd": _log1p(_safe_div(resp_bytes, resp_pkts)),
        "flow_duration_sec": _log1p(duration),
        "flow_rate": _log1p(_safe_div(total_bytes, duration)),
        "proto_unified": _proto(values["proto"]),
        "service_unified": "other",
        "conn_state_unified": "other",
    }
    return row


def build_features(record: dict) -> pd.DataFrame:
    return pd.DataFrame([_feature_row(record)], columns=FEATURES)


def build_features_batch(records: list[dict]) -> pd.DataFrame:
    return pd.DataFrame([_feature_row(record) for record in records], columns=FEATURES)


class IoTAuditCandidate:
    """Load and run the upstream artifact as an explicitly unpromoted model."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.pipeline = None
        self.error = "Artifact not found"
        self.model_sha256 = None
        self.serialized_sklearn_version = None
        self.version_match = False
        self.hash_verified = False
        self.warnings = []
        if not self.path.is_file():
            return
        try:
            self.model_sha256 = sha256_file(self.path)
            self.hash_verified = self.model_sha256 == ARTIFACT_SHA256
            if not self.hash_verified:
                raise ValueError("iot-audit artifact SHA-256 mismatch")
            with warnings.catch_warnings(record=True) as captured:
                warnings.simplefilter("always")
                pipeline = joblib.load(self.path)
            self.warnings = [str(item.message) for item in captured]
            versions = re.findall(r"version (\d+\.\d+\.\d+)", " ".join(self.warnings))
            self.serialized_sklearn_version = versions[0] if versions else sklearn.__version__
            self.version_match = self.serialized_sklearn_version == sklearn.__version__
            if not isinstance(pipeline, Pipeline) or list(pipeline.feature_names_in_) != FEATURES:
                raise ValueError("iot-audit pipeline feature contract mismatch")
            if list(pipeline.named_steps) != ["preprocessor", "model"]:
                raise ValueError("iot-audit pipeline steps mismatch")
            if set(pipeline.named_steps["model"].classes_) != {0, 1}:
                raise ValueError("iot-audit pipeline class contract mismatch")
            self.pipeline = pipeline
            self.error = None
        except Exception as error:
            self.error = str(error)

    def status(self) -> dict:
        return {
            "ready": self.pipeline is not None,
            "error": self.error,
            "schema": SCHEMA,
            "artifact_sha256": self.model_sha256,
            "hash_verified": self.hash_verified,
            "serialized_sklearn_version": self.serialized_sklearn_version,
            "runtime_sklearn_version": sklearn.__version__,
            "version_match": self.version_match,
            "classes": ["normal", "attack"],
            "features": FEATURES,
            "provenance": "published_iot_audit_ton_iot",
            "offline_only": True,
            "live_validated": False,
            "response_eligible": False,
        }

    def predict(self, record: dict) -> dict:
        if self.pipeline is None:
            return {"prediction": "unknown", "attack_probability": None, "error": self.error}
        frame = build_features(record)
        return self._prediction_rows(frame)[0]

    def _prediction_rows(self, frame: pd.DataFrame) -> list[dict]:
        probabilities = self.pipeline.predict_proba(frame)
        classes = list(self.pipeline.named_steps["model"].classes_)
        predictions = self.pipeline.predict(frame)
        attack_index = classes.index(1)
        return [
            {
                "prediction": "malicious" if int(prediction) == 1 else "benign",
                "attack_probability": float(probability[attack_index]),
                "model_scope": "TON-IoT pretrained candidate applied to Zeek-derived features; domain shift unvalidated",
            }
            for prediction, probability in zip(predictions, probabilities)
        ]

    def predict_many(self, records: list[dict]) -> list[dict]:
        if self.pipeline is None:
            return [{"prediction": "unknown", "attack_probability": None, "error": self.error} for _ in records]
        return self._prediction_rows(build_features_batch(records))
