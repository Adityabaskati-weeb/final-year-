"""Build a claim/evidence report without inventing model or live-test results.

The output is a review artifact. It records exactly which claims are supported
by local evidence and which remain blocked by missing data, validation, or
network topology. Runtime output is ignored by Git on purpose.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.attack_family import AttackFamilyDetector  # noqa: E402
from backend.config import Settings  # noqa: E402
from backend.detection import Detector  # noqa: E402
from backend.iot_audit_candidate import IoTAuditCandidate  # noqa: E402
from scripts.fetch_iot_audit_model import (  # noqa: E402
    ARTIFACT_SHA256,
    ARTIFACT_URL,
    UPSTREAM_COMMIT,
    UPSTREAM_REPOSITORY,
)


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def git_revision() -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def selected_live_model(settings: Settings) -> Path:
    if settings.live_model:
        return resolve_path(settings.live_model)
    candidates = sorted(settings.data_dir.glob("iot23-model*/model.joblib"))
    return candidates[-1] if candidates else settings.data_dir / "iot23-model/model.joblib"


def file_record(path: Path) -> dict:
    return {
        "path": str(path),
        "exists": path.is_file(),
        "bytes": path.stat().st_size if path.is_file() else None,
        "sha256": sha256_file(path),
    }


def load_external_evaluation(path: Path) -> dict:
    if not path.is_file():
        return {"available": False, "path": str(path), "reason": "Evaluation has not been run"}
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"available": False, "path": str(path), "reason": str(error)}
    return {
        "available": True,
        "path": str(path),
        "artifact_sha256": report.get("artifact_sha256"),
        "source_dataset": report.get("source_dataset"),
        "source_split": report.get("source_split"),
        "rows": report.get("rows"),
        "metrics": report.get("metrics", {}),
        "eligible": report.get("eligible") is True,
        "live_validated": report.get("live_validated") is True,
        "scope": report.get("scope"),
    }


def build_report() -> dict:
    settings = Settings.from_env()
    live_path = selected_live_model(settings)
    attack_path = resolve_path(settings.attack_type_model) if settings.attack_type_model else ROOT / "runtime/attack-type/model.joblib"
    external_path = settings.data_dir / "iot-audit-pretrained/binary_lightgbm.joblib"
    external_evaluation_path = settings.data_dir / "iot-audit-pretrained/evaluation.json"

    live = Detector(live_path)
    family = AttackFamilyDetector(attack_path)
    external = IoTAuditCandidate(external_path)
    evaluation = load_external_evaluation(external_evaluation_path)
    external_metrics = evaluation.get("metrics", {})
    external_cross_domain_failed = (
        evaluation.get("available") is True
        and (
            evaluation.get("eligible") is not True
            or external_metrics.get("false_positive_rate", 1) > 0.10
            or external_metrics.get("recall", 0) < 0.80
        )
    )

    claims = [
        {
            "id": "esp32_live_binary_detection",
            "status": "promoted_bounded_scope" if live.status()["response_eligible"] else "not_promoted",
            "supported_by": "real labelled lab captures and hash-linked promotion evidence",
            "allowed_claim": "validated binary classification for the registered ESP32, topology and matching extractor",
            "not_supported": "arbitrary devices, attack families, or other networks",
        },
        {
            "id": "external_iot_audit_reference",
            "status": "offline_reference_with_domain_shift_failure" if external_cross_domain_failed else "offline_reference_only",
            "supported_by": "pinned upstream artifact, SHA-256 verification and recorded offline evaluation",
            "allowed_claim": "the upstream TON-IoT pipeline is integrated as a reproducible offline benchmark",
            "not_supported": "live ESP32 inference, hardware alerts, or blocking",
        },
        {
            "id": "attack_family_classification",
            "status": "promoted" if family.status()["ready"] else "not_promoted",
            "supported_by": "capture-disjoint labelled family evidence only after promotion",
            "allowed_claim": "none until a multi-family model is promoted",
            "not_supported": "inferring a family from a binary score or sensor readings",
        },
        {
            "id": "gateway_enforcement",
            "status": "not_verified",
            "supported_by": "application response records only",
            "allowed_claim": "dry-run or host-only response state",
            "not_supported": "blocking a Wi-Fi client through the laptop without a controlled gateway",
        },
    ]

    return {
        "report_version": "credibility-v1",
        "generated_at": time.time(),
        "repository_revision": git_revision(),
        "models": {
            "live_binary": {"path": str(live_path), "status": live.status(), "file": file_record(live_path)},
            "attack_family": {"path": str(attack_path), "status": family.status(), "file": file_record(attack_path)},
            "external_iot_audit": {
                "path": str(external_path),
                "status": external.status(),
                "file": file_record(external_path),
                "expected_sha256": ARTIFACT_SHA256,
                "upstream_repository": UPSTREAM_REPOSITORY,
                "upstream_commit": UPSTREAM_COMMIT,
                "source_url": ARTIFACT_URL,
                "evaluation": evaluation,
            },
        },
        "claims": claims,
        "credibility_requirements": [
            "publish the exact commit, model hashes, feature schema and dependency versions",
            "use independent capture/device/day-disjoint test partitions",
            "report recall, false-positive rate, precision, F1, PR-AUC and confusion matrices",
            "replay labelled traffic through the same extractor used by the live service",
            "verify gateway block effectiveness independently from application logs",
            "keep offline benchmark, live model, hardware test and attack simulation visibly separate",
        ],
        "sources": {
            "upstream_model": UPSTREAM_REPOSITORY,
            "upstream_commit": UPSTREAM_COMMIT,
            "iot23_reference": "https://github.com/Iretha/IoT23-network-traffic-anomalies-classification",
        },
    }


def markdown(report: dict) -> str:
    lines = [
        "# Credibility Report",
        "",
        f"Repository revision: `{report.get('repository_revision') or 'unavailable'}`",
        "",
        "This report separates reproducible evidence from claims that are not supported.",
        "",
        "## Claim ledger",
        "",
        "| Claim | Status | Allowed claim | Not supported |",
        "|---|---|---|---|",
    ]
    for claim in report["claims"]:
        lines.append(
            f"| `{claim['id']}` | `{claim['status']}` | {claim['allowed_claim']} | {claim['not_supported']} |"
        )
    external = report["models"]["external_iot_audit"]
    evaluation = external["evaluation"]
    lines.extend(
        [
            "",
            "## External reference",
            "",
            f"Upstream: [{external['upstream_repository']}]({external['upstream_repository']}) at `{external['upstream_commit']}`.",
            f"Artifact SHA-256: `{external['expected_sha256']}`.",
            f"Evaluation available: `{evaluation.get('available')}`; eligible: `{evaluation.get('eligible')}`; live validated: `{evaluation.get('live_validated')}`.",
            f"Evaluation scope: {evaluation.get('scope') or 'not run'}",
            "",
            "The external artifact is never used for live ESP32 alerts or firewall response. It is a reproducible benchmark/reference only.",
            "",
            "## Evidence required before broad claims",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in report["credibility_requirements"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "runtime/credibility/report.json")
    parser.add_argument("--markdown", type=Path, default=None)
    args = parser.parse_args()
    report = build_report()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        markdown_path = args.markdown if args.markdown.is_absolute() else ROOT / args.markdown
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(markdown(report), encoding="utf-8")
    print(json.dumps({"output": str(output), "revision": report["repository_revision"], "claims": report["claims"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
