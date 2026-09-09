"""Fetch the pinned upstream iot-audit model and verify it before loading.

The binary is intentionally kept outside Git. This command makes the selected
external reference reproducible without silently accepting a changed model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from urllib import error as urllib_error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_REPOSITORY = "https://github.com/emanuelepiodebernardis/iot-audit"
UPSTREAM_COMMIT = "e0decb975e2c3d723375f3b87f0ed50cb5b73b0c"
ARTIFACT_PATH = "models/binary_lightgbm.joblib"
ARTIFACT_SHA256 = "3d113987cbaf696aef336aa398a3ce17d07a34a97473dc06f2399d232fb5d3f0"
ARTIFACT_URL = f"https://raw.githubusercontent.com/emanuelepiodebernardis/iot-audit/{UPSTREAM_COMMIT}/{ARTIFACT_PATH}"
MAX_BYTES = 50 * 1024 * 1024


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fetch(output: Path, *, force: bool = False) -> dict:
    output = output.resolve()
    metadata_path = output.with_suffix(output.suffix + ".metadata.json")
    if output.exists() and not force:
        actual = sha256_file(output)
        if actual != ARTIFACT_SHA256:
            raise SystemExit(
                f"Existing artifact hash mismatch: {actual}; remove it or pass --force"
            )
        return json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {
            "status": "verified_existing",
            "artifact": str(output),
            "sha256": actual,
            "upstream_repository": UPSTREAM_REPOSITORY,
            "upstream_commit": UPSTREAM_COMMIT,
            "source_url": ARTIFACT_URL,
        }

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix="iot-audit-", suffix=".download", dir=output.parent, delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
    try:
        request = urllib.request.Request(
            ARTIFACT_URL,
            headers={"User-Agent": "updated-iot-work-model-fetch/1.0"},
        )
        total = 0
        with urllib.request.urlopen(request, timeout=120) as response, temporary_path.open("wb") as stream:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BYTES:
                    raise ValueError(f"Refusing artifact larger than {MAX_BYTES} bytes")
                stream.write(chunk)
        actual = sha256_file(temporary_path)
        if actual != ARTIFACT_SHA256:
            raise ValueError(f"Downloaded artifact hash mismatch: {actual}")
        temporary_path.replace(output)
    finally:
        temporary_path.unlink(missing_ok=True)

    metadata = {
        "status": "downloaded_and_verified",
        "artifact": str(output),
        "bytes": output.stat().st_size,
        "sha256": ARTIFACT_SHA256,
        "upstream_repository": UPSTREAM_REPOSITORY,
        "upstream_commit": UPSTREAM_COMMIT,
        "source_url": ARTIFACT_URL,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "offline_only": True,
        "response_eligible": False,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "runtime/iot-audit-pretrained/binary_lightgbm.joblib",
    )
    parser.add_argument("--force", action="store_true", help="replace an existing artifact after re-verifying the hash")
    args = parser.parse_args()
    try:
        print(json.dumps(fetch(args.output, force=args.force), indent=2))
    except (OSError, ValueError, urllib_error.URLError) as error:
        print(f"Fetch failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
