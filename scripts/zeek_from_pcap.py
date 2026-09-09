"""Process an existing genuine PCAP with actual Zeek, without network replay."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.features import SCHEMA, connection, read_log


def convert(pcap, output, executable="zeek"):
    pcap, output = Path(pcap).resolve(), Path(output).resolve()
    zeek = shutil.which(executable)
    if not zeek:
        raise ValueError("Install actual Zeek on a Linux collector; no approximate extractor is substituted")
    if not pcap.is_file():
        raise ValueError("PCAP does not exist")
    with pcap.open("rb") as stream:
        magic = stream.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
            raise ValueError("Expected PCAP or PCAPNG, not feature CSV")
        stream.seek(0)
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    output.mkdir(parents=True, exist_ok=False)
    version = subprocess.run([zeek, "--version"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    command = [zeek, "-r", str(pcap), "LogAscii::use_json=T"]
    result = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=600)
    (output / "zeek.stderr.txt").write_text(result.stderr, encoding="utf-8")
    count = 0
    if result.returncode == 0 and (output / "conn.log").exists():
        for row in read_log(output / "conn.log"):
            connection(row)
            count += 1
    report = dict(provenance="zeek_from_pcap", schema=SCHEMA, pcap=str(pcap), pcap_sha256=digest,
                  zeek_version=version, command=command, returncode=result.returncode, connection_count=count,
                  live=False, labelled=False, status="converted" if result.returncode == 0 and count else "incomplete")
    (output / "capture_manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if report["status"] != "converted":
        raise ValueError("Zeek produced no valid connections; inspect stderr, do not manufacture features")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(convert(args.pcap, args.output), indent=2))
