"""Download only official labelled connection logs. No malware binaries or PCAPs."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

BASE = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
CAPTURES = {
    "CTU-Honeypot-Capture-4-1": "train",
    "CTU-IoT-Malware-Capture-20-1": "train",
    "CTU-IoT-Malware-Capture-34-1": "train",
    "CTU-IoT-Malware-Capture-8-1": "train",
    "CTU-Honeypot-Capture-5-1": "validation",
    "CTU-IoT-Malware-Capture-21-1": "validation",
    "CTU-Honeypot-Capture-7-1": "test",
    "CTU-IoT-Malware-Capture-42-1": "test",
    "CTU-IoT-Malware-Capture-44-1": "test",
}


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.extend(value for key, value in attrs if key == "href")


def find_log(url, depth=0):
    if depth > 3:
        return None
    with urllib.request.urlopen(url, timeout=45) as response:
        parser = Links()
        parser.feed(response.read(2_000_000).decode("utf-8"))
    for href in parser.links:
        if href == "conn.log.labeled":
            return urljoin(url, href)
    for href in parser.links:
        if href in {"bro/", "zeek/", "Somfy-01/"}:
            result = find_log(urljoin(url, href), depth + 1)
            if result:
                return result
    return None


def download(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    entries = []
    for capture, split in CAPTURES.items():
        target = root / capture / "conn.log.labeled"
        target.parent.mkdir(exist_ok=True)
        url = find_log(BASE + capture + "/")
        if not url or urlparse(url).hostname != "mcfp.felk.cvut.cz":
            raise ValueError("Official labelled log not found: " + capture)
        if not target.exists():
            temp = target.with_suffix(".part")
            size = 0
            with urllib.request.urlopen(url, timeout=60) as response, temp.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > 100_000_000:
                        raise ValueError("Per-log download limit exceeded")
                    output.write(chunk)
            temp.replace(target)
        with target.open("rb") as file:
            digest = hashlib.file_digest(file, "sha256").hexdigest()
        entries.append(dict(path=f"{capture}/conn.log.labeled", capture_id=capture, split=split,
                            source_url=url, sha256=digest, provenance="iot23_official"))
        (root / "manifest.json").write_text(json.dumps(entries, indent=2), encoding="utf-8")
        print(capture, split, target.stat().st_size, flush=True)
    return root / "manifest.json"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("runtime/iot23"))
    print(download(parser.parse_args().output))
