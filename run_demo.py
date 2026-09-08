"""Train the synthetic demo, build dashboard if needed, start the local server."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8020)
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    os.chdir(ROOT)
    from backend.config import Settings
    settings = Settings.from_env()
    if settings.firewall_mode != "dry-run":
        raise SystemExit("Demo launcher requires FIREWALL_MODE=dry-run")
    from backend.simulation import dataset
    from ml.train import train
    train(dataset(), settings.data_dir / "demo-model", "synthetic_demo")
    if args.build or not (ROOT / "frontend/dist/index.html").exists():
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm:
            raise SystemExit("Install Node.js, then retry")
        subprocess.run([npm, "ci"], cwd=ROOT / "frontend", check=True)
        subprocess.run([npm, "run", "build"], cwd=ROOT / "frontend", check=True)
    os.environ["DEMO_AUTOSTART"] = "1"
    import uvicorn
    uvicorn.run("backend.main:create_app", factory=True, host="127.0.0.1", port=args.port)
