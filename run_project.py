"""Start the real-data dashboard; never generate training data or attacks."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8020)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--model", type=Path, help="Explicit trusted candidate artifact; does not bypass live validation")
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.model:
        if not args.model.is_file():
            parser.error("Selected model file does not exist")
        os.environ["LIVE_MODEL_PATH"] = str(args.model.resolve())
    if args.build or not (ROOT / "frontend/dist/index.html").exists():
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm:
            raise SystemExit("Install Node.js first")
        subprocess.run([npm, "ci"], cwd=ROOT / "frontend", check=True)
        subprocess.run([npm, "run", "build"], cwd=ROOT / "frontend", check=True)
    import uvicorn
    uvicorn.run("backend.main:create_app", factory=True, host=args.host, port=args.port)
