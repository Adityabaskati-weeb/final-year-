from dataclasses import dataclass, field
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: ROOT / "runtime")
    firewall_mode: str = "dry-run"
    protected_ips: tuple = ()
    active_ack: str = ""
    admin_token: str = ""
    sensor_token: str = ""
    detection_threshold: float = 0.8
    block_threshold: float = 0.9
    block_risk: int = 85
    block_seconds: int = 120
    window_seconds: int = 5
    live_model: str = ""

    def __post_init__(self):
        if self.firewall_mode not in {"dry-run", "active"}:
            raise ValueError("FIREWALL_MODE must be dry-run or active")
        if not 0.5 <= self.detection_threshold <= self.block_threshold <= 1:
            raise ValueError("Require 0.5 <= detection threshold <= block threshold <= 1")
        if not 1 <= self.block_seconds <= 3600 or not 0 <= self.block_risk <= 100:
            raise ValueError("Invalid block TTL or risk threshold")
        if self.window_seconds != 5:
            raise ValueError("source-window-v1 requires five-second windows")
        if self.firewall_mode == "active" and (self.active_ack != "HOST_ONLY_CONFIRMED"
                or not self.protected_ips or not self.admin_token):
            raise ValueError("Active firewall requires acknowledgement, protected IPs and ADMIN_TOKEN")

    @classmethod
    def from_env(cls):
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")
        return cls(data_dir=Path(os.getenv("DATA_DIR", ROOT / "runtime")),
                   firewall_mode=os.getenv("FIREWALL_MODE", "dry-run"),
                   protected_ips=tuple(filter(None, os.getenv("PROTECTED_IPS", "").split(","))),
                   active_ack=os.getenv("ACTIVE_FIREWALL_ACK", ""),
                   admin_token=os.getenv("ADMIN_TOKEN", ""), sensor_token=os.getenv("IOT_TELEMETRY_TOKEN", ""),
                   detection_threshold=float(os.getenv("DETECTION_THRESHOLD", "0.8")),
                   block_threshold=float(os.getenv("BLOCK_THRESHOLD", "0.9")),
                   block_risk=int(os.getenv("BLOCK_RISK", "85")),
                   block_seconds=int(os.getenv("BLOCK_SECONDS", "120")),
                   live_model=os.getenv("LIVE_MODEL_PATH", ""))
