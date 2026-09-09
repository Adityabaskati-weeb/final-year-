"""Read-only environment diagnostics. No port opening, probing, capture or secrets output."""
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.config import Settings
from backend.detection import Detector


def inspect():
    settings = Settings.from_env()
    path = settings.live_model or settings.data_dir / "iot23-model/model.joblib"
    model = Detector(path).status()
    result = dict(python=sys.executable, zeek=shutil.which("zeek"), tshark=shutil.which("tshark"),
                  model_path=str(path), model_loaded=model["ready"], live_eligible=model["response_eligible"],
                  model_error=model["error"], telemetry_token_configured=bool(settings.sensor_token),
                  zeek_source_configured=bool(settings.zeek_log or settings.zeek_token), serial_ports=[])
    try:
        from scapy.all import conf
        result["pcap_available"] = bool(conf.use_pcap)
        result["interfaces"] = [dict(name=i.description, id=i.network_name, ip=i.ip) for i in conf.ifaces.values()]
    except Exception as error:
        result["capture_error"] = str(error)
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\SERIALCOMM") as key:
                for index in range(winreg.QueryInfoKey(key)[1]):
                    result["serial_ports"].append(winreg.EnumValue(key, index)[1])
        except OSError as error:
            result["serial_check"] = str(error)
    result["note"] = "Interface/serial availability is not proof that the sensor or attack traffic is visible."
    return result


if __name__ == "__main__":
    print(json.dumps(inspect(), indent=2))
