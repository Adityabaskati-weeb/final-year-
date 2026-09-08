"""Host-only firewall rules. Demo actions never invoke an OS command."""
import hashlib
import ipaddress
import platform
import socket
import subprocess
import threading
import time


class FirewallManager:
    def __init__(self, runner=None):
        self.runner = runner or self.run

    @staticmethod
    def run(command):
        subprocess.run(command, check=True, capture_output=True, timeout=15)

    @staticmethod
    def identity(ip):
        return "updated-iot-" + hashlib.sha256(str(ipaddress.ip_address(ip)).encode()).hexdigest()[:16]


class WindowsFirewallManager(FirewallManager):
    def commands(self, ip, block):
        ip = str(ipaddress.ip_address(ip))
        name = self.identity(ip)
        commands = []
        for direction in ("Inbound", "Outbound"):
            rule = name + "-" + direction
            script = (f"$ErrorActionPreference='Stop'; if (-not (Get-NetFirewallRule -Name '{rule}' -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -Name '{rule}' -DisplayName '{rule}' -Direction {direction} -RemoteAddress '{ip}' -Action Block -Profile Any | Out-Null }}"
                      if block else f"$ErrorActionPreference='Stop'; Get-NetFirewallRule -Name '{rule}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
            commands.append(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
        return commands

    def apply(self, ip, block):
        for command in self.commands(ip, block):
            self.runner(command)


class LinuxFirewallManager(FirewallManager):
    def commands(self, ip, block):
        address = ipaddress.ip_address(ip)
        binary = "iptables" if address.version == 4 else "ip6tables"
        return [[binary, "-w", "5", "-I" if block else "-D", chain, flag, str(address),
                 "-m", "comment", "--comment", self.identity(ip), "-j", "DROP"]
                for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d"))]

    def apply(self, ip, block):
        for command in self.commands(ip, block):
            check = list(command)
            check[3] = "-C"
            try:
                self.runner(check)
                exists = True
            except subprocess.CalledProcessError as error:
                if error.returncode != 1:
                    raise
                exists = False
            if exists != block:
                self.runner(command)


def local_protections():
    protected = {"127.0.0.1", "::1"}
    for info in socket.getaddrinfo(socket.gethostname(), None):
        protected.add(info[4][0].split("%")[0])
    try:
        from scapy.all import conf
        for route in conf.route.routes:
            if route[2] != "0.0.0.0":
                protected.add(route[2])
            if route[4] != "0.0.0.0":
                protected.add(route[4])
    except Exception:
        pass
    return protected


class ResponseEngine:
    def __init__(self, store, settings, event, device_ips, adapter=None):
        self.store, self.settings, self.event, self.device_ips = store, settings, event, device_ips
        self.protected = local_protections() | set(settings.protected_ips)
        self.adapter = adapter or (WindowsFirewallManager() if platform.system() == "Windows" else LinuxFirewallManager())
        self.lock = threading.RLock()

    def check(self, ip):
        address = ipaddress.ip_address(ip)
        if (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified
                or str(address) in self.protected | set(self.device_ips())):
            raise ValueError("Protected host, gateway or registered sensor cannot be blocked")
        return str(address)

    def block(self, ip, reason, origin="live", attack_type="manual"):
        with self.lock:
            ip = self.check(ip)
            key = origin + ":" + ip
            existing = self.store.get("blocks", key)
            if existing and existing["status"] in {"blocked", "simulated_block", "cleanup_required"}:
                return existing
            active = origin == "live" and self.settings.firewall_mode == "active"
            row = dict(id=key, source_ip=ip, reason=reason, attack_type=attack_type, origin=origin,
                       expires_at=time.time() + self.settings.block_seconds, active=active)
            self.event("RESPONSE_TRIGGERED", **row)
            # Persist intent first, so a crash cannot silently orphan a rule.
            self.store.put("blocks", {**row, "status": "cleanup_required" if active else "pending"})
            try:
                if active:
                    self.adapter.apply(ip, True)
                row["status"] = "blocked" if active else "simulated_block"
            except Exception as error:
                row.update(status="cleanup_required", error=str(error))
            result = self.store.put("blocks", row)
            self.event("FIREWALL_" + row["status"].upper(), **row)
            return result

    def unblock(self, key):
        with self.lock:
            row = self.store.get("blocks", key)
            if not row:
                raise ValueError("Unknown block")
            try:
                if row.get("active") and row["status"] != "released":
                    self.adapter.apply(row["source_ip"], False)
                row["status"] = "released"
                row.pop("error", None)
            except Exception as error:
                row.update(status="cleanup_required", error=str(error))
            self.store.put("blocks", row)
            self.event("FIREWALL_RELEASE", **row)
            return row

    def expire(self):
        for row in self.store.rows("blocks", 100000):
            if row["status"] != "released" and row["expires_at"] <= time.time():
                self.unblock(row["id"])

    def denied_demo(self, ip):
        row = self.store.get("blocks", "demo:" + ip)
        return bool(row and row["status"] == "simulated_block" and row["expires_at"] > time.time())
