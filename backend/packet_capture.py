"""Bounded Scapy/Npcap packet-to-flow extraction for an authorized lab device.

This adapter does not invent packet counts or payload sizes. Every emitted value
is aggregated from packets observed on the configured interface. It intentionally
uses the existing Zeek-compatible field contract, but records the extractor
identity in the runtime state so it cannot be confused with an actual Zeek log.
"""
from collections import deque
from dataclasses import dataclass
import hashlib
import threading
import time


def _service(port):
    return {53: "dns", 80: "http", 443: "ssl", 1883: "mqtt", 5683: "coap", 8080: "http"}.get(port, "-")


@dataclass
class _Flow:
    started_at: float
    last_seen: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_ip_bytes: int = 0
    resp_ip_bytes: int = 0
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False

    @classmethod
    def create(cls, packet, ip, transport, proto):
        source = (str(ip.src), int(transport.sport))
        destination = (str(ip.dst), int(transport.dport))
        seed = f"{float(packet.time):.6f}|{source[0]}|{source[1]}|{destination[0]}|{destination[1]}|{proto}"
        uid = "C" + hashlib.sha256(seed.encode("ascii")).hexdigest()[:18]
        return cls(float(packet.time), float(packet.time), uid, source[0], source[1],
                   destination[0], destination[1], proto)

    def observe(self, packet, ip, transport):
        timestamp = float(getattr(packet, "time", self.last_seen))
        self.last_seen = max(self.last_seen, timestamp)
        source = (str(ip.src), int(transport.sport))
        is_orig = source == (self.orig_h, self.orig_p)
        ip_size = int(getattr(ip, "len", 0) or len(bytes(ip)))
        payload = len(bytes(getattr(transport, "payload", b"")))
        if is_orig:
            self.orig_pkts += 1
            self.orig_ip_bytes += ip_size
            self.orig_bytes += payload
        else:
            self.resp_pkts += 1
            self.resp_ip_bytes += ip_size
            self.resp_bytes += payload
        if self.proto == "tcp":
            flags = int(transport.flags)
            self.syn_seen = self.syn_seen or bool(flags & 0x02 and not flags & 0x10)
            self.syn_ack_seen = self.syn_ack_seen or bool(flags & 0x12 == 0x12)
            self.fin_seen = self.fin_seen or bool(flags & 0x01)
            self.rst_seen = self.rst_seen or bool(flags & 0x04)

    def record(self):
        if self.proto == "udp":
            state = "SF"
        elif self.rst_seen and not self.syn_ack_seen:
            state = "REJ"
        elif self.syn_seen and not self.syn_ack_seen:
            state = "S0"
        elif self.fin_seen or self.rst_seen:
            state = "SF"
        else:
            state = "OTH"
        return {
            "ts": self.started_at,
            "uid": self.uid,
            "id.orig_h": self.orig_h,
            "id.orig_p": self.orig_p,
            "id.resp_h": self.resp_h,
            "id.resp_p": self.resp_p,
            "proto": self.proto,
            "service": _service(self.resp_p),
            "duration": max(0.0, self.last_seen - self.started_at),
            "orig_bytes": self.orig_bytes,
            "resp_bytes": self.resp_bytes,
            "conn_state": state,
            # No retransmission estimator is claimed by this adapter.
            "missed_bytes": None,
            "orig_pkts": self.orig_pkts,
            "orig_ip_bytes": self.orig_ip_bytes,
            "resp_pkts": self.resp_pkts,
            "resp_ip_bytes": self.resp_ip_bytes,
            "extractor": "scapy-lab-flow-v1",
        }


class ScapyFlowCapture:
    """Capture only traffic involving configured private lab target IPs."""

    extractor = "scapy-lab-flow-v1"

    def __init__(self, interface, target_ips, idle_timeout=1.25):
        self.interface = interface
        self.target_ips = frozenset(target_ips)
        self.idle_timeout = idle_timeout
        self._flows = {}
        self._queue = deque(maxlen=5000)
        self._lock = threading.Lock()
        self._sniffer = None
        self.error = None
        self.packet_count = 0
        self.flow_count = 0

    def _packet(self, packet):
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.l2 import Ether
            if IP not in packet:
                # Some Windows Npcap paths deliver a generic lazy Packet when
                # the adapter's datalink cannot be guessed. Decode its bytes
                # explicitly before applying the target filter.
                packet = Ether(bytes(packet))
            if IP not in packet or not ({packet[IP].src, packet[IP].dst} & self.target_ips):
                return
            transport = packet.getlayer(TCP) or packet.getlayer(UDP)
            if transport is None:
                return
            proto = "tcp" if TCP in packet else "udp"
            key_endpoints = tuple(sorted(((str(packet[IP].src), int(transport.sport)),
                                          (str(packet[IP].dst), int(transport.dport)))))
            key = (proto, key_endpoints)
            with self._lock:
                flow = self._flows.get(key)
                if flow is None:
                    flow = _Flow.create(packet, packet[IP], transport, proto)
                    self._flows[key] = flow
                flow.observe(packet, packet[IP], transport)
                self.packet_count += 1
                if proto == "tcp" and flow.rst_seen:
                    self._queue.append(flow.record())
                    self._flows.pop(key, None)
                    self.flow_count += 1
        except Exception as error:
            self.error = str(error)

    def start(self):
        from scapy.sendrecv import AsyncSniffer
        if not self.target_ips:
            raise ValueError("At least one registered lab target is required")
        bpf = " or ".join(f"host {target}" for target in sorted(self.target_ips))
        # Scapy/Npcap on Windows can skip a bound method callback; the wrapper
        # keeps the callback registered as a plain callable.
        self._sniffer = AsyncSniffer(iface=self.interface, filter=bpf,
                                     prn=lambda packet: self._packet(packet), store=False)
        self._sniffer.start()

    def poll(self):
        now = time.time()
        with self._lock:
            for key, flow in list(self._flows.items()):
                if now - flow.last_seen >= self.idle_timeout:
                    self._queue.append(flow.record())
                    self._flows.pop(key, None)
                    self.flow_count += 1
            rows = list(self._queue)
            self._queue.clear()
        return rows

    def stop(self):
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is not None:
            sniffer.stop(join=True)
        with self._lock:
            for flow in self._flows.values():
                self._queue.append(flow.record())
            self._flows.clear()

    def status(self):
        return {"extractor": self.extractor, "interface": self.interface,
                "target_ips": sorted(self.target_ips), "packets": self.packet_count,
                "flows": self.flow_count, "error": self.error}
