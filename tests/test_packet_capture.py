import time
import unittest

from scapy.all import IP, Raw, TCP

from backend.packet_capture import ScapyFlowCapture


class PacketCaptureTests(unittest.TestCase):
    def test_packet_aggregate_uses_observed_bidirectional_values(self):
        capture = ScapyFlowCapture("test", {"10.0.0.2"}, idle_timeout=0.1)
        started = time.time() - 1
        request = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=4000, dport=80, flags="S") / Raw(b"a")
        response = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=4000, flags="SA") / Raw(b"bb")
        request.time = started
        response.time = started + 0.5
        capture._packet(request)
        capture._packet(response)

        rows = capture.poll()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["id.orig_h"], "10.0.0.2")
        self.assertEqual(row["id.resp_p"], 80)
        self.assertEqual(row["orig_bytes"], 1)
        self.assertEqual(row["resp_bytes"], 2)
        self.assertEqual(row["orig_pkts"], 1)
        self.assertEqual(row["resp_pkts"], 1)
        self.assertAlmostEqual(row["duration"], 0.5)
        self.assertEqual(row["extractor"], "scapy-lab-flow-v1")

    def test_unrelated_packet_is_ignored(self):
        capture = ScapyFlowCapture("test", {"10.0.0.2"})
        packet = IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=1, dport=2, flags="S")
        capture._packet(packet)
        self.assertEqual(capture.packet_count, 0)
        self.assertEqual(capture.poll(), [])


if __name__ == "__main__":
    unittest.main()
