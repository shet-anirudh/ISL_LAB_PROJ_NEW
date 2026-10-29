"""tests/test_pcap_parser.py — Unit and integration tests for analysis/pcap_parser.py."""

import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw
import config
from analysis.pcap_parser import (
    parse_pcap,
    flag_exfiltration,
    flag_c2_beacon,
    flag_large_outbound,
    record_detection_latency
)


class TestPcapParser(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="isl_pcap_test_")
        self.pcap_path = os.path.join(self.test_dir, "test_traffic.pcap")
        self.db_path = os.path.join(self.test_dir, "flows_test.sqlite")

        # Synthesize a realistic network capture
        packets = []
        base_time = 1729000000.0

        victim_ip = getattr(config, "VICTIM_IP", "192.168.56.20")
        attacker_ip = getattr(config, "ATTACKER_IP", "192.168.56.10")
        c2_port = getattr(config, "C2_PORT", 9001)
        transfer_port = getattr(config, "TRANSFER_PORT", 9002)

        # 1. C2 Beacon packets (3 periodic connections, exactly 2.0s apart)
        for i in range(3):
            t = base_time + (i * 2.0)
            beacon_pkt = Ether(src="08:00:27:00:00:20", dst="08:00:27:00:00:10") / IP(src=victim_ip, dst=attacker_ip) / TCP(sport=40000 + i, dport=c2_port, flags="P") / Raw(load=b"BEACON_POLL")
            beacon_pkt.time = t
            packets.append(beacon_pkt)

        # 2. Exfiltration traffic (5 packets of 20,000 bytes = 100,000 bytes total)
        exfil_start = base_time + 10.0
        for i in range(5):
            t = exfil_start + (i * 0.1)
            payload = b"X" * 20000
            exfil_pkt = Ether(src="08:00:27:00:00:20", dst="08:00:27:00:00:10") / IP(src=victim_ip, dst=attacker_ip) / TCP(sport=50001, dport=transfer_port, flags="PA") / Raw(load=payload)
            exfil_pkt.time = t
            packets.append(exfil_pkt)

        # 3. Benign small background traffic (DNS query)
        dns_pkt = Ether(src="08:00:27:00:00:20", dst="08:00:27:00:00:01") / IP(src=victim_ip, dst="192.168.56.1") / UDP(sport=53535, dport=53) / Raw(load=b"DNS_LOOKUP")
        dns_pkt.time = base_time + 1.0
        packets.append(dns_pkt)

        # Write synthetic PCAP to disk
        wrpcap(self.pcap_path, packets)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_parse_and_detection_queries(self):
        # 1. Parse PCAP
        inserted = parse_pcap(self.pcap_path, self.db_path)
        self.assertGreater(inserted, 0, "Should have inserted flows into database")

        # 2. Flag Exfiltration
        exfil_flows = flag_exfiltration(self.db_path, threshold_bytes=50000)
        self.assertEqual(len(exfil_flows), 1, "Should identify exactly 1 exfiltration flow")
        exfil_flow = exfil_flows[0]
        self.assertEqual(exfil_flow["dst_port"], getattr(config, "TRANSFER_PORT", 9002))
        self.assertGreaterEqual(exfil_flow["total_bytes"], 100000)

        # 3. Flag C2 Beacon
        beacon_result = flag_c2_beacon(self.db_path, min_connections=2)
        self.assertTrue(beacon_result["beaconing_detected"], "C2 beaconing should be detected")
        self.assertTrue(beacon_result["is_periodic"], "Beaconing should be identified as periodic")
        self.assertEqual(beacon_result["flow_count"], 3)
        self.assertAlmostEqual(beacon_result["mean_interval_sec"], 2.0, places=1)

        # 4. Flag Large Outbound
        large_flows = flag_large_outbound(self.db_path, threshold_bytes=80000)
        self.assertEqual(len(large_flows), 1)

        # 5. Detection latency calculation
        latency = record_detection_latency(self.db_path)
        self.assertIsNotNone(latency)
        self.assertGreaterEqual(latency, 0.0)


if __name__ == "__main__":
    unittest.main()
