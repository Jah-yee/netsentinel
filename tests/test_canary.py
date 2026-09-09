"""MITM / transport-signature detector tests."""
import unittest

from netsentinel.canary import (CanaryEngine, detect_arp_spoof,
                                detect_dhcp_starvation, detect_dns_anomalies,
                                detect_tcp_signatures)
from netsentinel.config import load_config
from netsentinel.pcap import extract, read_pcap
from tests._base import FixtureTestCase


class TestArpSpoof(FixtureTestCase):

    def test_spoof_fixture_a_fires(self):
        alerts = detect_arp_spoof(extract(read_pcap(self.fixtures["arp_spoof_a"])))
        self.assertEqual(len(alerts), 2)
        self.assertTrue(all(a.category == "arp.spoof" for a in alerts))
        self.assertEqual({a.src for a in alerts}, {"192.0.2.66"})

    def test_clean_fixture_b_no_alert(self):
        alerts = detect_arp_spoof(extract(read_pcap(self.fixtures["arp_spoof_b"])))
        self.assertEqual(alerts, [])

    def test_evidence_lists_two_macs(self):
        alerts = detect_arp_spoof(extract(read_pcap(self.fixtures["arp_spoof_a"])))
        self.assertEqual(len(alerts[0].evidence["macs"]), 2)

    def test_single_unique_mac_no_alert(self):
        pkts = extract(read_pcap(self.fixtures["arp_spoof_b"]))
        dup = []
        for p in pkts:
            if p.get("arp") and p["arp"]["op"] == 2:
                # duplicate the same reply (same MAC): not a spoof signature
                dup.append(p)
                dup.append(p)
            else:
                dup.append(p)
        self.assertEqual(detect_arp_spoof(dup), [])


class TestDhcpStarvation(FixtureTestCase):

    def test_starvation_fires(self):
        alerts = detect_dhcp_starvation(
            extract(read_pcap(self.fixtures["dhcp_starvation"])), discover_threshold=20)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, "dhcp.starvation")
        self.assertEqual(alerts[0].src, "192.0.2.66")

    def test_clean_no_alert(self):
        alerts = detect_dhcp_starvation(
            extract(read_pcap(self.fixtures["dhcp_clean"])), discover_threshold=20)
        self.assertEqual(alerts, [])

    def test_threshold_respected(self):
        alerts = detect_dhcp_starvation(
            extract(read_pcap(self.fixtures["dhcp_starvation"])), discover_threshold=100)
        self.assertEqual(alerts, [])

    def test_evidence_discover_count(self):
        alerts = detect_dhcp_starvation(
            extract(read_pcap(self.fixtures["dhcp_starvation"])), discover_threshold=20)
        self.assertEqual(alerts[0].evidence["discovers"], 40)


class TestDnsAnomalies(FixtureTestCase):

    def test_dns_id_mismatch_fires(self):
        alerts = detect_dns_anomalies(extract(read_pcap(self.fixtures["dns_mismatch"])))
        cats = {a.category for a in alerts}
        self.assertIn("dns.id_mismatch", cats)
        self.assertIn("dns.source_mismatch", cats)

    def test_dns_clean_no_alert(self):
        alerts = detect_dns_anomalies(extract(read_pcap(self.fixtures["dns_clean"])))
        self.assertEqual(alerts, [])

    def test_id_mismatch_evidence(self):
        alerts = detect_dns_anomalies(extract(read_pcap(self.fixtures["dns_mismatch"])))
        mm = next(a for a in alerts if a.category == "dns.id_mismatch")
        self.assertEqual(mm.evidence["id"], 0x9999)
        self.assertEqual(mm.src, "192.0.2.66")

    def test_source_mismatch_evidence(self):
        alerts = detect_dns_anomalies(extract(read_pcap(self.fixtures["dns_mismatch"])))
        sm = next(a for a in alerts if a.category == "dns.source_mismatch")
        self.assertEqual(sm.evidence["expected_server"], "198.51.100.53")
        self.assertEqual(sm.evidence["actual_source"], "192.0.2.66")

    def test_too_many_answers_same_id(self):
        # two responses for the same pending id are still source-mismatched
        pkts = extract(read_pcap(self.fixtures["dns_mismatch"]))
        alerts = detect_dns_anomalies(pkts)
        self.assertGreaterEqual(len(alerts), 2)


class TestTcpSignatures(FixtureTestCase):

    def test_rst_flood_fires(self):
        alerts = detect_tcp_signatures(extract(read_pcap(self.fixtures["rst_flood"])),
                                       rst_threshold=50)
        self.assertEqual(alerts[0].category, "tcp.rst_flood")
        self.assertEqual(alerts[0].src, "192.0.2.66")
        self.assertEqual(alerts[0].evidence["rst_count"], 60)

    def test_single_rst_no_alert(self):
        alerts = detect_tcp_signatures(extract(read_pcap(self.fixtures["rst_clean"])),
                                       rst_threshold=50)
        self.assertEqual(alerts, [])

    def test_rst_threshold_not_reached(self):
        alerts = detect_tcp_signatures(extract(read_pcap(self.fixtures["rst_flood"])),
                                       rst_threshold=500)
        self.assertEqual(alerts, [])

    def test_syn_flood_signature(self):
        from netsentinel.fixtures.pcapbuild import tcp_pkt, write_pcap
        from netsentinel.pcap import DLT_RAW
        import tempfile, os
        pkts = [(1700000000.0 + i * 0.01, tcp_pkt("192.0.2.77", 1000 + i, "198.51.100.3", 80,
                                                  1, 0x02)) for i in range(120)]
        with tempfile.TemporaryDirectory() as d:
            path = write_pcap(os.path.join(d, "syn.pcap"), pkts, linktype=DLT_RAW)
            alerts = detect_tcp_signatures(extract(read_pcap(path)), syn_threshold=100)
            floods = [a for a in alerts if a.category == "tcp.syn_flood"]
            self.assertEqual(len(floods), 1)
            self.assertEqual(floods[0].evidence["syn_count"], 120)


class TestCanaryEngine(FixtureTestCase):

    def setUp(self):
        self.cfg = load_config(None)

    def test_scan_defaults(self):
        eng = CanaryEngine()
        alerts = eng.scan_capture(read_pcap(self.fixtures["arp_spoof_a"]), self.cfg)
        self.assertEqual(len(alerts), 2)

    def test_module_field(self):
        eng = CanaryEngine()
        alerts = eng.scan_capture(read_pcap(self.fixtures["dns_mismatch"]))
        self.assertTrue(all(a.module == "canary" for a in alerts))

    def test_dedupe_keys_unique_for_dup_macs(self):
        alerts = detect_arp_spoof(extract(read_pcap(self.fixtures["arp_spoof_a"])))
        keys = {a.key() for a in alerts}
        self.assertEqual(len(keys), 2)


if __name__ == "__main__":
    unittest.main()