"""Rules engine tests (Suricata-style subset)."""
import os
import unittest

from netsentinel.config import load_config
from netsentinel.pcap import extract, read_pcap
from netsentinel.rules import Rule, RuleParseError, RulesEngine, content_to_bytes
from netsentinel.fixtures.pcapbuild import tcp_pkt, udp_pkt
from netsentinel.pcap import DLT_RAW, Packet, decode_packet
from tests._base import FixtureTestCase

SCAN_RULE = ('alert tcp any any -> any any (msg:"test scan"; flags:S; threshold:20; '
             'sid:900001; rev:1; severity:2; classtype:attempted-recon; '
             'reference:url,https://example.test)')


class TestRuleParsing(unittest.TestCase):

    def test_parse_header_and_options(self):
        r = Rule.parse(SCAN_RULE)
        self.assertEqual(r.action, "alert")
        self.assertEqual(r.proto, "tcp")
        self.assertEqual(r.src, "any")
        self.assertEqual(r.dport, "any")
        self.assertEqual(r.msg, "test scan")
        self.assertEqual(r.flags, "S")
        self.assertEqual(r.threshold, 20)
        self.assertEqual(r.sid, 900001)
        self.assertEqual(r.severity, 2)
        self.assertEqual(r.classtype, "attempted-recon")
        self.assertEqual(r.references, ["url,https://example.test"])

    def test_msg_containing_parentheses_ok(self):
        r = Rule.parse('alert tcp any any -> any any (msg:"lab (nmap) scan"; sid:900002)')
        self.assertEqual(r.msg, "lab (nmap) scan")

    def test_content_to_bytes_hex_and_ascii(self):
        self.assertEqual(content_to_bytes("|ff d8 ff e0|"), b"\xff\xd8\xff\xe0")
        self.assertEqual(content_to_bytes("GET /"), b"GET /")
        self.assertEqual(content_to_bytes("SHELL!|00 01|"), b"SHELL!\x00\x01")

    def test_content_hex_bad_raises(self):
        with self.assertRaises(RuleParseError):
            content_to_bytes("|ff gz|")

    def test_missing_sid_raises(self):
        with self.assertRaises(RuleParseError):
            Rule.parse('alert tcp any any -> any any (msg:"no sid")')

    def test_unknown_option_raises(self):
        with self.assertRaises(RuleParseError):
            Rule.parse('alert tcp any any -> any any (msg:"x"; bogus:1; sid:1)')

    def test_default_severity_applied(self):
        r = Rule.parse('alert tcp any any -> any any (msg:"x"; sid:3)')
        self.assertEqual(r.severity, 2)


class TestRulesEngine(FixtureTestCase):

    def setUp(self):
        self.cfg = load_config(None)

    def _engine(self, rules):
        return RulesEngine([Rule.parse(r) for r in rules])

    def test_nmap_threshold_rule_fires(self):
        eng = self._engine([SCAN_RULE])
        alerts = eng.scan(extract(read_pcap(self.fixtures["scan"])))
        fired = [a for a in alerts if a.evidence["sid"] == 900001]
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0].src, "192.0.2.66")
        self.assertEqual(fired[0].dst, "198.51.100.2")

    def test_threshold_not_reached_on_baseline(self):
        eng = self._engine([SCAN_RULE])
        alerts = eng.scan(extract(read_pcap(self.fixtures["baseline"])))
        self.assertEqual([a for a in alerts if a.evidence["sid"] == 900001], [])

    def test_content_rule_fires_with_evidence(self):
        eng = self._engine(['alert tcp any any -> any any '
                            '(msg:"jpg"; content:"|ff d8 ff e0|"; sid:900010; severity:2)'])
        alerts = eng.scan(extract(read_pcap(self.fixtures["scan"])))
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0].evidence["matched_contents"])
        self.assertEqual(alerts[0].dst, "198.51.100.2")

    def test_multiple_contents_must_all_match(self):
        ok = 'alert tcp any any -> any any (msg:"ok"; content:"SHELL!"; content:"OR 1=1--"; sid:900011)'
        eng = self._engine([ok])
        alerts = eng.scan(extract(read_pcap(self.fixtures["scan"])))
        self.assertEqual(len(alerts), 1)
        no = 'alert tcp any any -> any any (msg:"no"; content:"SHELL!"; content:"nope"; sid:900012)'
        eng2 = self._engine([no])
        self.assertEqual(eng2.scan(extract(read_pcap(self.fixtures["scan"]))), [])

    def test_flags_exact_match(self):
        sak = 'alert tcp any any -> any any (msg:"sa"; flags:SA; sid:900013)'
        s_only = 'alert tcp any any -> any any (msg:"s"; flags:S; sid:900014)'
        # controlled packets: a pure-SYN and a pure SYN-ACK (SA=0x12)
        pure_syn = tcp_pkt("192.0.2.77", 1001, "198.51.100.3", 80, 5, 0x02)
        syn_ack = tcp_pkt("198.51.100.3", 80, "192.0.2.77", 1001, 6, 0x12, ack=6)
        pkts = [
            decode_packet(Packet(0, 100.0, len(pure_syn), len(pure_syn), pure_syn), DLT_RAW),
            decode_packet(Packet(1, 100.1, len(syn_ack), len(syn_ack), syn_ack), DLT_RAW),
        ]
        eng = self._engine([sak, s_only])
        alerts = eng.scan(pkts)
        sids = {a.evidence["sid"] for a in alerts}
        self.assertIn(900014, sids)
        self.assertIn(900013, sids)
        # exact match: SA rule must NOT fire on the pure-SYN packet
        sa_pkt = next(a for a in alerts if a.evidence["sid"] == 900013)
        self.assertEqual(sa_pkt.src, "198.51.100.3")

    def test_src_cidr_filter(self):
        r = 'alert tcp 192.0.2.0/24 any -> any any (msg:"cidr"; flags:S; threshold:20; sid:900015)'
        eng = self._engine([r])
        a = eng.scan(extract(read_pcap(self.fixtures["scan"])))
        self.assertEqual(len(a), 1)
        r2 = 'alert tcp 198.51.100.99/32 any -> any any (msg:"no"; flags:S; threshold:20; sid:900016)'
        eng2 = self._engine([r2])
        self.assertEqual(eng2.scan(extract(read_pcap(self.fixtures["scan"]))), [])

    def test_udp_rule_proto_filter(self):
        # SMB magic travels over TCP in the fixture; a UDP rule must not fire.
        eng = self._engine(['alert udp any any -> any any '
                            '(msg:"udp smb"; content:"|ff 53 4d 42|"; sid:900020)'])
        self.assertEqual(eng.scan(extract(read_pcap(self.fixtures["smb_probe"]))), [])

    def test_udp_smb_rule_fires(self):
        eng = self._engine(['alert udp any any -> any any '
                            '(msg:"udp smb"; content:"|ff 53 4d 42|"; sid:900021)'])
        raw = udp_pkt("203.0.113.5", 4000, "198.51.100.40", 137, b"\xffSMBSMBSMBsamba")
        pkt = decode_packet(Packet(0, 100.0, len(raw), len(raw), raw), DLT_RAW)
        alerts = eng.scan([pkt])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, "rules.content.match")

    def test_dns_rule_fires_on_query(self):
        eng = RulesEngine.load_rules(self.cfg["rules"]["file"],
                                     self.cfg["rules"].get("default_severity", 2))
        alerts = eng.scan(extract(read_pcap(self.fixtures["dns_clean"])))
        sids = {a.evidence["sid"] for a in alerts}
        self.assertIn(1000006, sids)

    def test_nmap_bundled_rule_fires(self):
        eng = RulesEngine.load_rules(self.cfg["rules"]["file"],
                                     self.cfg["rules"].get("default_severity", 2))
        alerts = eng.scan(extract(read_pcap(self.fixtures["scan"])))
        sids = {a.evidence["sid"] for a in alerts}
        self.assertIn(1000001, sids)
        self.assertIn(1000002, sids)
        self.assertIn(1000003, sids)
        self.assertIn(1000004, sids)
        self.assertLessEqual(len(alerts), 4)

    def test_load_rules_file(self):
        eng = RulesEngine.load_rules(self.cfg["rules"]["file"])
        sids = {r.sid for r in eng.rules}
        self.assertTrue(sids >= {1000001, 1000002, 1000003, 1000004, 1000005, 1000006})

    def test_severity_carried_into_alert(self):
        eng = self._engine(['alert tcp any any -> any any '
                            '(msg:"hi"; content:"OR 1=1--"; sid:900030; severity:1)'])
        alerts = eng.scan(extract(read_pcap(self.fixtures["scan"])))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 1)

    def test_within_option_enforced(self):
        # exploit payload contains jpg magic at offset 0: matches with within:8
        ok = 'alert tcp any any -> any any (msg:"w"; content:"|ff d8 ff e0|"; within:8; sid:900040)'
        eng = self._engine([ok])
        self.assertEqual(len(eng.scan(extract(read_pcap(self.fixtures["scan"])))), 1)
        no = 'alert tcp any any -> any any (msg:"w"; content:"SHELL!"; within:4; sid:900041)'
        eng2 = self._engine([no])
        self.assertEqual(eng2.scan(extract(read_pcap(self.fixtures["scan"]))), [])


if __name__ == "__main__":
    unittest.main()