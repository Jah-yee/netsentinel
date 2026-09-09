"""pcap reader/writer + layer decoder tests."""
import os
import struct
import unittest

from netsentinel.pcap import (DLT_EN10MB, DLT_RAW, extract, extract_flows,
                              payload_entropy, read_pcap, write_pcap)
from tests._base import FixtureTestCase


class TestPcapRead(FixtureTestCase):

    def test_linktype_and_length(self):
        cap = read_pcap(self.fixtures["baseline"])
        self.assertEqual(cap.linktype, DLT_RAW)
        self.assertGreater(len(cap.packets), 30)

    def test_ethernet_linktype(self):
        cap = read_pcap(self.fixtures["arp_spoof_a"])
        self.assertEqual(cap.linktype, DLT_EN10MB)
        self.assertGreater(len(cap.packets), 0)

    def test_ipv4_fields(self):
        pkt = next(p for p in extract(read_pcap(self.fixtures["baseline"]))
                   if p.get("ip"))
        self.assertEqual(pkt["ip"]["version"], 4)
        self.assertTrue(pkt["ip"]["src"].startswith("192.0.2."))
        self.assertIn(pkt["ip"]["proto"], (6, 17))

    def test_tcp_flags_decoded(self):
        pkts = extract(read_pcap(self.fixtures["scan"]))
        syn = next(p for p in pkts if p.get("tcp") and p["tcp"]["flags"]["SYN"])
        self.assertTrue(syn["tcp"]["flags"]["SYN"])
        self.assertFalse(syn["tcp"]["flags"]["ACK"])
        self.assertEqual(syn["tcp"]["flags_raw"], 0x02)

    def test_tcp_ports(self):
        pkts = extract(read_pcap(self.fixtures["scan"]))
        with_open = next(p for p in pkts if p.get("tcp") and p["tcp"]["dst_port"] == 8080)
        self.assertEqual(with_open["ip"]["src"], "192.0.2.66")

    def test_udp_ports(self):
        pkts = extract(read_pcap(self.fixtures["dns_clean"]))
        q = next(p for p in pkts if p.get("udp") and p["udp"]["dst_port"] == 53)
        self.assertEqual(q["udp"]["src_port"], 53002)

    def test_dns_query_parsed(self):
        pkts = extract(read_pcap(self.fixtures["dns_clean"]))
        dns = [p["dns"] for p in pkts if p.get("dns") and p["dns"]["qr"] == 0]
        self.assertEqual(len(dns), 1)
        self.assertEqual(dns[0]["id"], 0x2222)
        self.assertEqual(dns[0]["questions"][0]["qname"], "www.good.example.test")

    def test_dns_response_answers(self):
        pkts = extract(read_pcap(self.fixtures["dns_clean"]))
        resp = [p["dns"] for p in pkts if p.get("dns") and p["dns"]["qr"] == 1]
        self.assertEqual(len(resp), 1)
        self.assertEqual(resp[0]["answers"][0]["rdata"], "198.51.100.100")

    def test_arp_parsed(self):
        pkts = extract(read_pcap(self.fixtures["arp_spoof_a"]))
        who = next(p for p in pkts if p.get("arp") and p["arp"]["op"] == 1)
        repl = [p["arp"] for p in pkts if p.get("arp") and p["arp"]["op"] == 2]
        self.assertEqual(who["arp"]["tpa"], "192.0.2.66")
        self.assertGreaterEqual(len(repl), 3)
        macs = {r["sha_mac"] for r in repl}
        self.assertEqual(len(macs), 3)

    def test_dhcp_message_type(self):
        pkts = extract(read_pcap(self.fixtures["dhcp_starvation"]))
        discovers = [p["dhcp"] for p in pkts if p.get("dhcp")
                     and p["dhcp"]["message_type"] == 1]
        self.assertEqual(len(discovers), 40)
        self.assertEqual(discovers[0]["requested_ip"], "192.0.2.66")

    def test_flow_aggregation(self):
        flows = extract_flows(extract(read_pcap(self.fixtures["baseline"])))
        self.assertGreaterEqual(len(flows), 14)
        f = flows[0]
        self.assertEqual(f["client_ip"], "192.0.2.10")
        self.assertGreaterEqual(f["packets"], 1)
        self.assertGreater(f["bytes"], 0)
        self.assertGreaterEqual(f["bytes_client_to_server"], 0)
        self.assertGreaterEqual(f["bytes_server_to_client"], 0)

    def test_flow_payload_entropy_is_float(self):
        flows = extract_flows(extract(read_pcap(self.fixtures["baseline"])))
        for f in flows:
            self.assertIsInstance(f["payload_entropy"], float)

    def test_payload_entropy_zero_and_max(self):
        self.assertEqual(payload_entropy(b""), 0.0)
        self.assertEqual(payload_entropy(b"AAAA"), 0.0)
        self.assertAlmostEqual(payload_entropy(bytes(range(256))), 8.0, places=4)

    def test_write_read_roundtrip(self):
        path = os.path.join(self._tmp, "rt.pcap")
        write_pcap(path, [(100.0, b"\x00"), (100.5, b"\x01\x02")], linktype=DLT_RAW)
        cap = read_pcap(path)
        self.assertEqual(len(cap.packets), 2)
        self.assertEqual(cap.packets[0].data, b"\x00")
        self.assertAlmostEqual(cap.packets[0].ts, 100.0)
        self.assertEqual(cap.linktype, DLT_RAW)

    def test_big_endian_pcap_legible(self):
        path = os.path.join(self._tmp, "be.pcap")
        header = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, DLT_RAW)
        payload = struct.pack(">IIII", 99, 0, 2, 2) + b"\xab\xcd"
        with open(path, "wb") as fh:
            fh.write(header + payload)
        cap = read_pcap(path)
        self.assertEqual(cap.packets[0].ts, 99.0)
        self.assertEqual(cap.packets[0].data, b"\xab\xcd")

    def test_truncated_record_tolerated(self):
        path = os.path.join(self._tmp, "trunc.pcap")
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, DLT_RAW)
        rec = struct.pack("<IIII", 5, 0, 1, 1) + b"\x01"
        junk = struct.pack("<IIII", 9, 0, 50, 50)   # claims 50 bytes, none present
        with open(path, "wb") as fh:
            fh.write(header + rec + junk)
        cap = read_pcap(path)
        self.assertEqual(len(cap.packets), 1)

    def test_parse_error_tolerated(self):
        cap = read_pcap(self.fixtures["baseline"])
        pkts = extract(cap)
        self.assertGreater(len(pkts), 0)

    def test_smb_magic_hex_in_payload(self):
        pkts = extract(read_pcap(self.fixtures["smb_probe"]))
        tcp = [p for p in pkts if p.get("tcp")][0]
        self.assertTrue(tcp["payload"].startswith(b"\xff\x53\x4d\x42"))


if __name__ == "__main__":
    unittest.main()