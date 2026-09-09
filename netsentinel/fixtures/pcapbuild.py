"""Fixture packet builders + pcap fixture generators.

All fixture traffic is synthetic and local-only: IPs use RFC 5737
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and the
attacker identity is the documentation host 192.0.2.66. Nothing here touches
a real network. Packet building includes correct IP/TCP/UDP checksums.

`off` offsets are relative to BASE and used by the demo to lay out a coherent
kill-chain timeline (recon -> weaponize -> delivery -> ...).
"""
from __future__ import annotations

import os
import random
import struct
from typing import List, Optional, Tuple

from ..pcap import DLT_EN10MB, DLT_RAW, _checksum16, ip_checksum, write_pcap

BASE = 1700000000.0
ATTACKER = "192.0.2.66"
VICTIM = "192.0.2.10"
SERVER = "198.51.100.2"

F00 = bytes.fromhex("ffffffffffff")
VICTIM_MAC = bytes.fromhex("0a0000000001")
ATT_MAC1 = bytes.fromhex("f00000000001")
ATT_MAC2 = bytes.fromhex("f00000000002")
ATT_MAC3 = bytes.fromhex("f00000000003")


def _ip_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def _htons(n: int) -> bytes:
    return struct.pack("!H", n & 0xFFFF)


def eth_frame(dst_mac: bytes, src_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + _htons(ethertype) + payload


def arp_frame(op: int, sha: bytes, spa: str, tha: bytes, tpa: str, src_eth: bytes, dst_eth: bytes) -> bytes:
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + sha + _ip_bytes(spa) + tha + _ip_bytes(tpa)
    return eth_frame(dst_eth, src_eth, 0x0806, body)


def ipv4_pkt(src: str, dst: str, proto: int, payload: bytes, ident: int = 0, ttl: int = 64,
             flags: int = 0b010, frag_off: int = 0) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, (flags << 13) | frag_off,
                      ttl, proto, 0, _ip_bytes(src), _ip_bytes(dst))
    csum = ip_checksum(hdr)
    hdr = hdr[:10] + _htons(csum) + hdr[12:]
    return hdr + payload


def tcp_pkt(src: str, sport: int, dst: str, dport: int, seq: int, flags_bits: int,
            payload: bytes = b"", ack: int = 0, win: int = 65535) -> bytes:
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags_bits, win, 0, 0) + payload
    pseudo = _ip_bytes(src) + _ip_bytes(dst) + struct.pack("!BBH", 0, 6, len(seg))
    csum = _checksum16(pseudo + seg)
    seg = seg[:16] + _htons(csum) + seg[18:]
    return ipv4_pkt(src, dst, 6, seg)


def udp_pkt(src: str, sport: int, dst: str, dport: int, payload: bytes) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = _ip_bytes(src) + _ip_bytes(dst) + struct.pack("!BBH", 0, 17, len(seg))
    csum = _checksum16(pseudo + seg)
    seg = seg[:6] + _htons(csum) + seg[8:]
    return ipv4_pkt(src, dst, 17, seg)


def dns_qname(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        out += bytes([len(part)]) + part.encode("latin-1")
    return out + b"\x00"


def dns_query_pkt(cid: int, qname: str, csrc: str, cport: int, server: str) -> bytes:
    q = struct.pack("!HHHHHH", cid, 0x0100, 1, 0, 0, 0) + dns_qname(qname) + struct.pack("!HH", 1, 1)
    return udp_pkt(csrc, cport, server, 53, q)


def dns_response_pkt(cid: int, qname: str, rdata_ip: str, csrc: str, cport: int, server: str) -> bytes:
    header = struct.pack("!HHHHHH", cid, 0x8180, 1, 1, 0, 0)
    q = dns_qname(qname) + struct.pack("!HH", 1, 1)
    an = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + _ip_bytes(rdata_ip)
    return udp_pkt(server, 53, csrc, cport, header + q + an)


def dhcp_pkt(op: int, mac: bytes, xid: int, msg_type: int, requested_ip: Optional[str] = None,
             src_ip: str = "0.0.0.0", src_port: int = 68, dst_ip: str = "255.255.255.255",
             dst_port: int = 67) -> bytes:
    chaddr = mac.ljust(16, b"\x00")
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, xid, 0, 0,
                        _ip_bytes(src_ip), b"\x00\x00\x00\x00", b"\x00\x00\x00\x00",
                        b"\x00\x00\x00\x00", chaddr, b"", b"")
    opts = b"\x63\x82\x53\x63" + bytes([53, 1, msg_type])
    if requested_ip:
        opts += bytes([50, 4]) + _ip_bytes(requested_ip)
    opts += bytes([255])
    return udp_pkt(src_ip, src_port, dst_ip, dst_port, bootp + opts)


T = Tuple[float, bytes]


def _ts(off: float) -> float:
    return BASE + off


def build_baseline(path: str, linktype: int = DLT_RAW, seed: int = 0x5EED, off: float = 0.0) -> str:
    rng = random.Random(seed)
    packets: List[T] = []
    t = off
    payloads = [
        b"GET /index.html HTTP/1.1\r\nHost: www.example.test\r\nUser-Agent: test-agent\r\n\r\n",
        b"POST /submit HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 5\r\n\r\nhello",
        b"220 mail.example.test ESMTP Postfix\r\nMAIL FROM:<user@example.test>\r\n",
        b"\x16\x03\x01\x00!\x01\x00\x00\x1d\x03\x03" + bytes(rng.getrandbits(8)
                                                             for _ in range(24)),
        b"DATA\r\nsubject: fixture\r\n\r\nbody line one\r\nbody line two\r\n.\r\n",
        b"GET /robots.txt HTTP/1.1\r\nHost: www.example.test\r\n\r\n",
    ]
    for i in range(14):
        client_ip = f"192.0.2.{10 + i}"
        server_ip = f"198.51.100.{20 + (i % 6)}"
        server_port = [80, 443, 25, 53, 8080, 443][i % 6]
        cport = 10000 + i * 137
        n_pkts = 5 + (i % 10)
        base_seq = rng.getrandbits(31)
        for p in range(n_pkts):
            payload = payloads[(i + p) % len(payloads)]
            if server_port == 53:
                packets.append((_ts(t), dns_query_pkt(0x1000 + i, f"node{i}.example.test",
                                                      client_ip, cport, server_ip)))
            else:
                if p == 0:
                    fl = tcp_pkt(client_ip, cport, server_ip, server_port, base_seq, 0x02)
                elif p == 1:
                    fl = tcp_pkt(server_ip, server_port, client_ip, cport, base_seq + 1, 0x12,
                                 ack=base_seq + 1)
                else:
                    fl = tcp_pkt(client_ip, cport, server_ip, server_port, base_seq + p,
                                 0x18, payload=payload, ack=base_seq + 2)
                packets.append((_ts(t), fl))
            t += 0.12 + (p * 0.02)
        t += 1.5
    write_pcap(path, packets, linktype=linktype)
    return path


def build_scan(path: str, linktype: int = DLT_RAW, off: float = 0.0) -> str:
    """Recon + weaponization stage: SYN scan burst then a single exploit flow."""
    packets: List[T] = []
    for i in range(1, 31):
        packets.append((_ts(off + i * 0.01),
                        tcp_pkt(ATTACKER, 40000 + i, SERVER, i, 1000 + i, 0x02)))
    payload = (b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF\x00\x01" + b"EXPLOIT_PAYLOAD_"
               + b"SHELL!" + b"\x00\x01\x02\x03" + b" OR 1=1-- probe")
    seq = 1_000_000
    t = off + 1.0
    packets.append((_ts(t), tcp_pkt(ATTACKER, 50000, SERVER, 8080, seq, 0x02)))
    packets.append((_ts(t + 0.01), tcp_pkt(SERVER, 8080, ATTACKER, 50000, 2_000_000, 0x12,
                                           ack=seq + 1)))
    seq += 1
    packets.append((_ts(t + 0.02), tcp_pkt(ATTACKER, 50000, SERVER, 8080, seq, 0x18,
                                           payload=payload, ack=2_000_001)))
    packets.append((_ts(t + 0.03), tcp_pkt(SERVER, 8080, ATTACKER, 50000, 2_000_003, 0x10,
                                           ack=seq + len(payload))))
    write_pcap(path, packets, linktype=linktype)
    return path


def build_exfil(path: str, linktype: int = DLT_RAW, off: float = 0.0) -> str:
    """Exploitation stage: a 220-packet / 40-byte exfiltration burst."""
    packets: List[T] = [
        (_ts(off + i * 0.004),
         tcp_pkt(ATTACKER, 41000, "198.51.100.20", 5555, 5_000_000 + i,
                 0x18, payload=b"A" * 40))
        for i in range(220)
    ]
    write_pcap(path, packets, linktype=linktype)
    return path


def build_attack(path: str, linktype: int = DLT_RAW, off: float = 0.0) -> str:
    """Everything (scan + exploit + burst + RST + DNS) for end-to-end testing."""
    packets: List[T] = []
    for i in range(1, 31):
        packets.append((_ts(off + i * 0.01),
                        tcp_pkt(ATTACKER, 40000 + i, SERVER, i, 1000 + i, 0x02)))
    payload = (b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF\x00\x01" + b"EXPLOIT_PAYLOAD_"
               + b"SHELL!" + b"\x00\x01\x02\x03" + b" OR 1=1-- probe")
    seq = 1_000_000
    t = off + 1.0
    packets.append((_ts(t), tcp_pkt(ATTACKER, 50000, SERVER, 8080, seq, 0x02)))
    packets.append((_ts(t + 0.01), tcp_pkt(SERVER, 8080, ATTACKER, 50000, 2_000_000, 0x12,
                                           ack=seq + 1)))
    seq += 1
    packets.append((_ts(t + 0.02), tcp_pkt(ATTACKER, 50000, SERVER, 8080, seq, 0x18,
                                           payload=payload, ack=2_000_001)))
    packets.append((_ts(t + 0.03), tcp_pkt(SERVER, 8080, ATTACKER, 50000, 2_000_003, 0x10,
                                           ack=seq + len(payload))))
    for i in range(220):
        packets.append((_ts(off + 2.0 + i * 0.004),
                        tcp_pkt(ATTACKER, 41000, "198.51.100.20", 5555, 5_000_000 + i,
                                0x18, payload=b"A" * 40)))
    for i in range(60):
        packets.append((_ts(off + 4.0 + i * 0.005),
                        tcp_pkt(ATTACKER, 1111, "198.51.100.9", 80, 9_000_000 + i, 0x04)))
    packets.append((_ts(off + 5.0), dns_query_pkt(0x1234, "www.attacker.example.test", VICTIM, 53000,
                                                  "198.51.100.53")))
    packets.append((_ts(off + 5.01), dns_response_pkt(0x1234, "www.attacker.example.test",
                                                      "198.51.100.200", VICTIM, 53000, ATTACKER)))
    packets.append((_ts(off + 5.02), dns_response_pkt(0x7777, "www.attacker.example.test",
                                                      "198.51.100.201", VICTIM, 53000, ATTACKER)))
    write_pcap(path, sorted(packets, key=lambda p: p[0]), linktype=linktype)
    return path


def build_arp_spoof(path: str, reply_count: int = 3, off: float = 0.0) -> str:
    macs = [ATT_MAC1, ATT_MAC2, ATT_MAC3][:reply_count]
    packets: List[T] = [
        (_ts(off), arp_frame(1, VICTIM_MAC, VICTIM, F00, ATTACKER, VICTIM_MAC, F00)),
    ]
    for i, mac in enumerate(macs):
        packets.append((_ts(off + 0.05 + i * 0.01), arp_frame(2, mac, ATTACKER, VICTIM_MAC, VICTIM, mac,
                                                              VICTIM_MAC)))
    write_pcap(path, packets, linktype=DLT_EN10MB)
    return path


def build_arp_clean(path: str, off: float = 0.0) -> str:
    packets: List[T] = [
        (_ts(off), arp_frame(1, VICTIM_MAC, VICTIM, F00, ATTACKER, VICTIM_MAC, F00)),
        (_ts(off + 0.1), arp_frame(2, ATT_MAC1, ATTACKER, VICTIM_MAC, VICTIM, ATT_MAC1, VICTIM_MAC)),
    ]
    write_pcap(path, packets, linktype=DLT_EN10MB)
    return path


def build_dns_mismatch(path: str, off: float = 0.0) -> str:
    packets: List[T] = [
        (_ts(off), dns_query_pkt(0x1234, "www.good.example.test", "192.0.2.11", 53001, "198.51.100.53")),
        (_ts(off + 0.01), dns_response_pkt(0x1234, "www.good.example.test", "198.51.100.100",
                                           "192.0.2.11", 53001, ATTACKER)),
        (_ts(off + 0.02), dns_response_pkt(0x9999, "www.good.example.test", "198.51.100.101",
                                           "192.0.2.11", 53001, ATTACKER)),
    ]
    write_pcap(path, packets, linktype=DLT_RAW)
    return path


def build_dns_clean(path: str, off: float = 0.0) -> str:
    packets: List[T] = [
        (_ts(off), dns_query_pkt(0x2222, "www.good.example.test", "192.0.2.12", 53002, "198.51.100.53")),
        (_ts(off + 0.2), dns_response_pkt(0x2222, "www.good.example.test", "198.51.100.100",
                                          "192.0.2.12", 53002, "198.51.100.53")),
    ]
    write_pcap(path, packets, linktype=DLT_RAW)
    return path


def build_dhcp_starvation(path: str, count: int = 40, off: float = 0.0) -> str:
    mac = bytes.fromhex("aabbccddee01")
    packets: List[T] = [
        (_ts(off + i * 0.05), dhcp_pkt(1, mac, 0x1000 + (i % 7), 1, requested_ip=ATTACKER))
        for i in range(count)
    ]
    write_pcap(path, packets, linktype=DLT_RAW)
    return path


def build_dhcp_clean(path: str, off: float = 0.0) -> str:
    mac1 = bytes.fromhex("aabbccddee02")
    mac2 = bytes.fromhex("aabbccddee03")
    packets: List[T] = [
        (_ts(off), dhcp_pkt(1, mac1, 0x7001, 1)),
        (_ts(off + 0.05), dhcp_pkt(2, mac1, 0x7001, 2, dst_ip="192.0.2.21", dst_port=68, src_ip="198.51.100.67")),
        (_ts(off + 0.1), dhcp_pkt(1, mac2, 0x7002, 1)),
        (_ts(off + 0.15), dhcp_pkt(2, mac2, 0x7002, 2, dst_ip="192.0.2.22", dst_port=68, src_ip="198.51.100.67")),
    ]
    write_pcap(path, packets, linktype=DLT_RAW)
    return path


def build_rst_flood(path: str, count: int = 60, off: float = 0.0) -> str:
    packets: List[T] = [
        (_ts(off + i * 0.005), tcp_pkt(ATTACKER, 1111, "198.51.100.9", 80, 9_000_000 + i, 0x04))
        for i in range(count)
    ]
    write_pcap(path, packets, linktype=DLT_RAW)
    return path


def build_rst_clean(path: str, off: float = 0.0) -> str:
    packets: List[T] = [
        (_ts(off), tcp_pkt("192.0.2.30", 54321, "198.51.100.30", 443, 5, 0x04)),
    ]
    write_pcap(path, packets, linktype=DLT_RAW)
    return path


def build_smb_probe(path: str, off: float = 0.0) -> str:
    """Single SMB/NBT probe packet with SMB magic in payload (rules test)."""
    packets: List[T] = [
        (_ts(off), tcp_pkt("203.0.113.5", 4444, "198.51.100.40", 139, 10, 0x18,
                           payload=b"\xff\x53\x4d\x42" + b"samba probe")),
    ]
    write_pcap(path, packets, linktype=DLT_RAW)
    return path


def build_demo_pcaps(outdir: str) -> dict:
    """Demo fixtures laid out on a coherent kill-chain clock:
    scan(+0) -> content(+1) -> dns/arp/dhcp(+2..4) -> exfil(+5) -> rst(+6)
    ; kernel sim events sit at +100."""
    os.makedirs(outdir, exist_ok=True)
    paths = {
        "baseline": build_baseline(os.path.join(outdir, "baseline.pcap")),
        "scan": build_scan(os.path.join(outdir, "demo_scan.pcap"), off=0.0),
        "dns_mismatch": build_dns_mismatch(os.path.join(outdir, "demo_dns.pcap"), off=2.0),
        "arp_spoof": build_arp_spoof(os.path.join(outdir, "demo_arp.pcap"), reply_count=3, off=3.0),
        "dhcp_starvation": build_dhcp_starvation(os.path.join(outdir, "demo_dhcp.pcap"), off=4.0),
        "exfil": build_exfil(os.path.join(outdir, "demo_exfil.pcap"), off=5.0),
        "rst_flood": build_rst_flood(os.path.join(outdir, "demo_rst.pcap"), off=6.0),
    }
    return paths


_ALL: List[Tuple[str, object]] = [
    ("baseline", build_baseline),
    ("scan", build_scan),
    ("exfil", build_exfil),
    ("attack", build_attack),
    ("arp_spoof_a", lambda p: build_arp_spoof(p, 3)),
    ("arp_spoof_b", build_arp_clean),
    ("dns_mismatch", build_dns_mismatch),
    ("dns_clean", build_dns_clean),
    ("dhcp_starvation", build_dhcp_starvation),
    ("dhcp_clean", build_dhcp_clean),
    ("rst_flood", build_rst_flood),
    ("rst_clean", build_rst_clean),
    ("smb_probe", build_smb_probe),
]


def build_all(outdir: str) -> dict:
    os.makedirs(outdir, exist_ok=True)
    paths: dict = {}
    for name, builder in _ALL:
        paths[name] = builder(os.path.join(outdir, f"{name}.pcap"))
    return paths