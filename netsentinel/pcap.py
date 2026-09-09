"""Minimal, dependency-free pcap reader/writer and packet decoders.

Supported linktypes: ``101`` (RAW IPv4/IPv6) and ``1`` (Ethernet), plus NULL(0)
for completeness. Decoders: IPv4/IPv6, TCP, UDP, ICMP, DNS, ARP, DHCP.
Readers are tolerant: truncated/malformed records are skipped, not fatal.

References: tcpdump/libpcap file format, RFC 791/793/768/792/1035/2131/826.
"""
from __future__ import annotations

import math
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 101

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_IPV6 = 41

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD
ETH_VLAN = (0x8100, 0x88A8, 0x9100)

DNS_PORTS = (53, 5353)
DHCP_PORTS = (67, 68)


class PcapParseError(Exception):
    pass


def _checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    acc = 0
    for i in range(0, len(data), 2):
        acc += (data[i] << 8) | data[i + 1]
        acc = (acc & 0xFFFF) + (acc >> 16)
    return (acc & 0xFFFF) ^ 0xFFFF


def ip_checksum(header: bytes) -> int:
    return _checksum16(header)


def _htons(n: int) -> bytes:
    return struct.pack("!H", n & 0xFFFF)


@dataclass
class Packet:
    idx: int
    ts: float
    caplen: int
    wirelen: int
    data: bytes


@dataclass
class PcapFile:
    linktype: int
    snaplen: int = 65535
    packets: List[Packet] = field(default_factory=list)

    def __iter__(self) -> Iterator[Packet]:
        return iter(self.packets)

    def __len__(self) -> int:
        return len(self.packets)


def read_pcap(path: str) -> PcapFile:
    """Read a pcap file (all standard magics: micro/nano, LE/BE endian)."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if len(raw) < 24:
        raise PcapParseError("file too small to be a pcap")

    magic = raw[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, ts_div = "<", 1_000_000.0
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, ts_div = ">", 1_000_000.0
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, ts_div = "<", 1_000_000_000.0
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, ts_div = ">", 1_000_000_000.0
    else:
        raise PcapParseError(f"unrecognised pcap magic {magic!r}")

    ver_maj, ver_min, _tz, _sig, snaplen, linktype = struct.unpack(endian + "HHiiii", raw[4:24])
    if (ver_maj, ver_min) != (2, 4):
        raise PcapParseError(f"unsupported pcap version {ver_maj}.{ver_min} (expected 2.4)")

    pcap = PcapFile(linktype=linktype, snaplen=snaplen)
    off = 24
    idx = 0
    while off + 16 <= len(raw):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", raw[off:off + 16])
        off += 16
        if off + incl_len > len(raw):
            break  # truncated trailing record: tolerate
        data = raw[off:off + incl_len]
        off += incl_len
        ts = ts_sec + (ts_frac / ts_div if ts_div else ts_frac)
        pcap.packets.append(Packet(idx=idx, ts=ts, caplen=incl_len, wirelen=orig_len, data=data))
        idx += 1
    return pcap


def write_pcap(path: str, packets: List[Tuple[float, bytes]], linktype: int = DLT_RAW, snaplen: int = 65535) -> str:
    """Write a little-endian, microsecond pcap (linktype 101 or 1)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        for ts, data in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)
    return path


def _ip_to_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _parse_labels(data: bytes, start: int) -> Tuple[List[str], int]:
    """Parse DNS name (labels + optional compression pointers) from ``start``."""
    labels: List[str] = []
    i = start
    max_jumps = 32
    jumped = False
    first_end = start
    while i < len(data):
        ln = data[i]
        if ln == 0x00:
            if not jumped:
                first_end = i + 1
            break
        if ln & 0xC0 == 0xC0:
            if not jumped:
                first_end = i + 2
            i = (data[i] & 0x3F) << 8 | data[i + 1]
            jumped = True
            max_jumps -= 1
            if max_jumps <= 0:
                break
            continue
        if ln & 0xC0 or i + 1 + ln > len(data):
            break
        labels.append(data[i + 1:i + 1 + ln].decode("latin-1"))
        i += 1 + ln
        if jumped:
            max_jumps -= 1
            if max_jumps <= 0:
                break
    if not jumped:
        first_end = min(first_end, len(data))
    return labels, first_end


def parse_dns(payload: bytes) -> Optional[Dict[str, Any]]:
    """Best-effort DNS header + question/answer extraction."""
    if len(payload) < 12:
        return None
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
    out: Dict[str, Any] = {
        "id": ident,
        "qr": 1 if flags & 0x8000 else 0,
        "opcode": (flags >> 11) & 0x0F,
        "aa": bool(flags & 0x0400),
        "tc": bool(flags & 0x0200),
        "rd": bool(flags & 0x0100),
        "rcode": flags & 0x000F,
        "questions": [],
        "answers": [],
    }
    i = 12
    for _ in range(qd):
        if i >= len(payload):
            break
        name, i = _parse_labels(payload, i)
        if i + 4 > len(payload):
            break
        qtype, qclass = struct.unpack_from("!HH", payload, i)
        i += 4
        out["questions"].append({"qname": ".".join(name), "qtype": qtype, "qclass": qclass})
    for _ in range(an):
        if i >= len(payload):
            break
        name, i = _parse_labels(payload, i)
        if i + 10 > len(payload):
            break
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", payload, i)
        i += 10
        rdata = payload[i:i + rdlen]
        i += rdlen
        rr: Dict[str, Any] = {"name": ".".join(name), "type": rtype, "class": rclass, "ttl": ttl, "rdata": rdata}
        if rtype == 1 and len(rdata) == 4:
            rr["rdata"] = _ip_to_str(rdata)
        elif rtype == 28 and len(rdata) == 16:
            rr["rdata"] = ":".join(f"{b:02x}" for b in rdata)
        out["answers"].append(rr)
    return out


def parse_arp(payload: bytes) -> Optional[Dict[str, Any]]:
    if len(payload) < 8:
        return None
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", payload[:8])
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return None
    need = 8 + 2 * (hlen + plen)
    if len(payload) < need:
        return None
    sha = payload[8:8 + hlen]
    spa = payload[8 + hlen:8 + hlen + plen]
    tha = payload[8 + hlen + plen:8 + hlen + plen + hlen]
    tpa = payload[8 + hlen + plen + hlen:8 + hlen + plen + hlen + plen]
    return {
        "op": op,
        "sha_mac": ":".join(f"{b:02x}" for b in sha),
        "spa": _ip_to_str(spa),
        "tha_mac": ":".join(f"{b:02x}" for b in tha),
        "tpa": _ip_to_str(tpa),
    }


def parse_dhcp(payload: bytes) -> Optional[Dict[str, Any]]:
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    op = payload[0]
    hlen = payload[2]
    xid = struct.unpack("!I", payload[4:8])[0]
    mac = payload[28:28 + min(hlen, 16)]
    opts: Dict[int, bytes] = {}
    i = 240
    while i < len(payload):
        opt = payload[i]
        if opt == 0:  # pad
            i += 1
            continue
        if opt == 255:  # end
            break
        if i + 1 >= len(payload):
            break
        olen = payload[i + 1]
        if i + 2 + olen > len(payload):
            break
        opts[opt] = payload[i + 2:i + 2 + olen]
        i += 2 + olen
    msg_type = opts.get(53, b"\x00")[0] if opts.get(53) else 0
    requested = opts.get(50)
    req_ip = _ip_to_str(requested) if requested else ""
    return {
        "op": op,
        "xid": xid,
        "mac": ":".join(f"{b:02x}" for b in mac),
        "message_type": msg_type,
        "requested_ip": req_ip,
    }


def parse_ipv4(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 20 or (data[0] >> 4) != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if len(data) < ihl:
        return None
    total_len = struct.unpack("!H", data[2:4])[0] or len(data)
    ident = struct.unpack("!H", data[4:6])[0]
    flags = (data[6] >> 5) & 0x07
    frag_off = ((data[6] & 0x1F) << 8) | data[7]
    ttl = data[8]
    proto = data[9]
    src = data[12:16]
    dst = data[16:20]
    payload = data[ihl:min(total_len, len(data))]
    return {
        "version": 4,
        "ihl": ihl,
        "proto": proto,
        "src": _ip_to_str(src),
        "dst": _ip_to_str(dst),
        "id": ident,
        "flags": flags,
        "frag_offset": frag_off,
        "ttl": ttl,
        "payload": payload,
    }


def parse_ipv6(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 40 or (data[0] >> 4) != 6:
        return None
    plen = struct.unpack("!H", data[4:6])[0]
    proto = data[6]
    src = data[8:24]
    dst = data[24:40]
    payload = data[40:40 + min(plen, len(data) - 40)]
    return {
        "version": 6,
        "proto": proto,
        "src": ":".join(f"{b:02x}" for b in src),
        "dst": ":".join(f"{b:02x}" for b in dst),
        "payload": payload,
    }


def parse_tcp(payload: bytes) -> Optional[Dict[str, Any]]:
    if len(payload) < 20:
        return None
    sport, dport = struct.unpack("!HH", payload[0:4])
    seq, ack = struct.unpack("!II", payload[4:12])
    doff = (payload[12] >> 4) * 4
    raw_flags = payload[13]
    flags = {
        "FIN": bool(raw_flags & 0x01),
        "SYN": bool(raw_flags & 0x02),
        "RST": bool(raw_flags & 0x04),
        "PSH": bool(raw_flags & 0x08),
        "ACK": bool(raw_flags & 0x10),
        "URG": bool(raw_flags & 0x20),
        "ECE": bool(raw_flags & 0x40),
        "CWR": bool(raw_flags & 0x80),
    }
    window = struct.unpack("!H", payload[14:16])[0]
    body = payload[doff:] if doff <= len(payload) else b""
    return {
        "src_port": sport,
        "dst_port": dport,
        "seq": seq,
        "ack": ack,
        "flags": flags,
        "flags_raw": raw_flags,
        "window": window,
        "payload": body,
    }


def parse_udp(payload: bytes) -> Optional[Dict[str, Any]]:
    if len(payload) < 8:
        return None
    sport, dport, length = struct.unpack("!HHH", payload[0:6])
    # length includes the 8-byte header; guard against short captures
    body = payload[8:min(length, len(payload))]
    return {"src_port": sport, "dst_port": dport, "length": length, "payload": body}


def parse_icmp(payload: bytes) -> Optional[Dict[str, Any]]:
    if len(payload) < 4:
        return None
    return {"type": payload[0], "code": payload[1], "checksum": struct.unpack("!H", payload[2:4])[0]}


def eth_addr(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_ethernet(data: bytes) -> Dict[str, Any]:
    if len(data) < 14:
        return {"etype": None, "payload": b"", "src_mac": "", "dst_mac": ""}
    dst = eth_addr(data[0:6])
    src = eth_addr(data[6:12])
    off = 12
    etype = struct.unpack("!H", data[off:off + 2])[0]
    off += 2
    while etype in ETH_VLAN and off + 4 <= len(data):
        etype = struct.unpack("!H", data[off + 2:off + 4])[0]
        off += 4
    return {"etype": etype, "payload": data[off:], "src_mac": src, "dst_mac": dst}


def decode_packet(pkt: Packet, linktype: int) -> Dict[str, Any]:
    """Decode one packet into a metadata dict (never raises on odd bytes)."""
    info: Dict[str, Any] = {
        "idx": pkt.idx,
        "ts": pkt.ts,
        "caplen": pkt.caplen,
        "wirelen": pkt.wirelen,
        "linktype": linktype,
    }
    data = pkt.data
    if linktype == DLT_EN10MB:
        eth = parse_ethernet(data)
        info["eth"] = eth
        data = eth["payload"]
        info["alert_bytes"] = len(data)
        etype = eth["etype"]
        if etype == ETH_ARP:
            arp = parse_arp(data)
            if arp:
                info["arp"] = arp
            return info
        if etype == ETH_IPV4:
            pass
        elif etype == ETH_IPV6:
            ip = parse_ipv6(data)
            if ip:
                info["ip"] = ip
                data = ip["payload"]
                _fill_transport(info, data)
            return info
        else:
            return info
    elif linktype == DLT_NULL:
        if len(data) >= 4:
            data = data[4:]

    ip = parse_ipv4(data) or parse_ipv6(data)
    if ip is None:
        return info
    info["ip"] = ip
    info["alert_bytes"] = len(ip.get("payload", b"")) + ip.get("ihl", 40)
    data = ip["payload"]
    _fill_transport(info, data)
    return info


def _fill_transport(info: Dict[str, Any], data: bytes) -> None:
    ip = info["ip"]
    proto = ip.get("proto")
    if proto == IP_PROTO_TCP:
        tcp = parse_tcp(data)
        if tcp:
            info["tcp"] = tcp
            info["payload"] = tcp["payload"]
            _fill_app(info, ip, tcp)
    elif proto == IP_PROTO_UDP:
        udp = parse_udp(data)
        if udp:
            info["udp"] = udp
            info["payload"] = udp["payload"]
            _fill_app(info, ip, udp)
    elif proto == IP_PROTO_ICMP:
        icmp = parse_icmp(data)
        if icmp:
            info["icmp"] = icmp
    elif proto == IP_PROTO_IPV6:
        pass


def _fill_app(info: Dict[str, Any], ip: Dict[str, Any], l4: Dict[str, Any]) -> None:
    sport, dport = l4["src_port"], l4["dst_port"]
    if l4 is not None and l4.get("payload") is not None:
        payload = l4["payload"]
        if dport in DNS_PORTS or sport in DNS_PORTS:
            try:
                dns = parse_dns(payload)
                if dns is not None:
                    info["dns"] = dns
            except Exception:
                pass
        if sport in DHCP_PORTS and dport in DHCP_PORTS:
            try:
                dhcp = parse_dhcp(payload)
                if dhcp is not None:
                    info["dhcp"] = dhcp
            except Exception:
                pass


def extract(capture: PcapFile) -> List[Dict[str, Any]]:
    """Decode every packet in a capture into metadata dicts."""
    out: List[Dict[str, Any]] = []
    linktype = capture.linktype
    for pkt in capture.packets:
        try:
            out.append(decode_packet(pkt, linktype))
        except Exception:
            out.append({"idx": pkt.idx, "ts": pkt.ts, "linktype": linktype, "parse_error": True})
    return out


def payload_entropy(data: bytes) -> float:
    """Shannon entropy (bits/byte) of a payload. 0.0 for empty."""
    if not data:
        return 0.0
    freqs = {}
    for b in data:
        freqs[b] = freqs.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freqs.values())


def _flow_key(ip: Dict[str, Any], l4: Optional[Dict[str, Any]]) -> Optional[Tuple[str, Any, ...]]:
    proto = ip.get("proto")
    if l4 is None:
        return (proto, ip.get("src"), "-", ip.get("dst"), "-")
    return (proto, ip.get("src"), l4.get("src_port"), ip.get("dst"), l4.get("dst_port"))


def extract_flows(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Aggregate decoded packets into bidirectional 5-tuple flows with features.

    The initiator (first packet's src) is called ``client``; flows are
    canonicalised so upstream/downstream byte counts are direction-aware.
    """
    order: List[Tuple[str, Any, ...]] = []
    agg: Dict[Tuple[str, Any, ...], Dict[str, Any]] = {}

    def upsert(key: Tuple[str, Any, ...], pkt: Dict[str, Any]) -> Dict[str, Any]:
        if key not in agg:
            agg[key] = {
                "flow_key": key,
                "proto": key[0],
                "client_ip": key[1],
                "client_port": key[2],
                "server_ip": key[3],
                "server_port": key[4],
                "packets": 0,
                "bytes": 0,
                "bytes_client_to_server": 0,
                "bytes_server_to_client": 0,
                "first_ts": pkt["ts"],
                "last_ts": pkt["ts"],
                "payloads": bytearray(),
                "flags_seen": [],
                "dns_queries": [],
                "first_direction": (key[1], key[2]),
            }
            order.append(key)
        return agg[key]

    for pkt in packets:
        ip = pkt.get("ip")
        if not ip:
            continue
        l4 = pkt.get("tcp") or pkt.get("udp")
        key = _flow_key(ip, l4)
        if key is None:
            continue
        f = upsert(key, pkt)
        f["packets"] += 1
        size = pkt.get("alert_bytes", len(pkt.get("payload", b"")))
        f["bytes"] += size
        client_side = (ip.get("src"), l4.get("src_port") if l4 else None) == f["first_direction"]
        payload = pkt.get("payload", b"") or b""
        if payload:
            f["payloads"] += payload[:1024]  # cap per flow at 1 MiB total memory
            if len(f["payloads"]) > 1_000_000:
                f["payloads"] = f["payloads"][-1_000_000:]
        if client_side:
            f["bytes_client_to_server"] += size
        else:
            f["bytes_server_to_client"] += size
        f["last_ts"] = max(f["last_ts"], pkt["ts"])
        if l4 and l4.get("flags"):
            f["flags_seen"] = sorted(set(f["flags_seen"]) | {f for f, on in l4["flags"].items() if on})
        dnsq = pkt.get("dns", {}).get("questions")
        if dnsq:
            f["dns_queries"].extend(q.get("qname", "") for q in dnsq)

    flows: List[Dict[str, Any]] = []
    for key in order:
        f = agg[key]
        payloads = bytes(f["payloads"])
        f["payload_sample"] = payloads[:256].hex()
        f["payload_entropy"] = payload_entropy(payloads)
        f["avg_pkt_len"] = round(f["bytes"] / max(f["packets"], 1), 2)
        dur = f["last_ts"] - f["first_ts"]
        f["duration"] = round(max(dur, 1e-6), 6)
        f["rate_pkts"] = round(f["packets"] / f["duration"], 4)
        f["rate_bytes"] = round(f["bytes"] / f["duration"], 4)
        del f["payloads"]
        flows.append(f)
    flows.sort(key=lambda fl: fl["first_ts"])
    return flows


def flow_features(flow: Dict[str, Any]) -> Dict[str, float]:
    """Numeric feature vector for a flow (used by mldetect)."""
    return {
        "packets": float(flow["packets"]),
        "bytes": float(flow["bytes"]),
        "avg_pkt_len": float(flow["avg_pkt_len"]),
        "payload_entropy": float(flow["payload_entropy"]),
        "rate_pkts": float(flow["rate_pkts"]),
        "rate_bytes": float(flow["rate_bytes"]),
        "duration": float(flow["duration"]),
    }