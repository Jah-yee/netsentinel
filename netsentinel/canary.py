"""MITM / transport-signature detectors.

* ARP spoofing: two+ replies claiming the same protocol address with different
  hardware addresses.
* DHCP starvation: a single client flooding DISCOVER messages.
* DNS anomalies: responses with an unknown transaction ID (ID mismatch /
  unsolicited) and responses for a pending ID from a source other than the
  queried server (cache-poisoning signature).
* TCP signature: RST floods / SYN floods from a single actor.

All logic is pure: it takes decoded packets and returns Alert objects with
evidence. Never sends packets.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Sequence

from .model import Alert
from .pcap import DHCP_PORTS, DNS_PORTS, extract


def _mk(ts: float, category: str, severity: int, subject: str,
        src: str, dst: str, evidence: Dict[str, Any]) -> Alert:
    return Alert(
        ts=ts, module="canary", category=category, severity=severity,
        subject=subject, src=src, dst=dst, action="log-only",
        evidence=evidence,
        dedupe_key=f"canary|{category}|{src}|{evidence.get('marker', '')}",
    )


def detect_arp_spoof(packets: Sequence[Dict[str, Any]],
                     min_duplicate_answers: int = 2) -> List[Alert]:
    """Detect ARP answer duplication for a claimed IP (spoof indication)."""
    claims: Dict[str, Dict[str, Any]] = {}
    alerts: List[Alert] = []
    for pkt in packets:
        arp = pkt.get("arp")
        if not arp or arp.get("op") != 2:
            continue
        spa = arp.get("spa", "")
        mac = arp.get("sha_mac", "")
        tpa = arp.get("tpa", "")
        state = claims.setdefault(spa, {"macs": [], "tpa": tpa, "first_ts": pkt.get("ts", 0.0)})
        if mac not in state["macs"]:
            state["macs"].append(mac)
        if len(state["macs"]) >= 2:
            alerts.append(_mk(
                pkt.get("ts", 0.0), "arp.spoof", 1,
                "ARP answer duplication: claimed IP has multiple MAC owners",
                src=spa, dst=tpa,
                evidence={"claimed_ip": spa, "macs": list(state["macs"]),
                          "answers": len(state["macs"]), "marker": mac}))
            # keep only the most recent unique mac so a second distinct answer
            # fires again (each additional unique MAC = one alert)
            state["macs"] = [state["macs"][-1]]
    return alerts if len(alerts) >= (min_duplicate_answers - 1) else alerts


def detect_dhcp_starvation(packets: Sequence[Dict[str, Any]],
                           discover_threshold: int = 20, window_s: float = 30.0) -> List[Alert]:
    """DHCP DISCOVER flood per client MAC (starvation of the address pool)."""
    per_mac: Dict[str, List[float]] = defaultdict(list)
    requested: Dict[str, str] = {}
    for pkt in packets:
        dhcp = pkt.get("dhcp")
        if not dhcp or dhcp.get("message_type") != 1:
            continue
        mac = dhcp.get("mac", "")
        per_mac[mac].append(pkt.get("ts", 0.0))
        if dhcp.get("requested_ip"):
            requested[mac] = dhcp.get("requested_ip", "")
    alerts: List[Alert] = []
    for mac, times in per_mac.items():
        if len(times) < discover_threshold:
            continue
        if len(times) >= 2 and (max(times) - min(times)) <= window_s:
            actor = requested.get(mac, mac)
            alerts.append(_mk(
                min(times), "dhcp.starvation", 1,
                "DHCP DISCOVER flood (address-pool starvation)",
                src=actor, dst="198.51.100.67",
                evidence={"client_mac": mac, "discovers": len(times),
                          "window_s": round(max(times) - min(times), 3),
                          "marker": mac}))
    return alerts


def detect_dns_anomalies(packets: Sequence[Dict[str, Any]],
                         do_id_mismatch: bool = True,
                         do_source_mismatch: bool = True,
                         dns_ports: Optional[Sequence[int]] = None) -> List[Alert]:
    """DNS transaction-ID mismatches and spoofed-answer-source signatures."""
    ports = tuple(dns_ports or DNS_PORTS)
    pending: Dict[int, Dict[str, Any]] = {}
    answered: Dict[int, int] = {}
    alerts: List[Alert] = []
    for pkt in packets:
        dns = pkt.get("dns")
        if not dns:
            continue
        ip = pkt.get("ip", {})
        l4 = pkt.get("udp") or pkt.get("tcp") or {}
        qname = ""
        if dns.get("questions"):
            qname = str(dns["questions"][0].get("qname", ""))
        qid = int(dns.get("id", 0))
        is_query = dns.get("qr") == 0
        server = ip.get("dst", "")
        if is_query:
            pending.setdefault(qid, {"server": server, "qname": qname, "ts": pkt.get("ts", 0.0),
                                     "answers": 0})
            continue
        if not do_id_mismatch and not do_source_mismatch:
            continue
        rec = pending.get(qid)
        if do_id_mismatch and rec is None:
            alerts.append(_mk(
                pkt.get("ts", 0.0), "dns.id_mismatch", 1,
                "DNS response with unknown transaction ID (unsolicited/spoofed)",
                src=ip.get("src", ""), dst=ip.get("dst", ""),
                evidence={"id": qid, "qname": qname, "rdata": _rdata(dns),
                          "source": ip.get("src", ""), "marker": qid}))
            continue
        if rec is not None:
            rec["answers"] += 1
            if do_source_mismatch and ip.get("src", "") != rec.get("server"):
                alerts.append(_mk(
                    pkt.get("ts", 0.0), "dns.source_mismatch", 1,
                    "DNS answer for a pending query came from an unexpected source",
                    src=ip.get("src", ""), dst=ip.get("dst", ""),
                    evidence={"id": qid, "qname": qname, "expected_server": rec.get("server"),
                              "actual_source": ip.get("src", ""), "rdata": _rdata(dns),
                              "marker": f"{qid}"}))
    return alerts


def _rdata(dns: Dict[str, Any]) -> list:
    out = []
    for a in dns.get("answers", []):
        out.append(str(a.get("rdata", "")))
    return out


def detect_tcp_signatures(packets: Sequence[Dict[str, Any]], rst_threshold: int = 50,
                          syn_threshold: int = 100, window_s: float = 10.0,
                          ts_now: Optional[float] = None) -> List[Alert]:
    """TCP RST / SYN floods (per src actor; the span must fit the window)."""
    rst: Dict[str, List[float]] = defaultdict(list)
    syn: Dict[str, List[float]] = defaultdict(list)
    for pkt in packets:
        ip = pkt.get("ip", {})
        tcp = pkt.get("tcp")
        if not tcp:
            continue
        src = ip.get("src", "")
        ts = pkt.get("ts", 0.0)
        if tcp["flags"].get("RST"):
            rst[src].append(ts)
        elif tcp["flags"].get("SYN") and not tcp["flags"].get("ACK"):
            syn[src].append(ts)
    alerts: List[Alert] = []
    for src, times in rst.items():
        span = (max(times) - min(times)) if len(times) > 1 else 0.0
        if len(times) >= rst_threshold and span <= window_s:
            alerts.append(_mk(
                min(times), "tcp.rst_flood", 1,
                "TCP RST flood from a single actor (connection-kill signature)",
                src=src, dst="n/a",
                evidence={"rst_count": len(times), "span_s": round(span, 3),
                          "window_s": window_s, "marker": src}))
    for src, times in syn.items():
        span = (max(times) - min(times)) if len(times) > 1 else 0.0
        if len(times) >= syn_threshold and span <= window_s:
            alerts.append(_mk(
                min(times), "tcp.syn_flood", 1,
                "TCP SYN flood from a single actor",
                src=src, dst="n/a",
                evidence={"syn_count": len(times), "span_s": round(span, 3),
                          "window_s": window_s, "marker": src}))
    return alerts


class CanaryEngine:
    """Run all MITM/signature detectors over a capture."""

    def scan_packets(self, packets: Sequence[Dict[str, Any]], config: Optional[Dict[str, Any]] = None) -> List[Alert]:
        cfg = (config or {}).get("canary", {})
        alerts: List[Alert] = []
        arp_cfg = cfg.get("arp", {}).get("min_duplicate_answers", 2)
        dhcp_cfg = cfg.get("dhcp", {})
        dns_cfg = cfg.get("dns", {})
        tcp_cfg = cfg.get("tcp", {})
        alerts += detect_arp_spoof(packets, arp_cfg)
        alerts += detect_dhcp_starvation(
            packets,
            discover_threshold=dhcp_cfg.get("discover_threshold", 20),
            window_s=dhcp_cfg.get("window_s", 30.0))
        alerts += detect_dns_anomalies(
            packets,
            do_id_mismatch=dns_cfg.get("id_mismatch", True),
            do_source_mismatch=dns_cfg.get("source_mismatch", True),
            dns_ports=cfg.get("dns_ports"))
        alerts += detect_tcp_signatures(
            packets,
            rst_threshold=tcp_cfg.get("rst_threshold", 50),
            syn_threshold=tcp_cfg.get("syn_threshold", 100),
            window_s=tcp_cfg.get("window_s", 10.0))
        return alerts

    def scan_capture(self, capture: "PcapFile", config: Optional[Dict[str, Any]] = None) -> List[Alert]:
        return self.scan_packets(extract(capture), config)