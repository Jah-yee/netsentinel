"""Signature rules engine (Suricata-style subset).

Supported syntax (subset of Suricata rules):

    alert <proto> <src> <sport> -> <dst> <dport> (<options>)

Options implemented:
  msg:"text"
  sid:<id>, rev:<n>, severity:<1|2|3>, classtype:<name>
  reference:<type,value>   (repeatable)
  flags:S                  (exact TCP flags; repeatable letters S,A,F,R,P,U)
  threshold:<n>            (grouped per src->dst; alert once when count >= n)
  content:"..."            (repeatable; ASCII or |hex| tokens; all must match)
  within:<n>               (content match must begin within first n bytes)

IPv4/IPv6 CIDR supported in the header; 'any' is the wildcard.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .model import Alert

FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}

_SID_RE = re.compile(r"\*\s|next|last")


class RuleParseError(ValueError):
    pass


def content_to_bytes(expr: str) -> bytes:
    """Decode `content:"|ff d8 ff e0|GET"` style expressions to bytes."""
    out = bytearray()
    while expr:
        if expr.startswith("|"):
            end = expr.find("|", 1)
            if end == -1:
                raise RuleParseError(f"unterminated hex block in content {expr!r}")
            hexpart = expr[1:end].replace(" ", "").replace("\n", "")
            if len(hexpart) % 2:
                raise RuleParseError(f"odd-length hex block in content {expr!r}")
            try:
                out += bytes.fromhex(hexpart)
            except ValueError as exc:
                raise RuleParseError(f"invalid hex in content {expr!r}: {exc}")
            expr = expr[end + 1:]
        else:
            m = re.match(r"[^|]+", expr)
            assert m
            out += m.group(0).encode("latin-1")
            expr = expr[m.end():]
    return bytes(out)


def _split_options(opts: str) -> List[str]:
    """Split option list on ';' but not inside double-quoted strings."""
    parts: List[str] = []
    cur: List[str] = []
    in_q = False
    i = 0
    while i < len(opts):
        ch = opts[i]
        if ch == '"':
            in_q = not in_q
            cur.append(ch)
        elif ch == ";" and not in_q:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    if cur:
        parts.append("".join(cur).strip())
    return parts


def _cidr_match(host: str, pattern: str) -> bool:
    if pattern in ("any", ""):
        return True
    if "/" in pattern:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
    return host == pattern


@dataclass
class Rule:
    action: str
    proto: str
    src: str
    sport: str
    dst: str
    dport: str
    msg: str = ""
    sid: int = 0
    rev: int = 1
    severity: int = 2
    classtype: str = "misc"
    references: List[str] = field(default_factory=list)
    flags: str = ""
    contents: List[bytes] = field(default_factory=list)
    within: List[int] = field(default_factory=list)
    threshold: Optional[int] = None

    @classmethod
    def parse(cls, line: str, default_severity: int = 2) -> "Rule":
        line = line.strip()
        if not line or line.startswith("#"):
            raise RuleParseError("not a rule")
        if "(" not in line or not line.rstrip().endswith(")"):
            raise RuleParseError("missing '( ... )' option block")
        head, _, optpart = line.partition("(")
        optpart = optpart[:-1].strip()  # drop the trailing ')'
        parts = head.split()
        if len(parts) < 6:
            raise RuleParseError("rule header must be: action proto src sport -> dst dport")
        r = cls(
            action=parts[0],
            proto=parts[1],
            src=parts[2],
            sport=parts[3],
            dst=parts[5],
            dport=parts[6],
            severity=default_severity,
        )
        if parts[4] != "->":
            raise RuleParseError("only '->' direction is supported")
        for opt in _split_options(optpart):
            if not opt:
                continue
            key, _, val = opt.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key == "msg":
                r.msg = val.strip('"')
            elif key == "sid":
                r.sid = int(val)
            elif key == "rev":
                r.rev = int(val)
            elif key == "severity":
                r.severity = int(val)
            elif key == "classtype":
                r.classtype = val.strip(";").strip()
            elif key == "reference":
                r.references.append(val.strip('"'))
            elif key == "flags":
                r.flags = val.upper()
            elif key == "content":
                r.contents.append(content_to_bytes(val.strip('"')))
            elif key == "within":
                r.within.append(int(val))
            elif key == "threshold":
                r.threshold = int(val)
            elif key in ("flow", "offset", "depth", "nocase", "fast_pattern"):
                pass  # accepted but not enforced in this subset
            else:
                raise RuleParseError(f"unsupported option {key!r}")
        if not r.msg:
            r.msg = f"signature sid {r.sid}"
        if not r.sid:
            raise RuleParseError("rule must define sid:")
        return r

    def matches(self, pkt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return evidence dict if the packet matches, else None."""
        ip = pkt.get("ip")
        if not ip:
            return None
        if self.proto != "any" and ip.get("proto") is None:
            return None
        if self.proto not in ("any", "ip", "tcp", "udp", "icmp"):
            return None
        l4 = pkt.get("tcp") or pkt.get("udp") or None
        if self.proto == "tcp" and not pkt.get("tcp"):
            return None
        if self.proto == "udp" and not pkt.get("udp"):
            return None
        if self.proto == "icmp" and not pkt.get("icmp"):
            return None

        if not _cidr_match(ip.get("src", ""), self.src):
            return None
        if not _cidr_match(ip.get("dst", ""), self.dst):
            return None
        if l4:
            if not self._port_match(self.sport, l4.get("src_port")):
                return None
            if not self._port_match(self.dport, l4.get("dst_port")):
                return None
        elif self.sport != "any" or self.dport != "any":
            return None

        if self.flags:
            tcp = pkt.get("tcp")
            if not tcp:
                return None
            want = 0
            for c in self.flags:
                if c in FLAG_BITS:
                    want |= FLAG_BITS[c]
            if tcp.get("flags_raw", 0) != want:
                return None

        matched: List[str] = []
        for i, needle in enumerate(self.contents):
            payload = pkt.get("payload", b"") or b""
            pos = payload.find(needle)
            if pos == -1:
                return None
            limit = self.within[i] if i < len(self.within) else -1
            if limit > 0 and pos + len(needle) > limit:
                return None
            matched.append(f"content[{payload[pos:pos + len(needle)].hex()}]@{pos + 1}")

        evidence: Dict[str, Any] = {
            "matched_contents": matched,
            "ip": f"{ip.get('src')}:{l4.get('src_port', '-') if l4 else '-'} -> "
                  f"{ip.get('dst')}:{l4.get('dport', '-') if l4 else '-'}",
            "packet_ts": pkt.get("ts"),
        }
        if pkt.get("dns"):
            evidence["dns"] = {"id": pkt["dns"].get("id"), "qname": first_name(pkt["dns"].get("questions"))}
        return evidence

    @staticmethod
    def _port_match(pattern: str, port: Optional[int]) -> bool:
        if pattern in ("any", ""):
            return True
        if pattern.isdigit():
            return port == int(pattern)
        if ":" in pattern or "-" in pattern:
            parts = re.split(r"[:-]", pattern)
            try:
                return int(parts[0]) <= port <= int(parts[1])
            except (ValueError, IndexError):
                pass
        return False


def first_name(questions: Any) -> str:
    if not questions:
        return ""
    return str(questions[0].get("qname", ""))


class RulesEngine:
    def __init__(self, rules: List[Rule], default_severity: int = 2) -> None:
        self.rules = rules
        self.default_severity = default_severity

    @classmethod
    def load_rules(cls, path: str, default_severity: int = 2) -> "RulesEngine":
        rules: List[Rule] = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    rules.append(Rule.parse(line, default_severity))
                except RuleParseError as exc:
                    raise RuleParseError(f"{path}: {exc} (rule: {line})")
        return cls(rules, default_severity)

    def scan(self, packets: List[Dict[str, Any]]) -> List[Alert]:
        """Match every packet against every rule; honour threshold grouping."""
        alerts: List[Alert] = []
        counts: Dict[Any, int] = {}

        for rule in self.rules:
            for pkt in packets:
                ev = rule.matches(pkt)
                if ev is None:
                    continue
                if rule.threshold is not None:
                    ip = pkt.get("ip", {})
                    group = (rule.sid, ip.get("src"), ip.get("dst"))
                    counts[group] = counts.get(group, 0) + 1
                    if counts[group] != rule.threshold:
                        # threshold semantics: fire exactly once per (sid,src,dst)
                        # when the match count reaches the configured threshold
                        continue
                alerts.append(Alert(
                    ts=pkt.get("ts", 0.0),
                    module="rules",
                    category="rules.content.match" if rule.contents else "rules.signature.scan",
                    severity=rule.severity,
                    subject=rule.msg,
                    src=pkt.get("ip", {}).get("src", ""),
                    dst=pkt.get("ip", {}).get("dst", ""),
                    action="log-only",
                    evidence={**ev, "sid": rule.sid, "classtype": rule.classtype,
                              "reference": rule.references, "threshold": rule.threshold},
                    dedupe_key=f"rules|{rule.sid}|{pkt.get('ip', {}).get('src', '')}|{pkt.get('ip', {}).get('dst', '')}",
                ))
        return alerts


def load_rule_file(path: str) -> List[Rule]:
    rules: List[Rule] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                rules.append(Rule.parse(line))
    return rules