"""Shared data model: Alert, Incident, Mailbox, Notifier.

The alert object is the single currency of the suite: every module
(rules/mldetect/canary/kernel/correlate) produces ``Alert``s, the alert API
persists them to an on-disk mailbox (JSONL) and exports JSON, and the
correlation engine stitches them into ``Incident``s.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class Alert:
    """One detection event with evidence."""

    ts: float                      # epoch seconds
    module: str                    # rules|mldetect|canary|kernel|correlate|alert
    category: str                  # e.g. scan.threshold, content.match, arp.spoof
    severity: int                  # 1 (high) .. 3 (informational)
    subject: str                   # short human summary
    src: str = "n/a"
    dst: str = "n/a"
    action: str = "log-only"       # recommended handling (never mutating)
    evidence: Dict[str, Any] = field(default_factory=dict)
    dedupe_key: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def key(self) -> str:
        """Stable deduplication identity (module+category+src(+detail))."""
        return self.dedupe_key or f"{self.module}|{self.category}|{self.src}|{self.dst}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Alert":
        d = dict(d)
        return cls(**d)


@dataclass
class Incident:
    """Correlated group of alerts sharing an actor within a window."""

    src: str
    started: float
    alerts: List[Alert] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    stage: str = ""
    stage_path: List[str] = field(default_factory=list)

    def add(self, a: Alert) -> None:
        self.alerts.append(a)

    @property
    def severity(self) -> int:
        # lower integer = more severe (1 = high, 3 = informational)
        return min((a.severity for a in self.alerts), default=3)

    @property
    def last_ts(self) -> float:
        return max((a.ts for a in self.alerts), default=self.started)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "src": self.src,
            "started": self.started,
            "last_ts": self.last_ts,
            "severity": self.severity,
            "stage": self.stage,
            "stage_path": self.stage_path,
            "alert_count": len(self.alerts),
            "alerts": [a.to_dict() for a in sorted(self.alerts, key=lambda a: a.ts)],
        }


class Mailbox:
    """On-disk JSONL mailbox with time-windowed deduplication.

    Never talks to a network: only appends lines to a local file.
    """

    def __init__(self, path: str, dedupe_ttl_s: float = 300.0) -> None:
        self.path = path
        self.dedupe_ttl_s = dedupe_ttl_s
        self._seen: Dict[str, float] = {}

    def emit(self, alert: Alert, now: Optional[float] = None) -> bool:
        """Persist the alert unless it is a duplicate within the TTL.

        Returns True when the alert is newly accepted, False when suppressed.
        """
        now = float(now if now is not None else time.time())
        key = alert.key()
        last = self._seen.get(key)
        if last is not None and (now - last) < self.dedupe_ttl_s:
            return False
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(alert.to_json() + "\n")
        self._seen[key] = now
        return True

    def load(self) -> List[Alert]:
        out: List[Alert] = []
        if not os.path.exists(self.path):
            return out
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(Alert.from_dict(json.loads(line)))
                except (ValueError, TypeError):
                    continue
        return out

    def clear(self) -> None:
        if os.path.exists(self.path):
            os.remove(self.path)
        self._seen.clear()