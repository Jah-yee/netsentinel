"""SIEM-lite correlation: stitch alerts into incidents with kill-chain stages.

Alerts sharing an actor (src IP) within a correlation window are grouped into
an Incident. The estimated kill-chain stage is the highest stage reached by any
constituent alert; ``stage_path`` records the ordered progression over time.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from .model import Alert, Incident

KILL_CHAIN = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]

# module|category -> stage index
STAGE_OF = {
    "rules": {"scan": 0, "signature": 0, "content": 1, "probe": 1},
    "mldetect": {"anomaly": 3, "burst": 3, "exfil": 3},
    "canary": {"arp": 2, "dhcp": 2, "dns": 2, "tcp": 6},
    "kernel": {"proc": 4, "socket": 5, "trace": 4},
}
_DEFAULT_STAGE = 3


def stage_index(alert: Alert) -> int:
    idx = _DEFAULT_STAGE
    sub = STAGE_OF.get(alert.module, {})
    for key, val in sub.items():
        if key in alert.category:
            idx = min(idx, val)
            if key == alert.category[:len(key)]:
                idx = val
                break
    if alert.category in ("tcp.rst_flood", "tcp.syn_flood", "arp.spoof", "dhcp.starvation"):
        # RST/SYN floods and pool-exhaustion map to impact/denial; ARP/DHCP to delivery
        idx = 6 if "tcp" in alert.category else 2
    return idx


def estimate_stage(alerts: Sequence[Alert]) -> str:
    if not alerts:
        return ""
    idx = max(stage_index(a) for a in alerts)
    return KILL_CHAIN[idx]


def stage_path_of(alerts: Sequence[Alert]) -> List[str]:
    """Ordered unique stage names as the timeline progressed."""
    ordered = [(a, stage_index(a)) for a in sorted(alerts, key=lambda x: (x.ts, x.category))]
    path: List[str] = []
    for _, idx in ordered:
        stage = KILL_CHAIN[idx]
        if not path or path[-1] != stage:
            path.append(stage)
    return path


def correlate(alerts: Sequence[Alert], window_s: float = 120.0) -> List[Incident]:
    """Group alerts into incidents keyed by src IP, sliding by the window."""
    incidents: List[Incident] = []
    by_src: Dict[str, List[Alert]] = {}
    for a in alerts:
        src = a.src or "n/a"
        by_src.setdefault(src, []).append(a)

    for src, group in by_src.items():
        group.sort(key=lambda a: a.ts)
        for alert in group:
            placed = False
            for inc in incidents:
                if inc.src != src:
                    continue
                if alert.ts <= inc.last_ts + window_s:
                    inc.add(alert)
                    placed = True
                    break
            if not placed:
                incidents.append(Incident(src=src, started=max(alert.ts, alert.ts), alerts=[alert]))

    for inc in incidents:
        inc.stage_path = stage_path_of(inc.alerts)
        inc.stage = estimate_stage(inc.alerts)
    incidents.sort(key=lambda i: i.started)
    return incidents


def incident_timeline(inc: Incident) -> List[Dict[str, Any]]:
    """Chronological per-alert timeline for an incident."""
    return [
        {"ts": a.ts, "module": a.module, "category": a.category, "severity": a.severity,
         "subject": a.subject, "stage": KILL_CHAIN[stage_index(a)]}
        for a in sorted(inc.alerts, key=lambda x: x.ts)
    ]