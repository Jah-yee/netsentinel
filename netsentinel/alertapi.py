"""Alert API: JSON export stream, deduplication, on-disk mailbox, reporting."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence

from .model import Alert, Incident, Mailbox
from .report import write_json, write_markdown


def export_json(alerts: Sequence[Alert]) -> str:
    """JSON stream export of alerts (subject, action + full evidence)."""
    payload = {
        "count": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def export_jsonl(alerts: Sequence[Alert]) -> str:
    return "\n".join(a.to_json() for a in alerts) + ("\n" if alerts else "")


class Notifier:
    """Persists alerts to a mailbox with TTL-based dedup and emits JSON.

    Reads and writes are strictly local (no network paths are ever touched).
    """

    def __init__(self, mailbox: Mailbox) -> None:
        self.mailbox = mailbox
        self.accepted: List[Alert] = []
        self.suppressed: List[Alert] = []

    def emit(self, alert: Alert, now: Optional[float] = None) -> bool:
        ok = self.mailbox.emit(alert, now=now)
        (self.accepted if ok else self.suppressed).append(alert)
        return ok

    def summarize(self) -> Dict[str, Any]:
        return {
            "accepted": len(self.accepted),
            "suppressed_duplicates": len(self.suppressed),
            "categories": sorted({a.category for a in self.accepted}),
        }


def write_reports(outdir: str, title: str, json_payloads: Dict[str, Any],
                  markdown_doc: List[Dict[str, Any]], meta: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Write JSON + Markdown report files; return written paths."""
    import os
    os.makedirs(outdir, exist_ok=True)
    json_paths = {}
    for name, payload in json_payloads.items():
        json_paths[name] = write_json(os.path.join(outdir, f"{name}.json"), payload)
    md_path = write_markdown(os.path.join(outdir, "report.md"), title, markdown_doc, meta)
    return {**json_paths, "markdown": md_path}