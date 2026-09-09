"""Report rendering to JSON + Markdown (offline, own outputs only)."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def write_json(path: str, payload: Any) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True, default=str)
    return path


def render_markdown(title: str, sections: List[Dict[str, Any]], meta: Optional[Dict[str, Any]] = None) -> str:
    """Render a nested-dict document. Section keys: heading, text, list, table,
    code. Table is {'heading', 'columns': [...], 'rows': [[...]]}."""
    lines: List[str] = [f"# {title}", ""]
    if meta:
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        for k, v in meta.items():
            lines.append(f"| {k} | {v} |")
        lines.append("")
    for sec in sections:
        heading = sec.get("heading")
        if heading:
            lines.append(f"## {heading}")
            lines.append("")
        text = sec.get("text")
        if text:
            lines.append(str(text))
            lines.append("")
        items = sec.get("list")
        if items:
            for it in items:
                lines.append(f"- {it}")
            lines.append("")
        table = sec.get("table")
        if table:
            lines.append(f"### {table.get('heading', '')}")
            lines.append("")
            cols = table["columns"]
            lines.append("| " + " | ".join(cols) + " |")
            lines.append("|" + "|".join(["---"] * len(cols)) + "|")
            for row in table["rows"]:
                cells = [str(c) for c in row]
                lines.append("| " + " | ".join(cells) + " |")
            lines.append("")
        code = sec.get("code")
        if code is not None:
            lines.append("```")
            lines.append(str(code))
            lines.append("```")
            lines.append("")
    return "\n".join(lines)


def write_markdown(path: str, title: str, sections: List[Dict[str, Any]], meta: Optional[Dict[str, Any]] = None) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(title, sections, meta))
    return path


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")