"""Configuration loading (JSON primary, YAML optional), merged over defaults.

Pure-stdlib: falls back to JSON if PyYAML is unavailable; the bundled default
config is JSON so it always loads.
"""
from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict, Optional

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PACKAGE_DIR, "data")

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": 1,
    "analysis": {
        "dry_run": True,
    },
    "rules": {
        "file": os.path.join(DATA_DIR, "default_rules.rules"),
        "default_severity": 2,
    },
    "mldetect": {
        "threshold_std": 6.0,
        "k_ewma": 6.0,
        "bin_seconds": 1.0,
        "top_n": 5,
        "features": ["packets", "bytes", "avg_pkt_len", "payload_entropy", "rate_pkts"],
        "sklearn": {"enabled": True, "fallback": True},
    },
    "canary": {
        "arp": {"min_duplicate_answers": 2},
        "dhcp": {"discover_threshold": 20, "window_s": 30.0},
        "dns": {"id_mismatch": True, "source_mismatch": True},
        "tcp": {"rst_threshold": 50, "syn_threshold": 100, "window_s": 10.0},
        "dns_ports": [53, 5353],
    },
    "kernel": {
        "known_bad": ["xmrig", "kinsing", "cgminer", "minergate", "kdevtmpfsi", "pmmpminer"],
        "bad_ports": [31337, 4444, 6667],
        "beacon_ports": [4444, 5555],
        "tmp_paths": ["/tmp/", "/dev/shm/", "/var/tmp/"],
        "traces": [
            {"rex": r"wget\s+http", "severity": 2, "type": "trace.download"},
            {"rex": r"curl\s+(-[A-Za-z0-9 ]+ )?(http|ftp)", "severity": 2, "type": "trace.download"},
            {"rex": r"chmod \+x", "severity": 2, "type": "trace.mutation"},
            {"rex": r"nc\s+-[elp]", "severity": 1, "type": "trace.bind"},
            {"rex": r"socket.*SOCK_RAW", "severity": 1, "type": "trace.rawsocket"},
        ],
    },
    "correlate": {
        "window_s": 120.0,
        "min_alerts": 1,
        "src_prefixes": ["192.0.2.", "198.51.100.", "203.0.113."],
    },
    "alert": {
        "dedupe_ttl_s": 300.0,
        "mailbox": "reports/mailbox.jsonl",
    },
    "reports": {
        "outdir": "reports",
    },
}


def _load_json_or_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # optional convenience
    except ImportError:
        raise ValueError(f"Config {path} is not valid JSON and PyYAML is not installed")
    doc = yaml.safe_load(text)
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise ValueError(f"Config {path} must be a mapping at top level")
    return doc


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load a config file (JSON or YAML) and merge it over the defaults."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path:
        cfg = _deep_merge(cfg, _load_json_or_yaml(path))
    return cfg


def json_dumps_pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)


def ensure_http_only_scopes(scope: str) -> None:
    """Safety gate: refuse non-loopback / non-fixture targets by default."""
    if scope.startswith("eth") or scope.startswith("wlan") or scope.startswith("en"):
        raise ValueError(f"Interface capture {scope!r} requires --no-dry-run in an authorized lab")