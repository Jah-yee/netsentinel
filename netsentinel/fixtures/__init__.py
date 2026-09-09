"""Fixture generators: pcap captures + /proc-like observation trees.

Everything runs offline on synthetic RFC 5737 traffic. Used by tests and the
``--demo`` drill.
"""
from __future__ import annotations

import os
import tempfile

from .pcapbuild import (BASE, ATTACKER, SERVER, VICTIM, build_all, build_attack,
                        build_arp_clean, build_arp_spoof, build_baseline,
                        build_demo_pcaps, build_dhcp_clean, build_dhcp_starvation,
                        build_dns_clean, build_dns_mismatch, build_exfil,
                        build_rst_clean, build_rst_flood, build_scan, build_smb_probe)
from .proc import build_clean_proc_tree, build_proc_tree

__all__ = [
    "BASE", "ATTACKER", "SERVER", "VICTIM",
    "build_all", "build_attack", "build_arp_clean", "build_arp_spoof",
    "build_baseline", "build_demo_pcaps", "build_dhcp_clean",
    "build_dhcp_starvation", "build_dns_clean", "build_dns_mismatch",
    "build_exfil", "build_rst_clean", "build_rst_flood", "build_scan",
    "build_smb_probe",
    "build_proc_tree", "build_clean_proc_tree",
]


def make_fixtures_dir() -> str:
    """Create a fresh fixtures directory in a temp location (caller manages)."""
    tmp = tempfile.mkdtemp(prefix="netsentinel_fixtures_")
    build_all(tmp)
    build_proc_tree(os.path.join(tmp, "proc"))
    return tmp