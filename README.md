# netsentinel

Detection engine suite: signature rules NIDS, ML flow-anomaly detection,
kernel-watch monitor, MITM detectors (ARP/DHCP/DNS/TCP), SIEM-lite incident
correlation, and a JSON alert API with on-disk mailbox. **Offline /
fixture-first by default** — every subcommand defaults to dry-run and consumes
synthetic RFC 5737 documentation-range traffic; nothing here ever touches a
real network on its own.

## IMPORTANT: Read before use.

# IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

## Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

## Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

## Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

## Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

## No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

## Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

## Quickstart

```bash
python3 -m pip install -e .
python3 -m netsentinel --help
python3 -m netsentinel --demo    # offline detection drill, exit 0
python3 -m unittest discover -s tests
```

## Subcommands

| Command | Purpose |
|---|---|
| `netsentinel pcap [--pcap FILE]` | Read a capture (linktypes 101/1/0), extract 5-tuple flows, DNS queries, payloads. |
| `netsentinel rules [--pcap FILE] [--rules-file FILE]` | Match Suricata-style rules (flags, threshold, content hex/ascii, sid, severity) over a capture → alerts with evidence. |
| `netsentinel mldetect [--baseline FILE] [--pcap FILE] [--threshold N]` | Unsupervised flow anomaly (pure-stdlib z-score/MAD/EWMA; optional sklearn IsolationForest) trained on a normal baseline; flags attack flows. |
| `netsentinel canary [--pcap FILE]` | MITM detectors: ARP-spoof (two replies same IP, different MAC), DHCP starvation, DNS ID-mismatch / source-mismatch, RST/SYN flood signatures. |
| `netsentinel kernel [--proc-root DIR]` | Kernel-watch monitor over a /proc-like fixture tree: known-bad binaries, temp-path processes, abuse ports, beacons, trace events. |
| `netsentinel correlate --alerts FILE[,FILE...] [--window S]` | SIEM-lite incident correlation (RFC 5737 src within window), kill-chain stage estimate, timeline. |
| `netsentinel alert --emit FILE[,FILE...] [--export] [--report]` | Alert API: JSON stream export, TTL dedup, on-disk JSONL mailbox, combined Markdown report. |
| `netsentinel report [--title T]` | Render a combined Markdown report from outdir JSON artifacts. |

Global flags: `--config FILE` (JSON/YAML), `--outdir DIR` (default `reports`),
`--dry-run/--no-dry-run` (**dry-run is ON by default**), `--verbose`, `--demo`.

## Reporting

Every subcommand writes a JSON artifact and prints a JSON summary. The alert
mailbox is a JSONL file (one `Alert` per line). Correlation produces `Incident`
objects with a kill-chain stage estimate (Reconnaissance → Weaponization →
Delivery → Exploitation → Installation → Command and Control → Actions on
Objectives). See `METRICS.md` for measured figures.

## Live Lab Test Plan

The detection suite is validated offline first (fixtures + generated attack
traffic on localhost). To repeat the proof in a real lab you own, we document a
**manual** equivalence: generate the same synthetic artifacts with standard
tools, then replay them through the offline engine. Results are comparable to the
fixture baseline below.

1. **Rules NIDS**: `nmap -sS -Pn 198.51.100.2` (or the bundled `build_scan`
   fixture) then
   `netsentinel rules --pcap scan.pcap` → expect ≥1 alert with
   `sid` 1000001 (SYN threshold) and evidence `matched_contents`.
2. **ML anomaly**: record a clean-session baseline
   (`netsentinel pcap --pcap baseline.pcap`) then a burst
   (e.g. `nc`-style 40-byte exfil loop) →
   `netsentinel mldetect --baseline baseline.pcap --pcap burst.pcap` → expect
   exactly 1 flagged flow, `score >> baseline_max_score` (gap > 5.0).
3. **MITM detectors**: the bundled `build_arp_spoof` fixture =
   `arping -U` spoof or 2 ARP replies with distinct MACs; expect 2
   `arp.spoof` alerts. DHCP DISCOVER flood ≥ 20 in 30 s → `dhcp.starvation`.
4. **DNS**: forge a response with an unknown transaction ID (or from a non-queried
   source) → `dns.id_mismatch` / `dns.source_mismatch`.
5. **Kernel-watch**: point `--proc-root` at a fixture tree containing a
   known-bad binary (`xmrig`) and a 31337 listener → `proc.known_bad` and
   `socket.suspicious_port`.
6. **Correlation**: feed the alert mailbox into
   `netsentinel correlate --alerts alerts.json` → 1 incident whose
   `stage_path` starts `Reconnaissance → Weaponization → Delivery`.
7. **Alert API**: `netsentinel alert --emit alerts.json --export --report`
   → mailbox JSONL with dedup counts, combined `report.md`.

All targets above are RFC 5737 documentation IPs (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`). Replaying generated traffic against real
hosts requires `--no-dry-run` **and** a lab you own.

## Metrics

Measured on this machine (Linux, CPython 3.13.5, offline/dry-run). See
`METRICS.md` for the full table.

- Test suite: **132 tests, 0 failures** (`python -m unittest discover -s tests`).
- `--demo` offline drill: exit `0`; 4 rules fired, 1 anomaly flow flagged with
  score gap ≈ 37.8 vs baseline max 1.62, 2 ARP-spoof alerts, 9 kernel alerts,
  1 incident (full kill-chain path), 20 mailbox entries, ≈0.1 s wall time.

## Legal

The full legal notice lives in-line above (IMPORTANT section). By using this
software you agree to the applicable-use terms. Unauthorized testing is a crime;
only test systems you own or have written authorization to assess.

## License

MIT — see `LICENSE`. Copyright (c) 2026 5h4d0wn1k.