# Metrics

Measured on: Linux, CPython 3.13.5, offline / dry-run (no network contact).
Fixture traffic uses RFC 5737 documentation ranges only. Updated after each
feature lands.

## Test suite

- `python -m unittest discover -s tests`: **132 tests, 0 failures** (1.3 s).
  Coverage: pcap reader/decoders (linktypes 101 + 1), rules engine (flags,
  threshold, content hex/ascii, within), ML anomaly (z/MAD/EWMA, sklearn-guarded
  fallback), MITM detectors (ARP/DHCP/DNS/RST), kernel-watch, correlation,
  alert API/mailbox, CLI + demo.

## `--demo` offline drill (exit 0)

| Metric | Value |
|---|---|
| Rules fired | 4 (sids 1000001–1000004) |
| ML anomaly flows flagged | 1 (true positive) |
| ML anomaly score | 39.42 |
| ML baseline max score | 1.62 |
| ML score gap | **37.80** |
| ML EWMA rate bursts | 1 |
| ARP-spoof alerts | 2 (flow-set A; 0 on clean set B) |
| DHSTARV/DNS-ID/RST signatures | dhcp.starvation, dns.id_mismatch, dns.source_mismatch, tcp.rst_flood |
| Canary alerts total | 6 |
| Kernel alerts | 9 (proc.known_bad, proc.tmp_path, socket.suspicious_port, socket.beacon, trace.*) |
| Incidents | 1 |
| Incident stage | Actions on Objectives (recon→weaponize→delivery→exploitation→…→actions) |
| Mailbox accepted / suppressed | 20 / 0 |
| Wall time | ≈0.07 s |

## Detection accuracy (fixtures, TP vs FP)

| Detector | Fixture | Alerts | FP on clean? |
|---|---|---|---|
| Rules: NMAP-style SYN threshold | scan.pcap | 1 (sid 1000001) | No (baseline 0) |
| Rules: JPG-magic exploit marker | scan.pcap | 1 (sid 1000002) | No |
| Rules: shellcode marker `SHELL!` | scan.pcap | 1 (sid 1000003) | No |
| Rules: SQL tautology probe | scan.pcap | 1 (sid 1000004) | No |
| ML: exfil burst flow | exfil.pcap | 1 flagged, port 5555 | No (baseline 0 flagged) |
| ARP-spoof | arp_spoof_a vs arp_spoof_b | 2 vs 0 | No |
| DHCP starvation | starvation vs clean | 1 vs 0 | No |
| DNS ID-mismatch | mismatch vs clean | 1 vs 0 | No |
| DNS source-mismatch | mismatch vs clean | 1 vs 0 | No |
| RST flood | rst_flood vs clean | 1 vs 0 | No |
| Kernel bill | /proc fixture vs clean | 9 vs 0 | No |

## Performance

- Demo drill (all 7 modules + correlation + mailbox): ~70 ms.
- Full unittest suite: ~1.3 s.
- Memory: fixture-only, bounded (per-flow payload capped at 1 MiB).

## Environment note

Run with `python -m netsentinel --demo` or `python3 -m unittest discover -s tests`;
zero third-party runtime dependencies required (sklearn is optional and
auto-falls back to the pure-stdlib statistical engine).