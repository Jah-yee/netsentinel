"""netsentinel command-line interface.

Global flags:
  --config FILE    override config (JSON; YAML when PyYAML present)
  --outdir DIR     report output directory (default: ./reports)
  --dry-run/--no-dry-run   dry-run is ON by default (fixture-only, offline)
  --verbose

Subcommands: pcap, rules, mldetect, canary, kernel, correlate, alert, report.
`--demo` runs the full offline detection drill and exits 0 with real proof.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

from . import __version__
from .alertapi import Notifier, export_json, write_reports
from .canary import CanaryEngine
from .config import load_config
from .correlate import correlate, incident_timeline
from .fixtures import build_demo_pcaps, build_proc_tree
from .kernel import watch
from .mldetect import EwmaBurstDetector, FlowAnomalyDetector
from .model import Alert, Incident, Mailbox
from .pcap import extract, extract_flows, read_pcap
from .report import write_json
from .rules import RulesEngine

OFFLINE_OK = 0
REFUSED = 1


def _e(msg: str) -> int:
    print(f"netsentinel: {msg}", file=sys.stderr)
    return REFUSED


def _guard_dry_run(dry_run: bool, kind: str, value: str) -> Optional[int]:
    """Safety gate: real-system paths/interfaces are refused while dry-run is on."""
    if not dry_run:
        return None
    if kind == "proc" and (value == "/proc" or value.startswith("/proc/") or value in ("/sys", "/sys/", "/dev")):
        return _e(f"--dry-run refuses real kernel path {value!r}; use a fixture tree or --no-dry-run")
    if kind == "interface" and value in ("lo", "eth0", "any") or kind == "interface" and value.startswith(("eth", "wlan", "en")):
        return _e(f"--dry-run refuses interface capture {value!r}; point at a pcap file or --no-dry-run")
    return None


def _load_alert_dicts(path: str) -> List[Alert]:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    items = doc.get("alerts") if isinstance(doc, dict) else doc
    return [Alert.from_dict(d) for d in items]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netsentinel",
        description="Detection engine suite: rules NIDS, ML flow-anomaly, kernel watchdog, "
                    "MITM detectors, SIEM-lite correlation, alert API. Offline/fixture-first.",
        epilog="Authorized testing/education only. See README's IMPORTANT section.",
    )
    p.add_argument("--version", action="version", version=f"netsentinel {__version__}")
    p.add_argument("--config", default=None, help="config JSON/YAML override")
    p.add_argument("--outdir", default="reports", help="report output dir (default: reports)")
    p.add_argument("--dry-run", action=argparse.BooleanOptionalAction, default=True,
                   help="default: dry-run (fixture-only, offline). --no-dry-run lifts it.")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--demo", action="store_true", help="run full offline detection drill and exit 0")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS, help="config JSON/YAML override")
    common.add_argument("--outdir", default=argparse.SUPPRESS, help="report output dir (default: reports)")
    common.add_argument("--dry-run", action=argparse.BooleanOptionalAction, default=argparse.SUPPRESS,
                        help="default: dry-run (fixture-only, offline). --no-dry-run lifts it.")
    common.add_argument("--verbose", action="store_true")

    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    sp = sub.add_parser("pcap", parents=[common], help="read a capture, extract flows + metadata + DNS")
    sp.add_argument("--pcap", default=None, help="pcap path (default: generated baseline fixture)")
    sp.add_argument("--interface", default=None, help="interface name (requires --no-dry-run)")

    sp = sub.add_parser("rules", parents=[common], help="match Suricata-style rules over a capture")
    sp.add_argument("--pcap", default=None)
    sp.add_argument("--rules-file", default=None, help=".rules file (default: bundled default_rules.rules)")

    sp = sub.add_parser("mldetect", parents=[common], help="flow-anomaly detection trained on a baseline")
    sp.add_argument("--baseline", default=None, help="pcap to train on")
    sp.add_argument("--pcap", default=None, help="pcap to score")
    sp.add_argument("--threshold", type=float, default=None, help="anomaly z threshold")
    sp.add_argument("--top-n", type=int, default=None)
    sp.add_argument("--no-sklearn", action="store_true", help="disable sklearn IsolationForest")

    sp = sub.add_parser("canary", parents=[common], help="MITM detectors: ARP/DHCP/DNS/TCP-signature")
    sp.add_argument("--pcap", default=None)

    sp = sub.add_parser("kernel", parents=[common], help="kernel-watch: read /proc-like fixture tree")
    sp.add_argument("--proc-root", default=None, help="fixture tree root")

    sp = sub.add_parser("correlate", parents=[common], help="SIEM-lite correlation of alerts into incidents")
    sp.add_argument("--alerts", default=None, help="comma-separated JSON files of alerts")
    sp.add_argument("--window", type=float, default=None)

    sp = sub.add_parser("alert", parents=[common], help="alert API: mailbox, JSON export, report")
    sp.add_argument("--emit", default="", help="comma-separated JSON alert files to ingest")
    sp.add_argument("--mailbox", default=None)
    sp.add_argument("--export", action="store_true", help="print JSON stream to stdout")
    sp.add_argument("--report", action="store_true", help="write combined JSON+Markdown report to outdir")

    sp = sub.add_parser("report", parents=[common], help="render combined Markdown report from outdir JSON artifacts")
    sp.add_argument("--title", default="netsentinel analysis report")
    return p


def _fixture_dir(cfg: Dict[str, Any], outdir: str) -> str:
    d = os.path.join(outdir, "demo_fixtures")
    os.makedirs(d, exist_ok=True)
    return d


def cmd_pcap(args, cfg) -> int:
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    path = args.pcap
    if args.interface:
        guard = _guard_dry_run(args.dry_run, "interface", args.interface)
        if guard is not None:
            return guard
        return _e("interface capture requires live sniffing (--no-dry-run) + an authorized lab")
    if not path:
        from .fixtures import build_baseline
        path = build_baseline(os.path.join(outdir, "_fixture_baseline.pcap"))
    cap = read_pcap(path)
    packets = extract(cap)
    flows = extract_flows(packets)
    dns = [p for p in packets if p.get("dns")]
    summary = {
        "pcap": path, "linktype": cap.linktype, "packets": len(packets),
        "flows": len(flows), "dns_queries": len(dns),
        "flow_5tuples": [
            {"flow": f["flow_key"], "packets": f["packets"], "bytes": f["bytes"]}
            for f in flows[:20]
        ],
    }
    write_json(os.path.join(outdir, "pcap.json"), summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return OFFLINE_OK


def cmd_rules(args, cfg) -> int:
    rules_file = args.rules_file or cfg["rules"]["file"]
    engine = RulesEngine.load_rules(rules_file, cfg["rules"].get("default_severity", 2))
    if not args.pcap:
        from .fixtures import build_scan
        args.pcap = build_scan(os.path.join(args.outdir, "_fixture_scan.pcap"))
    cap = read_pcap(args.pcap)
    alerts = engine.scan(extract(cap))
    write_json(os.path.join(args.outdir, "rules.json"), {"rules": len(engine.rules), "alerts": [a.to_dict() for a in alerts]})
    payload = {
        "rules_loaded": len(engine.rules),
        "alerts_fired": len(alerts),
        "per_sid": sorted({a.evidence.get("sid") for a in alerts}),
        "alert_details": [
            {"sid": a.evidence.get("sid"), "msg": a.subject, "src": a.src, "dst": a.dst,
             "matched": a.evidence.get("matched_contents", [])}
            for a in alerts
        ],
    }
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return OFFLINE_OK


def cmd_mldetect(args, cfg) -> int:
    if not args.baseline:
        from .fixtures import build_baseline
        args.baseline = build_baseline(os.path.join(args.outdir, "_fixture_baseline.pcap"))
    if not args.pcap:
        from .fixtures import build_exfil
        args.pcap = build_exfil(os.path.join(args.outdir, "_fixture_exfil.pcap"))
    det = FlowAnomalyDetector(
        threshold_std=cfg["mldetect"]["threshold_std"] if args.threshold is None else args.threshold,
        features=cfg["mldetect"]["features"],
        use_sklearn=not args.no_sklearn,
    )
    base_flows = extract_flows(extract(read_pcap(args.baseline)))
    test_flows = extract_flows(extract(read_pcap(args.pcap)))
    det.fit(base_flows)
    rows = det.predict(test_flows, top_n=args.top_n)
    flagged = [r for r in rows if r["flagged"]]
    payload = {
        "engine": det.engine,
        "baseline_flows": len(base_flows),
        "test_flows": len(test_flows),
        "baseline_max_score": det.baseline_max_score,
        "baseline_mean_score": det.baseline_mean_score,
        "threshold": det.threshold_std,
        "flagged": len(flagged),
        "flagged_flows": flagged,
    }
    write_json(os.path.join(args.outdir, "mldetect.json"), payload)
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return OFFLINE_OK


def cmd_canary(args, cfg) -> int:
    if not args.pcap:
        from .fixtures import build_arp_spoof
        args.pcap = build_arp_spoof(os.path.join(args.outdir, "_fixture_arp.pcap"))
    cap = read_pcap(args.pcap)
    alerts = CanaryEngine().scan_capture(cap, cfg)
    write_json(os.path.join(args.outdir, "canary.json"), {"alerts": [a.to_dict() for a in alerts]})
    payload = {
        "alerts_fired": len(alerts),
        "categories": sorted({a.category for a in alerts}),
        "alerts": [a.to_dict() for a in alerts],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return OFFLINE_OK


def cmd_kernel(args, cfg) -> int:
    if not args.proc_root:
        from .fixtures import build_proc_tree as bpt
        args.proc_root = bpt(os.path.join(args.outdir, "_fixture_proc"))
    guard = _guard_dry_run(args.dry_run, "proc", args.proc_root)
    if guard is not None:
        return guard
    alerts = watch(args.proc_root, cfg)
    payload = {
        "proc_root": args.proc_root,
        "alerts_fired": len(alerts),
        "categories": sorted({a.category for a in alerts}),
        "alerts": [a.to_dict() for a in alerts],
    }
    write_json(os.path.join(args.outdir, "kernel.json"), payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return OFFLINE_OK


def _collect_alerts(paths: str, mailbox: Mailbox) -> List[Alert]:
    out: List[Alert] = []
    for p in [x for x in (paths or "").split(",") if x.strip()]:
        out.extend(_load_alert_dicts(p.strip()))
    return out


def cmd_correlate(args, cfg) -> int:
    if not args.alerts:
        return _e("correlate needs --alerts FILE[,FILE...] (JSON alert exports)")
    alerts = _collect_alerts(args.alerts, None)  # type: ignore[arg-type]
    window = cfg["correlate"]["window_s"] if args.window is None else args.window
    incidents = correlate(alerts, window_s=window)
    payload = {
        "alerts": len(alerts),
        "incidents": len(incidents),
        "incident_details": [
            {"id": i.id, "src": i.src, "alerts": len(i.alerts), "stage": i.stage,
             "stage_path": i.stage_path, "severity": i.severity,
             "timeline": incident_timeline(i)}
            for i in incidents
        ],
    }
    write_json(os.path.join(args.outdir, "correlate.json"), payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return OFFLINE_OK


def cmd_alert(args, cfg) -> int:
    mailbox_path = args.mailbox or cfg["alert"]["mailbox"]
    if args.outdir != "reports":
        mailbox_path = os.path.join(args.outdir, os.path.basename(mailbox_path))
    mailbox = Mailbox(mailbox_path, cfg["alert"]["dedupe_ttl_s"])
    alerts = _collect_alerts(args.emit, mailbox)
    notifier = Notifier(mailbox)
    for a in alerts:
        notifier.emit(a)
    if args.export:
        print(export_json(notifier.accepted))
    payload = {
        "mailbox": mailbox_path,
        "ingested": len(alerts),
        "accepted": len(notifier.accepted),
        "suppressed_duplicates": len(notifier.suppressed),
        "categories": sorted({a.category for a in notifier.accepted}),
    }
    if args.report:
        write_reports(args.outdir, "netsentinel alert report",
                      {"alerts": [a.to_dict() for a in notifier.accepted]},
                      [{"heading": "Alert mailbox", "list": [a.subject for a in notifier.accepted[:50]]},
                       {"heading": "Deduplication", "text": f"{len(notifier.accepted)} accepted, "
                                                             f"{len(notifier.suppressed)} suppressed"}],
                      meta={"tool": "netsentinel", "version": __version__})
    write_json(os.path.join(args.outdir, "alert.json"), payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return OFFLINE_OK


def cmd_report(args, cfg) -> int:
    import glob
    sections: List[Dict[str, Any]] = []
    total_alerts = 0
    for path in sorted(glob.glob(os.path.join(args.outdir, "*.json"))):
        if os.path.basename(path) in ("report.json", "alert.json"):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
        name = os.path.basename(path).replace(".json", "")
        alerts = doc.get("alerts") if isinstance(doc, dict) else None
        if isinstance(alerts, list):
            n = len(alerts)
        elif isinstance(doc, dict):
            n = doc.get("alerts_fired", 0)
        else:
            n = 0
        total_alerts += n if isinstance(n, int) else 0
        sections.append({"heading": name, "code": json.dumps(doc, indent=2, sort_keys=True, default=str)[:4000]})
    payload = {"artifact_count": len(sections), "total_reported_alerts": total_alerts}
    write_json(os.path.join(args.outdir, "report.json"), payload)
    from .report import write_markdown
    write_markdown(os.path.join(args.outdir, "report.md"), args.title, sections,
                   meta={"tool": "netsentinel", "version": __version__})
    print(json.dumps(payload, indent=2, sort_keys=True))
    return OFFLINE_OK


def run_demo(cfg: Dict[str, Any], outdir: str, verbose: bool) -> dict:
    """Full offline detection drill. Returns proof metrics."""
    t0 = time.time()
    fix_dir = _fixture_dir(cfg, outdir)
    fix = build_demo_pcaps(fix_dir)
    proc_root = os.path.join(fix_dir, "proc")
    build_proc_tree(proc_root, host_ip="192.0.2.66")

    from .pcap import extract as _xt, read_pcap as _rp

    # 1) Rules engine over the scan (recon + weaponization)
    rules_alerts = RulesEngine.load_rules(cfg["rules"]["file"],
                                          cfg["rules"].get("default_severity", 2)).scan(
        _xt(_rp(fix["scan"])))
    # 2) ML flow-anomaly (train on baseline, score the exfil burst)
    det = FlowAnomalyDetector(threshold_std=cfg["mldetect"]["threshold_std"],
                              features=cfg["mldetect"]["features"])
    det.fit(extract_flows(_xt(_rp(fix["baseline"]))))
    exfil_rows = det.predict(extract_flows(_xt(_rp(fix["exfil"]))), top_n=cfg["mldetect"]["top_n"])
    flagged = [r for r in exfil_rows if r["flagged"]]
    # EWMA rate-burst proof over packets: baseline + exfil timestamps together
    _base_pkt_ts = [p["ts"] for p in _xt(_rp(fix["baseline"]))]
    _exfil_pkt_ts = [p["ts"] for p in _xt(_rp(fix["exfil"]))]
    bursts = EwmaBurstDetector(alpha=0.2, k=cfg["mldetect"]["k_ewma"]).detect(
        _base_pkt_ts + _exfil_pkt_ts, bin_seconds=cfg["mldetect"]["bin_seconds"])
    ml_alerts = [
        Alert(ts=fix_ts("exfil") + 0.5, module="mldetect", category="anomaly.flow",
              severity=1,
              subject=f"flow anomaly (exfil burst) src={r['client_ip']} dst={r['server_ip']}:{r['server_port']} score={r['score']}",
              src=r["client_ip"], dst=f"{r['server_ip']}:{r['server_port']}",
              action="log-only",
              evidence={"score": r["score"], "packets": r["packets"], "bytes": r["bytes"], "why": r["why"]},
              dedupe_key=f"mldetect|{r['flow_key']}")
        for r in flagged
    ]
    # 3) MITM canary detectors
    canary_alerts: List[Alert] = []
    for name in ("dns_mismatch", "arp_spoof", "dhcp_starvation", "rst_flood"):
        canary_alerts += CanaryEngine().scan_capture(read_pcap(fix[name]), cfg)
    # 4) kernel watch
    kernel_alerts = watch(proc_root, cfg)
    # 5) correlation
    all_alerts = sorted(rules_alerts + ml_alerts + canary_alerts + kernel_alerts, key=lambda a: a.ts)
    incidents = correlate(all_alerts, window_s=cfg["correlate"]["window_s"])
    # 6) alert API
    mailbox = Mailbox(os.path.join(outdir, "demo", "mailbox.jsonl"), cfg["alert"]["dedupe_ttl_s"])
    notifier = Notifier(mailbox)
    for a in all_alerts:
        notifier.emit(a)

    t1 = time.time()
    proof = {
        "rules_fired": len(rules_alerts),
        "rules_per_sid": sorted({a.evidence.get("sid") for a in rules_alerts}),
        "ml_flagged_flows": len(ml_alerts),
        "ml_anomaly_score": max((r["score"] for r in flagged), default=0.0),
        "ml_baseline_max": det.baseline_max_score,
        "ml_gap": max((r["score"] for r in flagged), default=0.0) - det.baseline_max_score,
        "ml_threshold": det.threshold_std,
        "ml_ewma_bursts": len(bursts),
        "arp_spoof_alerts": sum(1 for a in canary_alerts if a.category == "arp.spoof"),
        "canary_alerts": len(canary_alerts),
        "canary_categories": sorted({a.category for a in canary_alerts}),
        "kernel_alerts": len(kernel_alerts),
        "kernel_categories": sorted({a.category for a in kernel_alerts}),
        "incidents": len(incidents),
        "incident_stage": incidents[0].stage if incidents else "",
        "incident_stage_path": incidents[0].stage_path if incidents else [],
        "mailbox_accepted": len(notifier.accepted),
        "mailbox_suppressed": len(notifier.suppressed),
        "elapsed_s": round(t1 - t0, 3),
    }
    _write_demo_reports(outdir, proof, all_alerts, incidents, det, flagged)
    return proof


def fix_ts(pcap_key: str) -> float:
    from .fixtures import BASE
    offsets = {"baseline": 0.0, "scan": 0.0, "dns_mismatch": 2.0, "arp_spoof": 3.0,
               "dhcp_starvation": 4.0, "exfil": 5.0, "rst_flood": 6.0}
    return BASE + offsets.get(pcap_key, 0.0)


def _write_demo_reports(outdir: str, proof: dict, alerts: List[Alert], incidents: List[Incident],
                        det: FlowAnomalyDetector, flagged: List[dict]) -> None:
    d = os.path.join(outdir, "demo")
    os.makedirs(d, exist_ok=True)
    write_json(os.path.join(d, "all_alerts.json"),
               {"count": len(alerts), "alerts": [a.to_dict() for a in alerts]})
    write_json(os.path.join(d, "proof.json"), proof)
    sections = [
        {"heading": "Proof metrics", "table": {
            "columns": ["metric", "value"],
            "rows": [[k, json.dumps(v)] for k, v in proof.items()]}},
        {"heading": "Rules fired", "list": [f"{a.subject} (sid {a.evidence.get('sid')}, "
                                            f"{a.src} -> {a.dst})" for a in alerts if a.module == "rules"]},
        {"heading": "ML anomaly", "text":
             f"engine={det.engine} threshold={det.threshold_std} baseline_max={round(det.baseline_max_score, 3)} "
             f"anomaly_score={proof['ml_anomaly_score']} gap={round(proof['ml_gap'], 3)}"},
        {"heading": "Incidents", "list": [
            f"{i.id} src={i.src} stage={i.stage} path={' -> '.join(i.stage_path)} alerts={len(i.alerts)}"
            for i in incidents]},
        {"heading": "Incident timeline", "table": {
            "columns": ["ts", "module", "category", "severity", "subject"],
            "rows": [[a.ts, a.module, a.category, a.severity, a.subject]
                     for a in sorted(alerts, key=lambda x: (x.ts, x.category))[:60]]}},
    ]
    from .report import write_markdown
    write_markdown(os.path.join(d, "report.md"), "netsentinel demo report", sections,
                   meta={"tool": "netsentinel", "version": __version__, "dry_run": "true", "offline": "true"})


def cmd_demo(args, cfg) -> int:
    proof = run_demo(cfg, args.outdir, args.verbose)
    print(json.dumps(proof, sort_keys=True))
    print("\nPROOF")
    print(f"  rules fired:               {proof['rules_fired']} (sids {proof['rules_per_sid']})")
    print(f"  ml anomaly flow flagged:   {proof['ml_flagged_flows']} "
          f"(score {proof['ml_anomaly_score']}, baseline max {proof['ml_baseline_max']}, "
          f"gap {proof['ml_gap']})")
    print(f"  arp-spoof alerts:          {proof['arp_spoof_alerts']}")
    print(f"  canary alerts:             {proof['canary_alerts']} {proof['canary_categories']}")
    print(f"  kernel alerts:             {proof['kernel_alerts']} {proof['kernel_categories']}")
    print(f"  incidents:                 {proof['incidents']} "
          f"stage={proof['incident_stage']} path={' -> '.join(proof['incident_stage_path'])}")
    print(f"  mailbox entries:           {proof['mailbox_accepted']} accepted, "
          f"{proof['mailbox_suppressed']} duplicate-suppressed")
    print(f"  elapsed:                   {proof['elapsed_s']}s (offline, dry-run)")
    return OFFLINE_OK


_HANDLERS = {
    "pcap": cmd_pcap,
    "rules": cmd_rules,
    "mldetect": cmd_mldetect,
    "canary": cmd_canary,
    "kernel": cmd_kernel,
    "correlate": cmd_correlate,
    "alert": cmd_alert,
    "report": cmd_report,
}


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    try:
        cfg = load_config(args.config)
    except (FileNotFoundError, ValueError, OSError) as exc:
        return _e(f"config: {exc}")
    if args.demo:
        return cmd_demo(args, cfg)
    if not args.command:
        parser.print_help()
        return REFUSED
    handler = _HANDLERS.get(args.command)
    if handler is None:
        parser.print_help()
        return REFUSED
    try:
        return handler(args, cfg)
    except (FileNotFoundError, ValueError, OSError) as exc:
        return _e(f"{args.command}: {exc}")


if __name__ == "__main__":
    sys.exit(main())