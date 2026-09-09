"""CLI end-to-end tests (all offline, dry-run by default)."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from netsentinel.cli import main
from netsentinel.model import Alert


class CliTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="netsentinel_cli_")

    def run_cli(self, argv, out=None, err=None):
        code = main(argv)
        if out is not None:
            self.assertIn("netsentinel", out.getvalue() or "")
        return code


class TestCliSubcommands(CliTestCase):

    def test_version_exit_zero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("1.0.0", buf.getvalue())

    def test_pcap_subcommand(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["pcap", "--outdir", self.tmp])
        self.assertEqual(code, 0)
        self.assertIn("flows", buf.getvalue())

    def test_rules_subcommand(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["rules", "--outdir", self.tmp])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "rules.json")))

    def test_mldetect_subcommand(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["mldetect", "--outdir", self.tmp])
        self.assertEqual(code, 0)
        doc = json.load(open(os.path.join(self.tmp, "mldetect.json")))
        self.assertGreaterEqual(doc["flagged"], 0)

    def test_canary_subcommand(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["canary", "--outdir", self.tmp])
        self.assertEqual(code, 0)

    def test_kernel_subcommand(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["kernel", "--outdir", self.tmp])
        self.assertEqual(code, 0)
        doc = json.load(open(os.path.join(self.tmp, "kernel.json")))
        self.assertGreaterEqual(doc["alerts_fired"], 1)

    def test_correlate_subcommand_requires_alerts(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = main(["correlate", "--outdir", self.tmp])
        self.assertEqual(code, 1)

    def test_correlate_subcommand_with_alerts(self):
        alert_file = os.path.join(self.tmp, "in_alerts.json")
        with open(alert_file, "w") as fh:
            json.dump({"alerts": [
                Alert(ts=100.0, module="rules", category="rules.signature.scan",
                      severity=2, subject="s", src="192.0.2.66", dst="198.51.100.2").to_dict()
            ]}, fh)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["correlate", "--alerts", alert_file, "--outdir", self.tmp])
        self.assertEqual(code, 0)
        doc = json.load(open(os.path.join(self.tmp, "correlate.json")))
        self.assertEqual(doc["incidents"], 1)

    def test_alert_subcommand_export_report(self):
        alert_file = os.path.join(self.tmp, "in2.json")
        with open(alert_file, "w") as fh:
            json.dump({"alerts": [
                Alert(ts=100.0, module="canary", category="arp.spoof", severity=1,
                      subject="arp", src="192.0.2.66", dst="192.0.2.10",
                      dedupe_key="arp|a").to_dict()
            ]}, fh)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["alert", "--emit", alert_file, "--export", "--report",
                         "--outdir", self.tmp])
        self.assertEqual(code, 0)
        self.assertIn("arp.spoof", buf.getvalue())
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "report.md")))
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "mailbox.jsonl")))

    def test_report_subcommand(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["report", "--outdir", self.tmp])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "report.md")))

    def test_no_command_prints_help_and_errors(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = main([])
        self.assertEqual(code, 1)

    def test_kernel_dry_run_refuses_real_proc(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = main(["kernel", "--proc-root", "/proc", "--outdir", self.tmp])
        self.assertEqual(code, 1)
        self.assertIn("dry-run", err.getvalue())

    def test_kernel_no_dry_run_allowed(self):
        # --no-dry-run lifts the gate; reading /proc is permitted by the flag
        # (no network side effects in this code path).
        with tempfile.TemporaryDirectory() as d:
            from netsentinel.fixtures import build_proc_tree
            root = build_proc_tree(os.path.join(d, "p"))
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["kernel", "--proc-root", root, "--no-dry-run", "--outdir", self.tmp])
            self.assertEqual(code, 0)

    def test_config_missing_file_errors(self):
        code = main(["--config", os.path.join(self.tmp, "missing.json"), "pcap"])
        self.assertEqual(code, 1)


class TestDemo(CliTestCase):

    def run_demo(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["--demo", "--outdir", self.tmp])
        return code, buf.getvalue()

    def test_demo_exit_zero(self):
        code, _ = self.run_demo()
        self.assertEqual(code, 0)

    def test_demo_writes_artifacts(self):
        self.run_demo()
        demo = os.path.join(self.tmp, "demo")
        self.assertTrue(os.path.exists(os.path.join(demo, "proof.json")))
        self.assertTrue(os.path.exists(os.path.join(demo, "report.md")))
        self.assertTrue(os.path.exists(os.path.join(demo, "all_alerts.json")))
        self.assertTrue(os.path.exists(os.path.join(demo, "mailbox.jsonl")))

    def test_demo_proof_numbers(self):
        _, out = self.run_demo()
        proof = json.loads(out.splitlines()[0])
        self.assertGreaterEqual(proof["rules_fired"], 3)
        self.assertEqual(proof["arp_spoof_alerts"], 2)
        self.assertEqual(proof["incidents"], 1)
        self.assertTrue(proof["incident_stage_path"])
        self.assertEqual(proof["incident_stage_path"][0], "Reconnaissance")
        self.assertGreater(proof["ml_gap"], 5.0)
        self.assertGreaterEqual(proof["kernel_alerts"], 5)
        self.assertGreaterEqual(proof["mailbox_accepted"], 10)

    def test_demo_mailbox_entries(self):
        _, _ = self.run_demo()
        path = os.path.join(self.tmp, "demo", "mailbox.jsonl")
        with open(path) as fh:
            lines = [ln for ln in fh if ln.strip()]
        self.assertGreaterEqual(len(lines), 10)


if __name__ == "__main__":
    unittest.main()