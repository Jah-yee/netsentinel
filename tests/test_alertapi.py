"""Alert API tests: JSON export, mailbox, dedupe, reports."""
import json
import os
import tempfile
import unittest

from netsentinel.alertapi import Mailbox, Notifier, export_json, write_reports
from netsentinel.model import Alert
from netsentinel.report import render_markdown, write_json, write_markdown

TS0 = 1_700_000_000.0


def a(category="x", src="192.0.2.66", ts=TS0, dedupe="k"):
    return Alert(ts=ts, module="test", category=category, severity=1,
                 subject="s", src=src, dst="198.51.100.2", action="notify",
                 evidence={"e": 1}, dedupe_key=dedupe)


class TestExport(unittest.TestCase):

    def test_export_json_shape(self):
        doc = json.loads(export_json([a()]))
        self.assertEqual(doc["count"], 1)
        self.assertEqual(doc["alerts"][0]["subject"], "s")
        self.assertEqual(doc["alerts"][0]["action"], "notify")
        self.assertEqual(doc["alerts"][0]["src"], "192.0.2.66")

    def test_export_json_empty(self):
        doc = json.loads(export_json([]))
        self.assertEqual(doc["count"], 0)

    def test_alert_to_dict_roundtrip(self):
        orig = a(dedupe="special")
        restored = Alert.from_dict(orig.to_dict())
        self.assertEqual(restored.dedupe_key, "special")
        self.assertEqual(restored.category, "x")


class TestMailbox(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mb = Mailbox(os.path.join(self.tmp, "mail.jsonl"), dedupe_ttl_s=100)

    def test_emit_persists_and_loads(self):
        self.assertTrue(self.mb.emit(a(), now=TS0))
        loaded = self.mb.load()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].category, "x")

    def test_dedupe_within_ttl(self):
        self.assertTrue(self.mb.emit(a(), now=TS0))
        self.assertFalse(self.mb.emit(a(), now=TS0 + 10))
        self.assertEqual(len(self.mb.load()), 1)

    def test_reemit_after_ttl(self):
        self.assertTrue(self.mb.emit(a(), now=TS0))
        self.assertTrue(self.mb.emit(a(), now=TS0 + 200))
        self.assertEqual(len(self.mb.load()), 2)

    def test_different_dedupe_keys_kept(self):
        self.assertTrue(self.mb.emit(a(dedupe="1"), now=TS0))
        self.assertTrue(self.mb.emit(a(dedupe="2"), now=TS0))
        self.assertEqual(len(self.mb.load()), 2)

    def test_clear(self):
        self.mb.emit(a(), now=TS0)
        self.mb.clear()
        self.assertEqual(self.mb.load(), [])

    def test_corrupt_line_tolerated(self):
        self.mb.emit(a(), now=TS0)
        with open(self.mb.path, "a") as fh:
            fh.write("{not json}\n")
        self.assertEqual(len(self.mb.load()), 1)

    def test_emit_creates_dirs(self):
        mb = Mailbox(os.path.join(self.tmp, "nested", "deep", "mail.jsonl"))
        self.assertTrue(mb.emit(a(), now=TS0))


class TestNotifier(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.n = Notifier(Mailbox(os.path.join(self.tmp, "mail.jsonl")))

    def test_accept_and_suppress_counting(self):
        ok1 = self.n.emit(a(dedupe="k"), now=TS0)
        ok2 = self.n.emit(a(dedupe="k"), now=TS0 + 5)
        self.assertTrue(ok1)
        self.assertFalse(ok2)
        self.assertEqual(self.n.summarize()["accepted"], 1)
        self.assertEqual(self.n.summarize()["suppressed_duplicates"], 1)


class TestReports(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_write_json(self):
        p = write_json(os.path.join(self.tmp, "x.json"), {"n": 1})
        self.assertTrue(os.path.exists(p))
        with open(p) as fh:
            self.assertEqual(json.load(fh)["n"], 1)

    def test_render_markdown_heading(self):
        md = render_markdown("T", [{"heading": "H", "text": "body"}])
        self.assertIn("# T", md)
        self.assertIn("## H", md)
        self.assertIn("body", md)

    def test_render_markdown_table(self):
        md = render_markdown("T", [{"table": {"heading": "X", "columns": ["a", "b"],
                                              "rows": [[1, 2]]}}])
        self.assertIn("| 1 | 2 |", md)

    def test_write_markdown(self):
        p = write_markdown(os.path.join(self.tmp, "r.md"), "T",
                           [{"heading": "H", "text": "x"}], meta={"k": "v"})
        with open(p) as fh:
            self.assertIn("| k | v |", fh.read())

    def test_write_reports_bundle(self):
        paths = write_reports(self.tmp, "R", {"alerts": {"n": 1}},
                              [{"heading": "H", "text": "t"}])
        self.assertTrue(os.path.exists(paths["alerts"]))
        self.assertTrue(os.path.exists(paths["markdown"]))


if __name__ == "__main__":
    unittest.main()