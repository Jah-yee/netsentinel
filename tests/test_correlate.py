"""SIEM-lite correlation tests."""
import unittest

from netsentinel.correlate import (KILL_CHAIN, correlate, estimate_stage,
                                   incident_timeline, stage_index, stage_path_of)
from netsentinel.model import Alert


def make(ts, module="rules", category="rules.signature.scan", src="192.0.2.66",
         severity=2, subject="t"):
    return Alert(ts=ts, module=module, category=category, severity=severity,
                 subject=subject, src=src)


class TestCorrelate(unittest.TestCase):

    def test_same_src_windowed_into_incident(self):
        incs = correlate([make(10), make(20), make(30)], window_s=60)
        self.assertEqual(len(incs), 1)
        self.assertEqual(len(incs[0].alerts), 3)

    def test_different_src_split(self):
        incs = correlate([make(10, src="192.0.2.1"), make(20, src="192.0.2.2")])
        self.assertEqual(len(incs), 2)

    def test_window_break_splits(self):
        incs = correlate([make(10), make(200)], window_s=60)
        self.assertEqual(len(incs), 2)

    def test_incident_severity_max(self):
        incs = correlate([make(10, severity=3), make(11, severity=1)])
        self.assertEqual(incs[0].severity, 1)

    def test_recon_stage_for_scan(self):
        incs = correlate([make(10)])
        self.assertEqual(incs[0].stage, "Reconnaissance")

    def test_stage_path_orders_timeline(self):
        a1 = make(10)                                   # recon
        a2 = make(20, category="rules.content.match")   # weaponization
        a3 = make(30, category="dns.id_mismatch", module="canary")  # delivery
        incs = correlate([a3, a2, a1], window_s=60)
        self.assertEqual(incs[0].stage_path[:3], ["Reconnaissance", "Weaponization", "Delivery"])
        self.assertEqual(incs[0].stage, "Delivery")

    def test_advanced_stage_estimate(self):
        incs = correlate([make(10, category="socket.beacon", module="kernel")])
        self.assertEqual(incs[0].stage, "Command and Control")

    def test_actions_stage_rst(self):
        incs = correlate([make(10, category="tcp.rst_flood", module="canary")])
        self.assertEqual(incs[0].stage, "Actions on Objectives")

    def test_timeline_sorted_ascending(self):
        a = [make(30), make(10), make(20)]
        incs = correlate(a)
        tl = incident_timeline(incs[0])
        ts = [x["ts"] for x in tl]
        self.assertEqual(ts, sorted(ts))

    def test_empty_input(self):
        self.assertEqual(correlate([]), [])

    def test_stage_index_within_bounds(self):
        for idx in range(len(KILL_CHAIN)):
            a = make(0, category="proc.known_bad", module="kernel")
            self.assertLess(stage_index(a), len(KILL_CHAIN))

    def test_estimate_stage_empty(self):
        self.assertEqual(estimate_stage([]), "")

    def test_stage_path_unique_progression(self):
        a1 = make(10)
        a2 = make(20, category="dns.id_mismatch", module="canary")
        path = stage_path_of([a1, a2])
        self.assertEqual(path, ["Reconnaissance", "Delivery"])

    def test_mldetect_exploitation_stage(self):
        incs = correlate([make(5, category="anomaly.flow", module="mldetect")])
        self.assertEqual(incs[0].stage, "Exploitation")

    def test_installation_stage_kernel_proc(self):
        incs = correlate([make(50, category="proc.known_bad", module="kernel")])
        self.assertEqual(incs[0].stage, "Installation")


if __name__ == "__main__":
    unittest.main()