"""Kernel-watch tests over /proc-like fixture trees."""
import os
import unittest

from netsentinel.config import load_config
from netsentinel.kernel import watch
from tests._base import FixtureTestCase


class TestKernelWatch(FixtureTestCase):

    def setUp(self):
        self.cfg = load_config(None)

    def test_known_bad_binary_flagged(self):
        alerts = watch(self.proc_root, self.cfg)
        bad = [a for a in alerts if a.category == "proc.known_bad"]
        comms = {a.evidence["comm"] for a in bad}
        self.assertTrue({"xmrig", "kdevtmpfsi", "cgminer"} <= comms)

    def test_tmp_binary_flagged(self):
        alerts = watch(self.proc_root, self.cfg)
        tmp = [a for a in alerts if a.category == "proc.tmp_path"]
        self.assertEqual(len(tmp), 1)
        self.assertEqual(tmp[0].evidence["comm"], "/tmp/trojan_agent")

    def test_suspicious_listening_port_flagged(self):
        alerts = watch(self.proc_root, self.cfg)
        ports = [a for a in alerts if a.category == "socket.suspicious_port"]
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0].evidence["local"][1], 31337)
        self.assertEqual(ports[0].evidence["pid"], "31337")

    def test_beacon_connection_flagged(self):
        alerts = watch(self.proc_root, self.cfg)
        beacons = [a for a in alerts if a.category == "socket.beacon"]
        self.assertEqual(len(beacons), 1)
        self.assertEqual(beacons[0].evidence["remote"], ("198.51.100.9", 4444))

    def test_tracepoints_flagged(self):
        alerts = watch(self.proc_root, self.cfg)
        cats = {a.category for a in alerts}
        self.assertIn("trace.download", cats)
        self.assertIn("trace.mutation", cats)
        self.assertIn("trace.rawsocket", cats)

    def test_clean_tree_no_alerts(self):
        alerts = watch(self.clean_proc_root, self.cfg)
        self.assertEqual(alerts, [])

    def test_missing_root_no_alerts(self):
        alerts = watch(os.path.join(self._tmp, "does_not_exist"), self.cfg)
        self.assertEqual(alerts, [])

    def test_host_identity_attributed(self):
        alerts = watch(self.proc_root, self.cfg)
        self.assertTrue(all(a.src == "192.0.2.66" for a in alerts))

    def test_bad_list_override(self):
        cfg = {"kernel": {"known_bad": ["nonexistent-unix-28690"]}}
        alerts = watch(self.proc_root, cfg)
        bad = [a for a in alerts if a.category == "proc.known_bad"]
        self.assertEqual(bad, [])

    def test_kernel_alerts_ordered_by_ts(self):
        alerts = watch(self.proc_root, self.cfg)
        ts = [a.ts for a in alerts]
        self.assertEqual(ts, sorted(ts))


if __name__ == "__main__":
    unittest.main()