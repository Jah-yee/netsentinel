"""ML flow-anomaly detection tests."""
import unittest

from netsentinel.mldetect import (EwmaBurstDetector, FlowAnomalyDetector,
                                  _mad, _z_robust)
from netsentinel.pcap import extract, extract_flows, read_pcap
from tests._base import FixtureTestCase


class TestStats(unittest.TestCase):

    def test_mad(self):
        self.assertEqual(_mad([1, 2, 3]), 0.6666666666666666)

    def test_z_robust(self):
        z = _z_robust(100, median=10, mad=1)
        self.assertGreater(z, 10)

    def test_fit_empty_raises(self):
        det = FlowAnomalyDetector()
        with self.assertRaises(ValueError):
            det.fit([])


class TestFlowAnomalyDetector(FixtureTestCase):

    def setUp(self):
        self.base_flows = extract_flows(extract(read_pcap(self.fixtures["baseline"])))
        self.exfil_flows = extract_flows(extract(read_pcap(self.fixtures["exfil"])))

    def test_baseline_max_low(self):
        det = FlowAnomalyDetector(threshold_std=6.0).fit(self.base_flows)
        self.assertLess(det.baseline_max_score, 4.0)
        self.assertGreater(det.baseline_mean_score, 0.0)

    def test_clean_baseline_no_false_positive(self):
        det = FlowAnomalyDetector(threshold_std=6.0).fit(self.base_flows)
        rows = det.predict(self.base_flows)
        self.assertEqual([r for r in rows if r["flagged"]], [])

    def test_exfil_flow_flagged(self):
        det = FlowAnomalyDetector(threshold_std=6.0).fit(self.base_flows)
        rows = det.predict(self.exfil_flows)
        flagged = [r for r in rows if r["flagged"]]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["server_port"], 5555)
        self.assertGreater(flagged[0]["score"], det.threshold_std)

    def test_anomaly_score_gap(self):
        det = FlowAnomalyDetector(threshold_std=6.0).fit(self.base_flows)
        ex = det.predict(self.exfil_flows)[0]
        gap = ex["score"] - det.baseline_max_score
        self.assertGreater(gap, 5.0)

    def test_sklearn_fallback_pure_stdlib(self):
        det = FlowAnomalyDetector(threshold_std=6.0, use_sklearn=False).fit(self.base_flows)
        self.assertEqual(det.engine, "statistical")
        self.assertFalse(det.sklearn_available)

    def test_predict_top_n(self):
        det = FlowAnomalyDetector(threshold_std=0.0).fit(self.base_flows)
        rows = det.predict(self.exfil_flows, top_n=1)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["flagged"])

    def test_threshold_parameter_respected(self):
        det = FlowAnomalyDetector(threshold_std=6.0).fit(self.base_flows)
        high = det.predict(self.exfil_flows, threshold_std=1000.0)
        self.assertEqual([r for r in high if r["flagged"]], [])

    def test_flag_flow_returns_keys(self):
        det = FlowAnomalyDetector(threshold_std=6.0).fit(self.base_flows)
        keys = det.flag_flow(self.exfil_flows)
        self.assertEqual(len(keys), 1)

    def test_iso_score_none_without_model(self):
        det = FlowAnomalyDetector(use_sklearn=False).fit(self.base_flows)
        self.assertIsNone(det._iso_score(self.exfil_flows[0]))

    def test_all_baseline_features_present(self):
        ffs = extract_flows(extract(read_pcap(self.fixtures["baseline"])))[0]
        from netsentinel.pcap import flow_features
        feats = flow_features(ffs)
        for name in ("packets", "bytes", "avg_pkt_len", "payload_entropy", "rate_pkts"):
            self.assertIn(name, feats)

    def test_rate_burst_detected(self):
        times = [1000 + i for i in range(120)]          # steady 1/sec (bins 1000..1119)
        times += [1130 + i * 0.001 for i in range(300)]  # burst in bin 1130 (300 pkts)
        det = EwmaBurstDetector(alpha=0.2, k=6.0)
        flagged = det.detect(times, bin_seconds=1.0)
        self.assertGreaterEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["count"], 300)

    def test_rate_burst_none_on_steady(self):
        times = [1000 + i * 0.5 for i in range(400)]    # 2/sec steady
        flagged = EwmaBurstDetector(alpha=0.2, k=6.0).detect(times, bin_seconds=1.0)
        self.assertEqual(flagged, [])


if __name__ == "__main__":
    unittest.main()