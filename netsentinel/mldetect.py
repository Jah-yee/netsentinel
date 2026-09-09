"""Unsupervised flow-anomaly detection.

Primary engine: robust statistics (median + MAD scaled z-scores, EWMA rate
tracking) using stdlib only. Optional engine: sklearn IsolationForest when
available, with transparent fallback to the statistical detector so the
behaviour is deterministic in any environment.

A detector is *fit* on a normal-baseline capture, then scores any capture:
flows with a combined score above the threshold are flagged.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence

from .pcap import flow_features

FALLBACK_FEATURES = ["packets", "bytes", "avg_pkt_len", "payload_entropy", "rate_pkts"]

_MAD_SCALE = 1.4826


def _mad(values: Sequence[float]) -> float:
    median = sorted(values)[len(values) // 2]
    return sum(abs(v - median) for v in values) / len(values)


def _z_robust(x: float, median: float, mad: float) -> float:
    scale = max(mad * _MAD_SCALE, 1e-9)
    return (x - median) / scale


class FlowAnomalyDetector:
    """Robust z-score / MAD anomaly scorer over per-flow feature vectors."""

    def __init__(self, threshold_std: float = 6.0, features: Optional[List[str]] = None,
                 use_sklearn: bool = True) -> None:
        self.threshold_std = float(threshold_std)
        self.features = features or FALLBACK_FEATURES
        self.use_sklearn = use_sklearn
        self._median: Dict[str, float] = {}
        self._mad: Dict[str, float] = {}
        self._std: Dict[str, float] = {}
        self.baseline_max_score = 0.0
        self.baseline_mean_score = 0.0
        self.engine = "statistical"
        self._iso: Any = None

    @property
    def sklearn_available(self) -> bool:
        if not self.use_sklearn:
            return False
        try:
            from sklearn.ensemble import IsolationForest  # type: ignore
            return True
        except Exception:
            return False

    def fit(self, flows: List[Dict[str, Any]]) -> "FlowAnomalyDetector":
        """Learn the normal baseline (median/MAD per feature + optional forest)."""
        feats = [flow_features(f) for f in flows]
        if not feats:
            raise ValueError("cannot fit on an empty baseline")
        for name in self.features:
            col = [f[name] for f in feats]
            col_sorted = sorted(col)
            self._median[name] = col_sorted[len(col_sorted) // 2]
            self._mad[name] = _mad(col)
            mean = sum(col) / len(col)
            self._std[name] = math.sqrt(sum((v - mean) ** 2 for v in col) / len(col))
        if self.sklearn_available:
            try:
                from sklearn.ensemble import IsolationForest  # type: ignore
                X = [[f[name] for name in self.features] for f in feats]
                self._iso = IsolationForest(contamination=0.05, random_state=0)
                self._iso.fit(X)
                self.engine = "sklearn+statistical"
            except Exception:
                self._iso = None
                self.engine = "statistical"
        scores = [self.score(f)[0] for f in flows]
        self.baseline_max_score = max(scores) if scores else 0.0
        self.baseline_mean_score = sum(scores) / len(scores) if scores else 0.0
        return self

    def _stat_score(self, flow: Dict[str, Any]) -> Dict[str, float]:
        f = flow_features(flow)
        per: Dict[str, float] = {}
        for name in self.features:
            z = _z_robust(f[name], self._median.get(name, 0.0), self._mad.get(name, 0.0))
            per[name] = max(z, 0.0)
        # combine using top-2 average so one noisy feature cannot dominate alone
        top2 = sorted(per.values(), reverse=True)[:2]
        return {"score": float(sum(top2) / 2.0 if top2 else 0.0), "per_feature": per}

    def _iso_score(self, flow: Dict[str, Any]) -> Optional[float]:
        if self._iso is None:
            return None
        X = [[flow_features(flow)[name] for name in self.features]]
        try:
            raw = float(self._iso.score_samples(X)[0])
            # normalise: ~0 (normal) .. ~1 (anomalous) over [-0.5..0]
            return max(0.0, min(1.0, -raw / 0.5))
        except Exception:
            return None

    def score(self, flow: Dict[str, Any]) -> tuple:
        stat = self._stat_score(flow)
        iso = self._iso_score(flow)
        if iso is not None:
            stat["iso_forrest_score"] = iso
        return stat["score"], stat

    def predict(self, flows: List[Dict[str, Any]], threshold_std: Optional[float] = None,
                top_n: Optional[int] = None) -> List[Dict[str, Any]]:
        thr = self.threshold_std if threshold_std is None else float(threshold_std)
        rows: List[Dict[str, Any]] = []
        for flow in flows:
            score, detail = self.score(flow)
            flagged = score >= thr
            rows.append({
                "flow_key": flow.get("flow_key"),
                "client_ip": flow.get("client_ip"),
                "server_ip": flow.get("server_ip"),
                "server_port": flow.get("server_port"),
                "packets": flow["packets"],
                "bytes": flow["bytes"],
                "score": round(score, 4),
                "flagged": flagged,
                "why": [name for name, v in detail["per_feature"].items() if v > 0.0],
                "detail": {k: round(v, 3) if isinstance(v, float) else v for k, v in detail.items()},
            })
        rows.sort(key=lambda r: r["score"], reverse=True)
        if top_n is not None:
            rows = rows[:max(top_n, 0)]
        return rows

    def flag_flow(self, flows: List[Dict[str, Any]], threshold_std: Optional[float] = None) -> List[str]:
        return [
            str(r.get("flow_key") or r.get("client_ip"))
            for r in self.predict(flows, threshold_std=threshold_std)
            if r["flagged"]
        ]


class EwmaBurstDetector:
    """Exponentially-weighted moving average burst detection over rate bins.

    Bins flow counts by time; an EWMA models the normal rate; bins whose count
    exceeds `ewma + k * stdev(residuals)` are flagged as bursts.
    """

    def __init__(self, alpha: float = 0.2, k: float = 6.0) -> None:
        self.alpha = alpha
        self.k = k

    @staticmethod
    def bin_counts(times: Sequence[float], bin_seconds: float = 1.0) -> Dict[int, int]:
        counts: Dict[int, int] = {}
        for t in times:
            b = int(t / bin_seconds) if bin_seconds else 0
            counts[b] = counts.get(b, 0) + 1
        return counts

    def detect(self, times: Sequence[float], bin_seconds: float = 1.0) -> List[Dict[str, Any]]:
        counts = self.bin_counts(times, bin_seconds)
        if not counts:
            return []
        ordered = sorted(counts.items())
        counts_only = [c for _, c in ordered]
        # Pass 1: ordinary EWMA residuals so we can measure the *normal*
        # spread robustly (MAD-of-residuals) without the burst dominating it.
        ewma = float(counts_only[0])
        residuals: List[float] = []
        for c in counts_only[1:]:
            ewma = self.alpha * c + (1 - self.alpha) * ewma
            residuals.append(c - ewma)
        residuals_sorted = sorted(residuals) if residuals else [0.0]
        rmed = residuals_sorted[len(residuals_sorted) // 2]
        rmad = sum(abs(r - rmed) for r in residuals) / len(residuals) if residuals else 1e-9
        robust_std = max(rmad * 1.4826, 1e-9)
        # Pass 2: feed-forward EWMA that never learns from an outlier; flag a bin
        # when it exceeds ewma + k * robust_std (the normal-spread measure).
        flagged: List[Dict[str, Any]] = []
        ewma_v = float(counts_only[0])
        for i, (b, c) in enumerate(ordered):
            if i > 0:
                ewma_v = self.alpha * c + (1 - self.alpha) * ewma_v
            z = (c - ewma_v) / (self.k * robust_std + 1e-9)
            if c > ewma_v + self.k * robust_std:
                flagged.append({"bin": b, "count": c, "ewma": round(ewma_v, 3),
                                "z": round(z, 3), "flagged": True,
                                "robust_std": round(robust_std, 3),
                                "residual_median": round(rmed, 3)})
        return flagged

    def detect_flows(self, flows: List[Dict[str, Any]], bin_seconds: float = 1.0) -> List[Dict[str, Any]]:
        times = [f["first_ts"] for f in flows]
        return self.detect(times, bin_seconds)