"""DriftGuard — self-evaluation against derived ground-truth labels."""
from __future__ import annotations

import pandas as pd

from .rules import CRITICAL_CONTROL_TYPES, FAMILY_THRESHOLDS, DEFAULT_THRESHOLD


def flag(row) -> bool:
    thr = FAMILY_THRESHOLDS.get(row["control_type"], DEFAULT_THRESHOLD)
    return float(row["risk_score"]) >= thr


def evaluate(scored: pd.DataFrame) -> dict:
    """`scored` must already be merged with derived labels (is_anomaly column)."""
    gt = scored["is_anomaly"].astype(bool)
    fl = scored.apply(flag, axis=1)

    tp = int((gt & fl).sum())
    fn = int((gt & ~fl).sum())
    fp = int((~gt & fl).sum())
    tn = int((~gt & ~fl).sum())

    detection_rate = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * detection_rate / max(1e-9, precision + detection_rate)

    per_type = {}
    for atype, grp in scored[gt].groupby("anomaly_type"):
        fl_grp = grp.apply(flag, axis=1)
        per_type[atype] = {
            "total": int(len(grp)),
            "detected": int(fl_grp.sum()),
            "rate": round(float(fl_grp.mean()), 3),
        }

    return {
        "ground_truth": "derived from PS-02 anomaly taxonomy (labels.py)",
        "events_total": int(len(scored)),
        "anomalies_total": int(gt.sum()),
        "flagged_total": int(fl.sum()),
        "detection_rate": round(detection_rate, 3),
        "false_positive_rate": round(fpr, 3),
        "precision": round(precision, 3),
        "f1": round(f1, 3),
        "targets": {"detection_rate": "> 0.80", "false_positive_rate": "< 0.15"},
        "meets_targets": bool(detection_rate > 0.80 and fpr < 0.15),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "per_anomaly_type": per_type,
    }
