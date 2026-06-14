"""DriftGuard — unsupervised ML layer (IsolationForest).

Learns what 'normal change behaviour' looks like across 365 days of events
and surfaces statistical outliers the rule engine may not encode.

IMPORTANT: the dataset's own `severity` column is *never* used as a model
feature — it is reserved exclusively as evaluation ground truth.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder, StandardScaler

FEATURE_CATS = ["control_type", "change_type", "change_reason", "status"]
FEATURE_NUMS = ["hour", "dow", "age_days", "exposure_days"]
FEATURE_BOOLS = ["weakened", "restored", "self_approved", "off_hours", "weekend", "stale_temporary", "unresolved", "exposure_open"]


def anomaly_scores(df: pd.DataFrame, random_state: int = 42) -> np.ndarray:
    """Return anomaly score in [0, 1] (1 = most anomalous) for each event."""
    enc = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    X_cat = enc.fit_transform(df[FEATURE_CATS])
    X_num = StandardScaler().fit_transform(df[FEATURE_NUMS].astype(float))
    X_bool = df[FEATURE_BOOLS].astype(int).to_numpy()
    X = np.hstack([X_cat, X_num, X_bool])

    iso = IsolationForest(
        n_estimators=300,
        contamination="auto",
        random_state=random_state,
        n_jobs=-1,
    )
    iso.fit(X)
    raw = -iso.score_samples(X)  # higher = more anomalous
    # min-max normalize to [0,1]
    return (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)
