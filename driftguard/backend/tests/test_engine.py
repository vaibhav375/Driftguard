"""DriftGuard — pytest suite.

Covers loader edge cases, rule engine signal correctness, scorer output,
and the PS-02 success criteria on the real dataset.

Run:  cd driftguard/backend && pytest tests/ -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DATA = Path(__file__).resolve().parents[3] / "Problem_02_Config_Drift" / "sample_data"


# ── Loader ────────────────────────────────────────────────────────────────────

def test_loader_returns_expected_columns():
    from engine.loader import load_events
    df = load_events(DATA / "config_drift_events.csv")
    required = {
        "drift_event_id", "control_type", "change_type", "change_date",
        "weakened", "restored", "off_hours", "weekend", "stale_temporary",
        "exposure_days", "exposure_open", "compliance_framework",
    }
    assert required.issubset(set(df.columns))


def test_loader_compliance_normalization():
    from engine.loader import load_events
    df = load_events(DATA / "config_drift_events.csv")
    # No truncated codes should survive normalization
    bad = {"GD", "NI", "CI", "PC", "IS"}
    assert not df["compliance_framework"].isin(bad).any()


def test_loader_weakened_semantics():
    from engine.loader import load_events
    df = load_events(DATA / "config_drift_events.csv")
    # weakened ↔ baseline True & current False
    mask_should_be_weakened = (df["baseline_enabled"] == True) & (df["current_enabled"] == False)  # noqa: E712
    assert (df["weakened"] == mask_should_be_weakened).all()


def test_loader_exposure_window_nonnegative():
    from engine.loader import load_events
    df = load_events(DATA / "config_drift_events.csv")
    assert (df["exposure_days"] >= 0).all()


def test_loader_1000_events():
    from engine.loader import load_events
    df = load_events(DATA / "config_drift_events.csv")
    assert len(df) == 1000


def test_baseline_load():
    from engine.loader import load_baselines
    bl = load_baselines(DATA / "baseline_configs.json")
    assert len(bl) >= 5
    assert all("control_id" in b for b in bl)


# ── Rules ─────────────────────────────────────────────────────────────────────

def _make_row(**kwargs):
    defaults = {
        "control_type": "Logging", "change_type": "Modify", "change_reason": "Policy Change",
        "status": "Compliant", "weakened": False, "restored": False, "off_hours": False,
        "weekend": False, "self_approved": False, "stale_temporary": False, "unresolved": False,
        "operator_name": "Alice", "age_days": 5, "exposure_days": 0.0, "exposure_open": False,
        "change_date": pd.Timestamp("2026-01-15 10:00"),
    }
    defaults.update(kwargs)
    return pd.Series(defaults)


def test_rule_r1_fires_on_weakened():
    from engine.rules import evaluate_rules
    row = _make_row(weakened=True)
    rules = {s.rule_id for s in evaluate_rules(row)}
    assert "R1" in rules


def test_rule_r1_absent_when_not_weakened():
    from engine.rules import evaluate_rules
    rules = {s.rule_id for s in evaluate_rules(_make_row(weakened=False))}
    assert "R1" not in rules


def test_rule_r2_fires_on_disable():
    from engine.rules import evaluate_rules
    rules = {s.rule_id for s in evaluate_rules(_make_row(change_type="Disable"))}
    assert "R2" in rules


def test_rule_r2_absent_on_update():
    from engine.rules import evaluate_rules
    rules = {s.rule_id for s in evaluate_rules(_make_row(change_type="Update"))}
    assert "R2" not in rules


def test_rule_r3_fires_on_critical_family():
    from engine.rules import evaluate_rules
    rules = {s.rule_id for s in evaluate_rules(_make_row(control_type="Logging", weakened=True))}
    assert "R3" in rules


def test_rule_r6_performance_on_encryption():
    from engine.rules import evaluate_rules
    signals = evaluate_rules(_make_row(
        control_type="Encryption", change_reason="Performance Tuning", weakened=True
    ))
    r6 = next((s for s in signals if s.rule_id == "R6"), None)
    assert r6 is not None
    assert r6.points == 15


def test_rule_r7_fires_on_stale_emergency():
    from engine.rules import evaluate_rules
    row = _make_row(
        stale_temporary=True, change_reason="Emergency Fix",
        status="Drifted", age_days=60
    )
    rules = {s.rule_id for s in evaluate_rules(row)}
    assert "R7" in rules


def test_rule_r9_mitigation_is_negative():
    from engine.rules import evaluate_rules
    row = _make_row(status="Remediated")
    signals = evaluate_rules(row)
    r9 = next((s for s in signals if s.rule_id == "R9"), None)
    assert r9 is not None
    assert r9.points < 0


def test_rule_r11_fires_on_open_exposure():
    from engine.rules import evaluate_rules
    row = _make_row(weakened=True, exposure_days=100.0, exposure_open=True)
    rules = {s.rule_id for s in evaluate_rules(row)}
    assert "R11" in rules


def test_rule_r11_absent_when_no_exposure():
    from engine.rules import evaluate_rules
    row = _make_row(weakened=True, exposure_days=0.0, exposure_open=False)
    rules = {s.rule_id for s in evaluate_rules(row)}
    assert "R11" not in rules


def test_benign_change_low_score():
    from engine.rules import evaluate_rules
    """An approved Security Update on a non-critical family should earn low total points."""
    row = _make_row(
        control_type="Vulnerability", change_type="Update",
        change_reason="Security Update", weakened=False,
        status="Compliant",
    )
    total = sum(s.points for s in evaluate_rules(row))
    assert total <= 5   # mitigation credit (R9c) should dominate


# ── Scorer ────────────────────────────────────────────────────────────────────

def test_scorer_columns():
    from engine.loader import load_events
    from engine.scorer import score_events
    df = load_events(DATA / "config_drift_events.csv")
    scored = score_events(df)
    for col in ["risk_score", "priority_score", "predicted_severity", "flagged", "signals", "explanation"]:
        assert col in scored.columns


def test_scorer_risk_score_bounds():
    from engine.loader import load_events
    from engine.scorer import score_events
    df = load_events(DATA / "config_drift_events.csv")
    scored = score_events(df)
    assert scored["risk_score"].between(0, 100).all()


def test_scorer_per_family_thresholds():
    """Logging (critical family) should have more flagged events per-event than Vulnerability."""
    from engine.loader import load_events
    from engine.scorer import score_events
    df = load_events(DATA / "config_drift_events.csv")
    scored = score_events(df)
    log_rate = scored[scored.control_type == "Logging"]["flagged"].mean()
    vul_rate = scored[scored.control_type == "Vulnerability"]["flagged"].mean()
    assert log_rate >= vul_rate, "Logging should flag at least as often as Vulnerability"


# ── PS-02 Success Criteria ────────────────────────────────────────────────────

def test_ps02_detection_rate():
    """Primary PS-02 target: detection rate > 80%."""
    from engine.loader import load_events
    from engine.labels import derive_labels
    from engine.scorer import score_events
    from engine.evaluate import evaluate, flag
    df = load_events(DATA / "config_drift_events.csv")
    lab = derive_labels(df)
    scored = score_events(df).merge(lab, on="drift_event_id")
    m = evaluate(scored)
    assert m["detection_rate"] > 0.80, f"Detection rate {m['detection_rate']:.3f} below 80% target"


def test_ps02_false_positive_rate():
    """Primary PS-02 target: FPR < 15%."""
    from engine.loader import load_events
    from engine.labels import derive_labels
    from engine.scorer import score_events
    from engine.evaluate import evaluate
    df = load_events(DATA / "config_drift_events.csv")
    lab = derive_labels(df)
    scored = score_events(df).merge(lab, on="drift_event_id")
    m = evaluate(scored)
    assert m["false_positive_rate"] < 0.15, f"FPR {m['false_positive_rate']:.3f} above 15% target"


def test_ps02_critical_anomalies_near_perfect():
    """Logging-disabled and encryption-weakened — the PS's headline breach patterns — should be caught."""
    from engine.loader import load_events
    from engine.labels import derive_labels
    from engine.scorer import score_events
    from engine.evaluate import evaluate
    df = load_events(DATA / "config_drift_events.csv")
    lab = derive_labels(df)
    scored = score_events(df).merge(lab, on="drift_event_id")
    m = evaluate(scored)
    # LOGGING_DISABLED: 91.7% (60 events), ENCRYPTION_WEAKENED: 99.3% — both well above 80%
    for atype in ["LOGGING_DISABLED", "ENCRYPTION_WEAKENED"]:
        rate = m["per_anomaly_type"].get(atype, {}).get("rate", 0)
        assert rate >= 0.90, f"{atype} detection rate {rate:.2f} < 90%"


def test_labels_anomaly_ratio():
    """PS-02 describes ~57% anomalous — our derived labels should be in 35–65% range."""
    from engine.loader import load_events
    from engine.labels import derive_labels
    df = load_events(DATA / "config_drift_events.csv")
    lab = derive_labels(df)
    ratio = lab["is_anomaly"].mean()
    assert 0.35 <= ratio <= 0.65, f"Anomaly ratio {ratio:.2f} outside expected range"
