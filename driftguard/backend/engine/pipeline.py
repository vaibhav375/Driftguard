"""DriftGuard — end-to-end pipeline.

CSV/JSONL in  →  normalize  →  rules + IsolationForest  →  fuse & explain
→  evaluate vs derived labels  →  emit artifacts (labels, baseline store,
alerts, summary, audit report).
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .campaigns import detect_campaigns
from .evaluate import evaluate
from .forecast import forecast_family_drift
from .labels import derive_labels
from .loader import FRAMEWORK_REFS, load_baselines, load_events
from .mitre import build_mitre_mapping
from .scorer import REMEDIATION, score_events

import os

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]  # driftguard/
# DATA_DIR: override via env var for Docker / CI deployments
_DEFAULT_DATA_DIR = ROOT.parent / "Problem_02_Config_Drift" / "sample_data"
DATA_DIR = Path(os.environ.get("DRIFTGUARD_DATA_DIR", str(_DEFAULT_DATA_DIR)))
OUT_DIR = ROOT / "backend" / "out"


def build_baseline_store(events: pd.DataFrame, rich_baselines: list[dict]) -> list[dict]:
    """Deliverable: Baseline Configuration Store — one JSON record per control."""
    store = {b["control_id"]: b for b in rich_baselines}
    first_seen = events.sort_values("change_date").groupby("control_name").first()
    for name, row in first_seen.iterrows():
        cid = f"CTL-{name.split('-')[-1]}" if "-" in name else name
        if cid in store:
            continue
        ct = row["control_type"]
        store[cid] = {
            "control_id": cid,
            "control_name": name,
            "system": ct.replace("_", " "),
            "control_type": ct,
            "baseline_config": row["baseline_state"] or {"enabled": True},
            "baseline_timestamp": "2025-04-01T00:00:00Z",
            "criticality": "high" if ct in ("Logging", "Encryption", "Access_Control", "Firewall") else "medium",
            "compliance_mappings": [
                f"{fw}: {ref}" for fw, ref in list(FRAMEWORK_REFS.get(ct, {}).items())[:3]
            ],
        }
    return list(store.values())


def run(data_dir: Path = DATA_DIR, out_dir: Path = OUT_DIR) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)

    events = load_events(data_dir / "config_drift_events.csv")
    rich_baselines = load_baselines(data_dir / "baseline_configs.json")

    labels = derive_labels(events)
    labels.to_csv(out_dir / "config_drift_labels.csv", index=False)

    scored = score_events(events).merge(labels, on="drift_event_id")
    metrics = evaluate(scored)

    baseline_store = build_baseline_store(events, rich_baselines)
    (out_dir / "baseline_store.json").write_text(json.dumps(baseline_store, indent=2, default=str))

    # Serializable event records for the API / dashboard
    cols = [
        "drift_event_id", "control_name", "control_type", "baseline_value", "current_value",
        "change_type", "severity", "operator_name", "operator_email", "approver_name",
        "change_date", "change_reason", "status", "compliance_framework", "compliance_was_dirty",
        "weakened", "restored", "off_hours", "weekend", "age_days", "stale_temporary",
        "risk_score", "priority_score", "predicted_severity", "flagged", "ml_anomaly",
        "rule_points", "signals", "explanation", "mitigating", "compliance_tags",
        "remediation_action", "remediation_sla_hours", "is_anomaly", "anomaly_type",
    ]
    rec = scored[cols].copy()
    rec["change_date"] = rec["change_date"].dt.strftime("%Y-%m-%d %H:%M:%S")
    records = rec.to_dict(orient="records")
    (out_dir / "scored_events.json").write_text(json.dumps(records, default=str))

    summary = build_summary(scored, metrics, baseline_store)
    threat_intel = build_threat_intel(scored)
    attack_intel = build_attack_intel(scored)
    (out_dir / "summary.json").write_text(json.dumps(summary, default=str))
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2, default=str))
    (out_dir / "threat_intel.json").write_text(json.dumps(threat_intel, indent=2, default=str))
    (out_dir / "attack_intel.json").write_text(json.dumps(attack_intel, indent=2, default=str))

    return {
        "summary": summary, "metrics": metrics,
        "events": records, "baselines": baseline_store,
        "threat_intel": threat_intel,
        "attack_intel": attack_intel,
    }


def build_summary(scored: pd.DataFrame, metrics: dict, baselines: list[dict]) -> dict:
    flagged = scored[scored["flagged"]]
    open_drifts = flagged[flagged["status"].isin(["Drifted", "Under_Review"])]

    # Timeline: weekly buckets of flagged vs benign
    s = scored.copy()
    s["week"] = s["change_date"].dt.to_period("W").dt.start_time.dt.strftime("%Y-%m-%d")
    timeline = []
    for wk, grp in s.groupby("week"):
        timeline.append({
            "week": wk,
            "total": int(len(grp)),
            "flagged": int(grp["flagged"].sum()),
            "critical": int((grp["predicted_severity"] == "Critical").sum()),
            "high": int((grp["predicted_severity"] == "High").sum()),
            "medium": int(((grp["predicted_severity"] == "Medium") & grp["flagged"]).sum()),
            "benign": int((~grp["flagged"]).sum()),
            "avg_risk": round(float(grp["risk_score"].mean()), 1),
        })

    # Control-type health
    health = []
    for ct, grp in s.groupby("control_type"):
        fl = grp[grp["flagged"]]
        openg = fl[fl["status"].isin(["Drifted", "Under_Review"])]
        health.append({
            "control_type": ct,
            "events": int(len(grp)),
            "flagged": int(len(fl)),
            "open": int(len(openg)),
            "critical": int((fl["predicted_severity"] == "Critical").sum()),
            "avg_risk": round(float(grp["risk_score"].mean()), 1),
            "health": round(100 - 100 * len(openg) / max(1, len(grp)), 1),
        })
    health.sort(key=lambda h: h["health"])

    # Compliance exposure among flagged drifts
    comp = {}
    for _, r in flagged.iterrows():
        for t in r["compliance_tags"]:
            fw = t["framework"]
            comp.setdefault(fw, {"framework": fw, "violations": 0, "refs": set()})
            comp[fw]["violations"] += 1
            comp[fw]["refs"].add(t["ref"])
    compliance = [
        {"framework": v["framework"], "violations": v["violations"], "refs": sorted(v["refs"])[:4]}
        for v in sorted(comp.values(), key=lambda x: -x["violations"])
    ]

    # Top risky operators
    ops = []
    for op, grp in flagged.groupby("operator_name"):
        if len(grp) >= 2:
            ops.append({
                "operator": op,
                "flagged_changes": int(len(grp)),
                "avg_risk": round(float(grp["risk_score"].mean()), 1),
            })
    ops.sort(key=lambda o: (-o["flagged_changes"], -o["avg_risk"]))

    sev_counts = flagged["predicted_severity"].value_counts().to_dict()
    return {
        "generated_at": pd.Timestamp.now().isoformat(),
        "kpis": {
            "events_total": int(len(scored)),
            "controls_tracked": len(baselines),
            "flagged_total": int(len(flagged)),
            "open_drifts": int(len(open_drifts)),
            "critical_alerts": int(sev_counts.get("Critical", 0)),
            "high_alerts": int(sev_counts.get("High", 0)),
            "medium_alerts": int(sev_counts.get("Medium", 0)),
            "detection_rate": metrics["detection_rate"],
            "false_positive_rate": metrics["false_positive_rate"],
            "precision": metrics["precision"],
            "meets_targets": metrics["meets_targets"],
            "compliance_score": round(100 * (1 - len(open_drifts) / max(1, len(scored))), 1),
            "data_quality_issues": int(scored["compliance_was_dirty"].sum()),
        },
        "timeline": timeline,
        "control_health": health,
        "compliance": compliance,
        "risky_operators": ops[:8],
        "anomaly_types": {
            k: v for k, v in metrics["per_anomaly_type"].items()
        },
    }


def build_threat_intel(scored: pd.DataFrame) -> dict:
    """Compute SOC-grade threat intelligence metrics over scored events."""
    flagged = scored[scored["flagged"]]

    # ── 1. MTTR (Mean Time to Remediate) per family ───────────────────────────
    mttr = []
    for ct, grp in flagged.groupby("control_type"):
        resolved = grp[grp["status"].isin(["Remediated", "Mitigated", "Compliant"])]
        open_ = grp[grp["status"].isin(["Drifted", "Under_Review"])]
        if len(resolved) > 0:
            # Use exposure_days (paired window) when available, else age_days proxy
            durations = resolved.apply(
                lambda r: r["exposure_days"] if r["exposure_days"] > 0 else r["age_days"], axis=1
            )
            avg_d = round(float(durations.mean()), 1)
            median_d = round(float(durations.median()), 1)
            worst_d = round(float(durations.max()), 1)
        else:
            avg_d = median_d = worst_d = 0.0
        mttr.append({
            "family": ct,
            "avg_days": avg_d,
            "median_days": median_d,
            "worst_days": worst_d,
            "open_count": int(len(open_)),
            "resolved_count": int(len(resolved)),
        })

    # ── 2. Operator risk profiles ─────────────────────────────────────────────
    op_profiles = []
    for op, grp in scored.groupby("operator_name"):
        fl = grp[grp["flagged"]]
        sa = int(grp["self_approved"].sum()) if "self_approved" in grp.columns else 0
        oh = int(grp["off_hours"].sum()) if "off_hours" in grp.columns else 0
        op_profiles.append({
            "operator": op,
            "total": int(len(grp)),
            "flagged": int(len(fl)),
            "avg_risk": round(float(grp["risk_score"].mean()), 1),
            "max_risk": round(float(grp["risk_score"].max()), 1),
            "critical": int((fl["predicted_severity"] == "Critical").sum()),
            "self_approved": sa,
            "off_hours": oh,
            "risk_ratio": round(float(len(fl) / max(1, len(grp))), 3),
        })
    op_profiles.sort(key=lambda o: (-o["avg_risk"], -o["flagged"]))

    # ── 3. Time-of-day heatmap (hour 0–23 × dow 0–6) ─────────────────────────
    tod = flagged.copy()
    tod["dow"] = tod["change_date"].dt.dayofweek
    if "hour" not in tod.columns:
        tod["hour"] = tod["change_date"].dt.hour
    tod_pivot = (
        tod.groupby(["dow", "hour"])
        .agg(count=("drift_event_id", "count"), avg_risk=("risk_score", "mean"))
        .reset_index()
    )
    heatmap_cells = [
        {
            "dow": int(r["dow"]),
            "hour": int(r["hour"]),
            "count": int(r["count"]),
            "avg_risk": round(float(r["avg_risk"]), 1),
        }
        for _, r in tod_pivot.iterrows()
    ]

    # ── 4. Drift velocity (weekly rolling 4-week detection rate) ──────────────
    s2 = scored.copy()
    s2["week"] = s2["change_date"].dt.to_period("W").dt.start_time
    weekly = (
        s2.groupby("week")
        .agg(total=("drift_event_id", "count"), flagged=("flagged", "sum"),
             avg_risk=("risk_score", "mean"))
        .reset_index()
    )
    weekly["rate"] = (weekly["flagged"] / weekly["total"].clip(1)).round(3)
    weekly["rolling"] = weekly["rate"].rolling(4, min_periods=1).mean().round(3)
    n = len(weekly)
    trend_dir = "stable"
    if n >= 8:
        early = float(weekly["rate"].iloc[:4].mean())
        late = float(weekly["rate"].iloc[-4:].mean())
        if late > early * 1.12:
            trend_dir = "worsening"
        elif late < early * 0.88:
            trend_dir = "improving"
    velocity = [
        {
            "week": r["week"].strftime("%Y-%m-%d"),
            "rate": r["rate"],
            "rolling": r["rolling"],
            "total": int(r["total"]),
            "flagged": int(r["flagged"]),
            "avg_risk": round(float(r["avg_risk"]), 1),
        }
        for _, r in weekly.iterrows()
    ]

    # ── 5. Top exposure chains ─────────────────────────────────────────────────
    exp = scored[(scored["exposure_days"] > 0) | scored["exposure_open"]].copy()
    exp = exp.sort_values("exposure_days", ascending=False).head(10)
    top_exposures = [
        {
            "id": r["drift_event_id"],
            "control": r["control_name"],
            "family": r["control_type"],
            "days": round(float(r["exposure_days"]), 1),
            "open": bool(r["exposure_open"]),
            "severity": r["predicted_severity"],
            "risk": float(r["risk_score"]),
            "reason": r["change_reason"],
        }
        for _, r in exp.iterrows()
    ]

    # ── 6. Change reason risk analysis ────────────────────────────────────────
    cr = (
        scored.groupby("change_reason")
        .agg(
            total=("drift_event_id", "count"),
            flagged=("flagged", "sum"),
            avg_risk=("risk_score", "mean"),
            critical=("predicted_severity", lambda x: (x == "Critical").sum()),
        )
        .reset_index()
    )
    change_reason = [
        {
            "reason": r["change_reason"],
            "total": int(r["total"]),
            "flagged": int(r["flagged"]),
            "avg_risk": round(float(r["avg_risk"]), 1),
            "critical": int(r["critical"]),
            "flag_rate": round(float(r["flagged"] / max(1, r["total"])), 3),
        }
        for _, r in cr.sort_values("avg_risk", ascending=False).iterrows()
    ]

    # ── 7. Compliance gap per framework ───────────────────────────────────────
    comp_gap = {}
    for _, row in flagged.iterrows():
        for tag in row["compliance_tags"]:
            fw = tag["framework"]
            if fw not in comp_gap:
                comp_gap[fw] = {"framework": fw, "open": 0, "resolved": 0, "refs": set()}
            if row["status"] in ("Drifted", "Under_Review"):
                comp_gap[fw]["open"] += 1
            else:
                comp_gap[fw]["resolved"] += 1
            comp_gap[fw]["refs"].add(tag["ref"])
    compliance_gaps = [
        {
            "framework": v["framework"],
            "open": v["open"],
            "resolved": v["resolved"],
            "total": v["open"] + v["resolved"],
            "gap_pct": round(100 * v["open"] / max(1, v["open"] + v["resolved"]), 1),
            "refs": sorted(v["refs"])[:5],
        }
        for v in sorted(comp_gap.values(), key=lambda x: -x["open"])
    ]

    return {
        "mttr": sorted(mttr, key=lambda x: -x["avg_days"]),
        "operator_profiles": op_profiles[:15],
        "heatmap_cells": heatmap_cells,
        "drift_velocity": velocity,
        "drift_trend": trend_dir,
        "top_exposures": top_exposures,
        "change_reason": change_reason,
        "compliance_gaps": compliance_gaps,
    }


def build_attack_intel(scored: pd.DataFrame) -> dict:
    """Build full attack intelligence: MITRE mapping, drift forecast, campaign detection,
    population UEBA, drift waves, and persistent hot-control identification."""
    mitre = build_mitre_mapping(scored)
    forecasts = forecast_family_drift(scored)
    campaigns = detect_campaigns(scored)

    # ── UEBA: R13 population timing anomalies ────────────────────────────────
    ueba_anomalies = []
    for _, row in scored[scored["flagged"]].iterrows():
        sigs = row.get("signals", [])
        if not isinstance(sigs, list):
            continue
        r13 = next((s for s in sigs if isinstance(s, dict) and s.get("rule") == "R13"), None)
        if r13:
            ueba_anomalies.append({
                "event_id": row["drift_event_id"],
                "operator": row["operator_name"],
                "control": row["control_name"],
                "family": row["control_type"],
                "risk": float(row["risk_score"]),
                "severity": row["predicted_severity"],
                "date": str(row["change_date"])[:16],
                "reason": r13.get("reason", ""),
            })
    ueba_anomalies.sort(key=lambda x: -x["risk"])

    # ── Drift waves: weeks where flagged rate > rolling mean + 1.2σ ──────────
    s2 = scored.copy()
    s2["week"] = s2["change_date"].dt.to_period("W").dt.start_time
    weekly = (
        s2.groupby("week")
        .agg(total=("drift_event_id", "count"), flagged=("flagged", "sum"),
             avg_risk=("risk_score", "mean"))
        .reset_index()
    )
    weekly["rate"] = (weekly["flagged"] / weekly["total"].clip(1)).round(3)
    weekly["roll_mean"] = weekly["rate"].rolling(6, min_periods=3).mean()
    weekly["roll_std"] = weekly["rate"].rolling(6, min_periods=3).std().fillna(0.04)
    weekly["z"] = (weekly["rate"] - weekly["roll_mean"]) / weekly["roll_std"].clip(0.015)
    drift_waves = [
        {
            "week": r["week"].strftime("%Y-%m-%d"),
            "rate": round(float(r["rate"]), 3),
            "baseline_rate": round(float(r["roll_mean"]), 3),
            "z_score": round(float(r["z"]), 2),
            "flagged": int(r["flagged"]),
            "total": int(r["total"]),
            "avg_risk": round(float(r["avg_risk"]), 1),
        }
        for _, r in weekly[weekly["z"] > 1.2].iterrows()
    ]
    drift_waves.sort(key=lambda x: -x["z_score"])

    # ── Persistent hot controls: flagged ≥ 2 times ───────────────────────────
    flagged = scored[scored["flagged"]].copy()
    ctrl_groups = (
        flagged.groupby("control_name")
        .agg(
            flagged_count=("drift_event_id", "count"),
            family=("control_type", "first"),
            avg_risk=("risk_score", "mean"),
            max_risk=("risk_score", "max"),
            dominant_severity=("predicted_severity", lambda x: x.value_counts().index[0]),
            open_count=("status", lambda x: (x.isin(["Drifted", "Under_Review"])).sum()),
            first_seen=("change_date", "min"),
            last_seen=("change_date", "max"),
        )
        .reset_index()
    )
    ctrl_groups["span_days"] = (
        ctrl_groups["last_seen"] - ctrl_groups["first_seen"]
    ).dt.days
    persistent = ctrl_groups[ctrl_groups["flagged_count"] >= 2].sort_values(
        ["flagged_count", "avg_risk"], ascending=False
    )
    hot_controls = [
        {
            "control": r["control_name"],
            "family": r["family"],
            "flagged_count": int(r["flagged_count"]),
            "avg_risk": round(float(r["avg_risk"]), 1),
            "max_risk": round(float(r["max_risk"]), 1),
            "severity": r["dominant_severity"],
            "open_count": int(r["open_count"]),
            "span_days": int(r["span_days"]),
            "first_seen": str(r["first_seen"])[:10],
            "last_seen": str(r["last_seen"])[:10],
        }
        for _, r in persistent.head(15).iterrows()
    ]

    return {
        "mitre": mitre,
        "forecasts": forecasts,
        "campaigns": campaigns,
        "ueba_anomalies": ueba_anomalies[:20],
        "ueba_total": len(ueba_anomalies),
        "drift_waves": drift_waves,
        "drift_waves_total": len(drift_waves),
        "hot_controls": hot_controls,
        "hot_controls_total": int(len(persistent)),
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result["metrics"], indent=2))
