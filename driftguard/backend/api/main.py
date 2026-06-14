"""DriftGuard API — FastAPI backend.

Run:  uvicorn api.main:app --reload --port 8000   (from driftguard/backend)
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import pipeline                       # noqa: E402
from engine.calibrate import fit_calibrated_model, evaluate_calibrated  # noqa: E402
from engine.evaluate import evaluate              # noqa: E402
from engine.labels import derive_labels           # noqa: E402
from engine.loader import load_events             # noqa: E402
from engine.pipeline import build_attack_intel    # noqa: E402
from engine.report import audit_report            # noqa: E402
from engine.ml import anomaly_scores                  # noqa: E402
from engine.rules import evaluate_rules               # noqa: E402
from engine.scorer import (                           # noqa: E402
    REMEDIATION, _compliance_tags, _compute_population_baselines,
    _severity_band, score_events,
)

app = FastAPI(
    title="DriftGuard API", version="2.0",
    description="Security Control Drift & Misconfiguration Detection — PS-02",
)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

STATE: dict = {}


@app.on_event("startup")
def boot():
    result = pipeline.run()
    STATE.update(result)
    STATE["events_df"] = load_events(pipeline.DATA_DIR / "config_drift_events.csv")
    lab = derive_labels(STATE["events_df"])
    scored_raw = score_events(STATE["events_df"])                    # no is_anomaly column
    scored = scored_raw.merge(lab, on="drift_event_id")              # has is_anomaly — for evaluate/report
    STATE["scored_df"] = scored

    # Fit calibrated LR model — pass unmerged scored so calibrate.py can do its own merge
    calib = fit_calibrated_model(scored_raw, lab)
    STATE["calib"] = calib
    STATE["calib_metrics"] = evaluate_calibrated(scored_raw, lab, calib)

    # Attack intelligence: MITRE mapping, drift forecast, campaign detection, UEBA
    STATE["attack_intel"] = build_attack_intel(scored)

    # Store population baselines and pre-trained ML scores for real-time ingest
    STATE["pop_baselines"] = _compute_population_baselines(scored_raw)
    STATE["ml_scores"] = anomaly_scores(STATE["events_df"])

    # Pre-sort events by change_date for stream replay
    events_sorted = sorted(
        STATE["events"],
        key=lambda e: e["change_date"],
    )
    STATE["events_sorted"] = events_sorted


# ── REST endpoints ──────────────────────────────────────────────────────────

@app.get("/api/summary")
def summary():
    return STATE["summary"]


@app.get("/api/metrics")
def metrics():
    base = STATE["metrics"]
    base["calibrated"] = STATE["calib_metrics"]
    return base


@app.get("/api/baselines")
def baselines():
    return STATE["baselines"]


@app.get("/api/alerts")
def alerts(
    severity: str | None = None,
    control_type: str | None = None,
    status: str | None = None,
    q: str | None = None,
    limit: int = 100,
):
    rows = [e for e in STATE["events"] if e["flagged"]]
    if severity:
        rows = [e for e in rows if e["predicted_severity"] == severity]
    if control_type:
        rows = [e for e in rows if e["control_type"] == control_type]
    if status == "open":
        rows = [e for e in rows if e["status"] in ("Drifted", "Under_Review")]
    elif status == "closed":
        rows = [e for e in rows if e["status"] not in ("Drifted", "Under_Review")]
    if q:
        ql = q.lower()
        rows = [e for e in rows if ql in str(e).lower()]
    rows.sort(key=lambda e: -e["priority_score"])
    return {"total": len(rows), "alerts": rows[:limit]}


@app.get("/api/events")
def events(limit: int = 1000):
    return STATE["events"][:limit]


@app.get("/api/event/{event_id}")
def event(event_id: str):
    for e in STATE["events"]:
        if e["drift_event_id"] == event_id:
            return e
    raise HTTPException(404, "event not found")


@app.get("/api/report", response_class=PlainTextResponse)
def report():
    return audit_report(STATE["scored_df"], STATE["metrics"])


@app.get("/api/playbook")
def playbook():
    return REMEDIATION


# ── WebSocket: live stream replay ────────────────────────────────────────────
# Emits 1,000 events over ~60 seconds (configurable via ?speed=).
# Each message: JSON event + running KPI snapshot.

@app.websocket("/ws/stream")
async def stream(ws: WebSocket, speed: float = 16.0):
    """Replay the 365-day event history at `speed` events/second.

    speed=16  → ~62 seconds for 1,000 events (good for a live demo).
    speed=50  → ~20 seconds (faster).
    Client can send {"cmd":"pause"} / {"cmd":"resume"} / {"cmd":"stop"}.
    """
    await ws.accept()
    events_sorted = STATE["events_sorted"]
    paused = False
    running = True

    async def recv_loop():
        nonlocal paused, running
        try:
            while running:
                msg = await asyncio.wait_for(ws.receive_text(), timeout=0.05)
                cmd = json.loads(msg).get("cmd", "")
                if cmd == "pause":
                    paused = True
                elif cmd == "resume":
                    paused = False
                elif cmd == "stop":
                    running = False
        except (asyncio.TimeoutError, WebSocketDisconnect):
            pass

    recv_task = asyncio.create_task(recv_loop())

    # Running KPI accumulators
    kpi = {"flagged": 0, "critical": 0, "high": 0, "open": 0, "total": 0}
    try:
        for ev in events_sorted:
            if not running:
                break
            while paused:
                await asyncio.sleep(0.1)
                if not running:
                    break

            kpi["total"] += 1
            if ev["flagged"]:
                kpi["flagged"] += 1
                if ev["predicted_severity"] == "Critical":
                    kpi["critical"] += 1
                elif ev["predicted_severity"] == "High":
                    kpi["high"] += 1
            if ev["status"] in ("Drifted", "Under_Review") and ev["flagged"]:
                kpi["open"] += 1

            await ws.send_json({
                "type": "event",
                "event": ev,
                "kpi": dict(kpi),
                "progress": round(kpi["total"] / len(events_sorted) * 100, 1),
            })
            await asyncio.sleep(1.0 / speed)

        await ws.send_json({"type": "done", "kpi": kpi})
    except WebSocketDisconnect:
        pass
    finally:
        recv_task.cancel()


# ── AI Insight engine (natural-language Q&A over drift data) ─────────────────

INSIGHT_PATTERNS = [
    # Logging
    (["logging", "audit", "blind", "cloudtrail", "siem"],
     lambda s: _insight_family(s, "Logging")),
    # Encryption
    (["encrypt", "aes", "crypto", "cipher", "key"],
     lambda s: _insight_family(s, "Encryption")),
    # Access / MFA
    (["access", "mfa", "auth", "admin", "credential", "identity"],
     lambda s: _insight_family(s, "Access_Control")),
    # Firewall
    (["firewall", "fw", "port", "rule", "traffic", "boundary"],
     lambda s: _insight_family(s, "Firewall")),
    # Worst / top / worst drift
    (["worst", "top", "most dangerous", "highest risk", "critical"],
     lambda s: _insight_top(s, 5)),
    # GDPR
    (["gdpr", "privacy", "data protection regulation", "article 32"],
     lambda s: _insight_compliance(s, "GDPR")),
    # NIST
    (["nist", "800-53", "sp 800"],
     lambda s: _insight_compliance(s, "NIST")),
    # PCI
    (["pci", "payment", "card", "cardholder"],
     lambda s: _insight_compliance(s, "PCI-DSS")),
    # CIS
    (["cis", "cis benchmark", "cis control"],
     lambda s: _insight_compliance(s, "CIS")),
    # Operator / who
    (["operator", "who", "user", "changed", "engineer", "responsible"],
     lambda s: _insight_operators(s)),
    # Open / unresolved
    (["open", "unresolved", "not fixed", "still drifted", "outstanding"],
     lambda s: _insight_open(s)),
    # Temporary / stale
    (["temporary", "temp", "emergency", "never reverted", "stale", "permanent"],
     lambda s: _insight_stale(s)),
    # Exposure window
    (["exposure", "window", "how long", "duration", "days"],
     lambda s: _insight_exposure(s)),
    # Summary / overview
    (["summary", "overview", "status", "posture", "health", "how are we"],
     lambda s: _insight_summary(s)),
]


def _match(q: str, keywords: list[str]) -> bool:
    ql = q.lower()
    return any(k in ql for k in keywords)


def _insight_family(scored, family: str) -> dict:
    sub = scored[(scored.control_type == family) & scored.flagged]
    open_ = sub[sub.status.isin(["Drifted", "Under_Review"])]
    worst = sub.nlargest(3, "priority_score")
    refs = {
        "Logging": "NIST AU-2 (Audit Events), CIS 8.2, GDPR Art. 30",
        "Encryption": "NIST SC-13, GDPR Art. 32, PCI-DSS Req. 3.4",
        "Access_Control": "NIST AC-2 / IA-2, CIS 6.5, PCI-DSS Req. 8",
        "Firewall": "NIST SC-7, CIS 4.4, PCI-DSS Req. 1",
        "DLP": "NIST SI-12, GDPR Art. 25, CIS 3.13",
    }.get(family, "NIST CM-2")
    return {
        "answer": (
            f"**{family.replace('_', ' ')} family health**: "
            f"{len(sub)} drift events detected, {len(open_)} currently open/unresolved. "
            f"{'⚠ This is one of the highest-risk families in the dataset.' if len(open_) > 20 else ''} "
            f"Compliance impact: {refs}."
        ),
        "top_events": _format_events(worst),
        "recommendation": REMEDIATION.get(family, {}).get("action", ""),
    }


def _insight_top(scored, n: int) -> dict:
    top = scored[scored.flagged].nlargest(n, "priority_score")
    return {
        "answer": f"**Top {n} highest-priority open drifts** (sorted by live priority score):",
        "top_events": _format_events(top),
        "recommendation": (
            "Focus remediation on Critical alerts first — each has an SLA. "
            "Open the Alert Queue tab to see the full prioritised list."
        ),
    }


def _insight_compliance(scored, framework: str) -> dict:
    hits = [
        e for e in STATE["events"]
        if e["flagged"] and any(t["framework"] == framework for t in e["compliance_tags"])
    ]
    count = len(hits)
    top = sorted(hits, key=lambda e: -e["priority_score"])[:3]
    top_df = scored[scored.drift_event_id.isin([e["drift_event_id"] for e in top])]
    return {
        "answer": (
            f"**{framework} exposure**: {count} flagged drift events have a "
            f"declared {framework} compliance impact in this dataset. "
            f"Every drift that weakens a control increases your {framework} liability — "
            "unresolved drifts are the ones regulators care about."
        ),
        "top_events": _format_events(top_df),
        "recommendation": f"Prioritise remediation of open {framework}-tagged drifts before the next audit cycle.",
    }


def _insight_operators(scored) -> dict:
    top_ops = (
        scored[scored.flagged]
        .groupby("operator_name")
        .agg(flagged=("flagged", "sum"), avg_risk=("risk_score", "mean"))
        .sort_values("flagged", ascending=False)
        .head(5)
    )
    rows = "\n".join(
        f"  • {op}: {row.flagged:.0f} risky changes, avg score {row.avg_risk:.0f}"
        for op, row in top_ops.iterrows()
    )
    return {
        "answer": (
            f"**Top operators by risky change count**:\n{rows}\n\n"
            "Note: high count ≠ malice — it may reflect role/team. "
            "Cross-reference with self-approval flags (R4) for governance concerns."
        ),
        "top_events": [],
        "recommendation": "Review operators with both high drift counts AND self-approval signals.",
    }


def _insight_open(scored) -> dict:
    open_ = scored[scored.flagged & scored.status.isin(["Drifted", "Under_Review"])]
    by_family = open_.groupby("control_type").size().sort_values(ascending=False)
    breakdown = "; ".join(f"{ct}: {n}" for ct, n in by_family.items())
    top = open_.nlargest(3, "priority_score")
    return {
        "answer": (
            f"**{len(open_)} open (unresolved) drift alerts** remain active. "
            f"By family — {breakdown}. "
            f"Each open drift is an active compliance liability and an open attack surface."
        ),
        "top_events": _format_events(top),
        "recommendation": (
            "Apply the SLA-based remediation playbook: Critical ≤ 4h, "
            "High ≤ 8h, Medium ≤ 24h. Use the Playbook tab for step-by-step instructions."
        ),
    }


def _insight_stale(scored) -> dict:
    stale = scored[scored.stale_temporary & scored.flagged]
    top = stale.nlargest(3, "exposure_days")
    return {
        "answer": (
            f"**{len(stale)} 'temporary' changes that became permanent drift** detected. "
            f"The longest exposure window is {int(stale.exposure_days.max()) if len(stale) else 0} days. "
            "This is PS-02 Case 2 (firewall rule open 2 years) — and it's happening in your dataset."
        ),
        "top_events": _format_events(top),
        "recommendation": (
            "Implement TTL (expiry dates) on all emergency/troubleshooting changes. "
            "NIST CM-3 requires bounded temporary-change windows."
        ),
    }


def _insight_exposure(scored) -> dict:
    exp = scored[(scored.exposure_open) & scored.flagged]
    avg = scored[scored.exposure_days > 0].exposure_days.mean()
    return {
        "answer": (
            f"**Exposure window analysis** (paired Disable→restore detection): "
            f"{len(exp)} controls were degraded and **never restored** "
            f"(exposure window still open). "
            f"Average exposure duration across all degraded controls: {avg:.0f} days."
        ),
        "top_events": _format_events(exp.nlargest(3, "exposure_days")),
        "recommendation": (
            "Controls with open exposure windows should be treated as P0. "
            "The 'never-restored' pattern is how the PS-02 Case 1 breach went "
            "undetected for 6 months."
        ),
    }


def _insight_summary(scored) -> dict:
    k = STATE["summary"]["kpis"]
    fam = STATE["summary"]["control_health"]
    worst = sorted(fam, key=lambda h: h["health"])[:3]
    return {
        "answer": (
            f"**Security posture summary**: "
            f"{k['events_total']:,} configuration changes analysed over 365 days. "
            f"**{k['flagged_total']} risky drifts detected** "
            f"({k['open_drifts']} open, {k['critical_alerts']} critical). "
            f"Overall compliance score: **{k['compliance_score']}%**. "
            f"Detection engine: {k['detection_rate']*100:.1f}% detection rate, "
            f"{k['false_positive_rate']*100:.1f}% false-positive rate — "
            f"{'both inside PS-02 targets ✓' if k['meets_targets'] else 'targets not fully met'}."
        ),
        "top_events": [],
        "recommendation": (
            f"Focus on the weakest families first: "
            + ", ".join(h["control_type"].replace("_", " ") for h in worst)
            + ". These have the most open unresolved drifts."
        ),
    }


def _format_events(df) -> list[dict]:
    if hasattr(df, "iterrows"):
        return [
            {
                "id": r["drift_event_id"],
                "name": r["control_name"],
                "type": r["control_type"],
                "risk": r["risk_score"],
                "severity": r["predicted_severity"],
                "reason": r["explanation"],
                "date": str(r["change_date"])[:16],
                "status": r["status"],
            }
            for _, r in df.iterrows()
        ]
    return []


@app.get("/api/threat-intel")
def threat_intel():
    """SOC-grade threat intelligence: MTTR, operator profiles, heatmap, drift velocity."""
    return STATE["threat_intel"]


@app.get("/api/attack-intel")
def attack_intel():
    """Attack intelligence: MITRE ATT&CK mapping, 30-day forecast, campaign detection, UEBA."""
    return STATE["attack_intel"]


class IngestEvent(BaseModel):
    """Real-time event ingest payload. Only the fields a security system would emit."""
    control_name: str = "Control-X"
    control_type: str = "Logging"
    change_type: str = "Disable"
    baseline_enabled: bool = True
    current_enabled: bool = False
    change_reason: str = "Troubleshooting"
    status: str = "Drifted"
    operator_name: str = "Operator"
    approver_name: str = "Approver"
    self_approved: bool = False
    hour: int | None = None          # defaults to now
    weekend: bool | None = None
    age_days: int = 0

    model_config = {"extra": "ignore"}   # tolerate extra fields from UI


@app.post("/api/ingest")
def ingest(event: IngestEvent):
    """Real-time event scoring endpoint — builds enriched row directly, no CSV roundtrip."""
    import time
    t0 = time.time()

    now = pd.Timestamp.now()
    change_dt = now - pd.Timedelta(days=event.age_days)
    if event.hour is not None:
        change_dt = change_dt.replace(hour=event.hour, minute=0, second=0, microsecond=0)

    hr = change_dt.hour
    dow = change_dt.dayofweek
    unresolved = event.status in ("Drifted", "Under_Review")
    stale = event.change_reason in ("Emergency Fix", "Troubleshooting") and unresolved and event.age_days > 30

    # Use the median ml_anomaly score from the existing dataset as a neutral baseline
    # for events we have no ML context for (avoids retraining IsolationForest per request)
    import numpy as np
    ml_scores = STATE.get("ml_scores")
    ml_neutral = float(np.median(ml_scores)) if ml_scores is not None else 0.3

    row = pd.Series({
        "drift_event_id":    f"LIVE-{int(t0 * 1000) % 100000:05d}",
        "control_name":      event.control_name,
        "control_type":      event.control_type,
        "baseline_value":    f"enabled={event.baseline_enabled}",
        "current_value":     f"enabled={event.current_enabled}",
        "change_type":       event.change_type,
        "severity":          "Medium",
        "operator_name":     event.operator_name,
        "operator_email":    f"{event.operator_name.lower().replace(' ', '.')}@company.com",
        "approver_name":     event.approver_name,
        "approver_email":    (f"{event.operator_name.lower().replace(' ', '.')}@company.com"
                              if event.self_approved
                              else f"{event.approver_name.lower().replace(' ', '.')}@company.com"),
        "change_date":       change_dt,
        "change_reason":     event.change_reason,
        "status":            event.status,
        "compliance_impact": None,
        "compliance_framework": None,
        # Derived features (mimicking load_events without needing file I/O)
        "baseline_enabled":  event.baseline_enabled,
        "current_enabled":   event.current_enabled,
        "weakened":          event.baseline_enabled and not event.current_enabled,
        "restored":          not event.baseline_enabled and event.current_enabled,
        "matches_baseline":  event.baseline_enabled == event.current_enabled,
        "hour":              hr,
        "dow":               dow,
        "off_hours":         hr < 6 or hr >= 22,
        "weekend":           event.weekend if event.weekend is not None else (dow >= 5),
        "self_approved":     event.self_approved,
        "unresolved":        unresolved,
        "age_days":          event.age_days,
        "stale_temporary":   stale,
        "exposure_days":     float(event.age_days) if (event.baseline_enabled and not event.current_enabled) else 0.0,
        "exposure_open":     (event.baseline_enabled and not event.current_enabled and unresolved),
    })

    pop_baselines = STATE.get("pop_baselines", {})
    from engine.scorer import ML_WEIGHT, FAMILY_THRESHOLDS, DEFAULT_THRESHOLD, RESOLUTION_CREDIT_RULES
    signals = evaluate_rules(row, pop_baselines)

    non_critical_resolved = (
        row["control_type"] not in FAMILY_THRESHOLDS and row.get("status") in ("Mitigated", "Remediated")
    )
    det_exclude = set() if non_critical_resolved else RESOLUTION_CREDIT_RULES
    det_pts = max(0, min(80, sum(s.points for s in signals if s.rule_id not in det_exclude)))
    res_credit = sum(s.points for s in signals if s.rule_id in RESOLUTION_CREDIT_RULES)
    score = round(min(100.0, det_pts + ml_neutral * ML_WEIGHT), 1)
    priority = round(max(0.0, min(100.0, score + res_credit)), 1)
    threshold = FAMILY_THRESHOLDS.get(row["control_type"], DEFAULT_THRESHOLD)
    flagged = score >= threshold
    band = _severity_band(score)
    if flagged and band == "Low":
        band = "Medium"

    triggered = [s for s in signals if s.points > 0]
    mitigants = [s for s in signals if s.points < 0]
    headline = (triggered[0].reason if triggered
                else "No risk rules triggered; change consistent with routine approved activity.")

    rem = REMEDIATION.get(row["control_type"], {}).get(row["change_type"], {})
    latency_ms = round((time.time() - t0) * 1000, 1)

    return {
        "event_id":              row["drift_event_id"],
        "latency_ms":            latency_ms,
        "risk_score":            score,
        "priority_score":        priority,
        "predicted_severity":    band,
        "flagged":               flagged,
        "explanation":           headline,
        "signals":               [{"rule": s.rule_id, "name": s.name, "points": s.points, "reason": s.reason} for s in signals],
        "mitigating":            [s.reason for s in mitigants],
        "compliance_tags":       _compliance_tags(row),
        "remediation_action":    rem.get("action", "Review change against baseline and revert if unapproved."),
        "remediation_sla_hours": rem.get("sla_hours", 24),
        "ml_anomaly":            round(ml_neutral, 3),
        "message":               f"Event scored in {latency_ms} ms — real-time detection pipeline.",
    }


@app.get("/api/export")
def export_alerts():
    """Download all flagged events as CSV."""
    import csv, io
    scored = STATE["scored_df"]
    flagged = scored[scored["flagged"]].sort_values("priority_score", ascending=False)
    buf = io.StringIO()
    cols = [
        "drift_event_id", "control_name", "control_type", "change_type",
        "change_date", "operator_name", "change_reason", "status",
        "risk_score", "priority_score", "predicted_severity",
        "ml_anomaly", "rule_points", "explanation",
    ]
    writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for _, row in flagged.iterrows():
        writer.writerow({c: row[c] for c in cols})
    from fastapi.responses import StreamingResponse
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=driftguard_alerts.csv"},
    )


@app.get("/api/ask")
def ask(q: str = "summary"):
    """Natural-language Q&A over the drift dataset."""
    scored = STATE["scored_df"]
    for keywords, fn in INSIGHT_PATTERNS:
        if _match(q, keywords):
            return fn(scored)
    # Default: treat as summary
    return _insight_summary(scored)


# ── Simulate ─────────────────────────────────────────────────────────────────

class SimulatedChange(BaseModel):
    control_type: str = "Logging"
    control_name: str = "Control-X"
    change_type: str = "Disable"
    baseline_enabled: bool = True
    current_enabled: bool = False
    change_reason: str = "Troubleshooting"
    status: str = "Drifted"
    hour: int = 3
    weekend: bool = False
    operator_name: str = "Demo Operator"
    approver_name: str = "Demo Approver"
    self_approved: bool = False
    age_days: int = 45


@app.post("/api/simulate")
def simulate(c: SimulatedChange):
    df = STATE["events_df"]
    row = {
        "drift_event_id": "SIM-0001",
        "control_name": c.control_name,
        "control_type": c.control_type,
        "baseline_value": f"enabled={c.baseline_enabled}",
        "current_value": f"enabled={c.current_enabled}",
        "change_type": c.change_type,
        "severity": "Medium",
        "operator_name": c.operator_name,
        "operator_email": "demo.op@company.com",
        "approver_name": c.approver_name,
        "approver_email": "demo.op@company.com" if c.self_approved else "demo.appr@company.com",
        "change_date": df["change_date"].max() - pd.Timedelta(days=c.age_days),
        "change_reason": c.change_reason,
        "status": c.status,
        "compliance_impact": None,
    }
    raw = pd.concat([df[list(row.keys())], pd.DataFrame([row])], ignore_index=True)
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        raw.to_csv(f.name, index=False)
        tmp_path = f.name
    enriched = load_events(Path(tmp_path))
    os.unlink(tmp_path)
    scored = score_events(enriched)
    rec = scored[scored["drift_event_id"] == "SIM-0001"].iloc[0]
    return {
        "risk_score": float(rec["risk_score"]),
        "severity": rec["predicted_severity"],
        "flagged": bool(rec["flagged"]),
        "explanation": rec["explanation"],
        "signals": rec["signals"],
        "mitigating": rec["mitigating"],
        "compliance_tags": rec["compliance_tags"],
        "remediation_action": rec["remediation_action"],
        "remediation_sla_hours": int(rec["remediation_sla_hours"]),
        "exposure_days": float(rec.get("exposure_days", 0)),
    }


# ── Frontend ──────────────────────────────────────────────────────────────────

DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/")
    def index():
        return FileResponse(DIST / "index.html")
