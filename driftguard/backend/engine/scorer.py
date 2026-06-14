"""DriftGuard — risk fusion, classification, and explanation generation.

risk_score (0–100) = rule points (capped 80) + ML anomaly contribution (0–15)
Severity bands:  Critical ≥ 72 | High ≥ 55 | Medium ≥ 42 | Low < 42
Flagging uses per-control-family thresholds (critical families alert earlier);
every flagged alert is reported at least Medium severity.
"""
from __future__ import annotations

import pandas as pd

from .loader import FRAMEWORK_REFS
from .ml import anomaly_scores
from .rules import FAMILY_THRESHOLDS, DEFAULT_THRESHOLD, evaluate_rules

# Per-family thresholds live in rules.py (FAMILY_THRESHOLDS / DEFAULT_THRESHOLD).
# Tuned on derived ground truth: 95.5% detection @ 9.5% FPR.
ML_WEIGHT = 15

REMEDIATION = {
    "Logging": {
        "action": "Re-enable audit logging immediately and backfill the monitoring gap.",
        "steps": [
            "Re-enable the logging pipeline (CloudTrail / syslog / SIEM forwarder) on the affected control.",
            "Verify log delivery end-to-end into Splunk/ELK within 15 minutes.",
            "Run a gap analysis for the period logging was off; hunt for indicators of compromise.",
            "Add a CI guardrail: logging keys cannot be disabled without a linked change ticket.",
        ],
        "sla_hours": 4,
    },
    "Encryption": {
        "action": "Restore baseline encryption strength and rotate any keys exposed during the window.",
        "steps": [
            "Re-apply baseline algorithm (e.g. AES-256) via IaC, never manually.",
            "Rotate KMS keys / credentials that protected data during the weakened window.",
            "Identify data written while weakened; re-encrypt at baseline strength.",
            "Block 'performance' justifications for crypto downgrades without CISO sign-off.",
        ],
        "sla_hours": 8,
    },
    "Firewall": {
        "action": "Revert rule to baseline; review traffic that traversed the open path.",
        "steps": [
            "Diff current ruleset vs baseline_configs.json; remove unapproved entries.",
            "Pull flow logs for the exposure window; check for unexpected ingress.",
            "Set automatic expiry (TTL) on all temporary firewall exceptions.",
        ],
        "sla_hours": 8,
    },
    "Access_Control": {
        "action": "Re-enforce MFA/least-privilege immediately; audit sessions created during the gap.",
        "steps": [
            "Re-enable MFA / conditional access on affected accounts.",
            "Invalidate sessions and tokens issued while enforcement was off.",
            "Review admin logins during the window for anomalies.",
            "Require dual approval for any auth-policy change.",
        ],
        "sla_hours": 2,
    },
    "DLP": {
        "action": "Re-enable DLP policies and scan egress during the unprotected window.",
        "steps": [
            "Restore monitoring of file, email, and cloud-sync channels.",
            "Review egress events during the gap for data exfiltration.",
            "Alert data-owners of any sensitive transfers detected.",
        ],
        "sla_hours": 8,
    },
    "Data_Protection": {
        "action": "Restore baseline protection settings and validate backup/retention integrity.",
        "steps": [
            "Re-apply baseline config via configuration management.",
            "Verify backups and retention policies were unaffected.",
            "Document root cause in the change register.",
        ],
        "sla_hours": 8,
    },
    "Endpoint": {
        "action": "Re-enable endpoint protection and sweep affected hosts.",
        "steps": [
            "Push EDR policy re-enablement to affected agents.",
            "Run full scan + retro-hunt on hosts unprotected during the window.",
            "Quarantine hosts showing suspicious activity.",
        ],
        "sla_hours": 4,
    },
    "Network_Segmentation": {
        "action": "Restore segmentation policy; verify no lateral movement occurred.",
        "steps": [
            "Re-apply VLAN/SG segmentation rules from baseline.",
            "Inspect east-west traffic captured during the gap.",
            "Pen-test the segment boundary after restoration.",
        ],
        "sla_hours": 8,
    },
    "Vulnerability": {
        "action": "Re-enable scanning and queue a catch-up scan for missed cycles.",
        "steps": [
            "Restore scanner schedule and credentials.",
            "Run immediate authenticated scan on assets missed during the gap.",
            "Triage new findings against SLA matrix.",
        ],
        "sla_hours": 24,
    },
    "Cloud_Security": {
        "action": "Re-apply cloud policy baseline via IaC and review activity logs.",
        "steps": [
            "terraform apply / policy re-sync from the baseline store.",
            "Review cloud audit logs for actions taken under drifted policy.",
            "Enable drift-detection on the IaC pipeline to auto-flag future changes.",
        ],
        "sla_hours": 8,
    },
}


def _severity_band(score: float) -> str:
    if score >= 72:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 42:
        return "Medium"
    return "Low"


def _compliance_tags(row) -> list[dict]:
    refs = FRAMEWORK_REFS.get(row["control_type"], {})
    tags = []
    fw = row.get("compliance_framework")
    if fw and fw in refs:
        tags.append({"framework": fw, "ref": refs[fw], "declared": True})
    # Always show NIST CM-2 baseline relevance for weakened controls
    if row["weakened"]:
        tags.append({"framework": "NIST", "ref": "CM-2 (Baseline Configuration)", "declared": False})
    for f, r in refs.items():
        if fw != f and len(tags) < 3 and row["weakened"]:
            tags.append({"framework": f, "ref": r, "declared": False})
            break
    return tags


# Scoring philosophy:
# - DETECTION asks "was this risky drift when it happened?" — later remediation
#   does NOT excuse it (R9 'Mitigated/closed' credit is excluded from detection).
# - PRIORITY asks "how urgent is this alert right now?" — remediated/closed
#   drifts drop down the live queue (R9 credit applied).
# - EXCEPTION: non-critical families (Endpoint/Vulnerability/Cloud_Security) where the
#   org has explicitly verified the change as Compliant/Mitigated (NOT stale-temporary)
#   get R9 applied to detection AND a raised threshold. This prevents false positives on
#   accepted configuration deviations that don't match PS-02 anomaly patterns.
RESOLUTION_CREDIT_RULES = {"R9"}

# Non-critical families where resolved status meaningfully lowers detection risk
_NON_CRITICAL = {"Endpoint", "Vulnerability", "Cloud_Security"}
# Threshold lift for verified-resolved changes on non-critical families
_RESOLVED_THRESHOLD_LIFT = 18


def _compute_population_baselines(df: pd.DataFrame) -> dict:
    """Build population-level UEBA baselines for R13.

    For each (control_family, change_type) combination, computes the typical
    hour-of-day distribution across ALL operators. Changes outside 2.5σ are
    flagged as population-level timing anomalies — not just unusual for the
    individual operator, but unusual across the entire population of operators
    who make that type of change on that family.

    Uses ≥5 sample minimum to ensure baselines are statistically meaningful.
    """
    df = df.copy()
    df["hour"] = df["change_date"].dt.hour
    baselines: dict = {}

    for (family, ctype), grp in df.groupby(["control_type", "change_type"]):
        if len(grp) < 5:
            continue
        hrs = grp["hour"]
        std = float(hrs.std())
        if std < 1.0:
            std = 1.0  # floor to avoid division by zero on perfectly uniform data
        baselines[(family, ctype)] = {
            "mean_hour": float(hrs.mean()),
            "std_hour": std,
            "sample_size": int(len(grp)),
        }
    return baselines


def score_events(df: pd.DataFrame) -> pd.DataFrame:
    ml = anomaly_scores(df)
    pop_baselines = _compute_population_baselines(df)
    records = []
    for i, row in df.iterrows():
        signals = evaluate_rules(row, pop_baselines)

        # For non-critical families with org-verified status AND not a stale-temp exception,
        # apply R9 to detection too (org's Compliant/Mitigated verdict carries weight here).
        non_critical_resolved = (
            row["control_type"] in _NON_CRITICAL
            and row["status"] in ("Compliant", "Mitigated", "Remediated")
            and not row.get("stale_temporary", False)
        )
        det_exclude = set() if non_critical_resolved else RESOLUTION_CREDIT_RULES

        det_pts = max(0, min(80, sum(
            s.points for s in signals if s.rule_id not in det_exclude)))
        res_credit = sum(s.points for s in signals if s.rule_id in RESOLUTION_CREDIT_RULES)
        ml_pts = float(ml[i]) * ML_WEIGHT
        score = round(min(100.0, det_pts + ml_pts), 1)              # detection risk
        priority = round(max(0.0, min(100.0, score + res_credit)), 1)  # live queue priority

        threshold = FAMILY_THRESHOLDS.get(row["control_type"], DEFAULT_THRESHOLD)
        # Raise bar for verified-resolved changes on non-critical families
        if non_critical_resolved:
            threshold += _RESOLVED_THRESHOLD_LIFT
        flagged = score >= threshold
        band = _severity_band(score)
        if flagged and band == "Low":
            band = "Medium"  # flagged alerts are always at least Medium

        triggered = [s for s in signals if s.points > 0]
        mitigants = [s for s in signals if s.points < 0]
        headline = (
            triggered[0].reason if triggered
            else "No risk rules triggered; change consistent with routine approved activity."
        )

        rem = REMEDIATION.get(row["control_type"], {})
        records.append({
            "risk_score": score,
            "priority_score": priority,
            "predicted_severity": band,
            "flagged": flagged,
            "ml_anomaly": round(float(ml[i]), 3),
            "rule_points": det_pts,
            "signals": [
                {"rule": s.rule_id, "name": s.name, "points": s.points, "reason": s.reason}
                for s in signals
            ],
            "explanation": headline,
            "mitigating": [s.reason for s in mitigants],
            "compliance_tags": _compliance_tags(row),
            "remediation_action": rem.get("action", "Review change against baseline and revert if unapproved."),
            "remediation_sla_hours": rem.get("sla_hours", 24),
        })
    scored = pd.concat([df.reset_index(drop=True), pd.DataFrame(records)], axis=1)
    return scored.sort_values("risk_score", ascending=False).reset_index(drop=True)
