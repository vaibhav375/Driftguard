"""DriftGuard — explainable heuristic rule engine.

Each rule returns (points, human-readable reason) when triggered.
Rules are the explainability backbone: every alert can cite exactly
which security principles were violated.

RULE MAP
R1  Baseline weakened          +35  core drift signal
R2  Destructive change type    +20  Disable/Remove semantics
R3  Critical control family    +15  Logging/Enc/Access/FW/NS/DLP families
R4  Self-approved change       +15  segregation-of-duties violation
R5  Suspicious timing           +8  off-hours/weekend degrading change
R6  Risky justification      +8/15  perf-tuning on crypto; temp-change risk
R7  Stale temporary            +28  never-reverted emergency change
R8  Unresolved drift state   +6/14  live Drifted or Under_Review
R10 Open exposure window       +12  weakened + still unresolved
R11 Exposure window analysis +6/10/18  paired Disable→restore; open = worst
R13 UEBA operator anomaly   +10/14  behaviour 2σ+ from operator's own baseline

R9  Mitigated/closed          -10  } mitigation credit applied to
R9b Restores baseline         -12  } PRIORITY score only, not detection
R9c Routine security update    -6  }
R12 Verified-resolved          -14  non-critical + org-verified as safe
"""
from __future__ import annotations

from dataclasses import dataclass

CRITICAL_CONTROL_TYPES = {
    "Logging", "Encryption", "Access_Control", "DLP", "Data_Protection",
    "Firewall", "Network_Segmentation",
}

# Per-family flag thresholds — tighter for families where the PS cites real breaches
FAMILY_THRESHOLDS = {
    "Logging": 38,        # disabled logging → 6-month undetected breach
    "Encryption": 38,     # AES downgrade → production data exposed
    "Access_Control": 38, # MFA off → credential abuse
    "DLP": 40,
    "Data_Protection": 38, # includes ENCRYPTION_WEAKENED pattern (lowered from 40)
    "Firewall": 40,        # firewall rule open 2 years
    "Network_Segmentation": 40,
    "Cloud_Security": 42,  # lowered from 44 to catch STALE_TEMPORARY
    "Endpoint": 44,
    "Vulnerability": 43,   # lowered from 46 to catch STALE_TEMPORARY
}
DEFAULT_THRESHOLD = 42


@dataclass
class Signal:
    rule_id: str
    name: str
    points: int
    reason: str


def evaluate_rules(row, op_baselines: dict | None = None) -> list[Signal]:  # op_baselines = population baselines keyed by (family, change_type)
    s: list[Signal] = []
    ct = row["control_type"]

    # R1 — Control weakened vs baseline (the core drift signal)
    if row["weakened"]:
        s.append(Signal(
            "R1", "Baseline weakened", 35,
            f"{ct} control was ENABLED in baseline but is now DISABLED — direct security "
            "regression from approved state.",
        ))

    # R2 — Destructive change type
    if row["change_type"] in ("Disable", "Remove"):
        s.append(Signal(
            "R2", "Destructive change", 20,
            f"Change type '{row['change_type']}' removes or switches off protection rather "
            "than tuning it.",
        ))

    # R3 — Critical control family
    if ct in CRITICAL_CONTROL_TYPES and (
        row["weakened"] or row["change_type"] in ("Disable", "Remove")
    ):
        s.append(Signal(
            "R3", "Critical control family", 15,
            f"{ct.replace('_', ' ')} is a detection/protection-critical family: weakening "
            "it can blind monitoring or expose data (cf. PS-02 breach cases: disabled logging "
            "→ 6-month undetected breach; firewall rule open 2 years).",
        ))

    # R4 — Self-approval (segregation-of-duties violation)
    if row["self_approved"]:
        s.append(Signal(
            "R4", "Self-approved change", 15,
            f"Operator {row['operator_name']} approved their own change — violates "
            "segregation of duties (NIST CM-3 change control, CIS CSC 5.1).",
        ))

    # R5 — Off-hours / weekend change (only when degrading posture)
    if (row["off_hours"] or row["weekend"]) and (
        row["weakened"] or row["change_type"] in ("Disable", "Remove", "Modify")
    ):
        when = "outside business hours" if row["off_hours"] else "on a weekend"
        s.append(Signal(
            "R5", "Suspicious timing", 8,
            f"Change executed {when} ({row['change_date']:%a %H:%M}) — pattern matches "
            "undocumented ad-hoc changes that bypass the standard change-request pipeline.",
        ))

    # R6 — Risky justification
    if row["change_reason"] == "Performance Tuning" and ct in (
        "Encryption", "Logging", "Data_Protection", "DLP"
    ):
        s.append(Signal(
            "R6", "Security traded for performance", 15,
            f"'Performance Tuning' on a {ct.replace('_', ' ')} control — classic precursor "
            "to silent downgrades (e.g. AES-256→AES-128 'for performance', Case 3 in PS-02).",
        ))
    elif row["change_reason"] in ("Emergency Fix", "Troubleshooting"):
        s.append(Signal(
            "R6", "Temporary-change risk", 8,
            f"Justified as '{row['change_reason']}' — temporary changes are the #1 source "
            "of permanent drift when not reverted (PS-02 Case 2: temp firewall rule open "
            "2 years).",
        ))

    # R7 — Stale temporary change (never reverted)
    if row["stale_temporary"]:
        s.append(Signal(
            "R7", "Temporary change became permanent", 28,
            f"'{row['change_reason']}' change is {int(row['age_days'])} days old and still "
            f"{row['status']} — the 'temporary' exception has become permanent drift "
            "(NIST CM-3: all temporary changes must have expiry dates).",
        ))

    # R8 — Unresolved drift state
    if row["status"] == "Drifted":
        s.append(Signal(
            "R8", "Unresolved drift", 14,
            "Control is currently in Drifted state — no remediation action recorded. "
            "Every day this persists increases compliance liability.",
        ))
    elif row["status"] == "Under_Review":
        s.append(Signal(
            "R8", "Pending review", 6,
            "Drift is still under review — risk exposure window remains open and "
            "SLA clock is running.",
        ))

    # R11 — Exposure window (paired Disable→restore analysis from loader)
    # This is the "logging disabled during maintenance, never re-enabled" pattern.
    # NOTE: If status is already Compliant/Mitigated, the org has verified the change
    # — "never restored" is a data artifact (restore event not in dataset), not an open
    # risk. We still fire on prolonged/extended windows to capture the duration signal.
    exp = float(row.get("exposure_days", 0))
    already_resolved = row["status"] in ("Compliant", "Mitigated")
    if row["weakened"] or row["change_type"] in ("Disable", "Remove"):
        if bool(row.get("exposure_open", False)) and not already_resolved:
            pts = 18 if ct in CRITICAL_CONTROL_TYPES else 14
            s.append(Signal(
                "R11", "Never restored — open exposure", pts,
                f"Drift detection engine found NO subsequent restoring change for this "
                f"control — it has been degraded for {int(exp)} days with no evidence of "
                "remediation (PS-02 Case 1: logging off → 6-month undetected breach).",
            ))
        elif exp > 90:
            s.append(Signal(
                "R11", "Prolonged exposure window", 10,
                f"Control stayed degraded for {int(exp)} days before being restored — "
                "far beyond any legitimate maintenance window (NIST CM-3 requires "
                "bounded temporary-change windows).",
            ))
        elif exp > 30:
            s.append(Signal(
                "R11", "Extended exposure window", 6,
                f"Control was degraded for {int(exp)} days — exceeds typical maintenance "
                "windows and warrants investigation.",
            ))

    # R10 — Weakened and never remediated (open exposure window)
    if row["weakened"] and row["unresolved"]:
        s.append(Signal(
            "R10", "Open exposure window", 12,
            f"Control remains weakened vs baseline with status '{row['status']}' — "
            f"exposure window still open after {int(row['age_days'])} days.",
        ))

    # R9 — Mitigating factors (negative points — applied to PRIORITY, not detection)
    if row["status"] in ("Remediated", "Compliant", "Mitigated"):
        s.append(Signal(
            "R9", "Mitigated/closed", -10,
            f"Status '{row['status']}' indicates the change was reverted, accepted, or "
            "compensated — reduced queue priority.",
        ))
    if row["restored"]:
        s.append(Signal(
            "R9b", "Restores baseline", -12,
            "Change moves the control back toward its approved baseline (improvement, "
            "not drift).",
        ))
    # R9c: only apply credit when the change didn't actually DISABLE or REMOVE the control.
    # A "Security Update" that disables something is still a risk signal.
    if (
        row["change_reason"] == "Security Update"
        and not row["weakened"]
        and row["change_type"] not in ("Disable", "Remove")
    ):
        s.append(Signal(
            "R9c", "Routine security update", -6,
            "Approved security-update workflow without baseline weakening or destructive "
            "action — consistent with CI/CD deployments.",
        ))

    # R12 — Verified-resolved on non-critical control (applied to DETECTION)
    # On Endpoint/Vulnerability/Cloud_Security, if the org has explicitly verified the
    # change as Compliant/Mitigated/Remediated and it was NOT a stale temporary exception,
    # reduce detection risk. (Critical families remain strict regardless of status.)
    if (
        ct not in CRITICAL_CONTROL_TYPES
        and row["status"] in ("Compliant", "Mitigated", "Remediated")
        and not row.get("stale_temporary", False)
    ):
        s.append(Signal(
            "R12", "Verified-resolved on non-critical control", -14,
            f"Control family '{ct}' is non-critical and the org has verified this change "
            f"as '{row['status']}' — detection risk reduced. "
            "(Critical families: Logging/Encryption/Access/Firewall/DLP/NS remain strict.)",
        ))

    # R13 — Population UEBA: behavioural timing anomaly
    # Fires when the change hour is > 2.5σ from the POPULATION norm for the
    # specific (control_family, change_type) combination — i.e., this isn't
    # just unusual for this operator, it's unusual for EVERYONE who makes this
    # type of change on this family. Requires weakening/destructive change.
    # Uses ≥5-sample population baselines to be statistically credible.
    if op_baselines is not None and (
        row["weakened"] or row["change_type"] in ("Disable", "Remove")
    ):
        key = (ct, row["change_type"])
        baseline = op_baselines.get(key)
        if baseline and baseline["sample_size"] >= 5:
            hour = row["change_date"].hour
            hour_z = abs(hour - baseline["mean_hour"]) / baseline["std_hour"]
            if hour_z > 2.5:
                band = "night" if hour < 6 else "after-hours" if hour > 20 else "off-peak"
                pts = 14 if hour_z > 3.5 else 10
                s.append(Signal(
                    "R13", "UEBA: Population timing anomaly", pts,
                    f"This {row['change_type']} on {ct} occurred at {hour:02d}:00 ({band}), "
                    f"which is {hour_z:.1f}σ away from the population norm "
                    f"(μ={baseline['mean_hour']:.0f}h, n={baseline['sample_size']} events). "
                    "Executing security-weakening changes at unusual hours reduces oversight "
                    "and is a classic lateral-movement cover technique "
                    "(MITRE ATT&CK T1078 — Valid Accounts / Privilege Escalation).",
                ))

    return s
