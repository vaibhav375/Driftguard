"""DriftGuard — ground-truth label derivation.

WHY THIS EXISTS
---------------
The problem statement describes a `config_drift_labels.csv` (is_anomaly,
anomaly_type, severity, explanation; ~57% anomalous). The provided sample_data
folder does not include it, and statistical analysis shows the events file's
`severity` column is independent of every other field (uniform crosstabs) —
i.e. it carries no learnable signal and cannot serve as ground truth.

We therefore derive labels from the PS's own anomaly taxonomy, applied
semantically to each event. The derivation is deterministic, documented,
and reproducible — exactly how a security team would bootstrap ground truth
from policy when no labelled history exists.

Anomaly taxonomy (from the problem statement):
  LOGGING_DISABLED      — audit/monitoring controls switched off
  ENCRYPTION_WEAKENED   — crypto/data-protection (incl. DLP) disabled or downgraded
  ACCESS_BROADENED      — authentication / boundary controls weakened
  UNAPPROVED_CHANGE     — segregation-of-duties violation (self-approval)
  STALE_TEMPORARY       — 'temporary' emergency change never reverted
  PROTECTION_DISABLED   — other protection family weakened vs baseline
"""
from __future__ import annotations

import pandas as pd

GT_SEVERITY = {
    "LOGGING_DISABLED": "Critical",
    "ENCRYPTION_WEAKENED": "Critical",
    "ACCESS_BROADENED": "High",
    "UNAPPROVED_CHANGE": "High",
    "STALE_TEMPORARY": "Medium",
    "PROTECTION_DISABLED": "High",
}


def derive_labels(df: pd.DataFrame) -> pd.DataFrame:
    labels = []
    for _, r in df.iterrows():
        destructive = r["change_type"] in ("Disable", "Remove")
        weak_or_destr = bool(r["weakened"]) or destructive
        atype = None

        if r["control_type"] == "Logging" and weak_or_destr:
            atype = "LOGGING_DISABLED"
        elif r["control_type"] in ("Encryption", "Data_Protection", "DLP") and weak_or_destr:
            atype = "ENCRYPTION_WEAKENED"
        elif r["control_type"] in ("Access_Control", "Firewall", "Network_Segmentation") and weak_or_destr:
            atype = "ACCESS_BROADENED"
        elif r["self_approved"]:
            atype = "UNAPPROVED_CHANGE"
        elif r["stale_temporary"]:
            atype = "STALE_TEMPORARY"
        elif r["weakened"] and r["unresolved"]:
            atype = "PROTECTION_DISABLED"

        if atype:
            labels.append({
                "drift_event_id": r["drift_event_id"],
                "is_anomaly": True,
                "anomaly_type": atype,
                "gt_severity": GT_SEVERITY[atype],
                "gt_explanation": _explain(atype, r),
            })
        else:
            labels.append({
                "drift_event_id": r["drift_event_id"],
                "is_anomaly": False,
                "anomaly_type": "BENIGN",
                "gt_severity": "None",
                "gt_explanation": "Routine approved change consistent with baseline.",
            })
    return pd.DataFrame(labels)


def _explain(atype: str, r) -> str:
    m = {
        "LOGGING_DISABLED": f"Audit logging weakened on {r['control_name']} — monitoring blind spot.",
        "ENCRYPTION_WEAKENED": f"Data protection weakened on {r['control_name']} — exposure risk.",
        "ACCESS_BROADENED": f"Boundary/auth control weakened on {r['control_name']} — attack surface increased.",
        "UNAPPROVED_CHANGE": f"{r['operator_name']} approved their own change — governance violation.",
        "STALE_TEMPORARY": f"'{r['change_reason']}' change unresolved for {r['age_days']} days.",
        "PROTECTION_DISABLED": f"{r['control_type']} control disabled vs baseline and unresolved.",
    }
    return m[atype]
