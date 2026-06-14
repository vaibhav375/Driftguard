"""DriftGuard — Incident campaign detection.

Groups correlated flagged drift events into named attack campaigns by clustering
on anomaly_type × calendar month. Each campaign is mapped to a MITRE ATT&CK
technique and, where applicable, to the specific PS-02 breach case it mirrors.

Instead of showing 400+ individual alerts, DriftGuard can surface 8–12 coherent
attack campaigns — a level of abstraction that actually helps incident responders.
"""
from __future__ import annotations

import pandas as pd

# Campaign metadata keyed by PS-02 anomaly type
CAMPAIGN_TYPES: dict[str, dict] = {
    "LOGGING_DISABLED": {
        "name": "Logging Suppression",
        "mitre": "T1562.002",
        "description": (
            "Audit logging disabled across multiple controls — prevents detection "
            "of subsequent malicious activity in the same time window."
        ),
        "ps02_case": "Case 1: 6-month undetected breach via disabled logging",
        "color": "#e9293d",
    },
    "ACCESS_BROADENED": {
        "name": "Access Escalation",
        "mitre": "T1098",
        "description": (
            "Sequential access broadening or MFA disablement — consistent with "
            "privilege escalation chain building toward account takeover."
        ),
        "ps02_case": None,
        "color": "#ffb020",
    },
    "ENCRYPTION_WEAKENED": {
        "name": "Encryption Downgrade",
        "mitre": "T1600",
        "description": (
            "Encryption weakened across multiple controls in the same period — "
            "possible data staging for exfiltration or insider threat."
        ),
        "ps02_case": "Case 3: AES downgrade enabling data compromise",
        "color": "#ff4d5e",
    },
    "STALE_TEMPORARY": {
        "name": "Stealthy Persistence",
        "mitre": "T1562.001",
        "description": (
            "Multiple temporary exceptions never reverted — systematic "
            "configuration erosion creating silent, long-lived attack surface."
        ),
        "ps02_case": "Case 2: Firewall rule open 2 years via stale temp",
        "color": "#9f7bff",
    },
    "PROTECTION_DISABLED": {
        "name": "Protection Bypass",
        "mitre": "T1562.001",
        "description": (
            "Endpoint/DLP/firewall protections systematically disabled — "
            "removing layered defense coverage across the organisation."
        ),
        "ps02_case": None,
        "color": "#38c8e8",
    },
}


def detect_campaigns(scored: pd.DataFrame, min_events: int = 4) -> list[dict]:
    """Cluster flagged events into named attack campaigns.

    Groups by (anomaly_type × calendar-month). Any group with ≥ min_events
    events is promoted to a named campaign. Returns top 10 by avg risk score.
    """
    flagged = scored[scored["flagged"]].copy()

    if len(flagged) < min_events or "anomaly_type" not in flagged.columns:
        return []

    flagged["period"] = flagged["change_date"].dt.to_period("M").astype(str)

    campaigns: list[dict] = []
    camp_n = 0

    for (atype, period), grp in flagged.groupby(
        ["anomaly_type", "period"], dropna=True, sort=True
    ):
        if len(grp) < min_events or atype not in CAMPAIGN_TYPES:
            continue

        camp_n += 1
        ctype = CAMPAIGN_TYPES[str(atype)]
        start_t = grp["change_date"].min()
        end_t = grp["change_date"].max()
        duration_h = round((end_t - start_t).total_seconds() / 3600, 1)

        operators = grp["operator_name"].unique().tolist()[:4]
        families = grp["control_type"].unique().tolist()[:4]
        crit = int((grp["predicted_severity"] == "Critical").sum())
        high = int((grp["predicted_severity"] == "High").sum())
        avg_risk = round(float(grp["risk_score"].mean()), 1)
        max_risk = round(float(grp["risk_score"].max()), 1)
        self_approved = (
            int(grp["self_approved"].sum()) if "self_approved" in grp.columns else 0
        )
        off_hours = (
            int(grp["off_hours"].sum()) if "off_hours" in grp.columns else 0
        )

        campaigns.append({
            "campaign_id": f"CAMP-{camp_n:03d}",
            "anomaly_type": str(atype),
            "name": ctype["name"],
            "description": ctype["description"],
            "mitre_technique": ctype["mitre"],
            "ps02_case": ctype["ps02_case"],
            "color": ctype["color"],
            "event_count": int(len(grp)),
            "operators": operators,
            "control_families": families,
            "period": str(period),
            "start_time": start_t.strftime("%Y-%m-%d"),
            "end_time": end_t.strftime("%Y-%m-%d"),
            "duration_hours": duration_h,
            "avg_risk": avg_risk,
            "max_risk": max_risk,
            "critical_events": crit,
            "high_events": high,
            "self_approved_count": self_approved,
            "off_hours_count": off_hours,
            "severity": "Critical" if crit > 0 else "High" if high > 0 else "Medium",
        })

    # Return the 10 most severe campaigns by avg risk
    return sorted(campaigns, key=lambda c: (-c["avg_risk"], -c["event_count"]))[:10]
