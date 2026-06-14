"""DriftGuard — data loading & normalization layer.

Handles real-world data chaos:
- JSONL baseline configs (one JSON object per line)
- CSV drift events with dirty/truncated compliance values ("GD" -> "GDPR")
- Mixed boolean string formats ("enabled=True" / "enabled=False")
- Missing values
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd

# Truncated / dirty compliance values observed in the dataset -> canonical framework
COMPLIANCE_CANON = {
    "GDPR": "GDPR", "GD": "GDPR",
    "NIST": "NIST", "NI": "NIST",
    "CIS": "CIS", "CI": "CIS",
    "PCI": "PCI-DSS", "PC": "PCI-DSS",
    "ISO": "ISO 27001", "IS": "ISO 27001",
}

# Framework article/control most relevant per control_type (for explainability)
FRAMEWORK_REFS = {
    "Logging": {"NIST": "AU-2 (Audit Events)", "CIS": "CIS 8.2 (Audit Log Mgmt)", "GDPR": "Art. 30 (Records)", "PCI-DSS": "Req. 10 (Logging)", "ISO 27001": "A.12.4 (Logging)"},
    "Encryption": {"NIST": "SC-13 (Crypto Protection)", "CIS": "CIS 3.11 (Encrypt Data)", "GDPR": "Art. 32 (Security of Processing)", "PCI-DSS": "Req. 3.4 (Encrypt PAN)", "ISO 27001": "A.10 (Cryptography)"},
    "Firewall": {"NIST": "SC-7 (Boundary Protection)", "CIS": "CIS 4.4 (Firewall Mgmt)", "GDPR": "Art. 32", "PCI-DSS": "Req. 1 (Firewall Config)", "ISO 27001": "A.13.1 (Network Security)"},
    "Access_Control": {"NIST": "AC-2 / IA-2 (Account & Auth)", "CIS": "CIS 6.5 (MFA)", "GDPR": "Art. 32", "PCI-DSS": "Req. 8 (Identify & Auth)", "ISO 27001": "A.9 (Access Control)"},
    "Cloud_Security": {"NIST": "CM-2 (Baseline Config)", "CIS": "CIS Foundations", "GDPR": "Art. 28 (Processors)", "PCI-DSS": "Req. 2 (Secure Config)", "ISO 27001": "A.12 (Operations)"},
    "DLP": {"NIST": "SI-12 (Info Mgmt)", "CIS": "CIS 3.13 (DLP)", "GDPR": "Art. 25 (Data Protection by Design)", "PCI-DSS": "Req. 3", "ISO 27001": "A.13.2 (Info Transfer)"},
    "Data_Protection": {"NIST": "MP-4 (Media Protection)", "CIS": "CIS 3 (Data Protection)", "GDPR": "Art. 32", "PCI-DSS": "Req. 3", "ISO 27001": "A.8 (Asset Mgmt)"},
    "Endpoint": {"NIST": "SI-3 (Malicious Code Protection)", "CIS": "CIS 10 (Malware Defense)", "GDPR": "Art. 32", "PCI-DSS": "Req. 5 (Anti-malware)", "ISO 27001": "A.12.2 (Malware)"},
    "Network_Segmentation": {"NIST": "SC-7 (Boundary Protection)", "CIS": "CIS 12 (Network Infra)", "GDPR": "Art. 32", "PCI-DSS": "Req. 1.3 (Segmentation)", "ISO 27001": "A.13.1"},
    "Vulnerability": {"NIST": "RA-5 (Vuln Scanning)", "CIS": "CIS 7 (Vuln Mgmt)", "GDPR": "Art. 32", "PCI-DSS": "Req. 11 (Test Security)", "ISO 27001": "A.12.6 (Vuln Mgmt)"},
}


def _parse_kv(value: str) -> dict:
    """Parse 'enabled=True' style strings into a dict; tolerate junk."""
    out = {}
    if not isinstance(value, str):
        return out
    for part in re.split(r"[;,]\s*", value.strip()):
        if "=" in part:
            k, v = part.split("=", 1)
            v = v.strip()
            if v.lower() in ("true", "false"):
                v = v.lower() == "true"
            out[k.strip()] = v
    return out


def canon_compliance(raw) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return COMPLIANCE_CANON.get(raw.strip().upper(), raw.strip())


def load_baselines(path: Path) -> list[dict]:
    baselines = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                baselines.append(json.loads(line))
    return baselines


def load_events(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["change_date"] = pd.to_datetime(df["change_date"])
    df = df.sort_values("change_date").reset_index(drop=True)

    # Normalize dirty compliance values, remember raw for data-quality flagging
    df["compliance_raw"] = df["compliance_impact"]
    df["compliance_framework"] = df["compliance_impact"].apply(canon_compliance)
    df["compliance_was_dirty"] = df.apply(
        lambda r: isinstance(r["compliance_raw"], str)
        and r["compliance_raw"].strip().upper() in ("GD", "NI", "CI", "PC", "IS"),
        axis=1,
    )

    # Parse config states
    df["baseline_state"] = df["baseline_value"].apply(_parse_kv)
    df["current_state"] = df["current_value"].apply(_parse_kv)
    df["baseline_enabled"] = df["baseline_state"].apply(lambda d: d.get("enabled"))
    df["current_enabled"] = df["current_state"].apply(lambda d: d.get("enabled"))

    # Drift semantics vs baseline
    df["weakened"] = (df["baseline_enabled"] == True) & (df["current_enabled"] == False)  # noqa: E712
    df["restored"] = (df["baseline_enabled"] == False) & (df["current_enabled"] == True)  # noqa: E712
    df["matches_baseline"] = df["baseline_enabled"] == df["current_enabled"]

    # Temporal features
    df["hour"] = df["change_date"].dt.hour
    df["dow"] = df["change_date"].dt.dayofweek
    df["off_hours"] = (df["hour"] < 6) | (df["hour"] >= 22)
    df["weekend"] = df["dow"] >= 5

    # Governance features
    df["self_approved"] = (
        df["operator_email"].str.lower().str.strip()
        == df["approver_email"].str.lower().str.strip()
    )
    df["unresolved"] = df["status"].isin(["Drifted", "Under_Review"])

    # Age of unresolved "temporary" changes (vs dataset end = "now")
    now = df["change_date"].max()
    df["age_days"] = (now - df["change_date"]).dt.days
    df["stale_temporary"] = (
        df["change_reason"].isin(["Emergency Fix", "Troubleshooting"])
        & df["unresolved"]
        & (df["age_days"] > 30)
    )

    df = _pair_exposure_windows(df, now)
    return df


def _pair_exposure_windows(df: pd.DataFrame, now: pd.Timestamp) -> pd.DataFrame:
    """Pair each weakening/destructive change with the next restoring change on
    the SAME control, yielding the true exposure window — the 'logging disabled
    during maintenance and never re-enabled' pattern from the problem statement.

    exposure_days  — days the control stayed degraded (until restore, or until
                     'now' if never restored)
    exposure_open  — True if no restoring change ever followed
    """
    df = df.sort_values("change_date").reset_index(drop=True)
    df["exposure_days"] = 0.0
    df["exposure_open"] = False

    for _, idx in df.groupby("control_name").groups.items():
        events = df.loc[idx].sort_values("change_date")
        for i, (eidx, ev) in enumerate(events.iterrows()):
            degrading = bool(ev["weakened"]) or ev["change_type"] in ("Disable", "Remove")
            if not degrading:
                continue
            restore_date = None
            for _, later in events.iloc[i + 1:].iterrows():
                restores = bool(later["restored"]) or (
                    later["change_type"] in ("Enable", "Rollback")
                    and later["current_enabled"] is True
                )
                if restores:
                    restore_date = later["change_date"]
                    break
            if restore_date is None:
                df.at[eidx, "exposure_days"] = float((now - ev["change_date"]).days)
                df.at[eidx, "exposure_open"] = True
            else:
                df.at[eidx, "exposure_days"] = float((restore_date - ev["change_date"]).days)
    return df
