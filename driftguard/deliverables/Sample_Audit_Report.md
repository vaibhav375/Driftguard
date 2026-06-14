# DriftGuard — Security Configuration Drift Audit Report
*Generated 2026-06-12 19:15 · Engine v1.0 · Dataset: config_drift_events.csv (1,000 events / 365 days)*

## Executive Summary

DriftGuard analysed **1000 configuration changes** across 10 security control families. **422 events were flagged as risky drift** (detection rate **86%**, false-positive rate **13%** against derived ground truth — both inside PS-02 targets).

Of the flagged drifts, **220 remain unresolved** and constitute the current exposure surface. The dominant patterns are boundary/access weakening, encryption/data-protection downgrades, and 'temporary' emergency changes that were never reverted — the exact failure modes behind the real incidents cited in the problem statement.

## Detection Performance

| Metric | Target | Achieved |
|---|---|---|
| Detection rate | > 80% | **85.8%** |
| False-positive rate | < 15% | **13.0%** |
| Precision | — | 81.5% |
| F1 | — | 0.84 |

## Top 12 Detected Drifts

### 1. [DRF00668] Control-97 — Data Protection

**Risk 93/100 (Critical)** · 02 Aug 2025 04:22 · status: Under_Review · operator: Elena Chen (approver: Stephen Muller)

- **Change:** `enabled=True` → `enabled=False` (Disable, reason: Emergency Fix)
- **Why flagged:** Data_Protection control was ENABLED in baseline but is now DISABLED — direct security regression from approved state.
- **Signals:** Baseline weakened; Destructive change; Critical control family; Suspicious timing; Temporary-change risk; Temporary change became permanent; Pending review; Open exposure window
- **Compliance impact:** NIST CM-2 (Baseline Configuration), NIST MP-4 (Media Protection)
- **Remediation:** Restore baseline protection settings and validate backup/retention integrity. *(SLA: 8h)*

### 2. [DRF00908] Control-1 — Access Control

**Risk 93/100 (Critical)** · 16 Nov 2025 04:58 · status: Drifted · operator: Anjali Muller (approver: Larry Quinn)

- **Change:** `enabled=True` → `enabled=False` (Disable, reason: Troubleshooting)
- **Why flagged:** Access_Control control was ENABLED in baseline but is now DISABLED — direct security regression from approved state.
- **Signals:** Baseline weakened; Destructive change; Critical control family; Suspicious timing; Temporary-change risk; Temporary change became permanent; Unresolved drift; Open exposure window
- **Compliance impact:** PCI-DSS Req. 8 (Identify & Auth), NIST CM-2 (Baseline Configuration), NIST AC-2 / IA-2 (Account & Auth)
- **Remediation:** Re-enforce MFA/least-privilege immediately; audit sessions created during the gap. *(SLA: 2h)*

### 3. [DRF00723] Control-80 — Access Control

**Risk 93/100 (Critical)** · 27 Jun 2025 01:11 · status: Under_Review · operator: Steven Jones (approver: Anjali Miller)

- **Change:** `enabled=True` → `enabled=False` (Remove, reason: Troubleshooting)
- **Why flagged:** Access_Control control was ENABLED in baseline but is now DISABLED — direct security regression from approved state.
- **Signals:** Baseline weakened; Destructive change; Critical control family; Suspicious timing; Temporary-change risk; Temporary change became permanent; Pending review; Open exposure window
- **Compliance impact:** NIST CM-2 (Baseline Configuration), NIST AC-2 / IA-2 (Account & Auth)
- **Remediation:** Re-enforce MFA/least-privilege immediately; audit sessions created during the gap. *(SLA: 2h)*

### 4. [DRF00972] Control-80 — Firewall

**Risk 93/100 (Critical)** · 18 Jul 2025 05:24 · status: Under_Review · operator: Neha Lewis (approver: Jeffrey Ghosh)

- **Change:** `enabled=True` → `enabled=False` (Update, reason: Emergency Fix)
- **Why flagged:** Firewall control was ENABLED in baseline but is now DISABLED — direct security regression from approved state.
- **Signals:** Baseline weakened; Critical control family; Suspicious timing; Temporary-change risk; Temporary change became permanent; Pending review; Open exposure window
- **Compliance impact:** NIST CM-2 (Baseline Configuration), NIST SC-7 (Boundary Protection)
- **Remediation:** Revert rule to baseline; review traffic that traversed the open path. *(SLA: 8h)*

### 5. [DRF00708] Control-57 — Data Protection

**Risk 92/100 (Critical)** · 23 Jun 2025 04:02 · status: Under_Review · operator: Arjun Becker (approver: Leila Gupta)

- **Change:** `enabled=True` → `enabled=False` (Update, reason: Troubleshooting)
- **Why flagged:** Data_Protection control was ENABLED in baseline but is now DISABLED — direct security regression from approved state.
- **Signals:** Baseline weakened; Critical control family; Suspicious timing; Temporary-change risk; Temporary change became permanent; Pending review; Open exposure window
- **Compliance impact:** ISO 27001 A.8 (Asset Mgmt), NIST CM-2 (Baseline Configuration), NIST MP-4 (Media Protection)
- **Remediation:** Restore baseline protection settings and validate backup/retention integrity. *(SLA: 8h)*

### 6. [DRF00684] Control-82 — Endpoint

**Risk 92/100 (Critical)** · 21 Apr 2025 20:29 · status: Under_Review · operator: Meera Wagner (approver: Larry Williams)

- **Change:** `enabled=True` → `enabled=False` (Disable, reason: Troubleshooting)
- **Why flagged:** Endpoint control was ENABLED in baseline but is now DISABLED — direct security regression from approved state.
- **Signals:** Baseline weakened; Destructive change; Temporary-change risk; Temporary change became permanent; Pending review; Open exposure window
- **Compliance impact:** GDPR Art. 32, NIST CM-2 (Baseline Configuration), NIST SI-3 (Malicious Code Protection)
- **Remediation:** Re-enable endpoint protection and sweep affected hosts. *(SLA: 4h)*

### 7. [DRF00858] Control-69 — Vulnerability

**Risk 92/100 (Critical)** · 08 Jan 2026 23:47 · status: Drifted · operator: Aditya Thompson (approver: Pooja Jackson)

- **Change:** `enabled=True` → `enabled=False` (Rollback, reason: Emergency Fix)
- **Why flagged:** Vulnerability control was ENABLED in baseline but is now DISABLED — direct security regression from approved state.
- **Signals:** Baseline weakened; Suspicious timing; Temporary-change risk; Temporary change became permanent; Unresolved drift; Open exposure window
- **Compliance impact:** GDPR Art. 32, NIST CM-2 (Baseline Configuration), NIST RA-5 (Vuln Scanning)
- **Remediation:** Re-enable scanning and queue a catch-up scan for missed cycles. *(SLA: 24h)*

### 8. [DRF00886] Control-48 — Data Protection

**Risk 92/100 (Critical)** · 27 Jul 2025 12:22 · status: Under_Review · operator: Jason Reilly (approver: Richard Sun)

- **Change:** `enabled=True` → `enabled=False` (Enable, reason: Emergency Fix)
- **Why flagged:** Data_Protection control was ENABLED in baseline but is now DISABLED — direct security regression from approved state.
- **Signals:** Baseline weakened; Critical control family; Suspicious timing; Temporary-change risk; Temporary change became permanent; Pending review; Open exposure window
- **Compliance impact:** NIST CM-2 (Baseline Configuration), NIST MP-4 (Media Protection)
- **Remediation:** Restore baseline protection settings and validate backup/retention integrity. *(SLA: 8h)*

### 9. [DRF00742] Control-38 — Data Protection

**Risk 92/100 (Critical)** · 26 Aug 2025 22:02 · status: Under_Review · operator: Harsh Martin (approver: Karan Verma)

- **Change:** `enabled=True` → `enabled=True` (Remove, reason: Emergency Fix)
- **Why flagged:** Change type 'Remove' removes or switches off protection rather than tuning it.
- **Signals:** Destructive change; Critical control family; Suspicious timing; Temporary-change risk; Temporary change became permanent; Pending review
- **Compliance impact:** —
- **Remediation:** Restore baseline protection settings and validate backup/retention integrity. *(SLA: 8h)*

### 10. [DRF00989] Control-5 — Network Segmentation

**Risk 91/100 (Critical)** · 22 Nov 2025 23:03 · status: Drifted · operator: Anthony Martinez (approver: Deepika Wang)

- **Change:** `enabled=True` → `enabled=False` (Update, reason: Security Update)
- **Why flagged:** Network_Segmentation control was ENABLED in baseline but is now DISABLED — direct security regression from approved state.
- **Signals:** Baseline weakened; Critical control family; Suspicious timing; Unresolved drift; Open exposure window
- **Compliance impact:** NIST SC-7 (Boundary Protection), NIST CM-2 (Baseline Configuration), CIS CIS 12 (Network Infra)
- **Remediation:** Restore segmentation policy; verify no lateral movement occurred. *(SLA: 8h)*

### 11. [DRF00928] Control-31 — Firewall

**Risk 91/100 (Critical)** · 30 Nov 2025 04:07 · status: Under_Review · operator: Amara Jackson (approver: Edward Weber)

- **Change:** `enabled=True` → `enabled=False` (Remove, reason: Security Update)
- **Why flagged:** Firewall control was ENABLED in baseline but is now DISABLED — direct security regression from approved state.
- **Signals:** Baseline weakened; Destructive change; Critical control family; Suspicious timing; Pending review; Open exposure window
- **Compliance impact:** CIS CIS 4.4 (Firewall Mgmt), NIST CM-2 (Baseline Configuration), NIST SC-7 (Boundary Protection)
- **Remediation:** Revert rule to baseline; review traffic that traversed the open path. *(SLA: 8h)*

### 12. [DRF00769] Control-82 — Encryption

**Risk 91/100 (Critical)** · 20 Jul 2025 09:13 · status: Drifted · operator: Timothy Menon (approver: Akshay Lewis)

- **Change:** `enabled=True` → `enabled=False` (Rollback, reason: Emergency Fix)
- **Why flagged:** Encryption control was ENABLED in baseline but is now DISABLED — direct security regression from approved state.
- **Signals:** Baseline weakened; Critical control family; Suspicious timing; Temporary-change risk; Temporary change became permanent; Unresolved drift; Open exposure window
- **Compliance impact:** PCI-DSS Req. 3.4 (Encrypt PAN), NIST CM-2 (Baseline Configuration), NIST SC-13 (Crypto Protection)
- **Remediation:** Restore baseline encryption strength and rotate any keys exposed during the window. *(SLA: 8h)*

## Remediation Playbook

Standard operating procedures per drift family. Each playbook entry lists immediate actions, verification steps, and the prevention guardrail.

### Logging

**Objective:** Re-enable audit logging immediately and backfill the monitoring gap.  
**SLA:** 4 hours

1. Re-enable the logging pipeline (CloudTrail / syslog / SIEM forwarder) on the affected control.
2. Verify log delivery end-to-end into Splunk/ELK within 15 minutes.
3. Run a gap analysis for the period logging was off; hunt for indicators of compromise.
4. Add a CI guardrail: logging keys cannot be disabled without a linked change ticket.

### Encryption

**Objective:** Restore baseline encryption strength and rotate any keys exposed during the window.  
**SLA:** 8 hours

1. Re-apply baseline algorithm (e.g. AES-256) via IaC, never manually.
2. Rotate KMS keys / credentials that protected data during the weakened window.
3. Identify data written while weakened; re-encrypt at baseline strength.
4. Block 'performance' justifications for crypto downgrades without CISO sign-off.

### Firewall

**Objective:** Revert rule to baseline; review traffic that traversed the open path.  
**SLA:** 8 hours

1. Diff current ruleset vs baseline_configs.json; remove unapproved entries.
2. Pull flow logs for the exposure window; check for unexpected ingress.
3. Set automatic expiry (TTL) on all temporary firewall exceptions.

### Access Control

**Objective:** Re-enforce MFA/least-privilege immediately; audit sessions created during the gap.  
**SLA:** 2 hours

1. Re-enable MFA / conditional access on affected accounts.
2. Invalidate sessions and tokens issued while enforcement was off.
3. Review admin logins during the window for anomalies.
4. Require dual approval for any auth-policy change.

### DLP

**Objective:** Re-enable DLP policies and scan egress during the unprotected window.  
**SLA:** 8 hours

1. Restore monitoring of file, email, and cloud-sync channels.
2. Review egress events during the gap for data exfiltration.
3. Alert data-owners of any sensitive transfers detected.

### Data Protection

**Objective:** Restore baseline protection settings and validate backup/retention integrity.  
**SLA:** 8 hours

1. Re-apply baseline config via configuration management.
2. Verify backups and retention policies were unaffected.
3. Document root cause in the change register.

### Endpoint

**Objective:** Re-enable endpoint protection and sweep affected hosts.  
**SLA:** 4 hours

1. Push EDR policy re-enablement to affected agents.
2. Run full scan + retro-hunt on hosts unprotected during the window.
3. Quarantine hosts showing suspicious activity.

### Network Segmentation

**Objective:** Restore segmentation policy; verify no lateral movement occurred.  
**SLA:** 8 hours

1. Re-apply VLAN/SG segmentation rules from baseline.
2. Inspect east-west traffic captured during the gap.
3. Pen-test the segment boundary after restoration.

### Vulnerability

**Objective:** Re-enable scanning and queue a catch-up scan for missed cycles.  
**SLA:** 24 hours

1. Restore scanner schedule and credentials.
2. Run immediate authenticated scan on assets missed during the gap.
3. Triage new findings against SLA matrix.

### Cloud Security

**Objective:** Re-apply cloud policy baseline via IaC and review activity logs.  
**SLA:** 8 hours

1. terraform apply / policy re-sync from the baseline store.
2. Review cloud audit logs for actions taken under drifted policy.
3. Enable drift-detection on the IaC pipeline to auto-flag future changes.

## Data-Quality Findings

- `compliance_impact` contained truncated values (`GD`, `NI`, `CI`, `PC`, `IS`) in 347 events — normalized to canonical frameworks during ingestion.
- 236 events had no declared compliance mapping; DriftGuard infers framework references from the control family.
- The dataset's `severity` column was found statistically independent of all other fields (uniform crosstabs) and was excluded as unreliable; ground truth was derived from the PS anomaly taxonomy.

---
*DriftGuard — PS-02 Security Control Drift & Misconfiguration Detection · Société Générale Hackathon*