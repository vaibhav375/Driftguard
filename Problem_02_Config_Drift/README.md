# Problem 02: Config Drift Detection - Sample Datasets

## Overview
Sample/mock datasets for Problem Statement 02 - detecting when security configurations drift from baseline.

## Files Included

### 1. `baseline_configs.json` (5 control baselines)
**Baseline security configurations** in JSON format (one per line).

**Each record contains:**
- `control_id` - Unique control ID
- `control_name` - Human-readable name
- `system` - Where this control is (Palo Alto, AWS, Azure, etc.)
- `baseline_config` - The "correct" configuration state (JSON object)
- `criticality` - high/medium/low
- `compliance_mappings` - Which standards it addresses

**Example Controls:**
- FW-001: Firewall allowed ports (should be 22,443,80,3306 only)
- ENC-001: Database encryption (AES-256 required)
- LOG-001: CloudTrail logging (must be enabled, multi-region)
- MFA-001: MFA enforcement (required for admins)
- DLP-001: Data Loss Prevention policies

### 2. `config_drift_events.csv` (250+ configuration changes)
**Comprehensive history of configuration changes** with details and markers across diverse controls.

**Columns:**
- `event_id` - Unique change ID
- `control_id` - Which control changed
- `timestamp` - When it changed
- `change_type` - add, modify, or delete
- `config_diff` - What specifically changed
- `change_reason` - Why it was changed
- `approved` - Was it properly approved?
- `severity_assessment` - low/medium/high/critical
- `drift_marker` - What makes it risky (for evaluation)

**Notable Drifts:**
- CFG-EV-0002: Threat prevention downgraded (security reduction)
- CFG-EV-0004: Logging disabled during maintenance & never re-enabled
- CFG-EV-0006: MFA disabled without approval (CRITICAL)
- CFG-EV-0014: Encryption disabled for testing (never restored)
- CFG-EV-0008: Audit logging disabled (compliance violation)

## How to Use

### Load in Python:
```python
import json
import pandas as pd

# Load baselines
with open('baseline_configs.json') as f:
    baselines = [json.loads(line) for line in f]
print(f"Loaded {len(baselines)} baseline controls")

# Load drift events
drifts = pd.read_csv('config_drift_events.csv')
print(f"Total drift events: {len(drifts)}")

# Show unapproved changes
print("\nUnapproved changes (HIGH RISK):")
print(drifts[drifts['approved'] == False][['control_id', 'change_reason', 'severity_assessment']])
```

### Analysis Ideas:
1. **Unapproved Changes**: Flag any config changes without proper approval
2. **Security Downgrades**: Detect when controls are weakened (e.g., encryption downgrade)
3. **Persistent Issues**: Changes that were made but never restored (logging disabled at CFG-EV-0004 but only re-enabled at CFG-EV-0005...was there a gap?)
4. **Risk Scoring**: Combine control criticality + change severity + approval status into risk score
5. **Compliance Mapping**: Link drifts to which standards they violate

## Data Characteristics

- **Controls**: 5 baseline configurations (sample)
- **Drift Events**: 15 changes over 2 months
- **Anomaly Ratio**: ~60% of changes introduce risk
- **Time Range**: Feb 15 - Apr 15, 2026
- **Systems**: Firewalls, AWS, Azure AD, Endpoint DLP, Databases

## Real-World Scale

Production would have:
- 150-300 controls tracked
- 10,000+ changes per 90 days
- Need for continuous comparison vs baselines

## Ground Truth

`drift_marker` column identifies risky patterns:
- `PORT_ADDED_UNAPPROVED` - New port without approval
- `SECURITY_DOWNGRADE` - Reduced security level
- `ENCRYPTION_WEAK` - Weaker encryption algorithm
- `LOGGING_DISABLED` - Audit logging turned off
- `MFA_DISABLED` - Multi-factor auth disabled

## Evaluation Approach

1. **Detect**: Identify configuration changes
2. **Classify**: Rate severity (low/medium/high/critical)
3. **Prioritize**: Show high-risk changes first
4. **Remediate**: Suggest restore/fix actions

## Next Steps

1. Load baseline configs
2. Compare with drift events
3. Score each drift
4. Visualize timeline
5. Generate remediation recommendations

---

See [PROBLEM_STATEMENT_02.md](../../PROBLEM_STATEMENT_02.md) for full details.
