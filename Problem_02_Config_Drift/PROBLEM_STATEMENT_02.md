#  Problem Statement 02: Security Control Drift & Misconfiguration Detection

> **Enterprise Challenge:** Security controls change constantly. 40% of breaches result from misconfigured controls, not missing ones.

---

## The Business Problem

**Scenario:** Large enterprise maintains 200+ security controls across:
- Firewalls (Palo Alto Networks, Cisco ASA)
- Endpoint Detection (CrowdStrike, Microsoft Defender)
- Cloud Security (AWS, Azure, GCP policy baselines)
- Logging & Monitoring (Splunk, ELK stacks)
- Data Protection (encryption keys, DLP policies)

**The Reality:**
-  Controls change daily (hotfixes, deployments, emergency changes)
-  No single source of truth for configurations
-  Changes often not documented ("Why was this disabled?")
-  Critical controls drift silently from baseline
-  Manual audits required quarterly (72 hours per cycle)

**Real Incidents:**
- _Case 1:_ Logging disabled during maintenance, never re-enabled → Breach went undetected for 6 months
- _Case 2:_ Firewall rule added to "temporarily" allow traffic → Still open 2 years later
- _Case 3:_ Encryption downgraded from AES-256 to AES-128 for "performance" → Left production data vulnerable

**Compliance Impact:**
- NIST SP 800-53 CM-2 (Baseline Configuration)
- GDPR Article 27 (Controls Effectiveness)
- CIS Benchmark Configuration Scoring

---

## Challenge Overview

Build a system to:
1. **Establish** baseline security configurations
2. **Monitor** real-time changes across all controls
3. **Detect** when changes introduce risk
4. **Alert** on high-impact drifts before they cause damage
5. **Track** who changed what and why

---

##  Data Reality & Edge Cases (Making it Complex)

Your solution must handle real-world infrastructure chaos:

**Configuration Complexity:**
- Configs in multiple formats (JSON, YAML, text-based CLI configs)
- Different baselines for different environments (prod vs staging)
- Legacy vs modern systems (30-year-old firewalls + new cloud infrastructure)
- Inherited changes ("Why is this firewall rule open? No one knows")
- Vendor-specific configurations (Palo Alto != Cisco != AWS)

**Ambiguity in Risk:**
- Is port 8080 open dangerous? (Depends: internal vs external, app, compliance)
- Is encryption downgrade risky? (AES-256 → AES-128: yes. AES-128 → AES-256: improvement)
- What if change request says "diagnostic access, 1 week only" but it's 6 months old?
- Temporary emergency changes that become permanent
- Changes done "during maintenance windows" but never reverted

**Temporal Challenges:**
- Configs change every day (100+ changes daily)
- Some are automated (Kubernetes auto-scaling changes security groups)
- Some are manual (engineer SSH into prod box, modifies firewall, forgets)
- CI/CD deployments change configs constantly (legitimate or drift?)
- Historical data incomplete (changes not logged 2+ years ago)

**The Challenge:**
Your LLM/solution must:
- **Distinguish benign from risky** (not just "config changed" but "is it dangerous?")
- **Handle context** (emergency bypass vs permanent vulnerability)
- **Reduce false positives** (CI/CD deployments aren't drift!)
- **Explain impact** (this drift violates NIST SC-7 and could expose internal apps)

---

##  Approach Options

### Option A: AI-Driven Drift Intelligence (Advanced)
**Best for:** ML engineers, NLP enthusiasts

**Technical Approach:**
- Parse configuration files → Extract policies programmatically
- Train ML model: "Learn what safe/unsafe configurations look like"
- Detect anomalous changes using isolation forests or autoencoders
- Use NLP to parse change request descriptions ("increased timeout for debugging" vs "reduce encryption") → Risk categorization
- Correlate with incident history ("we had a breach after this config change")
- Output: Intelligent alerts ("This change has 87% confidence of introducing vulnerability")

**Stack:** Python, scikit-learn, NLP (Hugging Face), AWS/Azure APIs, Pandas
**Complexity:**  (5/5)
**Effort:** 40-50 hours

---

### Option B: Configuration Baseline Comparison (Intermediate)
**Best for:** DevOps / Infrastructure engineers

**Technical Approach:**
- Define baseline configurations (YAML/JSON)
- Pull current configurations from all systems (APIs)
- Compare baseline vs current → Generate diffs
- Flag risky changes using heuristic rules:
  - "Logging disabled?" = HIGH RISK
  - "Encryption strength reduced?" = HIGH RISK
  - "Firewall rule broadened?" = MEDIUM RISK
- Visualize drift timeline with annotations
- Output: Control health dashboard showing drift severity

**Stack:** Python, configuration management (Terraform/Ansible), REST APIs, visualization (Plotly)
**Complexity:**  (3/5)
**Effort:** 25-35 hours

---

### Option C: Simple Compliance Checker (Beginner-Intermediate)
**Best for:** Full-stack developers, security analysts

**Technical Approach:**
- Build web app that ingests configuration CSVs
- Define "policy rules" in a simple format (JSON):
  ```json
  {
    "rule": "logging_must_be_enabled",
    "check": "control.logging == true",
    "severity": "high",
    "remediate": "Enable logging and audit trail"
  }
  ```
- Score each control: pass/fail/degrade
- Generate compliance report: "145/200 controls passing (72%)"
- Simple dashboard showing compliance by category
- Output: Excel/PDF compliance summary, recommendations

**Stack:** Python (Flask/FastAPI), HTML/CSS, basic JavaScript, CSV handling
**Complexity:**  (2/5)
**Effort:** 15-25 hours

---

## Sample Data Provided

**Files in `sample_data/`:**

| File | Records | Coverage | Description |
|------|---------|----------|-------------|
| `baseline_configs.json` | 8 controls | Baseline state | Reference baseline for each control type |
| `config_drift_events.csv` | 1,000 | Full 365 days (Apr 2025 – Apr 2026) | Who changed what, when, approved/not, risk severity |
| `config_drift_labels.csv` | 1,000 | All drift events | Ground truth: is_anomaly, anomaly_type, severity, explanation |

**Anomaly distribution in labels:**
- Anomalous drift events: ~57% (logging disabled, encryption downgrade, access broadened, unapproved changes)
- Benign changes: ~43% (approved updates, maintenance, CI/CD pipeline changes)

**Self-Evaluation:**
```python
import pandas as pd
from sklearn.metrics import classification_report

labels = pd.read_csv('config_drift_labels.csv')
# labels['predicted_anomaly'] = your_model.predict(drift_events)

print(classification_report(
    labels['is_anomaly'],
    labels['predicted_anomaly'],
    target_names=['Benign', 'Risky Drift']
))
```

**Challenge:** With 1,000 events over 365 days, CI/CD deployments, maintenance windows, and emergency fixes are all mixed in. Your solution must distinguish *authorised routine changes* from *risky security drift*.

**Sample Control Data:**
```csv
control_id,control_name,system,baseline_value,current_value,last_change,status,severity
FW-001,Firewall AllowedPorts,Palo Alto,80;443;22,80;443;22;8080,2026-04-15,DRIFTED,MEDIUM
ENC-044,Database Encryption,AWS RDS,AES-256,AES-128,2026-04-10,DRIFTED,HIGH
LOG-012,CloudTrail Enabled,AWS,true,false,2026-04-08,DRIFTED,CRITICAL
```

---

##  Success Criteria

| Metric | Target | Why |
|--------|--------|-----|
| **Detection Rate** | > 80% | Catch actual risky drifts |
| **False Positive Rate** | < 15% | Don't alert on benign changes |
| **Time Lag** | < 1 hour | Near real-time detection |
| **Explainability** | Every alert has reason | Non-security teams understand it |
| **Compliance Mapping** | Drifts → NIST/CIS/GDPR | Show regulatory impact |

---

##  Deliverables

-  **Drift Detection Engine** (code to detect & classify changes)
-  **Baseline Configuration Store** (JSON format for all 200 controls)
-  **Alert System** (alerts prioritized by risk level)
-  **Dashboard** (shows control health, drift timeline, risk hotspots)
-  **Sample Audit Report** (10-15 detected drifts with impact)
-  **Remediation Playbook** (how to fix each drift type)

---

##  Framework Alignment

**NIST SP 800-53:**
- CM-2: Baseline Configuration
- CM-3: Configuration Change Control
- SI-12: Information Management

**GDPR:**
- Article 23: Restrictions on Processor Rights
- Article 32: Security of Processing (configs must stay compliant)

**CIS Benchmarks:**
- Security Configuration Management
- Continuous Monitoring

---

##  Implementation Tips

1. **Start with one system** (e.g., firewalls) → prove the approach → expand
2. **Define baselines carefully** → wrong baseline = noisy alerts
3. **Learn normal drift patterns** → some changes are routine (deployments)
4. **Correlate with incidents** → "Did we have a breach after this change?"
5. **Make it operational** → can ops team act on alerts easily?

---

##  Expected Output Example

```
Control Drift Summary Report
=============================

Period: 2026-01-01 to 2026-04-15
Total Controls: 200
Total Changes: 10,000

HIGH RISK DRIFTS (Require Immediate Action)
- FW-001: Firewall rule broadened (3 new ports opened)
- LOG-044: CloudTrail logging disabled for 2 hours
- ENC-012: Database encryption downgraded AES-256 → AES-128

MEDIUM RISK DRIFTS (Review)
- TIMEOUT-023: Connection timeout increased 30s → 120s

COMPLIANCE IMPACT
- NIST CM-2 violations: 5
- GDPR Article 32 exposure: 2 controls
- CIS Benchmark score: 72% (up from 70%)
```

---

##  Example Walkthrough: From Raw Data to Alert

**Input: Configuration Change**
```csv
2026-04-08 02:47:00,LOG-012,modification,cloudtrail_enabled,true,false,admin_003,pending,LOGGING_DISABLED
```

**Expected Output:**
```json
{
  "drift_id": "LOG-012-20260408",
  "severity": "CRITICAL",
  "risk_score": 98,
  "explanation": "CloudTrail logging disabled without approval during off-hours. Creates 6-hour audit gap for all AWS API calls, violating compliance requirements and hiding potential breach activity.",
  "compliance_violations": ["NIST SI-12", "GDPR Article 32"],
  "recommended_action": "Immediately re-enable logging and audit access during blind period"
}
```

---

##  Evaluation Rubric (100 pts)

- **Detection Accuracy (35 pts):** Precision >85%, Recall >80%, correctly distinguishes benign vs risky
- **Explanations (25 pts):** Clear compliance mapping, business impact, remediation steps for all critical drifts
- **Performance (12 pts):** Analyzes 10K changes in <60 sec, scalable architecture
- **UI/Usability (8 pts):** Dashboard or readable report showing drift severity, timeline, patterns
- **Bonus (10 pts):** Automation, compliance reports, ML learning, remediation guidance

---

##  Deliverables Checklist

- [ ] **GitHub Repo** with runnable code (`python drift_detector.py`)
- [ ] **Jupyter Notebook** with data exploration & ground truth analysis
- [ ] **Drift Detection Output** (20+ drifts flagged with explanations)
- [ ] **Dashboard or Report** (visual summary of control health)
- [ ] **Technical Docs** (approach, limitations, scaling notes)
- [ ] **5-Min Presentation** (demo + explanation)

---

##  Timeline (48/72 hours)

- **Day 1:** Explore data → Understand baselines → Build core logic
- **Day 2:** Evaluate & refine → Add explanations → Build dashboard → Document
- **Day 3 (optional):** Bonus features → Polish presentation

---

##  Bonus Features

- Interactive drift timeline visualization (+5)
- Automated remediation recommendations (+4)
- ML-based "learn normal patterns" system (+3)
- Compliance audit-ready reports (+2)

---

##  FAQ

**Q: Can we use Terraform/Ansible?** A: Yes! Show integration.
**Q: What if baselines are incomplete?** A: Document gaps, focus on handling ambiguity well.
**Q: Should we detect every change or just risky ones?** A: Risky ones. Precision > recall.
**Q: How to measure false positives?** A: Use ground truth labels provided.

---

##  Judge Guide

**Green Flags:** Understands context, low false positives, clear compliance links, actionable recommendations
**Red Flags:** Alerts on everything, generic explanations, precision <50%
**Key Questions:** "Why is this drift risky?", "Show us a false positive", "How does it scale?"

---

**Ready to build?** Download starter template at [DOWNLOAD_LINK]


