<div align="center">

# DriftGuard

### Security Control Drift & Misconfiguration Detection

*PS-02 · Société Générale Hackathon*

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-IsolationForest-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![Tests](https://img.shields.io/badge/tests-24%2F24%20passing-2fd48f)](./driftguard/backend/tests)

**40% of breaches start with misconfiguration, not missing controls.**
DriftGuard catches them in under 200 milliseconds.

</div>

---

## Results

| PS-02 Criterion | Target | DriftGuard | Status |
|---|---|---|---|
| Detection Rate | > 80% | **95.7%** | ✅ |
| False-Positive Rate | < 15% | **4.8%** | ✅ |
| Time Lag | < 1 hour | **< 200ms** | ✅ |
| Explainability | per-alert reason | per-signal rule breakdown + MITRE | ✅ |
| Compliance Mapping | NIST / CIS / GDPR | 5 frameworks auto-mapped | ✅ |

**Precision 94.0% · F1 0.95** — full metrics in [`deliverables/metrics.json`](./driftguard/deliverables/metrics.json)

---

## Quick Start

```bash
# Docker — run from the repo root
docker build -t driftguard -f driftguard/Dockerfile .
docker run -p 8000:8000 driftguard
# Open http://localhost:8000
```

<details>
<summary>Local dev (no Docker)</summary>

```bash
# Backend
cd driftguard/backend
pip install fastapi uvicorn scikit-learn pandas numpy
uvicorn api.main:app --port 8000

# Frontend dev server (optional — backend already serves the pre-built bundle)
cd driftguard/frontend
npm install && npm run dev   # http://localhost:5173
```

</details>

---

## Dashboard

Eight purpose-built tabs covering the full SOC workflow:

| Tab | What you get |
|---|---|
| **Overview** | Animated KPIs, radar chart, 52-week drift timeline, control health bars, compliance heatmap |
| **Alert Queue** | Risk-sorted, filterable alert list — click any row for full signal drill-down + remediation SLA |
| **Attack Intel** | MITRE ATT&CK kill-chain heat map, 30-day family forecasts, incident campaigns, population UEBA, drift wave surges, persistent hot controls |
| **Threat Intel** | Cross-dataset threat patterns, risk distribution, top operator leaderboard |
| **Live Stream** | WebSocket replay of all 1,000 events + **live ingest demo** — score any event in < 200ms |
| **What-If Simulator** | Score hypothetical changes including the 3 PS-02 breach scenarios before they happen |
| **Remediation** | Per-family SOPs, SLA matrix, downloadable playbook |
| **Audit Report** | Auto-generated markdown audit report |

---

## How It Works

```
config CSV / JSONL baselines
        │
        ▼
  NORMALIZE ── drift semantics · dirty-compliance repair · exposure windows
        │
        ├──── RULE ENGINE (R1–R13) ──── +35  baseline weakened
        │                                +28  stale temporary change
        │                                +20  destructive change type
        │                                +18  open exposure window
        │                                +15  critical control family
        │                                +14  UEBA population timing anomaly
        │                                −14  verified-resolved non-critical
        │
        ├──── ML LAYER ─────────────── IsolationForest (300 trees, 14 features)
        │                               + calibrated LogisticRegression
        │
        ▼
  FUSION  risk_score = rules (cap 80) + 15 × ML anomaly
          per-family thresholds: Logging / Encryption / Access = 38, default = 42
        │
        ▼
  ATTACK INTEL ── MITRE mapping · 30-day forecast · campaigns · UEBA · hot controls
```

**Two-score design:** `risk_score` answers "did this ever pose risk?" while `priority_score` answers "how urgent right now?" — so remediated drifts fall off the live queue without disappearing from history.

### Rule Engine

| Rule | Signal | Points |
|---|---|---|
| R1 | Baseline weakened | +35 |
| R2 | Stale temporary change (> 30 days unresolved) | +28 |
| R3 | Destructive change type (Disable / Remove) | +20 |
| R4 | Open exposure window | +18 |
| R5 | Critical control family (Logging, Encryption, Access) | +15 |
| R6 | Off-hours change (before 06:00 or after 22:00) | +12 |
| R7 | Repeated drift on same control (≥ 2×) | +14 |
| R8 | Self-approved change (SoD violation) | +14 |
| R9 | Verified-resolved, non-critical | −14 |
| R10 | Emergency-reason pattern | +10 |
| R11 | Self-approval + no ML signal | +8 |
| R12 | Non-critical resolved (full mitigation) | −14 |
| R13 | UEBA — timing > 2.5σ from population norm | +14 |

---

## Bonus Features

**MITRE ATT&CK mapping** — every flagged event is tagged with an ATT&CK technique (T1562.002, T1098, T1600, T1078…) and visualised on an interactive kill-chain heat map. Auto-generates an attack narrative such as *"[PRE-EXFILTRATION] Defense Evasion + Privilege Escalation active."*

**30-day drift forecast** — linear regression on 52 weeks of per-family flag rates predicts which control families will deteriorate before they breach.

**Incident campaign detection** — correlated events are promoted to named attack campaigns with MITRE technique, severity, operator roster, and PS-02 breach pattern match.

**Population UEBA (R13)** — flags changes at statistically unusual hours (> 2.5σ from the population norm for that control family + change type) without requiring per-user baselines.

**Drift wave detection** — identifies org-wide surge weeks where the flag rate exceeds the 6-week rolling mean by ≥ 1.2σ. 8 waves found in the provided dataset.

**Persistent hot controls** — tracks controls flagged ≥ 2× across the dataset. 91 identified; top offender flagged 10× with avg risk 78.6.

**Real-time ingest API** — `POST /api/ingest` scores any raw configuration change in < 200ms and integrates directly with SIEM, CMDB, or IaC pipelines.

---

## API Reference

```
GET  /api/summary        KPIs, timeline, control health, compliance
GET  /api/alerts         Filterable queue  (?severity=&control_type=&status=open&q=)
GET  /api/event/{id}     Full event detail + signals + remediation
GET  /api/baselines      Baseline configuration store (104 controls)
GET  /api/playbook       Per-family remediation SOPs + SLAs
GET  /api/attack-intel   MITRE mapping, forecasts, campaigns, UEBA, hot controls
GET  /api/report         Auto-generated markdown audit report
GET  /api/metrics        Model performance metrics
POST /api/simulate       Score a hypothetical change (<200ms)
POST /api/ingest         Score any raw event in real time (<200ms)
WS   /ws/stream          Live WebSocket replay stream
```

**Example — real-time ingest:**

```bash
curl -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "control_type": "Logging",
    "change_type": "Disable",
    "change_reason": "Emergency Fix",
    "status": "Drifted",
    "self_approved": true
  }'
```

```json
{
  "risk_score": 82.0,
  "predicted_severity": "Critical",
  "flagged": true,
  "latency_ms": 8.3,
  "explanation": "Baseline weakened — control disabled from an enabled baseline state.",
  "signals": [
    { "rule": "R1", "name": "Baseline Weakened", "points": 35 },
    { "rule": "R3", "name": "Destructive Change Type", "points": 20 },
    { "rule": "R5", "name": "Critical Control Family", "points": 15 },
    { "rule": "R8", "name": "Self-approved Change", "points": 14 }
  ]
}
```

---

## Deliverables

| Deliverable | Location |
|---|---|
| Drift Detection Engine | [`backend/engine/`](./driftguard/backend/engine/) |
| Baseline Configuration Store | [`deliverables/baseline_store.json`](./driftguard/deliverables/baseline_store.json) |
| Alert System | `GET /api/alerts` + Alert Queue tab |
| Dashboard | React 18 + Vite + Recharts |
| Audit Report | [`deliverables/Sample_Audit_Report.md`](./driftguard/deliverables/Sample_Audit_Report.md) |
| Remediation Playbook | Playbook tab + `GET /api/playbook` |
| Ground-truth labels | [`deliverables/config_drift_labels.csv`](./driftguard/deliverables/config_drift_labels.csv) |
| Metrics | [`deliverables/metrics.json`](./driftguard/deliverables/metrics.json) |
| **Bonus: MITRE ATT&CK mapping** | Attack Intel tab + `GET /api/attack-intel` |
| **Bonus: 30-day drift forecast** | Attack Intel tab |
| **Bonus: Real-time ingest API** | `POST /api/ingest` + Live Stream demo |
| **Bonus: What-If Simulator** | Simulator tab + `POST /api/simulate` |

---

## Project Structure

```
driftguard/
├── backend/
│   ├── api/
│   │   └── main.py          # FastAPI app, all REST + WebSocket endpoints
│   └── engine/
│       ├── pipeline.py      # Orchestrator — loads, scores, builds intel
│       ├── loader.py        # CSV/JSONL ingest + normalization
│       ├── rules.py         # R1–R13 deterministic rule engine
│       ├── scorer.py        # Score fusion, severity bands, remediation
│       ├── ml.py            # IsolationForest anomaly detection
│       ├── calibrate.py     # Calibrated LogisticRegression layer
│       ├── labels.py        # Ground-truth label derivation
│       ├── mitre.py         # MITRE ATT&CK technique mapping
│       ├── forecast.py      # 30-day drift forecast (linear regression)
│       ├── campaigns.py     # Incident campaign detection
│       └── evaluate.py      # Precision / recall / F1 evaluation
├── frontend/
│   └── src/
│       ├── views/           # 8 dashboard tab components
│       └── components/      # Shared UI primitives
├── deliverables/            # PS-02 required output files
├── tests/                   # 24 pytest tests
└── Dockerfile
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, pandas, scikit-learn, numpy |
| Frontend | React 18, Vite, Recharts |
| ML | IsolationForest (300 trees) + calibrated LogisticRegression |
| Deployment | Docker multi-stage build |
| Tests | pytest — 24/24 passing |
