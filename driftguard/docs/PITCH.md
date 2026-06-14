# DriftGuard — 5-minute demo script & winning arguments

## The 30-second hook

"Every team here will show you a dashboard that says *a config changed*. DriftGuard answers
the question the problem statement actually asks: **is it dangerous?** It detected 85.8% of
risky drifts at a 13% false-positive rate — both inside the PS targets — and every single
alert explains itself: which rules fired, how many points each added, which NIST control it
violates, and how to fix it within SLA."

## Demo flow (rehearse this order)

1. **Overview tab (45s)** — point at the KPI row: both PS targets green. Then the timeline:
   "365 days, 1,000 changes, severity-stacked." Then control health: "Logging and Encryption
   are our weakest families — exactly the breach patterns from the brief."
2. **Alert Queue (60s)** — open the top alert. Walk the signal breakdown out loud:
   "+35 baseline weakened, +20 destructive change, +15 critical family, +9 ML anomaly = 79,
   Critical." Point at the compliance chips (NIST AU-2, GDPR Art. 30) and the remediation
   with SLA. "A non-security manager can read this."
3. **Drift Simulator (90s) — the showstopper.** Click preset *Case 1 — logging disabled
   during maintenance, never re-enabled* (a real incident from the brief): scores ~88
   Critical. Then click the *benign CI/CD* preset: stays low/unflagged. "This is the whole
   challenge in one screen — we distinguish drift from deployments."
4. **Playbook tab (30s)** — download the audit report live. "Deliverables done: audit
   report, playbook with SLAs, baseline store for 104 controls."
5. **Close (15s)** — the data-quality story (below). It proves depth.

## Differentiators to say explicitly

- **Hybrid, not either/or**: the PS offered Option A (ML) or B (rules). We fused them —
  rules give explainability and compliance mapping; IsolationForest catches behavioural
  outliers rules don't encode. Fusion is weighted and tuned, with the threshold documented.
- **Detection vs priority split**: detection judges the change *at event time* (remediation
  later doesn't excuse risky drift); priority ranks the live queue (closed drifts sink).
  Most teams will conflate these.
- **We audited the dataset itself**:
  - `compliance_impact` is dirty — truncated codes (GD, NI, CI, PC, IS) in ~35% of rows.
    We repair them at ingest and report it.
  - The labels file the PS describes isn't in the sample_data. Worse, the `severity`
    column is statistically independent of every other field — pure noise. We proved it
    (uniform crosstabs), excluded it from features, and derived ground truth from the PS's
    own anomaly taxonomy, deterministically and reproducibly.
  - If judges supply the real labels file, swap it in and re-run — the engine doesn't change.
- **Sub-second scoring** (`POST /api/simulate`) → the "< 1 hour time lag" criterion is
  beaten by 3 orders of magnitude; the architecture is stream-ready.
- **Hand-built UI** — no admin template, no UI kit. SOC-dark design system with a nod to
  SG's brand red.

## Likely judge questions & answers

- *"Your labels are derived — isn't evaluation circular?"* — Partially overlapping by
  necessity (no ground truth was shipped), but: the label definition is a semantic policy
  statement from the PS taxonomy, the detector additionally uses ML + timing + justification
  signals the labels never reference, and the 14% miss / 13% FP gap shows it's not an echo.
  Hand us the real labels file and we re-run unchanged.
- *"Why IsolationForest?"* — Unlabelled data, mixed categorical/numeric features, fast,
  robust, and its anomaly score fuses cleanly into a 0–100 risk scale. Autoencoders need
  more data and tuning for no demo benefit.
- *"How does this scale to 200+ controls / 100+ changes a day?"* — Stateless scoring per
  event (<1 ms rules + amortized forest), baseline store is JSON-keyed by control; swap CSV
  ingest for a message queue (each change event scored on arrival) — the API contract
  already models that.
- *"What about configs in other formats?"* — The loader is the isolation layer: JSON, YAML,
  CLI-text parsers all normalize into the same drift-semantics frame (weakened/restored vs
  baseline). One new parser per vendor, zero engine changes.
