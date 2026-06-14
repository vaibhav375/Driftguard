import React, { useState } from "react";
import { api, riskColor } from "../api.js";
import RiskRing from "../components/RiskRing.jsx";

const PRESETS = {
  "Case 1 — Logging disabled in maintenance, never re-enabled": {
    control_type: "Logging", change_type: "Disable", baseline_enabled: true,
    current_enabled: false, change_reason: "Troubleshooting", status: "Drifted",
    hour: 23, weekend: false, self_approved: false, age_days: 180,
  },
  "Case 2 — 'Temporary' firewall rule still open 2 years later": {
    control_type: "Firewall", change_type: "Modify", baseline_enabled: true,
    current_enabled: false, change_reason: "Emergency Fix", status: "Under_Review",
    hour: 14, weekend: false, self_approved: false, age_days: 730,
  },
  "Case 3 — Encryption downgraded 'for performance'": {
    control_type: "Encryption", change_type: "Modify", baseline_enabled: true,
    current_enabled: false, change_reason: "Performance Tuning", status: "Drifted",
    hour: 11, weekend: false, self_approved: true, age_days: 20,
  },
  "Benign — CI/CD security update, approved & compliant": {
    control_type: "Endpoint", change_type: "Update", baseline_enabled: true,
    current_enabled: true, change_reason: "Security Update", status: "Compliant",
    hour: 10, weekend: false, self_approved: false, age_days: 2,
  },
};

const DEFAULT = PRESETS["Case 1 — Logging disabled in maintenance, never re-enabled"];

export default function Simulator() {
  const [form, setForm] = useState({ ...DEFAULT, control_name: "Control-SIM" });
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  const set = (k, cast = (x) => x) => (e) =>
    setForm((f) => ({ ...f, [k]: cast(e.target.value) }));

  async function run() {
    setBusy(true);
    try { setResult(await api.simulate(form)); }
    finally { setBusy(false); }
  }

  return (
    <div className="fade-in">
      <div className="card">
        <h3>What-if drift simulator — score a hypothetical change in real time</h3>
        <div className="note" style={{ marginBottom: 14 }}>
          Recreate the real incidents from the problem statement, or build your own change.
          The engine scores it live through the same rules + IsolationForest pipeline.
        </div>
        <div className="filters">
          {Object.keys(PRESETS).map((p) => (
            <button key={p} className="btn ghost" style={{ fontSize: 12 }}
              onClick={() => { setForm({ ...PRESETS[p], control_name: "Control-SIM" }); setResult(null); }}>
              {p}
            </button>
          ))}
        </div>

        <div className="sim-form section-gap">
          <div>
            <label>Control family</label>
            <select value={form.control_type} onChange={set("control_type")}>
              {["Logging", "Encryption", "Firewall", "Access_Control", "Cloud_Security", "DLP",
                "Data_Protection", "Endpoint", "Network_Segmentation", "Vulnerability"]
                .map((c) => <option key={c}>{c}</option>)}
            </select>
          </div>
          <div>
            <label>Change type</label>
            <select value={form.change_type} onChange={set("change_type")}>
              {["Disable", "Remove", "Modify", "Update", "Enable", "Rollback"].map((c) => <option key={c}>{c}</option>)}
            </select>
          </div>
          <div>
            <label>Baseline → current</label>
            <select
              value={`${form.baseline_enabled}-${form.current_enabled}`}
              onChange={(e) => {
                const [b, c] = e.target.value.split("-");
                setForm((f) => ({ ...f, baseline_enabled: b === "true", current_enabled: c === "true" }));
              }}>
              <option value="true-false">enabled → DISABLED (weakened)</option>
              <option value="false-true">disabled → enabled (restored)</option>
              <option value="true-true">enabled → enabled (no state change)</option>
            </select>
          </div>
          <div>
            <label>Stated reason</label>
            <select value={form.change_reason} onChange={set("change_reason")}>
              {["Troubleshooting", "Emergency Fix", "Performance Tuning", "Policy Change", "Security Update"]
                .map((c) => <option key={c}>{c}</option>)}
            </select>
          </div>
          <div>
            <label>Current status</label>
            <select value={form.status} onChange={set("status")}>
              {["Drifted", "Under_Review", "Mitigated", "Remediated", "Compliant"].map((c) => <option key={c}>{c}</option>)}
            </select>
          </div>
          <div>
            <label>Hour of change (0–23)</label>
            <input type="number" min="0" max="23" value={form.hour} onChange={set("hour", Number)} />
          </div>
          <div>
            <label>Days since change</label>
            <input type="number" min="0" value={form.age_days} onChange={set("age_days", Number)} />
          </div>
          <div style={{ display: "flex", alignItems: "end", gap: 16 }}>
            <label className="toggle" style={{ marginBottom: 4 }}>
              <input type="checkbox" checked={form.self_approved}
                onChange={(e) => setForm((f) => ({ ...f, self_approved: e.target.checked }))} />
              Self-approved
            </label>
            <button className="btn" disabled={busy} onClick={run}>
              {busy ? "Scoring…" : "⚡ Score this change"}
            </button>
          </div>
        </div>
      </div>

      {result && (
        <div className="card section-gap fade-in">
          <h3>Engine verdict</h3>
          <div className="gauge-wrap">
            <div className="big-gauge">
              <RiskRing score={result.risk_score} size={168} stroke={11} fontSize={0} />
              <div className="num">
                <div>
                  <b style={{ color: riskColor(result.risk_score) }}>{Math.round(result.risk_score)}</b>
                  <span>RISK / 100</span>
                </div>
              </div>
            </div>
            <div style={{ flex: 1, minWidth: 260 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10 }}>
                <span className={`chip ${result.severity}`}>{result.severity}</span>
                <span className={`chip ${result.flagged ? "open" : "closed"}`}>
                  {result.flagged ? "⚠ FLAGGED AS RISKY DRIFT" : "✓ Assessed benign"}
                </span>
              </div>
              <div style={{ fontSize: 13.5, lineHeight: 1.7, marginBottom: 10 }}>{result.explanation}</div>
              {result.compliance_tags.length > 0 && (
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
                  {result.compliance_tags.map((t, i) => (
                    <span className="chip fw" key={i}>{t.framework} · {t.ref}</span>
                  ))}
                </div>
              )}
              <div className="remed">
                <b>⟲ Remediation</b> — {result.remediation_action}{" "}
                <span style={{ color: "#2fd48f", fontWeight: 600 }}>SLA {result.remediation_sla_hours}h</span>
              </div>
            </div>
          </div>

          <div className="section-gap">
            <h3 style={{ marginBottom: 6 }}>Signal breakdown</h3>
            {result.signals.map((s, i) => (
              <div className="signal-row" key={i}>
                <div className={`signal-pts ${s.points >= 0 ? "pos" : "neg"}`}>
                  {s.points >= 0 ? "+" : ""}{s.points}
                </div>
                <div className="signal-name">{s.name}</div>
                <div className="signal-reason">{s.reason}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
