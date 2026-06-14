import React, { useState } from "react";
import RiskRing from "./RiskRing.jsx";

export default function AlertCard({ alert, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  const a = alert;
  const isOpen = a.status === "Drifted" || a.status === "Under_Review";

  return (
    <div className={`alert-card ${open ? "expanded" : ""}`} onClick={() => setOpen(!open)}>
      <div className="alert-head">
        <RiskRing score={a.risk_score} />
        <div className="alert-title">
          <div className="t">
            {a.control_name} · {a.control_type.replaceAll("_", " ")}
          </div>
          <div className="s">
            <span className="mono">{a.drift_event_id}</span> · {a.change_date} ·{" "}
            {a.operator_name} → approved by {a.approver_name}
          </div>
        </div>
        <span className="diff bad">{a.baseline_value}</span>
        <span style={{ color: "#56677e" }}>→</span>
        <span className={`diff ${a.weakened ? "bad" : "good"}`}>{a.current_value}</span>
        <span className={`chip ${a.predicted_severity}`}>{a.predicted_severity}</span>
        <span className={`chip ${isOpen ? "open" : "closed"}`}>{isOpen ? "● OPEN" : "✓ " + a.status}</span>
      </div>

      {open && (
        <div className="alert-body fade-in" onClick={(e) => e.stopPropagation()}>
          <div>
            <h4>Why this was flagged</h4>
            <div style={{ fontSize: 13, lineHeight: 1.65 }}>{a.explanation}</div>
          </div>

          <div>
            <h4>Risk signals (rule engine + ML)</h4>
            {a.signals.map((s, i) => (
              <div className="signal-row" key={i}>
                <div className={`signal-pts ${s.points >= 0 ? "pos" : "neg"}`}>
                  {s.points >= 0 ? "+" : ""}{s.points}
                </div>
                <div className="signal-name">{s.name}</div>
                <div className="signal-reason">{s.reason}</div>
              </div>
            ))}
            <div className="signal-row">
              <div className="signal-pts pos">+{Math.round(a.ml_anomaly * 15)}</div>
              <div className="signal-name">ML anomaly score</div>
              <div className="signal-reason">
                IsolationForest behavioural outlier score: {a.ml_anomaly} (trained on 365 days of change patterns)
              </div>
            </div>
          </div>

          {a.compliance_tags.length > 0 && (
            <div>
              <h4>Compliance impact</h4>
              <div style={{ display: "flex", gap: 7, flexWrap: "wrap" }}>
                {a.compliance_tags.map((t, i) => (
                  <span className="chip fw" key={i}>{t.framework} · {t.ref}</span>
                ))}
              </div>
            </div>
          )}

          <div className="remed">
            <b>⟲ Remediation</b> — {a.remediation_action}{" "}
            <span style={{ color: "#2fd48f", fontWeight: 600 }}>SLA {a.remediation_sla_hours}h</span>
          </div>
        </div>
      )}
    </div>
  );
}
