import React, { useEffect, useState } from "react";
import { api } from "./api.js";

import Overview from "./views/Overview.jsx";
import Alerts from "./views/Alerts.jsx";
import Controls from "./views/Controls.jsx";
import Playbook from "./views/Playbook.jsx";
import Simulator from "./views/Simulator.jsx";
import LiveStream from "./views/LiveStream.jsx";
import AskDriftGuard from "./views/AskDriftGuard.jsx";
import ThreatIntel from "./views/ThreatIntel.jsx";
import AttackIntel from "./views/AttackIntel.jsx";

const TABS = [
  { id: "overview",  label: "Overview",          ic: "◈" },
  { id: "threat",    label: "Threat Intel",       ic: "⬡" },
  { id: "attack",    label: "Attack Intel",       ic: "⛶", badge: "NEW" },
  { id: "stream",    label: "Live Stream",        ic: "▶" },
  { id: "alerts",    label: "Alert Queue",        ic: "⚠" },
  { id: "ask",       label: "Ask DriftGuard",     ic: "✦" },
  { id: "controls",  label: "Baseline Store",     ic: "⛨" },
  { id: "playbook",  label: "Playbook & Report",  ic: "⟲" },
  { id: "simulator", label: "Drift Simulator",    ic: "⚡" },
];

const TITLES = {
  overview:  ["Security Posture Overview",      "365 days · 1,000 events · 10 control families · 95.7% detection rate · 4.7% FPR"],
  threat:    ["Threat Intelligence",            "MTTR · attack-pattern heatmap · operator risk profiles · drift velocity · compliance gaps"],
  attack:    ["Attack Intelligence",            "MITRE ATT&CK mapping · 30-day drift forecast · incident campaigns · UEBA operator anomalies"],
  stream:    ["Live Stream Replay",              "Watch DriftGuard score every change in real time — sub-second time lag vs PS-02's 1-hour target"],
  alerts:    ["Prioritized Alert Queue",         "Click any alert for the full rule + ML signal breakdown and compliance impact"],
  ask:       ["Ask DriftGuard",                  "Natural-language Q&A over your drift data — powered by the insight engine"],
  controls:  ["Baseline Configuration Store",   "The single source of truth the problem statement says is missing — 104 controls, JSON format"],
  playbook:  ["Remediation Playbook & Report",   "Per-family SOPs with SLAs — download the full audit report as Markdown"],
  simulator: ["What-If Drift Simulator",         "Score any hypothetical change live — including the 3 real incidents from the problem statement"],
};

export default function App() {
  const [tab, setTab] = useState("overview");
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [err, setErr] = useState(null);

  useEffect(() => {
    Promise.all([api.summary(), api.alerts({ status: "open", limit: 60 })])
      .then(([s, a]) => { setSummary(s); setAlerts(a.alerts); })
      .catch((e) => setErr(String(e)));
  }, []);

  if (err)
    return (
      <div className="loading">
        <div>
          <div style={{ fontSize: 18, marginBottom: 8 }}>Backend not reachable</div>
          <div style={{ color: "#56677e", fontSize: 13 }}>
            Run <span className="kbd">uvicorn api.main:app --port 8000</span> from{" "}
            <span className="kbd">driftguard/backend</span>, then reload.
          </div>
        </div>
      </div>
    );

  if (!summary)
    return (
      <div className="loading" style={{ width: "100%" }}>
        <div style={{ textAlign: "center" }}>
          <div className="spinner" style={{ margin: "0 auto 14px" }} />
          Analysing 1,000 configuration changes…
        </div>
      </div>
    );

  const k = summary.kpis;
  return (
    <>
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-logo">🛡</div>
          <div>
            <h1>Drift<span>Guard</span></h1>
            <small>PS-02 · Drift Intelligence</small>
          </div>
        </div>
        <nav className="nav">
          {TABS.map((t) => (
            <button key={t.id} className={tab === t.id ? "active" : ""} onClick={() => setTab(t.id)}>
              <span className="ic">{t.ic}</span> {t.label}
              {t.id === "alerts" && (
                <span className="chip Critical" style={{ marginLeft: "auto", fontSize: 10 }}>{k.open_drifts}</span>
              )}
              {t.badge && t.id !== "alerts" && (
                <span style={{ marginLeft: "auto", fontSize: 9, fontWeight: 700, color: "#38c8e8", background: "rgba(56,200,232,.1)", padding: "2px 6px", borderRadius: 6, letterSpacing: "0.5px" }}>
                  {t.badge}
                </span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div><span className="live-dot" />Engine v2.0 · online</div>
          <div>{k.controls_tracked} controls · {k.events_total.toLocaleString()} events</div>
          <div style={{ color: "#2fd48f", fontWeight: 600 }}>
            Detection {(k.detection_rate * 100).toFixed(1)}% · FPR {(k.false_positive_rate * 100).toFixed(1)}%
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="topbar">
          <div>
            <h2>{TITLES[tab][0]}</h2>
            <div className="sub">{TITLES[tab][1]}</div>
          </div>
          <div className="topbar-right">
            <span className={`badge ${k.meets_targets ? "ok" : "warn"}`}>
              {k.meets_targets ? "✓ PS-02 targets met" : "⚠ targets not met"}
            </span>
            <span className="badge warn">⚠ {k.open_drifts} open drifts</span>
            <span className="badge ok">Compliance {k.compliance_score}%</span>
            <button
              className="btn ghost"
              style={{ padding: "5px 12px", fontSize: 11.5, borderRadius: 8 }}
              onClick={() => api.exportAlerts()}
              title="Download all flagged alerts as CSV"
            >⬇ Export CSV</button>
          </div>
        </div>

        {tab === "overview"  && <Overview summary={summary} alerts={alerts} />}
        {tab === "threat"    && <ThreatIntel />}
        {tab === "attack"    && <AttackIntel />}
        {tab === "stream"    && <LiveStream />}
        {tab === "alerts"    && <Alerts />}
        {tab === "ask"       && <AskDriftGuard />}
        {tab === "controls"  && <Controls summary={summary} />}
        {tab === "playbook"  && <Playbook />}
        {tab === "simulator" && <Simulator />}
      </main>
    </>
  );
}
