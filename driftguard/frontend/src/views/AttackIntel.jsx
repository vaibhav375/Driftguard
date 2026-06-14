import React, { useEffect, useState } from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Cell, ReferenceLine,
} from "recharts";
import { api } from "../api.js";

const tooltipStyle = {
  background: "#0f1622", border: "1px solid #283750",
  borderRadius: 10, fontSize: 12, color: "#e8eef7",
};

const TACTIC_COLORS = {
  TA0005: "#ff4d5e",   // Defense Evasion — red
  TA0004: "#ffb020",   // Priv. Escalation — amber
  TA0003: "#9f7bff",   // Persistence — purple
  TA0040: "#e9293d",   // Impact — deep red
};

const RISK_COLORS = {
  critical: "#ff4d5e",
  high: "#ffb020",
  medium: "#5b8aff",
  low: "#2fd48f",
};

const TREND_ICON = { increasing: "↑", decreasing: "↓", stable: "→" };
const TREND_COLOR = { increasing: "#ff4d5e", decreasing: "#2fd48f", stable: "#8295ae" };

function Kpi({ val, lbl, accent, sub }) {
  return (
    <div className={`card kpi accent-${accent}`}>
      <div className="val">{val}</div>
      <div className="lbl">{lbl}</div>
      {sub && <div style={{ fontSize: 10.5, color: "#56677e", marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

/* ── MITRE Kill Chain tactic strip ────────────────────────────────────────── */
function TacticChain({ tactics, onSelect, selected }) {
  const max = Math.max(...tactics.map(t => t.event_count), 1);
  return (
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
      {tactics.map((t) => {
        const active = t.event_count > 0;
        const isSelected = selected === t.id;
        const intensity = active ? Math.max(0.18, t.event_count / max) : 0;
        const baseColor = TACTIC_COLORS[t.id] || "#5b8aff";
        return (
          <button
            key={t.id}
            onClick={() => active && onSelect(isSelected ? null : t.id)}
            style={{
              flex: "1 1 0",
              minWidth: 82,
              padding: "10px 8px",
              background: active
                ? `rgba(${baseColor === "#ff4d5e" ? "255,77,94" : baseColor === "#ffb020" ? "255,176,32" : baseColor === "#9f7bff" ? "159,123,255" : "91,138,255"},${intensity})`
                : "var(--card-2)",
              border: isSelected
                ? `1.5px solid ${baseColor}`
                : active
                  ? `1px solid ${baseColor}44`
                  : "1px solid #1c2738",
              borderRadius: 10,
              cursor: active ? "pointer" : "default",
              textAlign: "center",
              transition: "all 0.18s",
            }}
          >
            <div style={{
              fontSize: 10, fontWeight: 700, letterSpacing: "0.3px",
              color: active ? baseColor : "#3a4d63", marginBottom: 5,
            }}>
              {t.id}
            </div>
            <div style={{
              fontSize: 11, fontWeight: 600,
              color: active ? "#e8eef7" : "#3a4d63",
              lineHeight: 1.25,
            }}>
              {t.name}
            </div>
            {active && (
              <div style={{
                marginTop: 6, fontSize: 14, fontWeight: 800,
                color: baseColor, fontFamily: "var(--mono)",
              }}>
                {t.event_count}
              </div>
            )}
            {!active && (
              <div style={{ fontSize: 11, color: "#3a4d63", marginTop: 6 }}>—</div>
            )}
          </button>
        );
      })}
    </div>
  );
}

/* ── Campaign card ─────────────────────────────────────────────────────────── */
function CampaignCard({ c }) {
  const [open, setOpen] = useState(false);
  return (
    <div
      className="card"
      style={{
        borderLeft: `3px solid ${c.color}`,
        cursor: "pointer",
        padding: "14px 16px",
        transition: "background 0.15s",
      }}
      onClick={() => setOpen(o => !o)}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{
              fontFamily: "var(--mono)", fontSize: 10, color: "#56677e",
              background: "var(--card-2)", padding: "2px 7px", borderRadius: 5,
            }}>{c.campaign_id}</span>
            <span style={{ fontWeight: 700, fontSize: 13 }}>{c.name}</span>
            <span className={`chip ${c.severity}`}>{c.severity}</span>
            {c.ps02_case && (
              <span style={{
                fontSize: 9.5, fontWeight: 700, color: "#e9293d",
                background: "#e9293d18", padding: "2px 7px", borderRadius: 5,
                letterSpacing: "0.3px",
              }}>PS-02 MATCH</span>
            )}
          </div>
          <div style={{ color: "#8295ae", fontSize: 12, marginTop: 4 }}>
            {c.description}
          </div>
        </div>
        <div style={{ textAlign: "right", flexShrink: 0, minWidth: 80 }}>
          <div style={{
            fontFamily: "var(--mono)", fontSize: 18, fontWeight: 800,
            color: c.color,
          }}>{c.event_count}</div>
          <div style={{ fontSize: 10.5, color: "#56677e" }}>events</div>
          <div style={{ fontSize: 10, color: "#56677e", marginTop: 2 }}>
            {c.period}
          </div>
        </div>
        <div style={{ color: "#56677e", fontSize: 14, marginLeft: 4 }}>
          {open ? "▲" : "▼"}
        </div>
      </div>

      {open && (
        <div style={{
          marginTop: 12, paddingTop: 12, borderTop: "1px solid #1c2738",
          display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12,
        }}>
          <div>
            <div style={{ fontSize: 10, color: "#56677e", marginBottom: 4 }}>MITRE Technique</div>
            <div style={{
              fontFamily: "var(--mono)", fontSize: 12, fontWeight: 700,
              color: c.color,
            }}>{c.mitre_technique}</div>
          </div>
          <div>
            <div style={{ fontSize: 10, color: "#56677e", marginBottom: 4 }}>Operators Involved</div>
            <div style={{ fontSize: 11.5 }}>{c.operators.join(", ")}</div>
          </div>
          <div>
            <div style={{ fontSize: 10, color: "#56677e", marginBottom: 4 }}>Control Families</div>
            <div style={{ fontSize: 11.5 }}>{c.control_families.join(", ")}</div>
          </div>
          <div>
            <div style={{ fontSize: 10, color: "#56677e", marginBottom: 4 }}>Time Span</div>
            <div style={{ fontSize: 11.5 }}>{c.start_time} → {c.end_time}</div>
          </div>
          <div>
            <div style={{ fontSize: 10, color: "#56677e", marginBottom: 4 }}>Critical / High Events</div>
            <div style={{ fontSize: 11.5 }}>
              <span style={{ color: "#ff4d5e", fontWeight: 700 }}>{c.critical_events} Critical</span>
              {" · "}
              <span style={{ color: "#ffb020", fontWeight: 700 }}>{c.high_events} High</span>
            </div>
          </div>
          {c.ps02_case && (
            <div>
              <div style={{ fontSize: 10, color: "#56677e", marginBottom: 4 }}>PS-02 Breach Pattern</div>
              <div style={{ fontSize: 11, color: "#e9293d" }}>{c.ps02_case}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Main view ─────────────────────────────────────────────────────────────── */
export default function AttackIntel() {
  const [data, setData] = useState(null);
  const [selectedTactic, setSelectedTactic] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    api.attackIntel().then(setData).catch(e => setErr(String(e)));
  }, []);

  if (err) return <div className="loading" style={{ color: "#ff4d5e" }}>{err}</div>;
  if (!data) return (
    <div className="loading">
      <div style={{ textAlign: "center" }}>
        <div className="spinner" style={{ margin: "0 auto 14px" }} />
        Mapping MITRE ATT&CK techniques…
      </div>
    </div>
  );

  const {
    mitre, forecasts, campaigns, ueba_anomalies, ueba_total,
    drift_waves = [], drift_waves_total = 0,
    hot_controls = [], hot_controls_total = 0,
  } = data;

  // Filter techniques by selected tactic
  const visibleTechniques = selectedTactic
    ? mitre.techniques.filter(t => t.tactic_id === selectedTactic)
    : mitre.techniques;

  // Tactic strip needs the full chain
  const tacticChain = mitre.tactic_chain;

  // Forecast chart data
  const forecastData = forecasts.map(f => ({
    family: f.family.replace("_", " "),
    current: Math.round(f.current_rate * 100),
    predicted: Math.round(f.predicted_30d_rate * 100),
    trend: f.trend,
    risk: f.risk_level,
  }));

  const atRiskFamilies = forecasts.filter(f => f.risk_level === "critical" || f.risk_level === "high").length;
  const maxWaveZ = drift_waves.length > 0 ? Math.max(...drift_waves.map(w => w.z_score)) : 0;

  return (
    <div className="fade-in">

      {/* ── KPIs ─────────────────────────────────────────────────────────── */}
      <div className="grid kpis">
        <Kpi
          val={mitre.active_tactics}
          lbl="Active ATT&CK Tactics"
          accent="red"
          sub={`Primary: ${mitre.primary_tactic}`}
        />
        <Kpi
          val={mitre.techniques.length}
          lbl="Mapped Techniques"
          accent="amber"
          sub={`${mitre.total_technique_hits} total hits`}
        />
        <Kpi
          val={campaigns.length}
          lbl="Incident Campaigns"
          accent="blue"
          sub="Correlated attack clusters"
        />
        <Kpi
          val={drift_waves_total}
          lbl="Drift Wave Surges"
          accent={drift_waves_total > 4 ? "red" : "amber"}
          sub={drift_waves_total > 0 ? `Peak z=${maxWaveZ.toFixed(1)}σ above baseline` : "No surge weeks detected"}
        />
        <Kpi
          val={hot_controls_total}
          lbl="Persistent Hot Controls"
          accent={hot_controls_total > 20 ? "red" : "amber"}
          sub="Flagged ≥2× — chronic drift"
        />
        <Kpi
          val={ueba_total}
          lbl="UEBA Timing Anomalies"
          accent={ueba_total > 0 ? "red" : "green"}
          sub="Population outlier timing events"
        />
      </div>

      {/* ── Attack Narrative ─────────────────────────────────────────────── */}
      <div className="card section-gap" style={{
        borderLeft: "3px solid #ff4d5e",
        background: "linear-gradient(135deg, #12192600 0%, #ff4d5e08 100%)",
      }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
          <div style={{ fontSize: 22, lineHeight: 1 }}>⚠</div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 13, color: "#ff4d5e", marginBottom: 5 }}>
              AUTO-GENERATED ATTACK NARRATIVE
            </div>
            <div style={{ fontSize: 13, color: "#c8d4e3", lineHeight: 1.6 }}>
              {mitre.narrative}
            </div>
          </div>
        </div>
      </div>

      {/* ── MITRE ATT&CK Tactic Kill Chain ───────────────────────────────── */}
      <div className="card section-gap">
        <h3>MITRE ATT&CK Kill Chain — Tactic Activity Heat Map</h3>
        <div className="note" style={{ marginBottom: 12 }}>
          Click an active tactic to filter the technique list below.
          Intensity indicates event count relative to the most active tactic.
        </div>
        <TacticChain
          tactics={tacticChain}
          onSelect={setSelectedTactic}
          selected={selectedTactic}
        />
        {selectedTactic && (
          <div style={{ marginTop: 4, fontSize: 11, color: "#56677e" }}>
            Showing techniques for {tacticChain.find(t => t.id === selectedTactic)?.name} ·{" "}
            <button
              onClick={() => setSelectedTactic(null)}
              style={{ background: "none", border: "none", color: "#5b8aff", cursor: "pointer", fontSize: 11 }}
            >
              clear filter
            </button>
          </div>
        )}
      </div>

      {/* ── Technique list + Forecast chart ──────────────────────────────── */}
      <div className="grid row-2 section-gap">

        <div className="card">
          <h3>
            {selectedTactic
              ? `Active Techniques — ${tacticChain.find(t => t.id === selectedTactic)?.name}`
              : "All Mapped ATT&CK Techniques"}
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {visibleTechniques.length === 0 && (
              <div style={{ color: "#56677e", fontSize: 12 }}>No techniques in selected tactic.</div>
            )}
            {visibleTechniques.map((tech) => {
              const color = TACTIC_COLORS[tech.tactic_id] || "#5b8aff";
              const sev = tech.severity;
              return (
                <div key={tech.technique_id} style={{
                  background: "var(--card-2)", borderRadius: 10,
                  padding: "10px 12px",
                  borderLeft: `3px solid ${color}`,
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                        <span style={{
                          fontFamily: "var(--mono)", fontSize: 10.5,
                          fontWeight: 700, color,
                        }}>{tech.technique_id}</span>
                        {sev && (
                          <span className={`chip ${sev === "critical" ? "Critical" : sev === "high" ? "High" : "Medium"}`}
                            style={{ fontSize: 9 }}>
                            {sev}
                          </span>
                        )}
                        <span style={{ fontSize: 10, color: "#56677e" }}>{tech.tactic}</span>
                      </div>
                      <div style={{ fontSize: 12, fontWeight: 600, marginTop: 3 }}>
                        {tech.technique}
                      </div>
                      <div style={{ fontSize: 11, color: "#8295ae", marginTop: 3 }}>
                        {tech.description}
                      </div>
                    </div>
                    <div style={{
                      fontFamily: "var(--mono)", fontWeight: 800,
                      fontSize: 20, color, flexShrink: 0, marginLeft: 12,
                    }}>
                      {tech.event_count}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="card">
          <h3>30-Day Drift Risk Forecast — Per Control Family</h3>
          <div className="note" style={{ marginBottom: 8 }}>
            Linear regression on 52 weeks of per-family flag rates. Red = predicted ≥ 55%, amber ≥ 40%.
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart
              data={forecastData}
              layout="vertical"
              margin={{ left: 10, right: 56, top: 0, bottom: 0 }}
              barCategoryGap="28%"
              barGap={2}
            >
              <CartesianGrid stroke="#1c2738" strokeDasharray="3 6" horizontal={false} />
              <XAxis
                type="number" domain={[0, 100]}
                tick={{ fill: "#56677e", fontSize: 10 }}
                axisLine={false} tickLine={false}
                tickFormatter={v => `${v}%`}
              />
              <YAxis
                type="category" dataKey="family" width={110}
                tick={{ fill: "#8295ae", fontSize: 11 }}
                axisLine={false} tickLine={false}
              />
              <Tooltip
                contentStyle={tooltipStyle}
                formatter={(v, name) => [`${v}%`, name === "predicted" ? "Predicted 30d" : "Current 4-wk avg"]}
              />
              <ReferenceLine x={40} stroke="#ffb02055" strokeDasharray="4 3" />
              <ReferenceLine x={55} stroke="#ff4d5e55" strokeDasharray="4 3" />
              <Bar dataKey="current" name="Current" radius={[0, 4, 4, 0]} barSize={7} fill="#283750">
                {forecastData.map((d, i) => (
                  <Cell key={i} fill="#283750" />
                ))}
              </Bar>
              <Bar dataKey="predicted" name="Predicted 30d" radius={[0, 4, 4, 0]} barSize={7}>
                {forecastData.map((d, i) => (
                  <Cell key={i} fill={RISK_COLORS[d.risk]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", gap: 16, marginTop: 8, flexWrap: "wrap" }}>
            {forecastData.slice(0, 4).map(f => (
              <div key={f.family} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11 }}>
                <span style={{ color: TREND_COLOR[f.trend], fontWeight: 700 }}>
                  {TREND_ICON[f.trend]}
                </span>
                <span style={{ color: "#8295ae" }}>{f.family}</span>
                <span style={{ color: TREND_COLOR[f.trend], fontFamily: "var(--mono)", fontWeight: 600 }}>
                  {f.predicted}%
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Incident Campaigns ───────────────────────────────────────────── */}
      <div className="card section-gap">
        <h3>Detected Incident Campaigns — Correlated Attack Clusters</h3>
        <div className="note" style={{ marginBottom: 12 }}>
          Events grouped by anomaly type × calendar month. Campaigns with ≥ 4 correlated events
          are promoted from individual alerts to named attack campaigns. Click any campaign for details.
        </div>
        {campaigns.length === 0 ? (
          <div style={{ color: "#56677e", fontSize: 12 }}>No campaigns detected above threshold.</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {campaigns.map(c => <CampaignCard key={c.campaign_id} c={c} />)}
          </div>
        )}
      </div>

      {/* ── UEBA Anomalies ───────────────────────────────────────────────── */}
      {ueba_anomalies.length > 0 && (
        <div className="card section-gap">
          <h3>UEBA Behavioural Anomalies — R13 Operator Baseline Deviations</h3>
          <div className="note" style={{ marginBottom: 12 }}>
            Events where the operator's behaviour (time of day, change type, control family) deviated
            ≥ 2σ from their own historical baseline on a weakening or destructive change.
            MITRE ATT&CK T1078 (Valid Accounts — Insider Threat / Account Compromise).
          </div>
          <div className="op-scroll">
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ color: "#56677e", textTransform: "uppercase", fontSize: 10, letterSpacing: "0.5px" }}>
                  <th style={{ textAlign: "left", padding: "6px 10px" }}>Operator</th>
                  <th style={{ textAlign: "left", padding: "6px 10px" }}>Control</th>
                  <th style={{ textAlign: "left", padding: "6px 10px" }}>Family</th>
                  <th style={{ textAlign: "left", padding: "6px 10px" }}>Date</th>
                  <th style={{ textAlign: "right", padding: "6px 10px" }}>Risk</th>
                  <th style={{ textAlign: "left", padding: "6px 10px", maxWidth: 280 }}>Reason</th>
                </tr>
              </thead>
              <tbody>
                {ueba_anomalies.map((a, i) => (
                  <tr key={i} style={{ borderTop: "1px solid #1c2738" }}>
                    <td style={{ padding: "8px 10px", fontWeight: 600 }}>{a.operator}</td>
                    <td style={{ padding: "8px 10px", color: "#8295ae", fontFamily: "var(--mono)", fontSize: 11 }}>
                      {a.control}
                    </td>
                    <td style={{ padding: "8px 10px", color: "#8295ae" }}>{a.family.replace("_", " ")}</td>
                    <td style={{ padding: "8px 10px", color: "#56677e", fontFamily: "var(--mono)", fontSize: 11 }}>
                      {a.date}
                    </td>
                    <td style={{ padding: "8px 10px", textAlign: "right" }}>
                      <span style={{
                        fontFamily: "var(--mono)", fontWeight: 700, fontSize: 13,
                        color: a.risk >= 72 ? "#ff4d5e" : a.risk >= 55 ? "#ffb020" : "#5b8aff",
                      }}>{a.risk.toFixed(0)}</span>
                    </td>
                    <td style={{
                      padding: "8px 10px", color: "#8295ae", fontSize: 11,
                      maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    }} title={a.reason}>
                      {a.reason}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {ueba_total > 20 && (
            <div className="note" style={{ marginTop: 8 }}>
              Showing top 20 of {ueba_total} UEBA anomalies by risk score.
            </div>
          )}
        </div>
      )}

      {/* ── Drift Wave Surge Periods ─────────────────────────────────────── */}
      {drift_waves.length > 0 && (
        <div className="card section-gap">
          <h3>Drift Wave Surge Periods — Organisation-Wide Flag Rate Anomalies</h3>
          <div className="note" style={{ marginBottom: 14 }}>
            Weeks where the organisation's total flag rate exceeded the 6-week rolling mean
            by ≥ 1.2σ — indicating coordinated or systemic security degradation events,
            not random noise.
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 10 }}>
            {drift_waves.map((w, i) => {
              const intensity = maxWaveZ > 0 ? w.z_score / maxWaveZ : 0;
              const color = w.z_score > 2.0 ? "#ff4d5e" : w.z_score > 1.5 ? "#ffb020" : "#5b8aff";
              return (
                <div key={i} style={{
                  background: `rgba(${color === "#ff4d5e" ? "255,77,94" : color === "#ffb020" ? "255,176,32" : "91,138,255"},${0.06 + intensity * 0.1})`,
                  border: `1px solid ${color}44`,
                  borderLeft: `3px solid ${color}`,
                  borderRadius: 10,
                  padding: "12px 14px",
                }}>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "#56677e", marginBottom: 4 }}>
                    WEEK OF
                  </div>
                  <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6 }}>
                    {w.week}
                  </div>
                  <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 22, fontWeight: 800, color }}>
                      {w.z_score.toFixed(1)}σ
                    </span>
                    <span style={{ fontSize: 10, color: "#56677e" }}>above baseline</span>
                  </div>
                  <div style={{ marginTop: 6, fontSize: 11, color: "#8295ae" }}>
                    {w.flagged_rate !== undefined ? `${(w.flagged_rate * 100).toFixed(1)}% flag rate` : ""}
                    {w.flagged_events !== undefined ? ` · ${w.flagged_events} events` : ""}
                  </div>
                </div>
              );
            })}
          </div>
          <div className="note" style={{ marginTop: 10 }}>
            {drift_waves_total} surge {drift_waves_total === 1 ? "week" : "weeks"} detected
            · Peak intensity {maxWaveZ.toFixed(1)}σ
            · Suggests periodic systemic weakening events warranting calendar-correlated investigation
          </div>
        </div>
      )}

      {/* ── Persistent Hot Controls ──────────────────────────────────────── */}
      {hot_controls.length > 0 && (
        <div className="card section-gap">
          <h3>Persistent Hot Controls — Chronically Drifting Assets</h3>
          <div className="note" style={{ marginBottom: 12 }}>
            Controls flagged ≥ 2× across the full dataset — indicating chronic drift,
            inadequate remediation, or deliberate repeated weakening.
            {hot_controls_total} controls identified; showing top {Math.min(hot_controls.length, 15)}.
          </div>
          <div className="op-scroll">
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ color: "#56677e", textTransform: "uppercase", fontSize: 10, letterSpacing: "0.5px" }}>
                  <th style={{ textAlign: "left", padding: "6px 10px" }}>Control</th>
                  <th style={{ textAlign: "left", padding: "6px 10px" }}>Family</th>
                  <th style={{ textAlign: "center", padding: "6px 10px" }}>Flag Count</th>
                  <th style={{ textAlign: "right", padding: "6px 10px" }}>Avg Risk</th>
                  <th style={{ textAlign: "center", padding: "6px 10px" }}>Open</th>
                  <th style={{ textAlign: "right", padding: "6px 10px" }}>Span (days)</th>
                </tr>
              </thead>
              <tbody>
                {hot_controls.slice(0, 15).map((hc, i) => {
                  const risk = hc.avg_risk;
                  const rColor = risk >= 72 ? "#ff4d5e" : risk >= 55 ? "#ffb020" : "#5b8aff";
                  const flagCount = hc.flag_count;
                  const flagColor = flagCount >= 8 ? "#ff4d5e" : flagCount >= 5 ? "#ffb020" : "#5b8aff";
                  return (
                    <tr key={i} style={{ borderTop: "1px solid #1c2738" }}>
                      <td style={{ padding: "8px 10px", fontFamily: "var(--mono)", fontSize: 11, fontWeight: 600 }}>
                        {hc.control}
                      </td>
                      <td style={{ padding: "8px 10px", color: "#8295ae" }}>
                        {(hc.family || "").replace(/_/g, " ")}
                      </td>
                      <td style={{ padding: "8px 10px", textAlign: "center" }}>
                        <span style={{
                          display: "inline-block", fontFamily: "var(--mono)", fontSize: 13,
                          fontWeight: 800, color: flagColor,
                          background: `${flagColor}18`, padding: "2px 10px", borderRadius: 6,
                        }}>
                          {flagCount}×
                        </span>
                      </td>
                      <td style={{ padding: "8px 10px", textAlign: "right" }}>
                        <span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 13, color: rColor }}>
                          {typeof risk === "number" ? risk.toFixed(1) : risk}
                        </span>
                      </td>
                      <td style={{ padding: "8px 10px", textAlign: "center" }}>
                        {hc.open_count > 0 ? (
                          <span style={{
                            fontSize: 10, fontWeight: 700, color: "#ff4d5e",
                            background: "#ff4d5e18", padding: "2px 8px", borderRadius: 5,
                          }}>
                            {hc.open_count} open
                          </span>
                        ) : (
                          <span style={{ color: "#2fd48f", fontSize: 10 }}>✓ closed</span>
                        )}
                      </td>
                      <td style={{ padding: "8px 10px", textAlign: "right", color: "#56677e", fontFamily: "var(--mono)", fontSize: 11 }}>
                        {hc.span_days ?? "—"}d
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
