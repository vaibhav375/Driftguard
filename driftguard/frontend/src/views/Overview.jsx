import React from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  PieChart, Pie, Cell, BarChart, Bar, Legend,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from "recharts";
import { SEV_COLOR, riskColor } from "../api.js";
import AlertCard from "../components/AlertCard.jsx";

const tooltipStyle = {
  background: "#0f1622", border: "1px solid #283750", borderRadius: 10,
  fontSize: 12, color: "#e8eef7",
};

function Kpi({ val, lbl, accent, delta }) {
  return (
    <div className={`card kpi accent-${accent}`}>
      <div className="val">{val}</div>
      <div className="lbl">{lbl}</div>
      {delta && <div className="delta" style={{ color: delta.color }}>{delta.text}</div>}
    </div>
  );
}

const ANOMALY_COLORS = {
  ACCESS_BROADENED: "#ffb020",
  ENCRYPTION_WEAKENED: "#ff4d5e",
  LOGGING_DISABLED: "#e9293d",
  STALE_TEMPORARY: "#9f7bff",
  PROTECTION_DISABLED: "#38c8e8",
};

export default function Overview({ summary, alerts }) {
  const k = summary.kpis;
  const donut = Object.entries(summary.anomaly_types).map(([name, v]) => ({
    name: name.replaceAll("_", " "), value: v.total, detected: v.detected,
  }));
  const topAlerts = alerts.slice(0, 4);

  return (
    <div className="fade-in">
      <div className="grid kpis">
        <Kpi val={k.events_total.toLocaleString()} lbl="Changes analysed (365d)" accent="blue" />
        <Kpi val={k.flagged_total} lbl="Risky drifts detected" accent="amber" />
        <Kpi val={k.open_drifts} lbl="Open exposure (unresolved)" accent="red" />
        <Kpi val={k.critical_alerts} lbl="Critical alerts" accent="red" />
        <Kpi
          val={`${(k.detection_rate * 100).toFixed(1)}%`} lbl="Detection rate"
          accent="green" delta={{ text: "target > 80% ✓", color: "#2fd48f" }}
        />
        <Kpi
          val={`${(k.false_positive_rate * 100).toFixed(1)}%`} lbl="False-positive rate"
          accent="green" delta={{ text: "target < 15% ✓", color: "#2fd48f" }}
        />
      </div>

      <div className="grid row-2">
        <div className="card">
          <h3>Drift timeline — weekly change volume by outcome</h3>
          <ResponsiveContainer width="100%" height={265}>
            <AreaChart data={summary.timeline} margin={{ top: 5, right: 8, left: -18, bottom: 0 }}>
              <defs>
                <linearGradient id="gCrit" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ff4d5e" stopOpacity={0.7} />
                  <stop offset="100%" stopColor="#ff4d5e" stopOpacity={0.05} />
                </linearGradient>
                <linearGradient id="gHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ffb020" stopOpacity={0.6} />
                  <stop offset="100%" stopColor="#ffb020" stopOpacity={0.04} />
                </linearGradient>
                <linearGradient id="gBenign" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#2fd48f" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#2fd48f" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#1c2738" strokeDasharray="3 6" vertical={false} />
              <XAxis dataKey="week" tick={{ fill: "#56677e", fontSize: 10 }} tickLine={false} axisLine={false} interval={6} />
              <YAxis tick={{ fill: "#56677e", fontSize: 10 }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area type="monotone" dataKey="benign" name="Benign" stackId="1" stroke="#2fd48f" fill="url(#gBenign)" strokeWidth={1.4} />
              <Area type="monotone" dataKey="medium" name="Medium" stackId="1" stroke="#5b8aff" fill="#5b8aff22" strokeWidth={1.4} />
              <Area type="monotone" dataKey="high" name="High" stackId="1" stroke="#ffb020" fill="url(#gHigh)" strokeWidth={1.4} />
              <Area type="monotone" dataKey="critical" name="Critical" stackId="1" stroke="#ff4d5e" fill="url(#gCrit)" strokeWidth={1.6} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3>Anomaly taxonomy — detection coverage</h3>
          <ResponsiveContainer width="100%" height={185}>
            <PieChart>
              <Pie
                data={donut} dataKey="value" nameKey="name"
                innerRadius={52} outerRadius={80} paddingAngle={3} strokeWidth={0}
              >
                {donut.map((d, i) => (
                  <Cell key={i} fill={Object.values(ANOMALY_COLORS)[i % 5]} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "grid", gap: 5 }}>
            {donut.map((d, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                <span style={{ color: "#8295ae" }}>
                  <span style={{ color: Object.values(ANOMALY_COLORS)[i % 5] }}>●</span> {d.name}
                </span>
                <span className="mono">{d.detected}/{d.value} caught</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid row-2 section-gap">
        <div className="card">
          <h3>Control family health — % of changes without open drift</h3>
          {summary.control_health.map((h) => (
            <div className="health-row" key={h.control_type}>
              <div className="name">{h.control_type.replaceAll("_", " ")}</div>
              <div className="bar">
                <div
                  style={{
                    width: `${h.health}%`,
                    background:
                      h.health < 88 ? "linear-gradient(90deg,#ff4d5e,#ffb020)"
                        : h.health < 93 ? "linear-gradient(90deg,#ffb020,#5b8aff)"
                          : "linear-gradient(90deg,#2fd48f,#38c8e8)",
                  }}
                />
              </div>
              <div className="pct" style={{ color: h.health < 88 ? "#ff4d5e" : h.health < 93 ? "#ffb020" : "#2fd48f" }}>
                {h.health}% <span style={{ color: "#56677e", fontWeight: 400 }}>({h.open} open)</span>
              </div>
            </div>
          ))}
        </div>

        <div className="card">
          <h3>Compliance exposure — flagged drifts per framework</h3>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={summary.compliance} layout="vertical" margin={{ left: 10, right: 18 }}>
              <CartesianGrid stroke="#1c2738" strokeDasharray="3 6" horizontal={false} />
              <XAxis type="number" tick={{ fill: "#56677e", fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="framework" width={78} tick={{ fill: "#8295ae", fontSize: 11.5 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(91,138,255,.04)" }} />
              <Bar dataKey="violations" radius={[0, 6, 6, 0]} barSize={16}>
                {summary.compliance.map((c, i) => (
                  <Cell key={i} fill={["#e9293d", "#ffb020", "#5b8aff", "#9f7bff", "#38c8e8", "#2fd48f"][i % 6]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="note">
            Truncated framework codes in source data (GD, NI, CI, PC, IS) were auto-normalized
            during ingestion — {summary.kpis.data_quality_issues} dirty records repaired.
          </div>
        </div>
      </div>

      {/* Radar chart + Risky operators */}
      <div className="grid row-2 section-gap">
        <div className="card">
          <h3>Security posture radar — family health dimensions</h3>
          <div className="note" style={{ marginBottom: 8 }}>
            Each axis = % of events without open drift. Perfect posture = outer edge on all 10 axes.
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <RadarChart
              data={summary.control_health.map((h) => ({
                family: h.control_type.replace("_", " ").replace("Segmentation", "Seg."),
                health: h.health,
                critical: Math.max(0, 100 - h.critical * 4),
              }))}
              margin={{ top: 10, right: 16, bottom: 10, left: 16 }}
            >
              <PolarGrid stroke="#1c2738" />
              <PolarAngleAxis dataKey="family" tick={{ fill: "#8295ae", fontSize: 10 }} />
              <PolarRadiusAxis domain={[0, 100]} tick={{ fill: "#56677e", fontSize: 9 }} axisLine={false} tickCount={4} />
              <Radar name="Health %" dataKey="health" stroke="#2fd48f" fill="#2fd48f" fillOpacity={0.18} strokeWidth={2} />
              <Radar name="Critical-free" dataKey="critical" stroke="#e9293d" fill="#e9293d" fillOpacity={0.1} strokeWidth={1.5} strokeDasharray="4 3" />
              <Legend wrapperStyle={{ fontSize: 11, color: "#8295ae" }} />
              <Tooltip contentStyle={tooltipStyle} formatter={(v) => `${v}%`} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3>Risky operators — most flagged changes this period</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {summary.risky_operators.slice(0, 6).map((op, i) => (
              <div key={op.operator} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{
                  width: 24, height: 24, borderRadius: 7, background: "var(--card-2)",
                  display: "grid", placeItems: "center", fontSize: 10, fontWeight: 700,
                  color: "#56677e", flexShrink: 0,
                }}>{i + 1}</div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {op.operator}
                  </div>
                  <div style={{ display: "flex", gap: 6, marginTop: 3 }}>
                    <div style={{ flex: 1, height: 4, background: "#1c2738", borderRadius: 99 }}>
                      <div style={{
                        width: `${(op.avg_risk / 100) * 100}%`, height: "100%", borderRadius: 99,
                        background: `linear-gradient(90deg, ${riskColor(op.avg_risk)}, ${riskColor(op.avg_risk)}88)`,
                      }} />
                    </div>
                  </div>
                </div>
                <div style={{ textAlign: "right", flexShrink: 0 }}>
                  <div style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 13, color: riskColor(op.avg_risk) }}>
                    {op.avg_risk}
                  </div>
                  <div style={{ fontSize: 10.5, color: "#56677e" }}>{op.flagged_changes} alerts</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card section-gap">
        <h3>Highest-priority open drifts</h3>
        {topAlerts.map((a) => <AlertCard key={a.drift_event_id} alert={a} />)}
      </div>
    </div>
  );
}
