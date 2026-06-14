import React, { useEffect, useState, useMemo } from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  LineChart, Line, Legend, Cell,
} from "recharts";
import { api, riskColor } from "../api.js";

const tooltipStyle = {
  background: "#0f1622", border: "1px solid #283750", borderRadius: 10,
  fontSize: 12, color: "#e8eef7",
};

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const FAMILY_COLORS = {
  Logging: "#e9293d", Encryption: "#ff4d5e", Access_Control: "#ffb020",
  Firewall: "#ff7a45", DLP: "#9f7bff", Data_Protection: "#c67bff",
  Endpoint: "#38c8e8", Network_Segmentation: "#5b8aff",
  Cloud_Security: "#2fd48f", Vulnerability: "#56d48f",
};

function TrendBadge({ trend }) {
  const cfg = {
    worsening: { color: "#ff4d5e", bg: "rgba(255,77,94,.12)", icon: "↗", label: "Worsening" },
    improving: { color: "#2fd48f", bg: "rgba(47,212,143,.12)", icon: "↘", label: "Improving" },
    stable: { color: "#ffb020", bg: "rgba(255,176,32,.12)", icon: "→", label: "Stable" },
  }[trend] || { color: "#8295ae", bg: "rgba(130,149,174,.1)", icon: "–", label: "Unknown" };
  return (
    <span style={{
      background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}44`,
      borderRadius: 8, padding: "4px 10px", fontSize: 12, fontWeight: 700,
    }}>
      {cfg.icon} {cfg.label}
    </span>
  );
}

// Custom SVG time-of-day heatmap (24h × 7 days)
function TodHeatmap({ cells }) {
  const maxCount = useMemo(() => Math.max(1, ...cells.map((c) => c.count)), [cells]);
  const grid = useMemo(() => {
    const m = {};
    cells.forEach((c) => { m[`${c.dow}-${c.hour}`] = c; });
    return m;
  }, [cells]);

  const CELL_W = 24, CELL_H = 22, LABEL_W = 36, LABEL_H = 18;
  const W = LABEL_W + 24 * CELL_W + 4;
  const H = LABEL_H + 7 * CELL_H + 4;

  function cellColor(count, avg_risk) {
    if (!count) return "#0d1420";
    const intensity = count / maxCount;
    if (avg_risk >= 72) return `rgba(233,41,61,${0.2 + intensity * 0.75})`;
    if (avg_risk >= 55) return `rgba(255,176,32,${0.2 + intensity * 0.7})`;
    if (avg_risk >= 42) return `rgba(91,138,255,${0.2 + intensity * 0.65})`;
    return `rgba(47,212,143,${0.15 + intensity * 0.5})`;
  }

  return (
    <div style={{ overflowX: "auto" }}>
      <svg width={W} height={H} style={{ display: "block", margin: "0 auto" }}>
        {/* Hour labels */}
        {Array.from({ length: 24 }, (_, h) => (
          <text key={h} x={LABEL_W + h * CELL_W + CELL_W / 2} y={12}
            textAnchor="middle" fill="#56677e" fontSize={9}>
            {h % 4 === 0 ? `${h}h` : ""}
          </text>
        ))}
        {/* Day labels + cells */}
        {DAYS.map((day, dow) => (
          <g key={dow}>
            <text x={LABEL_W - 4} y={LABEL_H + dow * CELL_H + CELL_H / 2 + 4}
              textAnchor="end" fill="#8295ae" fontSize={10}>{day}</text>
            {Array.from({ length: 24 }, (_, h) => {
              const cell = grid[`${dow}-${h}`];
              const fill = cellColor(cell?.count || 0, cell?.avg_risk || 0);
              return (
                <g key={h}>
                  <rect
                    x={LABEL_W + h * CELL_W + 1}
                    y={LABEL_H + dow * CELL_H + 1}
                    width={CELL_W - 2} height={CELL_H - 2}
                    fill={fill} rx={3}
                  />
                  {cell && cell.count > 0 && (
                    <title>{day} {h}:00 — {cell.count} alerts, avg risk {cell.avg_risk}</title>
                  )}
                </g>
              );
            })}
          </g>
        ))}
      </svg>
      {/* Legend */}
      <div style={{ display: "flex", gap: 14, justifyContent: "center", marginTop: 8 }}>
        {[
          { label: "Critical (≥72)", color: "rgba(233,41,61,0.8)" },
          { label: "High (≥55)", color: "rgba(255,176,32,0.7)" },
          { label: "Medium (≥42)", color: "rgba(91,138,255,0.65)" },
          { label: "Low (<42)", color: "rgba(47,212,143,0.5)" },
          { label: "No alerts", color: "#0d1420" },
        ].map((l) => (
          <div key={l.label} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10.5, color: "#8295ae" }}>
            <div style={{ width: 12, height: 12, borderRadius: 2, background: l.color, border: "1px solid #283750" }} />
            {l.label}
          </div>
        ))}
      </div>
    </div>
  );
}

// Operator risk table with sort
function OperatorTable({ profiles }) {
  const [sort, setSort] = useState({ col: "avg_risk", dir: -1 });
  const sorted = useMemo(() => {
    return [...profiles].sort((a, b) => sort.dir * (b[sort.col] - a[sort.col]));
  }, [profiles, sort]);

  const col = (key, label) => (
    <th
      onClick={() => setSort((s) => ({ col: key, dir: s.col === key ? -s.dir : -1 }))}
      style={{ cursor: "pointer", userSelect: "none" }}
    >
      {label} {sort.col === key ? (sort.dir < 0 ? "↓" : "↑") : ""}
    </th>
  );

  return (
    <div style={{ overflowX: "auto" }}>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Operator</th>
            {col("avg_risk", "Avg Risk")}
            {col("flagged", "Flagged")}
            {col("critical", "Critical")}
            {col("total", "Total Changes")}
            {col("risk_ratio", "Risk Ratio")}
            {col("self_approved", "Self-Approved")}
            {col("off_hours", "Off-Hours")}
          </tr>
        </thead>
        <tbody>
          {sorted.map((op, i) => (
            <tr key={op.operator}>
              <td style={{ color: "#56677e", fontSize: 11 }}>{i + 1}</td>
              <td style={{ fontWeight: 600 }}>{op.operator}</td>
              <td>
                <span style={{ color: riskColor(op.avg_risk), fontWeight: 700, fontFamily: "var(--mono)" }}>
                  {op.avg_risk}
                </span>
              </td>
              <td>{op.flagged}</td>
              <td>
                {op.critical > 0 ? (
                  <span className="chip Critical" style={{ fontSize: 10.5 }}>{op.critical}</span>
                ) : "—"}
              </td>
              <td style={{ color: "#8295ae" }}>{op.total}</td>
              <td>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <div style={{ width: 60, height: 6, background: "#1c2738", borderRadius: 99 }}>
                    <div style={{
                      width: `${Math.min(100, op.risk_ratio * 100)}%`, height: "100%",
                      borderRadius: 99,
                      background: op.risk_ratio > 0.7 ? "#ff4d5e" : op.risk_ratio > 0.4 ? "#ffb020" : "#2fd48f",
                    }} />
                  </div>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{(op.risk_ratio * 100).toFixed(0)}%</span>
                </div>
              </td>
              <td>
                {op.self_approved > 0 ? (
                  <span className="chip High" style={{ fontSize: 10.5 }}>⚠ {op.self_approved}</span>
                ) : <span style={{ color: "#2fd48f", fontSize: 11 }}>✓ None</span>}
              </td>
              <td style={{ color: op.off_hours > 0 ? "#ffb020" : "#56677e" }}>
                {op.off_hours > 0 ? op.off_hours : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function ThreatIntel() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    api.threatIntel().then(setData).catch((e) => setErr(String(e)));
  }, []);

  if (err) return <div className="empty">Error: {err}</div>;
  if (!data) return <div className="empty"><div className="spinner" style={{ margin: "0 auto 12px" }} />Loading threat intelligence…</div>;

  const { mttr, operator_profiles, heatmap_cells, drift_velocity, drift_trend,
    top_exposures, change_reason, compliance_gaps } = data;

  // MTTR coloring
  const mttrColor = (days) => days > 60 ? "#ff4d5e" : days > 21 ? "#ffb020" : "#2fd48f";

  // Drift velocity summary KPIs
  const lastWeek = drift_velocity[drift_velocity.length - 1] || {};
  const firstWeek = drift_velocity[0] || {};
  const avgMTTR = mttr.length
    ? (mttr.reduce((s, x) => s + x.avg_days, 0) / mttr.length).toFixed(1)
    : "–";
  const worstExposure = top_exposures[0]?.days?.toFixed(0) || "–";

  return (
    <div className="fade-in">
      {/* Summary KPI strip */}
      <div className="grid kpis" style={{ marginBottom: 14 }}>
        {[
          { val: `${avgMTTR}d`, lbl: "Avg MTTR (all families)", accent: avgMTTR > 30 ? "red" : "green" },
          { val: `${worstExposure}d`, lbl: "Worst exposure window", accent: "red" },
          { val: `${(lastWeek.rate * 100 || 0).toFixed(1)}%`, lbl: "This week's drift rate", accent: "amber" },
          {
            val: operator_profiles.filter((o) => o.self_approved > 0).length,
            lbl: "Operators w/ self-approvals", accent: "amber",
          },
          { val: compliance_gaps.reduce((s, g) => s + g.open, 0), lbl: "Open compliance violations", accent: "red" },
          {
            val: <TrendBadge trend={drift_trend} />,
            lbl: "Posture trend (52w)", accent: "blue",
          },
        ].map(({ val, lbl, accent }) => (
          <div key={lbl} className={`card kpi accent-${accent}`}>
            <div className="val" style={{ fontSize: typeof val === "string" && val.length > 5 ? 20 : undefined }}>
              {val}
            </div>
            <div className="lbl">{lbl}</div>
          </div>
        ))}
      </div>

      {/* Row 1: MTTR + Change Reason */}
      <div className="grid row-2" style={{ marginBottom: 14 }}>
        <div className="card">
          <h3>Mean time to remediate (MTTR) per control family</h3>
          <div className="note" style={{ marginBottom: 10 }}>
            Derived from exposure-window pairing — how long each degraded control stayed open before restoration.
            Industry target: &lt;7 days for Critical families.
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={mttr} layout="vertical" margin={{ left: 10, right: 30, top: 4, bottom: 4 }}>
              <CartesianGrid stroke="#1c2738" strokeDasharray="3 6" horizontal={false} />
              <XAxis type="number" tick={{ fill: "#56677e", fontSize: 10 }} axisLine={false} tickLine={false}
                label={{ value: "days", fill: "#56677e", fontSize: 10, position: "insideRight", offset: -5 }} />
              <YAxis type="category" dataKey="family" width={116}
                tick={{ fill: "#8295ae", fontSize: 11 }} axisLine={false} tickLine={false}
                tickFormatter={(v) => v.replace("_", " ")} />
              <Tooltip contentStyle={tooltipStyle}
                formatter={(v, n) => [`${v} days`, n === "avg_days" ? "Avg MTTR" : "Worst case"]} />
              <Bar dataKey="avg_days" name="avg_days" radius={[0, 6, 6, 0]} barSize={14}>
                {mttr.map((m) => (
                  <Cell key={m.family} fill={mttrColor(m.avg_days)} />
                ))}
              </Bar>
              <Bar dataKey="worst_days" name="worst_days" radius={[0, 6, 6, 0]} barSize={6}
                fill="rgba(255,77,94,.3)" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3>Change reason → risk correlation</h3>
          <div className="note" style={{ marginBottom: 10 }}>
            Which stated justifications produce the riskiest outcomes in practice.
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 8 }}>
            {change_reason.map((cr) => (
              <div key={cr.reason}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontSize: 13, fontWeight: 600 }}>{cr.reason}</span>
                  <div style={{ display: "flex", gap: 8, fontSize: 11 }}>
                    <span style={{ color: riskColor(cr.avg_risk), fontWeight: 700 }}>
                      avg {cr.avg_risk}
                    </span>
                    <span style={{ color: "#56677e" }}>
                      {cr.flagged}/{cr.total} flagged
                    </span>
                  </div>
                </div>
                <div style={{ height: 7, background: "#1c2738", borderRadius: 99 }}>
                  <div style={{
                    width: `${cr.flag_rate * 100}%`, height: "100%", borderRadius: 99,
                    background: `linear-gradient(90deg, ${riskColor(cr.avg_risk)}, ${riskColor(cr.avg_risk)}88)`,
                    transition: "width .6s ease",
                  }} />
                </div>
                <div style={{ fontSize: 10.5, color: "#56677e", marginTop: 2 }}>
                  {(cr.flag_rate * 100).toFixed(0)}% flag rate
                  {cr.critical > 0 && (
                    <span style={{ color: "#ff4d5e", marginLeft: 8 }}>● {cr.critical} critical</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 2: Time-of-day heatmap (full width) */}
      <div className="card" style={{ marginBottom: 14 }}>
        <h3>Attack pattern heatmap — when do risky changes happen?</h3>
        <div className="note" style={{ marginBottom: 12 }}>
          Flagged drift events by hour of day × day of week. Colour intensity = alert volume; hue = severity.
          Red clusters outside business hours indicate off-hours activity (R5 signal).
        </div>
        <TodHeatmap cells={heatmap_cells} />
      </div>

      {/* Row 3: Drift velocity + Compliance gaps */}
      <div className="grid row-2" style={{ marginBottom: 14 }}>
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
            <h3 style={{ margin: 0 }}>Drift velocity — weekly detection rate (52 weeks)</h3>
            <TrendBadge trend={drift_trend} />
          </div>
          <div className="note" style={{ marginBottom: 10 }}>
            Weekly drift rate (blue) vs 4-week rolling average (red). Upward trend = posture degrading.
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={drift_velocity} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
              <CartesianGrid stroke="#1c2738" strokeDasharray="3 6" vertical={false} />
              <XAxis dataKey="week" tick={{ fill: "#56677e", fontSize: 9 }} tickLine={false} axisLine={false} interval={7} />
              <YAxis tick={{ fill: "#56677e", fontSize: 10 }} tickLine={false} axisLine={false}
                tickFormatter={(v) => `${(v * 100).toFixed(0)}%`} />
              <Tooltip contentStyle={tooltipStyle}
                formatter={(v) => `${(v * 100).toFixed(1)}%`} />
              <Line type="monotone" dataKey="rate" name="Weekly rate" stroke="#5b8aff"
                strokeWidth={1.5} dot={false} />
              <Line type="monotone" dataKey="rolling" name="4w rolling avg" stroke="#e9293d"
                strokeWidth={2.5} dot={false} strokeDasharray="4 2" />
              <Legend wrapperStyle={{ fontSize: 11, color: "#8295ae", paddingTop: 8 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3>Compliance gap analysis — open violations per framework</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 14, marginTop: 4 }}>
            {compliance_gaps.map((g) => (
              <div key={g.framework}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                  <span style={{ fontWeight: 700, fontSize: 13.5 }}>{g.framework}</span>
                  <div style={{ fontSize: 11, display: "flex", gap: 10 }}>
                    <span style={{ color: "#ff4d5e" }}>●&nbsp;{g.open} open</span>
                    <span style={{ color: "#2fd48f" }}>✓&nbsp;{g.resolved} resolved</span>
                  </div>
                </div>
                <div style={{ height: 8, background: "#1c2738", borderRadius: 99, position: "relative" }}>
                  <div style={{
                    position: "absolute", left: 0, top: 0, height: "100%", borderRadius: 99,
                    width: `${(g.resolved / Math.max(1, g.total)) * 100}%`,
                    background: "linear-gradient(90deg, #2fd48f, #38c8e8)",
                  }} />
                  <div style={{
                    position: "absolute", right: 0, top: 0, height: "100%", borderRadius: 99,
                    width: `${g.gap_pct}%`,
                    background: "linear-gradient(90deg, #ffb020, #ff4d5e)",
                  }} />
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 5 }}>
                  {g.refs.slice(0, 4).map((r) => (
                    <span key={r} className="chip fw" style={{ fontSize: 9.5 }}>{r}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 4: Top exposure chains */}
      <div className="card" style={{ marginBottom: 14 }}>
        <h3>Top 10 longest exposure chains — controls that stayed degraded longest</h3>
        <div className="note" style={{ marginBottom: 10 }}>
          Exposure window = time from degrading change to restore event (or still open).
          These are the exact breach patterns described in PS-02: logging off 6 months, firewall open 2 years.
        </div>
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th>Event</th><th>Control</th><th>Family</th>
                <th>Exposure</th><th>Status</th><th>Severity</th><th>Risk</th><th>Change Reason</th>
              </tr>
            </thead>
            <tbody>
              {top_exposures.map((ex) => (
                <tr key={ex.id}>
                  <td className="mono" style={{ fontSize: 11, color: "#56677e" }}>{ex.id}</td>
                  <td style={{ fontWeight: 600 }}>{ex.control}</td>
                  <td><span className="chip dim" style={{ fontSize: 10.5 }}>{ex.family.replace("_", " ")}</span></td>
                  <td>
                    <span style={{
                      fontFamily: "var(--mono)", fontWeight: 700,
                      color: ex.days > 90 ? "#ff4d5e" : ex.days > 30 ? "#ffb020" : "#5b8aff",
                    }}>
                      {ex.days}d
                    </span>
                  </td>
                  <td>
                    <span className={`chip ${ex.open ? "open" : "closed"}`} style={{ fontSize: 10.5 }}>
                      {ex.open ? "● OPEN" : "✓ Restored"}
                    </span>
                  </td>
                  <td><span className={`chip ${ex.severity}`} style={{ fontSize: 10.5 }}>{ex.severity}</span></td>
                  <td style={{ color: riskColor(ex.risk), fontWeight: 700, fontFamily: "var(--mono)" }}>
                    {ex.risk.toFixed(0)}
                  </td>
                  <td style={{ color: "#8295ae" }}>{ex.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Row 5: Operator risk table */}
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
          <h3 style={{ margin: 0 }}>Operator risk leaderboard</h3>
          <div className="note" style={{ margin: 0 }}>Click column headers to sort. Self-approved = segregation-of-duties violation (R4).</div>
        </div>
        <OperatorTable profiles={operator_profiles} />
      </div>
    </div>
  );
}
