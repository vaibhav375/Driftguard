import React, { useEffect, useRef, useState } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import RiskRing from "../components/RiskRing.jsx";
import { api, riskColor } from "../api.js";

const WS_URL = `ws://${location.host}/ws/stream`;

const CONTROL_TYPES = [
  "Logging", "Encryption", "Access_Control", "DLP", "Data_Protection",
  "Firewall", "Network_Segmentation", "Cloud_Security", "Endpoint", "Vulnerability",
];
const CHANGE_TYPES = ["Disable", "Remove", "Modify", "Add", "Update"];
const CHANGE_REASONS = [
  "Emergency Fix", "Performance Tuning", "Security Update",
  "Troubleshooting", "Routine Maintenance", "Compliance Requirement",
];
const STATUSES = ["Drifted", "Under_Review", "Compliant", "Mitigated", "Remediated"];

function IngestDemo() {
  const [form, setForm] = useState({
    control_type: "Logging",
    change_type: "Disable",
    change_reason: "Emergency Fix",
    status: "Drifted",
    self_approved: false,
    compliance_framework: "SOC2",
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  async function score() {
    setLoading(true);
    setErr(null);
    setResult(null);
    try {
      const res = await api.ingest(form);
      setResult(res);
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  }

  const SEL = {
    background: "#0a1018", color: "#e8eef7",
    border: "1px solid #283750", borderRadius: 8,
    padding: "7px 10px", fontSize: 12.5, width: "100%",
  };

  const triggered = result?.signals?.filter(s => s.points > 0) ?? [];
  const mitigants = result?.signals?.filter(s => s.points < 0) ?? [];

  return (
    <div className="card" style={{ marginTop: 14 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
        <div style={{
          background: "#ff4d5e22", border: "1px solid #ff4d5e44",
          borderRadius: 8, padding: "3px 10px", fontSize: 10.5,
          fontWeight: 700, color: "#ff4d5e", letterSpacing: "0.4px",
        }}>LIVE</div>
        <h3 style={{ margin: 0 }}>Real-Time Ingest Demo — Score any event in &lt;200ms</h3>
      </div>
      <div style={{ color: "#8295ae", fontSize: 12.5, marginBottom: 16 }}>
        POST a custom configuration change event to the{" "}
        <span style={{ fontFamily: "var(--mono)", color: "#5b8aff", fontSize: 11.5 }}>/api/ingest</span>{" "}
        endpoint. DriftGuard runs the full rule engine + ML pipeline and returns a scored result instantly —
        no batch processing, no delay.
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 10, marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 10, color: "#56677e", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.5px" }}>Control Family</div>
          <select style={SEL} value={form.control_type} onChange={e => set("control_type", e.target.value)}>
            {CONTROL_TYPES.map(t => <option key={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <div style={{ fontSize: 10, color: "#56677e", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.5px" }}>Change Type</div>
          <select style={SEL} value={form.change_type} onChange={e => set("change_type", e.target.value)}>
            {CHANGE_TYPES.map(t => <option key={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <div style={{ fontSize: 10, color: "#56677e", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.5px" }}>Change Reason</div>
          <select style={SEL} value={form.change_reason} onChange={e => set("change_reason", e.target.value)}>
            {CHANGE_REASONS.map(t => <option key={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <div style={{ fontSize: 10, color: "#56677e", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.5px" }}>Status</div>
          <select style={SEL} value={form.status} onChange={e => set("status", e.target.value)}>
            {STATUSES.map(t => <option key={t}>{t}</option>)}
          </select>
        </div>
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "flex-end" }}>
          <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: 12.5, color: "#c8d4e3" }}>
            <input
              type="checkbox"
              checked={form.self_approved}
              onChange={e => set("self_approved", e.target.checked)}
              style={{ width: 15, height: 15, accentColor: "#ff4d5e" }}
            />
            Self-approved (SoD violation)
          </label>
        </div>
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "flex-end" }}>
          <button
            className="btn"
            onClick={score}
            disabled={loading}
            style={{ width: "100%", opacity: loading ? 0.6 : 1 }}
          >
            {loading ? "Scoring…" : "⚡ Score It"}
          </button>
        </div>
      </div>

      {err && (
        <div style={{ color: "#ff4d5e", fontSize: 12, padding: "10px 14px", background: "#ff4d5e12", borderRadius: 8 }}>
          {err}
        </div>
      )}

      {result && (
        <div className="fade-in" style={{
          background: "var(--card-2)", borderRadius: 12, padding: "18px 20px",
          border: `1px solid ${riskColor(result.risk_score)}44`,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap", marginBottom: 16 }}>
            <div style={{ textAlign: "center" }}>
              <div style={{
                fontFamily: "var(--mono)", fontSize: 52, fontWeight: 900, lineHeight: 1,
                color: riskColor(result.risk_score),
              }}>
                {result.risk_score?.toFixed(0)}
              </div>
              <div style={{ fontSize: 10.5, color: "#56677e", marginTop: 4 }}>risk score</div>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 10, flexWrap: "wrap" }}>
                <span className={`chip ${result.predicted_severity}`} style={{ fontSize: 12 }}>
                  {result.predicted_severity}
                </span>
                {result.flagged && (
                  <span style={{
                    fontSize: 10, fontWeight: 700, color: "#ff4d5e",
                    background: "#ff4d5e18", padding: "3px 9px", borderRadius: 6,
                  }}>FLAGGED</span>
                )}
                <span style={{
                  fontFamily: "var(--mono)", fontSize: 11, color: "#2fd48f",
                  background: "#2fd48f15", padding: "3px 9px", borderRadius: 6,
                }}>
                  ⚡ {result.latency_ms?.toFixed(1)}ms
                </span>
              </div>
              <div style={{ fontSize: 12, color: "#c8d4e3", lineHeight: 1.55 }}>
                {result.explanation}
              </div>
            </div>
          </div>

          {triggered.length > 0 && (
            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 10, color: "#56677e", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: 6 }}>
                Triggered rules
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                {triggered.map((s, i) => (
                  <div key={i} style={{
                    display: "flex", alignItems: "flex-start", gap: 10,
                    background: "#0f1622", borderRadius: 8, padding: "8px 12px",
                    borderLeft: `3px solid ${riskColor(s.points * 2)}`,
                  }}>
                    <span style={{
                      fontFamily: "var(--mono)", fontSize: 10, fontWeight: 700,
                      color: "#5b8aff", flexShrink: 0, marginTop: 1,
                    }}>{s.rule}</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: 11.5, marginBottom: 2 }}>{s.name}</div>
                      <div style={{ fontSize: 11, color: "#8295ae", lineHeight: 1.45 }}>{s.reason}</div>
                    </div>
                    <span style={{
                      fontFamily: "var(--mono)", fontWeight: 800, fontSize: 13,
                      color: "#ffb020", flexShrink: 0,
                    }}>+{s.points}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {mitigants.length > 0 && (
            <div>
              <div style={{ fontSize: 10, color: "#56677e", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: 6 }}>
                Mitigating factors
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {mitigants.map((s, i) => (
                  <span key={i} style={{
                    fontSize: 11, color: "#2fd48f", background: "#2fd48f12",
                    padding: "3px 10px", borderRadius: 6,
                  }}>
                    {s.name} ({s.points})
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
const SPEED_OPTIONS = [
  { label: "Slow (2× — good for walkthroughs)", value: 8 },
  { label: "Normal (4× — live demo speed)", value: 16 },
  { label: "Fast (10× — quick overview)", value: 50 },
];

const tooltipStyle = {
  background: "#0f1622", border: "1px solid #283750", borderRadius: 10,
  fontSize: 12, color: "#e8eef7",
};

export default function LiveStream() {
  const wsRef = useRef(null);
  const [state, setState] = useState("idle"); // idle | running | paused | done
  const [speed, setSpeed] = useState(16);
  const [kpi, setKpi] = useState({ total: 0, flagged: 0, critical: 0, high: 0, open: 0 });
  const [progress, setProgress] = useState(0);
  const [recent, setRecent] = useState([]);  // last 8 events
  const [timeline, setTimeline] = useState([]); // weekly buckets
  const [alertFeed, setAlertFeed] = useState([]); // last 12 flagged

  const weekBuckets = useRef({});

  function connect() {
    if (wsRef.current) wsRef.current.close();
    weekBuckets.current = {};
    setKpi({ total: 0, flagged: 0, critical: 0, high: 0, open: 0 });
    setProgress(0);
    setRecent([]);
    setTimeline([]);
    setAlertFeed([]);
    setState("running");

    const ws = new WebSocket(`${WS_URL}?speed=${speed}`);
    wsRef.current = ws;

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === "done") { setState("done"); return; }
      if (msg.type !== "event") return;

      const ev = msg.event;
      setKpi(msg.kpi);
      setProgress(msg.progress);

      // Rolling recent feed (last 8)
      setRecent((prev) => [ev, ...prev].slice(0, 8));

      // Update flagged alert feed
      if (ev.flagged) {
        setAlertFeed((prev) => [ev, ...prev].slice(0, 14));
      }

      // Weekly timeline bucket
      const week = ev.change_date.slice(0, 7); // YYYY-MM
      const bk = weekBuckets.current;
      if (!bk[week]) bk[week] = { week, total: 0, flagged: 0, critical: 0, high: 0, benign: 0 };
      bk[week].total++;
      if (ev.flagged) {
        bk[week].flagged++;
        if (ev.predicted_severity === "Critical") bk[week].critical++;
        else if (ev.predicted_severity === "High") bk[week].high++;
      } else {
        bk[week].benign++;
      }
      setTimeline(Object.values(bk).sort((a, b) => a.week.localeCompare(b.week)));
    };

    ws.onclose = () => setState((s) => s === "running" ? "done" : s);
  }

  function toggle() {
    if (state === "running") {
      wsRef.current?.send(JSON.stringify({ cmd: "pause" }));
      setState("paused");
    } else if (state === "paused") {
      wsRef.current?.send(JSON.stringify({ cmd: "resume" }));
      setState("running");
    }
  }

  function stop() {
    wsRef.current?.send(JSON.stringify({ cmd: "stop" }));
    wsRef.current?.close();
    setState("idle");
  }

  useEffect(() => () => wsRef.current?.close(), []);

  const SEV = { Critical: "#ff4d5e", High: "#ffb020", Medium: "#5b8aff", Low: "#2fd48f" };

  return (
    <div className="fade-in">
      <div className="card" style={{ marginBottom: 14 }}>
        <h3 style={{ marginBottom: 10 }}>365-day live stream replay — watch DriftGuard score events in real time</h3>
        <div style={{ color: "#8295ae", fontSize: 13, marginBottom: 14 }}>
          The engine replays all 1,000 configuration changes chronologically, scoring each against the
          rule engine + IsolationForest and animating the dashboard live. This demonstrates{" "}
          <b>sub-second time lag</b> — the PS-02 target is &lt;1 hour.
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          {state === "idle" || state === "done" ? (
            <>
              <select
                value={speed}
                onChange={(e) => setSpeed(Number(e.target.value))}
                style={{ background: "#0f1622", color: "#e8eef7", border: "1px solid #283750", borderRadius: 9, padding: "8px 12px", fontSize: 12.5 }}
              >
                {SPEED_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              <button className="btn" onClick={connect}>
                {state === "done" ? "↺ Replay from start" : "▶ Start stream"}
              </button>
            </>
          ) : (
            <>
              <button className="btn ghost" onClick={toggle}>
                {state === "paused" ? "▶ Resume" : "⏸ Pause"}
              </button>
              <button className="btn ghost" style={{ borderColor: "#ff4d5e33", color: "#ff4d5e" }} onClick={stop}>
                ■ Stop
              </button>
            </>
          )}
          {(state === "running" || state === "paused") && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 200 }}>
              <div style={{ flex: 1, height: 6, background: "#1c2738", borderRadius: 99 }}>
                <div style={{ width: `${progress}%`, height: "100%", borderRadius: 99, background: "linear-gradient(90deg, #e9293d, #5b8aff)", transition: "width .3s" }} />
              </div>
              <span style={{ color: "#56677e", fontSize: 11.5, minWidth: 40 }}>{progress.toFixed(0)}%</span>
            </div>
          )}
        </div>
      </div>

      {/* Live KPI strip */}
      <div className="grid kpis" style={{ marginBottom: 14 }}>
        {[
          { val: kpi.total, lbl: "Events processed", accent: "blue" },
          { val: kpi.flagged, lbl: "Risky drifts detected", accent: "amber" },
          { val: kpi.critical, lbl: "Critical alerts", accent: "red" },
          { val: kpi.high, lbl: "High alerts", accent: "amber" },
          { val: kpi.open, lbl: "Open / unresolved", accent: "red" },
          {
            val: kpi.total > 0 ? `${((kpi.flagged / kpi.total) * 100).toFixed(1)}%` : "—",
            lbl: "Drift rate",
            accent: "cyan",
          },
        ].map(({ val, lbl, accent }) => (
          <div key={lbl} className={`card kpi accent-${accent}`}>
            <div className="val" style={{ transition: "all .2s" }}>{val}</div>
            <div className="lbl">{lbl}</div>
          </div>
        ))}
      </div>

      <div className="grid row-2" style={{ marginBottom: 14 }}>
        {/* Live timeline */}
        <div className="card">
          <h3>Monthly drift volume — live build</h3>
          {timeline.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={timeline} margin={{ top: 5, right: 8, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="gCrit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ff4d5e" stopOpacity={0.7} />
                    <stop offset="100%" stopColor="#ff4d5e" stopOpacity={0.05} />
                  </linearGradient>
                  <linearGradient id="gH" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ffb020" stopOpacity={0.6} />
                    <stop offset="100%" stopColor="#ffb020" stopOpacity={0.04} />
                  </linearGradient>
                  <linearGradient id="gB" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#2fd48f" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#2fd48f" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#1c2738" strokeDasharray="3 6" vertical={false} />
                <XAxis dataKey="week" tick={{ fill: "#56677e", fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: "#56677e", fontSize: 10 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="benign" name="Benign" stackId="1" stroke="#2fd48f" fill="url(#gB)" strokeWidth={1.4} />
                <Area type="monotone" dataKey="high" name="High" stackId="1" stroke="#ffb020" fill="url(#gH)" strokeWidth={1.4} />
                <Area type="monotone" dataKey="critical" name="Critical" stackId="1" stroke="#ff4d5e" fill="url(#gCrit)" strokeWidth={1.6} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty" style={{ paddingTop: 60 }}>
              {state === "idle" ? "Start the stream to see the timeline build live." : "Waiting for data…"}
            </div>
          )}
        </div>

        {/* Live alert feed */}
        <div className="card" style={{ overflow: "hidden" }}>
          <h3>Live alert feed — flagged drifts as they arrive</h3>
          <div style={{ maxHeight: 270, overflowY: "auto" }}>
            {alertFeed.map((ev, i) => (
              <div
                key={ev.drift_event_id + i}
                className="fade-in"
                style={{ display: "flex", alignItems: "center", gap: 10, padding: "7px 0", borderBottom: "1px solid #1c2738" }}
              >
                <RiskRing score={ev.risk_score} size={38} stroke={4} fontSize="11px" />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {ev.control_name} · {ev.control_type.replaceAll("_", " ")}
                  </div>
                  <div style={{ color: "#56677e", fontSize: 11 }}>{ev.change_date?.slice(0, 16)}</div>
                </div>
                <span className={`chip ${ev.predicted_severity}`}>{ev.predicted_severity}</span>
              </div>
            ))}
            {alertFeed.length === 0 && (
              <div className="empty" style={{ fontSize: 12.5 }}>No alerts yet…</div>
            )}
          </div>
        </div>
      </div>

      <IngestDemo />

      {/* Recent events ticker */}
      <div className="card" style={{ marginTop: 14 }}>
        <h3>Event ticker — last 8 changes (all types, real-time)</h3>
        <table>
          <thead>
            <tr>
              <th>Event</th><th>Control</th><th>Family</th><th>Change</th>
              <th>Reason</th><th>Risk</th><th>Verdict</th>
            </tr>
          </thead>
          <tbody>
            {recent.map((ev, i) => (
              <tr key={ev.drift_event_id + i} className="fade-in">
                <td className="mono">{ev.drift_event_id}</td>
                <td>{ev.control_name}</td>
                <td><span className="chip dim">{ev.control_type?.replaceAll("_", " ")}</span></td>
                <td style={{ color: ev.change_type === "Disable" || ev.change_type === "Remove" ? "#ff4d5e" : "#8295ae" }}>
                  {ev.change_type}
                </td>
                <td style={{ color: "#8295ae" }}>{ev.change_reason}</td>
                <td style={{ color: ev.risk_score >= 72 ? "#ff4d5e" : ev.risk_score >= 55 ? "#ffb020" : ev.risk_score >= 40 ? "#5b8aff" : "#2fd48f", fontWeight: 700 }}>
                  {ev.risk_score?.toFixed(0)}
                </td>
                <td>
                  <span className={`chip ${ev.flagged ? ev.predicted_severity : "closed"}`}>
                    {ev.flagged ? ev.predicted_severity : "Benign"}
                  </span>
                </td>
              </tr>
            ))}
            {recent.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: "center", color: "#56677e", padding: 24 }}>
                {state === "idle" ? "Start the stream to see events appear here." : "Waiting for events…"}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
