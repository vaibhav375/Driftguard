import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import { riskColor } from "../api.js";

const SPEEDS = { "30s": 12.17, "60s": 6.08, "120s": 3.04 }; // days per tick (200ms)
const TICK_MS = 200;

const tooltipStyle = {
  background: "#0f1622", border: "1px solid #283750", borderRadius: 10,
  fontSize: 12, color: "#e8eef7",
};

export default function Replay() {
  const [events, setEvents] = useState(null);
  const [cursor, setCursor] = useState(0);       // index of next event to ingest
  const [simTime, setSimTime] = useState(null);  // ms epoch of simulated "now"
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState("60s");
  const timerRef = useRef(null);

  useEffect(() => {
    fetch("/api/events")
      .then((r) => r.json())
      .then((evs) => {
        const sorted = [...evs].sort((a, b) => new Date(a.change_date) - new Date(b.change_date));
        setEvents(sorted);
        setSimTime(new Date(sorted[0].change_date).getTime());
      });
  }, []);

  useEffect(() => {
    if (!playing || !events) return;
    timerRef.current = setInterval(() => {
      setSimTime((t) => t + SPEEDS[speed] * 86400e3);
    }, TICK_MS);
    return () => clearInterval(timerRef.current);
  }, [playing, speed, events]);

  // advance cursor to match simTime
  useEffect(() => {
    if (!events || simTime == null) return;
    let c = cursor;
    while (c < events.length && new Date(events[c].change_date).getTime() <= simTime) c++;
    if (c !== cursor) setCursor(c);
    if (c >= events.length && playing) setPlaying(false);
  }, [simTime, events]); // eslint-disable-line

  const ingested = useMemo(() => (events ? events.slice(0, cursor) : []), [events, cursor]);

  const stats = useMemo(() => {
    let flagged = 0, critical = 0, open = 0;
    for (const e of ingested) {
      if (e.flagged) {
        flagged++;
        if (e.predicted_severity === "Critical") critical++;
        if (e.status === "Drifted" || e.status === "Under_Review") open++;
      }
    }
    return { total: ingested.length, flagged, critical, open };
  }, [ingested]);

  const chartData = useMemo(() => {
    const buckets = new Map();
    for (const e of ingested) {
      const wk = e.change_date.slice(0, 7); // YYYY-MM
      const b = buckets.get(wk) || { month: wk, flagged: 0, benign: 0 };
      e.flagged ? b.flagged++ : b.benign++;
      buckets.set(wk, b);
    }
    return [...buckets.values()];
  }, [ingested]);

  const feed = useMemo(() => ingested.slice(-9).reverse(), [ingested]);

  if (!events) return <div className="empty">Loading 1,000 events…</div>;

  const startMs = new Date(events[0].change_date).getTime();
  const endMs = new Date(events[events.length - 1].change_date).getTime();
  const progress = Math.min(100, ((simTime - startMs) / (endMs - startMs)) * 100);
  const simDate = new Date(Math.min(simTime, endMs));

  function reset() {
    setPlaying(false);
    setCursor(0);
    setSimTime(startMs);
  }

  return (
    <div className="fade-in">
      <div className="card" style={{ display: "flex", alignItems: "center", gap: 18, flexWrap: "wrap" }}>
        <button className="btn" onClick={() => setPlaying(!playing)}>
          {playing ? "⏸ Pause" : cursor >= events.length ? "✓ Done" : "⏵ Play 365 days"}
        </button>
        <button className="btn ghost" onClick={reset}>↺ Reset</button>
        <div>
          <span style={{ color: "#56677e", fontSize: 11, textTransform: "uppercase", letterSpacing: 1 }}>Replay speed</span>
          <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
            {Object.keys(SPEEDS).map((s) => (
              <button key={s} className="btn ghost"
                style={{ padding: "4px 12px", fontSize: 12, borderColor: speed === s ? "#e9293d" : undefined }}
                onClick={() => setSpeed(s)}>
                {s}
              </button>
            ))}
          </div>
        </div>
        <div style={{ flex: 1, minWidth: 220 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
            <span className="mono" style={{ fontSize: 16, color: "#e8eef7" }}>
              {simDate.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })}
            </span>
            <span className="mono" style={{ color: "#56677e" }}>{Math.round(progress)}%</span>
          </div>
          <div className="bar" style={{ height: 10 }}>
            <div style={{ width: `${progress}%`, background: "linear-gradient(90deg,#e9293d,#ffb020)" }} />
          </div>
        </div>
      </div>

      <div className="grid kpis section-gap">
        <div className="card kpi accent-blue"><div className="val">{stats.total}</div><div className="lbl">Changes ingested</div></div>
        <div className="card kpi accent-amber"><div className="val">{stats.flagged}</div><div className="lbl">Risky drifts flagged</div></div>
        <div className="card kpi accent-red"><div className="val">{stats.critical}</div><div className="lbl">Critical alerts</div></div>
        <div className="card kpi accent-red"><div className="val">{stats.open}</div><div className="lbl">Open exposure</div></div>
      </div>

      <div className="grid row-2 section-gap">
        <div className="card">
          <h3>Cumulative detections as the year streams in</h3>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={chartData} margin={{ top: 5, right: 8, left: -18, bottom: 0 }}>
              <defs>
                <linearGradient id="rFlag" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ff4d5e" stopOpacity={0.65} />
                  <stop offset="100%" stopColor="#ff4d5e" stopOpacity={0.04} />
                </linearGradient>
                <linearGradient id="rBenign" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#2fd48f" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#2fd48f" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#1c2738" strokeDasharray="3 6" vertical={false} />
              <XAxis dataKey="month" tick={{ fill: "#56677e", fontSize: 10 }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fill: "#56677e", fontSize: 10 }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area type="monotone" dataKey="benign" name="Benign" stroke="#2fd48f" fill="url(#rBenign)" strokeWidth={1.4} />
              <Area type="monotone" dataKey="flagged" name="Flagged drift" stroke="#ff4d5e" fill="url(#rFlag)" strokeWidth={1.8} />
            </AreaChart>
          </ResponsiveContainer>
          <div className="note">
            Each event is scored in &lt;1 ms on ingest — the PS asks for &lt;1 hour detection lag;
            DriftGuard's architecture is stream-native.
          </div>
        </div>

        <div className="card">
          <h3>Live event ticker</h3>
          {feed.length === 0 && <div className="empty">Press ⏵ Play to start the year…</div>}
          {feed.map((e) => (
            <div key={e.drift_event_id} className="fade-in"
              style={{
                display: "flex", alignItems: "center", gap: 10, padding: "7px 10px",
                borderLeft: `3px solid ${e.flagged ? riskColor(e.risk_score) : "#1c2738"}`,
                background: e.flagged ? "rgba(255,77,94,0.04)" : "transparent",
                borderRadius: 6, marginBottom: 5,
              }}>
              <span className="mono" style={{ color: "#56677e", fontSize: 10.5, width: 78, flexShrink: 0 }}>
                {e.change_date.slice(0, 10)}
              </span>
              <span style={{ flex: 1, fontSize: 12 }}>
                <b>{e.control_name}</b>{" "}
                <span style={{ color: "#8295ae" }}>{e.change_type} · {e.change_reason}</span>
              </span>
              {e.flagged ? (
                <span className={`chip ${e.predicted_severity}`}>{Math.round(e.risk_score)} · {e.predicted_severity}</span>
              ) : (
                <span className="chip dim">benign</span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
