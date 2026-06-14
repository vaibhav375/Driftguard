import React, { useEffect, useState } from "react";
import { api } from "../api.js";

export default function Controls({ summary }) {
  const [baselines, setBaselines] = useState(null);
  const [q, setQ] = useState("");

  useEffect(() => { api.baselines().then(setBaselines); }, []);

  if (!baselines) return <div className="empty">Loading baseline store…</div>;

  const healthByType = Object.fromEntries(
    summary.control_health.map((h) => [h.control_type, h])
  );
  const rows = baselines.filter(
    (b) => !q || JSON.stringify(b).toLowerCase().includes(q.toLowerCase())
  );

  return (
    <div className="fade-in">
      <div className="filters">
        <input placeholder="Search controls…" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="badge">{rows.length} controls in baseline store</span>
      </div>
      <div className="card">
        <h3>Baseline configuration store — single source of truth</h3>
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th>Control</th><th>System</th><th>Baseline config</th>
                <th>Criticality</th><th>Compliance mappings</th><th>Family health</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((b) => {
                const h = healthByType[b.control_type];
                return (
                  <tr key={b.control_id}>
                    <td>
                      <b>{b.control_name}</b>
                      <div className="mono" style={{ color: "#56677e" }}>{b.control_id}</div>
                    </td>
                    <td>{b.system}</td>
                    <td className="mono" style={{
                      maxWidth: 260, color: "#8295ae",
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      fontSize: 11,
                    }}
                      title={JSON.stringify(b.baseline_config)}
                    >
                      {JSON.stringify(b.baseline_config)}
                    </td>
                    <td>
                      <span className={`chip ${b.criticality === "high" ? "Critical" : "Medium"}`}>
                        {b.criticality}
                      </span>
                    </td>
                    <td style={{ maxWidth: 230 }}>
                      {(b.compliance_mappings || []).map((m, i) => (
                        <span className="chip fw" style={{ margin: "2px 3px 2px 0" }} key={i}>{m}</span>
                      ))}
                    </td>
                    <td className="mono" style={{ color: h && h.health < 90 ? "#ffb020" : "#2fd48f" }}>
                      {h ? `${h.health}%` : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
