import React, { useEffect, useState } from "react";
import { api } from "../api.js";

export default function Playbook() {
  const [pb, setPb] = useState(null);
  const [report, setReport] = useState(null);

  useEffect(() => {
    api.playbook().then(setPb);
  }, []);

  async function downloadReport() {
    const text = report || (await api.reportText());
    setReport(text);
    const blob = new Blob([text], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "DriftGuard_Audit_Report.md";
    a.click();
  }

  if (!pb) return <div className="empty">Loading playbook…</div>;

  return (
    <div className="fade-in">
      <div className="card" style={{ marginBottom: 14, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
        <div>
          <h3 style={{ marginBottom: 4 }}>Audit report</h3>
          <div className="note">Full markdown audit report: executive summary, detection metrics, top drifts with impact, playbook, and data-quality findings.</div>
        </div>
        <button className="btn" onClick={downloadReport}>⬇ Download audit report (.md)</button>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(330px, 1fr))" }}>
        {Object.entries(pb).map(([family, rem]) => (
          <div className="card" key={family}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <h3>{family.replaceAll("_", " ")}</h3>
              <span className="chip dim">SLA {rem.sla_hours}h</span>
            </div>
            <div style={{ fontSize: 13, lineHeight: 1.6, marginBottom: 10, color: "#cdd9e8" }}>
              {rem.action}
            </div>
            <ol style={{ paddingLeft: 18, display: "grid", gap: 6 }}>
              {rem.steps.map((s, i) => (
                <li key={i} style={{ fontSize: 12.5, color: "#8295ae", lineHeight: 1.55 }}>{s}</li>
              ))}
            </ol>
          </div>
        ))}
      </div>
    </div>
  );
}
