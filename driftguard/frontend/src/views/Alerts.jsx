import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import AlertCard from "../components/AlertCard.jsx";

const CONTROL_TYPES = [
  "Firewall", "Logging", "Encryption", "Access_Control", "Cloud_Security",
  "DLP", "Data_Protection", "Endpoint", "Network_Segmentation", "Vulnerability",
];

export default function Alerts() {
  const [filters, setFilters] = useState({ severity: "", control_type: "", status: "open", q: "" });
  const [data, setData] = useState(null);

  useEffect(() => {
    let live = true;
    api.alerts({ ...filters, limit: 60 }).then((d) => live && setData(d));
    return () => { live = false; };
  }, [filters]);

  const set = (k) => (e) => setFilters((f) => ({ ...f, [k]: e.target.value }));

  return (
    <div className="fade-in">
      <div className="filters">
        <select value={filters.status} onChange={set("status")}>
          <option value="">All statuses</option>
          <option value="open">Open (Drifted / Under review)</option>
          <option value="closed">Closed (Remediated / Mitigated / Compliant)</option>
        </select>
        <select value={filters.severity} onChange={set("severity")}>
          <option value="">All severities</option>
          <option>Critical</option><option>High</option><option>Medium</option>
        </select>
        <select value={filters.control_type} onChange={set("control_type")}>
          <option value="">All control families</option>
          {CONTROL_TYPES.map((c) => <option key={c} value={c}>{c.replaceAll("_", " ")}</option>)}
        </select>
        <input placeholder="Search operator, control, event id…" value={filters.q} onChange={set("q")} />
      </div>

      {!data ? (
        <div className="empty">Loading alerts…</div>
      ) : (
        <>
          <div className="note" style={{ marginBottom: 12 }}>
            {data.total} alerts match — sorted by live priority (detection risk + lifecycle state).
            Click any alert for the full signal breakdown.
          </div>
          {data.alerts.map((a) => <AlertCard key={a.drift_event_id} alert={a} />)}
          {data.alerts.length === 0 && <div className="empty">No alerts match the current filters.</div>}
        </>
      )}
    </div>
  );
}
