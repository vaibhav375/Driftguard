const BASE = "";

async function get(path) {
  const r = await fetch(BASE + path);
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

export const api = {
  summary: () => get("/api/summary"),
  metrics: () => get("/api/metrics"),
  alerts: (params = {}) => {
    const q = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, v]) => v))
    ).toString();
    return get(`/api/alerts${q ? "?" + q : ""}`);
  },
  baselines: () => get("/api/baselines"),
  playbook: () => get("/api/playbook"),
  reportText: async () => {
    const r = await fetch("/api/report");
    return r.text();
  },
  simulate: async (body) => {
    const r = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error("simulate failed");
    return r.json();
  },
  ask: (q) => get(`/api/ask?q=${encodeURIComponent(q)}`),
  threatIntel: () => get("/api/threat-intel"),
  attackIntel: () => get("/api/attack-intel"),
  ingest: async (body) => {
    const r = await fetch("/api/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error("ingest failed");
    return r.json();
  },
  exportAlerts: () => { window.open("/api/export", "_blank"); },
};

export const SEV_COLOR = {
  Critical: "#ff4d5e",
  High: "#ffb020",
  Medium: "#5b8aff",
  Low: "#2fd48f",
};

export function riskColor(score) {
  if (score >= 72) return "#ff4d5e";
  if (score >= 55) return "#ffb020";
  if (score >= 42) return "#5b8aff";
  return "#2fd48f";
}
