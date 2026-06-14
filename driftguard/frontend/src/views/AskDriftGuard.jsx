import React, { useEffect, useRef, useState } from "react";
import { api } from "../api.js";

const SUGGESTIONS = [
  "Give me an overview of our security posture",
  "Why is Logging unhealthy?",
  "What are the top 5 most dangerous drifts?",
  "Show me all GDPR violations",
  "Which changes involved encryption or AES?",
  "Show me temporary changes that became permanent",
  "Who are the operators with the most risky changes?",
  "What firewall drifts are still open?",
  "How long was the worst exposure window?",
  "What NIST controls are being violated?",
];

const SAMPLE_MESSAGES = [
  {
    role: "system",
    content:
      "I'm **DriftGuard Intelligence** — I can answer natural-language questions about your 1,000 drift events, compliance exposure, operators, exposure windows, and remediation priorities. Ask me anything about your security posture.",
  },
];

export default function AskDriftGuard() {
  const [messages, setMessages] = useState(SAMPLE_MESSAGES);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const bottomRef = useRef(null);

  async function ask(q) {
    if (!q.trim() || busy) return;
    const question = q.trim();
    setInput("");
    setMessages((m) => [...m, { role: "user", content: question }]);
    setBusy(true);
    try {
      const res = await api.ask(question);
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: res.answer,
          topEvents: res.top_events || [],
          recommendation: res.recommendation,
        },
      ]);
    } catch (e) {
      setMessages((m) => [...m, { role: "assistant", content: "Error fetching answer. Is the backend running?" }]);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  return (
    <div className="fade-in" style={{ display: "flex", gap: 14, height: "calc(100vh - 130px)", minHeight: 500 }}>
      {/* Chat panel */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        <div
          className="card"
          style={{ flex: 1, overflow: "auto", marginBottom: 10, display: "flex", flexDirection: "column", gap: 12 }}
        >
          {messages.map((m, i) => (
            <div
              key={i}
              className="fade-in"
              style={{
                display: "flex",
                justifyContent: m.role === "user" ? "flex-end" : "flex-start",
              }}
            >
              {m.role !== "user" && (
                <div style={{
                  width: 30, height: 30, borderRadius: 8, background: "linear-gradient(135deg, #e9293d, #7a1430)",
                  display: "grid", placeItems: "center", fontSize: 14, flexShrink: 0, marginRight: 9, marginTop: 2
                }}>🛡</div>
              )}
              <div
                style={{
                  maxWidth: "76%",
                  background: m.role === "user" ? "linear-gradient(135deg, #1e2e4a, #172038)" : "var(--card-2)",
                  border: `1px solid ${m.role === "user" ? "#283750" : "#1c2738"}`,
                  borderRadius: m.role === "user" ? "14px 14px 4px 14px" : "4px 14px 14px 14px",
                  padding: "10px 14px",
                  fontSize: 13.5,
                  lineHeight: 1.65,
                }}
              >
                {m.role === "system" && (
                  <div style={{ color: "#56677e", fontSize: 11, fontWeight: 600, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.8px" }}>
                    DriftGuard Intelligence
                  </div>
                )}
                {/* Render bold markdown */}
                <div dangerouslySetInnerHTML={{
                  __html: m.content
                    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
                    .replace(/\n/g, "<br/>")
                }} />

                {/* Top events */}
                {m.topEvents && m.topEvents.length > 0 && (
                  <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 6 }}>
                    {m.topEvents.map((ev, j) => (
                      <div
                        key={j}
                        style={{
                          background: "rgba(233,41,61,.06)", border: "1px solid rgba(233,41,61,.2)",
                          borderRadius: 9, padding: "8px 12px", fontSize: 12.5,
                        }}
                      >
                        <span style={{ fontFamily: "JetBrains Mono, monospace", color: "#56677e" }}>{ev.id}</span>
                        {" · "}<b>{ev.name}</b>{" · "}<span className={`chip ${ev.severity}`} style={{ fontSize: 10.5 }}>{ev.severity}</span>
                        <div style={{ color: "#8295ae", marginTop: 3 }}>{ev.reason}</div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Recommendation */}
                {m.recommendation && (
                  <div style={{
                    marginTop: 10, background: "rgba(47,212,143,.05)",
                    border: "1px solid rgba(47,212,143,.2)", borderRadius: 8, padding: "8px 12px",
                    fontSize: 12.5, color: "#8295ae"
                  }}>
                    <b style={{ color: "#2fd48f" }}>⟲ Recommendation</b><br />
                    {m.recommendation}
                  </div>
                )}
              </div>
            </div>
          ))}
          {busy && (
            <div style={{ display: "flex", gap: 9, alignItems: "center" }}>
              <div style={{ width: 30, height: 30, borderRadius: 8, background: "linear-gradient(135deg, #e9293d, #7a1430)", display: "grid", placeItems: "center" }}>🛡</div>
              <div style={{ display: "flex", gap: 5 }}>
                {[0, 1, 2].map((n) => (
                  <div key={n} style={{
                    width: 7, height: 7, borderRadius: "50%", background: "#e9293d",
                    animation: `pulse 1.2s ${n * 0.2}s infinite`,
                  }} />
                ))}
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <div style={{ display: "flex", gap: 9 }}>
          <input
            style={{
              flex: 1, background: "var(--card)", color: "var(--text)", border: "1px solid var(--border-2)",
              borderRadius: 11, padding: "11px 15px", fontSize: 13.5, outline: "none", fontFamily: "Inter, sans-serif",
            }}
            placeholder="Ask about any drift, control family, compliance impact, operator…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && ask(input)}
          />
          <button className="btn" disabled={busy || !input.trim()} onClick={() => ask(input)}>
            Ask ↵
          </button>
        </div>
      </div>

      {/* Suggestions panel */}
      <div style={{ width: 230, flexShrink: 0 }}>
        <div className="card" style={{ height: "100%" }}>
          <h3 style={{ marginBottom: 10 }}>Try asking</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {SUGGESTIONS.map((s) => (
              <button
                key={s}
                className="btn ghost"
                style={{ textAlign: "left", fontSize: 12, padding: "8px 11px", lineHeight: 1.45 }}
                onClick={() => ask(s)}
              >
                {s}
              </button>
            ))}
          </div>
          <div className="note" style={{ marginTop: 12 }}>
            Powered by DriftGuard's insight engine — pattern-matched over live scored event data.
          </div>
        </div>
      </div>
    </div>
  );
}
