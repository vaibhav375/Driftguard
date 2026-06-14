import React from "react";
import { riskColor } from "../api.js";

export default function RiskRing({ score, size = 46, stroke = 4.5, fontSize }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = riskColor(score);
  return (
    <div className="risk-ring" style={{ width: size, height: size }}>
      <svg width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1c2738" strokeWidth={stroke} />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke={color} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - score / 100)}
          style={{ transition: "stroke-dashoffset .7s ease" }}
        />
      </svg>
      <div className="num" style={{ color, fontSize }}>{Math.round(score)}</div>
    </div>
  );
}
