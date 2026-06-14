"""DriftGuard — 30-day per-family drift risk forecasting.

Uses the past 52 weeks of per-family weekly flag rates to fit a LinearRegression
and project 4 weeks ahead (≈ 30 days), giving SOC teams a proactive early-warning
signal for control families that are trending toward increased drift.

Most security tools are purely reactive. This module flips the posture.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression


def forecast_family_drift(scored: pd.DataFrame) -> list[dict]:
    """Predict next-30-day drift risk per control family.

    Returns a list sorted by predicted_30d_rate descending so the "most at-risk"
    families surface first.
    """
    s = scored.copy()
    s["week"] = s["change_date"].dt.to_period("W").dt.start_time

    forecasts = []
    for family, grp in s.groupby("control_type"):
        weekly = (
            grp.groupby("week")
            .agg(total=("drift_event_id", "count"), flagged=("flagged", "sum"))
            .reset_index()
            .sort_values("week")
        )
        weekly["rate"] = (weekly["flagged"] / weekly["total"].clip(1)).round(3)
        n = len(weekly)

        # Current rate — 4-week trailing average (or all weeks if fewer than 4)
        current_rate = (
            float(weekly["rate"].iloc[-4:].mean()) if n >= 4
            else float(weekly["rate"].mean())
        )

        if n >= 8:
            X = np.arange(n).reshape(-1, 1)
            y = weekly["rate"].values
            reg = LinearRegression().fit(X, y)
            pred_x = np.arange(n, n + 4).reshape(-1, 1)
            predicted_30d = float(np.clip(reg.predict(pred_x).mean(), 0.0, 1.0))
            slope = float(reg.coef_[0])
        else:
            # Not enough data — use current rate as forecast
            predicted_30d = current_rate
            slope = 0.0

        # Trend classification
        if slope > 0.005:
            trend = "increasing"
        elif slope < -0.005:
            trend = "decreasing"
        else:
            trend = "stable"

        # Risk level bracket for the forecasted period
        if predicted_30d >= 0.55:
            risk_level = "critical"
        elif predicted_30d >= 0.40:
            risk_level = "high"
        elif predicted_30d >= 0.22:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Days since the last completely clean week (zero flags)
        clean_weeks = weekly[weekly["flagged"] == 0]
        if len(clean_weeks) > 0:
            last_clean = clean_weeks.iloc[-1]["week"]
            last_week = weekly.iloc[-1]["week"]
            days_since_clean = int((last_week - last_clean).days)
        else:
            days_since_clean = n * 7  # Never had a clean week in the dataset

        # Percentage change from current to predicted (positive = getting worse)
        change_pct = round(
            (predicted_30d - current_rate) / max(current_rate, 0.01) * 100, 1
        )

        forecasts.append({
            "family": family,
            "current_rate": round(current_rate, 3),
            "predicted_30d_rate": round(predicted_30d, 3),
            "change_pct": change_pct,
            "slope_per_week": round(slope, 5),
            "trend": trend,
            "risk_level": risk_level,
            "days_since_clean_week": days_since_clean,
            "weeks_of_data": n,
        })

    return sorted(forecasts, key=lambda x: -x["predicted_30d_rate"])
