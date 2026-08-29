"""Deterministic trend detection + AI narration for the Admin host-metrics
and AI-usage graphs.

Trend detection (percent change, slope, threshold projection) is plain
Python arithmetic over already-collected data from app.host_metrics — the
LLM never computes or invents a trend, it only turns already-computed
numbers into a short readable summary, via the same provider-agnostic
app.llm interface used elsewhere in the app.
"""

from __future__ import annotations

import json


def compute_trend(series: list[dict], threshold: float = 90.0) -> dict:
    """Return start/end/pct_change/slope_per_day/days_to_threshold for one
    bucketed metric series ({"ts": int, "v": float|None} points, ordered).

    All fields are None when fewer than 2 non-null points are available.
    slope_per_day is 0.0 for a flat series, negative for a falling series;
    days_to_threshold is 0.0 when the series is already at/above the
    threshold, a projected day count when rising toward it, and None when
    flat or falling and still below the threshold.
    """
    points = [(p["ts"], p["v"]) for p in series if p.get("v") is not None]
    if len(points) < 2:
        return {
            "start": None,
            "end": None,
            "pct_change": None,
            "slope_per_day": None,
            "days_to_threshold": None,
        }

    start_ts, start_v = points[0]
    end_ts, end_v = points[-1]
    span_days = (end_ts - start_ts) / 86400.0

    pct_change = ((end_v - start_v) / start_v * 100.0) if start_v else 0.0
    slope_per_day = (end_v - start_v) / span_days if span_days > 0 else 0.0

    days_to_threshold = None
    if end_v >= threshold:
        days_to_threshold = 0.0
    elif slope_per_day > 0:
        days_to_threshold = round((threshold - end_v) / slope_per_day, 1)

    return {
        "start": round(start_v, 2),
        "end": round(end_v, 2),
        "pct_change": round(pct_change, 2),
        "slope_per_day": round(slope_per_day, 2),
        "days_to_threshold": days_to_threshold,
    }


def build_trend_narrative(
    trends: dict, ai_usage_summary: dict, user: str | None = None
) -> str:
    """Return an AI-written trend summary for the Admin page's host-metrics
    and AI-usage graphs.

    Raises whatever the configured provider's narrate() raises — callers
    must catch this and continue without a narrative.
    """
    from app.llm import get_provider

    payload = {
        "trends": trends,
        "ai_usage": {
            "total_calls": ai_usage_summary.get("total_calls", 0),
            "total_cost_usd": ai_usage_summary.get("total_cost_usd", 0.0),
            "total_failures": ai_usage_summary.get("total_failures", 0),
        },
    }

    provider = get_provider()
    return provider.narrate(
        system_prompt=(
            "You are an infrastructure monitoring assistant for the admin "
            "of a small internal web application. You are given "
            "already-computed 7-day trend statistics for host CPU, "
            "memory, and disk usage (percent, percent change, slope per "
            "day, and a naive days-until-90%-threshold projection when "
            "rising), plus AI-feature usage/cost stats, as JSON. Write a "
            "short summary (2-4 sentences) highlighting anything that "
            "needs attention — a metric trending toward its threshold, an "
            "unusual cost/failure count — or state that everything looks "
            "stable if nothing stands out. Never invent a number not "
            "present in the JSON."
        ),
        user_prompt=json.dumps(payload, default=str),
        feature="host_metrics_ai_summary",
        user=user,
    )
