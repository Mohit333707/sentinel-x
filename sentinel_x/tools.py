"""Tools the agent can call. Each tool returns plain data; the LLM
(in live mode) or the labelled offline scorer (offline mode only)
decides what it means. No tool hard-codes a verdict.
"""
from __future__ import annotations
import json, re, urllib.parse
import pandas as pd
import requests
from .graph import build_evidence_graph, graph_summary

def parse_goal(goal: str) -> dict:
    """Extract IP / counts / hour / device from a plain-English goal."""
    ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", goal or "")
    failed = re.search(r"failed logins?\s*[:=]?\s*(\d+)", goal or "", re.I)
    success = re.search(r"successful login[s]?\s*[:=]?\s*(\d+)", goal or "", re.I)
    hour_m = re.search(r"(\d{1,2}):(\d{2})\s*(AM|PM)?", goal or "", re.I)
    hour = 2
    if hour_m:
        hour = int(hour_m.group(1))
        if hour_m.group(3) and hour_m.group(3).upper() == "PM" and hour < 12: hour += 12
        if hour_m.group(3) and hour_m.group(3).upper() == "AM" and hour == 12: hour = 0
    return {"ip": ip.group(0) if ip else "192.0.2.45",
            "failed_logins": int(failed.group(1)) if failed else 35,
            "successful_login": int(success.group(1)) if success else 1,
            "hour": hour,
            "device_known": "unknown" not in (goal or "").lower(),
            "country_change": "country" in (goal or "").lower() and "change" in (goal or "").lower()}

def read_alerts(path: str = "data/synthetic_traces.csv") -> list[dict]:
    """Read the synthetic trace table with pandas."""
    df = pd.read_csv(path)
    return df.to_dict(orient="records")

def analyse_logs(trace: dict) -> dict:
    """Summarise login logs for one trace with pandas."""
    df = pd.DataFrame([{
        "failed_logins": int(trace.get("failed_logins", 0)),
        "successful_login": int(trace.get("successful_login", 0)),
        "hour": int(trace.get("hour", 0)),
    }])
    total = int(df["failed_logins"].iloc[0] + df["successful_login"].iloc[0])
    return {"total_attempts": total,
            "failure_rate": round(float(df["failed_logins"].iloc[0] / total), 3) if total else 0.0,
            "failed_logins": int(df["failed_logins"].iloc[0]),
            "successful_login": int(df["successful_login"].iloc[0]),
            "hour": int(df["hour"].iloc[0]),
            "night_time": 0 <= int(df["hour"].iloc[0]) <= 5,
            "burst": int(df["failed_logins"].iloc[0]) >= 10}

def check_ip(ip: str) -> dict:
    """Look up an IP with the free ip-api.com API (no key). Never crashes."""
    if ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
        return {"ip": ip, "note": "TEST-NET documentation range (RFC 5737) — synthetic, no real lookup performed.",
                "country": "unknown (synthetic)", "org": "unknown (synthetic)", "status": "synthetic"}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        d = r.json()
        return {"ip": ip, "country": d.get("country"), "org": d.get("org"), "status": d.get("status")}
    except Exception as exc:
        return {"ip": ip, "error": str(exc), "status": "lookup_failed"}

def search_threat_intel(query: str, base_url: str | None = None, timeout: int = 10) -> dict:
    """Free DuckDuckGo HTML search (no key). Returns titles only; never crashes.

    `base_url` is only used by the deliberately-induced failure test
    (see `python main.py --demo --offline --simulate-failure threat-intel`):
    pointing it at a host that does not exist makes the request fail
    with a real network error, so the agent has to detect and recover.
    """
    try:
        base = base_url or "https://html.duckduckgo.com/html/?q="
        url = base + urllib.parse.quote(query)
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=timeout)
        titles = re.findall(r'class="result__a"[^>]*>([^<]+)<', r.text)[:5]
        return {"query": query, "results": titles, "count": len(titles)}
    except Exception as exc:
        return {"query": query, "results": [], "count": 0, "error": str(exc)}

def build_evidence_graph_tool(trace: dict) -> dict:
    g = build_evidence_graph(trace)
    return graph_summary(g)
