#!/usr/bin/env python3
"""Run SENTINEL-X over all 20 synthetic traces in OFFLINE mode and
write evaluation/evaluation_report.json + .md with REAL computed
numbers. Labelled honestly: offline evidence-graph evaluation —
LLM reasoning not exercised; live Gemini run pending a free key.
"""
from __future__ import annotations
import csv, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel_x.agent import SentinelXAgent
from sentinel_x.evaluation import compute_metrics

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_traces():
    rows = []
    with open(os.path.join(BASE, "data", "synthetic_traces.csv")) as f:
        for r in csv.DictReader((l for l in f if not l.startswith("#"))):
            rows.append({"id": r["id"], "label": r["label"], "ip": r["ip"],
                         "failed_logins": int(r["failed_logins"]), "successful_login": int(r["successful_login"]),
                         "hour": int(r["hour"]), "device_known": r["device_known"].strip().lower() == "true",
                         "country_change": r["country_change"].strip().lower() == "true"})
    return rows

def main():
    traces = load_traces()
    agent = SentinelXAgent(offline=True, db_path=os.path.join(BASE, "sentinel_x.db"), out_dir=os.path.join(BASE, "reports"))
    y_true, y_pred, calls, times, per_trace = [], [], [], [], []
    unsupported = 0
    for t in traces:
        goal = (f"Investigate suspicious login activity. IP: {t['ip']}, Failed logins: {t['failed_logins']}, "
                f"Successful login: {t['successful_login']}, Time: {t['hour']:02d}:00, "
                f"Device: {'Known' if t['device_known'] else 'Unknown'}")
        r = agent.run(goal, trace=t)
        y_true.append(t["label"]); y_pred.append(r["verdict"])
        calls.append(r["tool_calls"]); times.append(r["execution_time_seconds"])
        unsupported += r.get("unsupported_conclusions", 0)
        per_trace.append({"id": t["id"], "true_label": t["label"], "predicted": r["verdict"],
                          "score": r["score"], "risk": r["risk"], "tool_calls": r["tool_calls"],
                          "time_seconds": r["execution_time_seconds"],
                          "revised_by_verifier": r["verification"]["revised"]})
    m = compute_metrics(y_true, y_pred, calls, times, unsupported, len(traces))
    report = {"mode": "offline evidence-graph evaluation — LLM reasoning not exercised; live Gemini run pending a free key",
              "metrics": m, "per_trace": per_trace}
    os.makedirs(os.path.join(BASE, "evaluation"), exist_ok=True)
    with open(os.path.join(BASE, "evaluation", "evaluation_report.json"), "w") as f: json.dump(report, f, indent=2)
    lines = ["# SENTINEL-X Evaluation Report\n",
             "Mode: **offline evidence-graph evaluation — LLM reasoning not exercised; live Gemini run pending a free key.**\n",
             "Method: the agent ran over 20 synthetic labelled traces (12 malicious / 8 benign) in offline mode. "
             "Each trace went through the full LangGraph pipeline (plan → logs → IP/device → evidence graph → verification → risk → human-approval gate). "
             "Abstentions (INSUFFICIENT_EVIDENCE) count as NOT malicious for precision/recall.\n",
             "## Metrics\n"]
    for k, v in m.items(): lines.append(f"- {k}: {v}")
    lines.append("\n## Per-trace results\n| id | true | predicted | score | risk | tool calls | time (s) | revised |\n|---|---|---|---|---|---|---|---|\n")
    for p in per_trace:
        lines.append(f"| {p['id']} | {p['true_label']} | {p['predicted']} | {p['score']} | {p['risk']} | {p['tool_calls']} | {p['time_seconds']} | {p['revised_by_verifier']} |")
    with open(os.path.join(BASE, "evaluation", "evaluation_report.md"), "w") as f: f.write("\n".join(lines) + "\n")
    print(json.dumps(m, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
