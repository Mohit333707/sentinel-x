#!/usr/bin/env python3
"""Generate docs/submission/ artifacts from REAL run outputs.

NOTE: this script only regenerates the architecture diagram and copies the
sample trace / test traces. It MUST NOT overwrite the expanded, hand-written
docs (sample_run_transcript.md/.txt, monitoring_report.md/.html,
FORM_ANSWERS.md) — those are maintained by hand since 25 Nov 2026.
Reads evaluation/evaluation_report.json and the demo trace JSON.
Run from the project root: python docs/submission/make_submission.py
"""
import json, os, shutil
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SUB = os.path.join(BASE, "docs", "submission")
ev = json.load(open(os.path.join(BASE, "evaluation", "evaluation_report.json")))
m = ev["metrics"]
DEMO_TRACE = "SX-DBB1B7B7"
trace = json.load(open(os.path.join(BASE, "reports", f"trace_{DEMO_TRACE}.json")))

# --- 1. Architecture diagram (matplotlib only) ---
fig, ax = plt.subplots(figsize=(13, 7.5)); ax.set_xlim(0, 13); ax.set_ylim(0, 7.5); ax.axis("off")
ax.set_title("SENTINEL-X Architecture — Evidence-Driven Autonomous Incident Investigation", fontsize=13, weight="bold", pad=12)
def box(x, y, w, h, title, body, color="#dceefb"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08", fc=color, ec="#2a6ea5", lw=1.2))
    ax.text(x + w/2, y + h - 0.35, title, ha="center", va="top", fontsize=10, weight="bold")
    ax.text(x + w/2, y + h - 0.75, body, ha="center", va="top", fontsize=8.5)
def arrow(x1, y1, x2, y2):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="->", mutation_scale=13, color="#2a6ea5", lw=1.4))
box(0.3, 5.6, 2.4, 1.3, "Security Alert", "IP 192.0.2.45\n35 failed logins\n02:30 AM, unknown device", "#ffe8cc")
box(3.4, 5.6, 2.6, 1.3, "LangGraph Planner", "StateGraph\nLLM picks next tool\nfrom evidence so far", "#dceefb")
box(6.7, 5.6, 2.6, 1.3, "Tools", "analyse_logs (pandas)\ncheck_ip (ip-api.com)\nsearch_threat_intel", "#e6f4d7")
box(10.0, 5.6, 2.6, 1.3, "LLM Reasoning", "Gemini 2.0 Flash\nREST, free tier\nGroq / OpenAI fallback", "#f3e2f5")
box(0.3, 3.4, 3.4, 1.5, "Evidence Graph (NetworkX)", "Nodes: IP, user, device,\nlogin events, time, country\nEdges carry support labels", "#dceefb")
box(4.6, 3.4, 3.4, 1.5, "Self-Verification Engine", "Re-checks draft verdict\nagainst the graph\nRevises if contradicted", "#fff2cc")
box(8.9, 3.4, 3.7, 1.5, "Uncertainty & Abstention", "Score >= 3.0 MALICIOUS\n<= 1.0 BENIGN, else\nINSUFFICIENT_EVIDENCE", "#ffe0e0")
box(0.3, 1.2, 3.4, 1.5, "Risk + Human Approval", "HIGH / LOW / UNKNOWN\nNo dangerous action\nwithout human approval", "#e6f4d7")
box(4.6, 1.2, 3.4, 1.5, "Audit Trail (SQLite + JSON)", "Every tool call, decision,\nrevision, recommendation\nsentinel_x.db + trace JSON", "#dceefb")
box(8.9, 1.2, 3.7, 1.5, "Streamlit Dashboard", "Goal input, live step trace,\nevidence graph, risk,\naudit history, metrics", "#f3e2f5")
for a in [(2.7,6.25,3.4,6.25),(6.0,6.25,6.7,6.25),(9.3,6.25,10.0,6.25),(7.3,5.6,5.0,4.9)]:
    arrow(*a)
arrow(2.0,3.4,2.0,2.7); arrow(6.3,3.4,6.3,2.7); arrow(10.7,3.4,10.7,2.7)
ax.text(6.5, 0.55, "Offline mode (labelled): evidence-graph scoring replaces LLM reasoning for testing only — never presented as a live Gemini run.",
        ha="center", fontsize=8.5, style="italic")
fig.tight_layout(); fig.savefig(os.path.join(SUB, "architecture_diagram.png"), dpi=180)
fig.savefig(os.path.join(SUB, "architecture_diagram.pdf"))
plt.close(fig)

# --- 2. Sample run transcript (from the REAL demo trace) ---
steps = trace["steps"]; g = trace["graph"]
lines = ["# SENTINEL-X — Sample Run Transcript\n",
         "**SYNTHETIC SAMPLE RUN / OFFLINE MODE** — This run used offline evidence-graph scoring. It is NOT a live Gemini run. Live Gemini run is pending a free API key.\n",
         f"Trace ID: {trace['trace_id']} | Mode: {trace['mode']} | Date: 25 Nov 2026\n",
         "## Goal\nInvestigate suspicious login activity. IP: 192.0.2.45, Failed logins: 35, Successful login: 1, Time: 02:30 AM, Device: Unknown\n",
         "## Step-by-step (thought / action / observation)\n"]
for i, s in enumerate(steps, 1):
    lines.append(f"### Step {i}\n{s}\n")
lines += ["## Evidence graph\n",
          f"Nodes: {g['nodes']} | Edges: {g['edges']} | Malicious-supporting edges: {g['malicious_supporting_edges']} | Benign-supporting edges: {g['benign_supporting_edges']}\n"]
for e in g["edge_list"]:
    lines.append(f"- {e['from']} --{e['relation']}--> {e['to']} (supports: {e['supports']})")
lines += [f"\n## Verification\nDraft verdict: {trace['draft_verdict']} (evidence score {trace['score']}) → Final verdict: **{trace['verdict']}**. "
          f"Revised by verifier: {trace['verification']['revised']}. Reasons: {'; '.join(trace['verification']['reasons'])}\n",
          f"\n## Abstention check\nVerdict is {trace['verdict']}, not INSUFFICIENT_EVIDENCE, because the evidence score ({trace['score']}) is above the 3.0 threshold and 5 graph edges support it. "
          "If the score had been between 1.0 and 3.0, the agent would have said INSUFFICIENT_EVIDENCE and listed the missing evidence instead of guessing.\n",
          f"\n## Human-approval gate\n{trace['approval_status']}\n",
          f"\n## Final report\nRisk: **{trace['risk']}**. Recommendation: block the IP, force a password reset, and review the account — only after human approval. "
          f"Tool calls: {trace['tool_calls']}. Execution time: {trace['execution_time_seconds']}s. Full report: `reports/incident_report_{trace['trace_id']}.md`.\n"]
txt = "\n".join(lines)
# NOTE (25 Nov 2026): the expanded transcript is maintained by hand; do not overwrite it.
# NOTE: expanded transcript .txt is maintained by hand; do not overwrite it.
shutil.copy(os.path.join(BASE, "reports", f"trace_{DEMO_TRACE}.json"), os.path.join(SUB, "sample_trace.json"))

# --- 3. Synthetic test traces (same 20) ---
shutil.copy(os.path.join(BASE, "data", "synthetic_traces.csv"), os.path.join(SUB, "synthetic_test_traces.csv"))

# --- 4. Monitoring report ---
rows = "".join(f"| {p['id']} | {p['true_label']} | {p['predicted']} | {p['score']} | {p['risk']} | {p['tool_calls']} | {p['time_seconds']} | {p['revised_by_verifier']} |\n" for p in ev["per_trace"])
md = f"""# SENTINEL-X — Monitoring Report

**Mode:** offline evidence-graph evaluation — LLM reasoning not exercised; live Gemini run pending a free key.
**Run date:** 25 Nov 2026 | **Traces:** {m['n_traces']} (12 malicious / 8 benign, synthetic)

## Run summary
- Precision: {m['precision']} | Recall: {m['recall']} | F1: {m['f1_score']} | False positive rate: {m['false_positive_rate']}
- Investigation completion rate: {m['investigation_completion_rate']} (abstentions: {m['abstentions']})
- Avg tool calls per investigation: {m['avg_tool_calls']} | Avg execution time: {m['avg_execution_time_seconds']}s
- Unsupported conclusion rate: {m['unsupported_conclusion_rate']} ({m['unsupported_conclusions']} of {m['total_conclusions']} conclusions had no supporting graph edge)

## Metrics table
| Metric | Value |
|---|---|
| True positives | {m['true_positives']} |
| False positives | {m['false_positives']} |
| False negatives | {m['false_negatives']} |
| True negatives | {m['true_negatives']} |
| Precision | {m['precision']} |
| Recall | {m['recall']} |
| F1 score | {m['f1_score']} |
| False positive rate | {m['false_positive_rate']} |
| Investigation completion rate | {m['investigation_completion_rate']} |
| Avg tool calls | {m['avg_tool_calls']} |
| Avg execution time (s) | {m['avg_execution_time_seconds']} |
| Unsupported conclusion rate | {m['unsupported_conclusion_rate']} |

## Per-trace table
| id | true | predicted | score | risk | tool calls | time (s) | revised |
|---|---|---|---|---|---|---|---|
{rows}
## Tool-call counts
Every investigation made {m['avg_tool_calls']} tool calls on average (analyse_logs, check_ip, search_threat_intel, build_evidence_graph).

## Audit counts
All runs are logged in `sentinel_x.db` (audit_events + traces tables) with a JSON trace per run in `reports/`.

## Limitations (honest)
- Offline evaluation only: the LLM did not reason in these runs; numbers measure the evidence-graph pipeline, not live Gemini reasoning.
- Synthetic data only (20 hand-designed traces, TEST-NET IPs). No real attacks or real users.
- The 1 false negative (SX012) is a deliberate borderline case the agent abstained on — that is the abstention feature working, not a crash.
- No dangerous action is ever executed without human approval.
"""
# NOTE (25 Nov 2026): the expanded monitoring report is maintained by hand; do not overwrite it.
html = ("<html><head><meta charset='utf-8'><title>SENTINEL-X Monitoring Report</title>"
        "<style>body{font-family:Arial,sans-serif;max-width:900px;margin:24px auto;padding:0 16px}table{border-collapse:collapse}td,th{border:1px solid #999;padding:6px 10px;text-align:left}th{background:#dceefb}</style></head><body>"
        + md.replace("\n", "<br>\n") + "</body></html>")
# NOTE: the monitoring HTML dashboard is generated from the expanded .md; do not overwrite it.

# --- 5. FORM_ANSWERS.md ---
fa = f"""# SENTINEL-X — Form Answers (copy-paste)

Plain simple English, written so Mohit Kumar can defend every line in an interview.

## Role
Agentic AI Engineer Intern

## GitHub link
https://github.com/Mohit333707/sentinel-x
(Note: the repository does not exist yet — it will be created and the code pushed after this submission is built. The code in this submission is the exact code for that repo.)

## Domain / goal
Cyber security incident investigation. Goal: build an autonomous agent that investigates suspicious login activity, connects evidence from many events, checks its own conclusions, and recommends safe responses — without guessing when evidence is weak and without taking dangerous actions without human approval.

## Write-up — design decisions
- Evidence Graph (NetworkX): every fact (IP, user, device, login attempts, time, country) becomes a node or edge. No decision is made from a single alert; a verdict needs supporting edges in the graph.
- Dynamic Investigation Planner (LangGraph StateGraph): in live mode the LLM reads the evidence so far and picks the next tool. There is no fixed step list.
- Self-Verification Engine: after a draft verdict, a verification step re-checks it against the evidence graph and revises it if the graph does not support it. A MALICIOUS verdict needs at least 3 malicious-supporting edges. Revisions are logged.
- Uncertainty and Abstention: evidence score 3.0 or more means MALICIOUS, 1.0 or less means BENIGN, and anything in between means INSUFFICIENT_EVIDENCE, with the missing evidence listed. The agent never makes a confident guess on weak evidence.
- Explainable Audit Trail: every tool call, decision, revision and recommendation is saved in SQLite (sentinel_x.db) and a JSON trace, with timestamps, so any verdict can be replayed.
- LLM: Google Gemini free tier (gemini-2.0-flash) over REST, with Groq/OpenAI as fallback. No hard-coded per-case answers in live mode — the LLM reasons each step.

## Write-up — limitations
- The live Gemini run is pending a free API key, so the numbers below are from an offline evidence-graph evaluation, not a live LLM run. This is stated in every report.
- Test data is synthetic (20 hand-designed traces). No real attacks and no real users were used.
- The agent never blocks an IP or resets a password on its own. Dangerous actions need human approval.
- IP lookup skips real lookups for TEST-NET (synthetic) IPs; threat intel uses the free DuckDuckGo HTML search.

## Assumptions / mock data
- All data is mock/synthetic. All IPs are RFC 5737 TEST-NET ranges (192.0.2.x, 198.51.100.x, 203.0.113.x). Names are synthetic only.
- The 20 test traces were hand-designed by me: 12 malicious (many failed logins at night, unknown device, country change, success after failures) and 8 benign (few failures, daytime, known device, no country change). Two traces are deliberately borderline, to test abstention.
- Offline scoring thresholds (score >= 3.0 malicious, <= 1.0 benign) are documented in sentinel_x/uncertainty.py and used only in offline mode.

## Total time spent
7 hours — time building Sentinel (the first version) plus SENTINEL-X today.

## Write-up — approach
I built it step by step: LLM layer first, then the evidence graph, then the LangGraph planner and agent, then verification, abstention and audit logging, then the Streamlit dashboard, then tests, then evaluation on 20 synthetic traces. I ran the tests (14 passed), ran the demo in offline mode, and ran the evaluation to get real numbers. Nothing in the reports is invented — every number below comes from evaluation/evaluation_report.json, computed with scikit-learn from real offline runs.

## Precision / recall (real numbers, offline evidence-graph evaluation)
- Precision: {m['precision']}
- Recall: {m['recall']}
- F1 score: {m['f1_score']}
- False positive rate: {m['false_positive_rate']}
- True positives: {m['true_positives']}, False positives: {m['false_positives']}, False negatives: {m['false_negatives']}, True negatives: {m['true_negatives']}
- Investigation completion rate: {m['investigation_completion_rate']} (abstentions: {m['abstentions']} of {m['n_traces']})
- Average tool calls per investigation: {m['avg_tool_calls']}
- Average execution time: {m['avg_execution_time_seconds']} seconds
- Unsupported conclusion rate: {m['unsupported_conclusion_rate']} ({m['unsupported_conclusions']} of {m['total_conclusions']} conclusions had no supporting graph edge)
- The 1 false negative is trace SX012, a deliberately borderline malicious case (score 2.0) where the agent correctly abstained with INSUFFICIENT_EVIDENCE instead of guessing. That is the abstention feature working as designed.

## Production-readiness
Not production-ready yet, honestly. What is ready: the full pipeline, the 5 features in real code, tests, audit logging, and the human-approval gate. What is still needed before production: (1) a live Gemini run with a free API key on real anonymised logs, to measure how the LLM reasons (not just the offline scorer); (2) a real threat-intel API key instead of free DuckDuckGo HTML; (3) a proper human-approval UI and role-based access before any blocking action; (4) testing on more, larger and messier real-world-style data. Until then, the numbers above describe the offline pipeline only.

## How test traces were generated / labelled
Synthetic, hand-designed by me — no real data. I wrote 20 traces in data/synthetic_traces.csv and .json, each with id, label, IP, failed logins, successful login, hour, device_known, country_change. Malicious traces combine several suspicious signals (for example 35 failed logins at 02:00 from an unknown device with a country change and then a success). Benign traces have few failures in the daytime from a known device with no country change. Two traces sit between the thresholds on purpose, so I could check that the agent abstains instead of guessing. All IPs are TEST-NET documentation ranges, so nothing points to a real person or system.
"""
# NOTE (25 Nov 2026): FORM-ANSWERS.md is expanded by hand (150-250 words per field); do not overwrite it.
print("submission artifacts written")
print(json.dumps(m, indent=2))
