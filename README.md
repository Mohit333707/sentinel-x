# SENTINEL-X — Evidence-Driven Autonomous Cyber Incident Investigation Agent

**Author:** Mohit Kumar — B.Tech CSE (final year), Amity University Rajasthan, CGPA 7.52
**GitHub:** https://github.com/Mohit333707/sentinel-x
**Built for:** Xiarch Bharat Pvt Ltd — Agentic AI Engineer Intern assessment
**Time spent:** 7 hours, building Sentinel (the first version) and then SENTINEL-X on the same day, 25 November 2026.

SENTINEL-X investigates suspicious login activity. You give it a goal in plain English, like "Investigate suspicious login activity. IP: 192.0.2.45, Failed logins: 35, Successful login: 1, Time: 02:30 AM, Device: Unknown". It reads the logs, checks the IP and device, links every fact into a graph, checks its own verdict against that graph, and only then writes a report. It never decides from one alert alone. It never guesses when the evidence is thin — it says `INSUFFICIENT_EVIDENCE` and lists what is missing. And it never blocks an IP or resets a password on its own. Every dangerous action waits for a human to approve it.

I built this because most alert tools I had seen do one thing: they fire a rule and stop. A rule like "more than 10 failed logins means attack" is easy to write and easy to get wrong. A real user mistypes a password five times at 2 am on a new phone, and that rule calls them an attacker. A real attacker who tries nine times and stops slips past it. So I wanted an agent that gathers several kinds of evidence, links them together, and then argues with itself before it calls anything malicious.

## What it does, in one run

The demo run is trace `SX-DBB1B7B7`. The goal was the 192.0.2.45 case above: 35 failed logins, 1 success, 02:30 AM, unknown device. The agent made 4 tool calls in 0.743 seconds, built a graph with 7 nodes and 7 edges, scored the evidence at 5.0, and gave a verdict of MALICIOUS with risk HIGH. Five of the seven graph edges supported that verdict. The verifier checked the draft, found 5 supporting edges and no contradiction, and kept it. The report went to `reports/incident_report_SX-DBB1B7B7.md` and the full trace to `reports/trace_SX-DBB1B7B7.json`. Nothing was blocked. Nothing was reset. The approval status stayed PENDING, waiting for a human.

## The five features, and how each one actually works in code

### 1. Evidence Graph — `sentinel_x/graph.py`, built on NetworkX

Every fact becomes a node or an edge. `build_evidence_graph(trace)` in `sentinel_x/graph.py` adds seven nodes: the IP, the user (`user:unknown-user`, synthetic), the device (known or unknown), the failed-logins event, the success event, the hour, and the country (changed or same). Then it adds seven edges, each with a `relation` and a `supports` label. The label is `malicious`, `benign`, or `neutral`. For example, the edge from `ip:192.0.2.45` to `event:failed-logins:35` has relation `attempted_from` and supports `malicious` when there are 8 or more failures. The edge to `time:2:00` supports `malicious` when the hour is between 00 and 05. The edge to `country:same` supports `benign`, because the country did not change.

`graph_summary()` in the same file counts nodes and edges and lists them, plus how many edges support each side. `supporting_edges()` returns the edges that back a given verdict. Nothing else in the system is allowed to claim a verdict is supported. If the graph does not back it, the verdict does not stand. That is the whole point of this feature, and it is also how the unsupported-conclusion rate is measured: a MALICIOUS verdict with zero malicious-supporting edges would count as unsupported. Across the 20 evaluation traces, that rate was 0.0.

The scoring that goes with the graph lives in `evidence_score()` in the same file, and it is only used in offline mode. It is plain and written out in the docstring so anyone can check it: 30 or more failed logins add 2.0, 15 or more add 1.5, 8 or more add 1.0, 3 or more add 0.5; a night hour (00–05) adds 1.0; an unknown device adds 1.0; a country change adds 1.0; a success after 10 or more failures adds 1.0. The demo trace scores 2.0 + 1.0 + 1.0 + 1.0 = 5.0. In live mode the LLM reasons over the graph instead, and this score is not used as the verdict.

### 2. Dynamic Investigation Planner — `sentinel_x/planner.py` and `sentinel_x/agent.py`, built on LangGraph

The planner is a LangGraph `StateGraph` in `sentinel_x/agent.py`, in the `SentinelXAgent._build_graph()` method. The state is an `InvestigationState` TypedDict: goal, trace, mode, plan, steps, log analysis, IP info, threat intel, graph summary, score, draft verdict, verification, verdict, risk, approval status, report, tool calls, missing evidence. The nodes run in this order: `understand_incident` → `create_plan` → `analyse_logs` → `check_ip_device` → `build_graph` → `verify_findings`, then a conditional edge from `_enough_evidence()` sends the run to `risk_assessment` → `human_approval` → `final_report` when the verdict is MALICIOUS or BENIGN, or to `request_more_evidence` → `final_report` when it is INSUFFICIENT_EVIDENCE.

In live mode, `live_plan()` in `sentinel_x/planner.py` asks the LLM which tool to run next, from the evidence so far, and the LLM replies with JSON like `{"next_tool": "check_ip", "reason": "..."}`. The JSON parsing lives in `LLMClient.call_json()` in `sentinel_x/llm.py`, with retries. In offline mode, `offline_plan()` returns the same five step names in a fixed order — `analyse_logs, check_ip, search_threat_intel, build_evidence_graph, verify_findings` — so the pipeline can still be tested without a key. The step names are the same in both modes on purpose. The difference is honest and labelled in every output: offline mode is a labelled stand-in for testing, not a live run.

Each node is a small method on the agent. `_understand()` calls `parse_goal()` from `sentinel_x/tools.py`, which pulls the IP, the failed and successful login counts, the hour, and the device out of the goal text with regular expressions. `_analyse_logs()` calls `analyse_logs()`, which uses pandas to work out total attempts (36 in the demo), failure rate (0.972), whether it is night time, and whether it is a burst (10 or more failures). `_check_ip_device()` calls `check_ip()` and `search_threat_intel()`. That node counts as 2 tool calls, which is why the demo total is 4: one for analyse_logs, two here, one for the graph build.

### 3. Self-Verification Engine — `sentinel_x/verifier.py`

After the draft verdict is made, `verify_verdict()` in `sentinel_x/verifier.py` re-checks it against the graph before anything is written to the report. The rule is simple and strict. A MALICIOUS draft needs at least 3 malicious-supporting graph edges. If it has fewer, the verdict is revised to INSUFFICIENT_EVIDENCE. If it has 3 or more benign-supporting edges and a score under 4.0, that is a contradiction, and it is also revised to INSUFFICIENT_EVIDENCE. A BENIGN draft with a score of 3.0 or more is a contradiction too, and gets revised the same way. A draft that is already INSUFFICIENT_EVIDENCE stays that way.

In the demo, the draft was MALICIOUS with a score of 5.0 and 5 malicious-supporting edges, so the verifier wrote back: "Verified: 5 malicious-supporting edge(s) back the verdict; no contradiction found." Revised: False. In live mode, `_verify()` in `agent.py` also asks the LLM to check the draft and appends its reply to the reasons list. If the LLM call fails, that failure is written into the reasons instead of crashing the run. Every revision is logged to the audit trail with the draft, the final verdict, and the reasons, so you can see exactly when the agent changed its mind and why.

### 4. Uncertainty and Abstention — `sentinel_x/uncertainty.py`

`decide_verdict()` in `sentinel_x/uncertainty.py` turns the evidence score into a verdict with three bands. Score 3.0 or more means MALICIOUS. Score 1.0 or less means BENIGN. Anything in between means INSUFFICIENT_EVIDENCE, with a list of what is missing. The thresholds are module constants, `MALICIOUS_THRESHOLD = 3.0` and `BENIGN_THRESHOLD = 1.0`, so they are easy to find and change.

There is one more rule in the same function. If malicious support is 2 or more and benign support is 2 or more and the score is near 2.0, the evidence contradicts itself, and the agent abstains even though the score sits in the middle band. It adds "resolve contradictory signals (known device vs night-time burst)" to the missing-evidence list.

`missing_evidence()` builds that list from the trace itself: fewer than 8 failed logins means it asks for a longer log window; a known device means it asks for device fingerprint history; no country change means it asks for geolocation history; no successful login means it asks whether any login actually succeeded. This is the feature I care about most. Saying "I do not know yet, here is what I need" is a better answer than a confident guess, and the evaluation shows it working: 2 of the 20 traces ended in abstention, and one of them, SX012, was a truly malicious trace that the agent refused to call. That counts as a false negative in the metrics, and I kept it that way instead of tuning the threshold to hide it, because the abstention was the correct behaviour for the evidence it had.

### 5. Explainable Audit Trail — `sentinel_x/audit.py`, SQLite plus JSON

Every run writes to two places. `AuditTrail` in `sentinel_x/audit.py` writes to `sentinel_x.db`, which has two tables: `audit_events` (id, trace_id, timestamp, event type, step, detail, verdict) and `traces` (trace_id, goal, verdict, mode, created time, report path). `agent.run()` logs a start event, one event per step, and a decision event with the draft verdict, final verdict, revised flag, and verifier reasons. At the evaluation run, the database held 21 traces and 229 audit events. The count grows with every run, because every run is logged.

The second place is `reports/`. Each run writes `reports/incident_report_<trace_id>.md`, a readable report, and `reports/trace_<trace_id>.json`, the full machine-readable record: goal, trace, verdict, draft verdict, score, risk, verification, missing evidence, graph, steps, tool calls, time, and approval status. You can replay any verdict from these two files plus the database. `python main.py --trace SX-DBB1B7B7` prints the audit history for one trace id.

## Why I chose each technology

I picked each tool for one plain reason, and each one has a drawback I ran into or know about. I am writing both down because a choice without its cost is not a real decision.

**LangGraph.** I chose it because the investigation is a graph of steps with a branch in the middle — enough evidence goes one way, not enough goes the other — and LangGraph's `StateGraph` with conditional edges says exactly that in code. I first tried to hand-roll the flow with plain if statements in one big function, and it turned into a mess the moment I added the branch back to request more evidence. The drawback is that LangGraph state has to be passed as a dict between nodes, and if a node forgets to return a key, the next node silently gets nothing instead of an error. I lost time to that once: a node returned the step text but not the updated tool-call count, and the count stayed at zero until I read the state dict key by key.

**Gemini (gemini-2.0-flash, free tier).** I chose it because it is free, it answers over a plain REST call with no heavy SDK, and it was the fastest way to get a real LLM reasoning over the evidence. `sentinel_x/llm.py` calls it with `requests`, and falls back to Groq (`llama-3.3-70b-versatile`) or OpenAI (`gpt-4o-mini`) if those keys are set instead. The drawback is the one this whole repo is honest about: I did not have a free Gemini key when I built this, so the live run is still pending. Every number in this README comes from the offline evidence-graph run, not from Gemini. I will not pretend otherwise.

**Pandas.** I chose it because the login logs are a table, and pandas makes "how many attempts, what failure rate, is this a burst" into three lines in `analyse_logs()`. The drawback is that it is a heavy dependency for what is, right now, a one-row table. A plain dict would have done the same job for a single trace. I kept pandas because the evaluation reads the whole 20-trace CSV with `read_alerts()` in `sentinel_x/tools.py`, and because real log files will be tables, not single rows.

**NetworkX.** I chose it because the evidence is a graph — IPs linked to devices linked to events — and NetworkX gives me nodes, edges, and edge attributes without me writing a graph library by hand. The drawback is that a NetworkX graph is not JSON by itself. I have to convert it with `graph_summary()` before it can go into a trace file or the audit log, and that conversion is a step I have to remember every time.

**Streamlit.** I chose it for the first dashboard (`app.py`) because it turns a Python function into a web page in an afternoon, with no frontend code at all. The drawback is that it looks like Streamlit, and it re-runs the whole script on every click. That is why the main frontend is now React (see the Frontend section below), and Streamlit stays as the simple second option.

**scikit-learn.** I chose it for the evaluation because precision, recall, F1, and the confusion matrix are three lines with `precision_score`, `recall_score`, `f1_score`, and `confusion_matrix` in `sentinel_x/evaluation.py`, and because using the standard library means my numbers are computed the same way anyone else would compute them. The drawback is that it is a big install just for four metrics on 20 traces. I kept it because the numbers in the report have to be beyond argument, and hand-rolled metric code is exactly the kind of place a small bug hides.

**SQLite.** I chose it for the audit trail because it is a real database with no server to run, no setup, and one file (`sentinel_x.db`) I can copy, open, and query. The drawback is that it is one file on one machine. Two runs at the same time can lock it, and it is not a place to store real incident data for a team. For this assessment, one file is the right size.

## What went wrong while building it, and what I changed

Three things went wrong in ways that taught me something, and I am keeping them here because they are part of the build.

First, the LLM JSON parsing. `live_plan()` asks the LLM for JSON, and the first version just called `json.loads()` on whatever came back. The model kept wrapping its answer in markdown fences, like ```json ... ```, and the parse failed every time. I fixed it in `LLMClient.call_json()` in `sentinel_x/llm.py`: it strips fences, retries up to 2 times, and only then raises a clear error with the last reply attached. The planner in `agent.py` catches that error and falls back to the default plan instead of crashing the run.

Second, LangGraph state handling. I already mentioned this above: a node that forgets a key silently drops it. My fix was boring and it worked. Every node now returns the full set of keys it touches, including `tool_calls`, even when the value did not change. I also made the tests check the tool-call count end to end, so a dropped key fails a test instead of silently giving a wrong number.

Third, IP lookup on TEST-NET ranges. `check_ip()` in `sentinel_x/tools.py` calls ip-api.com, which is a real lookup service. My test data uses TEST-NET documentation IPs like 192.0.2.45, and the service either returns nonsense for those or wastes a network call on an address that cannot belong to anyone. I first saw this when a demo run took a long time and came back with a wrong country. The fix is a guard at the top of `check_ip()`: if the IP starts with `192.0.2.`, `198.51.100.`, or `203.0.113.`, it returns `status: synthetic` with no network call at all, and a note saying so. Real IPs still go through the live lookup, and any failure there returns `status: lookup_failed` instead of crashing. The threat-intel search in the same file has the same habit: `search_threat_intel()` uses the free DuckDuckGo HTML page, and if that page changes shape or the network fails, it returns zero hits with the error recorded, not an exception.

## Three investigation examples

### Example 1 — the demo: 192.0.2.45, clearly malicious

Goal: "Investigate suspicious login activity. IP: 192.0.2.45, Failed logins: 35, Successful login: 1, Time: 02:30 AM, Device: Unknown". Trace id SX-DBB1B7B7. `analyse_logs()` found 36 total attempts, a 0.972 failure rate, night time true, burst true. `check_ip()` saw a TEST-NET address and skipped the real lookup. The graph had 7 nodes and 7 edges, 5 supporting malicious and 1 supporting benign. Score 5.0: 2.0 for 35 failures, 1.0 for the 2 am hour, 1.0 for the unknown device, 1.0 for a success after more than 10 failures. Draft MALICIOUS, verifier kept it, risk HIGH. Recommendation: block the IP, force a password reset, review the account — after human approval. The full step-by-step is in `docs/submission/sample_run_transcript.md`.

### Example 2 — a benign daytime login from a known device

Take trace SX014 from the evaluation set. IP 198.51.100.20, 1 failed login, 1 success, 2 pm, known device, no country change. Score 0.0: one failure is below every scoring band, the hour is daytime, the device is known, the country is the same. The graph still has 7 nodes and 7 edges, but the edges point the other way — the device edge and the country edge both support benign. Draft BENIGN, verifier checked it (low score, benign edges agree), risk LOW, recommendation: no action needed, keep monitoring. This is the case that matters for the false positive rate. If the agent had called this malicious, a real user would have been locked out for typing one password wrong at lunch. It did not, and across all 8 benign traces, it never did. False positive rate 0.0.

### Example 3 — a borderline case that abstains: SX012

Trace SX012 is the one I designed to sit on the edge. IP 203.0.113.88, 9 failed logins, 0 successes, 2 am, known device, no country change. Score 2.0: 1.0 for 9 failures, 1.0 for the night hour, and nothing else. The device is known, which points benign. The country did not change, which points benign. No login succeeded, so there is no "success after failures" signal. The score lands between 1.0 and 3.0, so `decide_verdict()` returns INSUFFICIENT_EVIDENCE, and the missing-evidence list asks for a longer log window, device fingerprint history, geolocation history, and whether any login actually succeeded. The verifier keeps the abstention. Risk UNKNOWN. No blocking action is recommended. The true label is malicious, so this counts as the 1 false negative in the evaluation, and recall drops to 0.9167 because of it. I did not tune the threshold to fix that number. A score of 2.0 on mixed signals is exactly when an agent should say it does not know yet. SX020 is the other abstention: a benign trace (6 failures, 1 success, 1 am, known device, score 1.5) that also sits between the thresholds. It abstained too, for the same reason, and that is also correct behaviour.

## Evaluation — real numbers, offline mode

The evaluation ran over 20 synthetic traces (12 malicious, 8 benign) in offline evidence-graph mode. The LLM was not exercised. A live Gemini run is still pending a free key. The numbers below come from `evaluation/evaluation_report.json`, computed with scikit-learn by `evaluation/run_evaluation.py`. They are not hand-written.

- Precision 1.0 — every trace the agent called MALICIOUS was truly malicious. 11 true positives, 0 false positives.
- Recall 0.9167 — it caught 11 of the 12 truly malicious traces. The one it missed is SX012, the borderline abstention above.
- F1 score 0.9565 — the balance of the two.
- False positive rate 0.0 — none of the 8 benign traces was called malicious.
- Investigation completion rate 0.90 — 18 of 20 traces got a firm verdict; 2 abstained (SX012 and SX020).
- Average tool calls 4.0 per investigation. Average execution time 0.839 seconds.
- Unsupported conclusion rate 0.0 — 0 of 20 conclusions had no supporting graph edge.
- Confusion counts: TP 11, FP 0, FN 1, TN 8.

`evaluation/evaluation_report.md` explains each metric in plain words: what it means here, why it has that value, and what would improve it. `docs/submission/monitoring_report.md` goes through all 20 traces one by one.

## Setup and how to run it

### Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # paste a FREE Gemini key from https://aistudio.google.com/app/apikey
```

The key is optional for offline mode and required for live mode. Without any key, live mode stops with a clear message and a 2-minute guide to get a free key. It never falls back to canned answers.

### CLI

```bash
python main.py --demo --offline    # offline evidence-graph demo (no key needed)
python main.py --demo              # live demo (needs a Gemini key)
python main.py --goal "Investigate suspicious login activity. IP: 203.0.113.9, Failed logins: 18, Successful login: 1, Time: 04:00 AM, Device: Known"
python main.py --trace SX-DBB1B7B7  # audit history for one trace id
python main.py                     # interactive mode, asks for a goal
```

Every run writes a report to `reports/incident_report_<trace_id>.md`, a trace to `reports/trace_<trace_id>.json`, and rows to `sentinel_x.db`.

### Streamlit dashboard (simple second option)

```bash
streamlit run app.py
```

Dark theme, metric cards for verdict, risk, score, tool calls and time, the step list, the evidence graph, the verification result, and the audit history table from SQLite. It runs investigations live or offline, same as the CLI.

### React frontend (main frontend)

```bash
cd frontend
npm install
npm run dev
```

Open the address Vite prints (usually http://localhost:5173). The dashboard has a top bar, a goal input with Run Investigation and Demo buttons, metric cards, an investigation timeline, an SVG evidence graph, the self-verification result, the final report, and the audit trail table. It tries the FastAPI backend at http://localhost:8000 first, and if the backend is not running it falls back to the bundled sample data in `frontend/public/`, so the dashboard still works with no backend at all. The full layout is described in the Frontend section below.

### API backend (FastAPI)

```bash
uvicorn backend.api:app --reload --port 8000
```

`POST /investigate` takes `{"goal": "..."}` and returns the agent trace and report as JSON. `GET /health` returns `{"status": "ok"}`. `GET /evaluation` returns the contents of `evaluation/evaluation_report.json`. It runs the same offline agent the CLI uses, unless a Gemini key is set, in which case it runs live. See `backend/api.py`.

### Evaluation and tests

```bash
python evaluation/run_evaluation.py   # regenerates evaluation/evaluation_report.json and .md
pytest tests/ -v                      # 14 tests, all passing
```

The tests in `tests/test_sentinel_x.py` cover the graph build, the scoring bands, the verifier revisions, the abstention thresholds, the audit trail, and the full offline agent run.

## Frontend

The React frontend lives in `frontend/`. It is Vite plus React in plain JavaScript, no TypeScript. The files are `package.json`, `vite.config.js`, `index.html`, `src/main.jsx`, `src/App.jsx`, `src/App.css`, and `src/components/` with seven components: `Dashboard`, `InvestigationRun`, `EvidenceGraph`, `TraceTimeline`, `MetricsCards`, `AuditTable`, and `ReportView`.

The layout, top to bottom: a dark top bar with the SENTINEL-X name, the mode label (offline or live), and a note that the data is synthetic; a goal bar with a text input, a Run Investigation button, and a Demo button that loads the 192.0.2.45 example; a row of metric cards showing verdict, risk, evidence score, evidence count (nodes and edges), tool calls, and execution time; then two columns, with the investigation steps timeline on the left and the evidence graph on the right; below that, the self-verification result and the missing-evidence list; then the final report; then the audit trail table. The evidence graph is a hand-drawn SVG: the IP node sits in the middle, the user, device, time, country, and event nodes sit around it, and each edge is labelled with its relation and coloured by what it supports — red for malicious, green for benign, grey for neutral. No graph library is used, because the graph is small (7 nodes, 7 edges) and a library would be more code than the drawing itself.

The dashboard works without a backend. `frontend/public/sample_trace.json` is a copy of the real demo trace `docs/submission/sample_trace.json`, and `frontend/public/evaluation_report.json` is a copy of the real `evaluation/evaluation_report.json`. When the page loads, it fetches those two files and renders the demo. When you click Run Investigation, it first tries `POST http://localhost:8000/investigate`; if that fails because the backend is not running, it falls back to the sample trace and says so on screen. There is no fake screenshot in this repo. The description above is the layout, and the running app is the proof.

## Sample output

Running `python main.py --demo --offline` prints:

```
Trace ID: SX-DBB1B7B7   Mode: offline
Verdict: MALICIOUS   Risk: HIGH   Score: 5.0
Tool calls: 4   Time: 0.743s
Report: reports/incident_report_SX-DBB1B7B7.md
Trace JSON: reports/trace_SX-DBB1B7B7.json
```

And the report it writes ends with the recommendation "Block the IP, force password reset, review the account", the human-approval note "PENDING — human approval required before any dangerous action (block/reset)", and the nine steps the agent took.

## Submission files — which file goes to which Google Form field

Every upload document is a separate file under `docs/submission/`. Nothing is merged into one big file. `05-Code.zip` is not made here; the parent makes it separately.

| Google Form field | File to upload |
|---|---|
| Architecture diagram | `docs/submission/01-Architecture-Diagram.png` and `docs/submission/01-Architecture-Diagram.pdf` |
| Sample run transcript | `docs/submission/02-Sample-Run-Transcript.pdf` (also `.md` and `.txt` in the same folder) |
| Synthetic test traces | `docs/submission/03-Synthetic-Test-Traces.csv` (also `.json` with the same 20 labelled traces) |
| Monitoring report | `docs/submission/04-Monitoring-Report.pdf` (also `.html` dashboard output in the same folder) |
| Code | `05-Code.zip` — made separately by the parent, not in this repo |
| Form answers / write-up | `docs/submission/FORM-ANSWERS.md` |

## Limitations — stated plainly

- The live Gemini run is pending a free API key. Every number here is from an offline evidence-graph evaluation. The LLM did not reason in those runs. I say this in the README, in the evaluation report, in the monitoring report, in the transcript, and in the app itself, because it is the most important limit in the project.
- The test data is synthetic: 20 hand-designed traces, TEST-NET IPs (192.0.2.x, 198.51.100.x, 203.0.113.x), no real attacks, no real users. The numbers describe how the offline pipeline behaves on those 20 traces. They do not describe how it would behave on real logs.
- The agent never blocks an IP or resets a password on its own. That is a design choice, not a missing feature. A wrong block locks a real user out.
- `check_ip()` skips real lookups for TEST-NET IPs by design. `search_threat_intel()` uses the free DuckDuckGo HTML page, which can change shape or fail, and returns zero hits when it does.
- The React frontend falls back to sample data when the backend is down. That is deliberate, so the dashboard can be shown without a server, but it means the numbers on screen are the demo numbers unless the backend is running.
- The offline scorer is a stand-in. It is transparent and written out in `sentinel_x/graph.py`, but it is still a fixed scoring table, not reasoning. The live LLM path exists in code (`planner.py`, `llm.py`, `agent.py`) and has not been measured yet.

## Future work

First, run it live. Get a free Gemini key, run the same 20 traces in live mode, and compare the live precision and recall with the offline numbers. That is the single most useful next step, and it is the one I have not been able to do yet.

Second, test on more and messier data. Twenty hand-designed traces are a start, not a test set. I would add traces with missing fields, out-of-order events, and several IPs in one incident, and see where the abstention rate goes.

Third, give the planner real choices in live mode. Right now the live planner picks the next tool, but the node order is still fixed after that. A fuller version would let the agent skip a tool when the evidence already answers the question, or run a tool twice with a different query.

Fourth, replace the free DuckDuckGo search with a real threat-intel API, and add a proper human-approval UI with roles, so that approving a block is a real action with a name and a timestamp attached, not a line in a report.

Fifth, add a confidence number that comes from the graph itself — for example, the share of supporting edges — instead of the fixed score bands, and check whether it lines up with how often the verdict is right.

## Files

- `sentinel_x/llm.py` — Gemini REST client, Groq/OpenAI fallback, JSON parsing with retries.
- `sentinel_x/tools.py` — `parse_goal`, `read_alerts`, `analyse_logs`, `check_ip`, `search_threat_intel`, `build_evidence_graph_tool`.
- `sentinel_x/graph.py` — evidence graph, `evidence_score`, `graph_summary`, `supporting_edges`.
- `sentinel_x/planner.py` — `offline_plan`, `live_plan`.
- `sentinel_x/agent.py` — LangGraph `StateGraph`, all ten nodes, `run()`, report rendering.
- `sentinel_x/verifier.py` — `verify_verdict`, the 3-edge rule.
- `sentinel_x/uncertainty.py` — `decide_verdict`, `missing_evidence`, the 3.0 and 1.0 thresholds.
- `sentinel_x/audit.py` — SQLite audit trail, `new_trace_id`, `write_json_trace`.
- `sentinel_x/evaluation.py` — scikit-learn metrics.
- `main.py` — CLI. `app.py` — Streamlit dashboard. `backend/api.py` — FastAPI backend.
- `frontend/` — React dashboard (Vite, plain JavaScript).
- `data/synthetic_traces.csv` and `.json` — the 20 hand-designed traces.
- `evaluation/run_evaluation.py`, `evaluation/evaluation_report.json`, `evaluation/evaluation_report.md`.
- `tests/test_sentinel_x.py` — 14 tests.
- `docs/submission/` — numbered upload files (01 architecture diagram, 02 sample run transcript, 03 synthetic test traces, 04 monitoring report), `FORM-ANSWERS.md`, plus the older unnumbered copies, and the script that builds the submission (`make_submission.py`).
- `INTERVIEW_TALK.md` — short notes I would use to talk through this project in an interview.
