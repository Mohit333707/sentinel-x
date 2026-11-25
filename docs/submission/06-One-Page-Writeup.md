# SENTINEL-X — One-Page Write-up

Mohit Kumar, B.Tech CSE (final year), Amity University Rajasthan | 25 Nov 2026 | github.com/Mohit333707/sentinel-x

SENTINEL-X is an evidence-driven autonomous agent that investigates suspicious login activity. You give it a goal in plain English, it reads the logs, checks the IP and device, links every fact into a graph, checks its own verdict against that graph, and writes an incident report. It never decides from one alert alone, never guesses on thin evidence, and never blocks an IP or resets a password without a human saying yes.

## Design decisions

I built five features, and each one is real code. First, an Evidence Graph on NetworkX (`sentinel_x/graph.py`): every fact — IP, user, device, login attempts, time, country — becomes a node or an edge, and each edge says whether it supports malicious, benign, or neither. A verdict only stands if the graph backs it. Second, a Dynamic Investigation Planner on LangGraph (`sentinel_x/agent.py`, `sentinel_x/planner.py`): a StateGraph with ten nodes and a branch in the middle — enough evidence goes to risk assessment, not enough goes to requesting more evidence. In live mode the LLM picks the next tool from the evidence so far; offline, the same step names run in a fixed order so the pipeline can be tested without a key. Third, a Self-Verification Engine (`sentinel_x/verifier.py`): after a draft verdict, it re-checks the draft against the graph, and a MALICIOUS draft needs at least 3 malicious-supporting edges or it is revised to INSUFFICIENT_EVIDENCE. Fourth, Uncertainty and Abstention (`sentinel_x/uncertainty.py`): score 3.0 or more means MALICIOUS, 1.0 or less means BENIGN, and anything between means INSUFFICIENT_EVIDENCE with the missing evidence listed. Fifth, an Explainable Audit Trail (`sentinel_x/audit.py`): every tool call, decision, revision, and recommendation goes into SQLite (`sentinel_x.db`) and a JSON trace, so any verdict can be replayed. The LLM is Google Gemini free tier over REST, with Groq and OpenAI as fallbacks. The frontend is React (Vite), with a FastAPI backend; Streamlit stays as a second, simpler option.

## Limitations

I want to be plain about these. The live Gemini run is pending a free API key, so every number below is from an offline evidence-graph evaluation, not from a live LLM run. The test data is synthetic: 20 hand-designed traces with TEST-NET documentation IPs, no real attacks and no real users. The agent never takes a dangerous action on its own, by design, so it is a reporting and recommendation tool, not an automated response tool. The IP lookup skips real lookups for TEST-NET IPs, and the threat-intel search uses the free DuckDuckGo HTML page, which can change shape or fail. The React dashboard falls back to bundled sample data when the backend is not running. None of these limits is hidden anywhere in the repo.

## Evaluation (offline, 20 synthetic traces)

Precision 1.0, Recall 0.9167, F1 0.9565, false positive rate 0.0, investigation completion 0.90 (2 abstentions), average tool calls 4.0, average time 0.839s, unsupported conclusion rate 0.0. The one false negative is SX012, a deliberately borderline trace the agent abstained on instead of guessing.

## What I would do differently with more time

First, run it live: get a free Gemini key, run the same 20 traces in live mode, and compare the live precision and recall with the offline numbers — that is the single most useful next step. Second, test on more and messier data: traces with missing fields, out-of-order events, and several IPs in one incident. Third, replace the free DuckDuckGo search with a real threat-intel API key. Fourth, let the live planner skip a tool when the evidence already answers the question, instead of running every tool every time. Fifth, build a proper human-approval screen with roles, so approving a block is a real action with a name and a timestamp, not a line in a report. And I would add a confidence number that comes from the graph itself — the share of supporting edges — and check whether it lines up with how often the verdict is right.
