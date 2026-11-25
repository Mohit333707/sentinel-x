# SENTINEL-X — 1-Minute Talk (simple English)

"Hello, I am Mohit Kumar. I built SENTINEL-X, an autonomous agent that investigates suspicious login activity. Most tools decide from one alert. Mine does not. It builds an evidence graph that connects the IP, the user, the device and the login events, and only then it decides. A planner built with LangGraph chooses the next tool from the evidence so far — there is no fixed step list. After a draft verdict, a verification step checks it again against the graph and changes it if the evidence does not support it. If the evidence is too weak, it does not guess — it says INSUFFICIENT_EVIDENCE and lists what is missing. And it never blocks an IP or resets a password without human approval. Every step is saved in SQLite and a JSON trace, so any decision can be replayed. I tested it on 20 synthetic traces. Thank you."

## Q&A — the 5 features
1. **Evidence Graph?** NetworkX graph: nodes are IP, user, device, events; edges say how they connect and whether they support a malicious or benign reading. A verdict needs supporting edges, not one alert.
2. **Dynamic Planner?** LangGraph StateGraph. In live mode the LLM reads the evidence so far and picks the next tool. Offline mode runs the same step names in order, clearly labelled.
3. **Self-Verification?** After the draft verdict, `verifier.py` counts supporting edges and checks for contradictions. A MALICIOUS verdict needs at least 3 malicious-supporting edges, otherwise it is revised to INSUFFICIENT_EVIDENCE and the revision is logged.
4. **Uncertainty / Abstention?** Evidence score ≥ 3.0 is MALICIOUS, ≤ 1.0 is BENIGN, between is INSUFFICIENT_EVIDENCE, with the missing evidence listed. Contradictory evidence also abstains.
5. **Audit Trail?** `audit.py` writes every tool call, decision, revision and recommendation to SQLite (`sentinel_x.db`) and a JSON trace per run, with timestamps. `python main.py --trace <id>` replays a run.

## Likely extra questions
- **Why not just use rules?** Live mode uses the LLM to reason each step. The offline scorer is only for testing without a key, and it is labelled as offline.
- **What if the LLM is wrong?** That is exactly why verification and abstention exist — a wrong draft gets checked against the graph before it becomes a final verdict.
- **Is it production-ready?** Not yet. It needs a live Gemini run on real (anonymised) logs, a real IP-intel key, and a human-approval UI before production. The evaluation here is honest offline evidence.
- **How did you test it?** 20 synthetic traces, 12 malicious / 8 benign, hand-designed. Metrics are computed with scikit-learn from real offline runs — see `evaluation/evaluation_report.md`.
