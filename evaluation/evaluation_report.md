# SENTINEL-X Evaluation Report

Mode: **offline evidence-graph evaluation — LLM reasoning not exercised; live Gemini run pending a free key.**

Method: the agent ran over 20 synthetic labelled traces (12 malicious / 8 benign) in offline mode. Each trace went through the full LangGraph pipeline (plan → logs → IP/device → evidence graph → verification → risk → human-approval gate). Abstentions (INSUFFICIENT_EVIDENCE) count as NOT malicious for precision/recall. Metrics were computed with scikit-learn (`precision_score`, `recall_score`, `f1_score`, `confusion_matrix`) in `sentinel_x/evaluation.py`, called by `evaluation/run_evaluation.py`, and stored in `evaluation/evaluation_report.json`. Nothing below is hand-written; the numbers in the table match that JSON file exactly.

## Metrics

- n_traces: 20
- true_positives: 11
- false_positives: 0
- false_negatives: 1
- true_negatives: 8
- precision: 1.0
- recall: 0.9167
- f1_score: 0.9565
- false_positive_rate: 0.0
- investigation_completion_rate: 0.9
- abstentions: 2
- avg_tool_calls: 4.0
- avg_execution_time_seconds: 0.839
- unsupported_conclusion_rate: 0.0
- unsupported_conclusions: 0
- total_conclusions: 20

## What each metric means here, why it is that value, and what would improve it

**Precision — 1.0.** Precision answers one question: when the agent said MALICIOUS, how often was it right? It said MALICIOUS 11 times, and all 11 were truly malicious, so 11 / (11 + 0) = 1.0. There were no false positives at all. That is the number I care about most, because a false positive in this system means a real user gets blocked or locked out. Why is it 1.0 here? Because the malicious traces in my set are clearly separated from the benign ones — the smallest correct malicious score is 3.5 (SX011) and the largest benign score that got a firm verdict is 1.0 (SX019), so there is a wide gap and nothing sits on the wrong side of the line. What would improve it? Nothing — it is already at the maximum. What would keep it there on harder data is the verifier: a MALICIOUS draft needs 3 supporting graph edges, so a single strong signal cannot produce a call on its own. The honest warning is that 1.0 on 20 hand-designed traces does not mean 1.0 on real logs, where the gap between malicious and benign is much narrower.

**Recall — 0.9167.** Recall answers: of all the truly malicious traces, how many did the agent catch? It caught 11 of 12, so 11 / 12 = 0.9167. The one it missed is SX012, a deliberately borderline malicious trace (IP 203.0.113.88, 9 failures, 0 successes, 2 am, known device, no country change, score 2.0) where the agent abstained with INSUFFICIENT_EVIDENCE instead of guessing. That abstention is counted as a false negative, which is the honest way to score it — the agent did not call it malicious, and it was malicious. What would improve recall? Lowering the malicious threshold from 3.0 to 2.0 would catch SX012 and push recall to 1.0. I did not do that, because the same change would also catch SX020 (a benign trace at score 1.5) only if the threshold went below 1.5, which it would not — but it would make the agent call more borderline traces malicious in general, and on real data that trades false negatives for false positives. The better improvement is more evidence, not a lower bar: if the agent could pull a longer log window or device history for SX012, the score would move on facts instead of on a tuned threshold.

**F1 score — 0.9565.** F1 is the balance of precision and recall: 2 × (1.0 × 0.9167) / (1.0 + 0.9167) = 0.9565. It is high because precision is perfect and recall is only one trace short. It would rise to 1.0 only if recall also reached 1.0, which means catching SX012, and the paragraph above explains why I did not force that. On a bigger and messier test set, F1 is the number to watch, because precision and recall usually pull in opposite directions and F1 shows whether a change helped both or just traded one for the other.

**False positive rate — 0.0.** This answers: of all the truly benign traces, how many were wrongly called malicious? None of the 8 benign traces was called malicious, so 0 / (0 + 8) = 0.0. It is 0.0 for the same reason precision is 1.0: the benign traces are clearly benign (scores 0.0 to 1.0, daytime, known device, no country change), and the verifier blocks a MALICIOUS draft that the graph does not support. What would improve it? Nothing, it is already at the floor. What would threaten it on real data is a benign trace that looks malicious — for example, a real user who forgets a password and tries 12 times at 2 am on a new phone. That trace would score 3.0 or more in the current bands and get called malicious. The fix for that is not a metric tweak; it is more evidence types, like checking whether the device has ever logged in successfully before, so a new-but-legitimate device is not treated the same as an unknown one.

**Investigation completion rate — 0.9.** This is the share of traces that got a firm verdict (MALICIOUS or BENIGN) instead of abstaining: 18 of 20, so 0.9. The 2 abstentions are SX012 (malicious, score 2.0) and SX020 (benign, score 1.5, 6 failures at 1 am from a known device). Both scores sit between the 1.0 and 3.0 thresholds, so the agent said INSUFFICIENT_EVIDENCE and listed what was missing. What would improve it? More evidence per trace. Both abstentions are traces where one or two more facts would have pushed the score out of the middle band — a longer log window for SX012, or device history for SX020. A lower completion rate is not always bad: an agent that abstains on 10% of hard cases and is right on the other 90% is more useful than one that guesses on all 100% and is wrong on 10%. The number to watch alongside it is the unsupported conclusion rate, which is 0.0 here.

**Abstentions — 2.** This is the count behind the completion rate: 2 of 20 traces ended in INSUFFICIENT_EVIDENCE. It is worth stating on its own because abstention is a feature, not a failure mode. Both abstentions were correct behaviour for the evidence available. If this number were 0 on a harder test set, I would be suspicious — it would mean the agent never admits it does not know. If it were 10 of 20, the thresholds would be too wide or the evidence too thin. Two of 20, both borderline by design, is about what I expected.

**Average tool calls — 4.0.** Every investigation made exactly 4 tool calls: 1 for `analyse_logs`, 2 in the `check_ip_device` node (`check_ip` plus `search_threat_intel`), and 1 for `build_evidence_graph`. The average is 4.0 with no variation, because the offline plan runs the same five step names in the same order every time. What would improve it? In live mode the planner can skip a tool when the evidence already answers the question, so the average could drop — but that has not been measured, and a lower number is not automatically better. Four calls for a full investigation is already small. The number matters mainly as a cost and latency check: each call is a function call or a network request, and 4 per investigation is cheap.

**Average execution time — 0.839 seconds.** This is the mean wall-clock time per investigation across the 20 traces, from the fastest (SX012, 0.719s) to the slowest (SX009, 1.211s). The spread comes from the network calls in `search_threat_intel` and `check_ip`, not from the agent's reasoning. What would improve it? Caching threat-intel results, or skipping the threat-intel search when the IP is a TEST-NET synthetic address (it already returns 0 hits for those, but it still makes the request). A live Gemini run would be slower than 0.839s, because every LLM call adds network time, and that has not been measured yet. For an offline pipeline, under a second per investigation is fast enough that time is not the bottleneck; evidence quality is.

**Unsupported conclusion rate — 0.0.** This is the share of conclusions with no supporting graph edge: 0 of 20. A MALICIOUS verdict with zero malicious-supporting edges, or a BENIGN verdict with zero benign-supporting edges and a score above 0.5, would count as unsupported. None of the 20 verdicts was unsupported, because every verdict in this set had edges behind it — the demo trace had 5 malicious edges, and even the benign traces had benign edges from the known device and unchanged country. What would improve it? Nothing, it is already 0.0. What keeps it there is the verifier: a draft without 3 supporting edges gets revised to INSUFFICIENT_EVIDENCE before it ever becomes a conclusion. This is the metric that proves the evidence graph is not decoration. If it ever rises above 0.0, it means the agent is concluding things its own evidence does not back, and that is the first thing I would fix.

## Confusion counts, in plain words

True positives 11: eleven malicious traces correctly called MALICIOUS. False positives 0: no benign trace was wrongly called malicious. False negatives 1: SX012, malicious, abstained. True negatives 8: all eight benign traces were not called malicious — seven got a firm BENIGN verdict (SX013–SX019) and one abstained (SX020), and abstentions count as NOT malicious in the binary scoring in `sentinel_x/evaluation.py` (malicious = 1, everything else = 0, for both true and predicted labels).

## Per-trace results

| id | true | predicted | score | risk | tool calls | time (s) | revised |
|---|---|---|---|---|---|---|---|
| SX001 | malicious | MALICIOUS | 6.0 | HIGH | 4 | 0.78 | False |
| SX002 | malicious | MALICIOUS | 5.5 | HIGH | 4 | 0.77 | False |
| SX003 | malicious | MALICIOUS | 4.5 | HIGH | 4 | 1.007 | False |
| SX004 | malicious | MALICIOUS | 4.5 | HIGH | 4 | 1.026 | False |
| SX005 | malicious | MALICIOUS | 5.5 | HIGH | 4 | 0.82 | False |
| SX006 | malicious | MALICIOUS | 4.0 | HIGH | 4 | 1.023 | False |
| SX007 | malicious | MALICIOUS | 4.0 | HIGH | 4 | 0.98 | False |
| SX008 | malicious | MALICIOUS | 4.0 | HIGH | 4 | 0.723 | False |
| SX009 | malicious | MALICIOUS | 4.5 | HIGH | 4 | 1.211 | False |
| SX010 | malicious | MALICIOUS | 4.0 | HIGH | 4 | 0.898 | False |
| SX011 | malicious | MALICIOUS | 3.5 | HIGH | 4 | 0.745 | False |
| SX012 | malicious | INSUFFICIENT_EVIDENCE | 2.0 | UNKNOWN | 4 | 0.719 | False |
| SX013 | benign | BENIGN | 0.0 | LOW | 4 | 0.762 | False |
| SX014 | benign | BENIGN | 0.0 | LOW | 4 | 0.751 | False |
| SX015 | benign | BENIGN | 0.5 | LOW | 4 | 0.719 | False |
| SX016 | benign | BENIGN | 0.0 | LOW | 4 | 0.754 | False |
| SX017 | benign | BENIGN | 0.5 | LOW | 4 | 0.742 | False |
| SX018 | benign | BENIGN | 0.5 | LOW | 4 | 0.855 | False |
| SX019 | benign | BENIGN | 1.0 | LOW | 4 | 0.758 | False |
| SX020 | benign | INSUFFICIENT_EVIDENCE | 1.5 | UNKNOWN | 4 | 0.732 | False |

A per-trace paragraph for each of these 20 traces, with what the trace was and why it got the verdict it did, is in `docs/submission/monitoring_report.md`.

## Limitations of this evaluation

- Offline mode only. The LLM did not reason in these runs. These numbers describe the evidence-graph scorer and the verifier, not Gemini.
- Only 20 traces, all hand-designed by me, all synthetic. A test set this small and this clean will flatter any system. The gap between the lowest malicious score (3.5) and the highest firm benign score (1.0) is wide, and real data will not be that kind.
- The verifier revised 0 verdicts in this set. The revision rule is tested in the unit tests, but this evaluation does not show it firing on a real trace.
- Tool calls and time are for the offline plan. Live-mode numbers will differ and have not been measured.
