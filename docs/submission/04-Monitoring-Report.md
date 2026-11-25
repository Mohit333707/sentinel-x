# SENTINEL-X — Monitoring Report

**Mode:** offline evidence-graph evaluation — LLM reasoning not exercised; live Gemini run pending a free key.
**Run date:** 25 Nov 2026 | **Traces:** 20 (12 malicious / 8 benign, synthetic, TEST-NET IPs only)
**Source of numbers:** `evaluation/evaluation_report.json`, computed with scikit-learn by `evaluation/run_evaluation.py`. Test traces: `data/synthetic_traces.csv` and `.json` (also shipped as `docs/submission/03-Synthetic-Test-Traces.csv` and `.json`).

## Run summary

- Precision: 1.0 | Recall: 0.9167 | F1: 0.9565 | False positive rate: 0.0
- Investigation completion rate: 0.9 (abstentions: 2 of 20 — SX012 and SX020)
- Avg tool calls per investigation: 4.0 | Avg execution time: 0.839s
- Unsupported conclusion rate: 0.0 (0 of 20 conclusions had no supporting graph edge)
- Confusion counts: TP 11, FP 0, FN 1, TN 8
- Audit trail at evaluation time: 21 traces, 229 audit events in `sentinel_x.db` (the count grows with every run, because every run is logged). Every run also writes a JSON trace to `reports/`.

## Metrics table

| Metric | Value |
|---|---|
| True positives | 11 |
| False positives | 0 |
| False negatives | 1 |
| True negatives | 8 |
| Precision | 1.0 |
| Recall | 0.9167 |
| F1 score | 0.9565 |
| False positive rate | 0.0 |
| Investigation completion rate | 0.9 |
| Abstentions | 2 |
| Avg tool calls | 4.0 |
| Avg execution time (s) | 0.839 |
| Unsupported conclusion rate | 0.0 |
| Unsupported conclusions | 0 |
| Total conclusions | 20 |

## Per-trace table

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

## Per-trace analysis — all 20 traces, one by one

**SX001 — malicious, predicted MALICIOUS, score 6.0, HIGH, 4 tool calls, 0.78s.** The strongest trace in the set: IP 192.0.2.45, 35 failed logins, 1 success, 2 am, unknown device, country changed. Every signal fired at once, so the score hit the maximum 6.0 (2.0 for 30+ failures, 1.0 night, 1.0 unknown device, 1.0 country change, 1.0 success after failures). The verifier found the draft backed by the graph and kept it. This is also the demo trace pattern (trace id SX-DBB1B7B7 in the sample run). Correct, and the easiest call in the set.

**SX002 — malicious, predicted MALICIOUS, score 5.5, HIGH, 4 tool calls, 0.77s.** IP 192.0.2.78, 28 failed logins, 1 success, 3 am, unknown device, country changed. The score is 5.5 because 28 failures sit in the 15+ band (1.5) rather than the 30+ band (2.0); the other four signals all fired. Correct, with room to spare above the 3.0 threshold.

**SX003 — malicious, predicted MALICIOUS, score 4.5, HIGH, 4 tool calls, 1.007s.** IP 198.51.100.12, 22 failed logins, 1 success, 1 am, unknown device, no country change. The country staying the same cost it 1.0, but the failure count, night hour, unknown device, and success after failures still add up to 4.5. Correct. This trace shows the graph matters: one benign edge (country same) did not outweigh four malicious ones.

**SX004 — malicious, predicted MALICIOUS, score 4.5, HIGH, 4 tool calls, 1.026s.** IP 203.0.113.9, 18 failed logins, 1 success, 4 am, known device, country changed. The device was known, which points benign, but 18 failures, the night hour, the country change, and the success after failures still reach 4.5. Correct. A known device alone does not clear a trace when everything else is suspicious.

**SX005 — malicious, predicted MALICIOUS, score 5.5, HIGH, 4 tool calls, 0.82s.** IP 192.0.2.101, 15 failed logins, 1 success, midnight (hour 0), unknown device, country changed. The midnight hour is the deepest night signal in the set. Score 5.5 (1.5 for 15 failures, plus 1.0 each for night, unknown device, country change, success after failures). Correct.

**SX006 — malicious, predicted MALICIOUS, score 4.0, HIGH, 4 tool calls, 1.023s.** IP 198.51.100.44, 12 failed logins, 0 successes, 2 am, unknown device, country changed. No login succeeded here, so there is no "success after failures" point, yet the score still reaches 4.0 (1.0 for 12 failures, 1.0 night, 1.0 unknown device, 1.0 country change). Correct. This trace matters because it proves the agent does not need a success to call a trace malicious; a burst at night from an unknown device with a country change is enough.

**SX007 — malicious, predicted MALICIOUS, score 4.0, HIGH, 4 tool calls, 0.98s.** IP 203.0.113.27, 31 failed logins, 1 success, 5 am, known device, no country change. The 31 failures alone give 2.0, the 5 am hour is still inside the night band, and the success after failures adds 1.0, so it reaches 4.0 even with a known device and no country change. Correct, and a good example of why the score adds up signals instead of letting one benign fact cancel the rest.

**SX008 — malicious, predicted MALICIOUS, score 4.0, HIGH, 4 tool calls, 0.723s.** IP 192.0.2.133, 9 failed logins, 1 success, 3 am, unknown device, country changed. Nine failures is the smallest count in the malicious set that still gets the full treatment: 1.0 for the 8+ band, 1.0 night, 1.0 unknown device, 1.0 country change. The success after failures does not add a point here because the count is below 10. Still 4.0, still correct, and the fastest malicious run in the set at 0.723s.

**SX009 — malicious, predicted MALICIOUS, score 4.5, HIGH, 4 tool calls, 1.211s.** IP 198.51.100.61, 25 failed logins, 1 success, midnight, unknown device, no country change. Score 4.5 (1.5 for 25 failures, 1.0 night, 1.0 unknown device, 1.0 success after failures). Correct. It was also the slowest run in the whole evaluation at 1.211 seconds, which is still fast in absolute terms — the spread across all 20 traces is only 0.719s to 1.211s, and it comes from network timing on the threat-intel search, not from the agent thinking longer.

**SX010 — malicious, predicted MALICIOUS, score 4.0, HIGH, 4 tool calls, 0.898s.** IP 203.0.113.52, 14 failed logins, 1 success, 2 am, known device, country changed. Score 4.0 (1.0 for 14 failures, 1.0 night, 1.0 country change, 1.0 success after failures). The known device is the one benign-leaning fact, and it does not stop the call. Correct.

**SX011 — malicious, predicted MALICIOUS, score 3.5, HIGH, 4 tool calls, 0.745s.** IP 192.0.2.167, 20 failed logins, 0 successes, 4 am, unknown device, no country change. The lowest-scoring correct malicious call in the set, and the closest to the 3.0 line: 1.5 for 20 failures, 1.0 night, 1.0 unknown device, and no country-change or success point. Correct, but only 0.5 above the threshold. If the hour had been daytime, this trace would have abstained. That is the threshold doing its job at the edge.

**SX012 — malicious, predicted INSUFFICIENT_EVIDENCE, score 2.0, UNKNOWN, 4 tool calls, 0.719s.** The one false negative, and the most important trace in the set. IP 203.0.113.88, 9 failed logins, 0 successes, 2 am, known device, no country change. Score 2.0 (1.0 for 9 failures, 1.0 night, nothing else). The device is known, the country did not change, and no login succeeded, so three of the five signals are missing or point benign. The score lands between 1.0 and 3.0, so `decide_verdict()` returns INSUFFICIENT_EVIDENCE and lists the missing evidence: a longer log window, device fingerprint history, geolocation history, and whether any login succeeded. The verifier keeps the abstention. This is counted as a false negative, which is why recall is 0.9167 and not 1.0. I kept it that way instead of lowering the threshold, because calling a mixed-signal trace malicious on a score of 2.0 would be guessing, and guessing is what the abstention feature exists to stop.

**SX013 — benign, predicted BENIGN, score 0.0, LOW, 4 tool calls, 0.762s.** IP 192.0.2.10, 2 failed logins, 1 success, 10 am, known device, no country change. Nothing suspicious at all: two failures is below every scoring band, the hour is daytime, the device is known, the country is the same. Score 0.0. Correct, and the cleanest benign case in the set.

**SX014 — benign, predicted BENIGN, score 0.0, LOW, 4 tool calls, 0.751s.** IP 198.51.100.20, 1 failed login, 1 success, 2 pm, known device, no country change. One mistyped password at lunch, on a known device. Score 0.0. Correct. This is the trace the false positive rate is really about: if the agent had called this malicious, a real user would have been locked out for one typo.

**SX015 — benign, predicted BENIGN, score 0.5, LOW, 4 tool calls, 0.719s.** IP 203.0.113.15, 4 failed logins, 1 success, 9 am, known device, no country change. Four failures earns 0.5 (the 3+ band), and nothing else fires. Score 0.5 is below the 1.0 benign threshold, so the verdict is BENIGN. Correct.

**SX016 — benign, predicted BENIGN, score 0.0, LOW, 4 tool calls, 0.754s.** IP 192.0.2.22, 0 failed logins, 1 success, 11 am, known device, no country change. A clean login with no failures at all. Score 0.0. Correct.

**SX017 — benign, predicted BENIGN, score 0.5, LOW, 4 tool calls, 0.742s.** IP 198.51.100.33, 3 failed logins, 1 success, 4 pm, known device, no country change. Three failures is the smallest count that scores anything (0.5), and the daytime hour, known device, and same country keep it benign. Correct.

**SX018 — benign, predicted BENIGN, score 0.5, LOW, 4 tool calls, 0.855s.** IP 203.0.113.40, 5 failed logins, 1 success, 1 pm, known device, no country change. Five failures, still 0.5, still benign. Correct. SX015, SX017, and SX018 together show the benign band has room in it: a few failures in the daytime from a known device do not push a trace toward malicious.

**SX019 — benign, predicted BENIGN, score 1.0, LOW, 4 tool calls, 0.758s.** IP 192.0.2.55, 0 failed logins, 1 success, 2 am, known device, no country change. The only signal is the night hour (1.0). No failures, no unknown device, no country change. Score 1.0 sits exactly on the benign threshold (1.0 or less means BENIGN), so the verdict is BENIGN. Correct, but it is the closest benign call to the line, and it shows the threshold is doing real work on this side too: one more signal and this trace would have abstained like SX020.

**SX020 — benign, predicted INSUFFICIENT_EVIDENCE, score 1.5, UNKNOWN, 4 tool calls, 0.732s.** The second abstention. IP 198.51.100.77, 6 failed logins, 1 success, 1 am, known device, no country change. Score 1.5 (0.5 for 6 failures, 1.0 night). That sits between 1.0 and 3.0, so the agent abstains and lists the missing evidence, even though the true label is benign. This abstention does not hurt precision or recall (it counts as NOT malicious, which matches the benign label), but it does lower the completion rate to 0.90. It is correct behaviour: six failures at 1 am is odd enough that a firm BENIGN would be a guess in the other direction.

## Tool-call counts

Every investigation made exactly 4 tool calls: 1 for `analyse_logs`, 2 in the `check_ip_device` node (`check_ip` plus `search_threat_intel`), and 1 for `build_evidence_graph`. The average is 4.0 with no variation across the 20 traces, because the offline plan runs the same five step names in the same order every time. In live mode the planner can pick the next tool, so this number would vary; in this offline run it does not, and I am not going to pretend it does. Total tool calls across the evaluation: 80.

## Execution time

Average execution time is 0.839 seconds per investigation. The fastest run was SX012 at 0.719s and the slowest was SX009 at 1.211s. The spread comes from the network calls in `check_ip` (skipped for TEST-NET IPs) and `search_threat_intel` (free DuckDuckGo HTML search), not from the agent's reasoning, which is a few dictionary lookups and a small graph build. These times are for the offline pipeline on this machine; a live Gemini run would be slower, because every LLM call adds network time, and I have not measured that yet.

## Audit counts

At the evaluation run, `sentinel_x.db` held 21 traces and 229 audit events across the `audit_events` and `traces` tables. Every investigation logs a start event, one event per step (9 steps in the demo run), and a decision event with the draft verdict, final verdict, revised flag, and verifier reasons. Every run also writes `reports/incident_report_<trace_id>.md` and `reports/trace_<trace_id>.json`. The count grows with every run. To check the current counts, run `python -c "import sqlite3; c = sqlite3.connect('sentinel_x.db'); print(c.execute('select count(*) from audit_events').fetchone(), c.execute('select count(*) from traces').fetchone())"`. To see one trace's history, run `python main.py --trace SX-DBB1B7B7`.

## What the verifier did

The verifier revised 0 verdicts across the 20 traces (`revised_by_verifier: false` for every trace in `evaluation_report.json`). That does not mean the verifier did nothing: it checked all 20 drafts against their graphs and confirmed them. It means no draft in this set failed the 3-edge rule and no draft contradicted its graph. The rule was tested separately in the unit tests in `tests/test_sentinel_x.py`, where a MALICIOUS draft with fewer than 3 supporting edges is revised to INSUFFICIENT_EVIDENCE. On this particular set of 20 traces, the drafts were all well supported, so there was nothing to revise.

## Limitations (honest)

- Offline evaluation only: the LLM did not reason in these runs; the numbers measure the evidence-graph pipeline, not live Gemini reasoning. A live run is pending a free API key.
- Synthetic data only (20 hand-designed traces, TEST-NET IPs). No real attacks or real users. The metrics describe these 20 traces.
- The 1 false negative (SX012) is a deliberate borderline case the agent abstained on. That is the abstention feature working, not a crash, and the threshold was not tuned to hide it.
- Every trace made exactly 4 tool calls, because the offline plan is fixed. Live-mode tool-call counts will differ and have not been measured.
- No dangerous action is ever executed without human approval. The monitoring in this report covers verdicts, scores, times, and audit counts — it does not cover any blocking or reset action, because none happened.
