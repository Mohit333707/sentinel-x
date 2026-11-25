# SENTINEL-X — Submission Checklist

For the Xiarch Bharat Agentic AI Engineer Intern take-home assignment.
Deadline: 26 November 2026, 11:59 PM IST. Total time spent: 15 hours.

## Google Form — what goes where

- Role: Agentic AI Engineer Intern
- GitHub Repo / Code Link: https://github.com/Mohit333707/sentinel-x
- Upload Code (zip): docs/submission/05-Code.zip
- Architecture Diagram: docs/submission/01-Architecture-Diagram.pdf
- Sample Run Transcripts / Logs: docs/submission/02-Sample-Run-Transcript.pdf (3 runs, 13 pages)
- Synthetic / Test Traces Used (with labels): docs/submission/03-Synthetic-Test-Traces.csv
- Monitoring Report / Dashboard Output: docs/submission/04-Monitoring-Report.pdf
- One-page write-up: docs/submission/06-One-Page-Writeup.pdf (exactly 1 page)
- Text answers (design decisions, limitations, domain/goal, assumptions, approach,
  precision/recall, production-readiness, trace generation): docs/submission/FORM-ANSWERS.md
- Total time spent (hours): 15
- Confirm checkbox: tick "I confirm this work is my own and was not copied from another source", then Submit.

## Evaluation numbers (from evaluation/evaluation_report.json)

20 synthetic traces (12 malicious, 8 benign). Precision 1.0, Recall 0.9167,
F1 0.9565, False Positive Rate 0.0, Completion 0.90 (2 abstentions),
avg tool calls 4.0, avg time 0.839s, unsupported conclusion rate 0.0.
Offline evidence-graph evaluation — live Gemini run pending a free key.

## Run it

```bash
pip install -r requirements.txt
python main.py --demo --offline
python -m pytest tests/ -v
cd frontend && npm install && npm run dev
```
