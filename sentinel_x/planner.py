"""Feature 2 — Dynamic Investigation Planner.

Live mode: the LLM reads the evidence so far and picks the next tool
— there is no fixed step list. Offline mode: the same step names are
followed in order, but every step is still executed and logged, and
the output is labelled offline.
"""
from __future__ import annotations
PLAN_STEPS = ["analyse_logs", "check_ip", "search_threat_intel", "build_evidence_graph", "verify_findings"]

def offline_plan(trace: dict) -> list[str]:
    return list(PLAN_STEPS)

def live_plan(llm, goal: str, evidence_so_far: str) -> list[str]:
    """Ask the LLM which tool to run next, with JSON retry in llm.call_json."""
    prompt = (
        "You are planning a cyber incident investigation.\n"
        f"Goal: {goal}\nEvidence so far: {evidence_so_far}\n"
        "Available tools: analyse_logs, check_ip, search_threat_intel, build_evidence_graph, verify_findings.\n"
        'Reply JSON only: {"next_tool": "<one tool name>", "reason": "<one sentence>"}.'
    )
    return llm.call_json(prompt)
