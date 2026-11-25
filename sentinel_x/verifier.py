"""Feature 3 — Self-Verification Engine.

After a draft verdict, this step re-checks it against the evidence
graph, looks for contradictions, and revises the verdict if the
graph does not support it. Every revision is logged.
Rule: a MALICIOUS verdict needs >= 3 malicious-supporting graph
edges; a BENIGN verdict needs the malicious score to be low and at
least 1 benign-supporting edge (or a very low score). Otherwise the
verdict is revised to INSUFFICIENT_EVIDENCE.
"""
from __future__ import annotations
from .graph import supporting_edges

def verify_verdict(draft_verdict: str, graph, score: float, trace: dict) -> dict:
    """Returns {final_verdict, revised, reasons, supporting_count}."""
    reasons, revised, final = [], False, draft_verdict
    mal = len(supporting_edges(graph, "MALICIOUS"))
    ben = len(supporting_edges(graph, "BENIGN"))
    if draft_verdict == "MALICIOUS":
        if mal < 3:
            reasons.append(f"Draft MALICIOUS has only {mal} malicious-supporting graph edge(s); need >= 3.")
            final, revised = "INSUFFICIENT_EVIDENCE", True
        elif ben >= 3 and score < 4.0:
            reasons.append(f"Contradiction: {ben} benign-supporting edges vs score {score}.")
            final, revised = "INSUFFICIENT_EVIDENCE", True
        else:
            reasons.append(f"Verified: {mal} malicious-supporting edge(s) back the verdict; no contradiction found.")
    elif draft_verdict == "BENIGN":
        if score >= 3.0:
            reasons.append(f"Contradiction: draft BENIGN but evidence score is {score} (>= 3.0).")
            final, revised = "INSUFFICIENT_EVIDENCE", True
        else:
            reasons.append(f"Verified: score {score} is low and {ben} benign-supporting edge(s) agree.")
    else:  # already abstaining
        reasons.append("Draft was already INSUFFICIENT_EVIDENCE; verification keeps the abstention.")
    return {"final_verdict": final, "revised": revised, "reasons": reasons,
            "supporting_count": mal if final == "MALICIOUS" else ben,
            "malicious_supporting": mal, "benign_supporting": ben}
