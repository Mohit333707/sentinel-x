"""Feature 4 — Uncertainty & Abstention.

If supporting evidence is below threshold, or evidence contradicts
itself, SENTINEL-X says INSUFFICIENT_EVIDENCE and lists exactly what
is missing — it never makes a confident guess.
Thresholds (documented, offline mode): score >= 3.0 -> MALICIOUS,
score <= 1.0 -> BENIGN, anything in between -> INSUFFICIENT_EVIDENCE.
Live mode: the LLM applies the same rule to the evidence graph.
"""
from __future__ import annotations
MALICIOUS_THRESHOLD = 3.0
BENIGN_THRESHOLD = 1.0

def missing_evidence(trace: dict) -> list[str]:
    missing = []
    if int(trace.get("failed_logins", 0)) < 8:
        missing.append("more failed-login history / a longer log window (failed logins below 8)")
    if trace.get("device_known", True):
        missing.append("device fingerprint / device history for the unknown-device check")
    if not trace.get("country_change", False):
        missing.append("geolocation / country history for the IP")
    if int(trace.get("successful_login", 0)) == 0:
        missing.append("whether any login actually succeeded after the failures")
    if trace.get("hour") is None:
        missing.append("exact timestamp / hour of the successful login")
    return missing

def decide_verdict(score: float, trace: dict, malicious_support: int = 0, benign_support: int = 0) -> dict:
    """Return {verdict, confidence, missing_evidence, reason}."""
    # Contradiction: strong evidence both ways -> abstain.
    if malicious_support >= 2 and benign_support >= 2 and abs(score - 2.0) <= 1.0:
        return {"verdict": "INSUFFICIENT_EVIDENCE", "confidence": 0.4,
                "missing_evidence": missing_evidence(trace) + ["resolve contradictory signals (known device vs night-time burst)"],
                "reason": "Contradictory evidence: malicious and benign signals are both strong."}
    if score >= MALICIOUS_THRESHOLD:
        return {"verdict": "MALICIOUS", "confidence": min(0.95, 0.6 + score * 0.05),
                "missing_evidence": [], "reason": f"Evidence score {score} >= threshold {MALICIOUS_THRESHOLD}."}
    if score <= BENIGN_THRESHOLD:
        return {"verdict": "BENIGN", "confidence": min(0.9, 0.85 - score * 0.05),
                "missing_evidence": [], "reason": f"Evidence score {score} <= threshold {BENIGN_THRESHOLD}."}
    return {"verdict": "INSUFFICIENT_EVIDENCE", "confidence": 0.45,
            "missing_evidence": missing_evidence(trace),
            "reason": f"Evidence score {score} is between {BENIGN_THRESHOLD} and {MALICIOUS_THRESHOLD}: not enough to decide."}
