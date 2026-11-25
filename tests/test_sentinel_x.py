"""SENTINEL-X tests — no API key needed. Run: pytest tests/ -v"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel_x.graph import build_evidence_graph, evidence_score, graph_summary, supporting_edges
from sentinel_x.uncertainty import decide_verdict, missing_evidence
from sentinel_x.verifier import verify_verdict
from sentinel_x.audit import AuditTrail
from sentinel_x.evaluation import compute_metrics
from sentinel_x.agent import SentinelXAgent
from sentinel_x.tools import analyse_logs, parse_goal
from sentinel_x.llm import NoAPIKeyError, LLMClient

MAL = {"ip": "192.0.2.45", "failed_logins": 35, "successful_login": 1, "hour": 2, "device_known": False, "country_change": True}
BEN = {"ip": "192.0.2.10", "failed_logins": 2, "successful_login": 1, "hour": 10, "device_known": True, "country_change": False}
BORDER = {"ip": "203.0.113.88", "failed_logins": 9, "successful_login": 0, "hour": 2, "device_known": True, "country_change": False}

def test_graph_builds_nodes_and_edges():
    g = build_evidence_graph(MAL)
    assert g.number_of_nodes() >= 6 and g.number_of_edges() >= 5
    assert any(d.get("relation") == "attempted_from" for _, _, d in g.edges(data=True))

def test_graph_summary_counts():
    s = graph_summary(build_evidence_graph(MAL))
    assert s["malicious_supporting_edges"] >= 3
    assert s["nodes"] == build_evidence_graph(MAL).number_of_nodes()

def test_evidence_score_malicious_high_benign_low():
    assert evidence_score(MAL) >= 3.0
    assert evidence_score(BEN) <= 1.0

def test_verification_revises_contradictory_verdict():
    # Draft MALICIOUS but a graph with almost no malicious support -> must revise.
    g = build_evidence_graph(BEN)  # benign graph
    out = verify_verdict("MALICIOUS", g, 0.0, BEN)
    assert out["revised"] is True and out["final_verdict"] == "INSUFFICIENT_EVIDENCE"

def test_verification_keeps_supported_verdict():
    g = build_evidence_graph(MAL)
    out = verify_verdict("MALICIOUS", g, evidence_score(MAL), MAL)
    assert out["revised"] is False and out["final_verdict"] == "MALICIOUS"

def test_abstention_on_insufficient_evidence():
    d = decide_verdict(evidence_score(BORDER), BORDER)
    assert d["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert d["missing_evidence"], "abstention must list missing evidence"

def test_decide_malicious_and_benign():
    assert decide_verdict(evidence_score(MAL), MAL)["verdict"] == "MALICIOUS"
    assert decide_verdict(evidence_score(BEN), BEN)["verdict"] == "BENIGN"

def test_audit_logging(tmp_path):
    a = AuditTrail(str(tmp_path / "test.db"))
    a.log("SX-TEST", "tool_call", "analyse_logs", "test detail", verdict="MALICIOUS")
    a.register_trace("SX-TEST", "goal", "MALICIOUS", "offline")
    assert len(a.history("SX-TEST")) == 1
    assert a.counts()["traces"] == 1
    a.close()

def test_evaluation_metrics_computation():
    m = compute_metrics(["malicious", "malicious", "benign"], ["MALICIOUS", "BENIGN", "BENIGN"], [4, 4, 4], [0.1, 0.1, 0.1], 0, 3)
    assert m["precision"] == 1.0 and m["recall"] == 0.5 and m["false_positive_rate"] == 0.0
    assert m["unsupported_conclusion_rate"] == 0.0

def test_analyse_logs_pandas():
    a = analyse_logs(MAL)
    assert a["failed_logins"] == 35 and a["night_time"] is True and a["burst"] is True
    assert a["failure_rate"] > 0.9

def test_parse_goal_extracts_ip_and_counts():
    t = parse_goal("Investigate suspicious login activity. IP: 192.0.2.45, Failed logins: 35, Successful login: 1, Time: 02:30 AM, Device: Unknown")
    assert t["ip"] == "192.0.2.45" and t["failed_logins"] == 35 and t["hour"] == 2 and t["device_known"] is False

def test_offline_agent_demo_end_to_end(tmp_path):
    agent = SentinelXAgent(offline=True, db_path=str(tmp_path / "x.db"), out_dir=str(tmp_path))
    r = agent.run("Investigate suspicious login activity. IP: 192.0.2.45, Failed logins: 35, Successful login: 1, Time: 02:30 AM, Device: Unknown")
    assert r["verdict"] == "MALICIOUS" and r["risk"] == "HIGH"
    assert r["tool_calls"] >= 3 and os.path.exists(r["report_path"]) and os.path.exists(r["trace_path"])

def test_offline_agent_abstains_on_borderline(tmp_path):
    agent = SentinelXAgent(offline=True, db_path=str(tmp_path / "x.db"), out_dir=str(tmp_path))
    r = agent.run("Investigate suspicious login activity. IP: 203.0.113.88, Failed logins: 9, Successful login: 0, Time: 02:00 AM, Device: Known", trace=BORDER)
    assert r["verdict"] == "INSUFFICIENT_EVIDENCE"

def test_simulated_threat_intel_failure_recovers(tmp_path):
    # The threat-intel tool is pointed at a host that does not exist, so it
    # fails for real. The agent must still finish with a verdict and say
    # plainly that the threat-intel evidence is missing.
    agent = SentinelXAgent(offline=True, db_path=str(tmp_path / "x.db"), out_dir=str(tmp_path),
                           simulate_failure={"threat-intel"})
    r = agent.run("Investigate suspicious login activity. IP: 192.0.2.45, Failed logins: 35, Successful login: 1, Time: 02:30 AM, Device: Unknown")
    assert r["verdict"] == "MALICIOUS" and r["risk"] == "HIGH"
    ti = r["threat_intel"]
    assert ti["count"] == 0 and ti.get("recovered") is True and ti.get("attempts") == 2
    assert "error" in ti and ti["error"]
    assert any("FAILED" in s and "Recovered" in s for s in r["steps"])
    assert r["simulated_failure"] == ["threat-intel"]

def test_no_key_raises_clean_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    try:
        LLMClient(); assert False, "should have raised"
    except NoAPIKeyError as e:
        assert "aistudio.google.com" in str(e)
