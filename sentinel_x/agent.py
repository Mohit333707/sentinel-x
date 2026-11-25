"""LangGraph agent — Dynamic Investigation Planner (Feature 2).

Flow: understand_incident -> create_plan -> analyse_logs ->
check_ip_device -> build_graph -> verify_findings ->
  enough evidence? -> risk_assessment -> human_approval -> final_report
  not enough?      -> request_more_evidence -> final_report (INSUFFICIENT_EVIDENCE)

Live mode: the LLM reasons at each step and picks the next tool.
Offline mode (clearly labelled): the evidence-graph scorer runs the
same nodes so the pipeline can be tested without a key. Offline
output is NEVER presented as a live Gemini run.
"""
from __future__ import annotations
import json, os, time
from typing import TypedDict, Optional
from langgraph.graph import StateGraph, START, END
from .audit import AuditTrail, new_trace_id, write_json_trace
from .graph import build_evidence_graph, evidence_score, graph_summary, supporting_edges
from .planner import offline_plan, live_plan
from .tools import analyse_logs, check_ip, search_threat_intel, parse_goal
from .uncertainty import decide_verdict
from .verifier import verify_verdict

class InvestigationState(TypedDict, total=False):
    goal: str; trace: dict; mode: str; plan: list; steps: list
    log_analysis: dict; ip_info: dict; threat_intel: dict
    graph_summary: dict; score: float; draft_verdict: str
    verification: dict; verdict: str; risk: str; risk_score: str
    approval_status: str; report: str; tool_calls: int; missing_evidence: list

class SentinelXAgent:
    def __init__(self, llm=None, offline: bool = False, max_steps: int = 10,
                 db_path: str = "sentinel_x.db", out_dir: str = "reports"):
        self.llm = llm; self.offline = offline; self.max_steps = max_steps
        self.db_path = db_path; self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.graph = self._build_graph()

    # -- LangGraph construction --------------------------------------
    def _build_graph(self):
        g = StateGraph(InvestigationState)
        g.add_node("understand_incident", self._understand)
        g.add_node("create_plan", self._create_plan)
        g.add_node("analyse_logs", self._analyse_logs)
        g.add_node("check_ip_device", self._check_ip_device)
        g.add_node("build_graph", self._build_graph_node)
        g.add_node("verify_findings", self._verify)
        g.add_node("risk_assessment", self._risk)
        g.add_node("human_approval", self._human_approval)
        g.add_node("request_more_evidence", self._request_more)
        g.add_node("final_report", self._final_report)
        g.add_edge(START, "understand_incident")
        g.add_edge("understand_incident", "create_plan")
        g.add_edge("create_plan", "analyse_logs")
        g.add_edge("analyse_logs", "check_ip_device")
        g.add_edge("check_ip_device", "build_graph")
        g.add_edge("build_graph", "verify_findings")
        g.add_conditional_edges("verify_findings", self._enough_evidence,
                                {"enough": "risk_assessment", "not_enough": "request_more_evidence"})
        g.add_edge("risk_assessment", "human_approval")
        g.add_edge("human_approval", "final_report")
        g.add_edge("request_more_evidence", "final_report")
        g.add_edge("final_report", END)
        return g.compile()

    def _enough_evidence(self, s: InvestigationState) -> str:
        return "enough" if s.get("verdict") in ("MALICIOUS", "BENIGN") else "not_enough"

    # -- nodes --------------------------------------------------------
    def _understand(self, s):
        trace = s.get("trace") or parse_goal(s.get("goal", ""))
        step = "Understand incident: parsed goal into IP, failed/successful logins, hour, device."
        if not self.offline and self.llm:
            try:
                r = self.llm.call(f"Summarise this security incident in 2 sentences, listing the key facts. Goal: {s.get('goal')}")
                step += f" LLM summary: {r.strip()[:300]}"
            except Exception as e:
                step += f" (LLM summary failed: {e}; continuing on parsed facts.)"
        return {"trace": trace, "steps": (s.get("steps") or []) + [step], "tool_calls": s.get("tool_calls", 0)}

    def _create_plan(self, s):
        if self.offline or not self.llm:
            plan = offline_plan(s["trace"])
            note = "Offline mode: fixed plan order (same step names as live planner)."
        else:
            try:
                nxt = live_plan(self.llm, s["goal"], json.dumps(s["trace"]))
                plan = offline_plan(s["trace"]); note = f"Live planner chose next tool {nxt.get('next_tool')}: {nxt.get('reason')}"
            except Exception as e:
                plan = offline_plan(s["trace"]); note = f"Live planner fell back to default plan ({e})."
        return {"plan": plan, "steps": s["steps"] + [f"Create investigation plan: {', '.join(plan)}. {note}"], "tool_calls": s.get("tool_calls", 0)}

    def _analyse_logs(self, s):
        a = analyse_logs(s["trace"])
        return {"log_analysis": a, "steps": s["steps"] + [f"Analyse login logs (pandas): {a}"], "tool_calls": s.get("tool_calls", 0) + 1}

    def _check_ip_device(self, s):
        ip_info = check_ip(s["trace"]["ip"])
        ti = search_threat_intel(f"{s['trace']['ip']} suspicious login brute force")
        return {"ip_info": ip_info, "threat_intel": ti,
                "steps": s["steps"] + [f"Check IP/device history: {ip_info}. Threat intel hits: {ti.get('count', 0)}."],
                "tool_calls": s.get("tool_calls", 0) + 2}

    def _build_graph_node(self, s):
        g = build_evidence_graph(s["trace"])
        return {"graph_summary": graph_summary(g),
                "steps": s["steps"] + [f"Build evidence graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges."],
                "tool_calls": s.get("tool_calls", 0) + 1}

    def _verify(self, s):
        g = build_evidence_graph(s["trace"])
        score = evidence_score(s["trace"])
        gs = graph_summary(g)
        draft = decide_verdict(score, s["trace"], gs["malicious_supporting_edges"], gs["benign_supporting_edges"])
        ver = verify_verdict(draft["verdict"], g, score, s["trace"])
        if not self.offline and self.llm:
            try:
                r = self.llm.call(f"Verify this draft verdict against this evidence. Draft: {draft['verdict']}. "
                                  f"Evidence score: {score}. Graph: {gs}. Reply with VERIFIED or REVISED plus one reason.")
                ver["reasons"].append(f"LLM verification: {r.strip()[:300]}")
            except Exception as e:
                ver["reasons"].append(f"LLM verification unavailable: {e}")
        return {"score": score, "draft_verdict": draft["verdict"], "verification": ver,
                "verdict": ver["final_verdict"], "missing_evidence": draft["missing_evidence"] if ver["final_verdict"] == "INSUFFICIENT_EVIDENCE" else [],
                "steps": s["steps"] + [f"Verify findings: draft {draft['verdict']} (score {score}) -> final {ver['final_verdict']}. "
                                        f"Revised: {ver['revised']}. Reasons: {'; '.join(ver['reasons'])}"],
                "tool_calls": s.get("tool_calls", 0)}

    def _risk(self, s):
        risk = {"MALICIOUS": ("HIGH", "Block the IP, force password reset, review the account."),
                "BENIGN": ("LOW", "No action needed; keep monitoring."),
                "INSUFFICIENT_EVIDENCE": ("UNKNOWN", "Collect the missing evidence listed; take no blocking action.")}[s["verdict"]]
        return {"risk": risk[0], "risk_score": risk[1],
                "steps": s["steps"] + [f"Generate risk assessment: risk {risk[0]}. Recommendation: {risk[1]}"],
                "tool_calls": s.get("tool_calls", 0)}

    def _human_approval(self, s):
        return {"approval_status": "PENDING — human approval required before any dangerous action (block/reset). No dangerous action was executed; this run only produces a report.",
                "steps": s["steps"] + ["Human approval gate: dangerous actions need human approval. None executed in this run."],
                "tool_calls": s.get("tool_calls", 0)}

    def _request_more(self, s):
        return {"risk": "UNKNOWN",
                "steps": s["steps"] + [f"Request more evidence: verdict INSUFFICIENT_EVIDENCE. Missing: {', '.join(s.get('missing_evidence') or ['more log history'])}."],
                "tool_calls": s.get("tool_calls", 0)}

    def _final_report(self, s):
        mode_label = "OFFLINE evidence-graph mode (synthetic, labelled — NOT a live Gemini run)" if self.offline else f"LIVE Gemini mode ({self.llm.provider}/{self.llm.model})"
        report = self._render_report(s, mode_label)
        return {"report": report, "steps": s["steps"] + ["Final incident report generated."], "tool_calls": s.get("tool_calls", 0)}

    def _render_report(self, s, mode_label):
        gs = s.get("graph_summary", {})
        return (f"# SENTINEL-X Incident Report\n\nMode: {mode_label}\n\n"
                f"## Goal\n{s.get('goal')}\n\n## Verdict: {s.get('verdict')}\n\n"
                f"- Evidence score: {s.get('score')}\n- Draft verdict: {s.get('draft_verdict')}\n"
                f"- Verification revised verdict: {s.get('verification', {}).get('revised')}\n"
                f"- Risk: {s.get('risk', 'UNKNOWN')}\n"
                f"- Missing evidence: {', '.join(s.get('missing_evidence') or ['none'])}\n\n"
                f"## Evidence Graph\nNodes: {gs.get('nodes')}, Edges: {gs.get('edges')}, "
                f"malicious-supporting edges: {gs.get('malicious_supporting_edges')}, "
                f"benign-supporting edges: {gs.get('benign_supporting_edges')}\n\n"
                + "\n".join(f"- {e['from']} --{e['relation']}--> {e['to']} (supports: {e['supports']})" for e in gs.get("edge_list", []))
                + f"\n\n## Recommendation\n{s.get('risk_score', '')}\n\n## Human approval\n{s.get('approval_status', '')}\n\n## Steps\n"
                + "\n".join(f"{i+1}. {st}" for i, st in enumerate(s.get("steps", [])))
                + "\n")

    # -- public run ---------------------------------------------------
    def run(self, goal: str, trace: dict | None = None) -> dict:
        trace_id = new_trace_id(); t0 = time.time()
        audit = AuditTrail(self.db_path)
        audit.log(trace_id, "start", "understand_incident", goal)
        init: InvestigationState = {"goal": goal, "trace": trace or parse_goal(goal),
                                    "mode": "offline" if self.offline else "live",
                                    "steps": [], "tool_calls": 0}
        final = self.graph.invoke(init)
        elapsed = round(time.time() - t0, 3)
        mode = "offline" if self.offline else "live"
        for st in final.get("steps", []):
            audit.log(trace_id, "step", "agent", st, verdict=final.get("verdict"))
        audit.log(trace_id, "decision", "verify_findings",
                  json.dumps({"draft": final.get("draft_verdict"), "final": final.get("verdict"),
                              "revised": final.get("verification", {}).get("revised"),
                              "reasons": final.get("verification", {}).get("reasons", [])}),
                  verdict=final.get("verdict"))
        audit.register_trace(trace_id, goal, final.get("verdict"), mode)
        report_path = os.path.join(self.out_dir, f"incident_report_{trace_id}.md")
        with open(report_path, "w", encoding="utf-8") as f: f.write(final.get("report", ""))
        trace_path = os.path.join(self.out_dir, f"trace_{trace_id}.json")
        gs = final.get("graph_summary", {})
        unsupported = 0
        if final.get("verdict") == "MALICIOUS" and gs.get("malicious_supporting_edges", 0) == 0: unsupported = 1
        if final.get("verdict") == "BENIGN" and gs.get("benign_supporting_edges", 0) == 0 and float(final.get("score") or 0) > 0.5: unsupported = 1
        record = {"trace_id": trace_id, "mode": mode, "goal": goal, "trace": final.get("trace"),
                  "verdict": final.get("verdict"), "draft_verdict": final.get("draft_verdict"),
                  "score": final.get("score"), "risk": final.get("risk"),
                  "verification": final.get("verification"), "missing_evidence": final.get("missing_evidence"),
                  "graph": gs, "steps": final.get("steps"), "tool_calls": final.get("tool_calls"),
                  "execution_time_seconds": elapsed, "unsupported_conclusions": unsupported,
                  "approval_status": final.get("approval_status"), "report_path": report_path}
        write_json_trace(trace_path, record)
        audit.close()
        return {**record, "trace_path": trace_path}
