"""SENTINEL-X Streamlit dashboard (simple second option; React in frontend/ is the main one).
Run: streamlit run app.py
"""
import json, os, sqlite3
import streamlit as st
from sentinel_x.agent import SentinelXAgent
from sentinel_x.llm import LLMClient, NoAPIKeyError

st.set_page_config(page_title="SENTINEL-X", layout="wide", initial_sidebar_state="collapsed")
st.markdown(
    "<style>"
    ".stApp { background-color: #0b1220; color: #e2e8f0; }"
    "h1, h2, h3 { color: #f1f5f9; }"
    "section[data-testid='stSidebar'] { background-color: #0f172a; }"
    "</style>",
    unsafe_allow_html=True,
)
st.title("SENTINEL-X — Evidence-Driven Incident Investigation")
st.caption("Live mode needs a free Gemini key. Offline mode is labelled and for testing only. Synthetic data only — TEST-NET IPs, no real users.")

goal = st.text_input("Investigation goal", value="Investigate suspicious login activity. IP: 192.0.2.45, Failed logins: 35, Successful login: 1, Time: 02:30 AM, Device: Unknown")
offline = st.checkbox("Offline evidence-graph mode (no key needed, labelled)", value=False)
col_run, col_demo = st.columns([1, 1])
run_clicked = col_run.button("Run investigation")
if col_demo.button("Load demo (192.0.2.45)"):
    st.info("Demo goal is already in the box above — press Run investigation (offline mode is the labelled demo).")

if run_clicked:
    llm = None
    if not offline:
        try: llm = LLMClient()
        except NoAPIKeyError as e: st.error(str(e)); st.stop()
    with st.spinner("Investigating…"):
        agent = SentinelXAgent(llm=llm, offline=offline)
        r = agent.run(goal)
    st.subheader(f"Verdict: {r['verdict']}  |  Risk: {r['risk']}  |  Score: {r['score']}")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Verdict", r["verdict"])
    m2.metric("Risk", r["risk"])
    m3.metric("Evidence score", r["score"])
    m4.metric("Tool calls", r["tool_calls"])
    m5.metric("Time (s)", r["execution_time_seconds"])
    st.write("**Evidence graph:**", f"{r['graph']['nodes']} nodes, {r['graph']['edges']} edges, "
             f"{r['graph']['malicious_supporting_edges']} malicious-supporting, "
             f"{r['graph']['benign_supporting_edges']} benign-supporting")
    st.write("**Live step trace:**")
    for i, s in enumerate(r["steps"], 1): st.write(f"{i}. {s}")
    st.write("**Verification:**", r["verification"])
    if r["missing_evidence"]: st.warning("Missing evidence: " + ", ".join(r["missing_evidence"]))
    st.info(r["approval_status"])
    st.subheader("Final report")
    st.code(r["report"] if isinstance(r.get("report"), str) else "")

st.subheader("Audit history (SQLite)")
if os.path.exists("sentinel_x.db"):
    conn = sqlite3.connect("sentinel_x.db")
    try:
        rows = conn.execute("SELECT trace_id, ts, event_type, step, verdict FROM audit_events ORDER BY id DESC LIMIT 50").fetchall()
        st.table([{"trace_id": x[0], "ts": x[1], "event": x[2], "step": x[3], "verdict": x[4]} for x in rows])
    except Exception as e: st.write(str(e))
    conn.close()
else:
    st.write("No audit DB yet — run an investigation first.")

st.subheader("Evaluation metrics")
if os.path.exists("evaluation/evaluation_report.json"):
    st.json(json.load(open("evaluation/evaluation_report.json")))
else:
    st.write("No evaluation yet — run: python evaluation/run_evaluation.py")
