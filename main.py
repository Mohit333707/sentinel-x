#!/usr/bin/env python3
"""SENTINEL-X CLI.

    python main.py --demo                 live demo (needs GEMINI_API_KEY)
    python main.py --demo --offline       offline evidence-graph demo (labelled, no key needed)
    python main.py --goal "..."           run with your own goal
    python main.py --goal "..." --offline run that goal offline
    python main.py --trace SX-XXXXXXX     show the audit history for a trace id
    python main.py                        interactive mode
"""
from __future__ import annotations
import argparse, json, sys
from sentinel_x.agent import SentinelXAgent
from sentinel_x.audit import AuditTrail
from sentinel_x.llm import LLMClient, NoAPIKeyError, helpful_no_key_message

DEFAULT_GOAL = ("Investigate suspicious login activity. IP: 192.0.2.45, "
                "Failed logins: 35, Successful login: 1, Time: 02:30 AM, Device: Unknown")

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="SENTINEL-X — evidence-driven autonomous incident investigation agent")
    p.add_argument("--goal", type=str, default=None)
    p.add_argument("--demo", action="store_true")
    p.add_argument("--offline", action="store_true", help="Offline evidence-graph mode (labelled, for testing only — NOT a live Gemini run)")
    p.add_argument("--trace", type=str, default=None, help="Show audit history for a trace id")
    p.add_argument("--max-steps", type=int, default=10)
    return p.parse_args(argv)

def main(argv=None) -> int:
    print("SENTINEL-X — Evidence-Driven Autonomous Cyber Incident Investigation Agent")
    args = parse_args(argv)
    if args.trace:
        a = AuditTrail("sentinel_x.db")
        for e in a.history(args.trace):
            print(f"{e['ts']}  {e['event_type']:12} {e['step']:20} {e['detail'][:200]}")
        a.close(); return 0
    if args.demo: goal = DEFAULT_GOAL
    elif args.goal: goal = args.goal.strip()
    else:
        print("No goal given — interactive mode.")
        try: goal = input("\nYour goal for SENTINEL-X: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled."); return 0
        if not goal: goal = DEFAULT_GOAL
    llm = None
    if not args.offline:
        try: llm = LLMClient()
        except NoAPIKeyError:
            print(helpful_no_key_message()); return 2
        print(f"LLM: {llm.provider} / {llm.model}  (live mode)")
    else:
        print("OFFLINE MODE — evidence-graph scoring only. This is NOT a live Gemini run.")
    agent = SentinelXAgent(llm=llm, offline=args.offline, max_steps=args.max_steps)
    result = agent.run(goal)
    print(f"\nTrace ID: {result['trace_id']}   Mode: {result['mode']}")
    print(f"Verdict: {result['verdict']}   Risk: {result['risk']}   Score: {result['score']}")
    print(f"Tool calls: {result['tool_calls']}   Time: {result['execution_time_seconds']}s")
    print(f"Report: {result['report_path']}\nTrace JSON: {result['trace_path']}")
    print("\n--- Steps ---")
    for i, s in enumerate(result["steps"], 1): print(f"{i}. {s}")
    print(f"\n{result['approval_status']}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
