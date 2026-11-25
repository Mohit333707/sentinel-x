"""Feature 5 — Explainable Audit Trail (SQLite + JSON).

Every tool call, evidence item, decision, revision and recommendation
is saved with a timestamp, so any verdict can be replayed step by step.
"""
from __future__ import annotations
import json, os, sqlite3, uuid
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id TEXT, ts TEXT, event_type TEXT, step TEXT,
    detail TEXT, verdict TEXT
);
CREATE TABLE IF NOT EXISTS traces (
    trace_id TEXT PRIMARY KEY, goal TEXT, verdict TEXT,
    mode TEXT, created_at TEXT, report_path TEXT
);
"""

class AuditTrail:
    def __init__(self, db_path: str = "sentinel_x.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True) if os.path.dirname(db_path) else None
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(SCHEMA); self.conn.commit()

    def log(self, trace_id: str, event_type: str, step: str, detail: str = "", verdict: str | None = None):
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute("INSERT INTO audit_events (trace_id, ts, event_type, step, detail, verdict) VALUES (?,?,?,?,?,?)",
                          (trace_id, ts, event_type, step, detail, verdict))
        self.conn.commit()
        return ts

    def log_tool_call(self, trace_id, tool, args, result):
        return self.log(trace_id, "tool_call", tool, json.dumps({"args": args, "result": str(result)[:500]}))

    def register_trace(self, trace_id, goal, verdict, mode, report_path=""):
        self.conn.execute("INSERT OR REPLACE INTO traces VALUES (?,?,?,?,?,?)",
                          (trace_id, goal, verdict, mode, datetime.now(timezone.utc).isoformat(), report_path))
        self.conn.commit()

    def history(self, trace_id: str | None = None, limit: int = 200) -> list[dict]:
        if trace_id:
            rows = self.conn.execute("SELECT trace_id, ts, event_type, step, detail, verdict FROM audit_events WHERE trace_id=? ORDER BY id LIMIT ?", (trace_id, limit))
        else:
            rows = self.conn.execute("SELECT trace_id, ts, event_type, step, detail, verdict FROM audit_events ORDER BY id DESC LIMIT ?", (limit,))
        return [{"trace_id": r[0], "ts": r[1], "event_type": r[2], "step": r[3], "detail": r[4], "verdict": r[5]} for r in rows]

    def counts(self) -> dict:
        n_events = self.conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        n_traces = self.conn.execute("SELECT COUNT(*) FROM traces").fetchone()[0]
        return {"audit_events": n_events, "traces": n_traces}

    def close(self):
        self.conn.close()

def new_trace_id() -> str:
    return "SX-" + uuid.uuid4().hex[:8].upper()

def write_json_trace(path: str, record: dict) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, default=str)
    return path
