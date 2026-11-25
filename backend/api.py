"""SENTINEL-X FastAPI backend for the React frontend.

Run from the project root:
    uvicorn backend.api:app --reload --port 8000

Endpoints:
    GET  /health       -> {"status": "ok"}
    GET  /evaluation   -> contents of evaluation/evaluation_report.json
    POST /investigate  -> {"goal": "..."} runs the agent and returns the
                          trace/report JSON. Offline mode unless a Gemini
                          key is set (GEMINI_API_KEY in .env), in which
                          case it runs live. No dangerous action is ever
                          executed; the approval status stays PENDING.
"""
from __future__ import annotations

import json
import os
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_x.agent import SentinelXAgent  # noqa: E402
from sentinel_x.llm import LLMClient, NoAPIKeyError  # noqa: E402

app = FastAPI(title="SENTINEL-X API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class InvestigateRequest(BaseModel):
    goal: str
    offline: bool | None = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/evaluation")
def evaluation():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "evaluation",
        "evaluation_report.json",
    )
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@app.post("/investigate")
def investigate(req: InvestigateRequest):
    goal = (req.goal or "").strip()
    if not goal:
        return {"error": "goal is required"}
    offline = req.offline
    llm = None
    if offline is None:
        try:
            llm = LLMClient()
            offline = False
        except NoAPIKeyError:
            offline = True
    elif not offline:
        try:
            llm = LLMClient()
        except NoAPIKeyError as exc:
            return {"error": str(exc), "offline_hint": "Run with offline=true or set GEMINI_API_KEY"}
    agent = SentinelXAgent(llm=llm, offline=bool(offline))
    result = agent.run(goal)
    result.pop("report", None)
    return result
