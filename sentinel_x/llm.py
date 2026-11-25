"""LLM layer for SENTINEL-X.

Gemini free tier first (GEMINI_API_KEY, gemini-2.0-flash via plain
``requests`` REST calls — no Google SDK), Groq / OpenAI fallback.
No hard-coded reasoning fallback: if no key is set, raise
NoAPIKeyError with a clean message and a free-key guide.
Get a free key: https://aistudio.google.com/app/apikey
"""
from __future__ import annotations
import json, os
import requests
from dotenv import load_dotenv
load_dotenv()

GEMINI_MODEL = "gemini-2.0-flash"
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
DEFAULT_MODELS = {"gemini": GEMINI_MODEL, "groq": "llama-3.3-70b-versatile", "openai": "gpt-4o-mini"}
TIMEOUT = 60

class NoAPIKeyError(Exception):
    """Raised when no LLM API key is configured at all."""

def helpful_no_key_message() -> str:
    return (
        "\n  SENTINEL-X needs an LLM API key to reason -- it does not use\n"
        "  hard-coded rules or canned answers, so it cannot run live without one.\n\n"
        "  Get a FREE Gemini key in about 2 minutes:\n"
        "    1. Go to https://aistudio.google.com/app/apikey\n"
        "    2. Sign in with Google and click 'Create API key'\n"
        "    3. Copy .env.example to .env and paste the key:\n"
        "         GEMINI_API_KEY=<redacted>\n"
        "    4. Run again:  python main.py --demo\n\n"
        "  (A Groq or OpenAI key also works -- set GROQ_API_KEY or\n"
        "   OPENAI_API_KEY in .env instead. Groq also has a free tier.)\n"
        "  Offline mode is available for testing only:\n"
        "    python main.py --demo --offline\n"
        "  Its output is clearly labelled OFFLINE and is NOT a live Gemini run.\n"
    )

class LLMClient:
    def __init__(self) -> None:
        self.provider = None; self.model = None; self.api_key = None; self.base_url = None
        gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
        groq_key = os.getenv("GROQ_API_KEY", "").strip()
        openai_key = os.getenv("OPENAI_API_KEY", "").strip()
        model_override = os.getenv("LLM_MODEL", "").strip()
        if gemini_key:
            self.provider = "gemini"; self.api_key = gemini_key
            self.model = model_override or DEFAULT_MODELS["gemini"]
        elif groq_key:
            self.provider = "groq"; self.api_key = groq_key
            self.base_url = os.getenv("OPENAI_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
            self.model = model_override or DEFAULT_MODELS["groq"]
        elif openai_key:
            self.provider = "openai"; self.api_key = openai_key
            self.base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
            self.model = model_override or DEFAULT_MODELS["openai"]
        else:
            raise NoAPIKeyError(helpful_no_key_message())

    def __repr__(self) -> str:
        return f"LLMClient(provider={self.provider!r}, model={self.model!r})"

    def call(self, prompt: str) -> str:
        return self._call_gemini(prompt) if self.provider == "gemini" else self._call_openai_compatible(prompt)

    def call_json(self, prompt: str, retries: int = 2) -> dict:
        """Call the LLM and parse a JSON object, retrying on bad JSON."""
        last = ""
        for attempt in range(retries + 1):
            text = self.call(prompt + "\nReply with valid JSON only, no markdown fences.")
            last = text
            try:
                cleaned = text.strip()
                if cleaned.startswith("```"):
                    cleaned = cleaned.strip("`").split("\n", 1)[-1].rsplit("```", 1)[0]
                return json.loads(cleaned)
            except (ValueError, IndexError):
                if attempt == retries:
                    raise RuntimeError(f"LLM did not return valid JSON after {retries+1} tries. Last reply: {last[:400]}")
        raise RuntimeError("unreachable")

    def _call_gemini(self, prompt: str) -> str:
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        try:
            resp = requests.post(GEMINI_URL, params={"key": self.api_key}, json=payload, timeout=TIMEOUT)
        except requests.RequestException as exc:
            raise RuntimeError(f"Could not reach Gemini API: {exc}") from exc
        if resp.status_code != 200:
            raise RuntimeError(f"Gemini API error ({resp.status_code}): {resp.text[:500]}. Check GEMINI_API_KEY and free-tier quota.")
        try:
            return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, ValueError) as exc:
            raise RuntimeError(f"Unexpected Gemini response format: {resp.text[:500]}") from exc

    def _call_openai_compatible(self, prompt: str) -> str:
        payload = {"model": self.model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2}
        try:
            resp = requests.post(f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json=payload, timeout=TIMEOUT)
        except requests.RequestException as exc:
            raise RuntimeError(f"Could not reach {self.provider} API: {exc}") from exc
        if resp.status_code != 200:
            raise RuntimeError(f"{self.provider} API error ({resp.status_code}): {resp.text[:500]}")
        try:
            return resp.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as exc:
            raise RuntimeError(f"Unexpected {self.provider} response format: {resp.text[:500]}") from exc
