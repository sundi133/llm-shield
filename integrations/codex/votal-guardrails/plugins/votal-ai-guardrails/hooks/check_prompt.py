"""Synchronous Codex prompt gate. Never logs prompts, keys, or HTTP bodies."""
import json
import os
import sys
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

DEFAULT_URL = "https://api.guardrails.votal.ai"
LIMIT = 2 * 1024 * 1024

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def blocked(reason):
    return {"decision": "block", "reason": reason}

def load_settings():
    key = os.environ.get("VOTAL_API_KEY")
    base = os.environ.get("VOTAL_SHIELD_URL") or DEFAULT_URL
    if not isinstance(key, str) or not key.strip():
        raise ValueError("Missing credential")
    url = urlsplit(base)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("HTTPS data-plane URL required")
    return base.rstrip("/") + "/guardrails/input", key.strip()

def evaluate(event):
    if not isinstance(event, dict) or event.get("hook_event_name") != "UserPromptSubmit" or not isinstance(event.get("prompt"), str):
        return blocked("Votal Shield could not validate the prompt hook input.")
    try:
        endpoint, key = load_settings()
    except Exception:
        return blocked("Votal Shield is not configured. Set VOTAL_API_KEY in the environment inherited by Codex, then restart Codex.")
    try:
        body = json.dumps({"message": event["prompt"]}).encode("utf-8")
        req = Request(endpoint, data=body, headers={"Content-Type": "application/json", "Accept": "application/json", "X-API-Key": key}, method="POST")
        with build_opener(NoRedirect()).open(req, timeout=15) as response:
            raw = response.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError("Response too large")
            verdict = json.loads(raw)
    except Exception:
        return blocked("Votal Shield check failed; this prompt was stopped. Check connectivity and tenant credentials.")
    if not isinstance(verdict, dict):
        return blocked("Votal Shield returned an invalid decision; this prompt was stopped.")
    if verdict.get("safe") is True and verdict.get("action") == "pass":
        return {}
    if verdict.get("safe") is False or verdict.get("action") in ("block", "redact", "mask"):
        return blocked("Blocked by Votal Shield: tenant policy rejected this prompt. Review the policy decision in your Votal console.")
    return blocked("Votal Shield did not explicitly allow this prompt; this prompt was stopped.")

def main():
    try:
        raw = sys.stdin.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("Input too large")
        result = evaluate(json.loads(raw))
    except Exception:
        result = blocked("Votal Shield could not validate the prompt; this prompt was stopped.")
    print(json.dumps(result))
    return 0

if __name__ == "__main__":
    sys.exit(main())
