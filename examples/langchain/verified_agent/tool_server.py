#!/usr/bin/env python3
"""Tool server — the OTHER side of the trust boundary (Phase 2).

This process is the only one that holds the real email credential. It does
NOT trust the agent. Before sending anything it independently calls Shield's
/cap/verify with the capability the agent presents. No valid cap → no send.

Notice what this server does NOT have:
  * the tenant API key (it never mints anything)
  * the agent token (it doesn't care who the agent says it is — the cap is
    already bound to a verified identity by Shield at mint time)

It only needs:
  * SHIELD_URL          — to reach /v1/shield/cap/verify
  * the real SMTP creds  — which the agent must never possess

Run:
    export SHIELD_URL=https://shield.your-company.com
    uvicorn tool_server:app --port 9100
"""

from __future__ import annotations

import os

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

SHIELD_URL = os.environ.get("SHIELD_URL", "http://localhost:8080").rstrip("/")
# Optional proxy auth (e.g. RunPod). NOT the tenant key.
PROXY_TOKEN = os.environ.get("RUNPOD_TOKEN", "")

# The real credential — lives ONLY here, never in the agent.
SMTP_CREDENTIAL = os.environ.get("SMTP_CREDENTIAL", "smtp://demo-secret@mailgun")

app = FastAPI(title="verified-tool-server")


class SendEmailRequest(BaseModel):
    to: str
    subject: str
    body: str
    cap_token: str            # the permission slip minted by Shield


def _verify_cap(cap_token: str, *, expected_tool: str, expected_resource: str) -> dict:
    """Ask Shield to verify the cap. Fails closed on anything suspicious.

    This is the enforcement point. verify_cap checks signature, expiry,
    tool match, resource match, revocation, and burns the one-time nonce.
    """
    headers = {"Content-Type": "application/json"}
    if PROXY_TOKEN:
        headers["Authorization"] = f"Bearer {PROXY_TOKEN}"
    resp = requests.post(
        f"{SHIELD_URL}/v1/shield/cap/verify",
        json={
            "cap_token": cap_token,
            "expected_tool": expected_tool,
            "expected_resource": expected_resource,   # bound to THIS recipient
        },
        headers=headers,
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("valid"):
        # bad signature / expired / wrong tool / wrong resource / replay
        raise HTTPException(status_code=403, detail=f"cap rejected: {data.get('error')}")
    return data.get("claims") or {}


@app.post("/tools/send_email")
def send_email(req: SendEmailRequest):
    # 1) Enforce: verify the cap BEFORE touching the credential.
    claims = _verify_cap(
        req.cap_token,
        expected_tool="send_email",
        expected_resource=req.to,
    )

    # 2) Only now do we use the real credential the agent never had.
    #    (simulated send)
    print(f"[tool-server] verified cap for {claims.get('agent_id')} "
          f"(user={claims.get('user_sub')}) — sending via {SMTP_CREDENTIAL[:12]}...")
    # smtp.send(SMTP_CREDENTIAL, req.to, req.subject, req.body)

    return {
        "sent": True,
        "to": req.to,
        "verified_agent": claims.get("agent_id"),
        "verified_user": claims.get("user_sub"),
    }
