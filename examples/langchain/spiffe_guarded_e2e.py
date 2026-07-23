#!/usr/bin/env python3
"""LangChain agent with SPIFFE identity (local) + Shield guardrails (cloud).

A realistic split:
  * IDENTITY  — the agent proves who it is with a SPIFFE X.509 SVID, validated
    by Shield's own validator locally. The SPIFFE ID -> agent_id drives RBAC.
  * ENFORCEMENT — tool-call RBAC, output screening, and the LLM itself run
    against the CLOUD Shield endpoint (tenant API key). No infra needed.

Flow per the enforcement-topology model:
  SPIFFE SVID -> agent identity
  register the agent's role_permissions (once)
  LLM turn -> Shield guarded proxy  (/v1/chat/completions)
  each tool -> /v1/shield/tool/check  (RBAC on the SPIFFE identity)
  each tool result -> /guardrails/output (data-policy screening)

  pip install langchain-core langchain-openai requests cryptography
  SHIELD_URL=https://api.guardrails.votal.ai TENANT_KEY=... \
    python examples/langchain/spiffe_guarded_e2e.py
"""
import datetime
import os
import sys

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field


class TicketIn(BaseModel):
    ticket_id: str = Field(description="the ticket id to look up")


class NoArgs(BaseModel):
    pass

BASE = os.environ.get("SHIELD_URL", "https://api.guardrails.votal.ai").rstrip("/")
KEY = os.environ["TENANT_KEY"]
H = {"X-API-Key": KEY, "Content-Type": "application/json"}
TRUST_DOMAIN = "bank-co.local"
WORKLOAD = "/agent/support-bot"

C = {"g": "\033[32m", "r": "\033[31m", "y": "\033[33m", "b": "\033[1m", "z": "\033[0m"}


def hr(t):
    print(f"\n{C['b']}{t}{C['z']}")


# ── 1. SPIFFE identity, validated by Shield's own code (local) ─────────────
def establish_identity():
    """Mint a workload SVID and resolve it through Shield's validator."""
    sys.path.insert(0, os.getcwd())
    from core.oauth.spiffe import validate_x509_svid, spiffe_id_to_identity, SPIFFETrustDomain

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{TRUST_DOMAIN} CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    spiffe_uri = f"spiffe://{TRUST_DOMAIN}{WORKLOAD}"
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(ca.subject)
            .public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]), critical=True)
            .sign(ca_key, hashes.SHA256()))

    bundle = "/tmp/e2e_bundle.pem"
    open(bundle, "wb").write(ca.public_bytes(Encoding.PEM))
    td = SPIFFETrustDomain(trust_domain=TRUST_DOMAIN, trust_bundle_path=bundle,
                           allowed_workloads=[spiffe_uri])
    sid = validate_x509_svid(leaf.public_bytes(Encoding.PEM).decode(), td)
    return spiffe_id_to_identity(sid, "bank-co")


# ── 2. Register the SPIFFE-derived agent's RBAC once (cloud) ───────────────
def register_agent(agent_id):
    body = {
        "agent_id": agent_id,
        "name": "SPIFFE support bot",
        "tools": ["get_ticket_status", "read_aws_credentials"],
        "role_permissions": {"support_agent": ["get_ticket_status"]},  # NOT read_aws_credentials
    }
    r = requests.post(f"{BASE}/v1/agents/register", headers=H, json=body, timeout=30)
    return r.status_code, r.text[:150]


# ── 3. The Shield guard wrapping every LangChain tool ──────────────────────
def guarded(agent_id, role, tool_name, fn):
    """Wrap a tool: RBAC check (cloud) -> run -> output screen (cloud)."""
    def _run(**kwargs):
        hdr = {**H, "X-Agent-Key": agent_id, "X-User-Role": role}
        chk = requests.post(f"{BASE}/v1/shield/tool/check", headers=hdr,
                            json={"agent_key": agent_id, "tool_name": tool_name,
                                  "user_role": role, "tool_params": kwargs}, timeout=30).json()
        if not chk.get("allowed"):
            reason = chk.get("guardrail_results", [{}])[0].get("message", "denied")
            print(f"   {C['r']}BLOCKED by RBAC{C['z']}: {reason}")
            return f"[blocked: {reason}]"
        result = fn(**kwargs)
        scr = requests.post(f"{BASE}/guardrails/output", headers=H,
                            json={"output": result}, timeout=90).json()
        if scr.get("safe") is False:
            print(f"   {C['r']}tool output BLOCKED by guardrail{C['z']} ({scr.get('action')})")
            return "[tool output withheld: policy violation]"
        print(f"   {C['g']}allowed{C['z']} -> {result[:60]}")
        return result
    return _run


def main():
    hr("1. SPIFFE identity (validated locally by Shield)")
    ident = establish_identity()
    agent_id = ident["agent_id"]
    print(f"   spiffe -> agent_id={agent_id}  method={ident['identity_method']}  trust={ident['trust_level']}")

    hr("2. Register RBAC for this SPIFFE identity (cloud)")
    code, msg = register_agent(agent_id)
    print(f"   register: {code}")

    role = "support_agent"

    def get_ticket_status(ticket_id: str) -> str:
        return f"Ticket {ticket_id} is OPEN, priority normal."

    def read_aws_credentials() -> str:
        return "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENGbPxRfiCYEXAMPLEKEY"

    tools = [
        StructuredTool.from_function(guarded(agent_id, role, "get_ticket_status", get_ticket_status),
                                     name="get_ticket_status", description="Look up a ticket's status.",
                                     args_schema=TicketIn),
        StructuredTool.from_function(guarded(agent_id, role, "read_aws_credentials", read_aws_credentials),
                                     name="read_aws_credentials", description="Read cloud credentials.",
                                     args_schema=NoArgs),
    ]
    by_name = {t.name: t for t in tools}

    hr("3. Guarded LLM turn through Shield's OpenAI-compatible proxy (cloud)")
    try:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(base_url=f"{BASE}/v1", api_key=KEY, model="shield-guarded", timeout=60)
        resp = llm.invoke("In one short sentence, what is a support bot?")
        print(f"   LLM via Shield proxy -> {resp.content[:80]}")
    except Exception as e:
        print(f"   (LLM turn skipped: {e})")

    hr("4. Agent calls an ALLOWED tool (RBAC permits get_ticket_status)")
    by_name["get_ticket_status"].invoke({"ticket_id": "T-1024"})

    hr("5. Agent calls a FORBIDDEN tool (RBAC denies read_aws_credentials)")
    by_name["read_aws_credentials"].invoke({})

    hr("Done — identity from SPIFFE, enforcement from Shield cloud.")


if __name__ == "__main__":
    main()
