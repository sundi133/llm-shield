#!/usr/bin/env python3
"""LangChain Agent with Shield-Guarded Tools — Defense in Depth

Demonstrates the correct separation of concerns for tool authorization:

  DISPATCHER (agent loop) — the CALLER side:
    Layer 1: RBAC check    — is this role allowed to use this tool?
    Layer 2: Cap mint      — freeze the decision into a single-use token

  TOOL WRAPPER — the TOOL side:
    Layer 3: Cap verify    — burn the nonce, prove the cap is valid
    Layer 4: Execute       — run the actual function
    Layer 5: Sanitize      — mask/redact/block sensitive data in output

Architecture:

  Agent decides what it wants to do
          ↓
  Dispatcher (agent loop)
          ↓  RBAC check + cap mint    ← OUTSIDE tool (caller side)
          ↓  passes cap_token to tool
  Tool wrapper
          ↓  cap verify (burn nonce)  ← INSIDE tool (tool side)
          ↓  execute function
          ↓  sanitize output
          ↓
  Sanitized result back to agent

The tool NEVER mints its own cap — it only verifies one it was given.
This models the real-world pattern where:
  - Your agent runtime / orchestrator mints caps
  - The tool server / MCP server / API gateway verifies caps

Why this matters:
  - Prompts can be manipulated (injection attacks)
  - The agent may misunderstand the task and call the wrong tool
  - Tool access is often broader than what the current task needs
  - Same-code functions are still dangerous without a boundary
  - Auditability requires verification at every call site

Usage:
    # Start Shield + LiteLLM:
    docker compose up -d

    # Set environment:
    export SHIELD_URL="http://localhost:8080"
    export SHIELD_TENANT_KEY="sk-tenant-xxx"
    export OPENAI_API_KEY="sk-..."

    python langchain_guarded_tools.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

import requests
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage

# ─── Config ──────────────────────────────────────────────────────────────

SHIELD_URL = os.getenv("SHIELD_URL", "http://localhost:8080")
TENANT_API_KEY = os.getenv("SHIELD_TENANT_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
LITELLM_URL = os.getenv("LITELLM_URL", "")  # optional; uses OpenAI directly if empty

# ─── Feature Flags: Tool Call Audit Sinks ────────────────────────────────
#
# Control where GuardedToolCall audit records are written.
# Each sink is independent — enable any combination.
#
#   SHIELD_AUDIT_LOCAL=true      → in-memory audit_log list (default: true)
#   SHIELD_AUDIT_REDIS=true      → Redis sorted set per tenant
#   SHIELD_AUDIT_SIEM=true       → forward to tenant's SIEM (Splunk/Sentinel/generic)
#
# Redis and SIEM sinks call Shield endpoints, so they work even when the
# tool runs in a separate process from Shield.

AUDIT_LOCAL = os.getenv("SHIELD_AUDIT_LOCAL", "true").lower() in ("true", "1", "yes")
AUDIT_REDIS = os.getenv("SHIELD_AUDIT_REDIS", "false").lower() in ("true", "1", "yes")
AUDIT_SIEM = os.getenv("SHIELD_AUDIT_SIEM", "false").lower() in ("true", "1", "yes")

AGENT_ID = "banking-support-agent"
AGENT_INSTANCE_ID = f"{AGENT_ID}-{uuid.uuid4().hex[:8]}"
SESSION_ID = f"sess-{int(time.time())}"
BUILD_HASH = "sha256:demo-guarded-tools"
MODEL_VERSION = "gpt-4o-mini"

# The human user — in production this comes from your OIDC IdP
USER_SUB = "user-42"
USER_ROLE = "customer_support"


# ─── Shield Client (minimal, inline) ────────────────────────────────────


class ShieldError(Exception):
    pass


class ShieldClient:
    """Minimal Shield client for the guarded-tools demo."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _headers(self, extra: dict | None = None) -> dict:
        h = {"Content-Type": "application/json", "X-API-Key": self.api_key}
        if extra:
            h.update(extra)
        return h

    def _post(self, path: str, body: dict, extra_headers: dict | None = None) -> dict:
        r = requests.post(
            f"{self.base_url}{path}",
            json=body,
            headers=self._headers(extra_headers),
            timeout=10,
        )
        if not r.ok:
            detail = r.text
            try:
                detail = r.json().get("detail", detail)
            except Exception:
                pass
            raise ShieldError(f"{r.status_code} {path}: {detail}")
        return r.json()

    # ── AuthN ──

    def mint_agent_token(
        self,
        *,
        user_sub: str,
        agent_id: str,
        agent_instance_id: str,
        build_hash: str,
        model_version: str,
        session_id: str,
        ttl_seconds: int = 600,
    ) -> str:
        """Get a signed agent token (call once per process, refresh every ~10min)."""
        data = self._post(
            "/v1/tenant/me/agent-auth/agent-token",
            {
                "user_sub": user_sub,
                "agent_id": agent_id,
                "agent_instance_id": agent_instance_id,
                "build_hash": build_hash,
                "model_version": model_version,
                "session_id": session_id,
                "ttl_seconds": ttl_seconds,
            },
        )
        return data["agent_token"]

    # ── AuthZ ──

    def mint_cap(
        self,
        agent_token: str,
        *,
        tool: str,
        resource: str,
        clearance_max: str = "public",
        ttl_seconds: int = 30,
    ) -> dict:
        """Mint a single-use capability token for one tool+resource."""
        return self._post(
            "/v1/shield/cap/mint",
            {
                "tool": tool,
                "resource": resource,
                "clearance_max": clearance_max,
                "ttl_seconds": ttl_seconds,
            },
            extra_headers={"X-Agent-Token": agent_token},
        )

    def verify_cap(
        self,
        cap_token: str,
        *,
        expected_tool: str,
        expected_resource: str | None = None,
    ) -> tuple[bool, dict]:
        """Verify a capability token (burns nonce — single use)."""
        body: dict = {
            "cap_token": cap_token,
            "expected_tool": expected_tool,
            "burn_nonce": True,
        }
        if expected_resource is not None:
            body["expected_resource"] = expected_resource
        r = requests.post(
            f"{self.base_url}/v1/shield/cap/verify",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        data = r.json()
        if data.get("valid"):
            return True, data.get("claims", {})
        return False, {"error": data.get("error", "unknown")}

    # ── RBAC ──

    def tool_check(
        self,
        *,
        tool_name: str,
        user_role: str,
        agent_key: str,
        tool_params: dict | None = None,
    ) -> dict:
        """RBAC pre-check: can this role use this tool?"""
        return self._post(
            "/v1/shield/tool/check",
            {
                "tool_name": tool_name,
                "user_role": user_role,
                "agent_key": agent_key,
                "tool_params": tool_params or {},
                "session_id": SESSION_ID,
            },
            extra_headers={"X-User-Role": user_role, "X-Agent-Key": agent_key},
        )

    # ── Output sanitization ──

    def sanitize_output(
        self,
        *,
        tool_name: str,
        tool_output: str,
        agent_key: str,
    ) -> dict:
        """Post-execution: sanitize tool output per data policies."""
        return self._post(
            "/v1/shield/tool/output",
            {
                "tool_name": tool_name,
                "tool_output": tool_output,
                "agent_key": agent_key,
                "session_id": SESSION_ID,
            },
            extra_headers={"X-Agent-Key": agent_key},
        )

    # ── Audit: write GuardedToolCall to Redis ──

    def audit_to_redis(self, record: dict) -> None:
        """Write a tool-call audit record to Shield's Redis audit log.

        Uses the same /guardrails/output-style audit endpoint. The record
        lands in the audit:{tenant_id} sorted set alongside guardrail events,
        queryable from the tenant portal.
        """
        try:
            self._post(
                "/v1/tenant/me/audit",
                record,
            )
        except ShieldError:
            # Fire-and-forget: never block the tool call for audit failures
            pass

    # ── Audit: forward GuardedToolCall to SIEM ──

    def audit_to_siem(self, record: dict) -> None:
        """Forward a tool-call audit record to the tenant's SIEM endpoints.

        Uses Shield's /v1/tenant/me/siem/ingest endpoint which fans out
        to all configured SIEM targets (Splunk HEC, Azure Sentinel, generic).
        """
        try:
            self._post(
                "/v1/tenant/me/siem/ingest",
                record,
            )
        except ShieldError:
            # Fire-and-forget: never block the tool call for SIEM failures
            pass


# ─── Architecture: Separation of Concerns ───────────────────────────────
#
# DISPATCHER (agent loop) — the CALLER side:
#   1. RBAC check        — is this role allowed to use this tool?
#   2. Cap mint          — get a single-use capability token
#   These run BEFORE the tool is invoked. The dispatcher decides
#   whether to proceed and obtains proof (the cap token).
#
# TOOL WRAPPER — the TOOL side (what the tool server would do):
#   3. Cap verify        — burn the nonce, prove the cap is valid
#   4. Execute function  — only if verify passed
#   5. Sanitize output   — mask/redact/block sensitive data
#   The tool never trusts the caller — it verifies the cap independently.
#
# Why this separation matters:
#   - The tool should NOT authorize itself (mint inside tool = lock handing
#     out its own key)
#   - The dispatcher is the policy decision point (PDP)
#   - The tool wrapper is the policy enforcement point (PEP)
#   - In production, mint happens in your agent runtime, verify happens
#     in the tool server / MCP server / API gateway
#


@dataclass
class GuardedToolCall:
    """Audit record for one guarded tool invocation."""
    tool_name: str
    resource: str
    agent_id: str
    user_sub: str
    user_role: str
    rbac_allowed: bool
    cap_minted: bool
    cap_verified: bool
    executed: bool
    output_sanitized: bool
    denied_reason: str | None = None
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

    def to_dict(self) -> dict:
        """Serialize for Redis/SIEM storage."""
        return {
            "event_type": "guarded_tool_call",
            "tool_name": self.tool_name,
            "resource": self.resource,
            "agent_id": self.agent_id,
            "user_sub": self.user_sub,
            "user_role": self.user_role,
            "session_id": SESSION_ID,
            "rbac_allowed": self.rbac_allowed,
            "cap_minted": self.cap_minted,
            "cap_verified": self.cap_verified,
            "executed": self.executed,
            "output_sanitized": self.output_sanitized,
            "denied_reason": self.denied_reason,
            "status": "allowed" if self.executed else "blocked",
            "timestamp": self.timestamp,
        }


# Audit trail — in-memory log (always available for local debugging)
audit_log: list[GuardedToolCall] = []

# Shield client reference — set by build_agent(), used by emit_audit()
_shield_client: ShieldClient | None = None


def emit_audit(record: GuardedToolCall) -> None:
    """Write a GuardedToolCall to all enabled audit sinks.

    Controlled by feature flags:
      SHIELD_AUDIT_LOCAL=true   → append to in-memory audit_log
      SHIELD_AUDIT_REDIS=true   → write to Shield's Redis audit log
      SHIELD_AUDIT_SIEM=true    → forward to tenant's SIEM endpoints

    Each sink is fire-and-forget: failures never block the tool call.
    """
    # Sink 1: Local in-memory list (for debugging / print_audit_log)
    if AUDIT_LOCAL:
        audit_log.append(record)

    # Sink 2: Redis via Shield API
    if AUDIT_REDIS and _shield_client:
        _shield_client.audit_to_redis(record.to_dict())

    # Sink 3: SIEM (Splunk / Sentinel / generic) via Shield API
    if AUDIT_SIEM and _shield_client:
        _shield_client.audit_to_siem(record.to_dict())


# ─── Tool Wrapper (TOOL SIDE — verify + execute + sanitize) ─────────────
#
# This is what runs inside the tool boundary. It receives a cap_token
# from the dispatcher and verifies it before executing. The tool never
# mints its own cap — it only accepts and verifies one.


def guarded_tool(
    shield: ShieldClient,
    tool_name: str,
    func: Callable,
    *,
    resource_fn: Callable[..., str] | None = None,
    description: str = "",
):
    """Wrap a raw function so it requires a verified cap token to execute.

    The wrapper does NOT mint caps — it only verifies them. The dispatcher
    (agent loop) is responsible for RBAC + minting before calling the tool.

    This models the real-world pattern where:
      - Your agent runtime / dispatcher mints the cap (caller side)
      - The tool server / MCP server / function wrapper verifies it (tool side)
    """

    # Thread-local holder for the cap token passed by the dispatcher.
    # In production this would be a request header, context var, or argument.
    _pending_cap: dict[str, Any] = {"cap_token": None, "resource": None}

    def set_cap(cap_token: str, resource: str):
        """Called by the dispatcher to pass the cap to the tool."""
        _pending_cap["cap_token"] = cap_token
        _pending_cap["resource"] = resource

    @tool(tool_name, description=description or func.__doc__ or tool_name)
    def wrapper(**kwargs) -> str:
        cap_token = _pending_cap.get("cap_token")
        resource = _pending_cap.get("resource") or tool_name
        _pending_cap["cap_token"] = None  # consume it

        record = GuardedToolCall(
            tool_name=tool_name,
            resource=resource,
            agent_id=AGENT_ID,
            user_sub=USER_SUB,
            user_role=USER_ROLE,
            rbac_allowed=True,   # RBAC already passed in dispatcher
            cap_minted=True,     # cap already minted by dispatcher
            cap_verified=False,
            executed=False,
            output_sanitized=False,
        )

        # ── Tool Layer 1: Verify capability (burns nonce) ────────────
        # "I received a cap token. Is it valid? Burn the nonce."
        # This is what a tool server / MCP server would do.
        if not cap_token:
            record.denied_reason = "no capability token provided"
            emit_audit(record)
            print(f"  [TOOL VERIFY] REJECTED {tool_name}: no cap token")
            return f"BLOCKED: {tool_name} requires a capability token"

        valid, claims_or_err = shield.verify_cap(
            cap_token,
            expected_tool=tool_name,
            expected_resource=resource,
        )
        if not valid:
            err = claims_or_err.get("error", "unknown")
            record.denied_reason = f"cap verify failed: {err}"
            emit_audit(record)
            print(f"  [TOOL VERIFY] REJECTED {tool_name}: {err}")
            return f"BLOCKED: capability verification failed — {err}"

        record.cap_verified = True
        verified_agent = claims_or_err.get("agent_id", "?")
        verified_user = claims_or_err.get("user_sub", "?")
        print(f"  [TOOL VERIFY] OK — agent={verified_agent}, user={verified_user}")

        # ── Tool Layer 2: Execute the actual function ────────────────
        # Only reached if the cap was verified.
        try:
            raw_output = func(**kwargs)
            record.executed = True
            print(f"  [TOOL EXECUTE] {tool_name} ran successfully")
        except Exception as e:
            record.denied_reason = f"execution error: {e}"
            emit_audit(record)
            print(f"  [TOOL EXECUTE] ERROR {tool_name}: {e}")
            return f"ERROR: {tool_name} failed — {e}"

        # ── Tool Layer 3: Sanitize output ────────────────────────────
        # "Mask/redact/block sensitive data before returning."
        try:
            sanitized = shield.sanitize_output(
                tool_name=tool_name,
                tool_output=str(raw_output),
                agent_key=AGENT_ID,
            )
            if sanitized.get("action") == "block":
                record.denied_reason = "output blocked by data policy"
                emit_audit(record)
                print(f"  [TOOL SANITIZE] OUTPUT BLOCKED for {tool_name}")
                return "BLOCKED: tool output withheld by data policy"

            clean_output = sanitized.get("sanitized_output", str(raw_output))
            record.output_sanitized = True
            if clean_output != str(raw_output):
                print(f"  [TOOL SANITIZE] REDACTED — output modified")
            else:
                print(f"  [TOOL SANITIZE] PASS — no sensitive data found")
        except ShieldError:
            # Fail closed: don't leak unsanitized output
            record.denied_reason = "sanitization error — output withheld"
            emit_audit(record)
            print(f"  [TOOL SANITIZE] ERROR — withholding output")
            return "BLOCKED: output sanitization failed — data withheld"

        audit_log.append(record)
        return clean_output

    # Attach the set_cap method so the dispatcher can pass caps
    wrapper.set_cap = set_cap  # type: ignore[attr-defined]
    # Store metadata for the dispatcher
    wrapper._shield_tool_name = tool_name  # type: ignore[attr-defined]
    wrapper._shield_resource_fn = resource_fn  # type: ignore[attr-defined]

    return wrapper


# ─── Raw Tool Functions (NEVER exposed directly to the agent) ────────────
#
# These are the actual implementations. The agent cannot call them.
# They are only accessible through the guarded wrapper above.


def _send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a customer or internal address."""
    # In production: call your SMTP/SES/SendGrid API here
    return json.dumps({
        "status": "sent",
        "message_id": f"MSG-{uuid.uuid4().hex[:8]}",
        "to": to,
        "subject": subject,
    })


def _read_customer_profile(customer_id: str) -> str:
    """Look up a customer's profile by ID."""
    # In production: query your CRM/database
    return json.dumps({
        "customer_id": customer_id,
        "name": "Jane Doe",
        "email": "jane.doe@example.com",
        "phone": "+1-555-0123",
        "ssn": "123-45-6789",  # PII — Shield should redact this
        "account_balance": 15420.50,
        "tier": "gold",
    })


def _get_transaction_history(customer_id: str, days: int = 30) -> str:
    """Get recent transactions for a customer."""
    return json.dumps({
        "customer_id": customer_id,
        "transactions": [
            {"date": "2026-06-07", "amount": -2340.00, "merchant": "Dubai Mall", "card": "4532-1234-5678-9012"},
            {"date": "2026-06-05", "amount": -150.00, "merchant": "Carrefour", "card": "4532-1234-5678-9012"},
            {"date": "2026-06-01", "amount": 50000.00, "type": "wire_in", "from_iban": "AE070331234567890123456"},
        ],
    })


def _execute_wire_transfer(from_account: str, to_iban: str, amount: float, currency: str = "USD") -> str:
    """Execute a wire transfer — high-risk action."""
    return json.dumps({
        "status": "executed",
        "transfer_id": f"TXN-{uuid.uuid4().hex[:8]}",
        "from": from_account,
        "to": to_iban,
        "amount": amount,
        "currency": currency,
    })


def _generate_statement(customer_id: str, month: str) -> str:
    """Generate a bank statement PDF."""
    return json.dumps({
        "status": "generated",
        "url": f"https://internal.bank.ae/statements/{customer_id}/{month}.pdf",
        "customer_id": customer_id,
        "month": month,
    })


# ─── Build the Guarded Agent ────────────────────────────────────────────


# ─── Tool Configuration ──────────────────────────────────────────────────
#
# Per-tool settings used by the dispatcher when minting caps.
# clearance_max is a dispatcher concern, not a tool concern — the tool
# only verifies whatever cap it receives.

TOOL_CONFIG = {
    "email_send":             {"clearance_max": "public"},
    "customer_profile_get":   {"clearance_max": "public"},
    "transaction_history":    {"clearance_max": "public"},
    "wire_transfer_execute":  {"clearance_max": "confidential"},  # high-risk
    "statement_generate":     {"clearance_max": "public"},
}


def build_agent():
    """Create a LangChain agent with Shield-guarded tools.

    Key point: the agent gets guarded_tool wrappers, NOT raw functions.
    The wrappers only VERIFY caps — they don't mint them. Minting
    happens in the dispatcher (run_agent) BEFORE the tool is called.

    BAD:
        tools = [send_email, read_database, wire_transfer]
        agent = Agent(tools=tools)   # agent has raw access to everything

    GOOD (what we do here):
        tools = [
            guarded_tool(shield, "email.send", _send_email, ...),
            ...
        ]
        # Dispatcher mints cap, passes it to tool, tool verifies
        agent = Agent(tools=tools)
    """
    # ── Initialize Shield client ──
    global _shield_client
    shield = ShieldClient(base_url=SHIELD_URL, api_key=TENANT_API_KEY)
    _shield_client = shield  # used by emit_audit() for Redis/SIEM sinks

    # ── Get agent token (once per process, refresh every ~10min) ──
    print("\n[SETUP] Minting agent token...")
    agent_token = shield.mint_agent_token(
        user_sub=USER_SUB,
        agent_id=AGENT_ID,
        agent_instance_id=AGENT_INSTANCE_ID,
        build_hash=BUILD_HASH,
        model_version=MODEL_VERSION,
        session_id=SESSION_ID,
    )
    print(f"[SETUP] Agent token minted (agent={AGENT_ID}, user={USER_SUB})")

    # ── Wrap each tool with Shield verification ──
    # Tools only verify + execute + sanitize. They do NOT mint.
    # The dispatcher (run_agent) handles RBAC + mint.

    tools = [
        guarded_tool(
            shield,
            "email_send", _send_email,
            resource_fn=lambda to, **_: f"inbox/{to}",
            description="Send an email to a customer or internal address. Args: to, subject, body",
        ),
        guarded_tool(
            shield,
            "customer_profile_get", _read_customer_profile,
            resource_fn=lambda customer_id, **_: f"customer/{customer_id}",
            description="Look up a customer's profile by ID. Args: customer_id",
        ),
        guarded_tool(
            shield,
            "transaction_history", _get_transaction_history,
            resource_fn=lambda customer_id, **_: f"customer/{customer_id}/transactions",
            description="Get recent transactions for a customer. Args: customer_id, days (optional)",
        ),
        guarded_tool(
            shield,
            "wire_transfer_execute", _execute_wire_transfer,
            resource_fn=lambda to_iban, **_: f"transfer/{to_iban}",
            description="Execute a wire transfer. Args: from_account, to_iban, amount, currency",
        ),
        guarded_tool(
            shield,
            "statement_generate", _generate_statement,
            resource_fn=lambda customer_id, **_: f"customer/{customer_id}/statement",
            description="Generate a bank statement. Args: customer_id, month",
        ),
    ]

    # ── Build the LangChain agent ──
    llm_base_url = f"{LITELLM_URL}/v1" if LITELLM_URL else None
    llm_kwargs = {"model": "gpt-4o-mini", "temperature": 0.1}
    if llm_base_url:
        llm_kwargs["base_url"] = llm_base_url
    llm = ChatOpenAI(**llm_kwargs)

    llm_with_tools = llm.bind_tools(tools)

    return llm_with_tools, tools, shield, agent_token


# ─── Agent Loop / Dispatcher (CALLER SIDE — RBAC + mint) ─────────────────
#
# The dispatcher is the policy decision point (PDP). It decides:
#   1. Should this tool call be allowed? (RBAC check)
#   2. If yes, mint a single-use cap token (proof of authorization)
#   3. Pass the cap to the tool wrapper
#   4. The tool wrapper verifies the cap and executes (PEP)
#
# This models the real-world separation:
#   - Agent runtime / orchestrator = dispatcher (mints caps)
#   - Tool server / MCP server / API gateway = tool wrapper (verifies caps)


def run_agent(llm_with_tools, tools, shield: ShieldClient, agent_token: str, user_message: str) -> str:
    """Run one conversation turn with the guarded agent.

    Flow:
      1. User message → LLM (input guardrails via LiteLLM if configured)
      2. LLM requests tool calls
      3. DISPATCHER: RBAC check + cap mint (OUTSIDE the tool)
      4. TOOL WRAPPER: cap verify + execute + sanitize (INSIDE the tool)
      5. Tool results → LLM for final response
    """
    print(f"\n{'='*70}")
    print(f"  USER: {user_message}")
    print(f"{'='*70}")

    tool_map = {t.name: t for t in tools}
    messages = [
        HumanMessage(content=(
            "You are a banking support agent. Use the provided tools to help "
            "customers. If a tool is blocked, explain that you don't have "
            "permission for that action.\n\n"
            f"User request: {user_message}"
        ))
    ]

    # ── First LLM call — may produce tool calls ──
    try:
        response = llm_with_tools.invoke(messages)
    except Exception as e:
        print(f"  [INPUT GUARDRAIL] BLOCKED: {e}")
        return f"Request blocked by input guardrails: {e}"

    # No tool calls — direct response
    if not response.tool_calls:
        print(f"\n  AGENT: {response.content}")
        return response.content

    # ── Process tool calls ──
    messages.append(response)

    for tc in response.tool_calls:
        name = tc["name"]
        args = tc["args"]
        tool_call_id = tc["id"]

        print(f"\n  --- Tool call: {name}({json.dumps(args, indent=2)}) ---")

        fn = tool_map.get(name)
        if not fn:
            messages.append(ToolMessage(content=f"Unknown tool: {name}", tool_call_id=tool_call_id))
            continue

        # ── DISPATCHER LAYER 1: RBAC check (OUTSIDE the tool) ────────
        # "Can this role use this tool with these arguments?"
        try:
            rbac = shield.tool_check(
                tool_name=name,
                user_role=USER_ROLE,
                agent_key=AGENT_ID,
                tool_params=args,
            )
            allowed = rbac.get("allowed", True) and rbac.get("action") != "block"
            if not allowed:
                reason = "denied by RBAC policy"
                for gr in rbac.get("guardrail_results", []):
                    if not gr.get("passed", True):
                        reason = gr.get("message", reason)
                        break
                print(f"  [DISPATCHER RBAC] BLOCKED {name}: {reason}")
                messages.append(ToolMessage(
                    content=f"BLOCKED: {name} denied for role '{USER_ROLE}' — {reason}",
                    tool_call_id=tool_call_id,
                ))
                continue
        except ShieldError as e:
            print(f"  [DISPATCHER RBAC] ERROR {name}: {e}")
            messages.append(ToolMessage(
                content=f"BLOCKED: RBAC check failed — {e}",
                tool_call_id=tool_call_id,
            ))
            continue

        print(f"  [DISPATCHER RBAC] PASSED {name} for role={USER_ROLE}")

        # ── DISPATCHER LAYER 2: Mint capability (OUTSIDE the tool) ───
        # "Freeze the authorization into a single-use token."
        # The tool will verify this token before executing.
        resource_fn = getattr(fn, "_shield_resource_fn", None)
        resource = name
        if resource_fn:
            try:
                resource = resource_fn(**args)
            except Exception:
                resource = name

        config = TOOL_CONFIG.get(name, {})
        clearance_max = config.get("clearance_max", "public")

        try:
            cap_result = shield.mint_cap(
                agent_token,
                tool=name,
                resource=resource,
                clearance_max=clearance_max,
            )
            cap_token = cap_result["cap_token"]
            print(f"  [DISPATCHER MINT] OK — expires in {cap_result['expires_in']}s")
        except ShieldError as e:
            print(f"  [DISPATCHER MINT] DENIED {name}: {e}")
            messages.append(ToolMessage(
                content=f"BLOCKED: capability denied — {e}",
                tool_call_id=tool_call_id,
            ))
            continue

        # ── Pass the cap to the tool wrapper, then invoke ─────────────
        # In production: this would be an HTTP header, gRPC metadata,
        # or MCP context field. Here we use the set_cap() method.
        fn.set_cap(cap_token, resource)

        # Now the tool runs: verify cap → execute → sanitize
        result = fn.invoke(args)

        messages.append(ToolMessage(content=str(result), tool_call_id=tool_call_id))

    # ── Final LLM call with tool results ──
    try:
        final = llm_with_tools.invoke(messages)
        print(f"\n  AGENT: {final.content}")
        return final.content
    except Exception as e:
        print(f"  [OUTPUT GUARDRAIL] BLOCKED: {e}")
        return f"Response blocked by output guardrails: {e}"


# ─── Print Audit Log ────────────────────────────────────────────────────


def print_audit_log():
    """Print the audit trail of all tool calls."""
    print(f"\n{'='*70}")
    print(f"  AUDIT LOG — {len(audit_log)} tool invocations")
    print(f"{'='*70}\n")

    for i, record in enumerate(audit_log, 1):
        status = "ALLOWED" if record.executed else "BLOCKED"
        print(f"  [{i}] {record.tool_name} → {status}")
        print(f"      resource:    {record.resource}")
        print(f"      agent:       {record.agent_id}")
        print(f"      user:        {record.user_sub} (role={record.user_role})")
        print(f"      rbac:        {'PASS' if record.rbac_allowed else 'FAIL'}")
        print(f"      cap_minted:  {'YES' if record.cap_minted else 'NO'}")
        print(f"      cap_verified:{'YES' if record.cap_verified else 'NO'}")
        print(f"      executed:    {'YES' if record.executed else 'NO'}")
        print(f"      sanitized:   {'YES' if record.output_sanitized else 'NO'}")
        if record.denied_reason:
            print(f"      denied:      {record.denied_reason}")
        print()


# ─── Main ────────────────────────────────────────────────────────────────


def main():
    if not TENANT_API_KEY:
        print("ERROR: Set SHIELD_TENANT_KEY environment variable")
        print("  export SHIELD_TENANT_KEY='sk-tenant-xxx'")
        sys.exit(1)

    print(f"Shield:    {SHIELD_URL}")
    print(f"Agent:     {AGENT_ID} (instance={AGENT_INSTANCE_ID})")
    print(f"User:      {USER_SUB} (role={USER_ROLE})")
    print(f"Session:   {SESSION_ID}")
    print(f"Audit sinks: local={'ON' if AUDIT_LOCAL else 'OFF'}"
          f"  redis={'ON' if AUDIT_REDIS else 'OFF'}"
          f"  siem={'ON' if AUDIT_SIEM else 'OFF'}")

    llm_with_tools, tools, shield, agent_token = build_agent()

    # ── Test scenarios ──

    # Scenario 1: Normal request — should pass all layers
    run_agent(
        llm_with_tools, tools, shield, agent_token,
        "Look up the profile for customer CUST-12345",
    )

    # Scenario 2: Tool the role can't access — RBAC should block
    run_agent(
        llm_with_tools, tools, shield, agent_token,
        "Execute a wire transfer of $50,000 from ACC-001 to IBAN AE070331234567890123456",
    )

    # Scenario 3: Sensitive output — sanitization should redact PII
    run_agent(
        llm_with_tools, tools, shield, agent_token,
        "Get the full profile and recent transactions for customer CUST-12345",
    )

    # Scenario 4: Email to external domain — data policy may block
    run_agent(
        llm_with_tools, tools, shield, agent_token,
        "Send an email to someone@gmail.com with subject 'Account Info' and body 'Here are the details'",
    )

    # ── Print the full audit trail ──
    print_audit_log()


if __name__ == "__main__":
    main()
