"""A small Shield client for LangChain agents.

The integration in three lines:

    shield = ShieldClient.from_env()

    @shield.tool
    def read_logs(service: str, lines: int = 20) -> str:
        \"\"\"Read recent log lines for a service.\"\"\"
        return "\\n".join(LOGS[service][-lines:])

    # once per request, with the role YOUR app resolved
    session = shield.session(role)
    agent = create_agent(llm, session.tools(), system_prompt=SYSTEM)

`@shield.tool` is a drop-in for LangChain's `@tool`. The function you write is
unchanged; what it gains is an authorization check before it runs, and a
capability minted and burned around it when you turn that on.

The one design constraint worth understanding
---------------------------------------------
`session.tools()` builds the LangChain tools fresh, closed over the role. That
is not an inefficiency to optimise away — it is the security property.

A tool built once at import and shared across requests would have to receive
the role as an ARGUMENT, and every argument of a tool is chosen by the model. A
prompt injection reading "call restart_service as sre_lead" would then work.
Because the role lives in a closure, there is no parameter for it, and the
model cannot express the idea at all. It picks WHICH tool. Your app picks WHO.

So: never add a `role` parameter to a guarded tool, and never cache a session
across users.

Where the role comes from is your problem, not this client's. A session cookie,
an IdP token, a service identity — all fine. What must not happen is reading it
off the incoming request, because then the caller chooses it.
"""
import json
import os
import time
import uuid
from typing import Callable, Optional

import requests
from langchain_core.tools import tool as langchain_tool

__all__ = ["ShieldClient", "ShieldSession", "Stage"]


class Stage(dict):
    """One step of the pipeline, for tracing. A dict so it is trivially JSON."""

    def __init__(self, stage, status, label="", meta="", ms=None):
        super().__init__(stage=stage, status=status, label=label,
                         meta=meta, ms=ms)


class ShieldClient:
    """Holds the deployment config and the tool registry.

    One per process. Sessions are per request.
    """

    def __init__(self, url: str, tenant_key: str, agent_id: str, *,
                 proxy_token: str = "", tenant_id: str = "",
                 capabilities: bool = False, model_version: str = "unknown",
                 timeout: int = 30):
        self.url = (url or "").rstrip("/")
        self.tenant_key = tenant_key
        self.agent_id = agent_id
        # Proves THIS HOP to Shield. Required for strict_proxy, where a role
        # asserted by an untrusted peer is discarded. Must never reach a client.
        self.proxy_token = proxy_token
        self.tenant_id = tenant_id
        self.capabilities = capabilities
        self.model_version = model_version
        self.timeout = timeout

        self.instance_id = "inst-" + uuid.uuid4().hex[:8]
        self._registry: list = []      # [(fn, name)]
        self._agent_token = ""

    @classmethod
    def from_env(cls) -> "ShieldClient":
        """Read the variables the examples in this folder already use."""
        return cls(
            url=os.getenv("LLM_SHIELD_URL", "http://localhost:8000"),
            tenant_key=os.getenv("TENANT_API_KEY", ""),
            agent_id=(os.getenv("SHIELD_AGENT_KEY")
                      or os.getenv("AGENT_ID") or "agent"),
            proxy_token=os.getenv("SHIELD_PROXY_TOKEN", ""),
            tenant_id=os.getenv("TENANT_ID", ""),
            capabilities=os.getenv("DEMO_CAPS", "").strip().lower()
            in ("1", "true", "yes", "on"),
            model_version=os.getenv("DEMO_MODEL", "unknown"),
        )

    # ── registration ─────────────────────────────────────────────────────

    def tool(self, fn: Callable) -> Callable:
        """Register a function as a guarded tool. Drop-in for `@tool`.

        Returns the ORIGINAL function, not a LangChain tool: the tool object is
        built per session so it can close over the role. Your module-level name
        stays callable and testable on its own, which is usually what you want
        anyway.
        """
        self._registry.append((fn, fn.__name__))
        return fn

    def session(self, role: str,
                on_stage: Optional[Callable[[dict], None]] = None) -> "ShieldSession":
        """A per-request binding of this client to one role.

        `on_stage` is called with each Stage as it happens — wire it to a
        stream and the user watches authorization occur.
        """
        return ShieldSession(self, role, on_stage)

    # ── transport ────────────────────────────────────────────────────────

    def headers(self, role: str, extra: Optional[dict] = None) -> dict:
        h = {"Content-Type": "application/json", "X-API-Key": self.tenant_key,
             "X-Agent-Key": self.agent_id}
        if role:
            h["X-User-Role"] = role
        if self.proxy_token:
            h["X-Shield-Proxy-Token"] = self.proxy_token
        if extra:
            h.update(extra)
        return h

    def post(self, path: str, body: dict, role: str,
             extra: Optional[dict] = None):
        """(json, elapsed_ms, error). Never raises — callers fail closed."""
        t0 = time.perf_counter()
        try:
            r = requests.post(f"{self.url}{path}", timeout=self.timeout,
                              headers=self.headers(role, extra), json=body)
        except Exception as e:
            return None, (time.perf_counter() - t0) * 1000, e.__class__.__name__
        ms = (time.perf_counter() - t0) * 1000
        if r.status_code != 200:
            return None, ms, f"{r.status_code}: {r.text[:160]}"
        try:
            return r.json(), ms, None
        except Exception:
            return None, ms, "non-JSON response"


class ShieldSession:
    """One request, one role. Do not reuse across users."""

    def __init__(self, client: ShieldClient, role: str,
                 on_stage: Optional[Callable[[dict], None]] = None):
        self.client = client
        self.role = role
        self.trace: list = []
        self._on_stage = on_stage

    def _emit(self, stage: Stage) -> None:
        self.trace.append(stage)
        if self._on_stage:
            try:
                self._on_stage(stage)
            except Exception:
                pass          # tracing must never break the request

    # ── input guardrails ─────────────────────────────────────────────────

    def screen_input(self, text: str) -> Optional[str]:
        """Run input guardrails. Returns a refusal string, or None to proceed.

        Call this BEFORE the model sees the prompt. A jailbreak that never
        reaches the model cannot talk it into anything.
        """
        d, ms, err = self.client.post("/guardrails/input", {"message": text},
                                      self.role)
        if err:
            self._emit(Stage("input", "fail", "unreachable", err, ms))
            return "Shield could not screen this request, so it was not sent."

        ran = d.get("guardrail_results", []) or []
        bad = [g for g in ran if not g.get("passed", True)]
        self._emit(Stage("input", "block" if bad else "pass",
                         "BLOCK" if bad else "pass",
                         f"{len(ran)} guardrails", ms))
        for g in bad:
            self._emit(Stage("", "detail", g.get("guardrail", ""),
                             str(g.get("message", ""))[:160]))
        if d.get("safe") is False or bad:
            why = bad[0].get("message") if bad else "blocked"
            return f"Blocked by input guardrails: {why}"
        return None

    # ── authorization ────────────────────────────────────────────────────

    def check(self, tool_name: str, params: dict) -> tuple:
        """(allowed, reason) from Shield's RBAC + data policies."""
        d, ms, err = self.client.post(
            "/v1/shield/tool/check",
            {"agent_key": self.client.agent_id, "tool_name": tool_name,
             "user_role": self.role, "tool_params": params}, self.role)
        if err:
            self._emit(Stage("rbac", "fail", "unreachable", err, ms))
            return False, f"could not reach Shield ({err})"

        allowed = bool(d.get("allowed"))
        shown = " ".join(f"{k}={v}" for k, v in params.items())
        self._emit(Stage("rbac", "allow" if allowed else "deny",
                         f"{'ALLOW' if allowed else 'DENY'} {tool_name}",
                         f"{shown}  role={self.role}".strip(), ms))
        why = next((g.get("message") for g in d.get("guardrail_results", [])
                    if not g.get("passed", True)), None)
        if not allowed:
            why = why or "not permitted"
            self._emit(Stage("", "detail", "", str(why)[:200]))
            if self.client.capabilities:
                self._emit(Stage("", "detail", "",
                                 "no capability minted — the check gates the mint"))
        return allowed, (why or "allowed")

    def _agent_token(self) -> Optional[str]:
        c = self.client
        if c._agent_token:
            return c._agent_token
        d, ms, err = c.post("/v1/shield/auth/agent-token",
                            {"user_sub": "app-session", "agent_id": c.agent_id,
                             "agent_instance_id": c.instance_id,
                             "tenant_id": c.tenant_id, "build_hash": "demo",
                             "model_version": c.model_version,
                             "session_id": c.instance_id, "ttl_seconds": 900},
                            self.role)
        if err:
            self._emit(Stage("authn", "fail", "no agent token", err, ms))
            return None
        c._agent_token = d["agent_token"]
        self._emit(Stage("authn", "ok", "agent token",
                         f"instance={c.instance_id}", ms))
        return c._agent_token

    def _capability(self, tool_name: str, params: dict) -> Optional[str]:
        """mint -> verify (nonce burned). Refusal string, or None to run."""
        c = self.client
        token = self._agent_token()
        if not token:
            return "DENIED — no agent identity could be established."

        resource = (f"service/{params['service']}" if params.get("service")
                    else f"secret/{params['name']}" if params.get("name")
                    else f"{tool_name}/any")
        d, mint_ms, err = c.post("/v1/shield/cap/mint",
                                 {"tool": tool_name, "resource": resource,
                                  "ttl_seconds": 30,
                                  "session_id": c.instance_id,
                                  "tool_params": params}, self.role,
                                 extra={"X-Agent-Token": token})
        if err:
            self._emit(Stage("cap", "deny", f"NO MINT {tool_name}", err, mint_ms))
            return f"DENIED by policy: {err}"

        v, verify_ms, verr = c.post("/v1/shield/cap/verify",
                                    {"cap_token": d["cap_token"],
                                     "expected_tool": tool_name}, self.role)
        ok = bool(v and v.get("valid") is True)
        self._emit(Stage(
            "cap", "ok" if ok else "deny",
            f"{'MINT+BURN' if ok else 'INVALID'} {tool_name}({resource})",
            f"role={self.role}  mint {mint_ms:.0f}ms · verify {verify_ms:.0f}ms"))
        if not ok:
            return f"DENIED — capability did not verify: {(v or {}).get('error', verr)}"
        return None

    def authorize(self, tool_name: str, params: dict) -> Optional[str]:
        """The whole gate. Returns a refusal string, or None to proceed.

        RBAC first, THEN mint. cap/mint does not enforce role -> tool on its
        own — it unions every role's permissions — so an app that wants the
        role respected has to ask for the check and refuse to mint on a denial.
        """
        allowed, reason = self.check(tool_name, params)
        if not allowed:
            return f"DENIED by policy: {reason}"
        if self.client.capabilities:
            return self._capability(tool_name, params)
        return None

    # ── the tools ────────────────────────────────────────────────────────

    def tools(self) -> list:
        """LangChain tools for THIS role.

        Built per session so each closes over the role. See the module
        docstring for why that is the point rather than an inefficiency.
        """
        built = []
        for fn, name in self.client._registry:
            built.append(self._wrap(fn, name))
        return built

    def _wrap(self, fn: Callable, name: str):
        session = self

        def guarded(*args, **kwargs):
            params = dict(kwargs)
            refusal = session.authorize(name, params)
            if refusal:
                # Returned to the MODEL, not raised. The agent then explains
                # the refusal instead of the request failing.
                return refusal
            out = fn(*args, **kwargs)
            session._emit(Stage("tool", "ok", "result", str(out)[:300]))
            return out

        # Carry the signature and docstring across — LangChain builds the tool
        # schema from them, and the model chooses arguments from that schema.
        guarded.__name__ = fn.__name__
        guarded.__doc__ = fn.__doc__
        guarded.__annotations__ = getattr(fn, "__annotations__", {})
        try:
            import inspect
            guarded.__signature__ = inspect.signature(fn)
        except Exception:
            pass
        return langchain_tool(guarded)
