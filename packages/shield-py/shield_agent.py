"""Agent identity for Votal Shield: a key-bound agent token, and one capability
per tool call.

    pip install "votalai-shield[agent]"        # httpx + cryptography

    from shield_agent import ShieldAgent, CapabilityVerifier, ApprovalRequired

    agent = ShieldAgent(agent_id="support-bot", user_sub="user-123",
                        session_id="ticket-9912", user_role="support")
    cap = agent.mint("ticket_lookup", resource="ticket/9912")   # raises if denied
    tool_server_call(..., capability=cap.token)

    # on the tool server
    claims = CapabilityVerifier().verify(cap_token, expected_tool="ticket_lookup",
                                         expected_resource="ticket/9912")

What it does for you, because each is where hand-written integrations go wrong:

1. **The token is bound to a key that never leaves the process.** An Ed25519
   key is made at start-up and its public half goes into the token request, so
   Shield binds the token to it (`cnf.jkt`). Every request then carries a fresh
   DPoP proof (RFC 9449) for that exact method and URL. A copied token is
   useless without the key once Shield runs with SHIELD_AGENT_TOKEN_POP=required.
2. **Tokens are short-lived and refreshed before they expire**, not after a
   failed call.
3. **A denial is an exception, not a status code to remember to check.**
   `CapabilityDenied` carries Shield's reasons; `ApprovalRequired` carries the
   approval request id a human must approve, after which `mint(...,
   approval_grant=...)` with the same parameters succeeds once.
4. **Capabilities are single use.** The tool server verifies once; a replay is
   refused by Shield.

Spec: docs/specs/agent-identity-poc.md. Server side: docs/AGENT_AUTH_ARCHITECTURE.md.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx

__all__ = ["AgentKey", "dpop_proof", "ShieldAgent", "Capability", "CapabilityVerifier",
           "AgentIdentityError", "CapabilityDenied", "ApprovalRequired", "CapabilityInvalid"]

TOKEN_PATH = "/v1/tenant/me/agent-auth/agent-token"
MINT_PATH = "/v1/shield/cap/mint"
VERIFY_PATH = "/v1/shield/cap/verify"
REVOKE_PATH = "/v1/tenant/me/agent-auth/revoke"
POP_HEADER = "X-Agent-DPoP"
TOKEN_HEADER = "X-Agent-Token"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _json_b64(obj: dict) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


# ── errors ───────────────────────────────────────────────────────────


class AgentIdentityError(Exception):
    """A call to Shield failed. `status` is the HTTP status (0 for transport
    errors); `detail` is Shield's error body, normalized to a string or dict."""

    def __init__(self, message: str, status: int = 0, detail: Any = None):
        super().__init__(message)
        self.status = status
        self.detail = detail


class CapabilityDenied(AgentIdentityError):
    """Shield refused the capability. `reasons` lists why, when the server is
    configured to say (SHIELD_VERBOSE_REASONS); otherwise it is generic."""

    def __init__(self, message: str, status: int, detail: Any, reasons: list[str]):
        super().__init__(message, status, detail)
        self.reasons = reasons


class ApprovalRequired(CapabilityDenied):
    """The tool needs a human approval first. Shield opened request
    `request_id`; once approved, call mint again with the grant it returns and
    the same tool, resource and tool_params."""

    def __init__(self, message: str, status: int, detail: dict):
        super().__init__(message, status, detail, ["approval_required"])
        self.request_id = detail.get("request_id", "")
        self.required_approvals = detail.get("required_approvals", 1)
        self.expires_at = detail.get("expires_at")


class CapabilityInvalid(AgentIdentityError):
    """A tool server's verification failed: forged, expired, for another tool
    or resource, or already used (`replayed`)."""

    @property
    def replayed(self) -> bool:
        return "replay" in str(self).lower()


def _detail(resp: httpx.Response) -> Any:
    try:
        body = resp.json()
    except Exception:
        return resp.text[:500]
    if isinstance(body, dict) and "detail" in body:
        return body["detail"]
    if isinstance(body, dict) and "error" in body:
        return body.get("detail") or body["error"]
    return body


def _message(detail: Any, fallback: str) -> str:
    if isinstance(detail, str):
        return detail
    if isinstance(detail, dict):
        reasons = detail.get("reasons")
        if isinstance(reasons, list) and reasons:
            return "; ".join(str(r) for r in reasons)
        return str(detail.get("message") or detail.get("reason") or detail.get("error") or fallback)
    return fallback


# ── the agent's key and its proofs ───────────────────────────────────


class AgentKey:
    """An Ed25519 key for one agent process. Generate one per process and keep
    it in memory; `from_pem` exists for agents that must survive restarts
    within a token's lifetime."""

    def __init__(self, private_key=None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self._key = private_key or Ed25519PrivateKey.generate()

    @classmethod
    def generate(cls) -> "AgentKey":
        return cls()

    @classmethod
    def from_pem(cls, pem: bytes) -> "AgentKey":
        from cryptography.hazmat.primitives import serialization
        return cls(serialization.load_pem_private_key(pem, password=None))

    def to_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption())

    @property
    def jwk(self) -> dict:
        """The public key as a JWK (RFC 8037). Never contains the private part."""
        from cryptography.hazmat.primitives import serialization
        raw = self._key.public_key().public_bytes(serialization.Encoding.Raw,
                                                  serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}

    @property
    def thumbprint(self) -> str:
        """RFC 7638 thumbprint: what Shield puts in the token's cnf.jkt."""
        j = self.jwk
        canon = json.dumps({"crv": j["crv"], "kty": j["kty"], "x": j["x"]}, separators=(",", ":"))
        return _b64url(hashlib.sha256(canon.encode()).digest())

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


def htu(url: str) -> str:
    """The URL a proof binds to: scheme, host and path, no query or fragment."""
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}{p.path}"


def dpop_proof(key: AgentKey, method: str, url: str, *, now: Optional[int] = None,
               jti: Optional[str] = None) -> str:
    """A DPoP proof (RFC 9449) for one request: typ dpop+jwt, EdDSA, the public
    JWK in the header, and jti / htm / htu / iat. Single use: Shield refuses a
    jti it has seen."""
    header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": key.jwk}
    claims = {"jti": jti or uuid.uuid4().hex, "htm": method.upper(), "htu": htu(url),
              "iat": int(now if now is not None else time.time())}
    signing_input = f"{_json_b64(header)}.{_json_b64(claims)}"
    return f"{signing_input}.{_b64url(key.sign(signing_input.encode()))}"


# ── the agent ────────────────────────────────────────────────────────


@dataclass
class Capability:
    """A single-use permission for one tool call. Pass `token` to the tool
    server, which verifies it with Shield before acting."""
    token: str
    expires_in: int
    decision: dict = field(default_factory=dict)
    tool: str = ""
    resource: str = ""


class ShieldAgent:
    """One running agent: its key, its token, and capability minting.

    shield_url / api_key default to SHIELD_URL / SHIELD_API_KEY. The API key is
    the tenant key used to obtain the agent token; it is also sent with each
    request so Shield can check the token belongs to the same tenant.

    Pass `client` to reuse an httpx.Client (or a compatible test client).
    """

    def __init__(self, agent_id: str, user_sub: str, session_id: str, *,
                 shield_url: Optional[str] = None, api_key: Optional[str] = None,
                 user_role: Optional[str] = None, build_hash: str = "unknown",
                 model_version: str = "unknown", key: Optional[AgentKey] = None,
                 bind_key: bool = True, ttl_seconds: int = 900, refresh_margin_s: int = 60,
                 instance_id: Optional[str] = None, runtime_profile: Optional[str] = None,
                 runtime_profile_hash: Optional[str] = None,
                 parent_agent_token: Optional[str] = None,
                 client: Optional[httpx.Client] = None, timeout: float = 15.0):
        self.shield_url = (shield_url or os.environ.get("SHIELD_URL") or "").rstrip("/")
        if not self.shield_url:
            raise ValueError("shield_url (or SHIELD_URL) is required")
        self.api_key = api_key if api_key is not None else os.environ.get("SHIELD_API_KEY", "")
        self.agent_id, self.user_sub, self.session_id = agent_id, user_sub, session_id
        self.user_role = user_role
        self.build_hash, self.model_version = build_hash, model_version
        self.key = key or (AgentKey.generate() if bind_key else None)
        self.ttl_seconds, self.refresh_margin_s = ttl_seconds, refresh_margin_s
        self.instance_id = instance_id or f"{agent_id}-{uuid.uuid4().hex[:12]}"
        self.runtime_profile, self.runtime_profile_hash = runtime_profile, runtime_profile_hash
        self.parent_agent_token = parent_agent_token
        self._client = client or httpx.Client(timeout=timeout)
        self._token: Optional[str] = None
        self._token_exp = 0.0
        self._lock = threading.Lock()

    # tokens

    def token(self, force: bool = False) -> str:
        """The current agent token, fetched or refreshed when it is within
        refresh_margin_s of expiring."""
        with self._lock:
            if force or not self._token or time.time() > self._token_exp - self.refresh_margin_s:
                self._token, ttl = self._fetch_token()
                self._token_exp = time.time() + ttl
            return self._token

    def _fetch_token(self) -> tuple[str, int]:
        body: dict[str, Any] = {
            "user_sub": self.user_sub, "agent_id": self.agent_id,
            "agent_instance_id": self.instance_id, "build_hash": self.build_hash,
            "model_version": self.model_version, "session_id": self.session_id,
            "ttl_seconds": self.ttl_seconds,
        }
        if self.key is not None:
            body["agent_jwk"] = self.key.jwk
        for k in ("runtime_profile", "runtime_profile_hash", "parent_agent_token"):
            if getattr(self, k):
                body[k] = getattr(self, k)
        resp = self._post(TOKEN_PATH, body, headers=self._key_header())
        if resp.status_code != 200:
            d = _detail(resp)
            raise AgentIdentityError(f"agent token refused: {_message(d, resp.reason_phrase)}",
                                     resp.status_code, d)
        data = resp.json()
        return data["agent_token"], int(data.get("expires_in", self.ttl_seconds))

    def _key_header(self) -> dict:
        return {"X-API-Key": self.api_key} if self.api_key else {}

    def auth_headers(self, method: str, url: str) -> dict:
        """Headers that authenticate this agent on one request to Shield: the
        token, a fresh proof for this method and URL, the tenant key and role."""
        h = {TOKEN_HEADER: self.token(), **self._key_header()}
        if self.key is not None:
            h[POP_HEADER] = dpop_proof(self.key, method, url)
        if self.user_role:
            h["X-User-Role"] = self.user_role
        return h

    def request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Any Shield call, authenticated as this agent (for example
        /v1/shield/tool/check). Returns the raw response."""
        url = self.shield_url + path
        headers = {**self.auth_headers(method, url), **(kwargs.pop("headers", None) or {})}
        try:
            return self._client.request(method, url, headers=headers, **kwargs)
        except httpx.HTTPError as e:
            raise AgentIdentityError(f"Shield unreachable: {e}") from e

    def _post(self, path: str, body: dict, headers: Optional[dict] = None) -> httpx.Response:
        try:
            return self._client.post(self.shield_url + path, json=body, headers=headers or {})
        except httpx.HTTPError as e:
            raise AgentIdentityError(f"Shield unreachable: {e}") from e

    # capabilities

    def mint(self, tool: str, resource: str, *, tool_params: Optional[dict] = None,
             data_scope: Optional[str] = None, approval_grant: Optional[str] = None,
             clearance_max: str = "public", ttl_seconds: int = 60,
             scope_constraints: Optional[list[str]] = None,
             session_id: Optional[str] = None) -> Capability:
        """Ask Shield for permission to make one tool call. Raises
        ApprovalRequired, CapabilityDenied or AgentIdentityError."""
        body: dict[str, Any] = {"tool": tool, "resource": resource, "clearance_max": clearance_max,
                                "ttl_seconds": ttl_seconds,
                                "session_id": session_id or self.session_id}
        if tool_params is not None:
            body["tool_params"] = tool_params
        if data_scope:
            body["data_scope"] = data_scope
        if approval_grant:
            body["approval_grant"] = approval_grant
        if scope_constraints:
            body["scope_constraints"] = scope_constraints
        resp = self.request("POST", MINT_PATH, json=body)
        if resp.status_code == 200:
            data = resp.json()
            return Capability(data["cap_token"], int(data.get("expires_in", ttl_seconds)),
                              data.get("decision") or {}, tool, resource)
        d = _detail(resp)
        if resp.status_code == 403 and isinstance(d, dict) and d.get("reason") == "approval_required":
            raise ApprovalRequired(f"'{tool}' needs approval (request {d.get('request_id')})",
                                   resp.status_code, d)
        if resp.status_code == 403:
            reasons = d.get("reasons") if isinstance(d, dict) else None
            raise CapabilityDenied(f"capability for '{tool}' denied: {_message(d, 'denied')}",
                                   resp.status_code, d, list(reasons or []))
        raise AgentIdentityError(f"cap/mint failed ({resp.status_code}): {_message(d, resp.reason_phrase)}",
                                 resp.status_code, d)

    # delegation and revocation

    def delegate(self, agent_id: str, **overrides) -> "ShieldAgent":
        """A sub-agent acting for the same user, its token chained to this one
        (Shield tracks the delegation depth). It gets its own key."""
        kw = dict(user_sub=self.user_sub, session_id=self.session_id, shield_url=self.shield_url,
                  api_key=self.api_key, user_role=self.user_role, client=self._client,
                  parent_agent_token=self.token())
        kw.update(overrides)
        return ShieldAgent(agent_id, **kw)

    def revoke(self, reason: str = "") -> dict:
        """Revoke this instance at once: its token stops working everywhere."""
        resp = self._post(REVOKE_PATH, {"agent_instance_id": self.instance_id, "reason": reason},
                          headers=self._key_header())
        if resp.status_code != 200:
            d = _detail(resp)
            raise AgentIdentityError(f"revoke failed: {_message(d, resp.reason_phrase)}",
                                     resp.status_code, d)
        with self._lock:
            self._token, self._token_exp = None, 0.0
        return resp.json()


class CapabilityVerifier:
    """For tool servers: check a capability with Shield before acting on it.
    Verification is single use; call it once per tool call."""

    def __init__(self, shield_url: Optional[str] = None, *, client: Optional[httpx.Client] = None,
                 timeout: float = 15.0):
        self.shield_url = (shield_url or os.environ.get("SHIELD_URL") or "").rstrip("/")
        if not self.shield_url:
            raise ValueError("shield_url (or SHIELD_URL) is required")
        self._client = client or httpx.Client(timeout=timeout)

    def verify(self, cap_token: str, expected_tool: str,
               expected_resource: Optional[str] = None) -> dict:
        """The capability's claims (agent, user, tool, resource, decision), or
        CapabilityInvalid. Fails closed: an unreachable Shield is an error."""
        try:
            resp = self._client.post(self.shield_url + VERIFY_PATH, json={
                "cap_token": cap_token, "expected_tool": expected_tool,
                "expected_resource": expected_resource})
        except httpx.HTTPError as e:
            raise CapabilityInvalid(f"Shield unreachable: {e}") from e
        if resp.status_code != 200:
            raise CapabilityInvalid(f"verification failed ({resp.status_code})", resp.status_code,
                                    _detail(resp))
        data = resp.json()
        if not data.get("valid"):
            raise CapabilityInvalid(data.get("error") or "invalid capability", 200, data)
        return data.get("claims") or {}
