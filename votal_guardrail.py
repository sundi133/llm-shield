"""
Votal AI Guardrails Integration for LiteLLM — Single-Pane Architecture

Handles:
  - Input guardrails (pre_call) via Shield /guardrails/input
  - Output guardrails (post_call) via Shield /guardrails/output
  - Tool call RBAC (post_call) via Shield /guardrails/output with tool context
  - Streaming output guardrails (periodic + final check)

Single-pane flow (developer calls LiteLLM only):
  App → LiteLLM /v1/chat/completions (with tools + guardrails)
         pre_call:  Shield /guardrails/input (text)
         LLM call → returns text + tool_calls
         post_call: Shield /guardrails/output (text)
                    Shield /guardrails/output per tool_call (tool context)
         Denied tool call → request blocked; allowed → response passes through

A denied tool call blocks the whole response. Set VOTAL_ENFORCE_TOOL_RBAC=false
to restore the older advisory behaviour, where the verdict was recorded in
response._hidden_params["tool_rbac"] and nothing was blocked.
"""

import json
import httpx
from typing import Dict, List, Any, Optional, Union
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.proxy._types import UserAPIKeyAuth
from litellm.caching.caching import DualCache


class VotalGuardrail(CustomGuardrail):
    """Votal guardrail with input, output, and tool RBAC enforcement."""

    #: Cap on a forwarded delegated user token. Mirrors _MAX_TOKEN_BYTES in
    #: core/delegation.py — a user token is small, and anything larger is not a
    #: credential. Bounds what this hook will push at Shield per request.
    MAX_OBO_BYTES = 8192

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Read settings from config.yaml
        api_base = "http://172.148.110.30:8080"
        api_token = ""
        last_k = 3
        try:
            import yaml, os, sys
            # Check env var first (highest priority)
            api_token = os.environ.get("RUNPOD_TOKEN", "") or os.environ.get("SHIELD_API_TOKEN", "")
            for i, arg in enumerate(sys.argv[:-1]):
                if arg.startswith("--config="):
                    path = arg.split("=", 1)[1]
                elif arg == "--config":
                    path = sys.argv[i + 1]
                else:
                    continue
                if os.path.exists(path):
                    with open(path) as f:
                        cfg = yaml.safe_load(f) or {}
                    votal_cfg = cfg.get("votal_guardrail", {})
                    api_base = votal_cfg.get("api_base", api_base)
                    if not api_token:
                        api_token = votal_cfg.get("api_token", "")
                    last_k = int(votal_cfg.get("last_k_messages", last_k))
                    break
        except:
            pass

        self.api_base = api_base.rstrip("/")
        self.last_k_messages = last_k
        self.block_on_failure = True
        # Tool RBAC is an authorization control, so a denial blocks the response.
        # Escape hatch: VOTAL_ENFORCE_TOOL_RBAC=false restores the previous
        # advisory behaviour (verdict recorded in _hidden_params, nothing blocked)
        # for anyone who was relying on denied tool calls still being returned.
        try:
            import os as _os
            self.enforce_tool_rbac = _os.environ.get(
                "VOTAL_ENFORCE_TOOL_RBAC", "true").strip().lower() not in ("false", "0", "no")
        except Exception:
            self.enforce_tool_rbac = True
        self.check_every_n_chunks = 20  # streaming check cadence

        # Shared secret proving this hop to Shield. When set, Shield's
        # strict_proxy role-binding mode accepts a role we assert; when unset,
        # nothing changes and Shield treats us as any other caller.
        # Must match SHIELD_TRUSTED_PROXY_SECRET on the Shield side.
        try:
            import os as _os
            self.proxy_token = _os.environ.get("VOTAL_SHIELD_PROXY_TOKEN", "").strip()
        except Exception:
            self.proxy_token = ""

        # Client with optional auth for RunPod/cloud deployments
        client_headers = {"Content-Type": "application/json"}
        if api_token:
            client_headers["Authorization"] = f"Bearer {api_token}"
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(10),
            headers=client_headers,
        )

        print(f"VotalGuardrail initialized → {self.api_base} (last_k={self.last_k_messages}, auth={'yes' if api_token else 'no'})")

    def _resolve_user_role(self, data: dict, user_api_key_dict) -> str:
        """The role Shield should see, most trustworthy source first.

        Sources, in order:

        1. The LiteLLM virtual key's metadata (``shield_user_role``). This is
           the only role on the request that was *authenticated* — the caller
           proved the key, and whoever provisioned the key chose the role.
        2. ``data["metadata"]["user_role"]``, the pre-existing path.
        3. The caller's own ``x-user-role`` header — kept only when we are NOT
           vouching, because it preserves today's behaviour for deployments
           that have not configured the proxy boundary.

        NOTE: ``user_api_key_dict.user_role`` is deliberately not read. That
        field is LiteLLM's own admin model (proxy_admin, internal_user, ...),
        not the application's RBAC role; forwarding it would inject LiteLLM's
        vocabulary into Shield's policy matrix.

        When ``self.proxy_token`` is set, this plugin is asserting to Shield
        that the hop is trusted (strict_proxy). Forwarding a caller-supplied
        header under that assertion would launder the caller's own claim
        through a hop Shield trusts, which is precisely the forgery the mode
        exists to stop — so source 3 is dropped in that case.
        """
        if user_api_key_dict is not None:
            try:
                key_meta = getattr(user_api_key_dict, "metadata", None) or {}
                role = str(key_meta.get("shield_user_role", "") or "").strip()
                if role:
                    return role
            except Exception:
                pass

        metadata = data.get("metadata", {}) or {}
        role = str(metadata.get("user_role", "") or "").strip()
        if role:
            return role

        if self.proxy_token:
            return ""

        proxy_headers = data.get("proxy_server_request", {}).get("headers", {})
        return str(proxy_headers.get("x-user-role", "") or "").strip()

    def _extract_shield_headers(self, data: dict, user_api_key_dict=None) -> dict:
        """Extract tenant/agent headers from the proxy request to forward to Shield.

        Reads from proxy_server_request.headers first, then falls back to
        metadata dict. The tenant_api_key is passed via metadata (not headers)
        because LiteLLM intercepts X-API-Key as its own user key.
        """
        headers = {}
        proxy_headers = data.get("proxy_server_request", {}).get("headers", {})
        metadata = data.get("metadata", {}) or {}

        # Tenant API key — prefer metadata (avoids LiteLLM interception)
        tenant_key = metadata.get("tenant_api_key") or proxy_headers.get("x-api-key", "")
        if tenant_key:
            headers["x-api-key"] = tenant_key

        # Agent identity
        agent_key = metadata.get("agent_key") or proxy_headers.get("x-agent-key", "")
        if agent_key:
            headers["x-agent-key"] = agent_key

        # Verified agent identity. A signed token Shield checks (signature,
        # expiry, revocation, build allowlist) rather than the x-agent-key
        # string it can only take our word for. Possession is not proven on
        # this path — see docs/spec-agent-token-pop.md §9.
        agent_token = metadata.get("agent_token") or proxy_headers.get("x-agent-token", "")
        if agent_token:
            headers["x-agent-token"] = agent_token

        # Delegated user token. This is what lets role binding stay VERIFIED
        # behind LiteLLM: unlike a DPoP proof, a bearer user token is not bound
        # to the HTTP request, so Shield can check its signature against the
        # issuer's JWKS even though we re-originated the call. Requires
        # SHIELD_DELEGATION=optional|required on Shield.
        obo = metadata.get("on_behalf_of") or proxy_headers.get("x-on-behalf-of", "")
        if obo and len(str(obo).encode("utf-8", "ignore")) <= self.MAX_OBO_BYTES:
            headers["x-on-behalf-of"] = str(obo)

        # User role — see _resolve_user_role for why this is not a plain
        # passthrough of the caller's header.
        user_role = self._resolve_user_role(data, user_api_key_dict)
        if user_role:
            headers["x-user-role"] = user_role

        # Tenant ID (if explicitly set)
        tenant_id = proxy_headers.get("x-tenant-id", "")
        if tenant_id:
            headers["x-tenant-id"] = tenant_id

        # Prove the hop. Shield's strict_proxy mode accepts a self-asserted
        # role only from a peer that presents this secret.
        if self.proxy_token:
            headers["x-shield-proxy-token"] = self.proxy_token

        return headers

    # ------------------------------------------------------------------
    # Input guardrail — pre_call
    # ------------------------------------------------------------------

    async def async_pre_call_hook(self, user_api_key_dict: UserAPIKeyAuth, cache: DualCache, data: dict, call_type):
        """Input guardrail — checks user message text via Shield."""
        try:
            messages = data.get("messages", [])
            user_msgs = [
                msg.get("content", "")
                for msg in messages
                if msg.get("role") == "user" and isinstance(msg.get("content"), str)
            ]
            last_k = user_msgs[-self.last_k_messages:]
            user_message = "\n".join(last_k) if last_k else None

            if not user_message:
                return data

            # Forward tenant/agent headers to Shield
            shield_headers = self._extract_shield_headers(data, user_api_key_dict)

            response = await self.client.post(
                f"{self.api_base}/guardrails/input",
                json={"message": user_message},
                headers=shield_headers,
            )

            if response.status_code == 200:
                result = response.json()
                if not result.get("safe", False):
                    blocked = result.get("guardrail_results", [])
                    names = [g.get("guardrail", "?") for g in blocked if not g.get("passed", True)]
                    msgs = [g.get("message", "blocked") for g in blocked if not g.get("passed", True)]
                    message = (
                        f"Your request was blocked by Votal guardrails. "
                        f"Triggered guardrails: {', '.join(names)}. "
                        f"Reason: {'; '.join(msgs)}"
                    )
                    self.raise_passthrough_exception(
                        violation_message=message,
                        request_data=data,
                        detection_info=result,
                    )
            else:
                if self.block_on_failure:
                    self.raise_passthrough_exception(
                        violation_message="Guardrail check failed",
                        request_data=data,
                        detection_info={"error": response.status_code},
                    )

            return data

        except Exception as e:
            if "passthrough" in str(type(e).__name__).lower() or "guardrail" in str(type(e).__name__).lower():
                raise
            print(f"[VOTAL] Exception: {e}")
            if self.block_on_failure:
                raise
            return data

    # ------------------------------------------------------------------
    # Output guardrail + tool RBAC + data policies — post_call (non-streaming)
    # ------------------------------------------------------------------

    async def async_post_call_success_hook(self, data: dict, user_api_key_dict: UserAPIKeyAuth, response):
        """Output guardrail + tool call RBAC + data policy enforcement.

        Uses /guardrails/output with full tool context so Shield handles
        everything in one call per tool:
          1. Role-based tool authorization (RBAC)
          2. Data policy sanitization (regex + AI reasoning)
          3. Standard output guardrails (PII, bias, tone, etc.)
        """
        try:
            content = None
            tool_calls = None

            if hasattr(response, "choices") and response.choices:
                choice = response.choices[0]
                if hasattr(choice, "message"):
                    msg = choice.message
                    if hasattr(msg, "content"):
                        content = msg.content
                    if hasattr(msg, "tool_calls") and msg.tool_calls:
                        tool_calls = msg.tool_calls

            # Forward tenant/agent headers to Shield
            shield_headers = self._extract_shield_headers(data, user_api_key_dict)
            metadata = data.get("metadata", {}) or {}
            proxy_headers = data.get("proxy_server_request", {}).get("headers", {})
            agent_key = metadata.get("agent_key") or proxy_headers.get("x-agent-key", "")
            user_role = metadata.get("user_role") or proxy_headers.get("x-user-role", "")

            # --- Step 1: Output guardrails on text (no tool context) ---
            if content:
                result_resp = await self.client.post(
                    f"{self.api_base}/guardrails/output",
                    json={"output": content},
                    headers=shield_headers,
                )

                if result_resp.status_code == 200:
                    result = result_resp.json()
                    if not result.get("safe", True):
                        blocked = result.get("guardrail_results", [])
                        names = [g.get("guardrail", "?") for g in blocked if not g.get("passed", True)]
                        msgs = [g.get("message", "blocked") for g in blocked if not g.get("passed", True)]
                        message = (
                            f"The model response was blocked by Votal guardrails. "
                            f"Triggered: {', '.join(names)}. "
                            f"Reason: {'; '.join(msgs)}"
                        )
                        self.raise_passthrough_exception(
                            violation_message=message,
                            request_data=data,
                            detection_info=result,
                        )

            # --- Step 2: Tool call RBAC + data policies via /guardrails/output ---
            if tool_calls:
                tool_results = await self._check_tool_calls(
                    tool_calls, agent_key, user_role, shield_headers,
                )

                has_blocked = any(not t["rbac"]["allowed"] for t in tool_results)

                # Inject tool RBAC results into response metadata
                if not hasattr(response, "_hidden_params"):
                    response._hidden_params = {}
                if not isinstance(response._hidden_params, dict):
                    response._hidden_params = {}

                response._hidden_params["tool_rbac"] = {
                    "tool_calls": tool_results,
                    "has_blocked_tools": has_blocked,
                    "all_tools_allowed": not has_blocked,
                }

                if has_blocked:
                    blocked_tools = [t["tool_name"] for t in tool_results if not t["rbac"]["allowed"]]
                    blocked_reasons = [t["rbac"].get("message", "") for t in tool_results if not t["rbac"]["allowed"]]
                    print(f"[VOTAL] Blocked tools: {blocked_tools} — {blocked_reasons}")
                    if self.enforce_tool_rbac:
                        # Returning the response here would hand the caller a tool
                        # call Shield just denied, leaving enforcement to a client
                        # that may never inspect _hidden_params. Block it, the way
                        # the output guardrail above already does.
                        reasons = "; ".join(r for r in blocked_reasons if r) or "denied by policy"
                        self.raise_passthrough_exception(
                            violation_message=(
                                f"The requested tool call was blocked by Votal guardrails. "
                                f"Blocked tools: {', '.join(blocked_tools)}. "
                                f"Reason: {reasons}"
                            ),
                            request_data=data,
                            detection_info=response._hidden_params["tool_rbac"],
                        )

            return response

        except Exception as e:
            if "passthrough" in str(type(e).__name__).lower() or "guardrail" in str(type(e).__name__).lower():
                raise
            print(f"[VOTAL] Output exception: {e}")
            if self.block_on_failure:
                raise
            return response

    async def _check_tool_calls(self, tool_calls, agent_key: str, user_role: str, shield_headers: dict = None) -> list[dict]:
        """Check each tool call via /guardrails/output with full context.

        This single call gives us:
          - Role-based tool authorization (RBAC)
          - Data policy sanitization (regex + AI)
          - Standard output guardrails on tool args
        """
        results = []
        for tc in tool_calls:
            tool_name = tc.function.name if hasattr(tc, "function") else ""
            tool_args_raw = tc.function.arguments if hasattr(tc, "function") else "{}"
            tool_call_id = tc.id if hasattr(tc, "id") else ""

            try:
                tool_args = json.loads(tool_args_raw) if isinstance(tool_args_raw, str) else tool_args_raw or {}
            except json.JSONDecodeError:
                tool_args = {"_raw": tool_args_raw}

            rbac = {"allowed": True, "action": "pass", "message": ""}
            sanitization = None

            try:
                # Call /guardrails/output with full tool context
                # Shield runs: tool authorization → data policy sanitization → output guardrails
                resp = await self.client.post(
                    f"{self.api_base}/guardrails/output",
                    json={
                        "output": json.dumps(tool_args),
                        "context": {
                            "tool_name": tool_name,
                            "tool_input": tool_args,
                            "agent_id": agent_key,
                            "user_role": user_role,
                            "stage": "input",  # checking tool args before execution
                        },
                    },
                    headers=shield_headers or {},
                )
                if resp.status_code == 200:
                    check = resp.json()
                    is_safe = check.get("safe", True)
                    rbac = {
                        "allowed": is_safe,
                        "action": check.get("action", "pass"),
                        "message": "",
                    }
                    if not is_safe:
                        for gr in check.get("guardrail_results", []):
                            if not gr.get("passed", True):
                                rbac["message"] = gr.get("message", "denied by policy")
                                break
                    # Capture sanitization metadata if present
                    if check.get("sanitization"):
                        sanitization = check["sanitization"]
                else:
                    print(f"[VOTAL] guardrails/output tool check failed for {tool_name}: {resp.status_code}")
            except Exception as e:
                print(f"[VOTAL] guardrails/output tool check error for {tool_name}: {e}")

            result = {
                "tool_call_id": tool_call_id,
                "tool_name": tool_name,
                "arguments": tool_args,
                "rbac": rbac,
            }
            if sanitization:
                result["sanitization"] = sanitization
            results.append(result)

        return results

    # ------------------------------------------------------------------
    # Streaming helpers
    # ------------------------------------------------------------------

    async def _is_output_safe(self, content: str, request_data: dict, shield_headers: dict = None):
        """Call Votal output endpoint. Returns (safe: bool, result: dict)."""
        try:
            resp = await self.client.post(
                f"{self.api_base}/guardrails/output",
                json={"output": content},
                headers=shield_headers or {},
            )
            if resp.status_code != 200:
                return (not self.block_on_failure), {"error": resp.status_code}
            result = resp.json()
            return bool(result.get("safe", True)), result
        except Exception as e:
            return (not self.block_on_failure), {"error": str(e)}

    # ------------------------------------------------------------------
    # Streaming output guardrail
    # ------------------------------------------------------------------

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response,
        request_data: dict,
    ):
        """Output guardrail for streaming responses.

        Checks text content periodically during stream + final check.
        Tool calls in streaming are accumulated and checked at stream end.
        """
        accumulated_text = []
        accumulated_tool_calls = {}  # index -> {id, name, arguments}
        chunks_since_check = 0
        shield_headers = self._extract_shield_headers(request_data, user_api_key_dict)

        async for chunk in response:
            delta_text = None
            try:
                if hasattr(chunk, "choices") and chunk.choices:
                    delta = getattr(chunk.choices[0], "delta", None)
                    if delta is not None:
                        # Accumulate text
                        delta_text = getattr(delta, "content", None)

                        # Accumulate tool_call deltas
                        delta_tool_calls = getattr(delta, "tool_calls", None)
                        if delta_tool_calls:
                            for dtc in delta_tool_calls:
                                idx = dtc.index if hasattr(dtc, "index") else 0
                                if idx not in accumulated_tool_calls:
                                    accumulated_tool_calls[idx] = {
                                        "id": getattr(dtc, "id", "") or "",
                                        "name": "",
                                        "arguments": "",
                                    }
                                if hasattr(dtc, "id") and dtc.id:
                                    accumulated_tool_calls[idx]["id"] = dtc.id
                                if hasattr(dtc, "function") and dtc.function:
                                    if hasattr(dtc.function, "name") and dtc.function.name:
                                        accumulated_tool_calls[idx]["name"] += dtc.function.name
                                    if hasattr(dtc.function, "arguments") and dtc.function.arguments:
                                        accumulated_tool_calls[idx]["arguments"] += dtc.function.arguments
            except Exception:
                delta_text = None

            if delta_text:
                accumulated_text.append(delta_text)
                chunks_since_check += 1

                # Periodic text check during stream
                if chunks_since_check >= self.check_every_n_chunks:
                    chunks_since_check = 0
                    full_text = "".join(accumulated_text)
                    safe, result = await self._is_output_safe(full_text, request_data, shield_headers)
                    if not safe:
                        blocked = result.get("guardrail_results", []) if isinstance(result, dict) else []
                        names = [g.get("guardrail", "?") for g in blocked if not g.get("passed", True)]
                        msgs = [g.get("message", "blocked") for g in blocked if not g.get("passed", True)]
                        message = (
                            "Streaming response blocked mid-stream by Votal guardrails. "
                            f"Triggered: {', '.join(names) or 'unknown'}. "
                            f"Reason: {'; '.join(msgs) or 'n/a'}"
                        )
                        self.raise_passthrough_exception(
                            violation_message=message,
                            request_data=request_data,
                            detection_info={"phase": "mid_stream", **(result or {})},
                        )

            yield chunk

        # --- Final text check ---
        full_text = "".join(accumulated_text)
        if full_text:
            safe, result = await self._is_output_safe(full_text, request_data)
            if not safe:
                blocked = result.get("guardrail_results", []) if isinstance(result, dict) else []
                names = [g.get("guardrail", "?") for g in blocked if not g.get("passed", True)]
                msgs = [g.get("message", "blocked") for g in blocked if not g.get("passed", True)]
                message = (
                    "Streaming response failed final Votal check. "
                    f"Triggered: {', '.join(names) or 'unknown'}. "
                    f"Reason: {'; '.join(msgs) or 'n/a'}"
                )
                self.raise_passthrough_exception(
                    violation_message=message,
                    request_data=request_data,
                    detection_info={"phase": "final", **(result or {})},
                )

        # --- Final tool call RBAC check (assembled from stream deltas) ---
        if accumulated_tool_calls:
            agent_key = (request_data.get("metadata", {}) or {}).get("agent_key", "")
            user_role = (request_data.get("metadata", {}) or {}).get("user_role", "")
            if not agent_key:
                agent_key = request_data.get("proxy_server_request", {}).get("headers", {}).get("x-agent-key", "")
            if not user_role:
                user_role = request_data.get("proxy_server_request", {}).get("headers", {}).get("x-user-role", "")

            for idx, tc_data in accumulated_tool_calls.items():
                tool_name = tc_data["name"]
                try:
                    tool_args = json.loads(tc_data["arguments"]) if tc_data["arguments"] else {}
                except json.JSONDecodeError:
                    tool_args = {"_raw": tc_data["arguments"]}

                try:
                    resp = await self.client.post(
                        f"{self.api_base}/v1/shield/tool/check",
                        json={
                            "agent_key": agent_key,
                            "tool_name": tool_name,
                            "user_role": user_role,
                            "tool_params": tool_args,
                        },
                        headers=shield_headers,
                    )
                    if resp.status_code == 200:
                        check = resp.json()
                        if not check.get("allowed", True):
                            reason = ""
                            for gr in check.get("guardrail_results", []):
                                if not gr.get("passed", True):
                                    reason = gr.get("message", "denied")
                                    break
                            print(f"[VOTAL] Stream tool blocked: {tool_name} — {reason}")
                            # NOTE: chunks already sent. Log for audit, client must
                            # still call /v1/shield/tool/check before executing.
                except Exception as e:
                    print(f"[VOTAL] Stream tool/check error for {tool_name}: {e}")
