"""Rollout kits as the tenant manages them: generate, list, revoke.

Spec: docs/specs/device-rollout-kit.md (approved), task 3. The generator itself
(core/dlp/rollout_kit.py) is pure; this module mints the kit's token, keeps the
tenant root current, and records the kit.

  device_kit:{tenant_id}:{kit_id}   what the kit is (never the token), until the
                                    token expires + 30 days

Order in create_kit: validate everything, reissue the root if needed, mint the
token, build the zip, record the kit. A request that is going to fail does so
before a token exists, and a build that fails revokes the token it minted.
"""

from __future__ import annotations

import os
import re
import secrets
import time
from typing import Optional

from core.dlp import devices as dv
from core.dlp import rollout_kit as rk

KIT_TTL_EXTRA_S = 30 * 86400
DEFAULT_RELEASE_BASE = "https://github.com/sundi133/llm-shield/releases/download"
#: The agent version kits pin by default: the device agent's own
#: packages/votal-device-agent/votal_device_agent/_version.py (a test holds
#: them equal; the server images do not ship the agent package).
DEFAULT_AGENT_VERSION = "0.1.0"
BODY_KEYS = ("fleet", "mdm", "platforms", "include_proxy", "extension_ids", "expires_in_days",
             "uses", "revoke_previous")


class KitAPIError(Exception):
    def __init__(self, message: str, status: int = 400, errors: Optional[list] = None):
        super().__init__(message)
        self.status, self.errors = status, errors or []


def settings() -> dict:
    """Server-side kit settings (env), shown to the portal as defaults."""
    ids = [i.strip() for i in os.environ.get("SHIELD_BROWSER_EXTENSION_IDS", "").split(",")
           if i.strip()]
    return {"agent_version": os.environ.get("SHIELD_DEVICE_AGENT_VERSION", "").strip()
            or DEFAULT_AGENT_VERSION,
            "release_base": os.environ.get("SHIELD_DEVICE_AGENT_RELEASE_BASE", "").strip()
            or DEFAULT_RELEASE_BASE,
            "apple_team_id": os.environ.get("SHIELD_APPLE_TEAM_ID", "").strip(),
            "windows_signer": os.environ.get("SHIELD_WINDOWS_SIGNER", "Votal").strip(),
            "extension_ids": ids}


def _key(tenant_id: str, kit_id: str) -> str:
    return f"device_kit:{tenant_id}:{kit_id}"


def _scan(prefix: str) -> list[str]:
    from storage.tenant_store import _fallback_store
    r = dv._redis()
    if r is None:
        return [k for k in list(_fallback_store) if k.startswith(prefix)]
    return [dv._decode(k) for k in r.scan_iter(match=prefix + "*")]


def parse_body(body: dict) -> dict:
    """The kit request, with defaults; every problem at once."""
    if not isinstance(body, dict):
        raise KitAPIError("body: an object")
    errors = [f"{k}: unknown field" for k in body if k not in BODY_KEYS]
    mdm = body.get("mdm")
    if mdm not in rk.MDMS:
        errors.append(f"mdm: one of {', '.join(rk.MDMS)}")
    platforms = body.get("platforms") or list(rk.DEFAULT_PLATFORMS.get(mdm, ()))
    if not isinstance(platforms, list) or not all(p in ("macos", "windows") for p in platforms):
        errors.append("platforms: a list of macos and/or windows")
        platforms = []
    ids = body.get("extension_ids")
    if ids is None:
        ids = settings()["extension_ids"]
    if not isinstance(ids, list):
        errors.append("extension_ids: a list")
        ids = []
    out = {"fleet": body.get("fleet"), "mdm": mdm, "platforms": tuple(dict.fromkeys(platforms)),
           "include_proxy": body.get("include_proxy", True), "extension_ids": ids,
           "expires_in_days": body.get("expires_in_days", 180), "uses": body.get("uses", 5000),
           "revoke_previous": body.get("revoke_previous", False)}
    for k in ("include_proxy", "revoke_previous"):
        if not isinstance(out[k], bool):
            errors.append(f"{k}: true or false")
    for k, hi in (("expires_in_days", dv.KIT_MAX_DAYS), ("uses", dv.KIT_MAX_USES)):
        v = out[k]
        if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= hi:
            errors.append(f"{k}: an integer from 1 to {hi}")
    if errors:
        raise KitAPIError("invalid rollout kit request", errors=errors)
    return out


def create_kit(tenant_id: str, body: dict, *, shield_url: str, actor: str) -> dict:
    """{zip, record, root_reissued}. Raises KitAPIError."""
    from core.dlp import device_ca, device_store
    from core.embodied import bundle as edge_bundle
    from storage.tenant_store import kv_set

    req_in = parse_body(body)
    hosts = device_store.get_policy(tenant_id)["ai_hosts"]
    pinned = edge_bundle.public_key_hex()
    if pinned is None:
        raise KitAPIError("bundle signing is not configured on this Shield "
                          "(SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY): laptops could verify nothing",
                          503)
    s = settings()
    kit_id = "kit_" + secrets.token_hex(8)
    root, reissued = {"pem": "", "fingerprint_sha256": ""}, False
    kit = rk.KitRequest(
        tenant_id=tenant_id, fleet=req_in["fleet"] or "", mdm=req_in["mdm"], kit_id=kit_id,
        token=f"vde.{tenant_id}." + "x" * 43, token_id="0" * 16, shield_url=shield_url,
        pinned_public_key=pinned, agent_version=s["agent_version"],
        release_base=s["release_base"], ai_hosts=list(hosts),
        platforms=req_in["platforms"], include_proxy=req_in["include_proxy"],
        extension_ids=req_in["extension_ids"], apple_team_id=s["apple_team_id"],
        windows_signer=s["windows_signer"], root_pem="-----BEGIN CERTIFICATE-----" if
        "macos" in req_in["platforms"] else "")
    try:
        rk.validate(kit)                          # before any token or root is touched
    except rk.KitError as e:
        raise KitAPIError("invalid rollout kit request", errors=e.errors)
    if "macos" in kit.resolved_platforms():
        try:
            root = device_ca.get_root(tenant_id, hosts)
            if not root["covers_policy"]:
                # The kit is about to replace the profile anyway: give it a root
                # that covers every AI host in the policy.
                root = {**device_ca.issue_root(tenant_id, hosts), "covers_policy": True}
                reissued = True
        except device_ca.DeviceCAError as e:
            raise KitAPIError(str(e), e.status)
        kit.root_pem, kit.root_fingerprint = root["pem"], root["fingerprint_sha256"]

    try:
        token, trec = dv.create_enrollment_token(
            tenant_id, kit.fleet, uses=req_in["uses"], expires_in_days=req_in["expires_in_days"],
            created_by=actor, kind="kit", kit_id=kit_id, mdm=kit.mdm)
    except dv.DeviceError as e:
        raise KitAPIError(str(e), e.status)
    kit.token, kit.token_id = token, trec["token_id"]
    kit.created_at, kit.expires_at, kit.uses = trec["created_at"], trec["expires_at"], trec["uses"]
    try:
        data = rk.build(kit)
    except Exception:
        dv.revoke_enrollment_token(tenant_id, kit.token_id)
        raise
    record = {**rk.manifest(kit), "uses": kit.uses, "created_by": actor[:200],
              "revoked_at": None, "root_reissued": reissued,
              # Kits made in the same second still list newest first.
              "created_ms": int(time.time() * 1000)}
    kv_set(_key(tenant_id, kit_id), record,
           ttl=max(60, kit.expires_at - int(time.time()) + KIT_TTL_EXTRA_S))
    revoked = []
    if req_in["revoke_previous"]:
        for other in list_kits(tenant_id):
            if (other["kit_id"] != kit_id and other["fleet"] == kit.fleet
                    and other["mdm"] == kit.mdm and other["status"] == "active"
                    and other["created_at"] <= kit.created_at):
                revoke_kit(tenant_id, other["kit_id"])
                revoked.append(other["kit_id"])
    return {"zip": data, "record": record, "root_reissued": reissued, "revoked": revoked}


def list_kits(tenant_id: str) -> list[dict]:
    """Every kit (never a token): status, uses left, and why it is stale."""
    from core.dlp import device_ca, device_store
    from storage.tenant_store import kv_get
    tokens = {t["token_id"]: t for t in dv.list_enrollment_tokens(tenant_id)}
    hosts = device_store.get_policy(tenant_id)["ai_hosts"]
    try:
        root = device_ca.get_root(tenant_id, hosts)
    except device_ca.DeviceCAError:
        root = None
    current = settings()["agent_version"]
    now = int(time.time())
    out = []
    for k in _scan(f"device_kit:{tenant_id}:"):
        rec = kv_get(k)
        if not isinstance(rec, dict):
            continue
        tok = tokens.get(rec.get("token_id"))
        if rec.get("revoked_at"):
            status = "revoked"
        elif rec.get("expires_at", 0) <= now:
            status = "expired"
        elif tok is None:
            status = "revoked"                    # revoked from the tokens list
        elif tok["uses_left"] <= 0:
            status = "exhausted"
        else:
            status = "active"
        stale = []
        if root is not None and "macos" in rec.get("platforms", []):
            if rec.get("root_fingerprint_sha256") != root["fingerprint_sha256"]:
                stale.append("the tenant root was reissued: upload this fleet's profile from a "
                             "new kit")
            if not root["covers_policy"]:
                stale.append("the policy has AI hosts no kit's root covers: "
                             + ", ".join(root["missing_hosts"]))
        if _version(rec.get("agent_version", "0")) < _version(current):
            stale.append(f"agent {rec.get('agent_version')} is older than {current}")
        # Laptops left only means something while the token can still enroll.
        out.append({**rec, "status": status,
                    "uses_left": tok["uses_left"] if tok and status in ("active", "exhausted")
                    else None, "stale": stale})
    return sorted(out, key=lambda r: (r.get("created_ms") or r.get("created_at", 0) * 1000),
                  reverse=True)


def _version(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.-]", str(v))[:3])


def revoke_kit(tenant_id: str, kit_id: str) -> Optional[dict]:
    """Stop the kit's token enrolling anything more. Enrolled laptops keep working."""
    from storage.tenant_store import kv_get, kv_set
    if not re.match(r"^kit_[0-9a-f]{16}$", kit_id or ""):
        return None
    key = _key(tenant_id, kit_id)
    rec = kv_get(key)
    if not isinstance(rec, dict):
        return None
    dv.revoke_enrollment_token(tenant_id, rec.get("token_id", ""))
    if not rec.get("revoked_at"):
        rec["revoked_at"] = int(time.time())
        kv_set(key, rec, ttl=max(60, int(rec.get("expires_at", 0)) - int(time.time())
                                 + KIT_TTL_EXTRA_S))
    return rec
