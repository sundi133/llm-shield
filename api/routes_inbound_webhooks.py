"""Webhook inbox: receive a partner's webhooks and record each one exactly
(docs/specs/webhook-inbox.md). Admin plane only; mounted by admin_app.py.

Receiver, unauthenticated (the token is the address, the signature the proof):
  POST|PUT|PATCH /v1/inbound/{token}   record the delivery
  GET            /v1/inbound/{token}   answer, record nothing

Tenant (portal session or tenant key; writes need a settings key or a session):
  /v1/tenant/me/inboxes[...]

Operator (behind the /v1/admin gate): platform inboxes, and read-only access
to any tenant's with ?owner=<tenant> (owner=all lists every owner):
  /v1/admin/inboxes[...]

Nothing here acts on a delivery or calls out because of one. Credential
headers and secret-looking JSON fields are masked before anything is stored.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import zlib
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from storage import webhook_inbox_store as store

router = APIRouter(tags=["webhook-inbox"])

MAX_BODY = 1024 * 1024
BODY_KEEP = 64 * 1024
HEADER_VALUE_CAP = 8 * 1024

_MASKED_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie",
                   "x-api-key", "x-admin-key", "x-votal-local-secret"}
_MASKED_HEADER_PARTS = ("secret", "token", "password", "apikey", "api-key", "credential")
# Body keys, compared with case and punctuation removed. Exact names, plus
# suffixes, so "token_id" and "api_key_id" (what a lifecycle event is about)
# stay readable while "api_key" and "client_secret" do not.
_MASKED_KEYS = {"secret", "token", "password", "passwd", "apikey", "key", "privatekey",
                "clientsecret", "accesstoken", "refreshtoken", "plaintextkey"}
_MASKED_KEY_SUFFIXES = ("secret", "password", "apikey", "privatekey", "accesstoken",
                        "refreshtoken")
_EVENT_FIELDS = ("type", "event", "event_type", "eventType", "action")
_EVENT_HEADERS = ("x-event-type", "x-webhook-event")


def _enabled() -> bool:
    return (os.environ.get("SHIELD_WEBHOOK_INBOX", "on") or "on").strip().lower() \
        not in ("off", "0", "false", "no")


def mask(value: str) -> str:
    """First 4 characters, then the length: enough to tell two values apart."""
    value = value if isinstance(value, str) else str(value)
    return f"{value[:4]}…({len(value)})"


def _header_is_secret(name: str, signature_header: str) -> bool:
    n = name.lower()
    if signature_header and n == signature_header.lower():
        return False
    return n in _MASKED_HEADERS or any(p in n for p in _MASKED_HEADER_PARTS)


def _key_is_secret(key: str) -> bool:
    k = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return k in _MASKED_KEYS or k.endswith(_MASKED_KEY_SUFFIXES)


def mask_json(obj, path: str = "", found: Optional[list] = None):
    """(masked copy, dotted paths of what was masked)."""
    found = [] if found is None else found
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            if _key_is_secret(k) and isinstance(v, (str, int, float)) and v != "":
                out[k] = mask(str(v))
                found.append(p)
            else:
                out[k] = mask_json(v, p, found)[0]
        return out, found
    if isinstance(obj, list):
        return [mask_json(v, f"{path}[{i}]", found)[0] for i, v in enumerate(obj)], found
    return obj, found


def _event_name(parsed, headers: list) -> str:
    if isinstance(parsed, dict):
        for f in _EVENT_FIELDS:
            v = parsed.get(f)
            if isinstance(v, str) and v.strip():
                return v.strip()[:200]
    for name, value in headers:
        if name in _EVENT_HEADERS and value.strip():
            return value.strip()[:200]
    return ""


def _digest(scheme: str, secret: str, body: bytes) -> bytes:
    algo = hashlib.sha1 if scheme == "hmac-sha1" else hashlib.sha256
    return hmac.new(secret.encode("utf-8"), body, algo).digest()


def _decode_sig(value: str, encoding: str) -> Optional[bytes]:
    try:
        if encoding == "base64":
            return base64.b64decode(value, validate=True)
        return bytes.fromhex(value)
    except (ValueError, binascii.Error):
        return None


def check_signature(signing: dict, raw_headers: list, body: bytes) -> dict:
    """{"result": verified|failed|absent|not_configured, "header", "detail"}."""
    scheme = signing.get("scheme") or "none"
    secret = signing.get("secret") or ""
    if scheme == "none":
        return {"result": "not_configured", "header": "", "detail": _guess(secret, raw_headers, body)}
    header = (signing.get("header") or "").lower()
    values = [v for n, v in raw_headers if n == header]
    if not header or not values:
        return {"result": "absent", "header": header,
                "detail": f"no {header or 'signature'} header in the request"}
    value = values[0].strip()
    prefix = signing.get("prefix") or ""
    if prefix and value.startswith(prefix):
        value = value[len(prefix):]
    given = _decode_sig(value, signing.get("encoding") or "hex")
    if given is None:
        return {"result": "failed", "header": header,
                "detail": f"the header is not {signing.get('encoding') or 'hex'} after removing the prefix"}
    if hmac.compare_digest(given, _digest(scheme, secret, body)):
        return {"result": "verified", "header": header, "detail": f"{scheme} over the raw body"}
    return {"result": "failed", "header": header,
            "detail": f"{scheme} of the body with this inbox's secret does not match"}


def _guess(secret: str, raw_headers: list, body: bytes) -> str:
    """With no scheme chosen yet, say which settings would verify, if any."""
    if not secret:
        return ""
    for name, value in raw_headers:
        if "sig" not in name:
            continue
        v = value.strip()
        for scheme in ("hmac-sha256", "hmac-sha1"):
            want = _digest(scheme, secret, body)
            for part in [v] + [p.strip() for p in re.split(r"[,;]", v)]:
                m = re.match(r"^([A-Za-z0-9_-]+=)(.+)$", part)
                candidates = [("", part)] + ([(m.group(1), m.group(2))] if m else [])
                for prefix, sig in candidates:
                    for enc in ("hex", "base64"):
                        got = _decode_sig(sig, enc)
                        if got is not None and hmac.compare_digest(got, want):
                            return (f"would verify as {scheme}, header {name}, "
                                    f"prefix '{prefix}', {enc}")
    return "no header verifies with this inbox's secret yet"


def _body_text(raw: bytes, content_encoding: str) -> tuple[bytes, bool]:
    """The body as sent, decompressed when it was gzip or deflate."""
    enc = (content_encoding or "").lower().strip()
    if enc not in ("gzip", "deflate", "x-gzip"):
        return raw, False
    try:
        d = zlib.decompressobj(zlib.MAX_WBITS | 32 if enc != "deflate" else zlib.MAX_WBITS)
        out = d.decompress(raw, MAX_BODY)
        return out, True
    except zlib.error:
        try:
            return zlib.decompressobj(-zlib.MAX_WBITS).decompress(raw, MAX_BODY), True
        except zlib.error:
            return raw, False


def build_delivery(*, method: str, path: str, query: dict, raw_headers: list,
                   body: bytes, source_ip: str, signing: dict) -> dict:
    """The record of one request, masked. Pure: tested without a server."""
    sig_header = (signing.get("header") or "").lower()
    headers = []
    for name, value in raw_headers:
        value = value[:HEADER_VALUE_CAP]
        headers.append([name, mask(value) if _header_is_secret(name, sig_header) else value])
    hmap = {n: v for n, v in reversed(raw_headers)}
    content_type = hmap.get("content-type", "")
    text, decoded = _body_text(body, hmap.get("content-encoding", ""))
    rec = {
        "id": "dlv_" + secrets.token_hex(8),
        "received_at": time.time(),
        "method": method,
        "path": path,
        "query": {k: (mask(v) if _key_is_secret(k) else v) for k, v in query.items()},
        "source_ip": source_ip,
        "user_agent": hmap.get("user-agent", ""),
        "headers": headers,
        "content_type": content_type,
        "size": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_decompressed": decoded,
        "body_masked_fields": [],
        "body_truncated": False,
        "binary": False,
    }
    parsed = None
    try:
        s = text.decode("utf-8")
    except UnicodeDecodeError:
        s = None
    if s is None:
        rec["binary"] = True
        keep = text[: (BODY_KEEP * 3) // 4]
        rec["body"] = base64.b64encode(keep).decode()
        rec["body_truncated"] = len(keep) < len(text)
    else:
        looks_json = "json" in content_type.lower() or s.lstrip()[:1] in ("{", "[")
        if looks_json and s.strip():
            try:
                parsed = json.loads(s)
            except ValueError as e:
                rec["body_json_error"] = str(e)[:200]
        if parsed is not None:
            masked, found = mask_json(parsed)
            rec["body_masked_fields"] = found
            if found:
                # Keep the sender's formatting: replace each masked value in
                # the text rather than re-serialising the document.
                s = _replace_masked(s, parsed, masked)
        rec["body_truncated"] = len(s) > BODY_KEEP
        rec["body"] = s[:BODY_KEEP]
    rec["event"] = _event_name(parsed, raw_headers)
    rec["signature"] = check_signature(signing, raw_headers, body)
    return rec


def _replace_masked(text: str, original, masked) -> str:
    pairs: list = []

    def walk(a, b):
        if isinstance(a, dict) and isinstance(b, dict):
            for k in a:
                walk(a[k], b.get(k))
        elif isinstance(a, list) and isinstance(b, list):
            for x, y in zip(a, b):
                walk(x, y)
        elif a != b:
            pairs.append((a, b))
    walk(original, masked)
    for a, b in pairs:
        for enc in {json.dumps(a), json.dumps(a, ensure_ascii=False)}:
            text = text.replace(enc, json.dumps(b, ensure_ascii=False))
    return text


def _masked_path(token: str) -> str:
    return f"/v1/inbound/{token[:4]}…"


def _client_ip(request: Request) -> str:
    try:
        from core.auth import _client_ip as ip
        return ip(request)
    except Exception:       # noqa: BLE001
        return request.client.host if request.client else ""


def _unavailable() -> JSONResponse:
    return JSONResponse(status_code=503, content={"error": "temporarily unavailable; retry"},
                        headers={"Retry-After": "30"})


def _not_found() -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": "Not Found"})


def _resolve(token: str) -> Optional[dict]:
    """The inbox for a token, if it is live and its owner still exists.
    Raises on a store error."""
    inbox = store.resolve_token(token)
    if not inbox:
        return None
    owner = inbox.get("owner")
    if owner != store.PLATFORM:
        from storage.tenant_store import get_tenant
        if not get_tenant(owner):
            return None
    return inbox


@router.get("/v1/inbound/{token}")
async def inbound_check(token: str):
    if not _enabled():
        return _not_found()
    try:
        inbox = _resolve(token)
    except Exception:       # noqa: BLE001
        return _unavailable()
    return {"ok": True} if inbox else _not_found()


@router.api_route("/v1/inbound/{token}", methods=["POST", "PUT", "PATCH"])
async def inbound_receive(token: str, request: Request):
    if not _enabled():
        return _not_found()
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > MAX_BODY:
        return JSONResponse(status_code=413, content={"error": "body over 1 MB"})
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY:
            return JSONResponse(status_code=413, content={"error": "body over 1 MB"})
    try:
        inbox = _resolve(token)
        if not inbox:
            store.note_old_token(token)
            return _not_found()
        if not inbox.get("enabled", True):
            return JSONResponse(status_code=410, content={"error": "this inbox is disabled"})
        if store.rate_hit(inbox["inbox_id"]) > store.RATE_PER_MINUTE:
            return JSONResponse(status_code=429, content={"error": "over 60 deliveries a minute"},
                                headers={"Retry-After": "60"})
        raw_headers = [(k.decode("latin-1").lower(), v.decode("latin-1"))
                       for k, v in request.headers.raw]
        rec = build_delivery(method=request.method, path=_masked_path(token),
                             query=dict(request.query_params), raw_headers=raw_headers,
                             body=body, source_ip=_client_ip(request),
                             signing=inbox.get("signing") or {})
        rejected = bool(inbox.get("require_signature")) and \
            rec["signature"]["result"] != "verified"
        rec["rejected"] = rejected
        store.record_delivery(inbox, rec)
    except Exception:       # noqa: BLE001 - the partner retries a 503
        return _unavailable()
    if rejected:
        return JSONResponse(status_code=401, content={"error": "signature did not verify",
                                                      "id": rec["id"]})
    return {"received": True, "id": rec["id"]}


# ── the inbox API, shared by the tenant and the operator ─────────────


def _base_url(request: Request) -> str:
    return (os.environ.get("SHIELD_PORTAL_BASE_URL", "") or "").rstrip("/") \
        or str(request.base_url).rstrip("/")


def public(inbox: dict) -> dict:
    """An inbox as the API shows it: never the token's hash, never the secret."""
    signing = dict(inbox.get("signing") or {})
    signing["secret_set"] = bool(signing.pop("secret", ""))
    out = {k: v for k, v in inbox.items() if k not in ("token_hash", "signing")}
    out["signing"] = signing
    try:
        out.update(store.stats(inbox["inbox_id"]))
    except Exception:       # noqa: BLE001
        pass
    return out


def summary(d: dict) -> dict:
    return {k: d.get(k) for k in ("id", "received_at", "method", "size", "content_type",
                                  "source_ip", "event", "rejected")} | \
        {"signature": (d.get("signature") or {}).get("result")}


def _str(body: dict, key: str, limit: int) -> Optional[str]:
    v = body.get(key)
    if v is None:
        return None
    if not isinstance(v, str):
        raise HTTPException(status_code=422, detail=f"{key}: a string")
    v = v.strip()
    if len(v) > limit:
        raise HTTPException(status_code=422, detail=f"{key}: at most {limit} characters")
    return v


def _validate_changes(body: dict) -> dict:
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="a JSON object")
    out: dict = {}
    for key, limit in (("name", 100), ("source", 100)):
        v = _str(body, key, limit)
        if v is not None:
            if key == "name" and not v:
                raise HTTPException(status_code=422, detail="name: required")
            out[key] = v
    for key in ("enabled", "require_signature"):
        if key in body:
            if not isinstance(body[key], bool):
                raise HTTPException(status_code=422, detail=f"{key}: true or false")
            out[key] = body[key]
    if "retention_days" in body:
        v = body["retention_days"]
        if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= store.MAX_RETENTION_DAYS:
            raise HTTPException(status_code=422,
                                detail=f"retention_days: 1 to {store.MAX_RETENTION_DAYS}")
        out["retention_days"] = v
    if "signing" in body:
        s = body["signing"]
        if not isinstance(s, dict):
            raise HTTPException(status_code=422, detail="signing: an object")
        sig: dict = {}
        if "scheme" in s:
            if s["scheme"] not in store.SCHEMES:
                raise HTTPException(status_code=422, detail=f"signing.scheme: one of {', '.join(store.SCHEMES)}")
            sig["scheme"] = s["scheme"]
        if "encoding" in s:
            if s["encoding"] not in store.ENCODINGS:
                raise HTTPException(status_code=422, detail="signing.encoding: hex or base64")
            sig["encoding"] = s["encoding"]
        for key in ("header", "prefix"):
            if key in s:
                v = s[key]
                if not isinstance(v, str) or len(v) > 100 or not re.fullmatch(r"[\x21-\x7e]*", v):
                    raise HTTPException(status_code=422, detail=f"signing.{key}: up to 100 printable characters")
                sig[key] = v.lower() if key == "header" else v
        out["signing"] = sig
    return out


def _create(request: Request, owner: str, body: dict, created_by: str) -> dict:
    body = body if isinstance(body, dict) else {}
    name = _str(body, "name", 100)
    if not name:
        raise HTTPException(status_code=422, detail="name: required")
    source = _str(body, "source", 100) or ""
    try:
        inbox, token, secret = store.create_inbox(owner, name=name, source=source,
                                                  created_by=created_by)
    except store.LimitReached as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {"inbox": public(inbox), "url": f"{_base_url(request)}/v1/inbound/{token}",
            "signing_secret": secret,
            "warning": "The URL and the signing secret are shown once. Store them now."}


def _deliveries(inbox: dict, limit: int, cursor: str) -> dict:
    try:
        offset = int(cursor) if cursor else 0
    except ValueError:
        raise HTTPException(status_code=422, detail="cursor: the next_cursor of a previous page")
    rows, total = store.list_deliveries(inbox["inbox_id"], limit=limit, offset=offset)
    nxt = offset + len(rows)
    return {"inbox_id": inbox["inbox_id"], "deliveries": [summary(d) for d in rows],
            "total": total, "next_cursor": str(nxt) if nxt < total else None}


def _delivery(inbox: dict, delivery_id: str) -> dict:
    d = store.get_delivery(inbox["inbox_id"], delivery_id)
    if not d:
        raise HTTPException(status_code=404, detail="no such delivery")
    return d


def _store_call(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except HTTPException:
        raise
    except Exception:       # noqa: BLE001
        raise HTTPException(status_code=503, detail="the inbox store is unavailable; retry")


# ── tenant routes ────────────────────────────────────────────────────


def _tenant(request: Request) -> str:
    from api.routes_tenant_self import _require_tenant
    return _require_tenant(request)


def _tenant_write(request: Request, tenant_id: str, action: str) -> None:
    from core.auth import require_registry_write
    require_registry_write(request, tenant_id, action)


def _own(tenant_id: str, inbox_id: str) -> dict:
    """The tenant's inbox, or 404: another tenant's inbox and an inbox that
    does not exist get the same answer."""
    inbox = store.get_inbox(inbox_id)
    if not inbox or inbox.get("owner") != tenant_id:
        raise HTTPException(status_code=404, detail="no such inbox")
    return inbox


def _tenant_audit(request: Request, tenant_id: str, action: str, **meta) -> None:
    try:
        from api.routes_tenant_self import _actor
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=_actor(request, tenant_id), tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "", metadata=meta)
    except Exception:       # noqa: BLE001 - the action happened; the audit is best effort
        pass


@router.get("/v1/tenant/me/inboxes")
async def tenant_list(request: Request):
    tid = _tenant(request)
    rows = _store_call(store.list_inboxes, tid)
    return {"tenant_id": tid, "inboxes": [public(i) for i in rows],
            "limit": store.MAX_TENANT_INBOXES}


@router.post("/v1/tenant/me/inboxes")
async def tenant_create(request: Request, body: dict = None):
    from api.routes_tenant_self import _reject_tenant_id_spoof
    await _reject_tenant_id_spoof(request, body if isinstance(body, dict) else None)
    tid = _tenant(request)
    _tenant_write(request, tid, "create an inbound webhook inbox")
    from api.routes_tenant_self import _actor
    out = _store_call(_create, request, tid, body, _actor(request, tid))
    _tenant_audit(request, tid, "tenant_inbox_create", inbox_id=out["inbox"]["inbox_id"],
                  name=out["inbox"]["name"])
    return out


@router.put("/v1/tenant/me/inboxes/{inbox_id}")
async def tenant_update(inbox_id: str, request: Request, body: dict = None):
    from api.routes_tenant_self import _reject_tenant_id_spoof
    await _reject_tenant_id_spoof(request, body if isinstance(body, dict) else None)
    tid = _tenant(request)
    _store_call(_own, tid, inbox_id)
    _tenant_write(request, tid, "change an inbound webhook inbox")
    changes = _validate_changes(body or {})
    inbox = _store_call(store.update_inbox, inbox_id, changes)
    _tenant_audit(request, tid, "tenant_inbox_update", inbox_id=inbox_id,
                  changed=sorted(changes))
    return {"inbox": public(inbox)}


@router.post("/v1/tenant/me/inboxes/{inbox_id}/rotate-url")
async def tenant_rotate_url(inbox_id: str, request: Request):
    tid = _tenant(request)
    _store_call(_own, tid, inbox_id)
    _tenant_write(request, tid, "rotate an inbound webhook URL")
    token = _store_call(store.rotate_token, inbox_id)
    _tenant_audit(request, tid, "tenant_inbox_rotate_url", inbox_id=inbox_id)
    return {"url": f"{_base_url(request)}/v1/inbound/{token}",
            "warning": "The old URL stopped working. This one is shown once."}


@router.post("/v1/tenant/me/inboxes/{inbox_id}/rotate-secret")
async def tenant_rotate_secret(inbox_id: str, request: Request):
    tid = _tenant(request)
    _store_call(_own, tid, inbox_id)
    _tenant_write(request, tid, "rotate an inbound webhook secret")
    secret = _store_call(store.rotate_secret, inbox_id)
    _tenant_audit(request, tid, "tenant_inbox_rotate_secret", inbox_id=inbox_id)
    return {"signing_secret": secret, "warning": "Shown once. Update the partner's form."}


@router.delete("/v1/tenant/me/inboxes/{inbox_id}")
async def tenant_delete(inbox_id: str, request: Request):
    tid = _tenant(request)
    _store_call(_own, tid, inbox_id)
    _tenant_write(request, tid, "delete an inbound webhook inbox")
    _store_call(store.delete_inbox, inbox_id)
    _tenant_audit(request, tid, "tenant_inbox_delete", inbox_id=inbox_id)
    return {"deleted": inbox_id}


@router.get("/v1/tenant/me/inboxes/{inbox_id}/deliveries")
async def tenant_deliveries(inbox_id: str, request: Request,
                            limit: int = Query(50, ge=1, le=200), cursor: str = Query("")):
    tid = _tenant(request)
    inbox = _store_call(_own, tid, inbox_id)
    return _store_call(_deliveries, inbox, limit, cursor)


@router.get("/v1/tenant/me/inboxes/{inbox_id}/deliveries/{delivery_id}")
async def tenant_delivery(inbox_id: str, delivery_id: str, request: Request):
    tid = _tenant(request)
    inbox = _store_call(_own, tid, inbox_id)
    return _store_call(_delivery, inbox, delivery_id)


# ── operator routes ──────────────────────────────────────────────────


def _admin_read(request: Request, owner: str) -> None:
    from core.auth import require_admin_scope
    if owner in (store.PLATFORM, "all"):
        require_admin_scope(request, "tenants:read", cross_tenant=True)
    else:
        require_admin_scope(request, "tenants:read", owner)


def _admin_write(request: Request) -> None:
    from core.auth import require_admin_scope
    require_admin_scope(request, "tenants:write", cross_tenant=True)


def _any(inbox_id: str) -> dict:
    inbox = store.get_inbox(inbox_id)
    if not inbox:
        raise HTTPException(status_code=404, detail="no such inbox")
    return inbox


def _platform_only(inbox: dict) -> None:
    if inbox.get("owner") != store.PLATFORM:
        raise HTTPException(status_code=403,
                            detail="this is a tenant's inbox: it is read only here, and "
                                   "changed in that tenant's portal")


def _admin_audit(request: Request, action: str, **meta) -> None:
    try:
        from api.routes_tenant import _actor_from_request
        actor = _actor_from_request(request)
    except Exception:       # noqa: BLE001
        actor = "admin"
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=actor, tenant_id=store.PLATFORM,
                         source_ip=request.client.host if request.client else "", metadata=meta)
    except Exception:       # noqa: BLE001
        pass


@router.get("/v1/admin/inboxes")
async def admin_list(request: Request, owner: str = Query(store.PLATFORM)):
    _admin_read(request, owner)

    def rows():
        wanted = store.owners() if owner == "all" else [owner]
        return [i for o in wanted for i in store.list_inboxes(o)]
    return {"owner": owner, "inboxes": [public(i) for i in _store_call(rows)],
            "limit": store.MAX_PLATFORM_INBOXES}


@router.post("/v1/admin/inboxes")
async def admin_create(request: Request, body: dict = None):
    _admin_write(request)
    try:
        from api.routes_tenant import _actor_from_request
        actor = _actor_from_request(request)
    except Exception:       # noqa: BLE001
        actor = "admin"
    out = _store_call(_create, request, store.PLATFORM, body, actor)
    _admin_audit(request, "inbox_create", inbox_id=out["inbox"]["inbox_id"],
                 name=out["inbox"]["name"])
    return out


@router.get("/v1/admin/inboxes/{inbox_id}")
async def admin_get(inbox_id: str, request: Request):
    inbox = _store_call(_any, inbox_id)
    _admin_read(request, inbox["owner"])
    return {"inbox": public(inbox)}


@router.put("/v1/admin/inboxes/{inbox_id}")
async def admin_update(inbox_id: str, request: Request, body: dict = None):
    _admin_write(request)
    inbox = _store_call(_any, inbox_id)
    _platform_only(inbox)
    changes = _validate_changes(body or {})
    inbox = _store_call(store.update_inbox, inbox_id, changes)
    _admin_audit(request, "inbox_update", inbox_id=inbox_id, changed=sorted(changes))
    return {"inbox": public(inbox)}


@router.post("/v1/admin/inboxes/{inbox_id}/rotate-url")
async def admin_rotate_url(inbox_id: str, request: Request):
    _admin_write(request)
    _platform_only(_store_call(_any, inbox_id))
    token = _store_call(store.rotate_token, inbox_id)
    _admin_audit(request, "inbox_rotate_url", inbox_id=inbox_id)
    return {"url": f"{_base_url(request)}/v1/inbound/{token}",
            "warning": "The old URL stopped working. This one is shown once."}


@router.post("/v1/admin/inboxes/{inbox_id}/rotate-secret")
async def admin_rotate_secret(inbox_id: str, request: Request):
    _admin_write(request)
    _platform_only(_store_call(_any, inbox_id))
    secret = _store_call(store.rotate_secret, inbox_id)
    _admin_audit(request, "inbox_rotate_secret", inbox_id=inbox_id)
    return {"signing_secret": secret, "warning": "Shown once. Update the partner's form."}


@router.delete("/v1/admin/inboxes/{inbox_id}")
async def admin_delete(inbox_id: str, request: Request):
    _admin_write(request)
    _platform_only(_store_call(_any, inbox_id))
    _store_call(store.delete_inbox, inbox_id)
    _admin_audit(request, "inbox_delete", inbox_id=inbox_id)
    return {"deleted": inbox_id}


@router.get("/v1/admin/inboxes/{inbox_id}/deliveries")
async def admin_deliveries(inbox_id: str, request: Request,
                           limit: int = Query(50, ge=1, le=200), cursor: str = Query("")):
    inbox = _store_call(_any, inbox_id)
    _admin_read(request, inbox["owner"])
    return _store_call(_deliveries, inbox, limit, cursor)


@router.get("/v1/admin/inboxes/{inbox_id}/deliveries/{delivery_id}")
async def admin_delivery(inbox_id: str, delivery_id: str, request: Request):
    inbox = _store_call(_any, inbox_id)
    _admin_read(request, inbox["owner"])
    return _store_call(_delivery, inbox, delivery_id)
