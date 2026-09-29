"""Background link to Shield: pull the signed bundle, push the audit log.

Neither is ever on the decision path; both are best effort and resumable.

pull_bundle  downloads /v1/edge/embodied-bundle, VERIFIES it against the pinned
             key before writing, and replaces the file atomically. A bundle that
             does not verify is never written, so a bad download cannot replace
             a good bundle.
push_audit   uploads audit records not yet sent to /v1/shield/runtime/events as
             kind "action", and remembers the last sequence Shield accepted.

Standard library HTTP (urllib); `http` is injectable for tests.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from shield_embodied.guard import BundleError, OfflineAuditChain, verify_bundle

Http = Callable[[str, str, dict, Optional[bytes]], tuple]


def _urllib(method: str, url: str, headers: dict, body: Optional[bytes]) -> tuple:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()


def pull_bundle(shield_url: str, api_key: str, *, profile: str, fleet: str, tenant: str,
                bundle_path: str, pinned_key_hex: str, http: Http = _urllib) -> str:
    """'updated', 'unchanged', or 'refused: <why>'. Never writes an unverified bundle."""
    etag_file = Path(str(bundle_path) + ".etag")
    headers = {"X-API-Key": api_key}
    if etag_file.exists() and Path(bundle_path).exists():
        headers["If-None-Match"] = etag_file.read_text().strip()
    q = urllib.parse.urlencode({"profile": profile, "fleet": fleet})
    try:
        status, resp_headers, body = http("GET", f"{shield_url.rstrip('/')}/v1/edge/embodied-bundle?{q}",
                                          headers, None)
    except OSError as e:
        return f"refused: shield unreachable ({e})"
    if status == 304:
        return "unchanged"
    if status != 200:
        return f"refused: HTTP {status}"
    try:
        bundle = json.loads(body)
        verify_bundle(bundle, public_key_hex=pinned_key_hex, expect_tenant=tenant,
                      expect_fleet=fleet)
    except (ValueError, BundleError) as e:
        return f"refused: {e}"
    tmp = Path(str(bundle_path) + ".tmp")
    tmp.write_text(json.dumps(bundle))
    os.replace(tmp, bundle_path)
    etag = {k.lower(): v for k, v in resp_headers.items()}.get("etag")
    if etag:
        etag_file.write_text(etag)
    return "updated"


def push_audit(shield_url: str, api_key: str, *, audit_dir: str, robot_id: str,
               profile: str = "", batch: int = 200, http: Http = _urllib) -> int:
    """Upload records after the last one Shield accepted. Returns how many."""
    chain = OfflineAuditChain(audit_dir)
    mark = Path(audit_dir) / "uploaded.json"
    done = json.loads(mark.read_text())["seq"] if mark.exists() else 0
    pending = [r for r in chain.records() if r.get("seq", 0) > done][:batch]
    if not pending:
        return 0
    events = [{
        "source": "custom", "kind": "action",
        "decision": "deny" if r.get("verdict") == "block" else "audit",
        "severity": "high" if r.get("verdict") == "block" else "medium",
        "agent_id": robot_id, "agent_instance_id": robot_id,
        "session_id": str(r.get("run_id") or ""), "profile": profile,
        "profile_hash": r.get("profile_hash") or "", "at": r.get("at"),
        "detail": {k: r.get(k) for k in ("tool", "verdict", "rail", "reasons", "mode", "stage",
                                        "step", "seq", "record_hash", "bundle_version")},
    } for r in pending]
    try:
        status, _, _ = http("POST", f"{shield_url.rstrip('/')}/v1/shield/runtime/events",
                            {"X-API-Key": api_key, "Content-Type": "application/json"},
                            json.dumps({"events": events}).encode())
    except OSError:
        return 0
    if status != 202:
        return 0
    mark.write_text(json.dumps({"seq": pending[-1]["seq"]}))
    return len(pending)
