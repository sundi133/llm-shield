"""The agent's link to Shield: enroll once, then pull the bundle, push the audit
log, send heartbeats. Never on the decision path; every call is best effort
and resumable, and the laptop keeps enforcing offline (spec §9).

Standard library HTTP (urllib); `http` is injectable for tests.
"""

from __future__ import annotations

import json
import os
import stat
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Callable, Optional

from votal_device_agent._deps import BundleError
from votal_device_agent.audit import AuditLog, to_event
from votal_device_agent.trust import TrustStore

Http = Callable[[str, str, dict, Optional[bytes]], tuple]
from votal_device_agent._version import __version__ as AGENT_VERSION  # noqa: E402


def _urllib(method: str, url: str, headers: dict, body: Optional[bytes]) -> tuple:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers or {}), e.read()
        except OSError:
            return e.code, dict(e.headers or {}), b""


@dataclass
class AgentConfig:
    """Written by the MDM install (agent.json). The pinned key comes from here,
    never from the network: a device that fetched its trust anchor from the
    server it is meant to verify would trust whoever answers."""
    shield_url: str
    tenant_id: str
    fleet: str
    pinned_public_key: str
    state_dir: str
    ollama_url: str = "http://127.0.0.1:11535"
    local_port: int = 47823
    proxy_port: int = 47824
    capture: str = "proxy"                # proxy | off (the extension still asks the agent)
    # device: a self-signed CA made on the laptop (Windows trusts it silently).
    # tenant: an intermediate under the tenant root that MDM trusts (macOS,
    # where only an MDM profile can trust a certificate silently).
    ca_mode: str = "device"
    fallback_path: str = ""
    model_inline: str = "auto"            # auto | always | never

    @classmethod
    def load(cls, path: str | Path) -> "AgentConfig":
        raw = json.loads(Path(path).read_text())
        cfg = cls(**{k: raw[k] for k in cls.__dataclass_fields__ if k in raw})
        key = cfg.pinned_public_key.strip().lower()
        if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("pinned_public_key: 64 hex characters (Ed25519 public key)")
        if cfg.model_inline not in ("auto", "always", "never"):
            raise ValueError("model_inline: auto, always or never")
        if cfg.capture not in ("proxy", "off"):
            raise ValueError("capture: proxy or off")
        if cfg.ca_mode not in ("device", "tenant"):
            raise ValueError("ca_mode: device or tenant")
        cfg.pinned_public_key = key
        return cfg


@dataclass
class Credentials:
    device_id: str
    api_key: str
    tenant_id: str
    fleet: str


class CredentialStore:
    """The device key. A file readable only by the agent's account here; the
    installers (task 6) move it to the macOS keychain or Windows DPAPI."""

    def __init__(self, state_dir: str | Path):
        self.path = Path(state_dir) / "credentials.json"

    def load(self) -> Optional[Credentials]:
        try:
            return Credentials(**json.loads(self.path.read_text()))
        except (OSError, ValueError, TypeError):
            return None

    def save(self, creds: Credentials) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            json.dump(asdict(creds), f)
        os.replace(tmp, self.path)

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class SyncError(Exception):
    pass


def _server_time(headers: dict, store: TrustStore) -> None:
    date = {k.lower(): v for k, v in (headers or {}).items()}.get("date")
    if date:
        try:
            store.observe_server_time(parsedate_to_datetime(date).timestamp())
        except (TypeError, ValueError):
            pass


def enroll(cfg: AgentConfig, token: str, info: dict, *, http: Http = _urllib,
           store=None) -> Credentials:
    """Exchange the MDM's enrollment token for this device's key. Refuses when
    Shield's signing key is not the one MDM pinned."""
    status, _h, body = http("POST", f"{cfg.shield_url.rstrip('/')}/v1/devices/enroll",
                            {"X-Enrollment-Token": token, "Content-Type": "application/json"},
                            json.dumps({**info, "agent_version": info.get("agent_version")
                                        or AGENT_VERSION}).encode())
    if status != 200:
        raise SyncError(f"enrollment refused: HTTP {status} {body[:200]!r}")
    out = json.loads(body)
    if out.get("pinned_public_key", "").lower() != cfg.pinned_public_key:
        raise SyncError("Shield's bundle signing key is not the key your MDM pinned: refusing "
                        "to enroll (wrong Shield, or an interception)")
    if out.get("tenant_id") != cfg.tenant_id or out.get("fleet") != cfg.fleet:
        raise SyncError(f"enrolled into {out.get('tenant_id')}/{out.get('fleet')}, but this "
                        f"install is for {cfg.tenant_id}/{cfg.fleet}")
    creds = Credentials(device_id=out["device_id"], api_key=out["api_key"],
                        tenant_id=out["tenant_id"], fleet=out["fleet"])
    (store or CredentialStore(cfg.state_dir)).save(creds)
    return creds


REFRESH_BEFORE_S = 12 * 3600


def _fresh(bundle_path: Path, now: float) -> bool:
    """Whether the bundle on disk has more than 12 hours left. If not, ask for a
    new one without If-None-Match: a Shield answering 304 for an unchanged
    policy would otherwise let the laptop's copy expire while it is online."""
    try:
        expires = int(json.loads(bundle_path.read_text())["header"]["expires_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return expires - now > REFRESH_BEFORE_S


def pull_bundle(cfg: AgentConfig, creds: Credentials, store: TrustStore, *,
                http: Http = _urllib) -> str:
    """updated, unchanged, revoked, or refused: <why>. Never writes a bundle
    that does not verify, so a bad download cannot replace a good bundle."""
    etag_file = store.dir / "bundle.etag"
    headers = {"X-API-Key": creds.api_key}
    if etag_file.exists() and _fresh(store.bundle_path, store.now()):
        headers["If-None-Match"] = etag_file.read_text().strip()
    q = urllib.parse.urlencode({"fleet": cfg.fleet})
    try:
        status, resp_headers, body = http("GET", f"{cfg.shield_url.rstrip('/')}/v1/edge/dlp-bundle?{q}",
                                          headers, None)
    except OSError as e:
        return f"refused: shield unreachable ({e})"
    _server_time(resp_headers, store)
    if status == 304:
        return "unchanged"
    if status == 401:
        return "revoked"
    if status != 200:
        return f"refused: HTTP {status}"
    try:
        store.accept(json.loads(body))
    except (ValueError, KeyError, TypeError, BundleError) as e:
        return f"refused: {e}"
    etag = {k.lower(): v for k, v in resp_headers.items()}.get("etag")
    if etag:
        etag_file.write_text(etag)
    return "updated"


def push_audit(cfg: AgentConfig, creds: Credentials, audit: AuditLog, *, batch: int = 200,
               http: Http = _urllib) -> int:
    """Upload records after the last one Shield accepted. Returns how many were
    sent, or -1 when the device key was revoked."""
    mark = audit.dir / "uploaded.json"
    done = json.loads(mark.read_text())["seq"] if mark.exists() else 0
    pending = [r for r in audit.records() if r.get("seq", 0) > done][:batch]
    if not pending:
        return 0
    try:
        status, _h, body = http("POST", f"{cfg.shield_url.rstrip('/')}/v1/shield/runtime/events",
                                {"X-API-Key": creds.api_key, "Content-Type": "application/json"},
                                json.dumps({"events": [to_event(r) for r in pending]}).encode())
    except OSError:
        return 0
    if status == 401:
        return -1
    if status != 202:
        return 0
    tmp = mark.with_suffix(".tmp")
    tmp.write_text(json.dumps({"seq": pending[-1]["seq"]}))
    os.replace(tmp, mark)
    return len(pending)


def request_ca(cfg: AgentConfig, creds: Credentials, csr_pem: str, *,
               http: Http = _urllib) -> tuple[int, dict]:
    """(status, body): this laptop's 7-day intermediate CA, for a CSR."""
    try:
        status, _h, body = http("POST", f"{cfg.shield_url.rstrip('/')}/v1/devices/ca",
                                {"X-API-Key": creds.api_key, "Content-Type": "application/json"},
                                json.dumps({"csr_pem": csr_pem}).encode())
    except OSError as e:
        return 0, {"detail": f"shield unreachable ({e})"}
    try:
        return status, json.loads(body or b"{}")
    except ValueError:
        return status, {}


def heartbeat(cfg: AgentConfig, creds: Credentials, payload: dict, store: TrustStore, *,
              http: Http = _urllib) -> int:
    """HTTP status (204 on success, 0 when Shield is unreachable)."""
    try:
        status, resp_headers, _b = http("POST", f"{cfg.shield_url.rstrip('/')}/v1/devices/heartbeat",
                                        {"X-API-Key": creds.api_key,
                                         "Content-Type": "application/json"},
                                        json.dumps(payload).encode())
    except OSError:
        return 0
    _server_time(resp_headers, store)
    return status
