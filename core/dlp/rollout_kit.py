"""Rollout kits: everything an admin uploads to Jamf, Kandji or Intune to put
the Votal device agent on a fleet's laptops, with every value filled in.

Spec: docs/specs/device-rollout-kit.md (approved), task 2. Pure: values in,
zip bytes out. Minting the kit's enrollment token and reading the tenant's
root and policy is the API's job (task 3).

Every value that lands in a script or a command line is validated against a
strict pattern first: a kit is run as root or SYSTEM on every laptop, so a
tenant id or a URL must not be able to carry shell or PowerShell syntax.

Templates live in core/dlp/kit_templates/ as *.tmpl (.dockerignore drops *.md,
so a template named README.md could vanish from an image), with {{name}}
placeholders; rendering fails on any unknown or leftover placeholder.
"""

from __future__ import annotations

import io
import json
import plistlib
import re
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parent / "kit_templates"
MDMS = ("jamf", "kandji", "intune")
PLATFORMS = {"jamf": ("macos",), "kandji": ("macos",), "intune": ("windows", "macos")}
DEFAULT_PLATFORMS = {"jamf": ("macos",), "kandji": ("macos",), "intune": ("windows", "macos")}
LOCAL_PORT, PROXY_PORT = 47823, 47824
PAC_URL = f"http://127.0.0.1:{LOCAL_PORT}/proxy.pac"
AGENT_LABEL = "ai.votal.device-agent"
#: Where Chrome and Edge fetch the extension. The Chrome Web Store's update URL
#: works only for a store listing; Votal's self-hosted VotalAI Guardrails is
#: served from its own update manifest (docs/enterprise-install.md).
CRX_UPDATE_URL = "https://clients2.google.com/service/update2/crx"
VOTAL_EXTENSION_ID = "gcbcablddjeicimnfipalnckffoiihnb"
VOTAL_EXTENSION_UPDATE_URL = "https://storage.googleapis.com/votal-public/extension/update.xml"
PROFILE_NAME = "Votal-Device-Agent.mobileconfig"
_NS = uuid.UUID("0b6f1e62-3a0f-4c1e-8e51-6a8c2f4d9b17")

_PATTERNS = {
    "tenant_id": r"^[A-Za-z0-9_-]{1,64}$",
    "fleet": r"^[a-z0-9][a-z0-9._-]{0,63}$",
    "kit_id": r"^kit_[0-9a-f]{16}$",
    "token": r"^vde\.[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{32,}$",
    "token_id": r"^[0-9a-f]{16}$",
    "shield_url": r"^https://[A-Za-z0-9.-]+(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$",
    "pinned_public_key": r"^[0-9a-f]{64}$",
    "agent_version": r"^\d+\.\d+\.\d+$",
    "release_base": r"^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~/-]*)?$",
    "extension_update_url": r"^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~/-]*)?$",
    "apple_team_id": r"^([A-Z0-9]{10})?$",
    "windows_signer": r"^[A-Za-z0-9 .,&()-]{0,100}$",
}
_EXT_ID = re.compile(r"^[a-p]{32}$")
_HOST = re.compile(r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class KitError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass
class KitRequest:
    tenant_id: str
    fleet: str
    mdm: str
    kit_id: str
    token: str                        # the enrollment token: goes into two files only
    token_id: str
    shield_url: str
    pinned_public_key: str
    agent_version: str
    release_base: str                 # e.g. https://github.com/<org>/<repo>/releases/download
    ai_hosts: list = field(default_factory=list)
    platforms: tuple = ()
    include_proxy: bool = True
    extension_ids: list = field(default_factory=list)
    extension_update_url: str = VOTAL_EXTENSION_UPDATE_URL
    root_pem: str = ""                # the tenant root (macOS)
    root_fingerprint: str = ""
    apple_team_id: str = ""           # Votal's Apple Team ID, once the release is signed
    windows_signer: str = "Votal"     # the Authenticode signer's name
    release_page: str = ""
    created_at: int = 0
    expires_at: int = 0
    uses: int = 0

    def resolved_platforms(self) -> tuple:
        return tuple(self.platforms) or DEFAULT_PLATFORMS.get(self.mdm, ())


def validate(req: KitRequest) -> KitRequest:
    errors = []
    for name, pattern in _PATTERNS.items():
        if not re.match(pattern, str(getattr(req, name) or "")):
            errors.append(f"{name}: not a valid value")
    if req.mdm not in MDMS:
        errors.append(f"mdm: one of {', '.join(MDMS)}")
    plats = req.resolved_platforms()
    for plat in plats:
        if plat not in PLATFORMS.get(req.mdm, ()):
            errors.append(f"platforms: {req.mdm} manages {', '.join(PLATFORMS.get(req.mdm, ()))} "
                          f"here, not {plat}")
    if not plats:
        errors.append("platforms: at least one")
    for i in req.extension_ids:
        if not _EXT_ID.match(str(i)):
            errors.append(f"extension_ids: {str(i)[:40]!r} is not an extension id")
    for h in req.ai_hosts:
        if not _HOST.match(str(h)):
            errors.append(f"ai_hosts: {str(h)[:80]!r} is not a hostname")
    if not req.ai_hosts:
        errors.append("ai_hosts: the policy lists none")
    if "macos" in plats and "BEGIN CERTIFICATE" not in (req.root_pem or ""):
        errors.append("root_pem: the tenant root is needed for macOS")
    if errors:
        raise KitError(errors)
    return req


# ── rendering ────────────────────────────────────────────────────────

_VAR = re.compile(r"\{\{([a-z_]+)\}\}")


def render(name: str, values: dict) -> str:
    text = (TEMPLATES / f"{name}.tmpl").read_text()

    def sub(m):
        key = m.group(1)
        if key not in values:
            raise KeyError(f"template {name} uses {{{{{key}}}}}, which the kit does not set")
        return str(values[key])
    out = _VAR.sub(sub, text)
    if "{{" in out or "}}" in out:
        raise ValueError(f"template {name}: a placeholder was left unrendered")
    return out


def _values(req: KitRequest) -> dict:
    ids = list(req.extension_ids)
    hosts = sorted(req.ai_hosts)
    return {
        "tenant_id": req.tenant_id, "fleet": req.fleet, "mdm": req.mdm, "kit_id": req.kit_id,
        "token": req.token, "shield_url": req.shield_url,
        "pinned_public_key": req.pinned_public_key, "version": req.agent_version,
        "release_base": req.release_base.rstrip("/"),
        "release_page": req.release_page or req.release_base.rstrip("/").rsplit("/download", 1)[0],
        "apple_team_id": req.apple_team_id, "windows_signer": req.windows_signer,
        "extension_ids_csv": ",".join(ids),
        "extension_ids_ps": ", ".join(f"'{i}'" for i in ids),
        "extension_update_url": req.extension_update_url,
        "pac_url": PAC_URL, "proxy_port": PROXY_PORT, "local_port": LOCAL_PORT,
        "root_fingerprint": req.root_fingerprint or "(no macOS in this kit)",
        "pac_snippet": _pac_snippet(hosts),
        "expires": _date(req.expires_at), "uses": req.uses or "(see portal)",
        "host_count": len(hosts),
        "profile_contents": _profile_contents(req),
        "windows_scripts_step": _windows_scripts_step(req),
    }


def _join(items: list) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _profile_contents(req: KitRequest) -> str:
    """What the Mac profile holds, from what this kit put in it."""
    parts = ["the agent's settings", "the root certificate"]
    if req.include_proxy:
        parts.append("the AI proxy setting")
    if req.extension_ids:
        parts.append("the browser extension")
    parts.append("a managed login item (so employees cannot turn the agent off). It "
                 "installs through MDM only; double-clicking it will not work")
    return _join(parts)


def _windows_scripts_step(req: KitRequest) -> str:
    """Step 2 of the Windows README, naming only the scripts this kit has."""
    scripts, does = [], []
    if req.include_proxy:
        scripts.append("`windows/set-pac.ps1`")
        does.append("send AI services to the agent")
    if req.extension_ids:
        scripts.append("`windows/browser-extensions.ps1`")
        does.append("install the browser extension")
    if not scripts:
        return ("2. **The scripts.** None needed: this kit leaves out the proxy setting "
                "and the browser extension.")
    noun = "a platform script" if len(scripts) == 1 else "platform scripts"
    return (f"2. **The scripts.** Add {_join(scripts)} as {noun} (Devices, Scripts and "
            f"remediations, Platform scripts; run as system, 64-bit). "
            f"{'It' if len(scripts) == 1 else 'They'} {_join(does)}.")


def _date(ts: int) -> str:
    import datetime
    return (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d")
            if ts else "(see portal)")


def _pac_snippet(hosts: list) -> str:
    cond = " ||\n    ".join(f'shExpMatch(host, "{h}") || shExpMatch(host, "*.{h}")' for h in hosts)
    return (f"  // Votal device agent: AI services only. Put this first in FindProxyForURL.\n"
            f"  if (\n    {cond}\n  ) {{\n    return \"PROXY 127.0.0.1:{PROXY_PORT}; DIRECT\";\n  }}")


# ── the macOS profile ────────────────────────────────────────────────


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(_NS, "|".join(parts))).upper()


def mac_profile(req: KitRequest) -> bytes:
    """One profile with every payload. Its identifier is stable per tenant and
    fleet, so uploading a newer kit's profile replaces the older one instead of
    installing a second (two proxy payloads on one Mac would conflict)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    ident = f"{AGENT_LABEL}.{req.tenant_id}.{req.fleet}"

    def payload(ptype: str, name: str, body: dict) -> dict:
        return {"PayloadType": ptype, "PayloadVersion": 1,
                "PayloadIdentifier": f"{ident}.{name}",
                "PayloadUUID": _uuid(req.kit_id, name), "PayloadDisplayName": body.pop(
                    "_display"), **body}

    settings = {"_display": "Votal device agent settings",
                "ShieldURL": req.shield_url, "TenantID": req.tenant_id, "Fleet": req.fleet,
                "PinnedPublicKey": req.pinned_public_key, "EnrollmentToken": req.token,
                "CAMode": "tenant"}
    if req.extension_ids:
        settings["ExtensionIDs"] = list(req.extension_ids)
    content = [payload("ai.votal.device-agent", "settings", settings)]
    der = x509.load_pem_x509_certificate(req.root_pem.encode()).public_bytes(
        serialization.Encoding.DER)
    content.append(payload("com.apple.security.root", "root", {
        "_display": "Votal Device DLP Root", "PayloadContent": der,
        "PayloadCertificateFileName": "votal-device-dlp-root.cer"}))
    if req.include_proxy:
        content.append(payload("com.apple.SystemConfiguration", "proxy", {
            "_display": "Votal: AI services through the device agent",
            "Proxies": {"ProxyAutoConfigEnable": 1, "ProxyAutoConfigURLString": PAC_URL,
                        "FallBackAllowed": 1, "ProxyCaptiveLoginAllowed": 1}}))
    if req.extension_ids:
        forcelist = [f"{i};{req.extension_update_url}" for i in req.extension_ids]
        content.append(payload("com.google.Chrome", "chrome", {
            "_display": "Chrome: Votal extension", "ExtensionInstallForcelist": forcelist}))
        content.append(payload("com.microsoft.Edge", "edge", {
            "_display": "Edge: Votal extension", "ExtensionInstallForcelist": forcelist}))
    rule = {"RuleType": "Label", "RuleValue": AGENT_LABEL,
            "Comment": "Votal device agent: keep it running, no background-item prompt"}
    if req.apple_team_id:
        rule["TeamIdentifier"] = req.apple_team_id
    content.append(payload("com.apple.servicemanagement", "login-items", {
        "_display": "Votal device agent: managed login item", "Rules": [rule]}))
    return plistlib.dumps({
        "PayloadType": "Configuration", "PayloadVersion": 1, "PayloadScope": "System",
        "PayloadIdentifier": ident, "PayloadUUID": _uuid(req.kit_id, "profile"),
        "PayloadDisplayName": f"Votal device agent ({req.fleet})",
        "PayloadDescription": "Settings, root certificate, AI proxy, browser extension and "
                              "login item for the Votal device agent. From rollout kit "
                              f"{req.kit_id}.",
        "PayloadOrganization": "Votal AI", "PayloadRemovalDisallowed": True,
        "PayloadContent": content})


# ── the kit ──────────────────────────────────────────────────────────

MAC_HEALTH = {"jamf": "jamf-extension-attribute.sh", "kandji": "kandji-audit.sh",
              "intune": "intune-macos-attribute.sh"}
#: Files that carry the enrollment token. Nothing else may.
TOKEN_FILES = (f"macos/{PROFILE_NAME}", "windows/install-command.txt")


def files(req: KitRequest) -> dict[str, bytes]:
    """name -> content. Deterministic for a given request."""
    validate(req)
    v = _values(req)
    plats = req.resolved_platforms()
    out: dict[str, bytes] = {}
    if "macos" in plats:
        out[f"macos/{PROFILE_NAME}"] = mac_profile(req)
        out["macos/get-installer.sh"] = render("macos/get-installer.sh", v).encode()
        health = MAC_HEALTH[req.mdm]
        out[f"macos/{health}"] = render(f"macos/{health}", v).encode()
    if "windows" in plats:
        out["windows/install-command.txt"] = render("windows/install-command.txt", v).encode()
        out["windows/get-installer.ps1"] = render("windows/get-installer.ps1", v).encode()
        out["windows/detect.ps1"] = render("windows/detect.ps1", v).encode()
        if req.include_proxy:
            out["windows/set-pac.ps1"] = render("windows/set-pac.ps1", v).encode()
        if req.extension_ids:
            out["windows/browser-extensions.ps1"] = render("windows/browser-extensions.ps1",
                                                           v).encode()
    out["README.md"] = readme(req, v).encode()
    out["SECURITY.txt"] = render("common/SECURITY.txt", {
        **v, "token_files": "\n".join(f"  - {f}" for f in TOKEN_FILES if f in out)}).encode()
    out["kit.json"] = (json.dumps(manifest(req), indent=2) + "\n").encode()
    return out


def readme(req: KitRequest, v: dict) -> str:
    plats = req.resolved_platforms()
    parts = [render("common/README-head.md", v)]
    if "macos" in plats:
        parts.append(render(f"macos/README-{req.mdm}.md", v))
    if "windows" in plats:
        parts.append(render("windows/README-intune.md", v))
    if not req.include_proxy:
        parts.append(render("common/README-own-pac.md", v))
    if not req.extension_ids:
        parts.append(render("common/README-no-extension.md", v))
    parts.append(render("common/README-tail.md", v))
    return "\n".join(p.rstrip() + "\n" for p in parts)


def manifest(req: KitRequest) -> dict:
    """kit.json: what the kit is, never the token."""
    return {"kit_id": req.kit_id, "tenant_id": req.tenant_id, "fleet": req.fleet,
            "mdm": req.mdm, "platforms": list(req.resolved_platforms()),
            "agent_version": req.agent_version, "include_proxy": req.include_proxy,
            "extension_ids": list(req.extension_ids),
            "extension_update_url": req.extension_update_url, "shield_url": req.shield_url,
            "root_fingerprint_sha256": req.root_fingerprint, "token_id": req.token_id,
            "created_at": req.created_at, "expires_at": req.expires_at}


def build(req: KitRequest) -> bytes:
    """The kit as zip bytes. Scripts are marked executable."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(files(req).items()):
            info = zipfile.ZipInfo(f"votal-rollout-kit-{req.fleet}-{req.mdm}/{name}",
                                   date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = (0o755 if name.endswith(".sh") else 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buf.getvalue()
