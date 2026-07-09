"""Bundle external $refs into a spec's local components.

OpenAPI specs can $ref other documents, e.g. `common.yaml#/components/schemas/X`
or `https://host/common.yaml#/X`. This pre-pass pulls those referenced schemas
into the main doc's components.schemas and rewrites the refs to local
`#/components/schemas/<name>`, so the normal local resolver handles the rest.

Safety: external documents are resolved from a caller-provided ``external_docs``
map by default — NO network. URL fetching is strictly opt-in
(``fetch_external=True``) and only for hosts in ``allowed_hosts``, with
private/loopback addresses blocked (SSRF defense). The API layer does NOT expose
fetching.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit

import yaml


def _basename(uri: str) -> str:
    tail = re.split(r"[\\/]", uri.split("#", 1)[0])[-1]
    return re.sub(r"\.(ya?ml|json)$", "", tail) or "External"


def _unique_name(base: str, taken: dict) -> str:
    base = re.sub(r"[^A-Za-z0-9]", "_", base).strip("_") or "External"
    name, i = base, 2
    while name in taken:
        name = f"{base}{i}"
        i += 1
    return name


def _host_is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local")


def _is_fetchable(uri: str, allowed_hosts: Optional[list]) -> bool:
    parts = urlsplit(uri)
    if parts.scheme not in ("http", "https"):
        return False
    host = parts.hostname or ""
    if _host_is_private(host):
        return False
    return bool(allowed_hosts) and host in allowed_hosts


def _fetch(uri: str, timeout: float = 10.0, max_bytes: int = 5_000_000) -> Optional[dict]:
    try:
        import httpx
        with httpx.Client(timeout=timeout, follow_redirects=False) as c:
            r = c.get(uri)
            if r.status_code != 200 or len(r.content) > max_bytes:
                return None
            return yaml.safe_load(r.text)
    except Exception:
        return None


def bundle_external_refs(
    doc: dict,
    *,
    external_docs: Optional[dict] = None,
    fetch_external: bool = False,
    allowed_hosts: Optional[list] = None,
) -> dict:
    """Return a copy of ``doc`` with external $refs inlined into components."""
    if not isinstance(doc, dict):
        return doc
    doc = copy.deepcopy(doc)
    external_docs = external_docs or {}
    schemas = doc.setdefault("components", {}).setdefault("schemas", {})

    loaded: dict[str, Any] = {}
    local_name: dict[tuple, str] = {}

    def load_doc(uri: str):
        if uri in loaded:
            return loaded[uri]
        d = external_docs.get(uri)
        if d is None and fetch_external and _is_fetchable(uri, allowed_hosts):
            d = _fetch(uri)
        loaded[uri] = d
        return d

    def resolve_pointer(d: Any, pointer: str):
        if not pointer or pointer == "/":
            return d
        cur = d
        for part in pointer.lstrip("/").split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur

    def ensure_local(uri: str, pointer: str) -> Optional[str]:
        key = (uri, pointer)
        if key in local_name:
            return local_name[key]
        d = load_doc(uri)
        if d is None:
            return None
        target = resolve_pointer(d, pointer)
        if target is None:
            return None
        base = (pointer.rstrip("/").split("/")[-1] if pointer else "") or _basename(uri)
        name = _unique_name(base, schemas)
        local_name[key] = name
        schemas[name] = {}                       # reserve (cycle-safe)
        bundled = copy.deepcopy(target)
        rewrite(bundled, base_uri=uri)           # bundle the target's own refs
        schemas[name] = bundled
        return name

    def rewrite(node: Any, base_uri: str) -> None:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str):
                if ref.startswith("#"):
                    if base_uri:                  # local ref *inside an external doc* -> bundle it
                        nm = ensure_local(base_uri, ref[1:])
                        if nm:
                            node.clear()
                            node["$ref"] = f"#/components/schemas/{nm}"
                    return                        # main-doc local ref: leave for local resolver
                uri_part, _, ptr = ref.partition("#")
                uri = uri_part if uri_part in external_docs else urljoin(base_uri or "", uri_part)
                nm = ensure_local(uri, ("/" + ptr.lstrip("/")) if ptr else "")
                if nm:
                    node.clear()
                    node["$ref"] = f"#/components/schemas/{nm}"
                return
            for v in list(node.values()):
                rewrite(v, base_uri)
        elif isinstance(node, list):
            for v in node:
                rewrite(v, base_uri)

    rewrite(doc, base_uri="")
    return doc
