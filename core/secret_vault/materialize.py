"""Egress materialization + ingress re-tokenization for the secret vault.

Developers reference a secret by an inert placeholder instead of the real value:

    shield://<ref>      readable reference (put this in an env var / tool arg)
    svlt_<hex>          opaque token returned at registration

The placeholder can flow freely through prompts, agent reasoning and tool args —
it is meaningless on its own. The real value is substituted **only** at the egress
boundary, and **only** when the outbound destination matches that secret's
bindings. Any other destination receives the inert placeholder unchanged; this is
the anti confused-deputy-exfiltration control.

`materialize_request` mutates an outbound request in place just before it is sent;
`retokenize` swaps any real secret value back to its placeholder before a tool
result is returned to the model.
"""

import re
from urllib.parse import urlparse

from core.secret_vault.keyprovider import vault_enabled

# shield://my_ref  or  svlt_deadbeef  — the two placeholder forms.
_REF_RE = re.compile(r"shield://([A-Za-z0-9_.\-]+)|(svlt_[0-9a-f]+)")


def _host_of(destination: str) -> str:
    """Extract a comparable host from a URL or bare host[:port] string."""
    if "://" in destination:
        host = urlparse(destination).hostname or ""
    else:
        host = destination.split("/")[0].split(":")[0]
    return host.lower().strip(".")


def _binding_matches(destination: str, bindings: list[str]) -> bool:
    """True if the real outbound destination is covered by any binding.

    A binding matches on exact host or as a parent-domain suffix (so
    ``api.stripe.com`` is covered by a ``stripe.com`` binding), or when it appears
    verbatim in the destination (covers tool-id bindings passed as the destination).
    """
    host = _host_of(destination)
    for b in bindings:
        b = b.lower().strip().strip(".")
        if not b:
            continue
        bhost = _host_of(b) if ("://" in b or "/" in b) else b
        if host == bhost or host.endswith("." + bhost):
            return True
        if b == destination.lower():  # exact tool-id / opaque destination match
            return True
    return False


def _tool_allowed(tool_id: str | None, tool_ids: list[str]) -> bool:
    """A secret with a non-empty tool_ids list may only be used by those tools
    (tier-1 scoping). An empty list means no tool restriction."""
    if not tool_ids:
        return True
    return tool_id is not None and tool_id in tool_ids


def _materialize_str(tenant_id: str, s: str, destination: str, tool_id: str | None) -> str:
    """Substitute any bound placeholder in a single string."""
    from storage.vault_store import resolve_binding

    def repl(m: re.Match) -> str:
        ref = m.group(1) or m.group(2)
        resolved = resolve_binding(tenant_id, ref)
        if resolved is None:
            return m.group(0)  # unknown reference — leave inert
        value, bindings, tool_ids = resolved
        if _binding_matches(destination, bindings) and _tool_allowed(tool_id, tool_ids):
            return value
        return m.group(0)  # destination/tool not allowed — do NOT reveal

    return _REF_RE.sub(repl, s)


def _walk(tenant_id: str, obj, destination: str, tool_id: str | None):
    if isinstance(obj, str):
        return _materialize_str(tenant_id, obj, destination, tool_id)
    if isinstance(obj, dict):
        return {k: _walk(tenant_id, v, destination, tool_id) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(tenant_id, v, destination, tool_id) for v in obj]
    return obj


def materialize_obj(tenant_id: str, obj, destination: str, tool_id: str | None = None):
    """Return a copy of ``obj`` with bound placeholders replaced by real values.

    A secret is revealed only when the destination matches its bindings AND (if it
    is tool-scoped) ``tool_id`` is in its tool_ids.
    """
    if not vault_enabled() or not tenant_id or obj is None:
        return obj
    return _walk(tenant_id, obj, destination, tool_id)


def materialize_request(tenant_id: str, req, tool_id: str | None = None) -> None:
    """Materialize bound secrets into an outbound request, in place.

    ``req`` is an UpstreamRequest (core.openapi.upstream_call). The destination is
    the request URL, so a call assembled for one host cannot pull a secret bound to
    another. ``tool_id`` enables tier-1 scoping. No-op when the vault is off or the
    tenant has no secrets.
    """
    if not vault_enabled() or not tenant_id:
        return
    dest = req.url
    req.headers = materialize_obj(tenant_id, req.headers, dest, tool_id)
    req.params = materialize_obj(tenant_id, req.params, dest, tool_id)
    req.json_body = materialize_obj(tenant_id, req.json_body, dest, tool_id)


def retokenize(tenant_id: str, obj):
    """Replace any real secret value in ``obj`` with its ``shield://ref`` placeholder.

    Backstop for tool outputs that echo a secret, so it never reaches the model.
    No-op when the vault is off or the tenant has no secrets.
    """
    if not vault_enabled() or not tenant_id or obj is None:
        return obj
    from storage.vault_store import reveal_all

    pairs = [(val, ref) for val, ref in reveal_all(tenant_id) if val]
    if not pairs:
        return obj
    # Replace longer values first to avoid partial overlaps.
    pairs.sort(key=lambda p: len(p[0]), reverse=True)

    def scrub(o):
        if isinstance(o, str):
            for val, ref in pairs:
                if val in o:
                    o = o.replace(val, f"shield://{ref}")
            return o
        if isinstance(o, dict):
            return {k: scrub(v) for k, v in o.items()}
        if isinstance(o, list):
            return [scrub(v) for v in o]
        return o

    return scrub(obj)
