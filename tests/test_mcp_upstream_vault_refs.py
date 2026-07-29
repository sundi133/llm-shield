"""Vault-backed upstream credentials (fleet control plane, phase 8).

SaaS MCP servers authenticate with bearer tokens. Storing one literally in the
route config leaves it in plaintext at rest, so a header may hold a vault
reference instead::

    {"Authorization": "Bearer shield://higgsfield-token"}

The secret is revealed only if its bindings cover the upstream host — the
vault's existing anti-exfiltration control, on the leg OUT of Shield to the real
upstream, which is precisely what that control was built for.

The load-bearing test is the fail-closed one: an unresolvable reference must
never be forwarded as a literal, because that is an unauthenticated call wearing
the costume of an authenticated one.
"""

from unittest.mock import patch

import pytest

from core.mcp.gateway import GatewayError, materialize_upstream_headers


def _cfg(headers=None, url="https://mcp.higgsfield.ai/mcp"):
    cfg = {"route": "higgsfield", "transport": "http", "url": url}
    if headers is not None:
        cfg["headers"] = headers
    return cfg


def _vault(entries):
    """Patch the vault so refs resolve to (value, bindings, tool_ids).

    Patches the name *in materialize*, which does `from ... import vault_enabled`
    and so binds it at import time — patching keyprovider would not be seen.
    """
    return (patch("core.secret_vault.materialize.vault_enabled", return_value=True),
            patch("storage.vault_store.resolve_binding",
                  side_effect=lambda tid, ref: entries.get(ref)))


# ── happy path ───────────────────────────────────────────────────────


def test_reference_bound_to_the_upstream_host_is_materialized():
    ve, rb = _vault({"hf-token": ("s3cret", ["mcp.higgsfield.ai"], [])})
    with ve, rb:
        out = materialize_upstream_headers(
            _cfg({"Authorization": "Bearer shield://hf-token"}), "acme")
    assert out["headers"]["Authorization"] == "Bearer s3cret"


def test_original_config_is_not_mutated():
    """The route document must never end up holding a plaintext secret."""
    cfg = _cfg({"Authorization": "Bearer shield://hf-token"})
    ve, rb = _vault({"hf-token": ("s3cret", ["mcp.higgsfield.ai"], [])})
    with ve, rb:
        materialize_upstream_headers(cfg, "acme")
    assert cfg["headers"]["Authorization"] == "Bearer shield://hf-token"


def test_literal_headers_are_untouched():
    """Backward compatibility: existing routes store a real token and keep working."""
    cfg = _cfg({"Authorization": "Bearer literal-token"})
    out = materialize_upstream_headers(cfg, "acme")
    assert out["headers"] == {"Authorization": "Bearer literal-token"}


def test_no_headers_is_a_no_op():
    cfg = _cfg()
    assert materialize_upstream_headers(cfg, "acme") is cfg
    assert materialize_upstream_headers(_cfg({}), "acme")["headers"] == {}


def test_other_headers_survive_materialization():
    ve, rb = _vault({"hf-token": ("s3cret", ["mcp.higgsfield.ai"], [])})
    with ve, rb:
        out = materialize_upstream_headers(
            _cfg({"Authorization": "Bearer shield://hf-token",
                  "ngrok-skip-browser-warning": "1"}), "acme")
    assert out["headers"]["ngrok-skip-browser-warning"] == "1"


# ── fail closed ──────────────────────────────────────────────────────


def test_unknown_reference_fails_closed():
    ve, rb = _vault({})
    with ve, rb, pytest.raises(GatewayError) as ei:
        materialize_upstream_headers(
            _cfg({"Authorization": "Bearer shield://missing"}), "acme")
    assert ei.value.status == 502


def test_binding_to_a_different_host_fails_closed():
    """The anti-exfil control: a secret bound to another vendor must not leak to
    this one just because an operator pasted the wrong ref."""
    ve, rb = _vault({"other": ("s3cret", ["api.stripe.com"], [])})
    with ve, rb, pytest.raises(GatewayError):
        materialize_upstream_headers(
            _cfg({"Authorization": "Bearer shield://other"}), "acme")


def test_vault_disabled_with_a_reference_fails_closed():
    """Rather than forwarding the literal placeholder as if it were a token."""
    with patch("core.secret_vault.keyprovider.vault_enabled", return_value=False), \
         pytest.raises(GatewayError):
        materialize_upstream_headers(
            _cfg({"Authorization": "Bearer shield://hf-token"}), "acme")


def test_opaque_token_form_also_fails_closed_when_unresolvable():
    ve, rb = _vault({})
    with ve, rb, pytest.raises(GatewayError):
        materialize_upstream_headers(_cfg({"X-Key": "svlt_deadbeef"}), "acme")


def test_error_names_the_header_but_never_the_secret():
    """An operator needs to know WHICH header to fix; the value must not appear
    in an error that will land in logs."""
    ve, rb = _vault({"other": ("s3cret", ["api.stripe.com"], [])})
    with ve, rb, pytest.raises(GatewayError) as ei:
        materialize_upstream_headers(
            _cfg({"Authorization": "Bearer shield://other"}), "acme")
    assert "Authorization" in ei.value.message
    assert "s3cret" not in ei.value.message


def test_one_bad_reference_fails_the_whole_connection():
    """Partially materialized credentials would produce a confusing upstream 401
    rather than an actionable Shield error."""
    ve, rb = _vault({"good": ("v", ["mcp.higgsfield.ai"], [])})
    with ve, rb, pytest.raises(GatewayError):
        materialize_upstream_headers(
            _cfg({"A": "shield://good", "B": "shield://missing"}), "acme")


# ── subdomain binding semantics come from the vault, unchanged ───────


def test_dot_prefixed_binding_covers_subdomains():
    ve, rb = _vault({"t": ("s3cret", [".higgsfield.ai"], [])})
    with ve, rb:
        out = materialize_upstream_headers(
            _cfg({"Authorization": "Bearer shield://t"}), "acme")
    assert out["headers"]["Authorization"] == "Bearer s3cret"


def test_exact_binding_does_not_cover_a_sibling_host():
    ve, rb = _vault({"t": ("s3cret", ["other.higgsfield.ai"], [])})
    with ve, rb, pytest.raises(GatewayError):
        materialize_upstream_headers(
            _cfg({"Authorization": "Bearer shield://t"}), "acme")
