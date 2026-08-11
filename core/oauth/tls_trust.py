"""Outbound TLS trust for the OIDC path, so it works behind a private CA.

An on-prem IdP — Keycloak, ADFS, Entra on a private endpoint — almost always
presents a certificate signed by the organisation's own CA. httpx does not use
the system trust store: it builds its context from the bundled `certifi` CAs.
So every discovery and JWKS fetch fails with "certificate verify failed" on
exactly the deployments this product is sold into, and nothing in the error
says "add your CA".

`SHIELD_OIDC_CA_BUNDLE=/etc/ssl/certs/internal-ca.pem` fixes that for every
outbound call in this package.

The bundle is validated when it is read, not when TLS fails. Python's
ssl.create_default_context() silently ignores a missing SSL_CERT_FILE and falls
back to the system store, so a typo'd path presents as a certificate error
rather than a missing file — the single most confusing way this can fail.

Air-gapped deployments need nothing here beyond the bundle: the only hosts
contacted are the issuer configured for the tenant, and nothing in this package
reaches a vendor endpoint.
"""
import logging
import os
import ssl
from typing import Optional, Union

logger = logging.getLogger("votal.oauth.tls")

_ENV_VAR = "SHIELD_OIDC_CA_BUNDLE"

# ssl contexts are not cheap to build and the bundle does not change at
# runtime. Keyed by path so a test that changes the env var is not served a
# stale context.
_context_cache: dict = {}


class CABundleError(RuntimeError):
    """The configured CA bundle cannot be used. Never fall back silently."""


def ca_bundle_path() -> str:
    """The configured bundle path, or "" for the default trust store."""
    return (os.environ.get(_ENV_VAR, "") or "").strip()


def _validated_path() -> str:
    path = ca_bundle_path()
    if not path:
        return ""
    if not os.path.isfile(path):
        raise CABundleError(
            f"{_ENV_VAR} points at {path!r}, which does not exist or is not a "
            f"file. Outbound TLS to your IdP would fall back to the default "
            f"trust store and fail with a certificate error that does not "
            f"mention this setting."
        )
    if not os.access(path, os.R_OK):
        raise CABundleError(
            f"{_ENV_VAR} points at {path!r}, which is not readable by this "
            f"process. Check the file mode and the container user."
        )
    return path


def httpx_verify() -> Union[bool, str]:
    """What to pass as httpx's `verify=`.

    A path when a bundle is configured, True otherwise. Never False: an
    on-prem deployment that cannot verify its own IdP has a configuration
    problem, and disabling verification would hide it behind a working login.
    """
    return _validated_path() or True


def ssl_context() -> Optional[ssl.SSLContext]:
    """An SSLContext for callers that take one, e.g. PyJWKClient.

    None when no bundle is configured, which lets the caller keep its own
    default rather than us imposing one.
    """
    path = _validated_path()
    if not path:
        return None
    cached = _context_cache.get(path)
    if cached is not None:
        return cached
    try:
        ctx = ssl.create_default_context(cafile=path)
    except Exception as e:
        raise CABundleError(f"{_ENV_VAR}={path!r} could not be loaded: {e}")
    _context_cache[path] = ctx
    return ctx


def warn_if_unset_and_issuer_is_private(issuer: str) -> None:
    """Log once when an issuer looks internal and no bundle is configured.

    A hint, not a check. It turns the most common on-prem failure from a bare
    TLS error into a line that names the setting to change.
    """
    if ca_bundle_path() or not issuer:
        return
    host = issuer.split("://")[-1].split("/")[0].split(":")[0]
    looks_internal = (
        "." not in host
        or host.endswith((".local", ".internal", ".lan", ".corp", ".intranet"))
    )
    if looks_internal:
        logger.info(
            "OIDC issuer %s looks internal and %s is not set. If its "
            "certificate is signed by a private CA, set %s to that CA bundle.",
            issuer, _ENV_VAR, _ENV_VAR,
        )
