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

# The same CA as inline PEM, for platforms with no way to mount a file.
# Railway, Fly, Heroku and a plain Kubernetes Secret all hand you environment
# variables and nothing else, so a path-only setting is unusable there. The
# content is written once to a private temp file, because both httpx and
# ssl.SSLContext want a path.
_ENV_VAR_PEM = "SHIELD_OIDC_CA_PEM"

_materialized_pem: Optional[str] = None

# ssl contexts are not cheap to build and the bundle does not change at
# runtime. Keyed by path so a test that changes the env var is not served a
# stale context.
_context_cache: dict = {}


class CABundleError(RuntimeError):
    """The configured CA bundle cannot be used. Never fall back silently."""


def ca_bundle_path() -> str:
    """The configured bundle path, or "" for the default trust store."""
    return (os.environ.get(_ENV_VAR, "") or "").strip()


def ca_bundle_pem() -> str:
    """Inline PEM content, or "" when not configured."""
    return (os.environ.get(_ENV_VAR_PEM, "") or "").strip()


def _materialize_pem() -> str:
    """Write inline PEM to a private temp file and return its path.

    Cached for the process: rewriting per request would churn temp files and
    make the path unstable underneath a cached SSLContext.
    """
    global _materialized_pem
    if _materialized_pem and os.path.isfile(_materialized_pem):
        return _materialized_pem

    pem = ca_bundle_pem()
    # Tolerate a value pasted with literal \n, which is what happens when a PEM
    # is squeezed through a dashboard field or a shell that ate the newlines.
    # Without this the file is one long line and OpenSSL rejects it with an
    # error about the certificate rather than about the formatting.
    if "\\n" in pem and "-----BEGIN" in pem:
        pem = pem.replace("\\n", "\n")
    if "-----BEGIN" not in pem:
        raise CABundleError(
            f"{_ENV_VAR_PEM} is set but does not contain a PEM certificate "
            f"(no -----BEGIN----- line). Paste the full certificate including "
            f"its header and footer.")

    import tempfile
    fd, path = tempfile.mkstemp(prefix="shield-oidc-ca-", suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem if pem.endswith("\n") else pem + "\n")
        os.chmod(path, 0o600)
    except Exception as e:
        raise CABundleError(f"{_ENV_VAR_PEM} could not be written to disk: {e}")

    _materialized_pem = path
    logger.info("Using inline CA bundle from %s", _ENV_VAR_PEM)
    return path


def _validated_path() -> str:
    path = ca_bundle_path()
    if not path:
        # Path wins when both are set: an operator who mounted a file meant it,
        # and silently preferring an inherited platform variable over their
        # explicit mount is the kind of surprise that costs a day.
        if ca_bundle_pem():
            return _materialize_pem()
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
    # Keyed on the file's identity, not just its path. A CA rotated in place —
    # which is exactly what cert-manager, a config-map remount or an Ansible
    # run does — would otherwise be ignored until the process restarted, and
    # the symptom is TLS failures that a restart "mysteriously" fixes.
    try:
        stat = os.stat(path)
        fingerprint = (path, stat.st_mtime_ns, stat.st_size)
    except OSError as e:
        raise CABundleError(f"{_ENV_VAR}={path!r} could not be read: {e}")

    cached = _context_cache.get(fingerprint)
    if cached is not None:
        return cached
    try:
        ctx = ssl.create_default_context(cafile=path)
    except Exception as e:
        raise CABundleError(f"{_ENV_VAR}={path!r} could not be loaded: {e}")
    # One entry per rotation, and rotations are rare — but unbounded growth in
    # a long-lived process is still a leak, so keep only the current one.
    _context_cache.clear()
    _context_cache[fingerprint] = ctx
    logger.info("Loaded CA bundle %s (%d bytes)", path, stat.st_size)
    return ctx


def warn_if_unset_and_issuer_is_private(issuer: str) -> None:
    """Log once when an issuer looks internal and no bundle is configured.

    A hint, not a check. It turns the most common on-prem failure from a bare
    TLS error into a line that names the setting to change.
    """
    if ca_bundle_path() or ca_bundle_pem() or not issuer:
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
