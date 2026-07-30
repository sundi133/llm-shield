"""Single-use nonce claiming, shared by capability tokens and approval grants.

Both are single-use credentials, and both enforce it the same way: claim the
nonce atomically, and treat a second claim as a replay. That logic lived in two
places (`core/capabilities.py`, `core/approvals.py`) as identical copies, which
is how a fix reaches one and not the other.

Fail-closed, and why it is conditional
--------------------------------------
The claim is a Redis ``SET NX``. Redis is what makes it *global*: without it,
each worker has its own view, so one token burns once per worker and every one
of those reports first-use. A replay defence that degrades silently is worse
than one that is off, because nothing in the logs or the audit trail says it
stopped working.

So a *configured* store that fails raises rather than guessing. But "no Redis
configured at all" is a different situation — dev, tests, a single process —
where there is no cross-worker state to lose and nothing to protect. Failing
that closed would break every local run for no security gain. The two cases are
distinguished by whether ``_get_redis()`` hands back a client:

    None          -> never configured   -> local dict, as before
    client, raises-> configured, broken  -> NonceStoreUnavailable

``SHIELD_NONCE_LOCAL_FALLBACK=1`` restores the old behaviour for an operator who
would rather keep serving through a Redis incident and accepts replay-per-worker
as the price. It logs, so the degradation is visible.
"""

from __future__ import annotations

import logging
import os
import time

logger = logging.getLogger(__name__)


class NonceStoreUnavailable(Exception):
    """The nonce store was configured but could not be reached.

    Distinct from a replay: one means "this token was already used", the other
    means "we cannot tell". Conflating them sends whoever is on call looking for
    an attacker during what is actually a Redis outage.
    """


def _local_fallback_allowed() -> bool:
    return os.environ.get("SHIELD_NONCE_LOCAL_FALLBACK", "").strip().lower() in (
        "1", "true", "yes", "on")


def burn_nonce_if_unused(key: str, ttl: int) -> bool:
    """Atomically claim ``key``. True if first-use, False if already claimed.

    Raises ``NonceStoreUnavailable`` when Redis is configured but unreachable
    and the local-fallback escape hatch is off.
    """
    from storage.tenant_store import _fallback_store, _get_redis

    r = _get_redis()
    if r is not None:
        try:
            # nx=True -> only set if absent, so exactly one caller wins a race.
            return bool(r.set(key, "1", ex=ttl, nx=True))
        except Exception as exc:
            if not _local_fallback_allowed():
                # Deliberately avoids the word "replay": callers classify
                # security events by matching on the message, and an outage
                # logged as an attack sends people hunting the wrong thing.
                raise NonceStoreUnavailable(
                    f"nonce store unreachable ({exc.__class__.__name__}); "
                    "refusing to verify — set SHIELD_NONCE_LOCAL_FALLBACK=1 to "
                    "degrade to per-process nonce tracking instead"
                ) from exc
            logger.warning(
                "nonce store unreachable (%s); SHIELD_NONCE_LOCAL_FALLBACK is on, "
                "so replay protection is now PER-WORKER and a token may be "
                "replayed once per process until Redis returns",
                exc.__class__.__name__,
            )

    # Either Redis was never configured, or the operator opted into degrading.
    if key in _fallback_store:
        return False
    _fallback_store[key] = str(int(time.time()) + ttl)
    return True


def clear_prefix_for_tests(prefix: str) -> None:
    from storage.tenant_store import _fallback_store
    for k in list(_fallback_store.keys()):
        if k.startswith(prefix):
            _fallback_store.pop(k, None)
