"""Which policy the agent enforces, and why (spec §7 "Bundle trust").

  verified   the bundle's signature checks against the key MDM pinned, it is for
             this tenant and fleet, and it has not expired
  grace      verified but expired less than `grace_s` ago: still used, reported
             as stale_bundle
  fallback   no bundle, one that does not verify, one expired past grace, or an
             older version than one already accepted: the MDM-shipped fallback
             (secrets only), or the built-in one below

Never an older bundle: the highest bundle_version ever accepted is kept on
disk, and a lower one is refused (a replay of a looser policy). Time is the
later of the device clock and the last time Shield's own clock was seen, so
winding the laptop's clock back does not extend a bundle.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from votal_device_agent._deps import BundleError, verify_bundle

# Only what a leak of cannot wait: credentials with a recognisable shape.
# Redacted, not blocked: with no tenant policy the agent should protect without
# breaking anyone's work.
# Held equal to icap.config.DEFAULT_AI_HOSTS by a test.
DEFAULT_AI_HOSTS = (
    "chatgpt.com", "claude.ai", "gemini.google.com", "copilot.microsoft.com",
    "perplexity.ai", "grok.com", "deepseek.com", "meta.ai", "poe.com",
    "openai.com", "anthropic.com", "generativelanguage.googleapis.com",
    "githubcopilot.com", "api.cohere.ai", "mistral.ai", "api.groq.com",
    "api.x.ai", "openrouter.ai",
)

BUILTIN_FALLBACK = {
    "mode": "enforce",
    "ai_hosts": list(DEFAULT_AI_HOSTS),
    "rules": [
        {"id": "fallback-aws-access-key", "regex": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
         "action": "redact", "severity": "critical"},
        {"id": "fallback-private-key",
         "regex": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END "
                  r"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
         "action": "redact", "severity": "critical"},
        {"id": "fallback-github-token", "regex": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
         "action": "redact", "severity": "critical"},
        {"id": "fallback-slack-token", "regex": r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
         "action": "redact", "severity": "critical"},
        {"id": "fallback-stripe-live", "regex": r"\b[sr]k_live_[A-Za-z0-9]{20,}\b",
         "action": "redact", "severity": "critical"},
    ],
    "blocklists": [],
    "fail_mode": "allow",
}

REQUIRED = ("mode", "ai_hosts", "rules", "thresholds", "enforcement", "fail_mode")


@dataclass
class Trust:
    status: str                        # verified | grace | fallback
    policy: dict
    reason: str = ""
    header: dict = field(default_factory=dict)

    @property
    def state(self) -> str:
        """The heartbeat state this trust implies."""
        return {"verified": "ok", "grace": "stale_bundle"}.get(self.status, "no_bundle")

    @property
    def bundle_version(self) -> Optional[int]:
        return self.header.get("bundle_version")


class TrustStore:
    """Files in the agent's state directory:

      bundle.json        the last verified bundle
      trust_state.json   {max_bundle_version, last_server_time}
      fallback.json      optional, installed by MDM (secrets-only rules)
    """

    def __init__(self, state_dir: str | Path, *, tenant_id: str, fleet: str,
                 pinned_key_hex: str, fallback_path: Optional[str | Path] = None):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.bundle_path = self.dir / "bundle.json"
        self.state_path = self.dir / "trust_state.json"
        self.fallback_path = Path(fallback_path) if fallback_path else self.dir / "fallback.json"
        self.tenant_id, self.fleet, self.pinned = tenant_id, fleet, pinned_key_hex

    # ── persisted state ────────────────────────────────────────────────

    def _state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return {}

    def _save_state(self, **changes) -> None:
        s = {**self._state(), **changes}
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(s))
        os.replace(tmp, self.state_path)

    def observe_server_time(self, t: float) -> None:
        if t > float(self._state().get("last_server_time", 0)):
            self._save_state(last_server_time=int(t))

    def now(self) -> int:
        return int(max(time.time(), float(self._state().get("last_server_time", 0))))

    # ── checking ───────────────────────────────────────────────────────

    def check(self, bundle: dict) -> tuple[dict, dict]:
        """(policy, header) for a bundle that verifies (expired or not) and is not
        older than one already accepted. Raises BundleError."""
        policy = verify_bundle(bundle, public_key_hex=self.pinned, expect_tenant=self.tenant_id,
                               expect_fleet=self.fleet, now=self.now(), allow_expired=True)
        header = bundle["header"]
        version = int(header.get("bundle_version", 0))
        highest = int(self._state().get("max_bundle_version", 0))
        if version < highest:
            raise BundleError(f"bundle version {version} is older than {highest}, already "
                              f"accepted: refusing a rollback")
        missing = [k for k in REQUIRED if k not in policy]
        if missing:
            raise BundleError(f"bundle policy lacks {', '.join(missing)}")
        return policy, header

    def accept(self, bundle: dict) -> dict:
        """Verify and store a bundle downloaded from Shield. Raises BundleError;
        a bundle that does not verify is never written."""
        _policy, header = self.check(bundle)
        tmp = self.bundle_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(bundle))
        os.replace(tmp, self.bundle_path)
        self._save_state(max_bundle_version=max(int(header["bundle_version"]),
                                                int(self._state().get("max_bundle_version", 0))))
        return header

    def load(self) -> Trust:
        """The policy to enforce right now."""
        try:
            bundle = json.loads(self.bundle_path.read_text())
        except FileNotFoundError:
            return self._fallback("no bundle yet")
        except (OSError, ValueError) as e:
            return self._fallback(f"bundle unreadable: {e}")
        try:
            policy, header = self.check(bundle)
        except (BundleError, KeyError, TypeError, ValueError) as e:
            return self._fallback(f"bundle refused: {e}")
        now = self.now()
        expires = int(header.get("expires_at", 0))
        if now < expires:
            return Trust("verified", policy, "", header)
        grace = int(policy.get("grace_s", 0))
        if now < expires + grace:
            return Trust("grace", policy,
                         f"bundle expired {(now - expires) // 3600} h ago; grace ends in "
                         f"{(expires + grace - now) // 3600} h", header)
        return self._fallback(f"bundle expired {(now - expires) // 3600} h ago, past its "
                              f"{grace // 3600} h grace")

    def _fallback(self, reason: str) -> Trust:
        policy = dict(BUILTIN_FALLBACK)
        try:
            shipped = json.loads(self.fallback_path.read_text())
            if isinstance(shipped, dict) and isinstance(shipped.get("rules"), list):
                policy = {**policy, **{k: shipped[k] for k in ("rules", "blocklists", "mode",
                                                                "fail_mode", "ai_hosts")
                                       if k in shipped}}
                reason += "; using the MDM fallback rules"
            else:
                reason += "; using the built-in fallback rules"
        except (OSError, ValueError):
            reason += "; using the built-in fallback rules"
        return Trust("fallback", policy, reason, {})
