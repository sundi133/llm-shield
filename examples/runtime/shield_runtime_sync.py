#!/usr/bin/env python3
"""Fetch, verify and write a Shield runtime bundle for a sandbox.

Run this where the sandbox is created (the broker, CI runner or host), never
inside the sandbox: it uses the tenant API key.

    python examples/runtime/shield_runtime_sync.py \
        --shield https://api.guardrails.votal.ai --profile research-agent \
        --out ./research-agent.openshell.yaml
    openshell sandbox create --policy ./research-agent.openshell.yaml -- <agent command>

The key is read from the SHIELD_API_KEY environment variable (never a flag, so
it stays out of shell history and process listings).

What it guarantees:
  * The policy was signed by your Shield (EdDSA, checked against
    /v1/edge/runtime-bundle/jwks) and names this tenant, profile and target.
  * The artifact is byte-for-byte the one that was signed (sha256 in the claims).
  * Nothing is written unless both hold. Exit code 1 means "do not start".
    --allow-unsigned accepts a bundle from a Shield with no signing key
    configured (development only); a bad signature is never accepted.
  * With --etag-file, an unchanged bundle is a cheap 304 and the file stays as is.
  * With --hash-file, the verified profile hash is written for the broker to
    mint the sandbox's agent token with runtime_profile_hash (attestation).

Watch mode keeps RUNNING sandboxes on the current policy, with no restart
(docs/specs/runtime-live-policy.md §5.1):

    SHIELD_API_KEY=<admin-scoped key> python examples/runtime/shield_runtime_sync.py \
        --shield https://api.guardrails.votal.ai --profile research-agent \
        --out ./research-agent.openshell.yaml --watch 30 --sandbox-prefix research-

  * Every --watch seconds it polls the bundle (a 304 when unchanged). A new
    verified bundle is applied to each managed sandbox with
    `openshell policy set NAME --policy OUT --wait`.
  * What OpenShell refuses on a running sandbox (a removed filesystem path, a
    process change) leaves that sandbox on its old policy, reported as
    restart_required. Shield never restarts sandboxes; the broker decides.
  * Each result is reported to /v1/shield/runtime/events. Use an admin-scoped
    key: only its reports let a live-updated sandbox pass attestation.
  * Fail static: Shield unreachable, the profile deleted or a bad signature
    never removes or changes a sandbox's policy.
  * Reconcile: a policy changed outside Shield (`openshell policy set`, a
    draft approved in `openshell term`) is reported as tampered, with each
    rule it added, and with --reconcile revert (default) Shield's policy is
    put back within one tick. --reconcile report only reports (development).
  * --lock global applies the policy as OpenShell's gateway-global policy:
    OpenShell then refuses sandbox-level changes and draft approvals, so there
    is no window at all. It is gateway wide, so the sidecar refuses it while
    the gateway runs any sandbox it does not manage.

Needs the `cryptography` package (already a Shield dependency).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class FetchError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _fetch(url: str, key: str, etag: str | None = None):
    """(status, body, etag). Raises FetchError on an HTTP error and OSError
    (URLError) when Shield cannot be reached."""
    headers = {"X-API-Key": key}
    if etag:
        headers["If-None-Match"] = etag
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}"), r.headers.get("ETag")
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return 304, None, etag
        raise FetchError(e.code, f"shield: {url} -> HTTP {e.code}: {e.read()[:300]!r}")


def _get(url: str, key: str, etag: str | None = None):
    try:
        return _fetch(url, key, etag)
    except FetchError as e:
        raise SystemExit(str(e))


def verify(bundle: dict, jwks: dict, *, tenant: str | None, profile: str, target: str) -> dict:
    """Raise ValueError unless the bundle's signature and claims check out."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    token = bundle.get("signature") or ""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("bundle signature is not a compact JWS")
    h, p, s = parts
    header = json.loads(_b64d(h))
    if header.get("alg") != "EdDSA":
        raise ValueError(f"unexpected signature algorithm {header.get('alg')!r}")
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if key is None:
        raise ValueError(f"no published key for kid {header.get('kid')!r}")
    try:
        Ed25519PublicKey.from_public_bytes(_b64d(key["x"])).verify(_b64d(s), f"{h}.{p}".encode())
    except InvalidSignature:
        raise ValueError("bundle signature does not verify") from None
    claims = json.loads(_b64d(p))
    digest = "sha256:" + hashlib.sha256(bundle["artifact"].encode("utf-8")).hexdigest()
    checks = {
        "aud": (claims.get("aud"), "shield-runtime-bundle"),
        "profile": (claims.get("profile"), profile),
        "target": (claims.get("target"), target),
        "artifact_sha256": (claims.get("artifact_sha256"), digest),
    }
    if tenant:
        checks["tenant_id"] = (claims.get("tenant_id"), tenant)
    for name, (got, want) in checks.items():
        if got != want:
            raise ValueError(f"claim {name} is {got!r}, expected {want!r}")
    return claims


# ── watch mode ───────────────────────────────────────────────────────

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_SUBMITTED = re.compile(r"Policy version (\d+) submitted \(hash: ([0-9a-f]+)\)")
_LOADED = re.compile(r"active version: (\d+)")
#: How OpenShell 0.0.80 words a change it cannot make to a running sandbox.
LIVE_REFUSED = "on a live sandbox"


def _clean(text: str) -> str:
    """OpenShell CLI output without colours, box drawing or line wrapping."""
    text = _ANSI.sub("", text or "")
    text = text.replace("│", " ").replace("×", " ").replace("✓", " ")
    text = re.sub(r"^\s*Error:\s*", "", text.strip())
    m = re.search(r'message:\s*"(.*)"', " ".join(text.split()))
    return m.group(1) if m else " ".join(text.split())


class OpenShell:
    """The few OpenShell CLI calls the watcher needs (checked against 0.0.80)."""

    def __init__(self, binary: str = "openshell", gateway: str | None = None,
                 timeout: float = 90):
        self.binary, self.gateway, self.timeout = binary, gateway, timeout

    def _run(self, *args: str):
        cmd = [self.binary] + (["-g", self.gateway] if self.gateway else []) + list(args)
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout,
                               env={**os.environ, "NO_COLOR": "1"})
            return p.returncode, p.stdout, p.stderr
        except FileNotFoundError:
            return 127, "", f"{self.binary}: not found"
        except subprocess.TimeoutExpired:
            return 124, "", f"{' '.join(cmd[:4])}: timed out after {self.timeout}s"

    def sandbox_names(self) -> list[str] | None:
        rc, out, _ = self._run("sandbox", "list", "--names")
        if rc != 0:
            return None
        return [n.strip() for n in _ANSI.sub("", out).splitlines() if n.strip()]

    def set_policy(self, name: str, path: str) -> dict:
        rc, out, err = self._run("policy", "set", name, "--policy", path, "--wait")
        text = _ANSI.sub("", out + "\n" + err)
        sub, loaded = _SUBMITTED.search(text), _LOADED.search(text)
        message = "" if rc == 0 else _clean(err or out)
        return {"ok": rc == 0, "version": int(loaded.group(1)) if loaded else
                (int(sub.group(1)) if sub else None),
                "hash": sub.group(2) if sub else "", "message": message,
                "live_refused": rc != 0 and LIVE_REFUSED in message}

    def policy(self, name: str, full: bool = False) -> dict | None:
        """``policy get NAME -o json``: {hash, version, policy_source, ...};
        with ``full``, also the effective ``policy`` payload."""
        return self._json("policy", "get", name, *(["--full"] if full else []), "-o", "json")

    def set_global(self, path: str) -> dict:
        rc, out, err = self._run("policy", "set", "--global", "--yes", "--policy", path)
        m = re.search(r"hash: ([0-9a-f]+)", _ANSI.sub("", out + err))
        message = "" if rc == 0 else _clean(err or out)
        return {"ok": rc == 0, "version": None, "hash": m.group(1) if m else "",
                "message": message, "live_refused": rc != 0 and LIVE_REFUSED in message}

    def global_policy(self, full: bool = False) -> dict | None:
        """The gateway-global policy, or None. ``status`` is ``superseded``
        once the lock has been deleted."""
        return self._json("policy", "get", "--global", *(["--full"] if full else []),
                          "-o", "json")

    def _json(self, *args: str) -> dict | None:
        rc, out, _ = self._run(*args)
        if rc != 0:
            return None
        try:
            doc = json.loads(out)
        except ValueError:
            return None
        return doc if isinstance(doc, dict) else None


def endpoints(policy_doc: dict | None) -> set[tuple]:
    """(host, port, method, path) for every allow rule in an OpenShell policy
    payload; an endpoint with no L7 rules allows everything on it."""
    out: set[tuple] = set()
    for rule in ((policy_doc or {}).get("network_policies") or {}).values():
        for ep in (rule or {}).get("endpoints") or []:
            host, port = str(ep.get("host", "")), int(ep.get("port") or 0)
            allows = [r.get("allow") or {} for r in ep.get("rules") or [] if r.get("allow")]
            if not allows:
                out.add((host, port, "*", "/**"))
            for a in allows:
                out.add((host, port, str(a.get("method") or "*"), str(a.get("path") or "/**")))
    return out


class Reporter:
    """Queues sidecar reports and posts them to /v1/shield/runtime/events.
    A failed post keeps them for the next tick (capped), so a Shield outage
    never blocks enforcement."""

    MAX_QUEUE = 500

    def __init__(self, shield: str, key: str, profile: str, post=None):
        self.url = shield.rstrip("/") + "/v1/shield/runtime/events"
        self.key, self.profile = key, profile
        self.queue: list[dict] = []
        self._post = post or self._http_post

    def report(self, instance: str, op: str, profile_hash: str, *,
               severity: str | None = None, **detail) -> None:
        ev = {"source": "openshell", "kind": "policy", "decision": "audit",
              "profile": self.profile, "profile_hash": profile_hash or "",
              "agent_instance_id": instance, "at": time.time(),
              "detail": {"op": op, "instance": instance,
                         **{k: v for k, v in detail.items() if v not in (None, "")}}}
        if severity:
            ev["severity"] = severity
        self.queue.append(ev)
        del self.queue[:-self.MAX_QUEUE]

    def out_of_band(self, instance: str, endpoint: tuple) -> None:
        """A rule someone added to the sandbox outside Shield. Shield's advisor
        turns it into a suggestion an operator can approve properly."""
        host, port, method, path = endpoint
        self.queue.append({
            "source": "openshell", "kind": "network", "decision": "audit",
            "severity": "high", "profile": self.profile, "agent_instance_id": instance,
            "at": time.time(),
            "detail": {"host": host, "port": port, "method": method, "path": path,
                       "out_of_band": True}})
        del self.queue[:-self.MAX_QUEUE]

    def _http_post(self, events: list[dict]) -> bool:
        req = urllib.request.Request(
            self.url, data=json.dumps({"events": events}).encode(), method="POST",
            headers={"X-API-Key": self.key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status == 202
        except (urllib.error.URLError, OSError):
            return False

    def flush(self) -> None:
        while self.queue:
            batch = self.queue[:100]
            if not self._post(batch):
                return
            del self.queue[:len(batch)]


class Watcher:
    """One tick: poll the bundle, reconcile, then bring every managed sandbox
    onto the current policy.

    State per sandbox, as this watcher last applied it: the profile hash, and
    OpenShell's own view of that policy (its hash and the endpoints it
    allows). Reconcile compares the live policy with that record: a change
    nobody made through Shield is `tampered`, reported with the rules it
    added, and with --reconcile revert the recorded policy is put back.

    --lock global applies the policy as OpenShell's gateway-global policy,
    which refuses sandbox-level changes and draft approvals outright. It is
    gateway wide, so it is only used when every sandbox on the gateway is
    managed here.
    """

    GLOBAL = "*global*"
    KEEP_ARTIFACTS = 5

    def __init__(self, *, shield: str, key: str, profile: str, target: str, out: str,
                 tenant: str | None = None, shield_url: str | None = None,
                 sandboxes=(), prefix: str | None = None, allow_unsigned: bool = False,
                 lock: str = "none", reconcile: str = "revert",
                 shell: OpenShell | None = None, reporter: Reporter | None = None,
                 fetch=None, log=None):
        self.base, self.key, self.profile, self.target = shield.rstrip("/"), key, profile, target
        self.out, self.tenant, self.shield_url = out, tenant, shield_url
        self.explicit, self.prefix, self.allow_unsigned = list(sandboxes), prefix, allow_unsigned
        self.lock, self.reconcile = lock, reconcile
        self.shell = shell or OpenShell()
        self.reporter = reporter or Reporter(shield, key, profile)
        self.fetch = fetch or _fetch
        self.log = log or (lambda msg: print(msg, file=sys.stderr, flush=True))
        self.etag: str | None = None
        self.bundle: dict | None = None          # last VERIFIED bundle
        self.artifacts: dict[str, str] = {}      # profile hash -> verified artifact
        #: sandbox (or GLOBAL) -> {profile_hash, runtime_hash, endpoints}
        self.running: dict[str, dict] = {}
        self.refused: dict[str, str] = {}        # sandbox -> profile hash OpenShell refused live
        self._tamper_seen: dict[str, str] = {}   # sandbox -> live hash already reported
        self._bad: str | None = None             # etag of a bundle that failed verification

    # ── what to manage ───────────────────────────────────────────────

    def _bundle_url(self) -> str:
        q = {"profile": self.profile, "target": self.target}
        if self.shield_url:
            q["shield_url"] = self.shield_url
        return f"{self.base}/v1/edge/runtime-bundle?{urllib.parse.urlencode(q)}"

    def managed(self) -> list[str]:
        names = list(self.explicit)
        if self.prefix:
            listed = self.shell.sandbox_names()
            if listed is None:                   # gateway unreachable: keep what we know
                listed = [n for n in self.running if n != self.GLOBAL]
            names += [n for n in listed if n.startswith(self.prefix)]
        return sorted(set(names))

    def unmanaged(self) -> list[str] | None:
        """Sandboxes on the gateway this watcher does not manage (None when
        the gateway cannot be listed)."""
        listed = self.shell.sandbox_names()
        if listed is None:
            return None
        mine = set(self.managed())
        return sorted(n for n in listed if n not in mine)

    # ── bundle ───────────────────────────────────────────────────────

    def poll(self) -> None:
        try:
            status, bundle, etag = self.fetch(self._bundle_url(), self.key, self.etag)
        except FetchError as e:
            self.log(f"keeping the last verified policy: {e}")
            return
        except OSError as e:
            self.log(f"shield unreachable, keeping the last verified policy: {e}")
            return
        if status == 304 or bundle is None:
            return
        problem = self._verify(bundle)
        if problem:
            if etag != self._bad:                # report each bad version once
                self._bad = etag
                self.log(f"REFUSED bundle: {problem}. Sandboxes keep their current policy.")
                for sb in self.managed():
                    self.reporter.report(sb, "apply_failed", self._runs(sb), severity="critical",
                                         target_hash=bundle.get("profile_hash", ""),
                                         message=f"bundle refused: {problem}")
            return
        tmp = self.out + ".tmp"
        with open(tmp, "w") as f:
            f.write(bundle["artifact"])
        os.replace(tmp, self.out)
        self.bundle, self.etag, self._bad = bundle, etag, None
        self.artifacts[bundle["profile_hash"]] = bundle["artifact"]
        for old in list(self.artifacts)[:-self.KEEP_ARTIFACTS]:
            self.artifacts.pop(old, None)
        self.log(f"new policy {bundle['profile_hash'][:19]}... written to {self.out}")

    def _verify(self, bundle: dict) -> str | None:
        if bundle.get("signed"):
            try:
                _, jwks, _ = self.fetch(f"{self.base}/v1/edge/runtime-bundle/jwks", self.key)
                verify(bundle, jwks, tenant=self.tenant, profile=self.profile,
                       target=self.target)
            except (ValueError, KeyError, FetchError, OSError) as e:
                return str(e)
            return None
        return None if self.allow_unsigned else "bundle is unsigned"

    def _runs(self, sb: str) -> str:
        return (self.running.get(sb) or {}).get("profile_hash", "")

    def _artifact_file(self, profile_hash: str) -> str | None:
        """A file holding the verified artifact for ``profile_hash``."""
        if self.bundle and profile_hash == self.bundle["profile_hash"]:
            return self.out
        artifact = self.artifacts.get(profile_hash)
        if artifact is None:
            return None
        path = self.out + ".revert"
        with open(path, "w") as f:
            f.write(artifact)
        return path

    def _extra(self) -> dict:
        return {"lock": self.lock, "reconcile": self.reconcile}

    # ── converge: bring sandboxes onto the current bundle ────────────

    def converge(self) -> None:
        if self.bundle is None:
            return
        if self.lock == "global":
            self._converge_global()
            return
        want = self.bundle["profile_hash"]
        names = self.managed()
        for gone in set(self.running) - set(names):
            self.running.pop(gone, None)
            self.refused.pop(gone, None)
            self._tamper_seen.pop(gone, None)
        for sb in names:
            if self._runs(sb) == want or self.refused.get(sb) == want:
                continue                          # current, or needs a restart
            self.apply(sb)

    def _record(self, key: str, profile_hash: str, live: dict | None, fallback_hash: str) -> dict:
        live = live or {}
        state = {"profile_hash": profile_hash,
                 "runtime_hash": live.get("hash") or fallback_hash,
                 "endpoints": endpoints(live.get("policy"))}
        self.running[key] = state
        if self.refused.get(key) == profile_hash:
            # Only now does the sandbox run what OpenShell refused live; a
            # revert to an older policy leaves the refusal standing.
            self.refused.pop(key, None)
        self._tamper_seen.pop(key, None)
        return state

    def apply(self, sb: str, profile_hash: str | None = None, op: str = "applied") -> bool:
        want = profile_hash or self.bundle["profile_hash"]
        path = self._artifact_file(want)
        if path is None:
            return False
        have = self._runs(sb)
        res = self.shell.set_policy(sb, path)
        if res["ok"]:
            state = self._record(sb, want, self.shell.policy(sb, full=True), res["hash"])
            self.reporter.report(sb, op, want, runtime_hash=state["runtime_hash"],
                                 runtime_version=res["version"], **self._extra())
            self.log(f"{sb}: policy {want[:19]}... {op} live (version {res['version']})")
            return True
        if res["live_refused"]:
            self.refused[sb] = want
            self.reporter.report(sb, "restart_required", have, target_hash=want,
                                 message=res["message"], **self._extra())
            self.log(f"{sb}: needs a restart to take {want[:19]}...: {res['message']}")
        else:
            self.reporter.report(sb, "apply_failed", have, target_hash=want,
                                 message=res["message"], **self._extra())
            self.log(f"{sb}: apply failed, retrying next tick: {res['message']}")
        return False

    def _converge_global(self) -> None:
        want = self.bundle["profile_hash"]
        if self._runs(self.GLOBAL) == want or self.refused.get(self.GLOBAL) == want:
            return
        self.apply_global(want)

    def apply_global(self, want: str, op: str = "applied") -> bool:
        names = self.managed()
        unmanaged = self.unmanaged()
        if unmanaged:
            # A global policy would silently replace their policies too.
            if self.refused.get("*unsafe*") != want:
                self.refused["*unsafe*"] = want
                for sb in names:
                    self.reporter.report(sb, "apply_failed", self._runs(sb), severity="critical",
                                         target_hash=want, **self._extra(),
                                         message="not applied: the gateway also runs "
                                                 f"unmanaged sandboxes {', '.join(unmanaged)}")
                self.log(f"REFUSED global lock: unmanaged sandboxes {unmanaged}")
            return False
        path = self._artifact_file(want)
        if path is None:
            return False
        have = self._runs(self.GLOBAL)
        res = self.shell.set_global(path)
        if res["ok"]:
            state = self._record(self.GLOBAL, want, self.shell.global_policy(full=True),
                                 res["hash"])
            self.refused.pop("*unsafe*", None)
            for sb in names:
                self.running[sb] = dict(state)
                self.reporter.report(sb, op, want, runtime_hash=state["runtime_hash"],
                                     **self._extra())
            self.log(f"gateway-global policy {want[:19]}... {op}")
            return True
        if res["live_refused"]:
            self.refused[self.GLOBAL] = want
        for sb in names:
            self.reporter.report(sb, "restart_required" if res["live_refused"] else
                                 "apply_failed", have, target_hash=want,
                                 message=res["message"], **self._extra())
        self.log(f"global policy not applied: {res['message']}")
        return False

    # ── reconcile: catch changes made outside Shield ─────────────────

    def reconcile_all(self) -> None:
        if self.lock == "global":
            self._reconcile_global()
            return
        for sb in self.managed():
            if sb in self.running:
                self._reconcile(sb)

    def _tampered(self, sb: str, base: dict, live: dict, added: set, why: str) -> None:
        self.reporter.report(sb, "tampered", base["profile_hash"],
                             runtime_hash=live.get("hash", ""),
                             runtime_version=live.get("version"),
                             message=f"{why}; expected runtime hash "
                                     f"{base['runtime_hash'][:12]}, found "
                                     f"{(live.get('hash') or 'none')[:12]}; "
                                     f"{len(added)} rule(s) added",
                             **self._extra())
        for ep in sorted(added):
            self.reporter.out_of_band(sb, ep)

    def _reconcile(self, sb: str) -> None:
        base = self.running[sb]
        live = self.shell.policy(sb)
        if live is None or live.get("hash") == base["runtime_hash"]:
            if live is not None:
                self._tamper_seen.pop(sb, None)
            return
        if self._tamper_seen.get(sb) == live.get("hash"):
            return                               # report mode: already reported
        self._tamper_seen[sb] = live.get("hash", "")
        full = self.shell.policy(sb, full=True) or {}
        added = endpoints(full.get("policy")) - base["endpoints"]
        why = ("sandbox policy changed outside Shield" if live.get("policy_source") != "global"
               else "a gateway-global policy not managed by Shield replaced it")
        self._tampered(sb, base, live, added, why)
        self.log(f"{sb}: TAMPERED ({why}, {len(added)} rule(s) added)")
        if self.reconcile == "revert":
            self.apply(sb, base["profile_hash"], op="reverted")

    def _reconcile_global(self) -> None:
        base = self.running.get(self.GLOBAL)
        if base is None:
            return
        live = self.shell.global_policy()
        if live is None:
            return
        active = live.get("status") != "superseded"
        if active and live.get("hash") == base["runtime_hash"]:
            self._tamper_seen.pop(self.GLOBAL, None)
            return
        seen = f"{live.get('hash')}:{active}"
        if self._tamper_seen.get(self.GLOBAL) == seen:
            return
        self._tamper_seen[self.GLOBAL] = seen
        added = set()
        if active:
            added = endpoints((self.shell.global_policy(full=True) or {}).get("policy")) \
                - base["endpoints"]
        why = "the gateway-global lock was replaced" if active else \
            "the gateway-global lock was deleted"
        for sb in self.managed():
            self._tampered(sb, base, live if active else {}, added, why)
        self.log(f"TAMPERED: {why}")
        if self.reconcile == "revert":
            self.apply_global(base["profile_hash"], op="reverted")

    def tick(self) -> None:
        self.poll()
        self.reconcile_all()      # before converge, so a tamper is never silently overwritten
        self.converge()
        self.reporter.flush()


def watch(args, key: str) -> int:
    if not (args.sandbox or args.sandbox_prefix):
        print("--watch needs --sandbox NAME or --sandbox-prefix PREFIX", file=sys.stderr)
        return 1
    w = Watcher(shield=args.shield, key=key, profile=args.profile, target=args.target,
                out=args.out, tenant=args.tenant, shield_url=args.shield_url,
                sandboxes=args.sandbox or [], prefix=args.sandbox_prefix,
                allow_unsigned=args.allow_unsigned, lock=args.lock, reconcile=args.reconcile,
                shell=OpenShell(args.openshell, args.gateway))
    if args.lock == "global":
        unmanaged = w.unmanaged()
        if unmanaged is None:
            print("--lock global: cannot list the gateway's sandboxes", file=sys.stderr)
            return 1
        if unmanaged:
            print(f"--lock global would also replace the policy of sandboxes this sidecar "
                  f"does not manage: {', '.join(unmanaged)}. Use a gateway dedicated to "
                  f"profile '{args.profile}', or --lock none.", file=sys.stderr)
            return 1
    n = 0
    while True:
        w.tick()
        n += 1
        if args.ticks and n >= args.ticks:
            return 0
        time.sleep(args.watch)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--shield", required=True, help="Shield base URL")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--target", default="openshell")
    ap.add_argument("--out", required=True, help="where to write the policy file")
    ap.add_argument("--tenant", help="expected tenant id (recommended)")
    ap.add_argument("--shield-url", help="Shield URL as the sandbox reaches it, if different")
    ap.add_argument("--etag-file", help="remember the bundle version between runs")
    ap.add_argument("--hash-file", help="write the verified profile hash here, for the broker "
                                        "to put in the agent token (runtime_profile_hash)")
    ap.add_argument("--allow-unsigned", action="store_true",
                    help="accept an unsigned bundle (development only)")
    w = ap.add_argument_group("watch mode (keep running sandboxes on the current policy)")
    w.add_argument("--watch", type=float, metavar="SECONDS",
                   help="poll every SECONDS and apply changes to running sandboxes")
    w.add_argument("--sandbox", action="append", metavar="NAME",
                   help="a sandbox to manage (repeatable)")
    w.add_argument("--sandbox-prefix", metavar="PREFIX",
                   help="manage every sandbox whose name starts with PREFIX")
    w.add_argument("--reconcile", choices=("revert", "report"), default="revert",
                   help="a policy changed outside Shield: put Shield's back (default) or "
                        "only report it (development)")
    w.add_argument("--lock", choices=("none", "global"), default="none",
                   help="global: apply as OpenShell's gateway-global policy, which refuses "
                        "any other change; needs a gateway running only this profile")
    w.add_argument("--openshell", default="openshell", help="OpenShell CLI binary")
    w.add_argument("--gateway", help="OpenShell gateway name (openshell -g)")
    w.add_argument("--ticks", type=int, default=0, help="stop after N ticks (0: run forever)")
    args = ap.parse_args()

    key = os.environ.get("SHIELD_API_KEY", "").strip()
    if not key:
        print("set SHIELD_API_KEY", file=sys.stderr)
        return 1
    if args.watch is not None:
        return watch(args, key)
    base = args.shield.rstrip("/")
    q = {"profile": args.profile, "target": args.target}
    if args.shield_url:
        q["shield_url"] = args.shield_url
    etag = None
    if args.etag_file and os.path.exists(args.etag_file) and os.path.exists(args.out):
        etag = open(args.etag_file).read().strip() or None

    status, bundle, new_etag = _get(f"{base}/v1/edge/runtime-bundle?{urllib.parse.urlencode(q)}",
                                    key, etag)
    if status == 304:
        print(f"unchanged: {args.out}")
        return 0

    if bundle.get("signed"):
        _, jwks, _ = _get(f"{base}/v1/edge/runtime-bundle/jwks", key)
        try:
            claims = verify(bundle, jwks, tenant=args.tenant, profile=args.profile,
                            target=args.target)
        except ValueError as e:
            print(f"REFUSED: {e}. Nothing written; do not start the sandbox.", file=sys.stderr)
            return 1
        print(f"verified: signed by kid {json.loads(_b64d(bundle['signature'].split('.')[0]))['kid']}"
              f", profile {claims['profile']} {claims['profile_hash']}")
    elif args.allow_unsigned:
        print("WARNING: bundle is unsigned (this Shield has no SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY)",
              file=sys.stderr)
    else:
        print("REFUSED: bundle is unsigned. Configure SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY on "
              "Shield, or pass --allow-unsigned for development.", file=sys.stderr)
        return 1

    tmp = args.out + ".tmp"
    with open(tmp, "w") as f:
        f.write(bundle["artifact"])
    os.replace(tmp, args.out)
    if args.hash_file:
        with open(args.hash_file, "w") as f:
            f.write(bundle["profile_hash"])
    if args.etag_file and new_etag:
        with open(args.etag_file, "w") as f:
            f.write(new_etag)
    for u in bundle.get("unsupported") or []:
        print(f"not enforced by {args.target}: {u}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
