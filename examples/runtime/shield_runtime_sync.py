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

    def policy(self, name: str) -> dict | None:
        rc, out, _ = self._run("policy", "get", name, "-o", "json")
        if rc != 0:
            return None
        try:
            return json.loads(out)
        except ValueError:
            return None


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
    """One tick: poll the bundle, then bring every managed sandbox onto it.

    State per sandbox: the profile hash it runs (as far as this watcher
    applied it) and, when OpenShell refused a live change, the hash it
    refused, so that change is not retried until the profile moves again.
    """

    def __init__(self, *, shield: str, key: str, profile: str, target: str, out: str,
                 tenant: str | None = None, shield_url: str | None = None,
                 sandboxes=(), prefix: str | None = None, allow_unsigned: bool = False,
                 shell: OpenShell | None = None, reporter: Reporter | None = None,
                 fetch=None, log=None):
        self.base, self.key, self.profile, self.target = shield.rstrip("/"), key, profile, target
        self.out, self.tenant, self.shield_url = out, tenant, shield_url
        self.explicit, self.prefix, self.allow_unsigned = list(sandboxes), prefix, allow_unsigned
        self.shell = shell or OpenShell()
        self.reporter = reporter or Reporter(shield, key, profile)
        self.fetch = fetch or _fetch
        self.log = log or (lambda msg: print(msg, file=sys.stderr, flush=True))
        self.etag: str | None = None
        self.bundle: dict | None = None          # last VERIFIED bundle
        self.running: dict[str, dict] = {}       # sandbox -> {profile_hash, runtime_hash}
        self.refused: dict[str, str] = {}        # sandbox -> profile hash OpenShell refused live
        self._bad: str | None = None             # etag of a bundle that failed verification

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
                listed = list(self.running)
            names += [n for n in listed if n.startswith(self.prefix)]
        return sorted(set(names))

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
                    self.reporter.report(sb, "apply_failed",
                                         (self.running.get(sb) or {}).get("profile_hash", ""),
                                         severity="critical",
                                         target_hash=bundle.get("profile_hash", ""),
                                         message=f"bundle refused: {problem}")
            return
        tmp = self.out + ".tmp"
        with open(tmp, "w") as f:
            f.write(bundle["artifact"])
        os.replace(tmp, self.out)
        self.bundle, self.etag, self._bad = bundle, etag, None
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

    def converge(self) -> None:
        if self.bundle is None:
            return
        want = self.bundle["profile_hash"]
        names = self.managed()
        for gone in set(self.running) - set(names):
            self.running.pop(gone, None)
            self.refused.pop(gone, None)
        for sb in names:
            if (self.running.get(sb) or {}).get("profile_hash") == want:
                continue
            if self.refused.get(sb) == want:
                continue                          # needs a restart; do not hammer OpenShell
            self.apply(sb)

    def apply(self, sb: str) -> None:
        want = self.bundle["profile_hash"]
        have = (self.running.get(sb) or {}).get("profile_hash", "")
        res = self.shell.set_policy(sb, self.out)
        if res["ok"]:
            live = self.shell.policy(sb) or {}
            runtime_hash = live.get("hash") or res["hash"]
            self.running[sb] = {"profile_hash": want, "runtime_hash": runtime_hash}
            self.refused.pop(sb, None)
            self.reporter.report(sb, "applied", want, runtime_hash=runtime_hash,
                                 runtime_version=res["version"])
            self.log(f"{sb}: policy {want[:19]}... loaded live (version {res['version']})")
        elif res["live_refused"]:
            self.refused[sb] = want
            self.reporter.report(sb, "restart_required", have, target_hash=want,
                                 message=res["message"])
            self.log(f"{sb}: needs a restart to take {want[:19]}...: {res['message']}")
        else:
            self.reporter.report(sb, "apply_failed", have, target_hash=want,
                                 message=res["message"])
            self.log(f"{sb}: apply failed, retrying next tick: {res['message']}")

    def tick(self) -> None:
        self.poll()
        self.converge()
        self.reporter.flush()


def watch(args, key: str) -> int:
    if not (args.sandbox or args.sandbox_prefix):
        print("--watch needs --sandbox NAME or --sandbox-prefix PREFIX", file=sys.stderr)
        return 1
    w = Watcher(shield=args.shield, key=key, profile=args.profile, target=args.target,
                out=args.out, tenant=args.tenant, shield_url=args.shield_url,
                sandboxes=args.sandbox or [], prefix=args.sandbox_prefix,
                allow_unsigned=args.allow_unsigned,
                shell=OpenShell(args.openshell, args.gateway))
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
