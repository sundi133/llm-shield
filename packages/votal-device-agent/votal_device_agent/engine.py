"""The decision engine: rules first, then Tev1, then the tenant's policy (spec §3.2).

    engine = Engine(trust, model, audit=audit_log)
    d = engine.check(text, destination="chatgpt.com", app="Google Chrome", last_user=turn)
    d.action   # allow | redact (send d.text instead) | block | justify

Two answers per prompt, kept apart on purpose:
  verdict   what the policy says about it (allow, redact, block, justify,
            uncertain, monitor)
  action    what the agent does. In `monitor` mode, or for a category that is
            monitor-only, the action is allow and the verdict is recorded.

Rules see everything and run inline. The model judges the rule-redacted text,
the last user turn first, then the rest in chunks. On hardware whose measured
p95 misses the latency gate, the model runs after the prompt is sent: its
verdict is recorded, the action comes from rules alone (spec §2.6).

No prompt text is kept or recorded: only its SHA-256 and length, and a masked
excerpt when the tenant turns on privacy.capture_excerpt.
"""

from __future__ import annotations

import hashlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
from typing import Optional

from votal_device_agent._deps import compile_bundle, evaluate, redact
from votal_device_agent.model import DecisionModel, ModelUnavailable, model_verdict
from votal_device_agent.trust import Trust

RANK = {"allow": 0, "uncertain": 0, "monitor": 0, "redact": 1, "justify": 2, "block": 3}
LABELS = {"credentials": "a password, key or token", "personal_data": "personal data",
          "customer_data": "customer data", "source_code": "private source code",
          "financial": "non-public financial information", "health": "health information",
          "exfil_intent": "moving company data outside the company"}
MAX_CHUNKS = 4           # spec §9
CHUNK_CHARS = 3000       # with the questions, inside Tev1's ~2,000-token context
EXCERPT_CHARS = 200
RULES_BUDGET_S = 0.25


@dataclass
class Decision:
    action: str
    verdict: str
    enforced: bool
    destination: str
    app: str
    source: str
    prompt_sha256: str
    prompt_len: int
    mode: str
    trust: str
    bundle_version: Optional[int] = None
    text: Optional[str] = None            # what to send, only when action == "redact"
    rule_ids: list = field(default_factory=list)
    category: Optional[str] = None
    model_verdict: Optional[str] = None
    p_category: Optional[float] = None
    confidence: Optional[float] = None
    exfil: Optional[float] = None
    probabilities: dict = field(default_factory=dict)
    model_state: str = "not_run"          # not_run | ok | after_send | no_model | model_*
    chunks_judged: int = 0
    justified: bool = False
    justify_reason: str = ""
    reason: str = ""
    notice: str = ""
    evaluated_ms: float = 0.0
    excerpt: Optional[str] = None         # masked; recorded only with capture_excerpt

    def public(self) -> dict:
        """For the loopback API: never the prompt, only the redacted text to send."""
        out = asdict(self)
        out.pop("excerpt")
        if self.action != "redact":
            out.pop("text")
        return out


def _host(h: str) -> str:
    h = (h or "").strip().lower()
    if h.startswith("["):
        return h[1:].split("]", 1)[0]
    return h.split(":", 1)[0] if h.count(":") == 1 else h


def _segments(text: str, size: int) -> list[str]:
    return [text[i:i + size] for i in range(0, len(text), size)] if text else []


class Engine:
    def __init__(self, trust: Trust, model: Optional[DecisionModel] = None, *, audit=None,
                 justify_ttl_s: float = 60.0, pending_ttl_s: float = 300.0,
                 clock=time.time, after_send_executor: Optional[ThreadPoolExecutor] = None):
        self.model, self.audit, self.clock = model, audit, clock
        self.justify_ttl_s, self.pending_ttl_s = justify_ttl_s, pending_ttl_s
        self._lock = threading.Lock()
        self._grants: dict[tuple, tuple] = {}      # (sha, host) -> (expires, reason)
        self._pending: dict[tuple, float] = {}     # (sha, host) -> expires: justify asked
        self._executor = after_send_executor
        self.counters: dict[str, int] = {}
        self.set_trust(trust)

    # ── policy ─────────────────────────────────────────────────────────

    def set_trust(self, trust: Trust) -> None:
        p = trust.policy
        compiled = compile_bundle({"rules": p.get("rules") or [],
                                   "blocklists": p.get("blocklists") or []}, keep_redact=True)
        with self._lock:
            self.trust, self.policy, self.rules = trust, p, compiled
            self.ai_hosts = tuple(h.lower() for h in p.get("ai_hosts") or ())

    def is_ai_host(self, host: str) -> bool:
        h = _host(host)
        return bool(h) and any(h == e or h.endswith("." + e) for e in self.ai_hosts)

    def pinned_action(self, host: str) -> str:
        """allow_and_log or block, for an app that refuses the device CA (spec §3.1)."""
        pin = self.policy.get("pinned_host_action") or {}
        return (pin.get("hosts") or {}).get(_host(host), pin.get("default", "allow_and_log"))

    def _count(self, name: str) -> None:
        with self._lock:
            self.counters[name] = self.counters.get(name, 0) + 1

    # ── justify ────────────────────────────────────────────────────────

    def justify(self, prompt_sha256: str, destination: str, reason: str) -> bool:
        """Allow this exact prompt to this destination once, within justify_ttl_s.
        Only for a prompt the engine asked to justify: a reason cannot be given
        in advance for a prompt nobody has seen."""
        key = (prompt_sha256, _host(destination))
        reason = (reason or "").strip()
        if len(reason) < 3:
            return False
        now = self.clock()
        with self._lock:
            if self._pending.get(key, 0) <= now:
                return False
            self._pending.pop(key, None)
            self._grants[key] = (now + self.justify_ttl_s, reason[:500])
        return True

    def _take_grant(self, key: tuple) -> Optional[str]:
        now = self.clock()
        with self._lock:
            for k in [k for k, (exp, _) in self._grants.items() if exp <= now]:
                self._grants.pop(k)
            for k in [k for k, exp in self._pending.items() if exp <= now]:
                self._pending.pop(k)
            got = self._grants.pop(key, None)
        return got[1] if got else None

    # ── deciding ───────────────────────────────────────────────────────

    def check(self, text: str, destination: str, app: str = "", source: str = "proxy",
              last_user: Optional[str] = None) -> Decision:
        t0 = time.perf_counter()
        text = text or ""
        host = _host(destination)
        p = self.policy
        mode = p.get("mode", "monitor")
        enforce = mode == "enforce"
        d = Decision(action="allow", verdict="allow", enforced=enforce, destination=host, app=app,
                     source=source, prompt_sha256=hashlib.sha256(text.encode()).hexdigest(),
                     prompt_len=len(text), mode=mode, trust=self.trust.status,
                     bundle_version=self.trust.bundle_version)
        if not self.is_ai_host(host):
            d.reason = "not an AI host: passed through untouched"
            return self._done(d, t0, record=False)
        self._count("checked")

        # 1. rules
        try:
            hit = evaluate(self.rules, text, timeout_s=RULES_BUDGET_S)
            redacted, red_hits = redact(self.rules, text, timeout_s=RULES_BUDGET_S)
        except TimeoutError:
            self._count("rule_timeout")
            hit, redacted, red_hits = None, text, []
            d.reason = "rule scan ran out of time"
            if p.get("fail_mode") == "block":
                d.verdict, d.reason = "block", "rule scan ran out of time and fail_mode is block"
                return self._finish(d, t0)
        d.excerpt = self._excerpt(text) if (p.get("privacy") or {}).get("capture_excerpt") else None

        grant = self._take_grant((d.prompt_sha256, host))
        if grant is not None and hit is None:
            d.justified, d.justify_reason = True, grant
            d.rule_ids = [h.rule_id for h in red_hits]
            d.verdict = "redact" if red_hits else "allow"
            d.text = redacted if red_hits else None
            d.reason = "sent after the user gave a reason"
            self._count("justified")
            return self._finish(d, t0)

        if hit is not None:
            d.verdict, d.rule_ids = "block", [hit.rule_id]
            d.reason = f"matched {'blocked term' if hit.kind == 'blocklist' else 'rule'} {hit.rule_id}"
            return self._finish(d, t0)
        if red_hits:
            d.verdict, d.text = "redact", redacted
            d.rule_ids = [h.rule_id for h in red_hits]
            d.reason = "redacted " + ", ".join(d.rule_ids)

        # 2. the model, on the rule-redacted text
        if not self._model_configured():
            d.model_state = "no_model"
            return self._finish(d, t0)
        # The last user turn first (spec §9), then the rest, as it will be sent.
        turn = last_user or ""
        if turn and red_hits:
            try:
                turn = redact(self.rules, turn, timeout_s=RULES_BUDGET_S)[0]
            except TimeoutError:
                pass
        segments = _segments(turn, CHUNK_CHARS)
        for seg in _segments(redacted, CHUNK_CHARS):
            if seg not in segments:
                segments.append(seg)
        segments = segments[:MAX_CHUNKS]
        if not self.model.gate.inline():
            d.model_state = "after_send"
            self._count("after_send")
            self._finish(d, t0, record=False)
            self._after_send(d, segments)
            return d
        self._apply_model(d, segments)
        return self._finish(d, t0)

    def _model_configured(self) -> bool:
        p = self.policy
        return (self.model is not None and self.trust.status != "fallback"
                and bool((p.get("model") or {}).get("name")) and bool(p.get("questions")))

    def _judge(self, d: Decision, segments: list[str]) -> Optional[dict]:
        """The strongest answer over the chunks, or None if the model failed
        (d.model_state says why)."""
        p = self.policy
        if self.model.state in ("model_unsupported", "model_mismatch"):
            d.model_state = self.model.state
            return None
        t = p["thresholds"]
        best, best_key = None, (-1, -1.0)
        for seg in segments:
            try:
                ans = self.model.decide(p["model"]["name"],
                                        {"prompt": seg, "destination": d.destination, "app": d.app},
                                        p["questions"], p.get("model_timeout_ms", 1500) / 1000.0)
            except ModelUnavailable as e:
                d.model_state = e.state
                return None
            d.chunks_judged += 1
            mv = model_verdict(ans, t)
            key = (RANK.get(mv, 0), ans["p_category"])
            if key > best_key:
                best, best_key = {**ans, "verdict": mv}, key
            if mv == "block":
                break
        d.model_state = "ok"
        return best

    def _apply_model(self, d: Decision, segments: list[str]) -> None:
        p = self.policy
        ans = self._judge(d, segments)
        if ans is None:
            self._count("model_unavailable")
            if p.get("fail_mode") == "block" and RANK[d.verdict] < RANK["block"]:
                d.verdict = "block"
                d.reason = f"the local model is unavailable ({d.model_state}) and fail_mode is block"
            return
        t = p["thresholds"]
        # A label is only meaningful when the model flagged something: on a benign
        # prompt the "most likely category" is noise at a few percent.
        d.model_verdict = ans["verdict"]
        d.category = ans["category"] if ans["verdict"] != "allow" else None
        d.p_category, d.confidence, d.exfil = ans["p_category"], ans["confidence"], ans["exfil"]
        d.probabilities = {k: round(v, 4) for k, v in ans["probabilities"].items()}
        mv = ans["verdict"]
        if mv in ("block", "justify"):
            by_category = (ans["confidence"] >= t["min_confidence"]
                           and ans["category"] not in (None, "none")
                           and ans["p_category"] >= t["justify_p"])
            driver = ans["category"] if by_category else "exfil_intent"
            d.category = driver
            if (p.get("enforcement") or {}).get(driver, "monitor") == "monitor":
                mv = "monitor"             # recorded, never acted on
        if RANK.get(mv, 0) > RANK[d.verdict] or (d.verdict == "allow" and mv in ("monitor",
                                                                                   "uncertain")):
            if mv in ("block", "justify"):
                d.text = None
            d.verdict = mv
            d.reason = {"block": f"the local model found {LABELS.get(d.category, d.category)}",
                        "justify": f"the local model found {LABELS.get(d.category, d.category)}",
                        "monitor": f"the local model found {LABELS.get(d.category, d.category)} "
                                   f"(monitor only for this category)",
                        "uncertain": "the local model was not confident"}.get(mv, d.reason)

    def _after_send(self, d: Decision, segments: list[str]) -> None:
        late = replace(d)          # the caller already holds d; judge a copy

        def run():
            self._apply_model(late, segments)
            if late.model_state == "ok":
                late.model_state = "after_send"
            if late.verdict in ("monitor", "uncertain", "block", "justify"):
                # The prompt has gone: what the model would have done is
                # recorded, never enforced.
                late.model_verdict = late.model_verdict or late.verdict
            late.action = d.action
            if self._should_record(late):
                self._record(late)
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="dlp-after-send")
        self._executor.submit(run)

    def drain(self, timeout: float = 10.0) -> None:
        """Wait for after-send judgements (tests, shutdown)."""
        if self._executor is not None:
            self._executor.submit(lambda: None).result(timeout=timeout)

    # ── finishing ──────────────────────────────────────────────────────

    def _finish(self, d: Decision, t0: float, record: bool = True) -> Decision:
        if d.enforced:
            d.action = {"block": "block", "justify": "justify", "redact": "redact"}.get(d.verdict,
                                                                                     "allow")
        else:
            d.action = "allow"
        if d.action != "redact":
            d.text = None
        if d.action == "justify":
            with self._lock:
                self._pending[(d.prompt_sha256, d.destination)] = self.clock() + self.pending_ttl_s
        d.notice = self._notice(d)
        self._count({"allow": "allowed", "redact": "redacted", "block": "blocked",
                     "justify": "justify_asked"}[d.action])
        if d.verdict in ("monitor", "uncertain"):
            self._count(d.verdict)
        return self._done(d, t0, record=record)

    def _done(self, d: Decision, t0: float, record: bool) -> Decision:
        d.evaluated_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        if record and self._should_record(d):
            self._record(d)
        return d

    def _should_record(self, d: Decision) -> bool:
        # Every non-allow decision, every allow in monitor mode (spec §3.3), and
        # every decision the model could not make.
        return (d.verdict != "allow" or not d.enforced or d.justified
                or d.model_state.startswith("model_"))

    def _record(self, d: Decision) -> None:
        if self.audit is not None:
            try:
                self.audit.record(d)
            except Exception:
                self._count("audit_error")

    def _notice(self, d: Decision) -> str:
        if d.action == "block":
            return ("Blocked by your company's AI data policy: "
                    + (f"this matches rule {d.rule_ids[0]}." if d.rule_ids and not d.category
                       else f"this looks like {LABELS.get(d.category, 'sensitive data')}."))
        if d.action == "justify":
            return (f"This looks like {LABELS.get(d.category, 'sensitive data')}. To send it "
                    f"anyway, give a reason in the Votal menu, then send it again within a minute.")
        if d.action == "redact":
            return "Sensitive values were replaced before sending: " + ", ".join(d.rule_ids) + "."
        return ""

    def _excerpt(self, text: str) -> Optional[str]:
        """The first 200 characters with EVERY rule and blocked term masked, not
        only the redact rules: a blocked secret must not reach Shield in an
        excerpt of the prompt that was blocked for containing it."""
        out = text
        try:
            deadline = time.monotonic() + RULES_BUDGET_S
            for rule in self.rules.rules:
                out = rule.pattern.sub("[REDACTED]", out,
                                       timeout=max(0.001, deadline - time.monotonic()))
        except TimeoutError:
            return None
        low = out.lower()
        for word in self.rules.blocklists:
            i = low.find(word)
            while i >= 0:
                out = out[:i] + "[REDACTED]" + out[i + len(word):]
                low = out.lower()
                i = low.find(word, i + len("[REDACTED]"))
        return out[:EXCERPT_CHARS]
