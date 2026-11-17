"""The "after": Shield's agent checks and fleet linking (spec sections 2 and 3).

Lab prototype of detectors A1 to A6 and the two-trait fleet rule. Weights and
thresholds are hand-set starting values; the lab's job is to measure them and
replace them with numbers from data. Every verdict carries its reasons.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from itertools import combinations

from sessions import Session

CLEAR_AGENT = 0.8
GREY_LOW = 0.4


@dataclass
class Verdict:
    key: str
    score: float
    band: str                      # clear_agent | grey | human_like
    reasons: list = field(default_factory=list)
    signals: dict = field(default_factory=dict)


def _rhythm(s: Session):
    """A1: gaps between actions sit in the model-latency band with low variation."""
    g = s.gaps()
    if len(g) < 4:
        return 0.0, None
    med = statistics.median(g)
    cv = statistics.pstdev(g) / statistics.mean(g)
    fast = sum(x < 1.2 for x in g) / len(g)
    in_band = 1.5 <= med <= 30
    score = 1.0 if (in_band and cv <= 0.6 and fast <= 0.1) else 0.5 if (in_band and cv <= 0.9 and fast <= 0.2) else 0.0
    return score, f"action gaps median {med:.1f}s, variation {cv:.2f}, quick follow-ups {fast:.0%}"


def _fill_timing(s: Session):
    """A2: seconds per form field are steady across forms (fields filled one model step at a time)."""
    per_field = [secs / n for _, secs, n in s.form_fill_seconds() if n >= 2 and secs > 0]
    if len(per_field) < 2:
        return 0.0, None
    mean = statistics.mean(per_field)
    cv = statistics.pstdev(per_field) / mean if mean else 1
    score = 1.0 if (2 <= mean <= 20 and cv <= 0.35) else 0.5 if (2 <= mean <= 25 and cv <= 0.6) else 0.0
    return score, f"{mean:.1f}s per form field, variation {cv:.2f} across {len(per_field)} forms"


def _error_recovery(s: Session):
    """A3: after a rejected submit, a changed resubmit follows after a model-latency pause."""
    hits = 0
    posts = [e for e in s.events if e["method"] == "POST"]
    for a, b in zip(posts, posts[1:]):
        if a["status"] in (400, 401) and b["uri"] == a["uri"] and 2.0 <= b["msec"] - a["msec"] <= 60 \
                and b.get("req_len") != a.get("req_len"):
            hits += 1
    return (1.0 if hits else 0.0), (f"{hits} rejected submit(s) fixed and resubmitted" if hits else None)


def _goal_directed(s: Session):
    """A4: completes the funnel with almost no browsing."""
    funnel = s.signups + s.promos + s.orders
    browse = s.browsing_pages()
    if funnel >= 2 and browse <= 1:
        return 1.0, f"completed {funnel} funnel steps while viewing {browse} other page(s)"
    if funnel >= 2 and browse <= 2:
        return 0.5, f"completed {funnel} funnel steps while viewing {browse} other pages"
    return 0.0, None


def _tripwire(s: Session):
    """A5 (spec 2.4): acted on a hidden instruction no person can see.

    The session's own code (T1 field, T2 link, T3 comment) or another
    session's code is clear; a value in a trap field with no code (T4, which
    browser autofill can also produce) is weak; an unknown canary code is in
    between.
    """
    hits = set(s.trap_hits)
    own = sorted(h for h in hits if h in ("T1", "T2", "T3"))
    if s.reused_codes:
        return 1.0, f"presented trap codes shown to {len(s.reused_codes)} other session(s): one controller"
    if own:
        return 1.0, f"followed a hidden instruction with this session's code ({', '.join(own)})"
    if "T2?" in hits:
        return 0.5, "opened a hidden verification link with an unknown code"
    if "T4" in hits:
        return 0.35, "filled a hidden field that carries no instruction (autofill can do this too)"
    return 0.0, None


def _client_traits(s: Session):
    """A6: client hints contradict the claimed browser."""
    ua = s.ua
    reasons = []
    if "Headless" in ua:
        reasons.append("headless browser")
    claims_windows, claims_mac = "Windows" in ua, "Macintosh" in ua
    plat = s.platform.strip('"')
    if plat and ((claims_windows and plat != "Windows") or (claims_mac and plat != "macOS")):
        reasons.append(f"user agent claims {'Windows' if claims_windows else 'macOS'} but the browser reports {plat}")
    if "Chrome/" in ua and not s.chua:
        reasons.append("claims Chrome but sends no client hints")
    import re
    claimed = re.search(r"Chrome/(\d+)", ua)
    hinted = re.search(r'"(?:Google Chrome|Chromium)";v="(\d+)"', s.chua)
    if claimed and hinted and claimed.group(1) != hinted.group(1):
        reasons.append(f"user agent claims Chrome {claimed.group(1)} but client hints say {hinted.group(1)}")
    return (1.0, "; ".join(reasons)) if reasons else (0.0, None)


def _forged_identity(s: Session):
    """A11 (spec 2.5): the edge says the Web Bot Auth signature is invalid, or a known
    operator was named with no valid signature. Someone is posing as a trusted agent."""
    if "invalid" in s.wba:
        return 1.0, f"claims to be the agent operator at {s.wba_agent or 'an unnamed directory'}, but the signature fails"
    return 0.0, None


SCANNER_ALLOW_UA = ("lab-scanner/",)     # the customer's own scanners, excluded from A12 (spec 2.6)
DECOY_RE = __import__("re").compile(r"^D[1-4]$")


def _decoys(s: Session):
    """A12 (spec 2.6): touched a decoy nobody legitimate needs.

    Following the instruction inside it (the session's code came back), or
    presenting the fake key, is a clear agent. A bare hit is medium and counts
    only alongside other activity on the site: the public web is full of
    scanners requesting /.env, and WAFs already handle those.
    """
    if not s.decoy_hits or s.ua.startswith(SCANNER_ALLOW_UA):
        return 0.0, None
    hits = set(s.decoy_hits)
    kinds = sorted(h for h in hits if DECOY_RE.match(h))
    followed = sorted(h[:2] for h in hits if h.endswith("f") and DECOY_RE.match(h[:2]))
    if "D3k" in hits:
        return 1.0, "presented the fake API key from the page code (D3)"
    if followed:
        return 1.0, f"followed the instruction inside a decoy with this session's code ({', '.join(followed)})"
    if any("x:" in h for h in hits):
        return 1.0, "brought back a decoy code shown to another visitor: one controller"
    # Probing paths that don't exist (404s) is scanner behavior, not using the site.
    other_pages = sum(1 for e in s.events if not e.get("decoy") and e.get("status", 200) < 400)
    if other_pages >= 2:
        return 0.5, f"opened decoys ({', '.join(kinds)}) while also using the site"
    return 0.0, None


def declared(s: Session, allow: set) -> str:
    """'declared' (valid signature, allowed operator), 'declared_unknown' (valid or
    unverifiable, operator not allowed), or '' (not a declared agent).

    No signature is not evidence of anything; an invalid one is A11, never declared.
    """
    if not s.wba or "invalid" in s.wba or s.wba <= {"none"}:
        return ""
    if s.wba - {"none"} == {"valid"} and s.wba_agent in allow:
        return "declared"
    return "declared_unknown"


DETECTORS = [  # id, function, weight
    ("A1", _rhythm, 0.45), ("A2", _fill_timing, 0.35), ("A3", _error_recovery, 0.25),
    ("A4", _goal_directed, 0.30), ("A5", _tripwire, 0.95), ("A6", _client_traits, 0.60),
    ("A11", _forged_identity, 0.90), ("A12", _decoys, 0.90),
]


def score_session(s: Session, tag=None, *, include_a8: bool = True) -> Verdict:
    """Tier 1 from the log alone; with `tag` (a beacons.TagData), tier 2 detectors A7 to A10 too."""
    keep = 1.0
    reasons, signals = [], {}
    for did, fn, weight in DETECTORS:
        value, why = fn(s)
        signals[did] = value
        if value:
            keep *= 1 - weight * value
            reasons.append(f"{did}: {why}")
    if tag is not None:
        import tier2
        for did, fn, weight in tier2.DETECTORS:
            if did == "A8" and not include_a8:
                continue
            value, why = fn(s, tag, signals)
            signals[did] = value
            if value:
                keep *= 1 - weight * value
                reasons.append(f"{did}: {why}")
    score = round(1 - keep, 3)
    band = "clear_agent" if score >= CLEAR_AGENT else "grey" if score >= GREY_LOW else "human_like"
    return Verdict(s.key, score, band, reasons, signals)


# ── fleets (spec section 3) ───────────────────────────────────────────────

def _shingles(seq: list[str], k: int = 3) -> set:
    return {tuple(seq[i:i + k]) for i in range(max(1, len(seq) - k + 1))}


def _timing_profile(s: Session):
    g = s.gaps()
    if len(g) < 3:
        return None
    return round(statistics.median(g) / 2)   # 2-second buckets


def _interaction_profile(tag):
    """A7 features bucketed (spec 3.2, tier 2), or None without enough interaction."""
    if not tag or not tag.joined:
        return None
    it = tag.interaction()
    if it["clicks"] < 2 and it["inputs"] < 2:
        return None
    ratio = lambda n, d: round(n / d, 1) if d else -1  # noqa: E731
    return (min(it["inputs_without_keys"], 5), ratio(it["centre_clicks"], it["clicks"]),
            ratio(it["clicks_without_move"], it["clicks"]), it["keys"] > 0)


def link_traits(a: Session, b: Session, sh: dict, tags: dict | None = None, rare_device=None) -> set[str]:
    """Trait groups two sessions share (spec 3.2). Tier 2 adds interaction, device and controller."""
    groups = set()
    ta_, tb_ = (tags or {}).get(a.key), (tags or {}).get(b.key)
    jacc = len(sh[a.key] & sh[b.key]) / max(1, len(sh[a.key] | sh[b.key]))
    ta, tb = _timing_profile(a), _timing_profile(b)
    ia, ib = _interaction_profile(ta_), _interaction_profile(tb_)
    if jacc >= 0.6 and ((ta is not None and ta == tb) or (ia is not None and ia == ib)):
        groups.add("behavior")
    if abs(a.start - b.start) <= 30 or abs(a.end - b.end) <= 30:
        groups.add("time")
    da, db = (ta_.device_hash if ta_ else ""), (tb_.device_hash if tb_ else "")
    if a.fingerprint == b.fingerprint or (da and da == db and rare_device and rare_device(da)):
        groups.add("environment")
    if a.net24 == b.net24:
        groups.add("network")
    if (b.shs_ids & a.reused_codes) or (a.shs_ids & b.reused_codes):
        groups.add("controller")
    return groups


def find_fleets(sessions: list[Session], *, min_size: int = 10, min_networks: int = 3,
                tags: dict | None = None, rare_device=None, exclude: set | None = None) -> list[dict]:
    """Union-find over pairs that share at least two independent trait groups.

    A shared network alone, or a shared path alone, never links two sessions.
    Behavior is required, so people who merely share an office IP and a
    browser build don't form a fleet. Trap code reuse (controller) links on
    its own: people never see the codes. `exclude` holds declared agents from
    allowed operators, which are never fleet members (spec 2.5).
    """
    if exclude:
        sessions = [s for s in sessions if s.key not in exclude]
    parent = {s.key: s.key for s in sessions}

    def root(k):
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    sh = {s.key: _shingles(s.path_sequence()) for s in sessions}
    link_groups: dict[tuple, set] = {}
    for a, b in combinations(sessions, 2):
        g = link_traits(a, b, sh, tags, rare_device)
        if (len(g) >= 2 and "behavior" in g) or "controller" in g:
            parent[root(a.key)] = root(b.key)
            link_groups[(a.key, b.key)] = g
    groups: dict[str, list[Session]] = {}
    for s in sessions:
        groups.setdefault(root(s.key), []).append(s)
    fleets = []
    for members in groups.values():
        nets = {m.net24 for m in members}
        if len(members) >= min_size and len(nets) >= min_networks:
            keys = {m.key for m in members}
            traits = {}
            for (a, b), g in link_groups.items():
                if a in keys:
                    for t in g:
                        traits[t] = traits.get(t, 0) + 1
            fleets.append({
                "id": f"fleet-{min(keys)[:8]}", "size": len(members), "networks": len(nets),
                "members": sorted(keys), "linking_traits": traits,
                "start": min(m.start for m in members), "end": max(m.end for m in members),
                "accounts": sorted({m.account for m in members if m.account}),
                "signups": sum(m.signups for m in members), "promos": sum(m.promos for m in members),
                "orders": sum(m.orders for m in members),
            })
    return fleets
