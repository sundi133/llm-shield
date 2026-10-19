"""Targets and routes: validation, storage, and the per-process cache.

Spec: docs/specs/gateway-routing-failover.md, sections 3.1 and 3.2.

  gw_targets:{tenant}   JSON {target_id: target}   (at most 50)
  gw_routes:{tenant}    JSON {route_name: route}   (at most 100)

The proxy never reads Redis on a request: `cached(tenant)` serves the copy it
loaded, refreshes it in the background once it is older than CACHE_S, and
loads it synchronously only the first time a process sees the tenant.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import threading
import time
from typing import Any, Optional

logger = logging.getLogger("votal.llm_gateway")

TARGETS_MAX = 50
ROUTES_MAX = 100
RULES_MAX = 50
FLAVORS = ("openai", "azure")
AUTH_MODES = ("vault", "passthrough", "none")
LOCATIONS = ("cloud", "on_prem")
STRATEGIES = ("priority", "lowest_latency", "lowest_cost", "weighted")
FAILOVER_ON = ("timeout", "connect", "429", "5xx")
AT_LIMIT = ("warn", "fallback", "block")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ROUTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,79}$")
_HEADER = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_REF = re.compile(r"^(shield://[A-Za-z0-9_.\-]+|svlt_[0-9a-f]+)$")


class ConfigError(ValueError):
    def __init__(self, errors: list, status: int = 422):
        super().__init__("; ".join(errors))
        self.errors = errors
        self.status = status


def enabled() -> bool:
    return os.environ.get("SHIELD_LLM_ROUTING", "1").strip().lower() not in ("0", "false", "no", "off")


def _num(raw, name: str, errors: list, lo: float, hi: float, default):
    if raw is None:
        return default
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not lo <= raw <= hi:
        errors.append(f"{name}: a number from {lo:g} to {hi:g}")
        return default
    return raw


def _bool(raw, name: str, errors: list, default: bool) -> bool:
    if raw is None:
        return default
    if not isinstance(raw, bool):
        errors.append(f"{name}: true or false")
        return default
    return raw


def _unknown(raw: dict, allowed: set, where: str, errors: list) -> None:
    extra = set(raw) - allowed
    if extra:
        errors.append(f"{where}: unknown field(s) {', '.join(sorted(extra))}")


# ── targets ──────────────────────────────────────────────────────────


def target_url(t: dict) -> str:
    """The chat completions URL for a target."""
    base = t["base_url"].rstrip("/")
    if t.get("flavor") == "azure":
        az = t.get("azure") or {}
        return (f"{base}/openai/deployments/{az.get('deployment', '')}/chat/completions"
                f"?api-version={az.get('api_version', '')}")
    return f"{base}/chat/completions"


def validate_target(target_id: str, raw: Any, *, check_url=None) -> dict:
    """A normalized target, or ConfigError listing every problem. `check_url`
    (url, allow_private) raises ValueError for an unsafe destination."""
    errors: list = []
    if not _ID.match(target_id or ""):
        errors.append("id: letters, digits, '.', '_' or '-', at most 64")
    if not isinstance(raw, dict):
        raise ConfigError(errors + ["target: an object"])
    _unknown(raw, {"id", "name", "base_url", "flavor", "model", "azure", "auth", "location",
                   "allow_private", "timeout_s", "first_byte_timeout_s", "price", "enabled",
                   "updated_at", "updated_by"}, "target", errors)
    flavor = raw.get("flavor", "openai")
    if flavor not in FLAVORS:
        errors.append(f"flavor: one of {', '.join(FLAVORS)}")
    base_url = str(raw.get("base_url") or "").strip()
    if not re.match(r"^https?://[^\s/]+", base_url) or len(base_url) > 500:
        errors.append("base_url: an http(s) URL, for example https://api.openai.com/v1")
    model = str(raw.get("model") or "").strip()
    if not model or len(model) > 200:
        errors.append("model: the model name the provider expects, at most 200 characters")
    azure = raw.get("azure") or {}
    if not isinstance(azure, dict):
        errors.append("azure: an object")
        azure = {}
    if flavor == "azure" and not (azure.get("deployment") and azure.get("api_version")):
        errors.append("azure: deployment and api_version are required for flavor azure")
    auth = raw.get("auth") or {"mode": "none"}
    if not isinstance(auth, dict):
        errors.append("auth: an object")
        auth = {"mode": "none"}
    _unknown(auth, {"mode", "header", "scheme", "secret_ref"}, "auth", errors)
    mode = auth.get("mode", "none")
    default_header = "api-key" if flavor == "azure" else "Authorization"
    header = str(auth.get("header") or default_header)
    scheme = str(auth.get("scheme") if auth.get("scheme") is not None else
                 ("" if flavor == "azure" else "Bearer"))
    if mode not in AUTH_MODES:
        errors.append(f"auth.mode: one of {', '.join(AUTH_MODES)}")
    if not _HEADER.match(header):
        errors.append("auth.header: a header name")
    if len(scheme) > 20 or not re.match(r"^[A-Za-z-]*$", scheme):
        errors.append("auth.scheme: a word such as Bearer, or empty")
    ref = str(auth.get("secret_ref") or "")
    if mode == "vault" and not _REF.match(ref):
        errors.append("auth.secret_ref: a vault reference (shield://name or svlt_...) for mode vault")
    if mode != "vault" and ref:
        errors.append("auth.secret_ref: only for mode vault")
    location = raw.get("location", "cloud")
    if location not in LOCATIONS:
        errors.append(f"location: one of {', '.join(LOCATIONS)}")
    allow_private = _bool(raw.get("allow_private"), "allow_private", errors, False)
    price = raw.get("price")
    if price is not None:
        if not isinstance(price, dict):
            errors.append("price: an object")
            price = None
        else:
            _unknown(price, {"input_per_mtok", "output_per_mtok", "currency"}, "price", errors)
            price = {"input_per_mtok": _num(price.get("input_per_mtok"), "price.input_per_mtok", errors, 0, 10_000, 0),
                     "output_per_mtok": _num(price.get("output_per_mtok"), "price.output_per_mtok", errors, 0, 10_000, 0),
                     "currency": str(price.get("currency") or "USD")[:3].upper()}
    out = {
        "id": target_id, "name": str(raw.get("name") or target_id)[:120], "base_url": base_url,
        "flavor": flavor, "model": model,
        "azure": {"deployment": str(azure.get("deployment") or "")[:120],
                  "api_version": str(azure.get("api_version") or "")[:40]},
        "auth": {"mode": mode, "header": header, "scheme": scheme, "secret_ref": ref},
        "location": location, "allow_private": allow_private,
        "timeout_s": _num(raw.get("timeout_s"), "timeout_s", errors, 1, 600, 60),
        "first_byte_timeout_s": _num(raw.get("first_byte_timeout_s"), "first_byte_timeout_s", errors, 1, 300, 20),
        "price": price, "enabled": _bool(raw.get("enabled"), "enabled", errors, True),
    }
    if not errors and check_url is not None:
        try:
            check_url(target_url(out), allow_private)
        except ValueError as e:
            errors.append(f"base_url: {e}")
    if errors:
        raise ConfigError(errors)
    return out


# ── routes ───────────────────────────────────────────────────────────

RULE_CONDITIONS = ("flagged", "data_class", "agent", "role", "location_required", "prompt_tokens_over")


def _str_list(raw, name: str, errors: list, cap: int = 50) -> list:
    if not isinstance(raw, list) or not raw or len(raw) > cap or \
            not all(isinstance(x, str) and 0 < len(x) <= 128 for x in raw):
        errors.append(f"{name}: a list of 1 to {cap} names")
        return []
    return list(dict.fromkeys(raw))


def validate_route(name: str, raw: Any, targets: dict) -> dict:
    errors: list = []
    if not _ROUTE.match(name or ""):
        errors.append("name: letters, digits, '.', '_', '-' or '/', at most 80")
    if not isinstance(raw, dict):
        raise ConfigError(errors + ["route: an object"])
    _unknown(raw, {"name", "targets", "strategy", "weights", "failover", "rules", "budget", "enabled",
                   "updated_at", "updated_by"}, "route", errors)
    tlist = _str_list(raw.get("targets"), "targets", errors, 20)
    missing = [t for t in tlist if t not in targets]
    if missing:
        errors.append(f"targets: no target {', '.join(missing)}")
    strategy = raw.get("strategy", "priority")
    if strategy not in STRATEGIES:
        errors.append(f"strategy: one of {', '.join(STRATEGIES)}")
    weights = raw.get("weights") or {}
    if not isinstance(weights, dict) or any(k not in tlist or isinstance(v, bool) or not isinstance(v, (int, float))
                                            or v < 0 for k, v in weights.items()):
        errors.append("weights: {target: non-negative number} for targets in this route")
        weights = {}
    if strategy == "weighted" and not any(v > 0 for v in weights.values()):
        errors.append("weights: at least one positive weight for strategy weighted")
    fo = raw.get("failover") or {}
    if not isinstance(fo, dict):
        errors.append("failover: an object")
        fo = {}
    _unknown(fo, {"max_attempts", "deadline_s", "on"}, "failover", errors)
    on = fo.get("on", list(FAILOVER_ON))
    if not isinstance(on, list) or any(x not in FAILOVER_ON for x in on):
        errors.append(f"failover.on: a list of {', '.join(FAILOVER_ON)}")
        on = list(FAILOVER_ON)
    failover = {"max_attempts": int(_num(fo.get("max_attempts"), "failover.max_attempts", errors, 1, 10, 3)),
                "deadline_s": _num(fo.get("deadline_s"), "failover.deadline_s", errors, 1, 900, 120),
                "on": list(dict.fromkeys(on))}
    rules = []
    raw_rules = raw.get("rules") or []
    if not isinstance(raw_rules, list) or len(raw_rules) > RULES_MAX:
        errors.append(f"rules: a list of at most {RULES_MAX}")
        raw_rules = []
    for i, r in enumerate(raw_rules):
        rules.append(_validate_rule(r, i, tlist, targets, errors))
    budget = raw.get("budget")
    if budget is not None:
        if not isinstance(budget, dict):
            errors.append("budget: an object")
            budget = None
        else:
            _unknown(budget, {"monthly", "currency", "at_limit", "fallback_targets"}, "budget", errors)
            at = budget.get("at_limit", "warn")
            if at not in AT_LIMIT:
                errors.append(f"budget.at_limit: one of {', '.join(AT_LIMIT)}")
            fb = budget.get("fallback_targets") or []
            if at == "fallback":
                fb = _str_list(fb, "budget.fallback_targets", errors, 20)
            if any(t not in tlist for t in fb):
                errors.append("budget.fallback_targets: targets of this route only")
            budget = {"monthly": _num(budget.get("monthly"), "budget.monthly", errors, 0, 10_000_000, 0),
                      "currency": str(budget.get("currency") or "USD")[:3].upper(),
                      "at_limit": at, "fallback_targets": fb}
    if errors:
        raise ConfigError(errors)
    return {"name": name, "targets": tlist, "strategy": strategy,
            "weights": {k: float(v) for k, v in weights.items()}, "failover": failover,
            "rules": rules, "budget": budget, "enabled": _bool(raw.get("enabled"), "enabled", [], True)}


def _validate_rule(r: Any, i: int, tlist: list, targets: dict, errors: list) -> dict:
    where = f"rules[{i}]"
    if not isinstance(r, dict):
        errors.append(f"{where}: an object")
        return {}
    _unknown(r, {"when", "use", "deny", "note"}, where, errors)
    when = r.get("when")
    if not isinstance(when, dict) or not when:
        errors.append(f"{where}.when: at least one condition ({', '.join(RULE_CONDITIONS)})")
        when = {}
    _unknown(when, set(RULE_CONDITIONS), f"{where}.when", errors)
    clean: dict = {}
    for k in ("flagged", "data_class", "agent", "role"):
        if k in when:
            clean[k] = _str_list(when[k], f"{where}.when.{k}", errors)
    if "location_required" in when:
        if when["location_required"] not in LOCATIONS:
            errors.append(f"{where}.when.location_required: one of {', '.join(LOCATIONS)}")
        clean["location_required"] = when["location_required"]
    if "prompt_tokens_over" in when:
        clean["prompt_tokens_over"] = int(_num(when["prompt_tokens_over"], f"{where}.when.prompt_tokens_over",
                                               errors, 1, 10_000_000, 1))
    use, deny = r.get("use"), r.get("deny")
    if (use is None) == (deny is None):
        errors.append(f"{where}: exactly one of use (a list of this route's targets) or deny (a message)")
    out = {"when": clean, "note": str(r.get("note") or "")[:200]}
    if use is not None:
        out["use"] = _str_list(use, f"{where}.use", errors, 20)
        outside = [t for t in out["use"] if t not in tlist]
        if outside:
            errors.append(f"{where}.use: rules only narrow; {', '.join(outside)} is not in targets")
    if deny is not None:
        if not isinstance(deny, str) or not 0 < len(deny) <= 300:
            errors.append(f"{where}.deny: a message of at most 300 characters")
        out["deny"] = str(deny)[:300]
    return out


# ── storage ──────────────────────────────────────────────────────────


def _tkey(t: str) -> str:
    return f"gw_targets:{t}"


def _rkey(t: str) -> str:
    return f"gw_routes:{t}"


def load(tenant_id: str) -> tuple[dict, dict]:
    from storage.tenant_store import kv_get
    targets = kv_get(_tkey(tenant_id)) or {}
    routes = kv_get(_rkey(tenant_id)) or {}
    return (targets if isinstance(targets, dict) else {}), (routes if isinstance(routes, dict) else {})


def save_target(tenant_id: str, target: dict, actor: str = "") -> dict:
    from storage.tenant_store import kv_set
    targets, _ = load(tenant_id)
    if target["id"] not in targets and len(targets) >= TARGETS_MAX:
        raise ConfigError([f"at most {TARGETS_MAX} targets"], 409)
    target = {**target, "updated_at": int(time.time()), "updated_by": actor[:200]}
    targets[target["id"]] = target
    kv_set(_tkey(tenant_id), targets)
    invalidate(tenant_id)
    return target


def delete_target(tenant_id: str, target_id: str) -> bool:
    from storage.tenant_store import kv_set
    targets, routes = load(tenant_id)
    if target_id not in targets:
        return False
    users = sorted(n for n, r in routes.items() if target_id in (r.get("targets") or []))
    if users:
        raise ConfigError([f"target '{target_id}' is used by route(s) {', '.join(users)}"], 409)
    targets.pop(target_id)
    kv_set(_tkey(tenant_id), targets)
    invalidate(tenant_id)
    return True


def save_route(tenant_id: str, route: dict, actor: str = "") -> dict:
    from storage.tenant_store import kv_set
    _, routes = load(tenant_id)
    if route["name"] not in routes and len(routes) >= ROUTES_MAX:
        raise ConfigError([f"at most {ROUTES_MAX} routes"], 409)
    route = {**route, "updated_at": int(time.time()), "updated_by": actor[:200]}
    routes[route["name"]] = route
    kv_set(_rkey(tenant_id), routes)
    invalidate(tenant_id)
    return route


def delete_route(tenant_id: str, name: str) -> bool:
    from storage.tenant_store import kv_set
    _, routes = load(tenant_id)
    if name not in routes:
        return False
    routes.pop(name)
    kv_set(_rkey(tenant_id), routes)
    invalidate(tenant_id)
    return True


def public_target(t: dict) -> dict:
    """A target as the API shows it: the credential is only its reference."""
    return {**t, "auth": {k: v for k, v in (t.get("auth") or {}).items()}}


# ── the per-process cache ────────────────────────────────────────────


def cache_s() -> float:
    try:
        return max(1.0, float(os.environ.get("SHIELD_LLM_ROUTING_CACHE_S", "10")))
    except ValueError:
        return 10.0


class Snapshot:
    __slots__ = ("targets", "routes", "spend", "loaded_at")

    def __init__(self, targets: dict, routes: dict, spend: Optional[dict] = None):
        self.targets, self.routes, self.spend = targets, routes, spend or {}
        self.loaded_at = time.time()


_cache: dict[str, Snapshot] = {}
_refreshing: set = set()
_cache_lock = threading.Lock()


def _load_snapshot(tenant_id: str) -> Snapshot:
    targets, routes = load(tenant_id)
    spend = {}
    try:
        from core.llm_gateway import usage
        spend = usage.month_spend(tenant_id)
    except Exception:
        logger.debug("spend not loaded", exc_info=True)
    return Snapshot(targets, routes, spend)


def invalidate(tenant_id: str) -> None:
    """This process sees a change it made at once; others within cache_s()."""
    with _cache_lock:
        _cache.pop(tenant_id, None)


def _refresh_in_background(tenant_id: str) -> None:
    with _cache_lock:
        if tenant_id in _refreshing:
            return
        _refreshing.add(tenant_id)

    def run():
        try:
            snap = _load_snapshot(tenant_id)
            with _cache_lock:
                _cache[tenant_id] = snap
        except Exception:
            logger.warning("routing config refresh failed for a tenant; keeping the cached copy",
                           exc_info=True)
        finally:
            with _cache_lock:
                _refreshing.discard(tenant_id)
    threading.Thread(target=run, daemon=True, name="llm-routing-refresh").start()


async def cached(tenant_id: str) -> Optional[Snapshot]:
    """The tenant's routing config. Never raises: None when it cannot be loaded."""
    if not tenant_id:
        return None
    with _cache_lock:
        snap = _cache.get(tenant_id)
    if snap is not None:
        if time.time() - snap.loaded_at > cache_s():
            _refresh_in_background(tenant_id)
        return snap
    try:
        snap = await asyncio.get_running_loop().run_in_executor(None, _load_snapshot, tenant_id)
    except Exception:
        _log_unavailable()
        return None
    with _cache_lock:
        _cache[tenant_id] = snap
    return snap


_last_unavailable_log = 0.0


def _log_unavailable() -> None:
    global _last_unavailable_log
    if time.time() - _last_unavailable_log > 60:
        _last_unavailable_log = time.time()
        logger.warning("routing config unavailable (store down?); calls take the default upstream")


def reset_for_tests() -> None:
    with _cache_lock:
        _cache.clear()
        _refreshing.clear()
