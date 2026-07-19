"""AIBOM (AI Bill of Materials) generator — observed sections.

Assembles a per-tenant AIBOM v1.0 document (see docs/spec-aibom.md) from
state Shield already holds: the agent registry, shadow agents observed in
traffic, tool definitions/policies, MCP gateway routes, guardrail config,
RBAC roles, and the bounded runtime activity buffer. Declared sections
(models, prompts, knowledge sources, memory, supply chain) are filled by
the declare API in a later task; until then they render empty with a note.

LATENCY: read-only aggregation over data already written by the
auth/registry/guard paths. Nothing in this module runs on the guard path
(/guardrails/*, cap/mint, tools/call) — admin-plane only.

Every source that fails to load degrades soft: the section renders empty
and an entry is appended to generation_notes. Emission caps are explicit
in generation_notes too — no silent gaps, no silent truncation. No secret
values ever appear in a BOM (MCP upstream credentials and webhook secrets
are dropped, not masked).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from storage.tenant_store import get_tenant, kv_get

logger = logging.getLogger("votal.aibom")

BOM_FORMAT = "aibom"
SPEC_VERSION = "1.0"
GENERATED_BY = "llm-shield"

VIEWS = ("full", "observed", "declared")

# Emission caps (spec §7) — anything dropped is counted in generation_notes.
MAX_AGENTS = 500
MAX_TOOLS = 500
MAX_MCP_SERVERS = 200

# Upstream MCP config keys that may hold credentials (mirrors the redaction
# list in api/routes_mcp_gateway.py) — dropped entirely from BOM output.
_MCP_SECRET_KEYS = ("headers", "env", "shield_tenant_key", "secret", "token", "api_key")

_ACTIVITY_WINDOW = 50  # agent_auth_stats.RECENT_BUFFER_MAX (bounded buffer)

DECLARED_SECTIONS = ("models", "prompts", "knowledge_sources", "memory", "supply_chain")
# "metadata" is declared as flat fields (environment, owner, ...) rather than
# id-keyed components; it overlays the observed metadata section on read.
DECLARABLE_SECTIONS = DECLARED_SECTIONS + ("metadata",)
OBSERVED_LIST_SECTIONS = ("agents", "mcp_servers", "tools", "guardrails", "runtime_policies")

# Declared metadata may not shadow generator-owned fields.
PROTECTED_METADATA_FIELDS = ("tenant_id", "generated_at", "generated_by")


# ── Snapshots & drift (spec §18) ──────────────────────────────────────────
#
# A snapshot is the approved design-time baseline: the full BOM minus
# volatile fields, so drift means configuration drift, not traffic.

MAX_SNAPSHOTS = 20
MAX_SNAPSHOT_BYTES = 512 * 1024

# Doc-level keys and per-entry fields excluded from snapshots/drift.
_VOLATILE_DOC_KEYS = ("generation_notes", "observability", "view")
_VOLATILE_ENTRY_FIELDS = ("last_seen", "first_seen", "recent_tools_used",
                          "created_at", "updated_at")
_VOLATILE_METADATA_FIELDS = ("generated_at",)

# section name -> field that identifies an entry within it (guardrails use a
# composite key since the same name can exist in both stages).
_DRIFT_SECTIONS = {
    "agents": "agent_id",
    "tools": "name",
    "mcp_servers": "name",
    "guardrails": ("stage", "name"),
    "runtime_policies": "tool_name",
    "models": "component_id",
    "prompts": "component_id",
    "knowledge_sources": "component_id",
    "memory": "component_id",
    "supply_chain": "component_id",
}


def _snapshot_key(tenant_id: str, snapshot_id: str) -> str:
    return f"aibom:snapshot:{tenant_id}:{snapshot_id}"


def _snapshot_index_key(tenant_id: str) -> str:
    return f"aibom:snapshots:{tenant_id}"


def strip_volatile(doc: dict) -> dict:
    """A copy of the BOM without traffic-derived fields (snapshot/drift form)."""
    out = {k: v for k, v in doc.items() if k not in _VOLATILE_DOC_KEYS}
    out["metadata"] = {k: v for k, v in (doc.get("metadata") or {}).items()
                       if k not in _VOLATILE_METADATA_FIELDS}
    for section in _DRIFT_SECTIONS:
        entries = doc.get(section)
        if isinstance(entries, list):
            out[section] = [
                {k: v for k, v in (e or {}).items() if k not in _VOLATILE_ENTRY_FIELDS}
                for e in entries
            ]
    return out


def create_snapshot(tenant_id: str, approved_by: str = "", note: str = "") -> dict:
    """Snapshot the current full BOM as the approved baseline.

    Returns the index entry. Raises ValueError if the snapshot exceeds
    MAX_SNAPSHOT_BYTES. The index keeps the MAX_SNAPSHOTS most recent
    entries; older snapshot docs are deleted with their index rows.
    """
    import json as _json
    import secrets as _secrets
    from storage.tenant_store import kv_set

    doc = strip_volatile(generate_aibom(tenant_id, view="full"))
    now = int(datetime.now(timezone.utc).timestamp())
    snapshot_id = f"bom-{now}-{_secrets.token_hex(3)}"
    snapshot = {
        "snapshot_id": snapshot_id,
        "created_at": now,
        "approved_by": approved_by or "tenant",
        "note": note or "",
        "bom": doc,
    }
    size = len(_json.dumps(snapshot))
    if size > MAX_SNAPSHOT_BYTES:
        raise ValueError(f"snapshot would be {size} bytes (max {MAX_SNAPSHOT_BYTES})")

    kv_set(_snapshot_key(tenant_id, snapshot_id), snapshot)

    index = kv_get(_snapshot_index_key(tenant_id)) or {"snapshots": []}
    entry = {"snapshot_id": snapshot_id, "created_at": now,
             "approved_by": snapshot["approved_by"], "note": snapshot["note"]}
    index.setdefault("snapshots", []).append(entry)
    evicted = []
    while len(index["snapshots"]) > MAX_SNAPSHOTS:
        evicted.append(index["snapshots"].pop(0))
    kv_set(_snapshot_index_key(tenant_id), index)
    for old in evicted:
        try:
            kv_set(_snapshot_key(tenant_id, old["snapshot_id"]), None)
        except Exception:
            logger.debug(f"aibom: failed to clear evicted snapshot {old['snapshot_id']}")
    if evicted:
        entry = dict(entry)
        entry["evicted"] = [o["snapshot_id"] for o in evicted]
    return entry


def list_snapshots(tenant_id: str) -> list[dict]:
    index = kv_get(_snapshot_index_key(tenant_id)) or {}
    return index.get("snapshots", [])


def get_snapshot(tenant_id: str, snapshot_id: str):
    return kv_get(_snapshot_key(tenant_id, snapshot_id)) or None


def _entry_key(section: str, entry: dict):
    key_field = _DRIFT_SECTIONS[section]
    if isinstance(key_field, tuple):
        return ":".join(str((entry or {}).get(f)) for f in key_field)
    return (entry or {}).get(key_field)


def _diff_entries(section: str, before: list, after: list) -> dict:
    b = {_entry_key(section, e): e for e in (before or []) if _entry_key(section, e) is not None}
    a = {_entry_key(section, e): e for e in (after or []) if _entry_key(section, e) is not None}
    added = sorted(k for k in a if k not in b)
    removed = sorted(k for k in b if k not in a)
    changed = []
    for k in sorted(k for k in a if k in b):
        fields = set(b[k]) | set(a[k])
        for f in sorted(fields):
            if b[k].get(f) != a[k].get(f):
                changed.append({"key": k, "field": f,
                                "before": b[k].get(f), "after": a[k].get(f)})
    return {"added": added, "removed": removed, "changed": changed}


def compute_drift(tenant_id: str, snapshot_id: str = None):
    """Diff the current BOM against an approved snapshot.

    Returns the drift report, or None when no snapshot exists (or the
    requested snapshot_id is unknown).
    """
    if snapshot_id is None:
        snaps = list_snapshots(tenant_id)
        if not snaps:
            return None
        snapshot_id = snaps[-1]["snapshot_id"]
    snapshot = get_snapshot(tenant_id, snapshot_id)
    if not snapshot:
        return None

    baseline = snapshot.get("bom") or {}
    current = strip_volatile(generate_aibom(tenant_id, view="full"))

    drift: dict = {}
    count = 0
    for section in _DRIFT_SECTIONS:
        d = _diff_entries(section, baseline.get(section), current.get(section))
        drift[section] = d
        count += len(d["added"]) + len(d["removed"]) + len(d["changed"])
    identity_diff = _diff_entries("guardrails", [], [])  # shape only
    identity_diff["changed"] = [
        {"key": "identity", "field": f,
         "before": (baseline.get("identity") or {}).get(f),
         "after": (current.get("identity") or {}).get(f)}
        for f in sorted(set(baseline.get("identity") or {}) | set(current.get("identity") or {}))
        if (baseline.get("identity") or {}).get(f) != (current.get("identity") or {}).get(f)
    ]
    drift["identity"] = identity_diff
    count += len(identity_diff["changed"])

    return {
        "tenant_id": tenant_id,
        "snapshot_id": snapshot_id,
        "snapshot_created_at": snapshot.get("created_at"),
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "drift": drift,
        "drift_count": count,
        "clean": count == 0,
    }


def _declared_key(tenant_id: str) -> str:
    return f"aibom:declared:{tenant_id}"


def load_declared(tenant_id: str) -> dict:
    """The tenant's declared-components document (empty dict if none)."""
    return kv_get(_declared_key(tenant_id)) or {}


def save_declared(tenant_id: str, doc: dict) -> None:
    from storage.tenant_store import kv_set
    kv_set(_declared_key(tenant_id), doc)


def generate_aibom(tenant_id: str, view: str = "full") -> dict:
    """Generate the tenant's AIBOM document. view: full | observed | declared."""
    if view not in VIEWS:
        raise ValueError(f"view must be one of {VIEWS}")

    notes: list[str] = []
    include_observed = view in ("full", "observed")
    include_declared = view in ("full", "declared")

    doc: dict = {
        "bom_format": BOM_FORMAT,
        "spec_version": SPEC_VERSION,
        "view": view,
        "metadata": _section(notes, "metadata", lambda: _build_metadata(tenant_id), {}),
    }

    if include_observed:
        doc["agents"] = _section(notes, "agents", lambda: _build_agents(tenant_id, notes), [])
        doc["mcp_servers"] = _section(notes, "mcp_servers", lambda: _build_mcp_servers(tenant_id, notes), [])
        doc["tools"] = _section(notes, "tools", lambda: _build_tools(tenant_id, notes), [])
        doc["guardrails"] = _section(notes, "guardrails", lambda: _build_guardrails(tenant_id), [])
        doc["runtime_policies"] = _section(notes, "runtime_policies", lambda: _build_runtime_policies(tenant_id), [])
        doc["identity"] = _section(notes, "identity", lambda: _build_identity(tenant_id), {})
        doc["observability"] = _section(notes, "observability", lambda: _build_observability(tenant_id), {})
    else:
        for s in OBSERVED_LIST_SECTIONS:
            doc[s] = []
        doc["identity"] = {}
        doc["observability"] = {}
        notes.append("observed sections excluded (view=declared)")

    declared_doc: dict = {}
    if include_declared:
        declared_doc = _section(notes, "declared_components", lambda: load_declared(tenant_id), {})
    for s in DECLARED_SECTIONS:
        comps = declared_doc.get(s) or {}
        doc[s] = [{**(c or {}), "component_id": cid} for cid, c in sorted(comps.items())]
    if include_declared:
        declared_meta = declared_doc.get("metadata") or {}
        for k, v in declared_meta.items():
            if k not in PROTECTED_METADATA_FIELDS:
                doc["metadata"][k] = v
        if not declared_meta and not any(doc[s] for s in DECLARED_SECTIONS):
            notes.append("no declared components")
    else:
        notes.append("declared sections excluded (view=observed)")

    # Threat/compliance/risk mapping ships in a later task (spec §15-§17).
    doc["threats"] = []
    doc["compliance"] = []
    doc["risk"] = {}
    notes.append("threat/compliance/risk mapping not yet available")

    doc["generation_notes"] = notes
    return doc


def _section(notes: list[str], name: str, builder, default):
    """Run one section builder fail-soft: on error, default + a note."""
    try:
        return builder()
    except Exception as e:
        logger.debug(f"aibom: {name} builder failed: {e}")
        notes.append(f"{name}: source unavailable ({type(e).__name__})")
        return default


# ── §2 Metadata ───────────────────────────────────────────────────────────

def _build_metadata(tenant_id: str) -> dict:
    config = get_tenant(tenant_id) or {}
    return {
        "application": config.get("name") or tenant_id,
        "tenant_id": tenant_id,
        "environment": None,  # declared metadata (later task) supplies this
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": GENERATED_BY,
        "organization": config.get("organization"),
        "owner": config.get("owner"),
        "git_commit": None,
        "deployment_id": None,
        "plan": config.get("plan"),
    }


# ── §5 Agents (registered + shadow) ───────────────────────────────────────

def _granted_tools(entry: dict) -> list[str]:
    """Union of directly-granted tools and all role_permissions (mirrors
    api/routes_governance.py)."""
    tools = set(entry.get("tools") or [])
    for perms in (entry.get("role_permissions") or {}).values():
        tools.update(perms or [])
    return sorted(tools)


def _activity_index(tenant_id: str, notes: list[str]) -> dict:
    """Per-agent recent activity from the bounded auth-event buffer.
    Failure here degrades activity fields only, never the section."""
    idx: dict[str, dict] = {}
    try:
        from storage import agent_auth_stats as stats
        for e in stats.get_recent(tenant_id, limit=_ACTIVITY_WINDOW):
            aid = e.get("agent_id")
            if not aid:
                continue
            a = idx.setdefault(aid, {"last_seen": 0, "tools": set()})
            ts = e.get("ts", 0) or 0
            if ts > a["last_seen"]:
                a["last_seen"] = ts
            if e.get("tool"):
                a["tools"].add(e["tool"])
        notes.append(f"agent activity window is the last {_ACTIVITY_WINDOW} auth events")
    except Exception as e:
        logger.debug(f"aibom: activity index failed: {e}")
        notes.append(f"agent activity unavailable ({type(e).__name__})")
    return idx


def _build_agents(tenant_id: str, notes: list[str]) -> list[dict]:
    registered = kv_get(f"agents:{tenant_id}") or {}
    unregistered = (kv_get(f"unregistered:{tenant_id}") or {}).get("agents", {}) or {}
    activity = _activity_index(tenant_id, notes)

    agents: list[dict] = []
    for aid, entry in registered.items():
        entry = entry or {}
        act = activity.get(aid, {})
        agents.append({
            "agent_id": aid,
            "name": entry.get("name", aid),
            "source": "registered",
            "status": entry.get("status", "active"),
            "allowed_tools": _granted_tools(entry),
            "allowed_resources": entry.get("allowed_resources", []) or [],
            "roles": sorted((entry.get("role_permissions") or {}).keys()),
            "require_resource_scope": bool(entry.get("require_resource_scope", False)),
            "created_at": entry.get("created_at"),
            "updated_at": entry.get("updated_at"),
            "last_seen": act.get("last_seen", 0),
            "recent_tools_used": sorted(act.get("tools", set())),
        })
    for aid, meta in unregistered.items():
        if aid in registered:
            continue
        act = activity.get(aid, {})
        agents.append({
            "agent_id": aid,
            "name": aid,
            "source": "shadow",  # observed in traffic, never registered
            "status": "unregistered",
            "allowed_tools": [],
            "allowed_resources": [],
            "roles": [],
            "require_resource_scope": False,
            "first_seen": (meta or {}).get("first_seen"),
            "last_seen": act.get("last_seen", (meta or {}).get("last_seen", 0)),
            "recent_tools_used": sorted(act.get("tools", set())),
        })

    agents.sort(key=lambda a: (a["source"] != "registered", a["agent_id"]))
    if len(agents) > MAX_AGENTS:
        notes.append(f"agents: {len(agents) - MAX_AGENTS} entries truncated (cap {MAX_AGENTS})")
        agents = agents[:MAX_AGENTS]
    return agents


# ── §6 MCP servers (gateway upstreams) ────────────────────────────────────

def _build_mcp_servers(tenant_id: str, notes: list[str]) -> list[dict]:
    from storage.mcp_gateway_store import list_upstreams

    servers: list[dict] = []
    for cfg in list_upstreams(tenant_id):
        cfg = cfg or {}
        servers.append({
            "name": cfg.get("route"),
            "endpoint": cfg.get("url"),
            "transport": cfg.get("transport"),
            "version": cfg.get("version"),
            # Credential material is dropped, never masked-in-place: the BOM
            # records only that credentials are configured.
            "has_credentials": any(cfg.get(k) for k in _MCP_SECRET_KEYS),
        })

    servers.sort(key=lambda s: s.get("name") or "")
    if len(servers) > MAX_MCP_SERVERS:
        notes.append(
            f"mcp_servers: {len(servers) - MAX_MCP_SERVERS} entries truncated (cap {MAX_MCP_SERVERS})")
        servers = servers[:MAX_MCP_SERVERS]
    return servers


# ── §7 Tools (definitions + policies + killswitch) ────────────────────────

def _build_tools(tenant_id: str, notes: list[str]) -> list[dict]:
    definitions = kv_get(f"tool_definitions:{tenant_id}") or []
    by_name: dict[str, dict] = {}
    for d in definitions:
        fn = (d or {}).get("function") or {}
        name = fn.get("name")
        if not name:
            continue
        by_name[name] = {
            "name": name,
            "description": fn.get("description"),
            "has_definition": True,
            "has_policy": False,
            "policy": None,
            "disabled": False,
        }

    try:
        from storage.policy_store import get_tool_policies
        policies = get_tool_policies(tenant_id) or {}
    except Exception as e:
        policies = {}
        notes.append(f"tools: policies unavailable ({type(e).__name__})")
    for name, policy in policies.items():
        if name == "updated_at" or not isinstance(policy, dict):
            continue
        t = by_name.setdefault(name, {
            "name": name, "description": None, "has_definition": False,
            "has_policy": False, "policy": None, "disabled": False,
        })
        t["has_policy"] = True
        t["policy"] = policy

    try:
        from storage.tool_killswitch import list_disabled_tools
        for d in list_disabled_tools(tenant_id) or []:
            name = d.get("tool_name") if isinstance(d, dict) else d
            if not name:
                continue
            t = by_name.setdefault(name, {
                "name": name, "description": None, "has_definition": False,
                "has_policy": False, "policy": None, "disabled": False,
            })
            t["disabled"] = True
    except Exception as e:
        notes.append(f"tools: killswitch state unavailable ({type(e).__name__})")

    tools = sorted(by_name.values(), key=lambda t: t["name"])
    if len(tools) > MAX_TOOLS:
        notes.append(f"tools: {len(tools) - MAX_TOOLS} entries truncated (cap {MAX_TOOLS})")
        tools = tools[:MAX_TOOLS]
    return tools


# ── §11 Guardrails (tenant config + custom policies) ──────────────────────

def _guardrail_entries(config_section: dict, stage: str) -> list[dict]:
    entries = []
    for name, cfg in (config_section or {}).items():
        enabled = bool(cfg.get("enabled", True)) if isinstance(cfg, dict) else bool(cfg)
        entries.append({"name": name, "stage": stage, "type": "builtin", "enabled": enabled})
    return entries


def _build_guardrails(tenant_id: str) -> list[dict]:
    config = get_tenant(tenant_id) or {}
    entries = _guardrail_entries(config.get("input_guardrails", {}), "input")
    entries += _guardrail_entries(config.get("output_guardrails", {}), "output")

    try:
        from storage.custom_policies import get_tenant_custom_policies
        for p in get_tenant_custom_policies(tenant_id, enabled_only=False) or []:
            entries.append({
                "name": p.get("name") or p.get("policy_id"),
                "stage": p.get("stage"),
                "type": "custom_policy",
                "enabled": bool(p.get("enabled", True)),
                "policy_id": p.get("policy_id"),
            })
    except Exception as e:
        logger.debug(f"aibom: custom policies unavailable: {e}")

    entries.sort(key=lambda g: (g.get("stage") or "", g.get("name") or ""))
    return entries


# ── §12 Runtime policies (per-tool policies) ──────────────────────────────

def _build_runtime_policies(tenant_id: str) -> list[dict]:
    from storage.policy_store import get_tool_policies
    policies = get_tool_policies(tenant_id) or {}
    entries = [
        {"type": "tool_policy", "tool_name": name, "policy": policy}
        for name, policy in policies.items()
        if name != "updated_at" and isinstance(policy, dict)
    ]
    entries.sort(key=lambda p: p["tool_name"])
    return entries


# ── §8 Identity & authorization surface ───────────────────────────────────

def _build_identity(tenant_id: str) -> dict:
    config = get_tenant(tenant_id) or {}
    allowlist = (config.get("input_guardrails", {}) or {}).get("tool_allowlist", {})
    settings = (allowlist or {}).get("settings", {}) if isinstance(allowlist, dict) else {}
    return {
        "rbac_roles": sorted((config.get("rbac", {}) or {}).get("roles", {}).keys()),
        "tool_allowlist_per_role": sorted((settings.get("per_role") or {}).keys()),
        "tool_allowlist_per_agent": sorted((settings.get("per_agent") or {}).keys()),
    }


# ── §13 Observability summary ─────────────────────────────────────────────

def _build_observability(tenant_id: str) -> dict:
    out: dict = {}
    try:
        from storage.guardrail_metrics import get_all_guardrails_summary
        summary = get_all_guardrails_summary(tenant_id, days=30) or []
        out["guardrail_metrics"] = {
            "window_days": 30,
            "guardrails_tracked": len(summary),
            "total_evaluations": sum(g.get("total", 0) for g in summary),
            "total_blocked": sum(g.get("blocked", 0) for g in summary),
        }
    except Exception as e:
        logger.debug(f"aibom: guardrail metrics unavailable: {e}")
        out["guardrail_metrics"] = None

    try:
        from storage.webhook_store import get_webhooks
        hooks = get_webhooks(tenant_id) or []
        # Only event subscriptions — webhook URLs and secrets stay out of the BOM.
        out["webhooks"] = {
            "count": len(hooks),
            "events": sorted({ev for h in hooks for ev in (h.get("events") or [])}),
        }
    except Exception as e:
        logger.debug(f"aibom: webhooks unavailable: {e}")
        out["webhooks"] = None
    return out
