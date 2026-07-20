"""CycloneDX 1.6 interop for the AIBOM (spec addendum, PRs 6-7).

Pure mapping functions, no I/O:
- to_cyclonedx(bom)   — Shield AIBOM document -> CycloneDX 1.6 ML-BOM JSON,
  so Shield BOMs flow into standard supply-chain tooling (GUAC,
  Dependency-Track) alongside cluster-side generators like k8s-aibom.
- from_cyclonedx(doc) — CycloneDX JSON -> declared-section components, so an
  external BOM (e.g. k8s-aibom's webhook sink) can be ingested into the
  tenant's declared inventory.

Shield-specific fields ride in `properties` under the `shield:` namespace
(CycloneDX property values must be strings — non-strings are JSON-encoded).
"""

from __future__ import annotations

import json
import re
import uuid

CDX_SPEC_VERSION = "1.6"

# Shield section -> CycloneDX component type
_SECTION_CDX_TYPE = {
    "models": "machine-learning-model",
    "prompts": "data",
    "knowledge_sources": "data",
    "memory": "data",
    "supply_chain": "library",
    "agents": "application",
    "tools": "application",
    "guardrails": "application",
    "runtime_policies": "application",
}

# CycloneDX component type -> Shield declared section (ingest direction).
# Anything unmapped lands in supply_chain, the catch-all dependency inventory.
_CDX_TYPE_SECTION = {
    "machine-learning-model": "models",
    "data": "knowledge_sources",
}
_INGEST_FALLBACK_SECTION = "supply_chain"
INGESTABLE_SECTIONS = ("models", "knowledge_sources", "supply_chain")

_ID_SANITIZE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _props(entry: dict, skip: tuple = ()) -> list[dict]:
    """Every entry field as a shield:* CycloneDX property (string values)."""
    props = []
    for k in sorted(entry):
        if k in skip or entry[k] is None:
            continue
        v = entry[k]
        props.append({"name": f"shield:{k}",
                      "value": v if isinstance(v, str) else json.dumps(v)})
    return props


def _component(cdx_type: str, ref: str, name: str, entry: dict, skip: tuple) -> dict:
    comp = {"type": cdx_type, "bom-ref": ref, "name": name}
    version = entry.get("version")
    if version is not None:
        comp["version"] = str(version)
    props = _props(entry, skip=skip + ("version",))
    if props:
        comp["properties"] = props
    return comp


def to_cyclonedx(bom: dict) -> dict:
    """Map a Shield AIBOM document to a CycloneDX 1.6 ML-BOM."""
    meta = bom.get("metadata") or {}
    components: list[dict] = []

    for section in ("models", "prompts", "knowledge_sources", "memory", "supply_chain"):
        for e in bom.get(section) or []:
            cid = e.get("component_id") or "unknown"
            components.append(_component(
                _SECTION_CDX_TYPE[section], f"{section}/{cid}",
                str(e.get("name") or cid), e, skip=("component_id", "name")))

    for a in bom.get("agents") or []:
        components.append(_component(
            "application", f"agents/{a.get('agent_id')}",
            str(a.get("name") or a.get("agent_id")), a, skip=("agent_id", "name")))
    for t in bom.get("tools") or []:
        components.append(_component(
            "application", f"tools/{t.get('name')}", str(t.get("name")), t, skip=("name",)))
    for g in bom.get("guardrails") or []:
        components.append(_component(
            "application", f"guardrails/{g.get('stage')}/{g.get('name')}",
            str(g.get("name")), g, skip=("name",)))

    services = []
    for s in bom.get("mcp_servers") or []:
        svc = {"bom-ref": f"mcp_servers/{s.get('name')}", "name": str(s.get("name"))}
        if s.get("endpoint"):
            svc["endpoints"] = [s["endpoint"]]
        props = _props(s, skip=("name", "endpoint"))
        if props:
            svc["properties"] = props
        services.append(svc)

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": meta.get("generated_at"),
            "tools": {"components": [{"type": "application", "name": "llm-shield"}]},
            "component": {
                "type": "application",
                "name": str(meta.get("application") or meta.get("tenant_id") or "unknown"),
                "properties": _props(meta, skip=("application", "generated_at")),
            },
        },
        "components": components,
    }
    if services:
        doc["services"] = services
    return doc


def _ingest_id(comp: dict) -> str:
    raw = comp.get("bom-ref") or comp.get("purl") or comp.get("name") or ""
    if comp.get("name") and comp.get("version") and not comp.get("bom-ref"):
        raw = f"{comp['name']}-{comp['version']}"
    return _ID_SANITIZE_RE.sub("-", str(raw)).strip("-")[:128]


def from_cyclonedx(doc: dict) -> tuple[dict, list[str]]:
    """Map CycloneDX components to declared sections.

    Returns ({section: {id: component}}, notes). Unmappable entries (no
    usable id) are skipped and counted in notes — never silently dropped.
    """
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX document (bomFormat != 'CycloneDX')")

    out: dict[str, dict] = {}
    notes: list[str] = []
    skipped_no_id = 0
    for comp in doc.get("components") or []:
        if not isinstance(comp, dict):
            continue
        cid = _ingest_id(comp)
        if not cid:
            skipped_no_id += 1
            continue
        section = _CDX_TYPE_SECTION.get(comp.get("type"), _INGEST_FALLBACK_SECTION)
        entry = {"name": comp.get("name"), "type": comp.get("type"),
                 "source": "cyclonedx-ingest"}
        if comp.get("version") is not None:
            entry["version"] = comp["version"]
        if comp.get("purl"):
            entry["purl"] = comp["purl"]
        for p in comp.get("properties") or []:
            if isinstance(p, dict) and p.get("name") and p.get("value") is not None:
                entry.setdefault("properties", {})[str(p["name"])] = str(p["value"])
        out.setdefault(section, {})[cid] = entry
    if skipped_no_id:
        notes.append(f"{skipped_no_id} components skipped (no usable id)")
    return out, notes
