"""Extract auth requirements from an OpenAPI spec's securitySchemes.

Turns the spec's declared auth into a small, language-agnostic plan the code
generators can wire to environment variables — so a generated server
authenticates to the upstream API without the developer hand-coding it.

Supported scheme types:
  - apiKey   (in header | query | cookie)
  - http bearer
  - http basic
  - oauth2 client-credentials (token fetched from the flow's tokenUrl)

Pure, no I/O.
"""

from __future__ import annotations

import re
from typing import Any


def _env_name(prefix: str, key: str) -> str:
    base = re.sub(r"[^A-Z0-9]+", "_", key.upper()).strip("_")
    return f"{prefix}_{base}" if base else prefix


def extract_security(spec: dict) -> list[dict]:
    """Return the applicable auth schemes as a list of plan dicts.

    Uses the global ``security`` requirement when present; otherwise falls back
    to every scheme defined in ``securitySchemes`` (so a spec that declares auth
    but forgets the global requirement still wires up). Each plan dict:

      {"type":"apiKey","in":"header","name":"X-API-Key","env":"API_KEY"}
      {"type":"bearer","env":"API_TOKEN"}
      {"type":"basic","env_user":"API_USERNAME","env_pass":"API_PASSWORD"}
      {"type":"oauth2","token_url":"...","env_id":"OAUTH_CLIENT_ID",
       "env_secret":"OAUTH_CLIENT_SECRET","scopes":[...]}
    """
    comps = (spec.get("components") or {}).get("securitySchemes") or {}
    # Swagger 2.0 puts them at top-level securityDefinitions.
    if not comps:
        comps = spec.get("securityDefinitions") or {}
    if not comps:
        return []

    global_sec = spec.get("security")
    if global_sec:
        wanted = []
        for req in global_sec:
            wanted.extend(req.keys())
        scheme_names = list(dict.fromkeys(wanted))  # de-dup, keep order
    else:
        scheme_names = list(comps.keys())

    plans: list[dict] = []
    for name in scheme_names:
        s = comps.get(name)
        if not isinstance(s, dict):
            continue
        plan = _plan_for(name, s)
        if plan:
            plans.append(plan)
    return plans


def _plan_for(name: str, s: dict) -> dict | None:
    stype = (s.get("type") or "").lower()

    if stype == "apikey":
        return {
            "type": "apiKey",
            "in": s.get("in", "header"),
            "name": s.get("name", "X-API-Key"),
            "env": _env_name("API_KEY", name),
        }
    if stype == "http":
        scheme = (s.get("scheme") or "").lower()
        if scheme == "basic":
            return {"type": "basic",
                    "env_user": _env_name("API_USER", name),
                    "env_pass": _env_name("API_PASS", name)}
        # default http -> bearer
        return {"type": "bearer", "env": _env_name("API_TOKEN", name)}
    if stype == "oauth2":
        flows = s.get("flows") or {}
        cc = flows.get("clientCredentials") or {}
        token_url = cc.get("tokenUrl") or (s.get("tokenUrl") if s.get("flow") == "application" else "")
        return {
            "type": "oauth2",
            "token_url": token_url or "",
            "scopes": list((cc.get("scopes") or {}).keys()),
            "env_id": _env_name("OAUTH_CLIENT_ID", name),
            "env_secret": _env_name("OAUTH_CLIENT_SECRET", name),
        }
    # Swagger 2.0 oauth2 uses type "oauth2" handled above; basic uses "basic".
    if stype == "basic":
        return {"type": "basic",
                "env_user": _env_name("API_USER", name),
                "env_pass": _env_name("API_PASS", name)}
    return None
