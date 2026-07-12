"""Connected mode: augment offline findings with Shield's model verdict.

POSTs each scanned description to the data-plane route `POST /guardrails/input`
(reused as-is — this package adds no server endpoint). The data plane runs its
model-backed guardrails (`AdversarialGuardrail` et al.) and returns a verdict;
a non-passing guardrail becomes a `source="model"` Finding.

Fail-open on augmentation: any network error / 5xx / auth failure degrades to
the offline heuristic verdict plus a note — a network blip must never turn a
clean scan into a CI failure. Heuristic findings still gate normally.

Privacy: only the description text is sent (as `{"message": <desc>}`). Never the
target server's credentials, env, or tool-call arguments.
"""

from __future__ import annotations

from shield_mcp.heuristics import subject_texts, _cap
from shield_mcp.report import Finding

# Map the guard's enforcement action to a scanner severity.
_MODEL_SEVERITY = {"block": "critical", "redact": "high", "warn": "medium", "log": "low"}
_INJECTION_HINTS = ("advers", "inject", "jailbreak", "prompt")


def _model_finding(kind: str, name: str, gr: dict) -> Finding:
    action = (gr.get("action") or "block").lower()
    sev = _MODEL_SEVERITY.get(action, "high")
    gname = gr.get("guardrail") or gr.get("guardrail_name") or "guardrail"
    if any(h in gname.lower() for h in _INJECTION_HINTS):
        category = "tool-poisoning"
        if action == "block":
            sev = "critical"
    else:
        category = "suspicious-metadata"
    return Finding(
        severity=sev,
        category=category,
        subject_kind=kind,
        subject_name=name,
        detail=gr.get("message") or f"model guardrail '{gname}' flagged this metadata.",
        evidence=gname,
        source="model",
    )


async def augment(
    report,
    catalog,
    *,
    shield_url: str,
    api_key: str = "",
    timeout: float = 20.0,
    transport=None,  # test seam: an httpx transport (e.g. MockTransport)
):
    """Merge model findings into `report` in place. Fail-open; returns `report`."""
    import httpx  # lazy: offline mode must not require httpx at import time

    url = shield_url.rstrip("/") + "/guardrails/input"
    headers = {"X-API-Key": api_key} if api_key else {}
    checked = 0
    try:
        async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
            for kind, name, text in subject_texts(catalog):
                text = _cap(text)
                if not text.strip():
                    continue
                # Privacy invariant: the ONLY thing that leaves the process is the
                # description text, under the "message" key. No creds, no args.
                resp = await client.post(url, json={"message": text}, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                for gr in data.get("guardrail_results", []) or []:
                    if gr.get("passed") is False:
                        report.findings.append(_model_finding(kind, name, gr))
                checked += 1
    except Exception as e:
        report.notes.append(
            f"connected mode skipped (model verdict unavailable): {type(e).__name__}: {e}; "
            "reporting heuristics-only verdict"
        )
        return report

    report.notes.append(f"connected: model verdict via {url} ({checked} descriptions)")
    return report
