"""Reference Web Bot Auth verifier for self-run edges (spec 2.5), lab version.

Nginx calls GET /verify as an auth_request subrequest for every shop request,
passing the original headers plus X-WBA-Authority (the Host the client
signed). It always answers 204: it labels, it never blocks. Nginx copies the
label into the access log:

    X-WBA        valid | invalid | unverified | none
    X-WBA-Agent  the operator's key directory URL from Signature-Agent

Shield reads those two log fields; it holds no keys and does no cryptography
(spec 2.5, "Verification happens at the edge").

Run:  python -m uvicorn verifier:app --port 8203   (from this directory)
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import Response

import webbotauth

STATE_DIR = Path(os.environ.get("LAB_STATE_DIR", Path(__file__).resolve().parent.parent / "state"))

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def registry() -> dict:
    """Directory origin -> keys: the lab's stand-in for fetched, cached key directories."""
    return {url: webbotauth.directory(STATE_DIR, name)["keys"] for name, url in webbotauth.OPERATORS.items()}


REGISTRY = registry()


def _clean(value: str, limit: int = 120) -> str:
    return "".join(c for c in value if 32 < ord(c) < 127)[:limit]


@app.get("/verify")
def verify(request: Request):
    result, agent = webbotauth.verify(dict(request.headers), request.headers.get("x-wba-authority", ""), REGISTRY)
    return Response(status_code=204, headers={"X-WBA": result, "X-WBA-Agent": _clean(agent)})


@app.get("/health")
def health():
    return {"ok": True, "operators": sorted(webbotauth.OPERATORS)}
