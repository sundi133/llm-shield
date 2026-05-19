"""Pluggable artifact registry storage.

Backends:
    redis  — uses the shared Redis connection from storage.tenant_store
    file   — JSON file on disk (default for dev / when Redis is absent)

Backend selection: ARTIFACT_STORE_BACKEND env var. If unset, Redis is used
when available, otherwise the file backend is used. The file location is
controlled by ARTIFACT_STORE_PATH (default: ./storage/artifacts.json).

Redis keys:
    artifact:{tenant_id}:{kind}:{name}:{version}  → JSON Artifact
    artifact:index:{tenant_id}:{kind}              → SET of f"{name}:{version}"
    artifact:pin:{tenant_id}:{kind}:{name}         → pinned version string
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime
from typing import Iterable, Optional

from core.artifacts import Artifact, ArtifactKind, artifact_id

logger = logging.getLogger("votal.artifact_store")


_BACKEND = os.environ.get("ARTIFACT_STORE_BACKEND", "").lower()
_FILE_PATH = os.environ.get(
    "ARTIFACT_STORE_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "storage", "artifacts.json"),
)


class ArtifactStore:
    """Abstract store interface."""

    def put(self, artifact: Artifact) -> Artifact: ...
    def get(self, tenant_id: str, kind: ArtifactKind, name: str, version: str) -> Optional[Artifact]: ...
    def delete(self, tenant_id: str, kind: ArtifactKind, name: str, version: str) -> bool: ...
    def list(self, tenant_id: str, kind: Optional[ArtifactKind] = None, name: Optional[str] = None) -> list[Artifact]: ...
    def set_pin(self, tenant_id: str, kind: ArtifactKind, name: str, version: Optional[str]) -> None: ...
    def get_pin(self, tenant_id: str, kind: ArtifactKind, name: str) -> Optional[str]: ...


# ---------------- File backend ----------------

class FileArtifactStore(ArtifactStore):
    """JSON-on-disk store. Process-safe via a threading lock; intended for
    dev/test or single-node deployments. For multi-node use the Redis backend.
    """

    def __init__(self, path: str = _FILE_PATH):
        self._path = path
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        if not os.path.exists(self._path):
            self._write({"artifacts": {}, "pins": {}})

    def _read(self) -> dict:
        try:
            with open(self._path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"artifacts": {}, "pins": {}}

    def _write(self, data: dict) -> None:
        tmp = self._path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, default=str, indent=2)
        os.replace(tmp, self._path)

    def put(self, artifact: Artifact) -> Artifact:
        with self._lock:
            data = self._read()
            artifact.updated_at = datetime.utcnow()
            data["artifacts"][artifact.id] = json.loads(artifact.model_dump_json())
            self._write(data)
        return artifact

    def get(self, tenant_id: str, kind: ArtifactKind, name: str, version: str) -> Optional[Artifact]:
        with self._lock:
            data = self._read()
        raw = data["artifacts"].get(artifact_id(tenant_id, kind, name, version))
        return Artifact(**raw) if raw else None

    def delete(self, tenant_id: str, kind: ArtifactKind, name: str, version: str) -> bool:
        with self._lock:
            data = self._read()
            key = artifact_id(tenant_id, kind, name, version)
            removed = data["artifacts"].pop(key, None) is not None
            if removed:
                self._write(data)
        return removed

    def list(self, tenant_id: str, kind: Optional[ArtifactKind] = None, name: Optional[str] = None) -> list[Artifact]:
        with self._lock:
            data = self._read()
        results: list[Artifact] = []
        for raw in data["artifacts"].values():
            if raw.get("tenant_id") != tenant_id:
                continue
            if kind and raw.get("kind") != kind.value:
                continue
            if name and raw.get("name") != name:
                continue
            results.append(Artifact(**raw))
        return results

    def set_pin(self, tenant_id: str, kind: ArtifactKind, name: str, version: Optional[str]) -> None:
        pin_key = f"{tenant_id}:{kind.value}:{name}"
        with self._lock:
            data = self._read()
            if version is None:
                data["pins"].pop(pin_key, None)
            else:
                data["pins"][pin_key] = version
            # Mark Artifact.pinned flags as well (best-effort, single source of truth = pins map)
            for raw in data["artifacts"].values():
                if (
                    raw.get("tenant_id") == tenant_id
                    and raw.get("kind") == kind.value
                    and raw.get("name") == name
                ):
                    raw["pinned"] = (version is not None and raw.get("version") == version)
            self._write(data)

    def get_pin(self, tenant_id: str, kind: ArtifactKind, name: str) -> Optional[str]:
        with self._lock:
            data = self._read()
        return data["pins"].get(f"{tenant_id}:{kind.value}:{name}")


# ---------------- Redis backend ----------------

class RedisArtifactStore(ArtifactStore):
    def __init__(self):
        from storage.tenant_store import _get_redis
        self._get_redis = _get_redis

    def _k(self, tenant_id: str, kind: ArtifactKind, name: str, version: str) -> str:
        return f"artifact:{tenant_id}:{kind.value}:{name}:{version}"

    def _index_key(self, tenant_id: str, kind: ArtifactKind) -> str:
        return f"artifact:index:{tenant_id}:{kind.value}"

    def _pin_key(self, tenant_id: str, kind: ArtifactKind, name: str) -> str:
        return f"artifact:pin:{tenant_id}:{kind.value}:{name}"

    def put(self, artifact: Artifact) -> Artifact:
        r = self._get_redis()
        artifact.updated_at = datetime.utcnow()
        payload = artifact.model_dump_json()
        r.set(self._k(artifact.tenant_id, artifact.kind, artifact.name, artifact.version), payload)
        r.sadd(self._index_key(artifact.tenant_id, artifact.kind), f"{artifact.name}:{artifact.version}")
        return artifact

    def get(self, tenant_id: str, kind: ArtifactKind, name: str, version: str) -> Optional[Artifact]:
        r = self._get_redis()
        raw = r.get(self._k(tenant_id, kind, name, version))
        if not raw:
            return None
        return Artifact(**json.loads(raw))

    def delete(self, tenant_id: str, kind: ArtifactKind, name: str, version: str) -> bool:
        r = self._get_redis()
        removed = r.delete(self._k(tenant_id, kind, name, version))
        if removed:
            r.srem(self._index_key(tenant_id, kind), f"{name}:{version}")
        return bool(removed)

    def list(self, tenant_id: str, kind: Optional[ArtifactKind] = None, name: Optional[str] = None) -> list[Artifact]:
        r = self._get_redis()
        kinds = [kind] if kind else list(ArtifactKind)
        results: list[Artifact] = []
        for k in kinds:
            members = r.smembers(self._index_key(tenant_id, k)) or []
            for m in members:
                m = m.decode() if isinstance(m, bytes) else m
                n, v = m.split(":", 1)
                if name and n != name:
                    continue
                art = self.get(tenant_id, k, n, v)
                if art:
                    results.append(art)
        return results

    def set_pin(self, tenant_id: str, kind: ArtifactKind, name: str, version: Optional[str]) -> None:
        r = self._get_redis()
        if version is None:
            r.delete(self._pin_key(tenant_id, kind, name))
        else:
            r.set(self._pin_key(tenant_id, kind, name), version)

    def get_pin(self, tenant_id: str, kind: ArtifactKind, name: str) -> Optional[str]:
        r = self._get_redis()
        v = r.get(self._pin_key(tenant_id, kind, name))
        if v is None:
            return None
        return v.decode() if isinstance(v, bytes) else v


# ---------------- Selector ----------------

_store_singleton: Optional[ArtifactStore] = None


def get_store() -> ArtifactStore:
    """Return the active artifact store, choosing the backend lazily."""
    global _store_singleton
    if _store_singleton is not None:
        return _store_singleton

    backend = _BACKEND
    if backend == "redis":
        _store_singleton = RedisArtifactStore()
    elif backend == "file":
        _store_singleton = FileArtifactStore()
    else:
        # auto: prefer Redis when reachable, else file
        try:
            from storage.tenant_store import _get_redis
            r = _get_redis()
            if r is not None:
                # cheap probe
                r.ping() if hasattr(r, "ping") else None
                _store_singleton = RedisArtifactStore()
            else:
                _store_singleton = FileArtifactStore()
        except Exception:
            _store_singleton = FileArtifactStore()
    return _store_singleton


def reset_store_for_tests(store: Optional[ArtifactStore] = None) -> None:
    """Test helper to inject a store or clear the cached singleton."""
    global _store_singleton
    _store_singleton = store
