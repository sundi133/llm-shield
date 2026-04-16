"""OpenTelemetry-based telemetry — traces and logs to any SIEM backend.

Supports: Elasticsearch, Splunk HEC, OTLP (Datadog/Grafana/Jaeger), local JSON file.
Configure via telemetry section in config/default.yaml.
"""

import asyncio
import json
import logging
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("votal.telemetry")

# ---------------------------------------------------------------------------
# Event buffer — batches events for efficient shipping
# ---------------------------------------------------------------------------

_buffer: deque[dict] = deque(maxlen=10000)
_flush_lock = asyncio.Lock() if asyncio.get_event_loop_policy() else None


def record_event(event: dict):
    """Add a telemetry event to the buffer. Non-blocking."""
    event.setdefault("@timestamp", datetime.now(timezone.utc).isoformat())
    event.setdefault("service.name", "votal-shield")
    _buffer.append(event)


# ---------------------------------------------------------------------------
# Request/response event builders
# ---------------------------------------------------------------------------


_HOSTNAME = os.environ.get("HOSTNAME", os.environ.get("POD_NAME", "votal-shield"))


def build_request_event(
    *,
    trace_id: str,
    endpoint: str,
    method: str,
    agent_key: str = "",
    tenant_id: str = "",
    session_id: str = "",
    role_name: str = "",
    source_ip: str = "",
    user_agent: str = "",
    input_text: str = "",
    body: Optional[dict] = None,
    headers: Optional[dict] = None,
) -> dict:
    return {
        "event.kind": "event",
        "event.category": "web",
        "event.type": "access",
        "event.action": "request",
        "trace.id": trace_id,
        "http.request.method": method,
        "url.path": endpoint,
        "source.ip": source_ip,
        "user_agent.original": user_agent,
        "host.name": _HOSTNAME,
        "agent.key": agent_key,
        "votal.tenant_id": tenant_id,
        "votal.session_id": session_id,
        "votal.role_name": role_name,
        "votal.input_text": _truncate_str(input_text, 1000),
        "request.body": _truncate(body),
        "request.headers": _safe_headers(headers),
    }


def build_response_event(
    *,
    trace_id: str,
    endpoint: str,
    status_code: int,
    latency_ms: float,
    action: str = "pass",
    safe: Optional[bool] = None,
    agent_key: str = "",
    tenant_id: str = "",
    session_id: str = "",
    role_name: str = "",
    source_ip: str = "",
    input_text: str = "",
    attack_type: str = "",
    blocked_guardrails: Optional[list[str]] = None,
    guardrail_results: Optional[list] = None,
    body: Optional[dict] = None,
) -> dict:
    # Compute risk score: 0 (safe) to 100 (blocked attack)
    risk_score = 0
    if not safe and action == "block":
        risk_score = 90
        if attack_type:
            risk_score = 95
    elif not safe and action == "warn":
        risk_score = 50
    elif action == "pending_confirmation":
        risk_score = 30

    return {
        "event.kind": "alert" if action == "block" else "event",
        "event.category": "intrusion_detection" if action == "block" else "web",
        "event.type": "denied" if action == "block" else "allowed",
        "event.action": "response",
        "event.outcome": "failure" if action == "block" else "success",
        "event.risk_score": risk_score,
        "event.severity": _risk_to_severity(risk_score),
        "trace.id": trace_id,
        "url.path": endpoint,
        "http.response.status_code": status_code,
        "event.duration": int(latency_ms * 1_000_000),  # nanoseconds (ECS)
        "host.name": _HOSTNAME,
        "source.ip": source_ip,
        "agent.key": agent_key,
        "votal.tenant_id": tenant_id,
        "votal.session_id": session_id,
        "votal.role_name": role_name,
        "votal.action": action,
        "votal.safe": safe,
        "votal.input_text": _truncate_str(input_text, 1000),
        "votal.attack_type": attack_type,
        "votal.blocked_guardrails": blocked_guardrails or [],
        "votal.guardrail_count": len(guardrail_results) if guardrail_results else 0,
        "votal.guardrail_results": guardrail_results,
        "votal.latency_ms": round(latency_ms, 2),
        "response.body": _truncate(body),
    }


def build_guardrail_event(
    *,
    trace_id: str,
    guardrail_name: str,
    passed: bool,
    action: str,
    message: str = "",
    latency_ms: float = 0,
    details: Optional[dict] = None,
    agent_key: str = "",
    tenant_id: str = "",
    source_ip: str = "",
    input_text: str = "",
) -> dict:
    return {
        "event.kind": "alert" if action == "block" and not passed else "event",
        "event.category": "intrusion_detection",
        "event.type": "allowed" if passed else "denied",
        "event.action": f"guardrail.{guardrail_name}",
        "event.outcome": "success" if passed else "failure",
        "trace.id": trace_id,
        "host.name": _HOSTNAME,
        "source.ip": source_ip,
        "agent.key": agent_key,
        "votal.tenant_id": tenant_id,
        "votal.input_text": _truncate_str(input_text, 500),
        "votal.guardrail.name": guardrail_name,
        "votal.guardrail.passed": passed,
        "votal.guardrail.action": action,
        "votal.guardrail.message": message,
        "votal.guardrail.latency_ms": round(latency_ms, 2),
        "votal.guardrail.details": details,
    }


def _risk_to_severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 10:
        return "low"
    return "informational"


# ---------------------------------------------------------------------------
# Exporters — pluggable backends
# ---------------------------------------------------------------------------


class BaseExporter:
    async def export(self, events: list[dict]):
        raise NotImplementedError

    async def shutdown(self):
        pass


class ElasticsearchExporter(BaseExporter):
    """Push events to Elasticsearch via bulk API."""

    def __init__(self, url: str, api_key: str, index: str = "votal-shield-logs",
                 verify_ssl: bool = True):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.index = index
        self.verify_ssl = verify_ssl
        self._client = None

    def _get_client(self):
        if self._client is None:
            import httpx
            self._client = httpx.AsyncClient(
                timeout=10,
                verify=self.verify_ssl,
                headers={
                    "Authorization": f"ApiKey {self.api_key}",
                    "Content-Type": "application/x-ndjson",
                },
            )
        return self._client

    async def export(self, events: list[dict]):
        client = self._get_client()
        # Build NDJSON bulk payload
        lines = []
        for event in events:
            lines.append(json.dumps({"index": {"_index": self.index}}))
            lines.append(json.dumps(event, default=str))
        body = "\n".join(lines) + "\n"

        try:
            resp = await client.post(f"{self.url}/_bulk", content=body)
            if resp.status_code >= 400:
                logger.error(f"ES bulk failed ({resp.status_code}): {resp.text[:200]}")
            else:
                result = resp.json()
                if result.get("errors"):
                    failed = sum(1 for item in result.get("items", [])
                                 if item.get("index", {}).get("error"))
                    logger.warning(f"ES bulk: {failed}/{len(events)} items had errors")
        except Exception as e:
            logger.error(f"ES export failed: {e}")

    async def shutdown(self):
        if self._client:
            await self._client.aclose()


class SplunkHECExporter(BaseExporter):
    """Push events to Splunk via HTTP Event Collector."""

    def __init__(self, url: str, token: str, index: str = "main",
                 source: str = "votal-shield", verify_ssl: bool = True):
        self.url = url.rstrip("/")
        self.token = token
        self.index = index
        self.source = source
        self.verify_ssl = verify_ssl
        self._client = None

    def _get_client(self):
        if self._client is None:
            import httpx
            self._client = httpx.AsyncClient(
                timeout=10,
                verify=self.verify_ssl,
                headers={
                    "Authorization": f"Splunk {self.token}",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def export(self, events: list[dict]):
        client = self._get_client()
        payload = ""
        for event in events:
            payload += json.dumps({
                "event": event,
                "index": self.index,
                "source": self.source,
                "sourcetype": "_json",
            }, default=str) + "\n"

        try:
            resp = await client.post(f"{self.url}/services/collector/event", content=payload)
            if resp.status_code >= 400:
                logger.error(f"Splunk HEC failed ({resp.status_code}): {resp.text[:200]}")
        except Exception as e:
            logger.error(f"Splunk export failed: {e}")

    async def shutdown(self):
        if self._client:
            await self._client.aclose()


class OTLPExporter(BaseExporter):
    """Push events via OTLP/HTTP to any OTEL-compatible collector."""

    def __init__(self, endpoint: str, headers: Optional[dict] = None,
                 verify_ssl: bool = True):
        self.endpoint = endpoint.rstrip("/")
        self.extra_headers = headers or {}
        self.verify_ssl = verify_ssl
        self._client = None

    def _get_client(self):
        if self._client is None:
            import httpx
            self._client = httpx.AsyncClient(
                timeout=10,
                verify=self.verify_ssl,
                headers={"Content-Type": "application/json", **self.extra_headers},
            )
        return self._client

    async def export(self, events: list[dict]):
        client = self._get_client()
        # Wrap events in OTLP log format
        log_records = []
        for event in events:
            log_records.append({
                "timeUnixNano": str(int(time.time() * 1e9)),
                "severityText": "INFO",
                "body": {"stringValue": json.dumps(event, default=str)},
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "votal-shield"}},
                ],
            })

        payload = {
            "resourceLogs": [{
                "resource": {"attributes": [
                    {"key": "service.name", "value": {"stringValue": "votal-shield"}},
                ]},
                "scopeLogs": [{
                    "logRecords": log_records,
                }],
            }],
        }

        try:
            resp = await client.post(
                f"{self.endpoint}/v1/logs",
                content=json.dumps(payload),
            )
            if resp.status_code >= 400:
                logger.error(f"OTLP export failed ({resp.status_code}): {resp.text[:200]}")
        except Exception as e:
            logger.error(f"OTLP export failed: {e}")

    async def shutdown(self):
        if self._client:
            await self._client.aclose()


class FileExporter(BaseExporter):
    """Write events to a local JSON file with rotation."""

    def __init__(self, path: str = "logs/votal-shield.json",
                 max_size_mb: int = 100, max_files: int = 10):
        self.path = Path(path)
        self.max_size = max_size_mb * 1024 * 1024
        self.max_files = max_files
        self.path.parent.mkdir(parents=True, exist_ok=True)

    async def export(self, events: list[dict]):
        self._rotate_if_needed()
        try:
            with open(self.path, "a") as f:
                for event in events:
                    f.write(json.dumps(event, default=str) + "\n")
        except Exception as e:
            logger.error(f"File export failed: {e}")

    def _rotate_if_needed(self):
        if not self.path.exists():
            return
        if self.path.stat().st_size < self.max_size:
            return
        # Rotate: shield.json → shield.json.1, .1 → .2, etc.
        for i in range(self.max_files - 1, 0, -1):
            src = self.path.with_suffix(f".json.{i}")
            dst = self.path.with_suffix(f".json.{i + 1}")
            if src.exists():
                if dst.exists():
                    dst.unlink()
                src.rename(dst)
        # Current → .1
        backup = self.path.with_suffix(".json.1")
        if self.path.exists():
            self.path.rename(backup)
        # Delete oldest if over max_files
        oldest = self.path.with_suffix(f".json.{self.max_files}")
        if oldest.exists():
            oldest.unlink()


# ---------------------------------------------------------------------------
# Telemetry manager — init from config, run flush loop
# ---------------------------------------------------------------------------

_exporters: list[BaseExporter] = []
_flush_interval: float = 5.0
_enabled: bool = False


def init_telemetry(config: Optional[dict] = None):
    """Initialize telemetry from config. Call once at startup."""
    global _exporters, _flush_interval, _enabled

    if config is None:
        # Try loading from yaml config
        try:
            import config.schema as _cfg
            config = (_cfg.config.telemetry if _cfg.config and hasattr(_cfg.config, "telemetry")
                      else None)
        except Exception:
            pass

    if not config:
        config = {}

    _enabled = config.get("enabled", False)
    if not _enabled:
        logger.info("Telemetry disabled")
        return

    _flush_interval = config.get("flush_interval_seconds", 5.0)

    # File exporter — only if explicitly enabled in config
    file_cfg = config.get("file", {})
    if file_cfg.get("enabled", False):
        _exporters.append(FileExporter(
            path=file_cfg.get("path", "logs/votal-shield.json"),
            max_size_mb=file_cfg.get("max_size_mb", 100),
            max_files=file_cfg.get("max_files", 10),
        ))
        logger.info(f"File exporter: {file_cfg.get('path', 'logs/votal-shield.json')}")

    # Elasticsearch — env vars override yaml
    es_cfg = config.get("elasticsearch", {})
    es_url = os.environ.get("VOTAL_ES_URL", es_cfg.get("url", ""))
    es_key = os.environ.get("VOTAL_ES_API_KEY", es_cfg.get("api_key", ""))
    es_enabled = os.environ.get("VOTAL_ES_ENABLED", str(es_cfg.get("enabled", False))).lower() in ("true", "1", "yes")
    if es_enabled and es_url and es_key:
        _exporters.append(ElasticsearchExporter(
            url=es_url,
            api_key=es_key,
            index=os.environ.get("VOTAL_ES_INDEX", es_cfg.get("index", "votal-shield-logs")),
            verify_ssl=es_cfg.get("verify_ssl", True),
        ))
        logger.info(f"ES exporter: {es_url}")

    # Splunk HEC — env vars override yaml
    splunk_cfg = config.get("splunk", {})
    splunk_url = os.environ.get("VOTAL_SPLUNK_URL", splunk_cfg.get("url", ""))
    splunk_token = os.environ.get("VOTAL_SPLUNK_TOKEN", splunk_cfg.get("token", ""))
    splunk_enabled = os.environ.get("VOTAL_SPLUNK_ENABLED", str(splunk_cfg.get("enabled", False))).lower() in ("true", "1", "yes")
    if splunk_enabled and splunk_url and splunk_token:
        _exporters.append(SplunkHECExporter(
            url=splunk_url,
            token=splunk_token,
            index=os.environ.get("VOTAL_SPLUNK_INDEX", splunk_cfg.get("index", "main")),
            source=splunk_cfg.get("source", "votal-shield"),
            verify_ssl=splunk_cfg.get("verify_ssl", True),
        ))
        logger.info(f"Splunk exporter: {splunk_url}")

    # OTLP — env vars override yaml
    otlp_cfg = config.get("otlp", {})
    otlp_endpoint = os.environ.get("VOTAL_OTLP_ENDPOINT", otlp_cfg.get("endpoint", ""))
    otlp_enabled = os.environ.get("VOTAL_OTLP_ENABLED", str(otlp_cfg.get("enabled", False))).lower() in ("true", "1", "yes")
    if otlp_enabled and otlp_endpoint:
        _exporters.append(OTLPExporter(
            endpoint=otlp_endpoint,
            headers=otlp_cfg.get("headers", {}),
            verify_ssl=otlp_cfg.get("verify_ssl", True),
        ))
        logger.info(f"OTLP exporter: {otlp_endpoint}")

    logger.info(f"Telemetry enabled: {len(_exporters)} exporter(s), flush every {_flush_interval}s")


async def flush():
    """Flush buffered events to all exporters."""
    if not _enabled or not _exporters or not _buffer:
        return

    # Drain buffer
    events = []
    while _buffer:
        events.append(_buffer.popleft())

    if not events:
        return

    # Send to all exporters in parallel
    tasks = [exporter.export(events) for exporter in _exporters]
    await asyncio.gather(*tasks, return_exceptions=True)


async def flush_loop():
    """Background task that flushes events periodically."""
    while True:
        await asyncio.sleep(_flush_interval)
        try:
            await flush()
        except Exception as e:
            logger.error(f"Telemetry flush error: {e}")


async def shutdown_telemetry():
    """Flush remaining events and close exporters."""
    await flush()
    for exporter in _exporters:
        try:
            await exporter.shutdown()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate_str(s: str, max_len: int = 1000) -> str:
    if not s:
        return ""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "...[truncated]"


def _truncate(obj: Any, max_len: int = 2000) -> Any:
    if obj is None:
        return None
    s = json.dumps(obj, default=str) if not isinstance(obj, str) else obj
    if len(s) > max_len:
        return s[:max_len] + "...[truncated]"
    return obj


def _safe_headers(headers: Optional[dict]) -> Optional[dict]:
    if not headers:
        return None
    # Redact sensitive headers
    safe = {}
    sensitive = {"authorization", "x-api-key", "cookie", "set-cookie"}
    for k, v in headers.items():
        if k.lower() in sensitive:
            safe[k] = "[REDACTED]"
        else:
            safe[k] = v
    return safe
