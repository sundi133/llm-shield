"""Integration tests for ASIM formatting in the telemetry export path.

Covers the two guarantees that make this change safe to ship:
  * native format is byte-identical to today (the default);
  * asim format renames fields only in the off-thread export path, and the
    FileExporter's "unsafe" filter selects the identical set in both formats.
"""
import asyncio
import json
import os

import pytest

from core import telemetry
from core.telemetry import (
    FileExporter,
    _render_events,
    build_response_event,
    init_telemetry,
)


@pytest.fixture(autouse=True)
def _reset_format():
    """Isolate the module-global format across tests."""
    saved = telemetry._telemetry_format
    saved_env = os.environ.pop("VOTAL_TELEMETRY_FORMAT", None)
    yield
    telemetry._telemetry_format = saved
    if saved_env is not None:
        os.environ["VOTAL_TELEMETRY_FORMAT"] = saved_env
    else:
        os.environ.pop("VOTAL_TELEMETRY_FORMAT", None)


def _block():
    return build_response_event(
        trace_id="tt1", endpoint="/guardrails/input", status_code=403,
        latency_ms=10.0, action="block", safe=False, tenant_id="bank-co",
    )


def _pass():
    return build_response_event(
        trace_id="tt2", endpoint="/guardrails/input", status_code=200,
        latency_ms=5.0, action="pass", safe=True, tenant_id="bank-co",
    )


def test_native_render_is_identity():
    telemetry._telemetry_format = "native"
    events = [_block(), _pass()]
    out = _render_events(events)
    assert out is events, "native format must not touch the batch at all"


def test_asim_render_maps_events_and_passes_spans_through():
    telemetry._telemetry_format = "asim"
    span = {"type": "span", "name": "guard", "trace.id": "s1"}
    events = [_block(), span]
    out = _render_events(events)
    # Non-span event is ASIM-shaped.
    assert out[0]["EventVendor"] == "Votal"
    assert out[0]["EventResult"] == "Failure"
    assert "votal.action" not in out[0]
    # Span is untouched (ASIM is for security events, not traces).
    assert out[1] is span


def test_asim_render_falls_back_to_native_on_bad_event():
    telemetry._telemetry_format = "asim"
    # A non-mappable entry must not be dropped.
    weird = {"type": "not-span", "@timestamp": "x"}
    out = _render_events([weird])
    assert len(out) == 1  # never dropped


def test_file_exporter_unsafe_set_is_identical_across_formats(tmp_path):
    events = [_block(), _pass(),
              {"type": "span", "name": "x"}]  # span is safe, never written

    # Native: writes only the unsafe (block) event, in native shape.
    telemetry._telemetry_format = "native"
    native_path = tmp_path / "native.json"
    asyncio.run(FileExporter(path=str(native_path)).export(list(events)))
    native_lines = native_path.read_text().splitlines()
    assert len(native_lines) == 1
    assert json.loads(native_lines[0])["votal.action"] == "block"

    # ASIM: same one unsafe event, ASIM-shaped.
    telemetry._telemetry_format = "asim"
    asim_path = tmp_path / "asim.json"
    asyncio.run(FileExporter(path=str(asim_path)).export(list(events)))
    asim_lines = asim_path.read_text().splitlines()
    assert len(asim_lines) == len(native_lines) == 1
    rec = json.loads(asim_lines[0])
    assert rec["EventVendor"] == "Votal"
    assert rec["EventResult"] == "Failure"
    assert "votal.action" not in rec


def test_init_telemetry_resolves_format():
    # From config.
    init_telemetry({"format": "asim"})
    assert telemetry.get_telemetry_format() == "asim"

    # Env overrides config.
    os.environ["VOTAL_TELEMETRY_FORMAT"] = "native"
    init_telemetry({"format": "asim"})
    assert telemetry.get_telemetry_format() == "native"

    # Unknown value falls back to the default (asim), never to a random shape.
    os.environ["VOTAL_TELEMETRY_FORMAT"] = "nonsense"
    init_telemetry({})
    assert telemetry.get_telemetry_format() == "asim"


def test_default_format_is_asim():
    init_telemetry({})
    assert telemetry.get_telemetry_format() == "asim"


def test_native_escape_hatch():
    os.environ["VOTAL_TELEMETRY_FORMAT"] = "native"
    init_telemetry({})
    assert telemetry.get_telemetry_format() == "native"


def test_shipped_config_selects_asim():
    import yaml
    from pathlib import Path
    cfg = yaml.safe_load((Path(__file__).resolve().parent.parent
                          / "config" / "default.yaml").read_text())
    assert cfg["telemetry"]["format"] == "asim"
