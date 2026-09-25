"""Integration tests for ASIM formatting in the telemetry export path.

Covers the guarantees that make this change safe to ship:
  * the default (both) keeps every existing field unchanged and only ADDS the
    ASIM fields, so nothing that reads today's telemetry breaks;
  * native is byte-identical to the pre-ASIM records;
  * asim renames fields only in the off-thread export path, and the
    FileExporter's "unsafe" filter selects the identical set in every format.
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

    # Unknown value falls back to the default (both), which removes nothing.
    os.environ["VOTAL_TELEMETRY_FORMAT"] = "nonsense"
    init_telemetry({})
    assert telemetry.get_telemetry_format() == "both"


def test_default_format_is_both():
    init_telemetry({})
    assert telemetry.get_telemetry_format() == "both"


def test_native_escape_hatch():
    os.environ["VOTAL_TELEMETRY_FORMAT"] = "native"
    init_telemetry({})
    assert telemetry.get_telemetry_format() == "native"


def test_shipped_config_selects_both():
    import yaml
    from pathlib import Path
    cfg = yaml.safe_load((Path(__file__).resolve().parent.parent
                          / "config" / "default.yaml").read_text())
    assert cfg["telemetry"]["format"] == "both"


def test_both_keeps_every_existing_field_unchanged():
    # The non-breaking guarantee: every key/value of today's record survives
    # byte-for-byte, in the same order, and ASIM fields are only appended.
    telemetry._telemetry_format = "both"
    for event in (_block(), _pass()):
        original = json.loads(json.dumps(event, default=str))
        out = _render_events([event])[0]
        assert {k: out[k] for k in original} == original
        assert list(out)[:len(original)] == list(original)
        assert out["EventVendor"] == "Votal" and "EventResult" in out


def test_both_mode_file_exporter_writes_old_and_asim_fields(tmp_path):
    telemetry._telemetry_format = "both"
    path = tmp_path / "both.json"
    asyncio.run(FileExporter(path=str(path)).export([_block(), _pass()]))
    lines = path.read_text().splitlines()
    assert len(lines) == 1  # same unsafe selection as native
    rec = json.loads(lines[0])
    assert rec["votal.action"] == "block" and rec["event.outcome"] == "failure"
    assert rec["EventResult"] == "Failure" and rec["DvcAction"] == "Deny"
