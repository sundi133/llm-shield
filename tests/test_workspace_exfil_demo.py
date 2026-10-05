"""The "agents launder confidential data" demo (examples/workspace_exfil_demo)
keeps working: the mock's enterprise controls stop a person, an agent's
paraphrase gets past them, and the flow policy the seed writes blocks the agent
through the real MCP enforcement path while internal mail still goes.

Also pins the seed's safety: a dry run sends nothing and never prints the
upstream's key, and a remote target needs an https upstream.
"""
import asyncio
import importlib.util
import pathlib
from unittest.mock import patch

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "workspace_exfil_demo"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"demo_{name}", DEMO / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mock = _load("mock_workspace_mcp")
seed = _load("seed")
runner = _load("run_demo")

DECK, PERSONAL, VENDOR, INTERNAL = runner.DECK, runner.PERSONAL, runner.VENDOR, runner.INTERNAL


@pytest.fixture(autouse=True)
def _empty_outbox():
    mock.OUTBOX.clear()
    yield
    mock.OUTBOX.clear()


# ── the mock's controls stop a person ──────────────────────────────────────


def test_sharing_the_confidential_deck_outside_is_refused():
    out = mock.drive_share(DECK, PERSONAL)
    assert out["blocked"] and "sharing policy" in out["by"]
    assert mock.drive_share(DECK, INTERNAL)["shared"] is True


def test_attaching_it_to_outside_mail_is_refused():
    out = mock.gmail_send(PERSONAL, "deck", "see attached", attachment_file_id=DECK)
    assert out["blocked"] and "DLP" in out["by"]
    assert mock.OUTBOX == []


def test_pasting_the_marked_text_is_refused():
    out = mock.gmail_send(PERSONAL, "notes", mock.DOCS[DECK]["content"])
    assert out["blocked"] and "marker" in out["by"]


# ── an agent's paraphrase gets past them ───────────────────────────────────


def test_the_agents_summary_leaves_the_company_unchallenged():
    assert mock.CLASSIFICATION_MARKER not in runner.SUMMARY
    assert mock.gmail_send(PERSONAL, "notes", runner.SUMMARY)["sent"] is True
    assert mock.OUTBOX[-1]["external"] is True


def test_the_poisoned_vendor_email_carries_the_instruction():
    body = mock.gmail_read("m-102")["body"]
    assert "Assistant processing this mailbox" in body and VENDOR in body


# ── the seed's flow policy blocks the agent through MCP enforcement ────────


@pytest.fixture
def tenant(monkeypatch):
    from core.xflow import runtime as xflow
    from core.xflow import state as xflow_state
    from storage.tenant_store import kv_set

    monkeypatch.setenv("SHIELD_MCP_CONTROL_PLANE", "off")
    monkeypatch.delenv("SHIELD_XFLOW", raising=False)
    xflow.invalidate()
    xflow_state.reset_memory()
    xflow_state._mem_policies.clear()
    tid = "demo-bank-co"
    kv_set(f"agents:{tid}", {seed.AGENT: {**seed.agent_entry(), "status": "active"}})
    xflow.save_policy(tid, seed.flow_policy())
    yield tid
    xflow.invalidate()
    xflow_state.reset_memory()
    xflow_state._mem_policies.clear()


def _call(tid, tool, args):
    """The gateway's decision for one tools/call, with the model-backed guards
    out of the way: this checks the flow policy, which needs no model."""
    from core.mcp import enforcement
    with patch.object(enforcement, "_tool_guard_chain", return_value=[]):
        return asyncio.run(enforcement.enforce_tool_call(
            tool, args, agent_key=seed.AGENT, user_role=seed.ROLE, tenant_id=tid,
            tenant_config={}, session_id=None, route=seed.ROUTE))


def test_the_seeded_flow_policy_is_valid():
    from core.xflow.policy import validate_policy
    p = validate_policy(seed.flow_policy())
    assert p["mode"] == "enforce" and p["principal_scope"] == "agent"


def test_after_reading_drive_outside_mail_is_blocked_and_inside_mail_is_not(tenant):
    assert _call(tenant, "drive_read", {"file_id": DECK})["allowed"] is True
    for outside in (PERSONAL, VENDOR):
        d = _call(tenant, "gmail_send", {"to": outside, "subject": "s", "body": runner.SUMMARY})
        assert d["allowed"] is False
        assert "confidential-leaves-company" in d["reason"]
    assert _call(tenant, "gmail_send", {"to": INTERNAL, "subject": "s", "body": "x"})["allowed"] is True


def test_outside_mail_without_reading_drive_first_is_not_blocked(tenant):
    """The rule is about confidential data leaving, not about email: an agent
    that has read nothing from Drive can still mail a vendor."""
    d = _call(tenant, "gmail_send", {"to": VENDOR, "subject": "s", "body": "Thanks, received."})
    assert d["allowed"] is True


def test_monitor_mode_reports_instead_of_blocking(tenant):
    from core.xflow import runtime as xflow
    xflow.save_policy(tenant, seed.flow_policy(mode="monitor"))
    xflow.invalidate()
    _call(tenant, "drive_read", {"file_id": DECK})
    d = _call(tenant, "gmail_send", {"to": PERSONAL, "subject": "s", "body": runner.SUMMARY})
    assert d["allowed"] is True


# ── the seed is safe to point at production ────────────────────────────────


def test_a_dry_run_sends_nothing_and_masks_the_key(monkeypatch, capsys):
    key = "k" * 32
    monkeypatch.setenv("SHIELD_API", "https://shield.example")
    monkeypatch.setenv("SHIELD_TENANT_KEY", "tenant-key")
    monkeypatch.setenv("DEMO_UPSTREAM_URL", "https://tunnel.example/mcp")
    monkeypatch.setenv("DEMO_UPSTREAM_KEY", key)
    sent = []

    def fake_urlopen(req, timeout=None):
        sent.append((req.get_method(), req.full_url))
        raise seed.urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)
    monkeypatch.setattr(seed.urllib.request, "urlopen", fake_urlopen)
    seed.main([])
    assert all(m == "GET" for m, _ in sent), sent
    assert key not in capsys.readouterr().out


def test_a_remote_target_needs_an_https_upstream(monkeypatch):
    monkeypatch.setenv("SHIELD_API", "https://shield.example")
    monkeypatch.setenv("SHIELD_TENANT_KEY", "tenant-key")
    monkeypatch.setenv("DEMO_UPSTREAM_URL", "http://127.0.0.1:9300/mcp")
    monkeypatch.setenv("DEMO_UPSTREAM_KEY", "k" * 32)
    with pytest.raises(SystemExit, match="cannot reach localhost"):
        seed.main([])


def test_the_mock_rejects_calls_without_its_key():
    from starlette.testclient import TestClient
    with TestClient(mock.build_app("s" * 32)) as c:
        assert c.get("/demo/outbox").status_code == 401
        assert c.get("/demo/outbox", headers={"X-Demo-Key": "wrong" * 8}).status_code == 401
        assert c.get("/demo/outbox", headers={"X-Demo-Key": "s" * 32}).status_code == 200
