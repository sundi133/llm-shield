"""Environment scoping: a staging agent must not act against production.

Copying an env file between deployments is a mistake people make constantly.
Before this, a staging agent pointed at the production Shield got every grant
its role allowed, because Shield had no concept of an environment at all.

Two properties carry the design, and both are tested rather than described:

  * The environment comes from the PROCESS, never the request. If a caller
    could send it, it would be X-User-Role again — a control that reads as
    enforcement and is a suggestion.
  * It costs nothing on the guard path. `test_no_added_store_reads` asserts
    that with a spy, because a per-request store read added here would be
    exactly the regression this repo's invariants exist to prevent.

Spec: docs/spec-agent-ownership-environment.md PR 2
"""
import pytest

from guardrails.agentic import rbac_guard
from guardrails.agentic.rbac_guard import (_environment_mismatch,
                                           deployment_environment)

AGENT = "payments-bot"
TENANT = "acme"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("SHIELD_ENVIRONMENT", raising=False)


@pytest.fixture
def entry(monkeypatch):
    """Control what the registry returns, and count how often it is asked."""
    state = {"entry": {"agent_id": AGENT}, "reads": 0}

    def _load(agent_key, tenant_id):
        state["reads"] += 1
        return state["entry"]

    monkeypatch.setattr(rbac_guard, "_load_agent_entry", _load)
    return state


# ── the matrix from the spec ─────────────────────────────────────────────


def test_unset_deployment_enforces_nothing(entry, monkeypatch):
    """Today's behaviour. Every existing deployment must land here."""
    entry["entry"]["environments"] = ["staging"]
    assert _environment_mismatch(AGENT, TENANT) is None


def test_agent_declaring_nothing_runs_anywhere(entry, monkeypatch):
    """The backward-compatibility guard: entries written before this field."""
    monkeypatch.setenv("SHIELD_ENVIRONMENT", "prod")
    assert "environments" not in entry["entry"]
    assert _environment_mismatch(AGENT, TENANT) is None


def test_empty_list_runs_anywhere(entry, monkeypatch):
    monkeypatch.setenv("SHIELD_ENVIRONMENT", "prod")
    entry["entry"]["environments"] = []
    assert _environment_mismatch(AGENT, TENANT) is None


def test_matching_environment_is_allowed(entry, monkeypatch):
    monkeypatch.setenv("SHIELD_ENVIRONMENT", "prod")
    entry["entry"]["environments"] = ["prod", "staging"]
    assert _environment_mismatch(AGENT, TENANT) is None


def test_mismatch_is_refused(entry, monkeypatch):
    """The whole point: staging agent, production Shield."""
    monkeypatch.setenv("SHIELD_ENVIRONMENT", "prod")
    entry["entry"]["environments"] = ["staging"]
    assert _environment_mismatch(AGENT, TENANT) == ("prod", ["staging"])


# ── the environment cannot come from the caller ──────────────────────────


def test_environment_is_read_from_the_process(monkeypatch):
    """There is no request parameter, and this is the reason there is not.

    Asserted by signature: deployment_environment() takes no arguments, so
    there is nowhere for a caller-supplied value to enter.
    """
    import inspect
    assert list(inspect.signature(deployment_environment).parameters) == []


def test_whitespace_environment_is_unset(entry, monkeypatch):
    monkeypatch.setenv("SHIELD_ENVIRONMENT", "   ")
    entry["entry"]["environments"] = ["staging"]
    assert deployment_environment() == ""
    assert _environment_mismatch(AGENT, TENANT) is None


# ── exact matching, deliberately ─────────────────────────────────────────


def test_case_mismatch_is_refused(entry, monkeypatch):
    """`Prod` is not `prod`. Case-insensitive matching lets three spellings
    coexist meaning the same thing until one day they do not."""
    monkeypatch.setenv("SHIELD_ENVIRONMENT", "prod")
    entry["entry"]["environments"] = ["Prod"]
    assert _environment_mismatch(AGENT, TENANT) == ("prod", ["Prod"])


def test_refusal_names_both_values(entry, monkeypatch):
    """A refusal you cannot diagnose is a support ticket."""
    monkeypatch.setenv("SHIELD_ENVIRONMENT", "prod")
    entry["entry"]["environments"] = ["staging"]
    env, declared = _environment_mismatch(AGENT, TENANT)
    assert env == "prod" and declared == ["staging"]


# ── degradation ──────────────────────────────────────────────────────────


def test_unknown_agent_is_not_our_problem(entry, monkeypatch):
    """No registry entry means no environment claim. The existing
    unregistered-agent handling decides, not this check."""
    monkeypatch.setenv("SHIELD_ENVIRONMENT", "prod")
    entry["entry"] = None
    assert _environment_mismatch(AGENT, TENANT) is None


def test_non_list_environments_is_ignored_not_fatal(entry, monkeypatch):
    """Validation refuses this at write time. If one is already in Redis from
    a hand-edit, the guard path must not raise on it."""
    monkeypatch.setenv("SHIELD_ENVIRONMENT", "prod")
    entry["entry"]["environments"] = "prod"
    assert _environment_mismatch(AGENT, TENANT) is None


# ── the latency contract ─────────────────────────────────────────────────


def test_no_added_store_reads(entry, monkeypatch):
    """Unset deployment must not touch the registry at all.

    The env check short-circuits before _load_agent_entry, so a deployment
    that never sets SHIELD_ENVIRONMENT pays literally nothing. This is the
    guard-path claim, and it is easier to keep true than to restore.
    """
    entry["entry"]["environments"] = ["staging"]
    entry["reads"] = 0
    for _ in range(50):
        _environment_mismatch(AGENT, TENANT)
    assert entry["reads"] == 0


def test_one_read_when_enforcing(entry, monkeypatch):
    """With enforcement on it reads the entry the guard already loads. One per
    call, no more — asserting the count so a cache or a second lookup added
    later shows up as a deliberate change."""
    monkeypatch.setenv("SHIELD_ENVIRONMENT", "prod")
    entry["entry"]["environments"] = ["prod"]
    entry["reads"] = 0
    _environment_mismatch(AGENT, TENANT)
    assert entry["reads"] == 1
