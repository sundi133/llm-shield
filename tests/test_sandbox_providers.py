"""Sandbox provider adapters (examples/sandbox/broker.py) — task 5:
K8s Agent Sandbox, E2B, Daytona (docs/spec-sandbox-guardrails.md).

All three lazy-import their vendor SDK, so these tests never touch the
network or a real cluster: the K8s adapter takes its API clients by
dependency injection (fakes below record calls); E2B/Daytona SDKs are faked
in ``sys.modules``, same pattern as ``ModalProvider``'s tests.
"""

from __future__ import annotations

import sys
import types

import pytest

from examples.sandbox.broker import (
    DaytonaProvider,
    E2BProvider,
    K8sAgentSandboxProvider,
    SandboxSpec,
    _dns1123,
    _egress_network_policy,
)


def _spec(**overrides) -> SandboxSpec:
    base = dict(
        agent_id="billing-bot",
        user_sub="alice@acme.com",
        build_hash="sha256:abc",
        model_version="claude-opus-4-8",
        session_id="conv-1",
    )
    base.update(overrides)
    return SandboxSpec(**base)


def _env(**overrides) -> dict:
    base = {
        "SHIELD_AGENT_TOKEN": "tok.abc",
        "SHIELD_BASE_URL": "http://shield-test",
        "SHIELD_AGENT_INSTANCE_ID": "billing-bot-abc123",
        "SHIELD_AGENT_ID": "billing-bot",
        "SHIELD_SESSION_ID": "conv-1",
    }
    base.update(overrides)
    return base


# ── _dns1123 / _egress_network_policy: pure helpers ─────────────────────


class TestDns1123:
    def test_lowercases_and_replaces_invalid_chars(self):
        assert _dns1123("Billing_Bot.1") == "billing-bot-1"

    def test_strips_leading_trailing_hyphens(self):
        assert _dns1123("--abc--") == "abc"

    def test_empty_falls_back_to_sbx(self):
        assert _dns1123("___") == "sbx"

    def test_truncates_to_max_len(self):
        assert len(_dns1123("a" * 100, max_len=10)) <= 10


class TestEgressNetworkPolicy:
    def test_default_is_dns_only_deny_all_else(self):
        policy = _egress_network_policy("sbx-1", "ns", {"k": "v"})
        assert policy["spec"]["podSelector"]["matchLabels"] == {"k": "v"}
        assert policy["spec"]["policyTypes"] == ["Egress"]
        egress = policy["spec"]["egress"]
        assert len(egress) == 1
        assert egress[0]["ports"] == [
            {"protocol": "UDP", "port": 53},
            {"protocol": "TCP", "port": 53},
        ]

    def test_allow_dns_false_yields_zero_rules_full_lockdown(self):
        policy = _egress_network_policy("sbx-1", "ns", {"k": "v"}, allow_dns=False)
        assert policy["spec"]["egress"] == []

    def test_egress_cidrs_become_ipblock_rule(self):
        policy = _egress_network_policy(
            "sbx-1", "ns", {"k": "v"}, egress_cidrs=["10.1.2.3/32"], allow_dns=False
        )
        assert policy["spec"]["egress"] == [
            {"to": [{"ipBlock": {"cidr": "10.1.2.3/32"}}]}
        ]

    def test_gateway_pod_selector_becomes_podselector_rule(self):
        policy = _egress_network_policy(
            "sbx-1",
            "ns",
            {"k": "v"},
            gateway_pod_selector={"app": "egress-gateway"},
            allow_dns=False,
        )
        assert policy["spec"]["egress"] == [
            {"to": [{"podSelector": {"matchLabels": {"app": "egress-gateway"}}}]}
        ]


# ── K8sAgentSandboxProvider: fake API clients via DI ────────────────────


class _FakeCoreV1:
    def __init__(self):
        self.secrets_created: list = []
        self.secrets_deleted: list = []

    def create_namespaced_secret(self, namespace, body):
        self.secrets_created.append((namespace, body))

    def delete_namespaced_secret(self, name, namespace):
        self.secrets_deleted.append((namespace, name))


class _FakeNetworkingV1:
    def __init__(self):
        self.policies_created: list = []
        self.policies_deleted: list = []

    def create_namespaced_network_policy(self, namespace, body):
        self.policies_created.append((namespace, body))

    def delete_namespaced_network_policy(self, name, namespace):
        self.policies_deleted.append((namespace, name))


class _FakeCustomObjects:
    def __init__(self):
        self.created: list = []
        self.deleted: list = []

    def create_namespaced_custom_object(self, group, version, namespace, plural, body):
        self.created.append((group, version, namespace, plural, body))

    def delete_namespaced_custom_object(self, group, version, namespace, plural, name):
        self.deleted.append((group, version, namespace, plural, name))


@pytest.fixture
def k8s_clients():
    return _FakeCoreV1(), _FakeNetworkingV1(), _FakeCustomObjects()


@pytest.fixture
def k8s_provider(k8s_clients):
    core_v1, networking_v1, custom_objects = k8s_clients
    return K8sAgentSandboxProvider(
        "agents-ns",
        "billing-warmpool",
        core_v1=core_v1,
        networking_v1=networking_v1,
        custom_objects=custom_objects,
    )


class TestK8sAgentSandboxProvider:
    def test_launch_creates_secret_with_full_env(self, k8s_provider, k8s_clients):
        core_v1, _n, _c = k8s_clients
        provider_id = k8s_provider.launch(_spec(), _env())
        assert provider_id == "agents-ns/sbx-billing-bot-abc123"
        namespace, body = core_v1.secrets_created[0]
        assert namespace == "agents-ns"
        assert body["stringData"] == _env()
        assert body["metadata"]["name"] == "sbx-billing-bot-abc123"

    def test_launch_scopes_networkpolicy_to_claim_labels(self, k8s_provider, k8s_clients):
        _c, networking_v1, _o = k8s_clients
        k8s_provider.launch(_spec(), _env())
        namespace, policy = networking_v1.policies_created[0]
        assert namespace == "agents-ns"
        claim_label = {"agents.x-k8s.io/claim": "sbx-billing-bot-abc123"}
        assert policy["spec"]["podSelector"]["matchLabels"] == claim_label

    def test_launch_creates_claim_referencing_warmpool_and_secret_env(
        self, k8s_provider, k8s_clients
    ):
        _c, _n, custom_objects = k8s_clients
        k8s_provider.launch(_spec(), _env())
        group, version, namespace, plural, body = custom_objects.created[0]
        assert (group, version, plural) == ("agents.x-k8s.io", "v1beta1", "sandboxclaims")
        assert namespace == "agents-ns"
        assert body["spec"]["warmPoolRef"] == {"name": "billing-warmpool"}
        env_entry = body["spec"]["env"][0]
        assert env_entry["valueFrom"]["secretKeyRef"]["name"] == "sbx-billing-bot-abc123"
        # never a literal value on the claim spec (warm-pool constraint, spec §7)
        assert "value" not in env_entry

    def test_egress_cidrs_forwarded_to_networkpolicy(self, k8s_clients):
        core_v1, networking_v1, custom_objects = k8s_clients
        provider = K8sAgentSandboxProvider(
            "agents-ns",
            "billing-warmpool",
            egress_cidrs=["10.1.2.3/32"],
            core_v1=core_v1,
            networking_v1=networking_v1,
            custom_objects=custom_objects,
        )
        provider.launch(_spec(), _env())
        _ns, policy = networking_v1.policies_created[0]
        rules = policy["spec"]["egress"]
        assert {"to": [{"ipBlock": {"cidr": "10.1.2.3/32"}}]} in rules

    def test_terminate_deletes_claim_networkpolicy_and_secret(
        self, k8s_provider, k8s_clients
    ):
        core_v1, networking_v1, custom_objects = k8s_clients
        provider_id = k8s_provider.launch(_spec(), _env())
        k8s_provider.terminate(provider_id)
        assert custom_objects.deleted[0][-1] == "sbx-billing-bot-abc123"
        assert networking_v1.policies_deleted[0] == ("agents-ns", "sbx-billing-bot-abc123")
        assert core_v1.secrets_deleted[0] == ("agents-ns", "sbx-billing-bot-abc123")


# ── E2BProvider: fake e2b SDK in sys.modules ────────────────────────────


def _fake_e2b(monkeypatch, created: list, killed: list, run_calls: list):
    fake = types.ModuleType("e2b")

    class _Commands:
        def run(self, cmd, background=False):
            run_calls.append((cmd, background))

    class _Sandbox:
        def __init__(self, sandbox_id):
            self.sandbox_id = sandbox_id
            self.commands = _Commands()

        @classmethod
        def create(cls, *, template=None, envs=None, timeout=None):
            created.append({"template": template, "envs": envs, "timeout": timeout})
            return cls("e2b-sbx-1")

        @staticmethod
        def kill(sandbox_id):
            killed.append(sandbox_id)

    fake.Sandbox = _Sandbox
    monkeypatch.setitem(sys.modules, "e2b", fake)


class TestE2BProvider:
    def test_launch_passes_template_and_full_env(self, monkeypatch):
        created, killed, run_calls = [], [], []
        _fake_e2b(monkeypatch, created, killed, run_calls)
        sandbox_id = E2BProvider(default_template="py-agent").launch(_spec(), _env())
        assert sandbox_id == "e2b-sbx-1"
        assert created[0]["template"] == "py-agent"
        assert created[0]["envs"] == _env()

    def test_spec_image_overrides_default_template(self, monkeypatch):
        created, killed, run_calls = [], [], []
        _fake_e2b(monkeypatch, created, killed, run_calls)
        E2BProvider(default_template="py-agent").launch(
            _spec(image="custom-template"), _env()
        )
        assert created[0]["template"] == "custom-template"

    def test_entrypoint_runs_in_background(self, monkeypatch):
        created, killed, run_calls = [], [], []
        _fake_e2b(monkeypatch, created, killed, run_calls)
        E2BProvider().launch(_spec(entrypoint=("python", "run.py")), _env())
        assert run_calls == [("python run.py", True)]

    def test_no_entrypoint_no_run_call(self, monkeypatch):
        created, killed, run_calls = [], [], []
        _fake_e2b(monkeypatch, created, killed, run_calls)
        E2BProvider().launch(_spec(), _env())
        assert run_calls == []

    def test_terminate_kills_by_id(self, monkeypatch):
        created, killed, run_calls = [], [], []
        _fake_e2b(monkeypatch, created, killed, run_calls)
        E2BProvider().terminate("e2b-sbx-1")
        assert killed == ["e2b-sbx-1"]


# ── DaytonaProvider: fake daytona SDK in sys.modules ────────────────────


def _fake_daytona(monkeypatch, created: list, exec_calls: list, deleted: list):
    fake = types.ModuleType("daytona")

    class DaytonaConfig:
        def __init__(self, api_key=None, api_url=None):
            self.api_key = api_key
            self.api_url = api_url

    class CreateSandboxFromSnapshotParams:
        def __init__(self, snapshot=None, env_vars=None):
            self.snapshot = snapshot
            self.env_vars = env_vars

    class _Process:
        def exec(self, command, env=None, timeout=None):
            exec_calls.append((command, env))

    class _Sandbox:
        def __init__(self, sandbox_id):
            self.id = sandbox_id
            self.process = _Process()

        def delete(self):
            deleted.append(self.id)

    class Daytona:
        def __init__(self, config):
            self.config = config
            self._sandboxes: dict = {}

        def create(self, params):
            created.append({"snapshot": params.snapshot, "env_vars": params.env_vars})
            sandbox = _Sandbox("daytona-sbx-1")
            self._sandboxes[sandbox.id] = sandbox
            return sandbox

        def get(self, sandbox_id):
            return self._sandboxes[sandbox_id]

    fake.Daytona = Daytona
    fake.DaytonaConfig = DaytonaConfig
    fake.CreateSandboxFromSnapshotParams = CreateSandboxFromSnapshotParams
    monkeypatch.setitem(sys.modules, "daytona", fake)


class TestDaytonaProvider:
    def test_launch_creates_from_snapshot_with_env_vars(self, monkeypatch):
        created, exec_calls, deleted = [], [], []
        _fake_daytona(monkeypatch, created, exec_calls, deleted)
        sandbox_id = DaytonaProvider(default_snapshot="py-agent").launch(_spec(), _env())
        assert sandbox_id == "daytona-sbx-1"
        assert created[0] == {"snapshot": "py-agent", "env_vars": _env()}

    def test_spec_image_overrides_default_snapshot(self, monkeypatch):
        created, exec_calls, deleted = [], [], []
        _fake_daytona(monkeypatch, created, exec_calls, deleted)
        DaytonaProvider(default_snapshot="py-agent").launch(
            _spec(image="custom-snapshot"), _env()
        )
        assert created[0]["snapshot"] == "custom-snapshot"

    def test_entrypoint_runs_via_process_exec(self, monkeypatch):
        created, exec_calls, deleted = [], [], []
        _fake_daytona(monkeypatch, created, exec_calls, deleted)
        DaytonaProvider().launch(_spec(entrypoint=("python", "run.py")), _env())
        assert exec_calls == [("python run.py", _env())]

    def test_no_entrypoint_no_exec_call(self, monkeypatch):
        created, exec_calls, deleted = [], [], []
        _fake_daytona(monkeypatch, created, exec_calls, deleted)
        DaytonaProvider().launch(_spec(), _env())
        assert exec_calls == []

    def test_terminate_gets_and_deletes(self, monkeypatch):
        created, exec_calls, deleted = [], [], []
        _fake_daytona(monkeypatch, created, exec_calls, deleted)
        provider = DaytonaProvider()
        sandbox_id = provider.launch(_spec(), _env())
        provider.terminate(sandbox_id)
        assert deleted == ["daytona-sbx-1"]

    def test_client_constructed_once_and_reused(self, monkeypatch):
        created, exec_calls, deleted = [], [], []
        _fake_daytona(monkeypatch, created, exec_calls, deleted)
        provider = DaytonaProvider(api_key="k", api_url="https://api.daytona.io")
        first = provider._daytona()
        second = provider._daytona()
        assert first is second
