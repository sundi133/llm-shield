"""Tests for the runtime hardening helpers (H3, M1, M3, M5)."""

from __future__ import annotations

import pytest

from core import agent_auth_safety as safety


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "SHIELD_VERBOSE_REASONS",
        "SHIELD_RATELIMIT_TOKEN_PER_MIN",
        "SHIELD_RATELIMIT_TOKEN_PER_DAY",
        "SHIELD_RATELIMIT_CAP_PER_MIN",
        "SHIELD_RATELIMIT_CAP_PER_DAY",
        "SHIELD_ALLOW_INMEMORY_MULTIWORKER",
        "WEB_CONCURRENCY",
        "UVICORN_WORKERS",
        "GUNICORN_WORKERS",
    ):
        monkeypatch.delenv(var, raising=False)
    # Reset rate-limiter in-memory buckets between tests
    from storage import rate_limiter
    rate_limiter._memory_minute.clear()
    rate_limiter._memory_day.clear()


# ── M3 ───────────────────────────────────────────────────────────────


class TestVerboseReasonsGate:
    def test_default_is_quiet(self):
        assert safety.verbose_reasons_enabled() is False

    def test_truthy_env_enables(self, monkeypatch):
        monkeypatch.setenv("SHIELD_VERBOSE_REASONS", "1")
        assert safety.verbose_reasons_enabled() is True
        monkeypatch.setenv("SHIELD_VERBOSE_REASONS", "true")
        assert safety.verbose_reasons_enabled() is True
        monkeypatch.setenv("SHIELD_VERBOSE_REASONS", "yes")
        assert safety.verbose_reasons_enabled() is True

    def test_anything_else_stays_quiet(self, monkeypatch):
        monkeypatch.setenv("SHIELD_VERBOSE_REASONS", "0")
        assert safety.verbose_reasons_enabled() is False
        monkeypatch.setenv("SHIELD_VERBOSE_REASONS", "")
        assert safety.verbose_reasons_enabled() is False


class TestPublicDenialPayload:
    def test_quiet_mode_hides_reasons(self):
        payload = safety.public_denial_payload(
            ["role 'reader' not permitted to use tool 'send_email'"]
        )
        assert payload["error"] == "authz_denied"
        assert "reasons" not in payload
        assert payload["request_id"]  # has a correlator
        assert len(payload["request_id"]) >= 8

    def test_verbose_mode_includes_reasons(self, monkeypatch):
        monkeypatch.setenv("SHIELD_VERBOSE_REASONS", "1")
        payload = safety.public_denial_payload(["reason A", "reason B"])
        assert payload["reasons"] == ["reason A", "reason B"]
        assert payload["error"] == "authz_denied"
        assert payload["request_id"]


# ── H3 ───────────────────────────────────────────────────────────────


class TestTokenIssuanceRateLimit:
    def test_under_limit_allowed(self, monkeypatch):
        monkeypatch.setenv("SHIELD_RATELIMIT_TOKEN_PER_MIN", "5")
        # Reset the module's cached defaults that were captured at import time
        monkeypatch.setattr(safety, "_DEFAULT_ISSUE_PER_MIN", 5)
        for _ in range(5):
            ok, err = safety.rate_limit_token_issuance("t1")
            assert ok, err

    def test_over_limit_rejects(self, monkeypatch):
        monkeypatch.setattr(safety, "_DEFAULT_ISSUE_PER_MIN", 3)
        for _ in range(3):
            ok, _ = safety.rate_limit_token_issuance("t1")
            assert ok
        ok, err = safety.rate_limit_token_issuance("t1")
        assert ok is False
        assert err and "minute" in err.lower() or "rate" in err.lower()

    def test_isolated_per_tenant(self, monkeypatch):
        monkeypatch.setattr(safety, "_DEFAULT_ISSUE_PER_MIN", 2)
        ok, _ = safety.rate_limit_token_issuance("t1")
        assert ok
        ok, _ = safety.rate_limit_token_issuance("t1")
        assert ok
        ok, _ = safety.rate_limit_token_issuance("t1")
        assert ok is False
        # t2 has its own bucket
        ok, _ = safety.rate_limit_token_issuance("t2")
        assert ok


# ── M5 ───────────────────────────────────────────────────────────────


class TestCapMintRateLimit:
    def test_keyed_by_instance_and_tenant(self, monkeypatch):
        monkeypatch.setattr(safety, "_DEFAULT_MINT_PER_MIN", 2)
        # inst-1 exhausts its quota
        for _ in range(2):
            ok, _ = safety.rate_limit_cap_mint("inst-1", "t1")
            assert ok
        ok, _ = safety.rate_limit_cap_mint("inst-1", "t1")
        assert ok is False
        # A DIFFERENT instance in the same tenant has its own bucket
        # (a noisy pod can't burn the whole tenant)
        ok, _ = safety.rate_limit_cap_mint("inst-2", "t1")
        assert ok


# ── M1 ───────────────────────────────────────────────────────────────


class TestMultiWorkerStartupCheck:
    def test_redis_ok_passes(self, monkeypatch):
        class _FakeRedis:
            def ping(self): return True
        from storage import tenant_store
        monkeypatch.setattr(tenant_store, "_get_redis", lambda: _FakeRedis())
        monkeypatch.setenv("WEB_CONCURRENCY", "8")
        # Should not raise
        safety.verify_storage_is_multiworker_safe()

    def test_redis_down_single_worker_warns_only(self, monkeypatch, caplog):
        from storage import tenant_store
        monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
        # No worker var → defaults to 1
        with caplog.at_level("WARNING"):
            safety.verify_storage_is_multiworker_safe()
        assert any("single-worker fallback" in r.message for r in caplog.records)

    def test_redis_down_multiworker_hard_fails(self, monkeypatch):
        from storage import tenant_store
        monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
        monkeypatch.setenv("WEB_CONCURRENCY", "4")
        with pytest.raises(RuntimeError, match="REFUSING TO START"):
            safety.verify_storage_is_multiworker_safe()

    def test_redis_down_multiworker_override_for_tests(self, monkeypatch, caplog):
        from storage import tenant_store
        monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
        monkeypatch.setenv("WEB_CONCURRENCY", "4")
        monkeypatch.setenv("SHIELD_ALLOW_INMEMORY_MULTIWORKER", "1")
        # Must not raise when override is set
        with caplog.at_level("WARNING"):
            safety.verify_storage_is_multiworker_safe()

    def test_uvicorn_workers_env_also_recognized(self, monkeypatch):
        from storage import tenant_store
        monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
        monkeypatch.setenv("UVICORN_WORKERS", "8")
        with pytest.raises(RuntimeError):
            safety.verify_storage_is_multiworker_safe()

    def test_redis_ping_failure_treated_as_down(self, monkeypatch):
        class _BrokenRedis:
            def ping(self): raise ConnectionError("nope")
        from storage import tenant_store
        monkeypatch.setattr(tenant_store, "_get_redis", lambda: _BrokenRedis())
        monkeypatch.setenv("WEB_CONCURRENCY", "2")
        with pytest.raises(RuntimeError):
            safety.verify_storage_is_multiworker_safe()
