"""Batched guardrail-metrics reads must be byte-for-byte equivalent to the
prior sequential reads — on clients that DO pipeline (Upstash-style .exec())
and on clients that DON'T (sequential fallback).

Regression for the live 502: get_all_guardrails_summary used to do one Redis
hgetall per guardrail per day. The batched read must not change any value.
"""

from datetime import datetime, timedelta

import pytest

import storage.guardrail_metrics as gm


def _seed(store, tenant, name, day_offsets_to_fields):
    for off, fields in day_offsets_to_fields.items():
        date = (datetime.utcnow() - timedelta(days=off)).strftime("%Y-%m-%d")
        store[gm._key(tenant, name, date)] = {k: str(v) for k, v in fields.items()}


class _BaseFake:
    def __init__(self, store):
        self.store = store

    def hgetall(self, key):
        return dict(self.store.get(key, {}))

    def scan(self, cursor=0, match="*", count=100):
        import fnmatch
        return 0, [k for k in self.store if fnmatch.fnmatch(k, match)]


class NoPipelineFake(_BaseFake):
    """Mimics the in-memory/Upstash-record path where pipeline() raises."""
    def pipeline(self, *a, **k):
        raise TypeError("no pipeline")


class _ExecPipeline:
    def __init__(self, fake):
        self.fake = fake
        self.ops = []

    def hgetall(self, key):
        self.ops.append(key)
        return self

    def exec(self):  # upstash_redis-style
        return [dict(self.fake.store.get(k, {})) for k in self.ops]


class ExecPipelineFake(_BaseFake):
    """Mimics the Upstash REST client: pipeline().exec()."""
    def pipeline(self, *a, **k):
        return _ExecPipeline(self)


class _UpstashPipeline(_ExecPipeline):
    """Upstash pipeline has BOTH exec() (run) and execute(command) (queue one).

    Calling execute() with no args raises — this is the trap that made the
    batch read silently fall back to sequential. The helper must call exec().
    """
    def execute(self, command):  # noqa: D401 - mirrors upstash signature
        self.ops.append(command)
        return self


class UpstashLikeFake(_BaseFake):
    def pipeline(self, *a, **k):
        return _UpstashPipeline(self)


class _RedisPyPipeline:
    """redis-py style: execute() runs the batch; no exec()."""
    def __init__(self, fake):
        self.fake = fake
        self.ops = []

    def hgetall(self, key):
        self.ops.append(key)
        return self

    def execute(self):
        return [dict(self.fake.store.get(k, {})) for k in self.ops]


class RedisPyLikeFake(_BaseFake):
    def pipeline(self, *a, **k):
        return _RedisPyPipeline(self)


@pytest.fixture
def seeded_store():
    store = {}
    # two guardrails, several days incl. a gap day (offset 1 missing for g2)
    _seed(store, "t1", "pii_leakage", {
        0: {"total": 10, "passed": 6, "blocked": 4, "latency_sum_ms": 200, "latency_count": 10},
        2: {"total": 5, "passed": 5, "latency_sum_ms": 50, "latency_count": 5},
    })
    _seed(store, "t1", "toxicity", {
        0: {"total": 3, "passed": 1, "blocked": 2},
    })
    return store


def test_exec_pipeline_matches_sequential(seeded_store, monkeypatch):
    """Fast path (exec pipeline) == fallback path (no pipeline), value for value."""
    seq = NoPipelineFake(dict(seeded_store))
    fast = ExecPipelineFake(dict(seeded_store))

    monkeypatch.setattr(gm, "_get_redis", lambda: seq)
    seq_summary = gm.get_all_guardrails_summary("t1", days=30)
    seq_eff = gm.get_effectiveness("t1", "pii_leakage", days=30)

    monkeypatch.setattr(gm, "_get_redis", lambda: fast)
    fast_summary = gm.get_all_guardrails_summary("t1", days=30)
    fast_eff = gm.get_effectiveness("t1", "pii_leakage", days=30)

    assert seq_summary == fast_summary
    assert seq_eff == fast_eff


def test_summary_values(seeded_store, monkeypatch):
    monkeypatch.setattr(gm, "_get_redis", lambda: ExecPipelineFake(seeded_store))
    summary = gm.get_all_guardrails_summary("t1", days=30)
    by_name = {s["guardrail"]: s for s in summary}
    assert by_name["pii_leakage"]["total"] == 15
    assert by_name["pii_leakage"]["blocked"] == 4
    assert by_name["pii_leakage"]["passed"] == 11
    assert by_name["pii_leakage"]["avg_latency_ms"] == round(250 / 15, 2)
    assert by_name["toxicity"]["blocked"] == 2
    # sorted by blocked desc
    assert summary[0]["guardrail"] == "pii_leakage"


def test_summary_matches_per_guardrail_effectiveness(seeded_store, monkeypatch):
    monkeypatch.setattr(gm, "_get_redis", lambda: ExecPipelineFake(seeded_store))
    summary = {s["guardrail"]: s for s in gm.get_all_guardrails_summary("t1", days=30)}
    for name in ("pii_leakage", "toxicity"):
        eff = gm.get_effectiveness("t1", name, days=30)
        for field in ("total", "passed", "blocked", "pass_rate", "block_rate",
                      "avg_latency_ms", "trend"):
            assert summary[name][field] == eff[field], field


def test_upstash_pipeline_uses_exec_not_execute(seeded_store, monkeypatch):
    """Upstash exposes exec()+execute(command); the helper must pick exec().

    Regression for the live days=30 502: calling execute() with no args raised,
    so the batch read fell back to sequential and stayed slow. With the correct
    selection the values match the sequential path exactly.
    """
    seq = NoPipelineFake(dict(seeded_store))
    monkeypatch.setattr(gm, "_get_redis", lambda: seq)
    expected = gm.get_all_guardrails_summary("t1", days=30)

    monkeypatch.setattr(gm, "_get_redis", lambda: UpstashLikeFake(dict(seeded_store)))
    got = gm.get_all_guardrails_summary("t1", days=30)
    assert got == expected and got  # non-empty and identical


def test_redispy_pipeline_uses_execute(seeded_store, monkeypatch):
    """redis-py has only execute() (no exec) — that branch must work too."""
    seq = NoPipelineFake(dict(seeded_store))
    monkeypatch.setattr(gm, "_get_redis", lambda: seq)
    expected = gm.get_all_guardrails_summary("t1", days=30)

    monkeypatch.setattr(gm, "_get_redis", lambda: RedisPyLikeFake(dict(seeded_store)))
    got = gm.get_all_guardrails_summary("t1", days=30)
    assert got == expected and got


def test_bad_pipeline_shape_falls_back(seeded_store, monkeypatch):
    """If a pipeline returns the wrong shape, we must fall back, not corrupt."""
    class BadPipeline:
        def hgetall(self, key): return self
        def exec(self): return ["wrong", "length"]  # never matches chunk size

    class BadFake(_BaseFake):
        def pipeline(self, *a, **k): return BadPipeline()

    monkeypatch.setattr(gm, "_get_redis", lambda: BadFake(seeded_store))
    summary = {s["guardrail"]: s for s in gm.get_all_guardrails_summary("t1", days=30)}
    # fallback (sequential hgetall) still produces correct totals
    assert summary["pii_leakage"]["total"] == 15
