"""Built-in financial detectors and the decode pass (R3, task 1).

Spec: docs/specs/builtin-financial-patterns-decoded-pii.md, sections 7 and 8.
The corpus positives are computed valid by tests/fixtures/make_sensitive_identifiers_corpus.py,
independently of the module under test.
"""
import base64
import json
import random
import statistics
import time
from pathlib import Path

import pytest

from icap import detectors as d

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "sensitive_identifiers_corpus.jsonl"
BENCH = ROOT / "dlp-bench" / "dlp_eval.jsonl"
SLOW = 5.0   # deadline for tests about behaviour, not timing


def found(text, **kw):
    kw.setdefault("deadline_s", SLOW)
    return sorted({f.detector for f in d.scan(text, **kw).findings})


# ── copies stay identical ────────────────────────────────────────────

def test_server_copy_is_byte_identical():
    """core/dlp/detectors.py ships to the server images, which have no icap/."""
    assert (ROOT / "core" / "dlp" / "detectors.py").read_bytes() == (ROOT / "icap" / "detectors.py").read_bytes()


# ── labelled corpus and benign prompts ───────────────────────────────

def _corpus():
    return [json.loads(line) for line in CORPUS.read_text().splitlines() if line.strip()]


def test_corpus_is_large_and_balanced():
    rows = _corpus()
    pos = [r for r in rows if r["expect"]]
    assert len(rows) >= 350 and len(pos) >= 150 and len(rows) - len(pos) >= 150
    assert {e for r in pos for e in r["expect"]} == set(d.DETECTORS)


def test_corpus_full_recall_no_false_positives():
    wrong = [(r["note"], r["text"][:80], found(r["text"])) for r in _corpus() if found(r["text"]) != r["expect"]]
    assert wrong == []


def test_jwt_without_pii_is_not_flagged():
    """A JWT whose claims hold no PII is not a finding. Built here rather than
    kept as a literal in the corpus, so secret scanners do not flag a fake token."""
    def seg(obj):
        raw = obj if isinstance(obj, bytes) else json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    token = ".".join([seg({"alg": "HS256", "typ": "JWT"}), seg({"sub": "user-42", "role": "admin"}),
                      seg(b"testsignature")])
    assert found("token " + token) == []


def test_dlp_bench_benign_prompts_at_most_one_false_positive():
    rows = [json.loads(line) for line in BENCH.read_text().splitlines() if line.strip()]
    benign = [r for r in rows if not r["sensitive"]]
    assert len(benign) >= 115
    fps = [r["id"] for r in benign if found(r["text"])]
    assert len(fps) <= 1, fps


# ── validators against published vectors ─────────────────────────────

@pytest.mark.parametrize("num", ["79927398713", "4111111111111111", "378282246310005", "6011111111111117"])
def test_luhn_valid(num):
    assert d.luhn_ok(num)


@pytest.mark.parametrize("num", ["79927398710", "4111111111111112", "", "12a4"])
def test_luhn_invalid(num):
    assert not d.luhn_ok(num)


@pytest.mark.parametrize("num,brand", [
    ("4111111111111111", "visa"), ("5555555555554444", "mastercard"), ("2223003122003222", "mastercard"),
    ("378282246310005", "amex"), ("6011111111111117", "discover"), ("3530111333300000", "jcb"),
    ("30569309025904", "diners"), ("6200000000000005", "unionpay")])
def test_card_brands(num, brand):
    assert d.card_brand(num) == brand and d.card_ok(num)


def test_card_needs_issuer_and_length():
    assert not d.card_ok("1234567812345670")        # valid Luhn, no issuer
    assert not d.card_ok("411111111111111")         # visa prefix, length 15


@pytest.mark.parametrize("iban", ["GB82WEST12345698765432", "DE89 3704 0044 0532 0130 00",
                                  "FR1420041010050500013M02606", "NO9386011117947"])
def test_iban_valid(iban):
    assert d.iban_ok(iban)


@pytest.mark.parametrize("iban", ["GB00WEST12345698765432", "GB82WEST1234569876543", "XX82WEST12345698765432",
                                  "GB82WEST1234569876543!"])
def test_iban_invalid(iban):
    assert not d.iban_ok(iban)


def test_aba_checksum_and_prefix():
    assert d.aba_ok("021000021") and d.aba_ok("011000015")
    assert not d.aba_ok("123456789")              # checksum
    assert not d.aba_ok("990000000")              # prefix range
    assert not d.aba_ok("000000000")


def test_ssn_rules():
    assert d.ssn_ok("219099999")
    for bad in ("000123456", "666123456", "900123456", "123004567", "123450000"):
        assert not d.ssn_ok(bad), bad


# ── context rules ────────────────────────────────────────────────────

def test_context_required_for_aba_bic_account_and_bare_ssn():
    assert found("021000021") == []
    assert found("routing 021000021") == ["aba_routing"]
    assert found("DEUTDEFF") == [] and found("BIC: DEUTDEFF") == ["swift_bic"]
    assert found("12345678901") == [] and found("acct 12345678901") == ["bank_account"]
    assert found("219099999") == [] and found("SSN 219099999") == ["us_ssn"]


def test_negative_context_suppresses_card():
    assert found("invoice 4111111111111111") == []
    assert found("tracking ref 4556 7375 8689 9855") == []
    assert found("pay with 4111111111111111") == ["card_number"]


def test_card_with_trailing_year_is_found():
    assert found("4111 1111 1111 1111 2028") == ["card_number"]


# ── decode pass and its limits ───────────────────────────────────────

CARD = "4556737586899855"     # valid Visa, not a published test value


def b64(s):
    return base64.b64encode(s.encode() if isinstance(s, str) else s).decode()


def test_decode_off_skips_encoded_text():
    t = "x " + b64(f"card {CARD}")
    assert found(t) == ["card_number"]
    assert found(t, decode=False) == []


def test_depth_limit_two():
    assert found(b64(b64(f"card {CARD}"))) == ["card_number"]
    assert found(b64(b64(b64(f"card {CARD}")))) == []


def test_fragment_limit():
    t = " ".join(b64(f"card {CARD[:-1]}{i % 10} and {CARD}") for i in range(40))
    r = d.scan(t, deadline_s=SLOW)
    assert r.decoded and len(r.matches) == d.MAX_FRAGMENTS


def test_decoded_byte_cap():
    filler = "lorem ipsum " * 12000                        # about 144 KB
    late = d.scan(b64(filler + f" card {CARD}"), deadline_s=SLOW)
    early = d.scan(b64(f"card {CARD} " + filler), deadline_s=SLOW)
    assert not late.matches and early.findings[0].detector == "card_number"


def test_printable_ratio_drops_binary():
    raw = CARD.encode() + b"\x00\x01\x02\x03" * 10
    assert found("blob " + b64(raw)) == []


def test_binary_and_hash_tokens_are_not_decoded():
    png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    assert not d.scan(png, deadline_s=SLOW).decoded
    assert not d.scan("9fceb02d0ae598e95dc970b74767f19372d61af8", deadline_s=SLOW).decoded


def test_base64_inside_url_encoding_counts_once():
    t = "u=" + b64(f"card: {CARD}").replace("=", "%3D")
    f = d.scan(t, deadline_s=SLOW).findings
    assert [(x.detector, x.count) for x in f] == [("card_number", 1)]


# ── size, deadline, failure ──────────────────────────────────────────

def test_truncation_over_256_kib():
    pad = "x" * (d.MAX_SCAN_CHARS + 10)
    late = d.scan(pad + f" card {CARD}", deadline_s=SLOW)
    early = d.scan(f"card {CARD} " + pad, deadline_s=SLOW)
    assert late.truncated and not late.matches
    assert early.truncated and early.matches


def test_deadline_fails_open_without_raising():
    r = d.scan(f"card {CARD} " * 50, deadline_s=0)
    assert r.timeout


def test_never_raises_on_arbitrary_text():
    rng = random.Random(7)
    alphabet = "0123456789 -._/%&#;xX=+ABCDEFabcdef​１١ ÉSN"
    for _ in range(300):
        t = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 300)))
        d.scan(t, deadline_s=SLOW)


def test_empty_and_unknown_detectors():
    assert d.scan("").matches == []
    assert d.scan(f"card {CARD}", detectors=["nope"]).matches == []
    assert found(f"card {CARD} SSN 219-09-9999", detectors=["us_ssn"]) == ["us_ssn"]


# ── test values, findings and redaction ──────────────────────────────

def test_test_values_flagged_and_ignorable():
    f = d.scan("4111 1111 1111 1111", deadline_s=SLOW).findings
    assert f[0].test_value is True
    assert d.scan(f"card {CARD}", deadline_s=SLOW).findings[0].test_value is False
    assert d.scan("4111 1111 1111 1111", ignore_test_values=True, deadline_s=SLOW).matches == []


def test_findings_never_carry_the_value():
    t = f"card {CARD} iban GB82 WEST 1234 5698 7654 32 x {b64('SSN 219-09-9999')}"
    details = json.dumps(d.scan(t, deadline_s=SLOW).details())
    for secret in (CARD, "56987654", "219099999", "219-09-9999"):
        assert secret not in details


def test_redact_plain_and_encoded():
    enc = b64(f"card {CARD}")
    t = f"pay {CARD[:4]} {CARD[4:8]} {CARD[8:12]} {CARD[12:]} or {enc} ok"
    r = d.scan(t, deadline_s=SLOW)
    out = d.redact(t, r.matches)
    assert out == "pay [REDACTED:card_number] or [REDACTED:card_number] ok"
    assert d.scan(out, deadline_s=SLOW).matches == []


def test_redact_maps_unicode_spans_back_to_original():
    fw = "".join(chr(0xFF10 + int(c)) for c in CARD)
    t = f"«{fw}»"
    assert d.redact(t, d.scan(t, deadline_s=SLOW).matches) == "«[REDACTED:card_number]»"


# ── latency (generous, CI-safe; the spec budget is measured in task 3) ──

def test_latency_smoke_64_kib():
    rows = [json.loads(line)["text"] for line in BENCH.read_text().splitlines() if line.strip()]
    text = " ".join(rows * 20)[:65536]
    times = []
    for _ in range(9):
        s = time.perf_counter()
        r = d.scan(text, deadline_s=SLOW)
        times.append(time.perf_counter() - s)
    assert not r.timeout
    assert statistics.median(times) < 0.15
