"""Built-in, validated detectors for financial identifiers and SSNs, with a
decode pass for obfuscated and encoded text.

Spec: docs/specs/builtin-financial-patterns-decoded-pii.md (R3).

Pure and deterministic: text in, findings out. No network, no model, no shared
state. The same file ships three ways:

  icap/detectors.py       the source; the ICAP image and the device agent
                          installers bundle `icap/`
  core/dlp/detectors.py   a byte-identical copy for the server images, which do
                          not ship `icap/` (kept equal by a test)

Detectors:
  card_number   13 to 19 digits, issuer prefix and length, Luhn
  iban          country length table and mod-97
  aba_routing   9 digits, prefix range and checksum, needs routing context
  swift_bic     8 or 11 characters, ISO country, needs SWIFT / BIC context
  bank_account  8 to 17 digits, needs account-number context
  us_ssn        area / group / serial validity; dashed, or with SSN context

A finding never carries the matched value: `{detector, count, encodings,
test_value}`. Redaction replaces a plain match by its span and a match found in
decoded text by the whole encoded fragment, because decoded offsets do not map
back to the original text.
"""
from __future__ import annotations

import base64
import binascii
import html
import logging
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable, Optional

import regex

log = logging.getLogger("shield.detectors")

SCHEMA = 1
DETECTORS = ("card_number", "iban", "aba_routing", "swift_bic", "bank_account", "us_ssn")
SEVERITY = {"card_number": "high", "iban": "high", "aba_routing": "medium",
            "swift_bic": "low", "bank_account": "medium", "us_ssn": "high"}
ACTIONS = ("off", "monitor", "redact", "block")

MAX_SCAN_CHARS = 256 * 1024
MAX_DEPTH = 2
MAX_FRAGMENTS = 32
MAX_DECODED_BYTES = 128 * 1024
MIN_PRINTABLE = 0.70
DEFAULT_DEADLINE_S = 0.025

_NEG_CONTEXT = regex.compile(
    r"\b(?:order|invoice|inv|tracking|track|ticket|ref|reference|isbn|imei|serial|sku|"
    r"confirmation|po)\b", regex.I)
_CTX_ABA = regex.compile(r"\b(?:routing|aba|rtn|transit)\b", regex.I)
# A BIC must directly follow its label ("SWIFT: X", "BIC X", "SWIFT/BIC code is X"),
# so all-caps words such as BUSINESS near the word SWIFT do not fire.
_CTX_BIC = regex.compile(
    r"\b(?:swift|bic)(?:\s*/\s*(?:swift|bic))?(?:\s+(?:code|number|no\.?|#))?"
    r"(?:\s+is)?\s*[:=#\-]?\s*$", regex.I)
_CTX_ACCOUNT = regex.compile(
    r"(?:\baccount\s*(?:no\b\.?|number\b|num\b|#)|\bacct\b\.?|\ba/c\b)", regex.I)
_CTX_SSN = regex.compile(r"\b(?:ssn|social\s+security)\b", regex.I)

# A digit run: digits joined by at most two separator characters.
_DIGIT_RUN = regex.compile(r"(?<![0-9A-Za-z])[0-9](?:[ \-. _/]{0,2}[0-9])+(?![0-9A-Za-z])")
_SSN_DASHED = regex.compile(r"(?<![0-9A-Za-z])([0-9]{3})([- ])([0-9]{2})\2([0-9]{4})(?![0-9A-Za-z])")
_IBAN_START = regex.compile(r"(?<![0-9A-Za-z])([A-Z]{2})([0-9]{2})")
_BIC = regex.compile(r"(?<![0-9A-Za-z])([A-Z]{4})([A-Z]{2})([A-Z0-9]{2})([A-Z0-9]{3})?(?![0-9A-Za-z])")

_B64 = regex.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_ESC = regex.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}")
_HEX_0X = regex.compile(r"(?<![0-9A-Za-z])0x([0-9A-Fa-f]{8,})(?![0-9A-Za-z])")
_HEX_PLAIN = regex.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Za-z])")
_PCT = regex.compile(r"%[0-9A-Fa-f]{2}")
_ENTITY = regex.compile(r"(?:&#(?:[0-9]{1,7}|[xX][0-9A-Fa-f]{1,6});){3,}")

# IBAN lengths by country (SWIFT IBAN registry).
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
    "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
    "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27,
    "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20,
    "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27,
    "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28,
    "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24, "SC": 31,
    "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25, "SV": 28,
    "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}
# ISO 3166-1 alpha-2 codes, for the BIC country field.
_ISO_COUNTRIES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ
BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM
DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS
GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN
KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ
MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM
PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV
SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI
VN VU WF WS XK YE YT ZA ZM ZW
""".split())

# Published test values: detected and flagged `test_value`.
TEST_VALUES = frozenset({
    "4111111111111111", "4242424242424242", "4012888888881881", "4000056655665556",
    "5555555555554444", "5105105105105100", "2223003122003222", "378282246310005",
    "371449635398431", "6011111111111117", "6011000990139424", "3530111333300000",
    "3566002020360505", "30569309025904", "38520000023237", "6200000000000005",
    "123456789", "078051120",
    "GB82WEST12345698765432", "DE89370400440532013000", "FR1420041010050500013M02606",
    "NL91ABNA0417164300", "GB29NWBK60161331926819", "CH9300762011623852957",
})


# ── validators ────────────────────────────────────────────────────────

def luhn_ok(digits: str) -> bool:
    if not digits.isdigit() or len(digits) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def card_brand(digits: str) -> Optional[str]:
    """The issuer for a digit string by prefix and length, or None."""
    n = len(digits)
    p2, p3, p4 = (int(digits[:k]) if n >= k else -1 for k in (2, 3, 4))
    if digits[0] == "4" and n in (13, 16, 19):
        return "visa"
    if (51 <= p2 <= 55 or 2221 <= p4 <= 2720) and n == 16:
        return "mastercard"
    if p2 in (34, 37) and n == 15:
        return "amex"
    if (p4 == 6011 or 644 <= p3 <= 649 or p2 == 65) and 16 <= n <= 19:
        return "discover"
    if 3528 <= p4 <= 3589 and 16 <= n <= 19:
        return "jcb"
    if (300 <= p3 <= 305 or p2 in (36, 38, 39)) and 14 <= n <= 19:
        return "diners"
    if p2 == 62 and 16 <= n <= 19:
        return "unionpay"
    return None


def card_ok(digits: str) -> bool:
    return 13 <= len(digits) <= 19 and card_brand(digits) is not None and luhn_ok(digits)


def iban_ok(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    if len(s) < 15 or not s.isalnum() or IBAN_LENGTHS.get(s[:2]) != len(s) or not s[2:4].isdigit():
        return False
    moved = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in moved)
    return int(num) % 97 == 1


def aba_ok(digits: str) -> bool:
    if len(digits) != 9 or not digits.isdigit():
        return False
    p = int(digits[:2])
    if not (0 <= p <= 12 or 21 <= p <= 32 or 61 <= p <= 72 or p == 80):
        return False
    if digits == "000000000":
        return False
    d = [int(c) for c in digits]
    return (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10 == 0


def ssn_ok(digits: str) -> bool:
    if len(digits) != 9 or not digits.isdigit():
        return False
    area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
    return area != 0 and area != 666 and area < 900 and group != 0 and serial != 0


# ── results ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Match:
    detector: str
    start: int          # span in the ORIGINAL text (the whole fragment when decoded)
    end: int
    encoding: str = ""  # "" for plain text, else e.g. "base64" or "url+base64"
    test_value: bool = False


@dataclass(frozen=True)
class Finding:
    detector: str
    count: int
    encodings: tuple[str, ...] = ()
    test_value: bool = False

    def as_dict(self) -> dict:
        return {"detector": self.detector, "count": self.count,
                "encodings": list(self.encodings), "test_value": self.test_value}


@dataclass
class ScanResult:
    matches: list[Match] = field(default_factory=list)
    decoded: bool = False
    truncated: bool = False
    timeout: bool = False

    @property
    def findings(self) -> list[Finding]:
        out: dict[str, dict] = {}
        for m in self.matches:
            f = out.setdefault(m.detector, {"count": 0, "enc": [], "test": True})
            f["count"] += 1
            if m.encoding and m.encoding not in f["enc"]:
                f["enc"].append(m.encoding)
            f["test"] = f["test"] and m.test_value
        return [Finding(d, v["count"], tuple(v["enc"]), v["test"])
                for d, v in sorted(out.items(), key=lambda kv: DETECTORS.index(kv[0]))]

    def details(self) -> dict:
        return {"findings": [f.as_dict() for f in self.findings], "decoded": self.decoded,
                "truncated": self.truncated, "timeout": self.timeout}


class _Deadline(Exception):
    pass


class _Clock:
    def __init__(self, seconds: float):
        self.end = time.monotonic() + max(0.0, seconds)

    def left(self) -> float:
        r = self.end - time.monotonic()
        if r <= 0:
            raise _Deadline()
        return r


# ── normalization ─────────────────────────────────────────────────────

def normalize(text: str) -> tuple[str, Optional[list[int]]]:
    """NFKC per character, format characters dropped, Unicode digits mapped to
    ASCII. Returns the normalized text and, for each of its characters, the
    index of the original character it came from (None when the text is ASCII,
    which needs no change)."""
    if text.isascii():
        return text, None
    out: list[str] = []
    src: list[int] = []
    for i, ch in enumerate(text):
        if ch.isascii():
            out.append(ch)
            src.append(i)
            continue
        cat = unicodedata.category(ch)
        if cat == "Cf":                      # zero-width joiners, BOM, bidi marks
            continue
        if cat == "Nd":
            out.append(str(unicodedata.digit(ch)))
            src.append(i)
            continue
        for c in unicodedata.normalize("NFKC", ch):
            out.append(c)
            src.append(i)
    return "".join(out), src


def _span(src: Optional[list[int]], s: int, e: int) -> tuple[int, int]:
    return (s, e) if src is None else (src[s], src[e - 1] + 1)


def _near(pattern, text: str, s: int, e: int, before: int = 30, after: int = 0) -> bool:
    return bool(pattern.search(text[max(0, s - before):min(len(text), e + after)]))


# ── detectors on one normalized string ────────────────────────────────

def _candidates(norm: str, wanted: frozenset, clock: _Clock) -> list[tuple[str, int, int, str]]:
    """(detector, start, end, canonical value) in normalized coordinates."""
    found: list[tuple[str, int, int, str]] = []
    taken: list[tuple[int, int]] = []

    def free(s, e):
        return all(e <= a or s >= b for a, b in taken)

    def add(det, s, e, value):
        if free(s, e):
            found.append((det, s, e, value))
            taken.append((s, e))

    if "iban" in wanted:
        for m in _IBAN_START.finditer(norm, timeout=clock.left()):
            cc = m.group(1)
            need = IBAN_LENGTHS.get(cc)
            if not need:
                continue
            chars, i, gap = [], m.start(), 0
            while i < len(norm) and len(chars) < need:
                c = norm[i]
                if c.isascii() and c.isalnum():
                    chars.append(c.upper())
                    gap = 0
                elif c in " -" and chars and gap == 0:
                    gap = 1
                else:
                    break
                i += 1
            end = i
            if len(chars) != need or (end < len(norm) and norm[end].isascii() and norm[end].isalnum()):
                continue
            value = "".join(chars)
            if iban_ok(value):
                add("iban", m.start(), end, value)

    runs = []
    for m in _DIGIT_RUN.finditer(norm, timeout=clock.left()):
        groups = regex.findall(r"[0-9]+", m.group(0))
        runs.append((m, groups))

    if "card_number" in wanted:
        for m, groups in runs:
            digits = "".join(groups)
            if len(digits) < 13 or len(digits) > 40:
                continue
            hit = None
            if 13 <= len(digits) <= 19 and card_ok(digits):
                hit = (m.start(), m.end(), digits)
            elif len(groups) > 1 and all(len(g) >= 3 for g in groups):
                # card plus a neighbour (a year, a CVV): try group-aligned windows.
                # Only real groupings (3+ digits each), so a list of small
                # numbers ("1 2 3 ... 14") is never stitched into a card.
                offs, pos = [], 0
                for g in groups:
                    k = m.group(0).index(g, pos)
                    offs.append((m.start() + k, m.start() + k + len(g)))
                    pos = k + len(g)
                for a in range(len(groups)):
                    for b in range(len(groups), a, -1):
                        d = "".join(groups[a:b])
                        if 13 <= len(d) <= 19 and card_ok(d):
                            hit = (offs[a][0], offs[b - 1][1], d)
                            break
                    if hit:
                        break
            if hit and not _near(_NEG_CONTEXT, norm, hit[0], hit[1], before=20, after=20):
                add("card_number", *hit)

    if "us_ssn" in wanted:
        for m in _SSN_DASHED.finditer(norm, timeout=clock.left()):
            d = m.group(1) + m.group(3) + m.group(4)
            if ssn_ok(d):
                add("us_ssn", m.start(), m.end(), d)
        for m, groups in runs:
            d = "".join(groups)
            if len(d) == 9 and len(groups) == 1 and ssn_ok(d) and _near(_CTX_SSN, norm, m.start(), m.end()):
                add("us_ssn", m.start(), m.end(), d)

    if "aba_routing" in wanted:
        for m, groups in runs:
            d = "".join(groups)
            if len(d) == 9 and aba_ok(d) and _near(_CTX_ABA, norm, m.start(), m.end()):
                add("aba_routing", m.start(), m.end(), d)

    if "swift_bic" in wanted:
        for m in _BIC.finditer(norm, timeout=clock.left()):
            if m.group(2) in _ISO_COUNTRIES and _CTX_BIC.search(norm[max(0, m.start() - 30):m.start()]):
                add("swift_bic", m.start(), m.end(), m.group(0))

    if "bank_account" in wanted:
        for m, groups in runs:
            d = "".join(groups)
            if 8 <= len(d) <= 17 and _near(_CTX_ACCOUNT, norm, m.start(), m.end()):
                add("bank_account", m.start(), m.end(), d)
    return found


# ── decode pass ───────────────────────────────────────────────────────

def _printable(s: str) -> bool:
    if not s:
        return False
    ok = sum(1 for c in s if c.isprintable() or c in "\t\r\n")
    return ok / len(s) >= MIN_PRINTABLE


def _bytes_text(b: bytes) -> Optional[str]:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if _printable(s) else None


def _try_b64(tok: str) -> Optional[str]:
    t = tok.rstrip("=")
    if len(t) < 16 or len(t) % 4 == 1:
        return None
    padded = t + "=" * (-len(t) % 4)
    for alt in (b"+/", b"-_"):
        try:
            raw = base64.b64decode(padded, altchars=alt, validate=True)
        except (binascii.Error, ValueError):
            continue
        s = _bytes_text(raw)
        if s:
            return s
    return None


def _try_hex(h: str) -> Optional[str]:
    try:
        return _bytes_text(bytes.fromhex(h))
    except ValueError:
        return None


def _url_tokens(text: str) -> Iterable[tuple[int, int]]:
    """Whitespace-delimited tokens holding at least two %XX escapes, found by
    walking from each '%' (a token regex rescans every token; this does not)."""
    i, n = text.find("%"), len(text)
    last_end = -1
    while 0 <= i < n:
        if i < last_end:
            i = text.find("%", last_end)
            continue
        s = i
        while s > 0 and not text[s - 1].isspace():
            s -= 1
        e = i
        while e < n and not text[e].isspace():
            e += 1
        if len(_PCT.findall(text, s, e)) >= 2:
            yield s, e
        last_end = e
        i = text.find("%", e)


def _fragments(text: str, clock: _Clock) -> Iterable[tuple[int, int, str, str]]:
    """(start, end, decoded text, encoding) for encoded fragments of `text`."""
    for start, end in _url_tokens(text):
        tok = text[start:end]
        try:
            dec = urllib.parse.unquote(tok, errors="strict")
        except UnicodeDecodeError:
            continue
        if dec != tok and _printable(dec):
            yield start, end, dec, "url"
    for m in _ENTITY.finditer(text, timeout=clock.left()):
        dec = html.unescape(m.group(0))
        if dec != m.group(0) and _printable(dec):
            yield m.start(), m.end(), dec, "html"
    for m in _HEX_ESC.finditer(text, timeout=clock.left()):
        dec = _try_hex(m.group(0).replace("\\x", ""))
        if dec:
            yield m.start(), m.end(), dec, "hex"
    for m in _HEX_0X.finditer(text, timeout=clock.left()):
        if len(m.group(1)) % 2 == 0:
            dec = _try_hex(m.group(1))
            if dec:
                yield m.start(), m.end(), dec, "hex"
    for m in _HEX_PLAIN.finditer(text, timeout=clock.left()):
        dec = _try_hex(m.group(0))
        if dec:
            yield m.start(), m.end(), dec, "hex"
    for m in _B64.finditer(text, timeout=clock.left()):
        dec = _try_b64(m.group(0))
        if dec:
            yield m.start(), m.end(), dec, "base64"


# ── public API ────────────────────────────────────────────────────────

def scan(text: str, detectors: Iterable[str] = DETECTORS, *, decode: bool = True,
         ignore_test_values: bool = False, deadline_s: float = DEFAULT_DEADLINE_S) -> ScanResult:
    """Find the given detectors in `text`, plain and (if `decode`) encoded.
    Never raises; on the deadline it returns what it found with `timeout`."""
    res = ScanResult()
    wanted = frozenset(d for d in detectors if d in DETECTORS)
    if not text or not wanted:
        return res
    if len(text) > MAX_SCAN_CHARS:
        text, res.truncated = text[:MAX_SCAN_CHARS], True
    clock = _Clock(deadline_s)
    budget = {"fragments": MAX_FRAGMENTS, "bytes": min(2 * len(text), MAX_DECODED_BYTES)}

    def keep(det, value):
        is_test = value in TEST_VALUES
        return (not (ignore_test_values and is_test)), is_test

    def visit(t: str, depth: int, outer: Optional[tuple[int, int]], enc: str):
        norm, src = normalize(t)
        for det, s, e, value in _candidates(norm, wanted, clock):
            ok, is_test = keep(det, value)
            if not ok:
                continue
            start, end = outer if outer else _span(src, s, e)
            res.matches.append(Match(det, start, end, enc, is_test))
        if not decode or depth >= MAX_DEPTH:
            return
        for fs, fe, dec, how in list(_fragments(t, clock)):
            if budget["fragments"] <= 0 or budget["bytes"] <= 0:
                return
            budget["fragments"] -= 1
            dec = dec[:budget["bytes"]]
            budget["bytes"] -= len(dec)
            res.decoded = True
            span = outer if outer else (fs, fe)
            visit(dec, depth + 1, span, f"{enc}+{how}" if enc else how)

    try:
        visit(text, 0, None, "")
    except (_Deadline, TimeoutError):
        res.timeout = True
    except Exception:   # a detector bug must never break the caller's request
        log.warning("detectors: scan failed, failing open", exc_info=True)
        res.timeout = True
    res.matches = _merge(res.matches)
    return res


def _merge(matches: list[Match]) -> list[Match]:
    """One match per detector and overlapping span. The same value reached two
    ways (base64 found directly inside a URL-encoded token, and again after URL
    decoding) is one hit; the merged span is the widest, so redaction removes
    all of it. The first-found encoding is kept."""
    out: list[Match] = []
    for m in matches:
        for i, o in enumerate(out):
            if o.detector == m.detector and m.start < o.end and o.start < m.end:
                out[i] = Match(o.detector, min(o.start, m.start), max(o.end, m.end),
                               o.encoding, o.test_value and m.test_value)
                break
        else:
            out.append(m)
    return sorted(out, key=lambda x: (x.start, x.detector))


def redact(text: str, matches: Iterable[Match], fmt: str = "[REDACTED:{detector}]") -> str:
    """Replace every matched span (plain spans, or whole encoded fragments)."""
    spans = sorted({(m.start, m.end, m.detector) for m in matches})
    merged: list[list] = []
    for s, e, d in spans:
        if merged and s < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e, d])
    out, pos = [], 0
    for s, e, d in merged:
        out.append(text[pos:s])
        out.append(fmt.format(detector=d))
        pos = e
    out.append(text[pos:])
    return "".join(out)
