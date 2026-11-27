"""Regenerate tests/fixtures/sensitive_identifiers_corpus.jsonl (deterministic).

    python tests/fixtures/make_sensitive_identifiers_corpus.py

Every positive is computed valid here (Luhn check digit, IBAN mod-97 check
digits, ABA checksum), independently of icap/detectors.py, so the corpus tests
the detectors rather than echoing them. Negatives are the look-alikes in
docs/specs/builtin-financial-patterns-decoded-pii.md section 8.
"""
from __future__ import annotations

import base64
import json
import random
from pathlib import Path

OUT = Path(__file__).with_name("sensitive_identifiers_corpus.jsonl")
rng = random.Random(20261126)
rows: list[dict] = []


def add(text, expect, note):
    rows.append({"text": text, "expect": sorted(expect), "note": note})


def luhn_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def card(prefix: str, length: int) -> str:
    body = prefix + "".join(rng.choice("0123456789") for _ in range(length - len(prefix) - 1))
    return body + luhn_digit(body)


def bad_luhn(num: str) -> str:
    last = (int(num[-1]) + rng.randint(1, 9)) % 10
    return num[:-1] + str(last)


def iban(cc: str, length: int) -> str:
    bban = "".join(rng.choice("0123456789") for _ in range(length - 4))
    num = "".join(str(int(c, 36)) for c in bban + cc + "00")
    return f"{cc}{98 - int(num) % 97:02d}{bban}"


def aba() -> str:
    prefixes = [f"{p:02d}" for p in list(range(1, 13)) + list(range(21, 33)) + list(range(61, 73)) + [80]]
    d = [int(c) for c in rng.choice(prefixes) + "".join(rng.choice("0123456789") for _ in range(6))]
    s = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5])
    return "".join(map(str, d)) + str((-s) % 10)


def ssn() -> str:
    while True:
        a = rng.randint(1, 899)
        if a != 666:
            return f"{a:03d}{rng.randint(1, 99):02d}{rng.randint(1, 9999):04d}"


def grouped(s: str, sep: str = " ", n: int = 4) -> str:
    return sep.join(s[i:i + n] for i in range(0, len(s), n))


# ── card positives ───────────────────────────────────────────────────
BRANDS = [("visa", "4", 16), ("visa13", "4", 13), ("mastercard", "53", 16),
          ("mastercard2", "2720", 16), ("amex", "37", 15), ("discover", "6011", 16),
          ("jcb", "3530", 16), ("diners", "36", 14), ("unionpay", "62", 16),
          ("unionpay19", "62", 19)]
CARD_TEMPLATES = ["my card is {}", "Card: {}", "use {} expiring 09/29 please",
                  "charge the corporate card {} today"]
for name, prefix, length in BRANDS:
    for t in CARD_TEMPLATES:
        c = card(prefix, length)
        fmt = rng.choice([c, grouped(c), grouped(c, "-")])
        add(t.format(fmt), ["card_number"], f"card {name}")

# ── IBAN positives ───────────────────────────────────────────────────
for cc, n in [("DE", 22), ("GB", 22), ("FR", 27), ("NL", 18), ("ES", 24), ("IT", 27),
              ("BE", 16), ("CH", 21), ("AT", 20), ("IE", 22), ("PL", 28), ("SE", 24),
              ("NO", 15), ("DK", 18), ("FI", 18), ("PT", 25), ("CZ", 24), ("HU", 28),
              ("RO", 24), ("AE", 23)]:
    v = iban(cc, n)
    add(f"Please wire it to IBAN {v}", ["iban"], f"iban {cc} compact")
    add(f"Beneficiary account: {grouped(v)} (Acme GmbH)", ["iban"], f"iban {cc} grouped")
for known in ["GB82 WEST 1234 5698 7654 32", "DE89 3704 0044 0532 0130 00",
              "FR14 2004 1010 0505 0001 3M02 606", "NL91ABNA0417164300"]:
    add(f"IBAN: {known}", ["iban"], "iban published example")

# ── ABA, BIC, account, SSN positives ─────────────────────────────────
for t in ["routing number {}", "ABA {} for the payroll account", "RTN: {}", "bank routing {} ok"]:
    for _ in range(4):
        add(t.format(aba()), ["aba_routing"], "aba with context")
for bic in ["DEUTDEFF", "BOFAUS3N", "CHASUS33", "NWBKGB2L", "HSBCGB2L", "BNPAFRPP",
            "COBADEFFXXX", "UBSWCHZH80A", "INGBNL2A", "CITIUS33", "SCBLSGSG", "ANZBAU3M"]:
    add(rng.choice(["SWIFT: {}", "BIC {}", "SWIFT code {}", "SWIFT/BIC: {}"]).format(bic),
        ["swift_bic"], "bic with context")
for _ in range(12):
    n = "".join(rng.choice("0123456789") for _ in range(rng.randint(8, 12)))
    add(rng.choice(["account number {}", "acct {}", "Account no. {}", "a/c {}"]).format(n),
        ["bank_account"], "account with context")
for _ in range(10):
    s = ssn()
    add(f"employee SSN {s[:3]}-{s[3:5]}-{s[5:]}", ["us_ssn"], "ssn dashed")
for _ in range(5):
    add(f"social security number {ssn()}", ["us_ssn"], "ssn undashed with context")

# ── encoded positives ────────────────────────────────────────────────
for _ in range(4):
    c = card("4", 16)
    msg = f"card {c}".encode()
    add(" ".join(c), ["card_number"], "spaced digits")
    add(grouped(c, "."), ["card_number"], "dotted digits")
    add("".join(chr(0xFF10 + int(x)) if x.isdigit() else x for x in grouped(c)), ["card_number"],
        "fullwidth digits")
    add("​".join(c), ["card_number"], "zero-width joined")
    add("data: " + base64.b64encode(msg).decode(), ["card_number"], "base64")
    add("data: " + base64.urlsafe_b64encode(msg + b"??>>").decode().rstrip("="), ["card_number"],
        "url-safe base64")
    add("bytes " + "".join(f"\\x{b:02x}" for b in msg), ["card_number"], "hex \\x escapes")
    add("value 0x" + msg.hex(), ["card_number"], "hex 0x")
    add("blob " + msg.hex(), ["card_number"], "hex plain")
    add("q=" + "".join(f"%{b:02X}" for b in msg), ["card_number"], "percent-encoded")
    add("text " + "".join(f"&#{b};" for b in msg), ["card_number"], "html entities")
    b64 = base64.b64encode(msg).decode()
    add("u=" + b64.replace("=", "%3D").replace("+", "%2B").replace("/", "%2F"), ["card_number"],
        "base64 inside url-encoding")
for _ in range(3):
    v = iban("DE", 22)
    add("iban " + base64.b64encode(f"IBAN {v}".encode()).decode(), ["iban"], "iban base64")
    s = ssn()
    add("x " + base64.b64encode(f"SSN {s[:3]}-{s[3:5]}-{s[5:]}".encode()).decode(), ["us_ssn"],
        "ssn base64")

# ── negatives ────────────────────────────────────────────────────────
for _ in range(10):
    c = card("4", 16)
    add(f"Order #{c} shipped", [], "order number, valid luhn, negative context")
    add(f"ticket {grouped(c)} closed", [], "ticket number, negative context")
    add(f"my number {bad_luhn(c)}", [], "16 digits, bad luhn")
for _ in range(10):
    body = rng.choice("1789") + "".join(rng.choice("0123456789") for _ in range(14))
    add(f"id {body + luhn_digit(body)}", [], "valid luhn, no issuer prefix")
fixed_negatives = [
    ("Invoice INV-2026-000123 is due", "invoice id"),
    ("UPS 1Z999AA10123456784 arrives Friday", "ups tracking"),
    ("Tracking 794644790138 via FedEx", "fedex tracking"),
    ("IMEI 490154203237518 on the device", "imei"),
    ("ISBN 978-0-306-40615-7", "isbn-13"),
    ("ISBN 9780306406157", "isbn-13 compact"),
    ("Call +1 (415) 555-0132 tomorrow", "us phone"),
    ("Call +44 20 7946 0958", "uk phone"),
    ("ring 415-555-0132", "phone dashed"),
    ("created at 1732579200", "unix seconds"),
    ("created at 1732579200123", "unix ms"),
    ("request id 3f2b8c9e-1d4a-4f6b-9a2e-7c5d8e1f0a3b", "uuid"),
    ("commit 9fceb02d0ae598e95dc970b74767f19372d61af8", "git sha"),
    ("sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
    ("img data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
     "png base64"),
    ("upgrade to v1.24.3 then 2.0.0-rc.1", "versions"),
    ("meeting on 2026-11-26 and 11/26/2026", "dates"),
    ("price $1,299.00 or EUR 1.299,00", "prices"),
    ("Employee ID 123456789 joined", "9 digits, no routing or ssn context"),
    ("ZIP 94105-1234", "zip+4"),
    ("PLEASE CONFIRM BUSINESS TRANSFER TODAY", "all-caps words"),
    ("What is a SWIFT code for BUSINESS accounts", "swift word then all-caps word"),
    ("the BANKCODE field is empty", "all-caps bic-shaped word, no context"),
    ("account balance 12345678 dollars", "account without number context"),
    ("IBAN GB00 WEST 1234 5698 7654 32", "iban bad check digits"),
    ("IBAN XX82 WEST 1234 5698 7654 32", "unknown country"),
    ("SSN 000-12-3456", "ssn area 000"),
    ("SSN 666-12-3456", "ssn area 666"),
    ("SSN 900-12-3456", "ssn area 9xx"),
    ("SSN 123-00-4567", "ssn group 00"),
    ("routing number 123456789", "aba bad checksum"),
    ("base64 " + base64.b64encode(b"hello world, nothing sensitive in here at all").decode(),
     "base64 of benign text"),
    ("hex " + b"just a harmless hex encoded sentence".hex(), "hex of benign text"),
    ("list 1 2 3 4 5 6 7 8 9 10 11 12 13 14", "counting"),
    ("ref 4111111111111111", "test card with ref context"),
    ("aws key AKIAIOSFODNN7EXAMPLE rotated", "aws key id is not a bic"),
    ("Q3 revenue 41200000 down 12 percent", "large number"),
    ("bytes 0x00ff10a0bb", "short hex"),
    ("color #FF5733 and #33FF57", "hex colors"),
]
for text, note in fixed_negatives:
    add(text, [], note)
for _ in range(25):
    add(rng.choice(["Room {a}, floor {b}, building {c}", "{a} users signed up in {c} days, {b} churned",
                    "ticket {a}-{b}-{c} reopened", "batch {a} of {b}, retry {c}",
                    "latency p95 {a} ms over {b} requests at {c} rps"]).format(
        a=rng.randint(1, 99999), b=rng.randint(1, 9999), c=rng.randint(1, 999)), [], "everyday numbers")
for _ in range(50):
    n = rng.randint(13, 19)
    s = "".join(rng.choice("0123456789") for _ in range(n))
    add(f"reading {s} units", [], "random long number (filtered below if valid)")
for _ in range(25):
    add(f"build {''.join(rng.choice('0123456789abcdef') for _ in range(40))}", [], "random sha1")

# Random long numbers can be valid cards by chance: label them by the rule the
# spec states (issuer prefix + length + Luhn), computed here, not by the detector.
def _brand_ok(d):
    n = len(d)
    p2, p3, p4 = int(d[:2]), int(d[:3]), int(d[:4])
    return ((d[0] == "4" and n in (13, 16, 19)) or ((51 <= p2 <= 55 or 2221 <= p4 <= 2720) and n == 16)
            or (p2 in (34, 37) and n == 15) or ((p4 == 6011 or 644 <= p3 <= 649 or p2 == 65) and 16 <= n <= 19)
            or (3528 <= p4 <= 3589 and 16 <= n <= 19) or ((300 <= p3 <= 305 or p2 in (36, 38, 39)) and 14 <= n <= 19)
            or (p2 == 62 and 16 <= n <= 19))


def _luhn_ok(d):
    return luhn_digit(d[:-1]) == d[-1]


for r in rows:
    if r["note"].startswith("random long number"):
        d = r["text"].split()[1]
        if _brand_ok(d) and _luhn_ok(d):
            r["expect"], r["note"] = ["card_number"], "random number that is a valid card"

OUT.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
print(f"{len(rows)} rows -> {OUT}")
