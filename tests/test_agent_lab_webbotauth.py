"""Web Bot Auth in the lab (spec 2.5 and 12, declared agent tests).

Pins: a valid signature verifies in both Signature-Agent forms; a forged key,
a stale or replayed-elsewhere signature, a Signature-Agent with no signature
and a tampered directory are all invalid; an unknown directory is
unverified; no headers is 'none'. In the analysis a verified, allowed
operator is declared and never joins a fleet, an invalid signature raises
A11, and no signature changes nothing.
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

LAB = Path(__file__).resolve().parent.parent / "lab" / "agent-traffic"
sys.path.insert(0, str(LAB / "edge"))
sys.path.insert(0, str(LAB / "analysis"))

import detect  # noqa: E402
import webbotauth as w  # noqa: E402
from sessions import build_sessions  # noqa: E402

A_URL = w.OPERATORS["operator-a"]
HOST = "localhost:8180"
NOW = 1_800_000_000


def setup_registry(tmp_path):
    key = w.load_or_create(tmp_path, "operator-a")
    return key, {A_URL: w.directory(tmp_path, "operator-a")["keys"]}


def test_valid_in_both_forms(tmp_path):
    key, reg = setup_registry(tmp_path)
    for form in ("string", "dict"):
        h = w.sign_headers(key, A_URL, HOST, form=form, created=NOW)
        assert w.verify(h, HOST, reg, now=NOW + 5) == ("valid", A_URL), form


def test_invalid_cases(tmp_path):
    key, reg = setup_registry(tmp_path)
    good = w.sign_headers(key, A_URL, HOST, created=NOW)
    forged = w.sign_headers(Ed25519PrivateKey.generate(), A_URL, HOST, created=NOW)
    assert w.verify(forged, HOST, reg, now=NOW)[0] == "invalid"
    assert w.verify({"Signature-Agent": f'"{A_URL}"'}, HOST, reg, now=NOW)[0] == "invalid"
    assert w.verify(good, "evil.example", reg, now=NOW)[0] == "invalid"            # signed for another host
    assert w.verify(good, HOST, reg, now=NOW + 7200)[0] == "invalid"               # expired
    assert w.verify(dict(good, **{"Signature-Agent": '"https://operator-b.agents.example"'}),
                    HOST, {**reg, "https://operator-b.agents.example": reg[A_URL]}, now=NOW)[0] == "invalid"
    assert w.verify(dict(good, Signature="sig1=:AAAA:"), HOST, reg, now=NOW)[0] == "invalid"
    assert w.verify({"Signature-Input": "garbage", "Signature": "x"}, HOST, reg, now=NOW)[0] == "invalid"


def test_unknown_directory_is_unverified_and_no_headers_is_none(tmp_path):
    _, reg = setup_registry(tmp_path)
    other = w.sign_headers(Ed25519PrivateKey.generate(), "https://new.agents.example", HOST, created=NOW)
    assert w.verify(other, HOST, reg, now=NOW) == ("unverified", "https://new.agents.example")
    assert w.verify({}, HOST, reg, now=NOW) == ("none", "")


def test_thumbprint_is_rfc7638():
    # RFC 8037 appendix A.3 Ed25519 public key and its thumbprint.
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
    assert w.thumbprint(jwk) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def ev(sid, t, uri, ip, wba="", agent="", method="GET"):
    return {"msec": t, "ip": ip, "method": method, "uri": uri, "status": 200, "ua": "UA", "chua": "",
            "chua_platform": "", "al": "", "sid": sid, "sid_set": "", "acct": "", "event": "", "trip": "",
            "enforced": "", "shs": "", "wba": wba, "wba_agent": agent}


def agent_rows(sid, start, ip, wba="", agent=""):
    steps = ["/", "/signup", "/account", "/promo", "/product/6", "/checkout", "/cart"]
    return [ev(sid, start + i * 5, u, ip, wba, agent) for i, u in enumerate(steps)]


def test_declared_label_and_a11():
    allow = {A_URL}
    ok = build_sessions(agent_rows("d", 0, "24.1.1.1", "valid", A_URL))[0]
    other = build_sessions(agent_rows("u", 0, "24.1.1.2", "valid", "https://operator-b.agents.example"))[0]
    forged = build_sessions(agent_rows("f", 0, "24.1.1.3", "invalid", A_URL))[0]
    plain = build_sessions(agent_rows("p", 0, "24.1.1.4", "none"))[0]
    assert detect.declared(ok, allow) == "declared"
    assert detect.declared(other, allow) == "declared_unknown"
    assert detect.declared(forged, allow) == "" and detect.score_session(forged).signals["A11"] == 1.0
    assert detect.declared(plain, allow) == "" and detect.score_session(plain).signals["A11"] == 0.0


def test_declared_agents_never_join_a_fleet():
    rows = []
    for i in range(12):
        rows += agent_rows(f"d{i}", i * 2, f"{24 + i}.9.{i}.5", "valid", A_URL)
    sessions = build_sessions(sorted(rows, key=lambda e: e["msec"]))
    assert len(detect.find_fleets(sessions, min_size=10)) == 1          # alike enough to form one
    exempt = {s.key for s in sessions if detect.declared(s, {A_URL}) == "declared"}
    assert detect.find_fleets(sessions, min_size=10, exclude=exempt) == []
