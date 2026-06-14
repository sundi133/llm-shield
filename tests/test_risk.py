"""Offline tests for the zero-config risk classifier.

    PYTHONPATH=. python tests/test_risk.py
"""

from core.risk import score_tool, is_dangerous, LOW, MEDIUM, HIGH


def test_high_risk_names():
    for name in ("wire_transfer_execute", "delete_records", "exec_command",
                 "revoke_access", "issue_refund"):
        assert score_tool(name)["risk"] == HIGH, name


def test_medium_risk_names():
    for name in ("send_email", "create_invoice", "update_profile", "export_data"):
        assert score_tool(name)["risk"] == MEDIUM, name


def test_low_risk_names():
    for name in ("get_balance", "list_orders", "lookup_customer", "search_docs"):
        assert score_tool(name)["risk"] == LOW, name


def test_http_method_signal():
    assert score_tool("things", method="GET")["risk"] == LOW
    assert score_tool("things", method="POST")["risk"] == MEDIUM
    assert score_tool("things", method="DELETE")["risk"] == HIGH


def test_strongest_signal_wins():
    # read-style name but DELETE method → high
    r = score_tool("get_thing", method="DELETE")
    assert r["risk"] == HIGH
    # benign name but SSN in args → high
    r = score_tool("lookup", arguments={"q": "ssn 123-45-6789"})
    assert r["risk"] == HIGH


def test_arg_sniffing():
    assert score_tool("op", arguments={"amount": 5000})["risk"] == MEDIUM
    assert score_tool("op", arguments={"amount": "1,250.00"})["risk"] == MEDIUM
    assert score_tool("op", arguments={"to": "a@b.com"})["risk"] == MEDIUM
    assert score_tool("op", arguments={"card": "4111 1111 1111 1111"})["risk"] == HIGH
    assert score_tool("op", arguments={"path": "/etc/passwd"})["risk"] == MEDIUM


def test_no_signal_defaults_low():
    r = score_tool("frobnicate")
    assert r["risk"] == LOW
    assert r["signals"] == []


def test_reason_present():
    assert score_tool("wire_transfer")["reason"]
    assert is_dangerous("delete_all") is True
    assert is_dangerous("get_thing") is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
