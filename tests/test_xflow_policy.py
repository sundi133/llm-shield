"""Cross-app flow policy engine (pure): validation, classification, exposure,
rule matching and precedence. Spec: docs/specs/cross-app-flow-control.md."""

import copy

import pytest

from core.xflow.policy import (
    PolicyError,
    apps_for,
    compile_policy,
    destination_rules,
    effective_classification,
    evaluate,
    exposure_for,
    fingerprint,
    make_record,
    source_classification,
    starter_policy,
    validate_policy,
)
from core.xflow.runtime import simulate


def _cp(policy=None):
    return compile_policy(validate_policy(policy or _policy()))


def _policy(**over):
    p = starter_policy()
    p["mode"] = "enforce"
    p.update(over)
    return p


def _decide(policy, tool, params=None, sources=(), route=None, resource=None):
    s = simulate(policy, tool_name=tool, params=params, route=route, resource=resource,
                 sources=[{"tool_name": t} if isinstance(t, str) else t for t in sources])
    return s["decision"]["action"] if s["result"] else None, s


# ── validation ───────────────────────────────────────────────────────


def test_starter_policy_validates_and_is_idempotent():
    once = validate_policy(starter_policy())
    assert validate_policy(once) == once          # a stored policy loads back unchanged
    assert validate_policy(copy.deepcopy(once)) == once


def test_every_rule_references_known_apps_and_template_has_all_actions():
    p = validate_policy(starter_policy())
    assert {r["action"] for r in p["rules"]} == {"block", "require_approval", "warn"}


@pytest.mark.parametrize("bad, needle", [
    ({"rulez": []}, "unknown field 'rulez'"),
    ({"mode": "enforcing"}, "mode: must be one of"),
    ({"apps": {"Drive": {"tools": ["x"]}}}, "app name 'Drive'"),
    ({"apps": {"drive": {}}}, "needs at least one of tools or routes"),
    ({"apps": {"drive": {"tools": ["x"], "classification": "secret"}}}, "classification"),
    ({"apps": {"drive": {"tools": ["x"], "source_tools": ["x"]}}}, "source_tools has no effect"),
    ({"apps": {"drive": {"tools": ["x"], "extra": 1}}}, "unknown field 'extra'"),
    ({"exposure_rules": [{"tools": ["*"], "param": "a", "matches": "(", "exposure": "public"}]},
     "invalid regex"),
    ({"exposure_rules": [{"tools": ["*"], "param": "a", "equals": 1, "in": [1],
                          "exposure": "public"}]}, "exactly one operator"),
    ({"exposure_rules": [{"param": "a", "equals": 1, "exposure": "public"}]}, "needs tools or apps"),
    ({"exposure_rules": [{"tools": ["*"], "param": "a", "equals": 1}]}, "exposure: required"),
    ({"exposure_rules": [{"tools": ["*"], "param": "a", "equals": 1, "exposure": "internal"}]},
     "exposure: must be one of"),
    ({"exposure_rules": [{"tools": ["*"], "param": "a", "domain_not_in": [],
                          "exposure": "external"}]}, "non-empty list of domains"),
    ({"rules": [{"id": "r", "source": {}, "destination": {"exposure": ["public"]}}]},
     "empty source would match every read"),
    ({"rules": [{"id": "r", "source": {"tags": ["SSN"]}, "destination": {}}]},
     "destination: set at least one"),
    ({"rules": [{"id": "r", "source": {"apps": ["nope"]},
                 "destination": {"exposure": ["public"]}}]}, "unknown app 'nope'"),
    ({"rules": [{"id": "r", "source": {"tags": ["SSN"]}, "destination": {"exposure": ["public"]},
                 "action": "deny"}]}, "action: must be one of"),
    ({"rules": [{"id": "r", "source": {"tags": ["SSN"]}, "destination": {"exposure": ["public"]}},
                {"id": "r", "source": {"tags": ["SSN"]}, "destination": {"exposure": ["public"]}}]},
     "duplicate id 'r'"),
    ({"rules": [{"id": "Bad Id", "source": {"tags": ["x"]}, "destination": {"exposure": ["public"]}}]},
     "rules[0].id"),
    ({"session_ttl_seconds": 5}, "session_ttl_seconds: must be between"),
    ({"principal_scope": "user"}, "principal_scope"),
    ({"enabled": "yes"}, "enabled: must be true or false"),
    ({"tag_classifications": {"SSN": "top-secret"}}, "tag_classifications.SSN"),
])
def test_validation_errors_are_reported(bad, needle):
    with pytest.raises(PolicyError) as e:
        validate_policy(bad)
    assert any(needle in err for err in e.value.errors), e.value.errors


def test_validation_reports_every_error_not_just_the_first():
    with pytest.raises(PolicyError) as e:
        validate_policy({"mode": "x", "principal_scope": "y", "rulez": 1})
    assert len(e.value.errors) >= 3


def test_limits_are_enforced():
    apps = {f"a{i}": {"tools": [f"t{i}"]} for i in range(201)}
    with pytest.raises(PolicyError) as e:
        validate_policy({"apps": apps})
    assert any("more than 200 apps" in x for x in e.value.errors)
    with pytest.raises(PolicyError):
        validate_policy({"apps": {"a": {"tools": ["x"] * 51}}})


def test_non_object_policy():
    with pytest.raises(PolicyError):
        validate_policy(["not", "an", "object"])


# ── classification ───────────────────────────────────────────────────


def test_app_membership_matches_both_naming_styles_and_is_case_insensitive():
    cp = _cp()
    assert apps_for(cp, "drive_read_file") == ["google_drive"]
    assert apps_for(cp, "drive.read_file") == ["google_drive"]
    assert apps_for(cp, "DRIVE_Read_File") == ["google_drive"]
    assert apps_for(cp, "calculator") == []


def test_route_adds_an_app_but_never_removes_one():
    p = _policy()
    p["apps"]["google_drive"]["routes"] = ["drive-mcp"]
    cp = _cp(p)
    assert apps_for(cp, "read_file", "drive-mcp") == ["google_drive"]
    # A caller claiming a benign route for a Drive tool still gets Drive.
    assert "google_drive" in apps_for(cp, "drive_read_file", "calculator-mcp")
    # Route claim adds Drive to a GitHub tool: both apps.
    assert set(apps_for(cp, "github_create_repo", "drive-mcp")) == {"github", "google_drive"}


def test_source_tools_limit_which_calls_record():
    cp = _cp()
    apps = apps_for(cp, "salesforce_get_account")
    assert source_classification(cp, "salesforce_get_account", apps) == "confidential"
    apps = apps_for(cp, "salesforce_update_account")
    assert source_classification(cp, "salesforce_update_account", apps) is None


def test_source_classification_takes_the_max_over_apps():
    p = _policy()
    p["apps"]["google_drive"]["routes"] = ["shared"]
    p["apps"]["github"]["routes"] = ["shared"]
    cp = _cp(p)
    apps = apps_for(cp, "anything", "shared")
    assert source_classification(cp, "anything", apps) == "confidential"


def test_tags_lift_effective_classification():
    cp = _cp()
    rec = make_record(tool_name="x", route=None, apps=[], classification="internal",
                      tags=["SSN"], evidence="observed", path="t", at=1.0)
    assert effective_classification(cp, rec) == "restricted"
    rec = make_record(tool_name="x", route=None, apps=[], classification=None,
                      tags=["unknown_tag"], evidence="observed", path="t", at=1.0)
    assert effective_classification(cp, rec) is None


def test_tenant_tag_classification_override():
    cp = _cp(_policy(tag_classifications={"PII": "restricted", "PHI": "restricted"}))
    assert cp.tag_classes["PII"] == "restricted"
    assert cp.tag_classes["SSN"] == "restricted"   # defaults kept
    assert cp.tag_classes["PHI"] == "restricted"


# ── exposure ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("params, expected", [
    ({"name": "x", "private": False}, "public"),
    ({"name": "x", "private": "false"}, "public"),      # loose bool
    ({"name": "x", "private": "FALSE "}, "public"),
    ({"name": "x", "private": 0}, "public"),
    ({"name": "x"}, "public"),                          # GitHub default is public
    ({"name": "x", "private": None}, "public"),         # null is missing
    ({"name": "x", "private": True}, "internal"),
    ({"name": "x", "private": "true"}, "internal"),
    ({"name": "x", "private": True, "visibility": "PUBLIC"}, "public"),
])
def test_github_repo_exposure(params, expected):
    cp = _cp()
    apps = apps_for(cp, "github_create_repo")
    assert exposure_for(cp, "github_create_repo", apps, params) == expected


@pytest.mark.parametrize("params, expected", [
    ({"to": "bob@example.com"}, "internal"),
    ({"to": "bob@eu.example.com"}, "internal"),                  # subdomain is internal
    ({"to": "bob@example.com.evil.io"}, "external"),             # suffix trick
    ({"to": "bob@notexample.com"}, "external"),
    ({"to": ["bob@example.com", "eve@evil.io"]}, "external"),    # any element
    ({"to": "bob@example.com", "bcc": "eve@evil.io"}, "external"),
    ({"to": "Bob <bob@EXAMPLE.com>"}, "internal"),
    ({"message": {"headers": {"cc": "x@evil.io"}}}, "external"),  # nested
    ({}, "internal"),
])
def test_email_exposure_by_domain(params, expected):
    cp = _cp()
    apps = apps_for(cp, "gmail_send")
    assert exposure_for(cp, "gmail_send", apps, params) == expected


def test_app_baseline_exposure_and_regex_rule():
    cp = _cp()
    assert exposure_for(cp, "pastebin_create", apps_for(cp, "pastebin_create"), {}) == "public"
    slack = apps_for(cp, "slack_post_message")
    assert exposure_for(cp, "slack_post_message", slack, {"channel": "ext-acme"}) == "external"
    assert exposure_for(cp, "slack_post_message", slack, {"channel": "general"}) == "internal"


def test_resource_param_and_other_operators():
    p = _policy(exposure_rules=[
        {"tools": ["s3_put*"], "param": "$resource", "matches": "^s3://public-", "exposure": "public"},
        {"tools": ["http_*"], "param": "url", "not_in": ["https://intranet"], "exposure": "external"},
        {"tools": ["share_*"], "param": "audience", "not_equals": "team", "exposure": "external"},
        {"tools": ["notify_*"], "param": "to", "domain_in": ["gmail.com"], "exposure": "external"},
    ])
    cp = _cp(p)
    assert exposure_for(cp, "s3_put", [], {}, resource="s3://public-assets/x") == "public"
    assert exposure_for(cp, "s3_put", [], {}, resource="s3://internal/x") == "internal"
    assert exposure_for(cp, "s3_put", [], {}) == "internal"
    assert exposure_for(cp, "http_get", [], {"url": "https://intranet"}) == "internal"
    assert exposure_for(cp, "http_get", [], {"url": "https://evil.io"}) == "external"
    assert exposure_for(cp, "share_doc", [], {"audience": "team"}) == "internal"
    assert exposure_for(cp, "share_doc", [], {"audience": "world"}) == "external"
    assert exposure_for(cp, "notify_user", [], {"to": "me@gmail.com"}) == "external"
    assert exposure_for(cp, "notify_user", [], {"to": "me@corp.com"}) == "internal"


def test_exposure_only_escalates_and_huge_values_are_bounded():
    cp = _cp()
    apps = apps_for(cp, "gmail_send")
    big = "x" * 1_000_000 + " eve@evil.io"
    # The address sits past the 4 KB matching window: not seen, and no hang.
    assert exposure_for(cp, "gmail_send", apps, {"body": big}) == "internal"
    many = {f"k{i}": "bob@example.com" for i in range(5000)}
    assert exposure_for(cp, "gmail_send", apps, many) == "internal"


# ── rules ────────────────────────────────────────────────────────────


def test_confidential_read_then_public_repo_is_blocked():
    action, s = _decide(_policy(), "github_create_repo", {"private": False}, ["drive_read_file"])
    assert action == "block"
    v = s["decision"]["violations"][0]
    assert v["rule_id"] == "confidential-to-public"
    assert v["sources"][0]["apps"] == ["google_drive"]
    assert "google_drive" in s["decision"]["message"] and "github" in s["decision"]["message"]
    assert s["decision"]["lineage"] and "->" in s["decision"]["lineage"][0]


def test_private_repo_and_clean_session_are_allowed():
    assert _decide(_policy(), "github_create_repo", {"private": True}, ["drive_read_file"])[0] is None
    assert _decide(_policy(), "github_create_repo", {"private": False}, [])[0] == "allow"
    # An internal (not confidential) source does not trip confidential-to-public.
    assert _decide(_policy(), "github_create_repo", {"private": False},
                   ["jira_get_issue"])[0] == "allow"


def test_require_approval_and_warn():
    assert _decide(_policy(), "gmail_send", {"to": "a@partner.com"},
                   ["salesforce_get_account"])[0] == "require_approval"
    assert _decide(_policy(), "gmail_send", {"to": "a@example.com"},
                   ["salesforce_get_account"])[0] is None
    assert _decide(_policy(), "slack_post_message", {"channel": "general"},
                   ["drive_read_file"])[0] == "warn"


def test_tags_rule_blocks_regardless_of_app():
    action, _ = _decide(_policy(), "gmail_send", {"to": "a@partner.com"},
                        [{"tool_name": "lookup", "tags": ["SSN"]}])
    assert action == "block"


def test_strongest_action_wins():
    # Salesforce (approval) + SSN (block) both flow to external mail: block.
    action, s = _decide(_policy(), "gmail_send", {"to": "a@partner.com"},
                        ["salesforce_get_account", {"tool_name": "lookup", "tags": ["SSN"]}])
    assert action == "block"
    assert {v["rule_id"] for v in s["decision"]["violations"]} == {
        "customer-data-external", "regulated-pii-anywhere-out"}
    assert s["decision"]["violations"][0]["action"] == "block"


def test_disabled_rule_is_skipped_and_every_destination_field_must_match():
    p = _policy()
    for r in p["rules"]:
        if r["id"] == "confidential-to-public":
            r["enabled"] = False
    action, s = _decide(p, "github_create_repo", {"private": False}, ["drive_read_file"])
    assert action == "allow"      # another rule still watches public destinations
    assert "confidential-to-public" not in s["rules_matching_destination"]
    p = _policy(rules=[{"id": "r", "source": {"apps": ["google_drive"]},
                        "destination": {"apps": ["github"], "tools": ["github_create_*"],
                                        "exposure": ["public"]}}])
    assert _decide(p, "github_create_repo", {"private": False}, ["drive_read_file"])[0] == "block"
    assert _decide(p, "github_create_issue", {}, ["drive_read_file"])[0] is None
    assert _decide(p, "github_create_repo", {"private": True}, ["drive_read_file"])[0] is None


def test_classifications_list_and_min_classification():
    p = _policy(rules=[{"id": "r", "source": {"classifications": ["internal"]},
                        "destination": {"exposure": ["public"]}}])
    assert _decide(p, "pastebin_create", {}, ["jira_get"])[0] == "block"
    assert _decide(p, "pastebin_create", {}, ["drive_read"])[0] == "allow"   # confidential != internal
    p = _policy(rules=[{"id": "r", "source": {"min_classification": "internal"},
                        "destination": {"exposure": ["public"]}}])
    assert _decide(p, "pastebin_create", {}, ["drive_read"])[0] == "block"


def test_custom_message_is_used():
    p = _policy(rules=[{"id": "r", "source": {"apps": ["google_drive"]},
                        "destination": {"exposure": ["public"]}, "message": "Nope, contracts stay in."}])
    _, s = _decide(p, "pastebin_create", {}, ["drive_read"])
    assert s["decision"]["message"] == "Nope, contracts stay in."


def test_destination_rules_is_the_cheap_prefilter():
    cp = _cp()
    assert destination_rules(cp, "drive_read_file", ["google_drive"], "internal") == []
    assert [r.id for r in destination_rules(cp, "pastebin_create", ["public_web"], "public")] == \
        ["confidential-to-public", "regulated-pii-anywhere-out"]


def test_evaluate_caps_sources_in_details():
    cp = _cp()
    recs = [make_record(tool_name=f"drive_read_{i}", route=None, apps=["google_drive"],
                        classification="confidential", tags=[], evidence="authorized",
                        path="t", at=float(i)) for i in range(40)]
    d = evaluate(cp, tool_name="pastebin_create", apps=["public_web"], exposure="public",
                 records=recs)
    v = d["violations"][0]
    assert v["source_count"] == 40 and len(v["sources"]) == 10
    assert v["sources"][0]["tool"] == "drive_read_39"    # most recent first


def test_fingerprint_dedupes_repeat_reads():
    a = make_record(tool_name="drive_read", route=None, apps=["g"], classification="confidential",
                    tags=["b", "a"], evidence="authorized", path="x", at=1.0)
    b = make_record(tool_name="drive_read", route=None, apps=["g"], classification="confidential",
                    tags=["a", "b"], evidence="observed", path="y", at=2.0)
    c = make_record(tool_name="drive_read", route=None, apps=["g"], classification="confidential",
                    tags=["SSN"], evidence="observed", path="y", at=2.0)
    assert fingerprint(a) == fingerprint(b) != fingerprint(c)


def test_simulate_notes_when_nothing_applies():
    s = simulate(_policy(), tool_name="calculator_add", params={})
    assert s["result"] is None and "no rule" in s["note"]
    s = simulate(_policy(enabled=False), tool_name="pastebin_create", sources=[{"tool_name": "drive_x"}])
    assert "disabled" in s["note"]
