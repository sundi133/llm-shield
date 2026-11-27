"""Claude Code hook: Bash redirect targets inside command substitutions.

A profile that limits writable paths denied V=$(cmd 2>/dev/null) because the
tokenizer kept the closing ")" on the target ("/dev/null)"). These pin the
fix and that it opens no way past the write check.
"""

import pytest

from core.runtime_policy import check as rc
from core.runtime_policy import hooks
from core.runtime_policy.model import validate_profile

PROJECT = "/home/dev/proj"


@pytest.fixture(scope="module")
def cp():
    profile = validate_profile({"filesystem": {"read_write": ["@project", "/tmp"]}})
    return rc.compile_checks("limited-writes", profile)


def _bash(cp, command):
    return hooks.decide(cp, {"tool_name": "Bash", "tool_input": {"command": command},
                             "cwd": PROJECT})


HEREDOC = (
    "cat > /tmp/probe.sh <<'EOF'\n"
    "V=$(sw_vers -productVersion 2>/dev/null)\n"
    "echo \"it's $V\"\n"
    "EOF"
)
# A heredoc line the quote-aware tokenizer cannot parse (stray quote), so the
# str.split fallback is used: the shapes the live hook blocked on 2026-11-27.
HEREDOC_FALLBACK = (
    "python3 - <<'PY'\n"
    "run(\"V=$(sw_vers 2>/dev/null)\",  # it's\n"
    "run('v=$(uname 2>/dev/null)',  \"x\n"
    "PY"
)


@pytest.mark.parametrize("command", [
    "x=$(cmd 2>/dev/null)",
    "V=$(sw_vers -productVersion 2>/dev/null)",
    'echo "$(git rev-parse HEAD 2>/dev/null)"',
    "a=$(b 2>/dev/null); c",
    "a=$(b 2>/dev/null) && echo \"$a\" > out.txt",
    "x=`cmd 2>/dev/null`",
    "cmd 2>&1 >/dev/null",
    'echo x > "out file.txt"',
    "echo x >./a/b",
    "echo x >> /tmp/log)",
    HEREDOC,
    HEREDOC_FALLBACK,
])
def test_substitutions_and_real_writable_paths_are_allowed(cp, command):
    d = _bash(cp, command)
    assert d.decision == "allow", d.reason


@pytest.mark.parametrize("command, path", [
    ("$(echo x > /etc/passwd)", "/private/etc/passwd"),
    ("x=$(echo x > /etc/passwd 2>/dev/null)", "/private/etc/passwd"),
    ("echo x >/etc/hosts)", "/private/etc/hosts"),
    ("echo x 2>/dev/null >/etc/hosts", "/private/etc/hosts"),
    # A quoted ")" is part of the name: /tmp)x is a file in /, not in /tmp.
    ('echo x > "/tmp)x"', "/tmp)x"),
    # The str.split fallback (stray quote) still checks the cut path.
    ("echo don't >/etc/hosts)", "/private/etc/hosts"),
    ("echo don't >/etc/hosts),#", "/private/etc/hosts"),
    # ... and the uncut one, so a cut to a writable root is not a way out.
    ("echo x >/tmp', \"", "/tmp',"),
])
def test_real_writes_outside_the_profile_are_denied(cp, command, path):
    d = _bash(cp, command)
    assert d.decision == "deny", command
    assert d.kind == "file" and d.op == "write"
    assert d.value == path
    assert "writable paths" in d.reason


def test_unlimited_profile_is_unchanged():
    profile = validate_profile({})
    open_cp = rc.compile_checks("open", profile)
    assert _bash(open_cp, "echo x > /etc/hosts").decision == "allow"


@pytest.mark.parametrize("command, writes", [
    ("x=$(cmd 2>/dev/null)", 0),
    ("echo \"$(git rev-parse HEAD 2>/dev/null)\"", 0),
    ("echo x > /tmp/a 2>/dev/null", 1),
    ("$(echo x > /etc/passwd)", 1),
    ("echo don't >/tmp/a),#", 1),          # one redirect, counted once
    ("a > /tmp/x; b >> /tmp/y", 2),
])
def test_file_changes_counts_each_redirect_once(command, writes):
    payload = {"tool_name": "Bash", "tool_input": {"command": command}}
    assert hooks.file_changes(payload) == (writes, 0)
