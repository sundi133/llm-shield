"""Secret-vault use cases, each with a success and a failure path.

Runs against live code (core.secret_vault + storage.vault_store) and prints a
pass/fail matrix. Exit code is non-zero if any security property does not hold.

    PYTHONPATH=. python examples/secret_vault_scenarios.py
"""

import base64
import json
import os

os.environ.setdefault("SECRET_VAULT_ENABLED", "true")
os.environ.setdefault("SECRET_VAULT_KEY_PROVIDER", "software")
os.environ.setdefault(
    "SECRET_VAULT_KEK", base64.b64encode(b"scenario-kek-scenario-kek-32byte").decode())

from core.secret_vault import crypto                                    # noqa: E402
from core.secret_vault.keyprovider import SoftwareKeyProvider, _reset_provider_for_tests  # noqa: E402
from core.secret_vault.materialize import materialize_obj, retokenize   # noqa: E402
from storage import vault_store as vault                                # noqa: E402

REAL = "REALKEY-do-not-log-9f8e7d"          # fake stand-in, not secret-shaped
T = "scenarios"

_rows = []
def check(usecase, path, expect_ok, actual_ok, detail):
    ok = (expect_ok == actual_ok)
    _rows.append((usecase, path, "reveal" if actual_ok else "hidden", "PASS" if ok else "FAIL", detail))

def reset():
    for k in list(vault.get_vault_entries(T)):
        vault.delete_vault_entry(T, k["ref"])


# 1. Third-party API key, bound to a host --------------------------------------
reset()
vault.create_vault_entry(T, "api_key", REAL, bindings=["api.stripe.com"])
out = materialize_obj(T, "shield://api_key", "https://api.stripe.com/v1/charges")
check("Bound API key", "success: call bound host", True, out == REAL, "key delivered to api.stripe.com")
out = materialize_obj(T, "shield://api_key", "https://attacker.example/collect")
check("Bound API key", "failure: injected exfil", False, out == REAL, "attacker.example got only the placeholder")

# 2. Parent-domain binding -----------------------------------------------------
reset()
vault.create_vault_entry(T, "api_key", REAL, bindings=[".stripe.com"])
out = materialize_obj(T, "shield://api_key", "https://api.stripe.com/v1")
check("Domain binding", "success: subdomain via .stripe.com", True, out == REAL, "api.stripe.com covered by .stripe.com")
out = materialize_obj(T, "shield://api_key", "https://notstripe.com/v1")
check("Domain binding", "failure: look-alike domain", False, out == REAL, "notstripe.com rejected")

# 3. Tool-scoped secret (tier-1) ----------------------------------------------
reset()
vault.create_vault_entry(T, "gh", REAL, bindings=["api.github.com"], tool_ids=["gh.createIssue"])
out = materialize_obj(T, "shield://gh", "https://api.github.com", tool_id="gh.createIssue")
check("Tool scoping", "success: the allowed tool", True, out == REAL, "gh.createIssue may use it")
out = materialize_obj(T, "shield://gh", "https://api.github.com", tool_id="gh.deleteRepo")
check("Tool scoping", "failure: a different tool", False, out == REAL, "gh.deleteRepo blocked even on same host")

# 4. Ingress re-tokenization (output echo) ------------------------------------
reset()
vault.create_vault_entry(T, "api_key", REAL, bindings=["api.stripe.com"])
result = {"echo": f"upstream returned {REAL} in its body"}
safe = retokenize(T, result)
leaked = REAL in json.dumps(safe)
check("Output scrub", "success: echoed secret", False, leaked, "value re-tokenized to shield://api_key before model")

# 5. Registration requires a binding ------------------------------------------
reset()
try:
    vault.create_vault_entry(T, "loose", REAL, bindings=[])
    rejected = False
except (ValueError, Exception):
    rejected = True
check("Binding required", "failure: no binding given", False, not rejected, "unbound secret refused at registration")
vault.create_vault_entry(T, "ok", REAL, bindings=["api.stripe.com"])
check("Binding required", "success: with a binding", True, True, "bound secret accepted")

# 6. Encryption at rest + fail-closed keys ------------------------------------
reset()
vault.create_vault_entry(T, "api_key", REAL, bindings=["api.stripe.com"])
at_rest_leak = REAL in json.dumps(vault.get_vault_entries(T))
check("Encryption at rest", "success: nothing in plaintext", False, at_rest_leak, "stored record is ciphertext only")
entry = vault.get_vault_entries(T)[0]
try:
    crypto.decrypt_value(entry, SoftwareKeyProvider(b"w" * 32))   # attacker's KEK
    wrong_ok = True
except Exception:
    wrong_ok = False
check("Encryption at rest", "failure: wrong KEK", False, wrong_ok, "decrypt rejected (fail-closed)")

# 7. Vault disabled -> no-op ---------------------------------------------------
reset()
vault.create_vault_entry(T, "api_key", REAL, bindings=["api.stripe.com"])
os.environ["SECRET_VAULT_ENABLED"] = "false"
_reset_provider_for_tests()
out = materialize_obj(T, "shield://api_key", "https://api.stripe.com")
check("Vault off", "flag off: pass-through", False, out == REAL, "placeholder unchanged when feature disabled")
os.environ["SECRET_VAULT_ENABLED"] = "true"
_reset_provider_for_tests()


# ── print matrix ─────────────────────────────────────────────────────────────
w1 = max(len(r[0]) for r in _rows); w2 = max(len(r[1]) for r in _rows)
print(f"{'USE CASE':<{w1}}  {'PATH':<{w2}}  {'RESULT':<6}  {'VERDICT':<7}  DETAIL")
print("-" * (w1 + w2 + 60))
for uc, path, res, verdict, detail in _rows:
    print(f"{uc:<{w1}}  {path:<{w2}}  {res:<6}  {verdict:<7}  {detail}")
fails = sum(1 for r in _rows if r[3] == "FAIL")
print("-" * (w1 + w2 + 60))
print(f"{len(_rows)} checks, {fails} failed")
raise SystemExit(1 if fails else 0)
