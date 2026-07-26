#!/usr/bin/env python3
"""Secret Vault round-trip: the raw key never reaches the model, only egress.

Demonstrates, using Shield's real vault code, that:
  1. the model only ever sees an inert placeholder (shield://<name>)
  2. the real value is materialized ONLY on the wire to the bound destination
  3. any other destination gets the placeholder unchanged (anti-exfiltration)
  4. a tool output that echoes the secret is retokenized before it returns

Run:
    SECRET_VAULT_ENABLED=true \
    SECRET_VAULT_KEK="a-32-byte-key-or-passphrase" \
      python examples/vault/egress_demo.py

In production the KEK comes from a mounted Secret (env/file), never inline; and
secrets are registered via POST /v1/tenant/me/vault, not this script.
"""
import os
import sys

# Repo root on sys.path so `core` / `storage` import when run directly.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.secret_vault.materialize import materialize_obj, retokenize, vault_enabled
from storage.vault_store import create_vault_entry

TENANT = "acme"
REAL = "sk_live_51ABCDEF_super_secret_key"          # pretend this is a live API key
G, R, Z = "\033[32m", "\033[31m", "\033[0m"


def check(label, condition_true_is_good, detail=""):
    mark = f"{G}OK{Z}" if condition_true_is_good else f"{R}LEAK{Z}"
    print(f"  [{mark}] {label}{('  ' + detail) if detail else ''}")


def main():
    if not vault_enabled():
        sys.exit("Set SECRET_VAULT_ENABLED=true and SECRET_VAULT_KEK=... first "
                 "(see the module docstring).")

    # Register the secret, bound to exactly one destination.
    pub = create_vault_entry(TENANT, name="stripe_key", value=REAL,
                             bindings=["api.stripe.com"])
    placeholder = f"shield://{pub['ref']}"
    print(f"\nRegistered secret -> placeholder the agent/LLM uses: {G}{placeholder}{Z}")
    print(f"(bindings={pub['bindings']}, token={pub['token']})\n")

    # What the LLM produces for a tool call — only the placeholder.
    headers = {"Authorization": f"Bearer {placeholder}", "Content-Type": "application/json"}
    print("1. Model-facing tool call (what the LLM sees / produced):")
    check("raw key absent from the model's view", REAL not in str(headers),
          headers["Authorization"])

    # 2. Egress to the BOUND host — materialized on the wire, downstream of the model.
    out = materialize_obj(TENANT, dict(headers), destination="https://api.stripe.com/v1/charges")
    print("\n2. Egress -> api.stripe.com (bound destination):")
    check("real key materialized only here", REAL in str(out), out["Authorization"])

    # 3. Egress to ANY other host — placeholder stays inert.
    evil = materialize_obj(TENANT, dict(headers), destination="https://evil.example.com/collect")
    print("\n3. Egress -> evil.example.com (NOT bound):")
    check("real key NOT released to the wrong destination", REAL not in str(evil),
          evil["Authorization"])

    # 4. Tool output echoing the secret — retokenized before returning to the model.
    back = retokenize(TENANT, {"message": f"charged ok using {REAL}"})
    print("\n4. Tool output returned to the model (retokenized):")
    check("real key never reaches the model", REAL not in str(back), back["message"])

    print(f"\n{G}The raw key existed only on the wire to api.stripe.com — never in the "
          f"model context, never to another host.{Z}\n")


if __name__ == "__main__":
    main()
