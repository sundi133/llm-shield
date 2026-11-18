"""Product mode for the lab (rev 8 step R8): create this run's tenant, site key
and feed token in the lab Redis, the way a customer does in the portal.

Run by run_shop.sh with the REPO's Python and REDIS_URL pointing at the
lab-only Redis container. Writes, mode 600, under state/product/:
  site_key     the shop renders it in the tag line
  admin_key    a tenant admin key for this run (portal and enforcement API)
  feed_token   what feed_poll.sh sends as X-Shield-Feed-Token
All three are test values for this local lab and die with its Redis.
"""
import os
import secrets
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
STATE = Path(os.environ["LAB_STATE_DIR"]) / "product"
STATE.mkdir(parents=True, exist_ok=True)

from core.agent_detection import indicators, sitekeys  # noqa: E402
from storage import tenant_store as ts  # noqa: E402

TENANT = "lab-shop"
if ts._get_redis() is None:
    sys.exit("REDIS_URL is not reachable: product mode needs the lab Redis")


def write(name: str, value: str) -> None:
    p = STATE / name
    p.write_text(value)
    p.chmod(0o600)


admin_key = "sk-lab-" + secrets.token_hex(16)
if not ts.get_tenant(TENANT):
    ts.create_tenant(TENANT, {"name": "Acme Outfitters (lab)", "plan": "pro"})
ts.add_api_key(TENANT, admin_key, scope=ts.SCOPE_ADMIN)
write("admin_key", admin_key)
for rec in sitekeys.list_for(TENANT):
    sitekeys.delete(TENANT, rec["site_key"])
key = sitekeys.create(TENANT, origins=["http://localhost:8180", "http://127.0.0.1:8180",
                                       "http://host.docker.internal:8180"],
                      label="Lab shop", created_by="lab")["site_key"]
write("site_key", key)
for t in indicators.list_tokens(TENANT):
    indicators.delete_token(TENANT, t["id"])
write("feed_token", indicators.mint_token(TENANT, "lab edge")[1])
print(f"product mode: tenant {TENANT}, site key {key[:14]}...")
