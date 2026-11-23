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

from core.agent_detection import decoys, indicators, sitekeys  # noqa: E402
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
                      decoys=True, label="Lab shop", created_by="lab")["site_key"]
write("site_key", key)

# Decoys (rev 9): on, in the shop's own key format, and the PRODUCT's edge rules
# for the lab Nginx (which runs in Docker, so the collector is host.docker.internal).
# The lab edge passes the agent's simulated address, as it does for /_shs/.
decoys.save(TENANT, {"enabled": True, "key_prefix": "acme_pk_"})
plan = decoys.plan(TENANT)
rules = decoys.edge_nginx(plan, key, "http://host.docker.internal:8201")
rules = rules.replace("$proxy_add_x_forwarded_for", "$client_ip")
rules += f'location = /robots.txt {{ default_type text/plain; return 200 "User-agent: *\\n{decoys.robots_line(plan)}\\n"; }}\n'
(Path(os.environ["LAB_STATE_DIR"]) / "shield" / "decoys.conf").write_text(rules)
print("product decoys: " + " ".join(decoys.paths(plan)))
for t in indicators.list_tokens(TENANT):
    indicators.delete_token(TENANT, t["id"])
write("feed_token", indicators.mint_token(TENANT, "lab edge")[1])
print(f"product mode: tenant {TENANT}, site key {key[:14]}...")
