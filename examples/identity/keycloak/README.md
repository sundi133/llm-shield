# Keycloak for the Shield identity demo

A Keycloak with the `bank` realm baked in: five banking roles, one demo user per
role, and an audience mapper so issued tokens carry `aud: votal-shield`. The
realm is imported at boot, so it is version controlled rather than clicked into
an admin console, and a wiped database rebuilds identically.

This exists to answer one question on stage: **where did the role come from?**
Today Shield reads it from an `X-User-Role` header that anyone can set. With a
token, the role comes from a claim signed by an issuer Shield trusts.

## What is in the realm

| user | password | realm role |
| --- | --- | --- |
| `alice` | `demo-only-change-me` | `customer_support` |
| `omar` | `demo-only-change-me` | `payments_officer` |
| `rashid` | `demo-only-change-me` | `fraud_analyst` |
| `fatima` | `demo-only-change-me` | `compliance_officer` |
| `layla` | `demo-only-change-me` | `branch_manager` |

The role names match `role_permissions` on the `customer-service-agent` in the
Shield agent registry, so a token's role maps straight onto the tool matrix.

Client `demo-cli` is public with direct access grants enabled, so a password
grant works from curl. That is a demo affordance, not a production pattern.

## Run it locally

```bash
docker run -d --name keycloak -p 8085:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -v "$PWD/realm-bank.json:/opt/keycloak/data/import/realm-bank.json:ro" quay.io/keycloak/keycloak:26.0 start-dev --import-realm
```

Ready in about 30 seconds. Confirm the realm exists:

```bash
curl -s http://localhost:8085/realms/bank/.well-known/openid-configuration | python3 -m json.tool | head -20
```

Then confirm a token actually carries the role — this is the step worth running
before every demo, because a realm that imports is not the same as a token that
carries the claim:

```bash
curl -s -X POST "http://localhost:8085/realms/bank/protocol/openid-connect/token" -d grant_type=password -d client_id=demo-cli -d username=omar -d password=demo-only-change-me | python3 -c "import json,sys,base64; t=json.load(sys.stdin)['access_token']; p=t.split('.')[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p+'==')), indent=2))"
```

Verified output for `omar`: `iss` ends in `/realms/bank`, `aud` is
`votal-shield`, `realm_access.roles` contains `payments_officer`, and the token
lives 300 seconds.

## Deploy on Railway

1. **New → Database → Postgres** first. Keycloak in production mode will not
   start without one, and adding it later means a failed first deploy.
2. **New → Empty Service**, Settings → Source → **Root Directory** =
   `examples/identity/keycloak`. The Dockerfile here builds against Postgres so
   the container starts fast.
3. Variables:

   | Variable | Value |
   | --- | --- |
   | `KC_DB_URL` | `jdbc:postgresql://${{Postgres.PGHOST}}:${{Postgres.PGPORT}}/${{Postgres.PGDATABASE}}` |
   | `KC_DB_USERNAME` | `${{Postgres.PGUSER}}` |
   | `KC_DB_PASSWORD` | `${{Postgres.PGPASSWORD}}` |
   | `KC_BOOTSTRAP_ADMIN_USERNAME` | `admin` |
   | `KC_BOOTSTRAP_ADMIN_PASSWORD` | a real password |
   | `KC_HOSTNAME` | your Railway domain, after step 4 |

4. Settings → Networking → **Generate Domain**, target port **8080**. Keycloak
   does not read Railway's `$PORT`; that mismatch is the most common failure
   here, and it presents as a healthy build that never serves traffic.
5. Verify with the two curls above against the public domain.

**It must be publicly reachable.** Shield verifies the token and Shield runs
outside your Railway project, so it fetches JWKS over the internet. Railway's
private network is not enough.

On Keycloak 25 and earlier the admin variables are `KEYCLOAK_ADMIN` and
`KEYCLOAK_ADMIN_PASSWORD`. If the logs say no admin user exists, that is the
version difference. The image tag is pinned for this reason — `latest` renames
environment variables across majors and will break a working demo on a redeploy
you did not ask for.

## Wiring it into Shield

Set the tenant's `allowed_issuers` to `https://<domain>/realms/bank` and
`role_claim` to `realm_access.roles`.

**Nothing consumes that configuration yet.** It needs the verified role binding
described in [docs/spec-agent-role-binding.md](../../../docs/spec-agent-role-binding.md),
which is specced and not implemented. Until then this Keycloak issues correct
tokens that Shield does not yet read.

## Security

The passwords in `realm-bank.json` are demo credentials committed on purpose so
the realm is reproducible. They are not secrets and must not be reused.

A Keycloak on a public Railway domain is a real, internet-reachable identity
provider. Give the bootstrap admin a strong password, do not point it at
anything that matters, and delete the service when the talk is over.
