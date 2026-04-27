# Identity Provider (IdP) Integration with LLM Shield RBAC

Connect your organization's Identity Provider to Shield so that user roles come from **verified JWT tokens** instead of self-declared `X-User-Role` headers.

## Why This Matters

Without IdP integration, any caller can set `X-User-Role: doctor` and gain full access. With IdP integration, your proxy/middleware validates the JWT issued by your IdP and extracts the verified role before forwarding to Shield.

```
Current (header-based):
  Client  ──X-User-Role: doctor──▶  Shield   (self-declared, unverified)

With IdP (JWT-based):
  Client  ──▶  IdP (login)  ──▶  JWT with role claims
  Client  ──▶  Your Proxy   ──▶  validates JWT, extracts role
  Proxy   ──X-User-Role: doctor──▶  Shield   (verified by IdP)
```

## Architecture

```
┌──────────┐     ┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│  Client  │────▶│  Identity    │────▶│  Your API       │────▶│  LLM Shield  │
│  (App)   │     │  Provider    │     │  Gateway/Proxy  │     │  RBAC        │
└──────────┘     └──────────────┘     └─────────────────┘     └──────────────┘
      │                 │                      │                      │
      │  1. Login       │                      │                      │
      │────────────────▶│                      │                      │
      │  2. JWT token   │                      │                      │
      │◀────────────────│                      │                      │
      │                                        │                      │
      │  3. API call with Authorization:       │                      │
      │     Bearer <JWT>                       │                      │
      │───────────────────────────────────────▶│                      │
      │                                        │                      │
      │         4. Validate JWT signature      │                      │
      │            Extract role from claims    │                      │
      │                                        │                      │
      │         5. Forward to Shield with      │                      │
      │            X-User-Role: <verified>     │                      │
      │            X-Agent-Key: <agent-id>     │                      │
      │                                        │─────────────────────▶│
      │                                        │                      │
      │         6. RBAC enforced               │  tool allowed/blocked│
      │◀───────────────────────────────────────│◀─────────────────────│
```

**Key point**: Shield does not validate the JWT itself. Your API gateway or middleware does that and passes the verified role to Shield via `X-User-Role`. This keeps Shield stateless and IdP-agnostic.

## Provider Setup

### Okta

**1. Create an Authorization Server**

- Go to **Security → API → Authorization Servers** in Okta Admin
- Note your **Issuer URI**: `https://your-domain.okta.com/oauth2/default`

**2. Add Groups Claim to Tokens**

- Go to your Authorization Server → **Claims** tab
- Add a claim:
  - Name: `groups`
  - Include in: `Access Token`
  - Value type: `Groups`
  - Filter: Matches regex `.*` (or specific groups)

**3. Create Groups for Shield Roles**

| Okta Group | Shield Role |
|---|---|
| `ShieldDoctors` | `doctor` |
| `ShieldNurses` | `nurse` |
| `ShieldAdmins` | `admin` |
| `ShieldPatients` | `patient` |

**4. JWT Claims Structure**

```json
{
  "iss": "https://your-domain.okta.com/oauth2/default",
  "sub": "user@example.com",
  "aud": "api://shield",
  "groups": ["ShieldDoctors", "ShieldAdmins"],
  "exp": 1700000000
}
```

**5. Extract Role in Your Proxy**

```python
import jwt
import requests

OKTA_ISSUER = "https://your-domain.okta.com/oauth2/default"
JWKS_URL = f"{OKTA_ISSUER}/v1/keys"

ROLE_MAPPING = {
    "ShieldDoctors": "doctor",
    "ShieldNurses": "nurse",
    "ShieldAdmins": "admin",
    "ShieldPatients": "patient",
}

def get_shield_role_from_okta_jwt(token: str) -> str:
    jwks_client = jwt.PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience="api://shield",
        issuer=OKTA_ISSUER,
    )
    groups = claims.get("groups", [])
    for group in groups:
        if group in ROLE_MAPPING:
            return ROLE_MAPPING[group]
    return "patient"  # default role
```

**6. Call Shield with Verified Role**

```bash
# Step 1: Get token from Okta (client_credentials flow)
TOKEN=$(curl -s -X POST \
  https://your-domain.okta.com/oauth2/default/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&scope=openid groups" \
  | jq -r '.access_token')

# Step 2: Your proxy validates the JWT and extracts the role,
#          then forwards to Shield:
curl -X POST http://localhost:8080/v1/shield/chat/agent \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Agent-Key: healthcare-doctor" \
  -H "X-User-Role: doctor" \
  -d '{
    "llm_api_key": "'"$OPENAI_API_KEY"'",
    "messages": [{"role": "user", "content": "Look up patient John Smith"}]
  }' | jq '.tool_results[] | {tool_name, allowed: .rbac.allowed}'
```

---

### Auth0

**1. Create an API**

- Go to **Applications → APIs** in Auth0 Dashboard
- Create API with identifier: `https://shield.your-domain.com`

**2. Add Roles via Actions**

Auth0 doesn't include roles in tokens by default. Add a **Login Action**:

- Go to **Actions → Flows → Login**
- Add a custom action:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://shield.your-domain.com';
  const roles = event.authorization?.roles || [];
  api.accessToken.setCustomClaim(`${namespace}/roles`, roles);
};
```

**3. Create Roles**

- Go to **User Management → Roles**
- Create roles: `doctor`, `nurse`, `admin`, `patient`
- Assign roles to users

**4. JWT Claims Structure**

```json
{
  "iss": "https://your-domain.auth0.com/",
  "sub": "auth0|user-id",
  "aud": "https://shield.your-domain.com",
  "https://shield.your-domain.com/roles": ["doctor"],
  "exp": 1700000000
}
```

**5. Extract Role in Your Proxy**

```python
import jwt

AUTH0_DOMAIN = "your-domain.auth0.com"
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
API_AUDIENCE = "https://shield.your-domain.com"
NAMESPACE = "https://shield.your-domain.com"

def get_shield_role_from_auth0_jwt(token: str) -> str:
    jwks_client = jwt.PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=API_AUDIENCE,
        issuer=f"https://{AUTH0_DOMAIN}/",
    )
    roles = claims.get(f"{NAMESPACE}/roles", [])
    return roles[0] if roles else "patient"
```

**6. Call Shield**

```bash
# Step 1: Get token from Auth0
TOKEN=$(curl -s -X POST \
  https://your-domain.auth0.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "CLIENT_ID",
    "client_secret": "CLIENT_SECRET",
    "audience": "https://shield.your-domain.com",
    "grant_type": "client_credentials"
  }' | jq -r '.access_token')

# Step 2: Your proxy validates and extracts role, then forwards:
curl -X POST http://localhost:8080/v1/shield/chat/agent \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Agent-Key: healthcare-doctor" \
  -H "X-User-Role: doctor" \
  -d '{
    "llm_api_key": "'"$OPENAI_API_KEY"'",
    "messages": [{"role": "user", "content": "Look up patient John Smith"}]
  }' | jq '.tool_results[] | {tool_name, allowed: .rbac.allowed}'
```

---

### Azure AD (Entra ID)

**1. Register an Application**

- Go to **Azure Portal → App registrations → New registration**
- Set redirect URI as needed
- Note the **Application (client) ID** and **Directory (tenant) ID**

**2. Define App Roles**

- Go to your App Registration → **App roles**
- Create roles:

| Display Name | Value | Allowed Member Types |
|---|---|---|
| Doctor | `doctor` | Users/Groups |
| Nurse | `nurse` | Users/Groups |
| Admin | `admin` | Users/Groups |
| Patient | `patient` | Users/Groups |

**3. Assign Users to Roles**

- Go to **Enterprise Applications → your app → Users and groups**
- Assign users/groups to the app roles

**4. JWT Claims Structure**

```json
{
  "iss": "https://login.microsoftonline.com/TENANT_ID/v2.0",
  "sub": "user-object-id",
  "aud": "CLIENT_ID",
  "roles": ["doctor"],
  "preferred_username": "user@example.com",
  "exp": 1700000000
}
```

**5. Extract Role in Your Proxy**

```python
import jwt

TENANT_ID = "your-tenant-id"
CLIENT_ID = "your-client-id"
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"

def get_shield_role_from_azure_jwt(token: str) -> str:
    jwks_client = jwt.PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=ISSUER,
    )
    roles = claims.get("roles", [])
    return roles[0] if roles else "patient"
```

**6. Call Shield**

```bash
# Step 1: Get token from Azure AD
TOKEN=$(curl -s -X POST \
  "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=$CLIENT_ID/.default" \
  | jq -r '.access_token')

# Step 2: Your proxy validates and extracts role, then forwards:
curl -X POST http://localhost:8080/v1/shield/chat/agent \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Agent-Key: healthcare-doctor" \
  -H "X-User-Role: doctor" \
  -d '{
    "llm_api_key": "'"$OPENAI_API_KEY"'",
    "messages": [{"role": "user", "content": "Look up patient John Smith"}]
  }' | jq '.tool_results[] | {tool_name, allowed: .rbac.allowed}'
```

---

### Keycloak

**1. Create a Realm and Client**

- Create a realm (e.g. `shield`)
- Create a client:
  - Client ID: `shield-api`
  - Access Type: `confidential`
  - Enable **Service Accounts Enabled** for machine-to-machine

**2. Create Realm Roles**

- Go to **Realm Roles** → Add roles:
  - `doctor`, `nurse`, `admin`, `patient`

**3. Assign Roles to Users**

- Go to **Users → select user → Role Mappings**
- Assign the appropriate realm role

**4. JWT Claims Structure**

Keycloak includes realm roles by default:

```json
{
  "iss": "https://keycloak.your-domain.com/realms/shield",
  "sub": "user-uuid",
  "aud": "shield-api",
  "realm_access": {
    "roles": ["doctor", "default-roles-shield"]
  },
  "preferred_username": "dr.smith",
  "exp": 1700000000
}
```

**5. Extract Role in Your Proxy**

```python
import jwt

KEYCLOAK_HOST = "https://keycloak.your-domain.com"
REALM = "shield"
JWKS_URL = f"{KEYCLOAK_HOST}/realms/{REALM}/protocol/openid-connect/certs"
ISSUER = f"{KEYCLOAK_HOST}/realms/{REALM}"

SHIELD_ROLES = {"doctor", "nurse", "admin", "patient"}

def get_shield_role_from_keycloak_jwt(token: str) -> str:
    jwks_client = jwt.PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience="shield-api",
        issuer=ISSUER,
    )
    realm_roles = claims.get("realm_access", {}).get("roles", [])
    for role in realm_roles:
        if role in SHIELD_ROLES:
            return role
    return "patient"
```

**6. Call Shield**

```bash
# Step 1: Get token from Keycloak
TOKEN=$(curl -s -X POST \
  "https://keycloak.your-domain.com/realms/shield/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=shield-api&client_secret=CLIENT_SECRET" \
  | jq -r '.access_token')

# Step 2: Your proxy validates and extracts role, then forwards:
curl -X POST http://localhost:8080/v1/shield/chat/agent \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Agent-Key: healthcare-doctor" \
  -H "X-User-Role: doctor" \
  -d '{
    "llm_api_key": "'"$OPENAI_API_KEY"'",
    "messages": [{"role": "user", "content": "Look up patient John Smith"}]
  }' | jq '.tool_results[] | {tool_name, allowed: .rbac.allowed}'
```

---

### Generic OIDC Provider

Any OIDC-compliant provider works. You need:

| Parameter | Where to Find |
|---|---|
| JWKS URL | `{issuer}/.well-known/openid-configuration` → `jwks_uri` |
| Issuer | The `iss` claim in your provider's tokens |
| Audience | The `aud` your provider issues tokens for |
| Role Claim | Provider-specific (check your token payload at [jwt.io](https://jwt.io)) |

```python
import jwt

def get_shield_role_from_oidc_jwt(
    token: str,
    jwks_url: str,
    issuer: str,
    audience: str,
    role_claim: str = "roles",
    role_mapping: dict = None,
) -> str:
    jwks_client = jwt.PyJWKClient(jwks_url)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
    )

    # Navigate nested claims (e.g. "realm_access.roles")
    value = claims
    for key in role_claim.split("."):
        value = value.get(key, {}) if isinstance(value, dict) else value

    roles = value if isinstance(value, list) else [value] if value else []

    if role_mapping:
        for role in roles:
            if role in role_mapping:
                return role_mapping[role]

    return roles[0] if roles else "patient"
```

---

## Integration Patterns

### Pattern 1: API Gateway (Recommended for Production)

Use your existing API gateway (Kong, AWS API Gateway, Nginx + lua, Envoy) to validate JWTs and inject `X-User-Role`:

```
Client → API Gateway → validates JWT → adds X-User-Role header → Shield
```

**Kong example** (JWT plugin):

```yaml
plugins:
  - name: jwt
    config:
      claims_to_verify: [exp]
  - name: request-transformer
    config:
      add:
        headers:
          - "X-User-Role:$(jwt.roles[0])"
```

**Nginx example** (with auth_jwt module):

```nginx
location /v1/shield/ {
    auth_jwt "Shield API";
    auth_jwt_key_file /etc/nginx/jwks.json;

    proxy_set_header X-User-Role $jwt_claim_roles;
    proxy_set_header X-Agent-Key $http_x_agent_key;
    proxy_pass http://shield-backend:8080;
}
```

### Pattern 2: Sidecar / Middleware (Python Apps)

Add JWT validation in your application before calling Shield:

```python
import requests

def call_shield_with_idp(user_jwt: str, message: str, agent_key: str):
    # 1. Validate JWT and extract role (use provider-specific function above)
    role = get_shield_role_from_okta_jwt(user_jwt)

    # 2. Call Shield with verified role
    response = requests.post(
        f"{SHIELD_URL}/v1/shield/chat/agent",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
            "X-Agent-Key": agent_key,
            "X-User-Role": role,  # verified from JWT
        },
        json={
            "llm_api_key": OPENAI_API_KEY,
            "messages": [{"role": "user", "content": message}],
        },
    )
    return response.json()
```

### Pattern 3: Agent-to-Agent with IdP

When one agent calls another agent's tools, pass both the verified user role and the calling agent identity:

```python
def agent_to_agent_call(user_jwt: str, message: str):
    role = get_shield_role_from_okta_jwt(user_jwt)

    response = requests.post(
        f"{SHIELD_URL}/v1/shield/chat/agent",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
            "X-Agent-Key": "healthcare-doctor",       # target agent
            "X-User-Role": role,                      # verified from JWT
            "X-Calling-Agent": "healthcare-triage",   # calling agent
        },
        json={
            "llm_api_key": OPENAI_API_KEY,
            "messages": [{"role": "user", "content": message}],
        },
    )
    result = response.json()
    # RBAC now enforces 3 dimensions:
    #   1. agent_ok   — tool is in target agent's tool list
    #   2. role_ok    — user's verified role has access
    #   3. caller_ok  — calling agent has permission on target
    return result
```

---

## Role Mapping Reference

Each IdP uses different names for groups/roles. Map them to Shield's role names:

```
IdP Group/Role Name     →     Shield Role
─────────────────────────────────────────
Okta:
  ShieldDoctors         →     doctor
  ShieldNurses          →     nurse
  ShieldAdmins          →     admin

Auth0:
  doctor                →     doctor        (direct match)
  MedicalStaff          →     nurse

Azure AD:
  app-role-doctor       →     doctor
  app-role-nurse        →     nurse

Keycloak:
  doctor                →     doctor        (direct match)
  nurse                 →     nurse         (direct match)
```

The mapping is done in your proxy/middleware code (see provider-specific examples above). Shield only sees the final role string.

---

## Testing Your Integration

### Verify JWT contents

Decode your token at [jwt.io](https://jwt.io) or via CLI:

```bash
# Decode JWT payload (no verification, just inspect)
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

Check that the role claim is present and contains the expected value.

### Test with Shield

```bash
# 1. Self-declared role (current behavior, no IdP)
curl -X POST http://localhost:8080/v1/shield/chat/agent \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Agent-Key: healthcare-doctor" \
  -H "X-User-Role: doctor" \
  -d '{
    "llm_api_key": "'"$OPENAI_API_KEY"'",
    "messages": [{"role": "user", "content": "Look up patient records"}]
  }' | jq '.tool_results[] | {tool_name, allowed: .rbac.allowed}'

# Expected: patient_lookup → allowed: true

# 2. Wrong role (should be blocked)
curl -X POST http://localhost:8080/v1/shield/chat/agent \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Agent-Key: healthcare-doctor" \
  -H "X-User-Role: patient" \
  -d '{
    "llm_api_key": "'"$OPENAI_API_KEY"'",
    "messages": [{"role": "user", "content": "Prescribe medication"}]
  }' | jq '.tool_results[] | {tool_name, allowed: .rbac.allowed}'

# Expected: prescribe_medication → allowed: false
```

### End-to-End Test with Proxy

```bash
# 1. Get token from your IdP (example: Okta)
TOKEN=$(curl -s -X POST \
  https://your-domain.okta.com/oauth2/default/v1/token \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=openid groups" \
  | jq -r '.access_token')

# 2. Call your proxy (which validates JWT and forwards to Shield)
curl -X POST https://your-proxy.example.com/v1/shield/chat/agent \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Agent-Key: healthcare-doctor" \
  -d '{
    "llm_api_key": "'"$OPENAI_API_KEY"'",
    "messages": [{"role": "user", "content": "Look up patient John Smith"}]
  }' | jq .
```

---

## Dependencies (Proxy/Middleware Only)

These are needed in **your proxy/middleware**, not in Shield itself:

```
PyJWT>=2.8.0
cryptography>=41.0.0
requests>=2.31.0
```

Install:

```bash
pip install PyJWT cryptography requests
```

---

## Security Considerations

- **Always validate JWT signatures** using the IdP's JWKS endpoint. Never trust unverified tokens.
- **Cache JWKS keys** with a TTL (1 hour is typical). PyJWT's `PyJWKClient` handles this automatically.
- **Verify issuer and audience** to prevent token misuse across applications.
- **Check token expiry** (`exp` claim). PyJWT does this by default.
- **Use HTTPS** for all IdP communication and JWKS fetching.
- **Map roles explicitly** rather than passing IdP group names directly. This prevents privilege escalation if IdP group names change.
- **Log role source** in your proxy so you can audit whether a role came from JWT or fallback header.

---

## Roadmap

Built-in JWT validation directly in Shield middleware is planned for a future release. This will allow Shield to validate JWTs natively without requiring an external proxy, with per-tenant IdP configuration stored in Redis.
