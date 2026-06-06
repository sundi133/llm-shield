# Verified LangChain agent (Option C — two-pane)

Demonstrates a **verified agent**: identity is proven cryptographically, and
every sensitive tool call rides a single-use capability that a **separate tool
server** verifies before touching the real credential.

```
 LangChain agent            Shield service              Tool server
 (agent.py)                 (SHIELD_URL)                (tool_server.py)
 ──────────────             ──────────────              ────────────────
 Phase 0  mint_agent_token ─────►  verify tenant key, sign Ed25519 JWT
          ◄───────────────────────  agent_token (verified identity)

 Phase 1  mint_cap(send_email, ──►  run RBAC/policy; 403 if denied
          resource=bob@acme.com)
          ◄───────────────────────  cap_token (30s, single-use, bound)

 Phase 2  POST /tools/send_email ───────────────────────►  verify_cap()
          {..., cap_token}                                  (sig/exp/tool/
                                                             resource/nonce)
          ◄───────────────────────────────────────────────  sent ✓ / 403
```

Key property: **the agent never holds the SMTP credential.** Its only path to
sending email is a cap that the tool server independently verifies. "Ignore the
mint and send anyway" is impossible — there is nothing to send with.

## Run

```bash
export SHIELD_URL=https://shield.your-company.com
export SHIELD_TENANT_KEY=sk-tenant-...

# terminal 1 — the tool server (holds the real credential)
uvicorn tool_server:app --port 9100

# terminal 2 — the agent
export TOOL_SERVER_URL=http://localhost:9100
export USER_SUB=alice@acme.com
export USER_ROLE=invoicing
python agent.py
```

If `alice@acme.com`'s role isn't permitted `send_email`, `mint_cap` raises
`403` in Phase 1 and the agent never receives a cap to present.
