"""The "show me the code" panel behind the demo's Code button.

Every Python snippet here is pulled with `inspect.getsource` from the function
that actually runs. Nothing is copy-pasted, so the panel cannot drift from the
behaviour it claims to explain — which is the usual failure of a docs tab that
sits next to working software.

Blocks marked *config* are request bodies rather than code, and are labelled as
such so nobody goes looking for a Python file that does not exist.
"""
import inspect
import textwrap


def src(obj) -> str:
    """Live source for a function or method, dedented."""
    try:
        return textwrap.dedent(inspect.getsource(obj)).rstrip()
    except Exception as e:                                  # pragma: no cover
        return f"# source unavailable: {e}"


REGISTRY_ENTRY = '''POST /v1/agents/registry          # config, not code

{
  "agent_id": "sre-agent",
  "tools": ["read_logs", "restart_service", "rotate_credential"],
  "role_permissions": {
    "sre_lead": ["read_logs", "restart_service", "rotate_credential"],
    "oncall":   ["read_logs", "restart_service"],
    "intern":   ["read_logs"]
  }
}

# This matrix IS the enforcement. What you see on the Agent Registry page
# in the portal is what tool/check answers from.'''

DATA_SCOPES = '''# ABAC part 1 — which DATA, not just which tool.        config, not code
#
# rbac_guard maps the tool's ARGUMENTS to data scopes, then checks them
# against what the role is allowed to see. So "may an analyst call
# query_prod_db" and "may they read the pii columns" are separate answers.

"role_permissions": {"analyst": ["query_prod_db"]},
"role_data_scopes": {
  "analyst": {
    "allowed_data_scopes": ["orders"],
    "denied_data_scopes":  ["pii", "financial"]
  }
}

# This is why the tool's params travel with the check, not just its name.'''

RESOURCE_SCOPE = '''# ABAC part 2 — which OBJECT.                          config, not code
#
# fnmatch patterns on the agent entry. {user_sub} and {tenant_id} expand
# per request, so a capability is scoped to the caller's own objects
# rather than to the tool as a whole.

"allowed_resources": [
  "service/checkout-*",
  "secret/{tenant_id}/*"
],
"require_resource_scope": true

# Opt-in per agent: declaring allowed_resources turns enforcement on.
# SHIELD_REQUIRE_RESOURCE_SCOPE=true makes it deny-by-default fleet-wide.
# A capability minted for service/checkout-api does not authorize
# service/payments-svc — that binding is the point of minting per action.'''

CUSTOM_POLICY = '''POST /v1/tenant/me/policies/custom        # config, not code

{
  "name": "no card numbers",
  "description": "Block anything containing a customer card number",
  "prompt": "Block the request if it contains a payment card number, "
            "even partially redacted.",
  "action": "block",       # pass | warn | redact | block
  "stage": "input"         # input | output
}

# POST .../custom/validate first — a policy that stores but never fires
# is the worst outcome here.'''

POLICY_CAVEAT = '''# RBAC is deterministic. It reads a matrix.
#
# A custom policy is a natural-language rule scored by an LLM. It can
# reach a conclusion no configured rule states, in EITHER direction:
# it can miss something you meant to catch, and it can block something
# you meant to allow.
#
# Use RBAC for anything that must be certain. Treat custom policy as
# defence in depth on top of it, never as the control of record.'''

AUDIT_FIELDS = '''# Every decision records where its identity came from.

role_source     oidc | agent_token | mtls    proven — a signature Shield checked
                proxy                        vouched — a trusted hop asserted it
                header | body                claimed — the caller said so
                none                         refused or absent

role_verified   true only for the first row.

# A `proxy` role is deliberately NOT "verified". Any dashboard that
# treats it as such is wrong.'''


def sections(app_module) -> list:
    """Build the tour. `app_module` is the running demo, for live source."""
    from shield_client import ShieldClient, ShieldSession

    return [
        {
            "id": "integrate",
            "title": "1 · Wire it up",
            "why": "Three lines: a client per process, a decorator per tool, "
                   "a session per request.",
            "blocks": [
                {"label": "Create the client — once, at import",
                 "code": "from shield_client import ShieldClient\n\n"
                         "shield = ShieldClient.from_env()"},
                {"label": "Mark a tool — drop-in for LangChain's @tool",
                 "code": src(app_module.restart_service)},
                {"label": "Build the agent for ONE role, per request",
                 "code": src(app_module.run_agent)},
                {"label": "ShieldClient.from_env()",
                 "code": src(ClientRef(ShieldClient).from_env)},
            ],
        },
        {
            "id": "rbac",
            "title": "2 · RBAC — which role may call which tool",
            "why": "Deterministic. Reads role_permissions from the agent "
                   "registry.",
            "blocks": [
                {"label": "The check every tool makes before it runs",
                 "code": src(ShieldSession.check)},
                {"label": "The registry entry that decides the answer",
                 "code": REGISTRY_ENTRY},
            ],
        },
        {
            "id": "abac",
            "title": "3 · ABAC — which data, which object",
            "why": "RBAC answers 'may this role call this tool'. ABAC answers "
                   "'on which rows, and which specific resource'.",
            "blocks": [
                {"label": "Data scopes, from the tool's arguments",
                 "code": DATA_SCOPES},
                {"label": "Object-level scope, bound into the capability",
                 "code": RESOURCE_SCOPE},
                {"label": "Where the resource is chosen and the cap is burned",
                 "code": src(ShieldSession._capability)},
            ],
        },
        {
            "id": "policies",
            "title": "4 · Custom policies — rules in English",
            "why": "Natural-language rules per tenant. Flexible, and NOT "
                   "deterministic.",
            "blocks": [
                {"label": "Screening the prompt before the model sees it",
                 "code": src(ShieldSession.screen_input)},
                {"label": "Creating a policy",
                 "code": CUSTOM_POLICY},
                {"label": "The caveat worth knowing",
                 "code": POLICY_CAVEAT},
            ],
        },
        {
            "id": "governance",
            "title": "5 · Governance — proving what happened",
            "why": "Every step emits a record. The trace in this chat is that "
                   "same stream, live.",
            "blocks": [
                {"label": "What each step appends",
                 "code": src(ShieldSession._emit)},
                {"label": "Subscribing to it and streaming it out",
                 "code": src(app_module.stream_agent)},
                {"label": "What lands in the audit",
                 "code": AUDIT_FIELDS},
            ],
        },
    ]


class ClientRef:
    """Tiny shim so `from_env` resolves as a function for getsource.

    classmethod objects are not directly introspectable on some versions;
    going through the class attribute is.
    """

    def __init__(self, cls):
        self._cls = cls

    def __getattr__(self, name):
        return getattr(self._cls, name)
