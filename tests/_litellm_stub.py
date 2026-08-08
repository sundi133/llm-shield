"""Import `votal_guardrail` without installing LiteLLM.

The guardrail plugin ships with the LiteLLM proxy, not with Shield, so
`litellm` is deliberately not in requirements-test.txt. The consequence was
that every test of the plugin was `importorskip`-ed and therefore never ran in
CI — the plugin is the entire identity surface for the "Shield behind LiteLLM"
topology, and none of it was covered.

The plugin touches three things from litellm, all of them trivial: a base class
it subclasses, a type it annotates with, and a cache type it never calls. Stub
them and the plugin's own logic becomes testable in CI without pulling in a
large dependency Shield does not otherwise use.

If litellm IS installed, this is a no-op and the real classes are used.
"""
import sys
import types


def install() -> None:
    """Install minimal litellm stubs into sys.modules if litellm is absent."""
    try:  # pragma: no cover - depends on the local environment
        import litellm  # noqa: F401
        return
    except Exception:
        pass

    litellm_mod = types.ModuleType("litellm")
    litellm_mod.__path__ = []  # mark as a package so submodules can be added

    integrations = types.ModuleType("litellm.integrations")
    integrations.__path__ = []
    custom_guardrail = types.ModuleType("litellm.integrations.custom_guardrail")

    class CustomGuardrail:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    custom_guardrail.CustomGuardrail = CustomGuardrail

    proxy = types.ModuleType("litellm.proxy")
    proxy.__path__ = []
    proxy_types = types.ModuleType("litellm.proxy._types")

    class UserAPIKeyAuth:
        """Stand-in for LiteLLM's authenticated-key object."""

        def __init__(self, metadata=None, user_role=None, **kw):
            self.metadata = metadata or {}
            self.user_role = user_role
            for k, v in kw.items():
                setattr(self, k, v)

    proxy_types.UserAPIKeyAuth = UserAPIKeyAuth

    caching_pkg = types.ModuleType("litellm.caching")
    caching_pkg.__path__ = []
    caching_mod = types.ModuleType("litellm.caching.caching")

    class DualCache:
        pass

    caching_mod.DualCache = DualCache

    for name, mod in (
        ("litellm", litellm_mod),
        ("litellm.integrations", integrations),
        ("litellm.integrations.custom_guardrail", custom_guardrail),
        ("litellm.proxy", proxy),
        ("litellm.proxy._types", proxy_types),
        ("litellm.caching", caching_pkg),
        ("litellm.caching.caching", caching_mod),
    ):
        sys.modules.setdefault(name, mod)
