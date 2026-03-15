import importlib
import inspect
import pkgutil
from typing import Optional

from guardrails.base import BaseGuardrail

_registry: dict[str, BaseGuardrail] = {}
_discovered = False


def _discover_guardrails():
    """Scan guardrails.input, guardrails.output, and guardrails.agentic for BaseGuardrail subclasses."""
    global _discovered
    if _discovered:
        return

    package_names = [
        "guardrails.input",
        "guardrails.output",
        "guardrails.agentic",
    ]

    for package_name in package_names:
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            continue

        package_path = getattr(package, "__path__", None)
        if package_path is None:
            continue

        for _importer, module_name, _is_pkg in pkgutil.walk_packages(
            package_path, prefix=f"{package_name}."
        ):
            try:
                module = importlib.import_module(module_name)
            except ImportError:
                continue

            for _attr_name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BaseGuardrail)
                    and obj is not BaseGuardrail
                    and not inspect.isabstract(obj)
                ):
                    instance = obj()
                    _registry[instance.name] = instance

    _discovered = True


def get_guardrail(name: str) -> Optional[BaseGuardrail]:
    """Get a guardrail instance by name."""
    _discover_guardrails()
    return _registry.get(name)


def list_guardrails() -> list[BaseGuardrail]:
    """Return all discovered guardrail instances."""
    _discover_guardrails()
    return list(_registry.values())


def get_by_tier(tier: str) -> list[BaseGuardrail]:
    """Return guardrails filtered by tier ('fast' or 'slow')."""
    _discover_guardrails()
    return [g for g in _registry.values() if g.tier == tier]


def get_by_stage(stage: str) -> list[BaseGuardrail]:
    """Return guardrails filtered by stage ('input' or 'output')."""
    _discover_guardrails()
    return [g for g in _registry.values() if g.stage == stage]


def get_grouped() -> dict[str, dict[str, list[BaseGuardrail]]]:
    """Return guardrails grouped by tier and stage.

    Returns:
        {
            "fast": {"input": [...], "output": [...]},
            "slow": {"input": [...], "output": [...]},
        }
    """
    _discover_guardrails()
    grouped: dict[str, dict[str, list[BaseGuardrail]]] = {
        "fast": {"input": [], "output": [], "agentic": []},
        "slow": {"input": [], "output": [], "agentic": []},
    }
    for guardrail in _registry.values():
        tier = guardrail.tier if guardrail.tier in grouped else "fast"
        stage = guardrail.stage if guardrail.stage in grouped[tier] else "input"
        grouped[tier][stage].append(guardrail)
    return grouped
