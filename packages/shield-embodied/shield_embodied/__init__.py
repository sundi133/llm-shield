"""shield-embodied: guardrails for world and action models, decided on the robot.

Spec: docs/specs/embodied-action-guard.md. `evaluator.py` and `model.py` are
byte-identical to core/embodied/ in Shield, so the robot and the server decide
the same way (tests/test_embodied_sdk.py fails if they drift).
"""

from shield_embodied.guard import DEGRADED_DEFAULT, Decision, Guard  # noqa: F401
