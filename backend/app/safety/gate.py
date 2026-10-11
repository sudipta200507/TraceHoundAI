"""TraceHoundAI safety gate interface (Phase 2).

Future recon stages MUST call authorize_tool_execution() before executing
any external security tool:

    validate_target(...)      -> scope allow-list (deterministic)
    check_execution_policy(...) -> passive/active/exploitation policy
    execute_tool(...)           -> only when both checks pass

The LLM must NEVER call tools directly and must NEVER bypass this gate.
No reconnaissance is implemented here.
"""

from __future__ import annotations

from typing import Optional

from backend.app.safety.exceptions import ExecutionPolicyError, ScopeViolationError
from backend.app.safety.execution_policy import check_execution_policy
from backend.app.safety.scope_validator import (
    ScopeConfig,
    ScopeDecision,
    ScopePolicy,
    load_scope_config,
    validate_target,
)


def authorize_tool_execution(
    target: str,
    operation: str = "passive",
    config: Optional[ScopeConfig] = None,
    policy: Optional[ScopePolicy] = None,
) -> ScopeDecision:
    """Single entry point for all future tool execution.

    Raises ScopeViolationError when the target is out of scope or malformed.
    Raises ExecutionPolicyError when the operation class is not permitted.
    Returns the ScopeDecision when both checks pass.
    """
    cfg = config or load_scope_config()
    pol = policy or cfg.policy

    decision = validate_target(target, cfg)
    if not decision.allowed:
        raise ScopeViolationError(decision.reason)

    policy_decision = check_execution_policy(operation, pol)
    if not policy_decision.allowed:
        raise ExecutionPolicyError(policy_decision.reason)

    return decision
