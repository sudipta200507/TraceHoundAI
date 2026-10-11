"""TraceHoundAI execution policy (Phase 2).

Distinguishes OBSERVATION/PASSIVE from ACTIVE reconnaissance from
EXPLOITATION. Defaults are deny-by-default for anything active:

  dry_run = True
  allow_active_scanning = False
  allow_exploitation = False

No exploitation functionality is implemented in this project.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

from backend.app.safety.exceptions import ExecutionPolicyError
from backend.app.safety.scope_validator import ScopePolicy, load_scope_config

OperationType = Literal[
    "passive", "observation", "passive_discovery", "dns_resolution",
    "http_discovery", "active", "active_port_scan", "port_discovery",
    "vulnerability_verification", "nuclei_verification", "exploitation"
]


class PolicyDecision(BaseModel):
    allowed: bool
    reason: str
    operation: str
    dry_run: bool = True


def _canonical_operation(operation: str) -> str:
    op = (operation or "").strip().lower()
    if op in ("passive", "observation", "observe", "passive_discovery", "passive-discovery", "discovery",
              "dns_resolution", "dns-resolution", "dns", "http_discovery", "http-discovery", "http"):
        return "passive"
    if op in ("active", "scan", "recon", "active_port_scan", "active-port-scan",
              "port_scan", "port-scan", "port_discovery", "port-discovery",
              "vulnerability_verification", "vulnerability-verification",
              "nuclei_verification", "nuclei-verification", "nuclei"):
        return "active"
    if op in ("exploitation", "exploit"):
        return "exploitation"
    return op


def check_execution_policy(
    operation: str,
    policy: Optional[ScopePolicy] = None,
) -> PolicyDecision:
    """Deterministic policy check — no LLM, no network."""
    pol = policy or load_scope_config().policy
    op = _canonical_operation(operation)

    if op == "exploitation":
        if not pol.allow_exploitation:
            return PolicyDecision(
                allowed=False,
                reason="exploitation is not permitted by policy",
                operation=op,
                dry_run=pol.dry_run,
            )
        # Even when the flag is enabled, Phase 2 implements no exploitation.
        return PolicyDecision(
            allowed=False,
            reason="exploitation modules are not implemented",
            operation=op,
            dry_run=pol.dry_run,
        )

    if op == "active":
        if pol.dry_run:
            return PolicyDecision(
                allowed=False,
                reason="dry_run is enabled — active execution refused",
                operation=op,
                dry_run=True,
            )
        if not pol.allow_active_scanning:
            return PolicyDecision(
                allowed=False,
                reason="active scanning is not permitted by policy",
                operation=op,
                dry_run=pol.dry_run,
            )
        return PolicyDecision(
            allowed=True,
            reason="active operation permitted by explicit policy",
            operation=op,
            dry_run=pol.dry_run,
        )

    # Passive / observation: read-only checks, always allowed by policy
    # (scope authorization is enforced separately by the scope gate).
    return PolicyDecision(
        allowed=True,
        reason="passive observation permitted",
        operation="passive",
        dry_run=pol.dry_run,
    )


def enforce_execution_policy(
    operation: str,
    policy: Optional[ScopePolicy] = None,
) -> PolicyDecision:
    decision = check_execution_policy(operation, policy)
    if not decision.allowed:
        raise ExecutionPolicyError(decision.reason)
    return decision


class ActiveScanAuthorization(BaseModel):
    """Explicit, auditable consent for one authorized lab active-scan run.

    No LLM may construct this. A human operator (or authorized lab harness)
    supplies scan_id + approved_by + reason. This is the ONLY path that
    permits active_port_scan — the repository default policy still denies it.
    """

    scan_id: str = Field(min_length=1)
    approved_by: str = Field(min_length=1)
    reason: str = Field(min_length=1)


def lab_active_scan_policy(authorization: ActiveScanAuthorization) -> ScopePolicy:
    """Build the minimal explicit policy permitting active port scanning.

    dry_run=False + allow_active_scanning=True; exploitation stays denied.
    Raises ExecutionPolicyError for empty approval fields (no hidden bypass).
    """
    if not authorization.scan_id.strip() or not authorization.approved_by.strip():
        raise ExecutionPolicyError("active scan requires scan_id and approved_by")
    if not authorization.reason.strip():
        raise ExecutionPolicyError("active scan requires a reason")
    return ScopePolicy(
        dry_run=False,
        require_explicit_authorization=True,
        allow_active_scanning=True,
        allow_exploitation=False,
    )
