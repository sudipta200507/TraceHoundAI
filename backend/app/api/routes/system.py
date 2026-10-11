"""System health + safety routes — Phase 1 tool health, Phase 2 scope gate."""

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.app.core.tool_manager import check_all_tools
from backend.app.safety.scope_validator import validate_target

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/tools")
def get_tools():
    """Return current health state of all configured external tools."""
    results = check_all_tools()
    tools = [
        {
            "name": r.name,
            "available": r.available,
            "version": r.version,
            "status": r.status,
            "executable": r.executable,
        }
        for r in results
    ]
    return {"tools": tools}


class ScopeValidateRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)


class ScopeValidateResponse(BaseModel):
    allowed: bool
    target: str
    reason: str
    matched_rule: str | None = None
    risk_level: str


@router.post("/scope/validate", response_model=ScopeValidateResponse)
def validate_scope(payload: ScopeValidateRequest):
    """Deterministic scope check — never executes tools, never exposes secrets."""
    decision = validate_target(payload.target)
    return ScopeValidateResponse(
        allowed=decision.allowed,
        target=decision.target,
        reason=decision.reason,
        matched_rule=decision.matched_rule,
        risk_level=decision.risk_level,
    )
