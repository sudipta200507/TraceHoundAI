"""Recommendation prompt (Phase 9 v001) — evidence-grounded, non-executing."""

from backend.app.ai.prompts.system import SYSTEM_PROMPT

RECOMMENDATION_INSTRUCTIONS = """Propose remediation and safe manual verification steps.

Each recommendation: recommendation_id, text (patch, disable, restrict, review,
validate, or investigate — grounded in cited evidence), evidence_ids,
rationale (which evidence motivates it), priority (low | medium | high).

FORBIDDEN: remediation unsupported by cited evidence; exploit execution;
destructive actions; invented requirements.
"""


def build_recommendation_prompt(context: str) -> tuple[str, str]:
    user = (
        RECOMMENDATION_INSTRUCTIONS
        + "\nSCAN EVIDENCE:\n" + context
        + '\nRespond with JSON: {"recommendations": [...]}'
    )
    return SYSTEM_PROMPT, user
