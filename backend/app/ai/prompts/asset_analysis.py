"""Asset-analysis prompt (Phase 9 v001) — inventory-focused analyst view."""

from backend.app.ai.prompts.system import SYSTEM_PROMPT

ASSET_ANALYSIS_INSTRUCTIONS = """Summarize the scanned asset inventory from evidence.

Describe each in-scope asset, its observed services/technologies/endpoints,
and which Evidence IDs establish each fact. Flag assets with no supporting
evidence as UNKNOWN. No new assets may be introduced beyond the evidence.
"""


def build_asset_prompt(context: str) -> tuple[str, str]:
    user = (
        ASSET_ANALYSIS_INSTRUCTIONS
        + "\nSCAN EVIDENCE:\n" + context
        + '\nRespond with JSON: {"assets": [{"hostname": "...", "evidence_ids": [...], "notes": "..."}]}'
    )
    return SYSTEM_PROMPT, user
