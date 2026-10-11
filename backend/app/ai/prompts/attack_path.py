"""Attack-path prompt (Phase 9 v001) — hypotheses only, non-executing."""

from backend.app.ai.prompts.system import SYSTEM_PROMPT

ATTACK_PATH_INSTRUCTIONS = """Propose hypothetical attack paths LINKED to cited evidence.

Each path: attack_path_id, title, starting_asset, steps (each with asset,
observed_condition grounded in cited evidence, relationship, hypothesis,
required_verification describing the manual check that would confirm or
refute it), evidence_ids, confidence, status ("hypothesis" always).

FORBIDDEN: exploit commands, payloads, tool invocations, destructive
instructions, path-traversal examples (such as ../ sequences), sensitive
file references — no executable instructions of any kind. Every step must cite evidence IDs.
Uncertainty must be explicit.
"""


def build_attack_path_prompt(context: str) -> tuple[str, str]:
    user = (
        ATTACK_PATH_INSTRUCTIONS
        + "\nSCAN EVIDENCE:\n" + context
        + '\nRespond with JSON: {"attack_paths": [...]}'
    )
    return SYSTEM_PROMPT, user
