"""Finding-analysis prompt (Phase 9 v001)."""

from backend.app.ai.prompts.system import SYSTEM_PROMPT

FINDING_ANALYSIS_INSTRUCTIONS = """Analyze the scan evidence and produce security findings.

For each finding provide: finding_id, title, description, classification
(observed_fact | hypothesis | verified_finding | unknown), severity
(info | low | medium | high | critical), confidence (0-1, evidence support —
NOT severity), evidence_ids (at least one supplied ID), observed_facts
(quotes grounded in cited evidence), reasoning, verification_status
(unverified unless deterministic verification evidence is cited),
next_manual_steps (safe, non-executing checks only), and entity lists
(cves, technologies, services, ports, endpoints, versions) containing ONLY
values that appear verbatim in the cited evidence. Keep every list concise:
cite at most 10 most relevant Evidence IDs per finding and at most 5
observed_facts; prefer grounding quality over quantity. Also provide
"executive_summary": 3-6 sentences summarizing the overall security posture
for a non-technical reader, grounded ONLY in the cited evidence (counts of
assets, open services, and validated findings). Never mention evidence you
were not given.

FORBIDDEN: inventing CVEs/IDs/services/technologies/endpoints/ports/versions;
citing IDs not present in the evidence; marking verified; exploit instructions.
"""


def build_finding_prompt(context: str) -> tuple[str, str]:
    user = (
        FINDING_ANALYSIS_INSTRUCTIONS
        + "\nSCAN EVIDENCE:\n" + context
        + '\nRespond with JSON: {"findings": [...], "recommendations": [...], '
        + '"executive_summary": "..."}'
    )
    return SYSTEM_PROMPT, user
