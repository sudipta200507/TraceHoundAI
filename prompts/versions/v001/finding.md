Analyze the scan evidence and produce security findings.

For each finding provide: finding_id, title, description, classification
(observed_fact | hypothesis | verified_finding | unknown), severity
(info | low | medium | high | critical), confidence (0-1, evidence support —
NOT severity), evidence_ids (at least one supplied ID), observed_facts
(quotes grounded in cited evidence), reasoning, verification_status
(unverified unless deterministic verification evidence is cited),
next_manual_steps (safe, non-executing checks only), and entity lists
(cves, technologies, services, ports, endpoints, versions) containing ONLY
values that appear verbatim in the cited evidence.

FORBIDDEN: inventing CVEs/IDs/services/technologies/endpoints/ports/versions;
citing IDs not present in the evidence; marking verified; exploit instructions.
