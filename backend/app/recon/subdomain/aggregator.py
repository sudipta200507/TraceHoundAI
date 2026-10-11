"""Subdomain aggregation stage (Phase 4).

Subfinder + crt.sh -> normalize -> scope filter -> dedup (+provenance)
-> Evidence -> asset_list.json. Deterministic, restartable, gate-enforced.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from backend.app.evidence.evidence_id import EvidenceIdGenerator
from backend.app.evidence.models import Evidence, EvidenceSource, EvidenceType
from backend.app.evidence.normalizer import build_observed_evidence
from backend.app.recon.subdomain.crtsh import query_crtsh
from backend.app.recon.subdomain.subfinder import run_subfinder
from backend.app.safety.gate import authorize_tool_execution
from backend.app.safety.scope_validator import ScopeConfig, validate_target

STAGE_NAME = "subdomain_discovery"


class DiscoveredAsset(BaseModel):
    hostname: str
    sources: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class RejectedHost(BaseModel):
    value: str
    reason: str


class AssetDiscoveryResult(BaseModel):
    scan_id: str
    target: str
    assets: list[DiscoveredAsset] = Field(default_factory=list)
    rejected: list[RejectedHost] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    checkpoint: dict[str, Any] = Field(default_factory=dict)


def normalize_hostname(value: str) -> Optional[str]:
    """Canonical hostname or None when invalid. Never upgrades bad input."""
    s = (value or "").strip().lower().rstrip(".")
    while s.startswith("*."):
        s = s[2:].strip().rstrip(".")
    if not s or len(s) > 253 or " " in s or "_" in s or ".." in s:
        return None
    labels = s.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    if any(c not in allowed for c in s):
        return None
    return s


def aggregate(
    subfinder_names: list[str],
    crtsh_names: list[str],
    target: str,
    config: Optional[ScopeConfig] = None,
) -> tuple[list[DiscoveredAsset], list[RejectedHost]]:
    """Dedup + provenance + scope enforcement. Out-of-scope never becomes assets."""
    authorize_tool_execution(target, "passive_discovery", config=config)
    provenance: dict[str, set[str]] = {}
    for name in subfinder_names or []:
        n = normalize_hostname(name)
        if n:
            provenance.setdefault(n, set()).add("subfinder")
    for name in crtsh_names or []:
        n = normalize_hostname(name)
        if n:
            provenance.setdefault(n, set()).add("crtsh")

    assets: list[DiscoveredAsset] = []
    rejected: list[RejectedHost] = []
    for hostname in sorted(provenance):
        decision = validate_target(hostname, config)
        if decision.allowed:
            assets.append(
                DiscoveredAsset(hostname=hostname, sources=sorted(provenance[hostname]))
            )
        else:
            rejected.append(RejectedHost(value=hostname, reason=decision.reason))
    # Malformed raw entries that normalized to None.
    raw_all = list(subfinder_names or []) + list(crtsh_names or [])
    for raw in raw_all:
        if normalize_hostname(raw) is None:
            rejected.append(RejectedHost(value=raw, reason="malformed hostname"))
    return assets, rejected


def build_evidence(
    assets: list[DiscoveredAsset],
    scan_id: str,
    generator: Optional[EvidenceIdGenerator] = None,
) -> list[Evidence]:
    """One observed Evidence per (asset, source). Deterministic ID order."""
    gen = generator or EvidenceIdGenerator()
    source_of = {"subfinder": EvidenceSource.SUBFINDER, "crtsh": EvidenceSource.CRTSH}
    raw_of = {
        "subfinder": f"data/raw/subdomain/{scan_id}/subfinder.json",
        "crtsh": f"data/raw/subdomain/{scan_id}/crtsh.json",
    }
    out: list[Evidence] = []
    for asset in assets:
        ids: list[str] = []
        for source in asset.sources:
            if source not in source_of:
                # e.g. the authorized scan root itself ("scan-root") has no
                # network collection source — the hostname is still valid.
                continue
            eid = gen.next()
            ids.append(eid)
            out.append(
                build_observed_evidence(
                    id=eid,
                    type=EvidenceType.SUBDOMAIN,
                    source=source_of[source],
                    target=asset.hostname,
                    observed_value=asset.hostname,
                    raw_reference=raw_of[source],
                    metadata={"tool": source, "scan_id": scan_id},
                )
            )
        asset.evidence_ids = ids
    return out


def project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def write_raw_checkpoint(
    scan_id: str,
    target: str,
    subfinder_stdout: str,
    subfinder_hostnames: list[str],
    crtsh_raw_text: str,
    crtsh_hostnames: list[str],
    base: Optional[Path] = None,
) -> list[str]:
    root = base or project_root()
    d = root / "data" / "raw" / "subdomain" / scan_id
    d.mkdir(parents=True, exist_ok=True)
    sf = d / "subfinder.json"
    cs = d / "crtsh.json"
    sf.write_text(
        json.dumps(
            {
                "scan_id": scan_id,
                "target": target,
                "hostnames": subfinder_hostnames,
                "stdout": subfinder_stdout,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    cs.write_text(
        json.dumps(
            {
                "scan_id": scan_id,
                "target": target,
                "hostnames": crtsh_hostnames,
                "raw_text": crtsh_raw_text,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return [str(sf), str(cs)]


def write_asset_list(
    scan_id: str,
    target: str,
    assets: list[DiscoveredAsset],
    base: Optional[Path] = None,
) -> str:
    root = base or project_root()
    p = root / "data" / "processed" / "asset_list.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(
            {
                "scan_id": scan_id,
                "target": target,
                "assets": [a.model_dump() for a in assets],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return str(p)


def run_discovery(
    target: str,
    scan_id: str,
    config: Optional[ScopeConfig] = None,
    subfinder_runner=None,
    crtsh_fetcher: Optional[Callable[[str, int], str]] = None,
    base: Optional[Path] = None,
    generator: Optional[EvidenceIdGenerator] = None,
) -> AssetDiscoveryResult:
    """Full passive stage: gate -> collect -> aggregate -> evidence -> checkpoint.

    Partial-failure isolation: each source is attempted independently. A
    failed source is recorded and its partial absence noted, but the other
    source's results still become assets. The stage fails only when BOTH
    sources fail.
    """
    started = datetime.now(timezone.utc).isoformat()
    decision = authorize_tool_execution(target, "passive_discovery", config=config)

    sf_hostnames: list[str] = []
    sf_stdout = ""
    sf_error = ""
    try:
        sf = run_subfinder(
            decision.target,
            config=config,
            **({"runner": subfinder_runner} if subfinder_runner else {}),
        )
        sf_hostnames = sf.hostnames
        sf_stdout = sf.stdout
    except Exception as exc:
        sf_error = f"subfinder failed for {decision.target}: {exc}"

    cs_hostnames: list[str] = []
    cs_raw_text = ""
    cs_error = ""
    try:
        cs = query_crtsh(
            decision.target,
            config=config,
            **({"fetcher": crtsh_fetcher} if crtsh_fetcher else {}),
        )
        cs_hostnames = cs.hostnames
        cs_raw_text = cs.raw_text
    except Exception as exc:
        cs_error = f"crt.sh query failed for {decision.target}: {exc}"

    if sf_error and cs_error:
        raise RuntimeError(f"asset discovery failed: {sf_error}; {cs_error}")
    assets, rejected = aggregate(sf_hostnames, cs_hostnames, decision.target, config)
    for message in (sf_error, cs_error):
        if message:
            rejected.append({"value": decision.target, "reason": message})

    # Real-world targets: passive enumerators may legitimately return nothing
    # for a small/new domain, and crt.sh can be flaky. The authorized root is
    # ALWAYS a valid in-scope asset (the scope gate already approved it), so
    # the scan continues with full potential instead of dying on an empty
    # list. Without the root asset, live discovery would find nothing at all.
    if not assets:
        decision_root = validate_target(decision.target, config)
        if decision_root.allowed:
            assets.append(DiscoveredAsset(
                hostname=decision.target, sources=["scan-root"]))
            reason_bits = [message.split(": ", 1)[-1]
                           for message in (sf_error, cs_error) if message]
            rejected.append({
                "value": decision.target,
                "reason": "no subdomains returned by passive enumerators; the "
                          "authorized root domain itself is scanned"
                          + (f" ({'; '.join(reason_bits)})" if reason_bits else ""),
            })

    evidence = build_evidence(assets, scan_id, generator)
    raw_files = write_raw_checkpoint(
        scan_id, decision.target, sf_stdout, sf_hostnames, cs_raw_text, cs_hostnames, base
    )
    asset_file = write_asset_list(scan_id, decision.target, assets, base)
    completed = datetime.now(timezone.utc).isoformat()
    return AssetDiscoveryResult(
        scan_id=scan_id,
        target=decision.target,
        assets=assets,
        rejected=rejected,
        evidence=evidence,
        checkpoint={
            "scan_id": scan_id,
            "stage": STAGE_NAME,
            "status": "completed",
            "started_at": started,
            "completed_at": completed,
            "output_files": raw_files + [asset_file],
        },
    )
