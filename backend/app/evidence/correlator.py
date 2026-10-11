"""Evidence correlator (Phase 3) — small, deterministic, no invented links."""

from __future__ import annotations

from pydantic import BaseModel, Field

from backend.app.evidence.evidence_store import EvidenceStore

SUPPORTED_RELATIONS = {
    "subdomain_to_live_host",
    "host_to_port",
    "port_to_service",
    "host_to_technology",
    "endpoint_to_technology",
    "vulnerability_to_service",
}


class Correlation(BaseModel):
    from_id: str = Field(pattern=r"^E\d{3,}$")
    to_id: str = Field(pattern=r"^E\d{3,}$")
    relation: str


def _host(e) -> str:
    return (e.target or "").strip().lower()


def create_link(
    store: EvidenceStore, from_id: str, to_id: str, relation: str
) -> Correlation:
    if relation not in SUPPORTED_RELATIONS:
        raise ValueError(f"unsupported relation: {relation}")
    if from_id == to_id:
        raise ValueError("cannot link evidence to itself")
    if store.get(from_id) is None or store.get(to_id) is None:
        raise ValueError("both evidence IDs must exist in the store")
    return Correlation(from_id=from_id, to_id=to_id, relation=relation)


def correlate(store: EvidenceStore) -> list[Correlation]:
    """Derive only evidence-supported relationships (exact host equality)."""
    out: list[Correlation] = []
    items = store.list()
    by_id = {e.id: e for e in items}

    def link(a: str, b: str, rel: str) -> None:
        if a in by_id and b in by_id and a != b:
            out.append(Correlation(from_id=a, to_id=b, relation=rel))

    subdomains = [e for e in items if e.type.value == "subdomain"]
    live_hosts = [e for e in items if e.type.value == "live_host"]
    ports = [e for e in items if e.type.value == "port"]
    services = [e for e in items if e.type.value == "service"]
    techs = [e for e in items if e.type.value == "technology"]
    endpoints = [e for e in items if e.type.value == "endpoint"]
    vulns = [e for e in items if e.type.value == "vulnerability"]

    host_values = {e.normalized_value.strip().lower() for e in live_hosts}
    host_values |= {_host(e) for e in live_hosts}

    for s in subdomains:
        name = s.normalized_value.strip().lower()
        for h in live_hosts:
            if name and name in {_host(h), h.normalized_value.strip().lower()}:
                link(s.id, h.id, "subdomain_to_live_host")

    for h in live_hosts:
        for p in ports:
            if _host(p) == _host(h):
                link(h.id, p.id, "host_to_port")

    for p in ports:
        for s in services:
            if _host(s) == _host(p) and s.metadata.get("port") == p.normalized_value:
                link(p.id, s.id, "port_to_service")

    for h in live_hosts:
        for t in techs:
            if _host(t) == _host(h) and not t.metadata.get("endpoint"):
                link(h.id, t.id, "host_to_technology")

    for ep in endpoints:
        for t in techs:
            if t.metadata.get("endpoint") == ep.normalized_value:
                link(ep.id, t.id, "endpoint_to_technology")

    for v in vulns:
        for s in services:
            want = v.metadata.get("service")
            if (
                want
                and _host(v) == _host(s)
                and want == s.normalized_value
            ):
                link(v.id, s.id, "vulnerability_to_service")

    # Deduplicate while preserving order.
    seen: set[tuple[str, str, str]] = set()
    unique: list[Correlation] = []
    for c in out:
        key = (c.from_id, c.to_id, c.relation)
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique
