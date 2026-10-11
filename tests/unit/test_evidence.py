"""Phase 3 tests: evidence foundation — deterministic, no recon, no LLM."""

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.evidence.correlator import correlate, create_link
from backend.app.evidence.evidence_id import EvidenceIdGenerator, assign_ids
from backend.app.evidence.evidence_store import DuplicateEvidenceIdError, EvidenceStore
from backend.app.evidence.models import (
    EvidencedClaim,
    Evidence,
    EvidenceSource,
    EvidenceStatus,
    EvidenceType,
    ScanContext,
)
from backend.app.evidence.normalizer import (
    build_observed_evidence,
    subdomain_record_to_evidence,
)
from backend.app.evidence.validation import assert_valid, validate_evidence


def _ev(eid="E001", **kw):
    base = {
        "id": eid,
        "type": EvidenceType.SUBDOMAIN,
        "source": EvidenceSource.SUBFINDER,
        "target": "example.lab",
        "observed_value": "www.example.lab",
        "normalized_value": "www.example.lab",
        "status": EvidenceStatus.OBSERVED,
        "confidence": 1.0,
        "raw_reference": "data/raw/subdomain/subfinder.json",
    }
    base.update(kw)
    return Evidence(**base)


def test_evidence_creation():
    e = _ev()
    assert e.id == "E001"
    assert e.type == EvidenceType.SUBDOMAIN
    assert e.status == EvidenceStatus.OBSERVED


def test_evidence_id_generation():
    gen = EvidenceIdGenerator()
    assert gen.next() == "E001"
    assert gen.next() == "E002"


def test_sequential_ids():
    rows = assign_ids([{"type": "x"}, {"type": "y"}, {"type": "z"}])
    assert [r["id"] for r in rows] == ["E001", "E002", "E003"]


def test_evidence_validation():
    assert validate_evidence(_ev()) == []
    assert_valid(_ev())


def test_invalid_confidence():
    with pytest.raises(Exception):
        _ev(eid="E002", confidence=1.5)
    with pytest.raises(Exception):
        _ev(eid="E003", confidence=-0.1)


def test_missing_source():
    with pytest.raises(Exception):
        Evidence(
            id="E010",
            type=EvidenceType.PORT,
            target="example.lab",
            observed_value="443",
            normalized_value="443",
            status=EvidenceStatus.OBSERVED,
            confidence=1.0,
            raw_reference="data/raw/ports/naabu.json",
        )


def test_observed_evidence_requirements():
    e2 = _ev()
    object.__setattr__(e2, "raw_reference", "")
    problems = validate_evidence(e2)
    assert any("raw_reference" in p for p in problems)


def test_evidence_store_add():
    store = EvidenceStore()
    store.add(_ev("E001"))
    assert len(store) == 1


def test_evidence_store_lookup():
    store = EvidenceStore()
    store.add(_ev("E001"))
    assert store.get("E001").id == "E001"
    assert store.get("E999") is None


def test_evidence_filtering():
    store = EvidenceStore()
    store.add(_ev("E001"))
    store.add(
        _ev(
            "E002",
            type=EvidenceType.PORT,
            source=EvidenceSource.NAABU,
            target="www.example.lab",
            observed_value="443",
            normalized_value="443",
            raw_reference="data/raw/ports/naabu.json",
        )
    )
    assert len(store.filter_by_type(EvidenceType.PORT)) == 1
    assert len(store.filter_by_source(EvidenceSource.SUBFINDER)) == 1
    assert len(store.filter_by_target("www.example.lab")) == 1
    assert len(store.filter_by_target("example.lab")) == 1
    assert len(store.filter_by_target("WWW.EXAMPLE.LAB")) == 1
    assert len(store.filter_by_target("other.lab")) == 0


def test_json_export(tmp_path):
    store = EvidenceStore()
    store.add(_ev("E001"))
    p = store.export_json(tmp_path / "evidence.json")
    data = json.loads(p.read_text(encoding="utf-8"))
    assert isinstance(data, list) and data[0]["id"] == "E001"


def test_json_load(tmp_path):
    store = EvidenceStore()
    store.add(_ev("E001"))
    p = store.export_json(tmp_path / "evidence.json")
    loaded = EvidenceStore.load_json(p)
    assert loaded.get("E001").normalized_value == "www.example.lab"


def test_correlation():
    store = EvidenceStore()
    store.add(_ev("E001"))  # subdomain www.example.lab for example.lab
    store.add(
        _ev(
            "E002",
            type=EvidenceType.LIVE_HOST,
            source=EvidenceSource.HTTPX,
            target="www.example.lab",
            observed_value="https://www.example.lab",
            normalized_value="https://www.example.lab",
            raw_reference="data/raw/httpx/httpx.json",
        )
    )
    store.add(
        _ev(
            "E003",
            type=EvidenceType.PORT,
            source=EvidenceSource.NAABU,
            target="www.example.lab",
            observed_value="443",
            normalized_value="443",
            raw_reference="data/raw/ports/naabu.json",
        )
    )
    rels = correlate(store)
    kinds = {(r.from_id, r.to_id, r.relation) for r in rels}
    assert ("E001", "E002", "subdomain_to_live_host") in kinds
    assert ("E002", "E003", "host_to_port") in kinds


def test_invalid_correlation_rejection():
    store = EvidenceStore()
    store.add(_ev("E001"))
    with pytest.raises(ValueError):
        create_link(store, "E001", "E999", "host_to_port")
    with pytest.raises(ValueError):
        create_link(store, "E001", "E001", "host_to_port")
    with pytest.raises(ValueError):
        create_link(store, "E001", "E001", "made_up_relation")
    # Unrelated evidence yields no invented links.
    store.add(
        _ev(
            "E002",
            type=EvidenceType.PORT,
            source=EvidenceSource.NAABU,
            target="other.lab",
            observed_value="80",
            normalized_value="80",
            raw_reference="data/raw/ports/naabu.json",
        )
    )
    assert correlate(store) == []


def test_evidence_reference_lookup():
    store = EvidenceStore()
    store.add(_ev("E001"))
    store.add(_ev("E002", target="other.lab"))
    found = store.find_evidence(["E001", "E999"])
    assert [e.id for e in found] == ["E001"]
    claim = EvidencedClaim(
        finding_id="F001",
        claim="www.example.lab is a subdomain",
        evidence_ids=["E001"],
        confidence=0.9,
        status="supported",
    )
    assert claim.evidence_ids == ["E001"]


def test_scan_context():
    ctx = ScanContext(
        scan_id="scan-001",
        target="example.lab",
        scope={"allowed_domains": ["example.lab"]},
        evidence_ids=["E001", "E002"],
    )
    assert ctx.scan_id == "scan-001"
    assert "E001" in ctx.evidence_ids


def test_serialization_deserialization(tmp_path):
    e = _ev()
    dumped = e.model_dump(mode="json")
    assert Evidence(**dumped) == e
    store = EvidenceStore()
    store.add(e)
    p = store.export_json(tmp_path / "e.json")
    assert EvidenceStore.load_json(p).get("E001") == e


def test_duplicate_id_handling():
    store = EvidenceStore()
    store.add(_ev("E001"))
    with pytest.raises(DuplicateEvidenceIdError):
        store.add(_ev("E001"))


def test_no_llm_in_evidence_engine():
    pkg = PROJECT_ROOT / "backend" / "app" / "evidence"
    banned = ("langchain", "ollama", "openai", "anthropic", "llm", "transformers")
    for py in pkg.glob("*.py"):
        text = py.read_text(encoding="utf-8").lower()
        for term in banned:
            # 'llm' may appear in comments about "no LLM"; allow the phrase
            # "no llm" / "never" context but reject actual imports/usages.
            if term == "llm":
                lines = [
                    ln
                    for ln in text.splitlines()
                    if "llm" in ln and "no llm" not in ln and "never" not in ln
                ]
                assert not lines, f"{py.name} references LLM: {lines[:2]}"
            else:
                assert term not in text, f"{py.name} must not depend on {term}"


def test_normalizer_example_fixture():
    e = subdomain_record_to_evidence(
        id="E001", subdomain="WWW.Example.Lab", target="example.lab"
    )
    assert e.normalized_value == "www.example.lab"
    assert e.status == EvidenceStatus.OBSERVED
    assert e.raw_reference == "data/raw/subdomain/subfinder.json"
    e2 = build_observed_evidence(
        id="E002",
        type=EvidenceType.PORT,
        source=EvidenceSource.NAABU,
        target="www.example.lab",
        observed_value=" 443 ",
        raw_reference="data/raw/ports/naabu.json",
    )
    assert e2.normalized_value == "443"


def test_verified_evidence_rules():
    e = _ev(status=EvidenceStatus.VERIFIED)
    problems = validate_evidence(e)
    assert any("verified_by" in p for p in problems)
    e.metadata = {"verified_by": "nuclei", "verification_ref": "data/raw/nuclei/nuclei.json"}
    assert validate_evidence(e) == []


def test_canonical_fixture_loads():
    from backend.app.evidence.evidence_store import EvidenceStore as Store

    store = Store.load_json(PROJECT_ROOT / "data" / "processed" / "evidence.json")
    assert len(store) >= 2
    assert store.get("E001") is not None
