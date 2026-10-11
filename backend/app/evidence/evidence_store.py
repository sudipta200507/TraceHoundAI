"""JSON-backed evidence store (Phase 3) — no database."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from backend.app.evidence.models import Evidence, EvidenceSource, EvidenceType


class DuplicateEvidenceIdError(ValueError):
    pass


class EvidenceStore:
    def __init__(self) -> None:
        self._items: dict[str, Evidence] = {}

    def add(self, evidence: Evidence) -> Evidence:
        if evidence.id in self._items:
            raise DuplicateEvidenceIdError(f"duplicate evidence id: {evidence.id}")
        self._items[evidence.id] = evidence
        return evidence

    def get(self, evidence_id: str) -> Optional[Evidence]:
        return self._items.get(evidence_id)

    def find_evidence(self, ids: list[str]) -> list[Evidence]:
        """Anti-hallucination helper: which evidence supports this claim?"""
        return [self._items[i] for i in ids if i in self._items]

    def list(self) -> list[Evidence]:
        return [self._items[k] for k in sorted(self._items)]

    def filter_by_type(self, type: EvidenceType | str) -> list[Evidence]:
        t = type.value if isinstance(type, EvidenceType) else str(type)
        return [e for e in self.list() if e.type.value == t]

    def filter_by_source(self, source: EvidenceSource | str) -> list[Evidence]:
        s = source.value if isinstance(source, EvidenceSource) else str(source)
        return [e for e in self.list() if e.source.value == s]

    def filter_by_target(self, target: str) -> list[Evidence]:
        want = (target or "").strip().lower()
        return [e for e in self.list() if e.target.strip().lower() == want]

    def export_json(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = [e.model_dump(mode="json") for e in self.list()]
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return p

    @classmethod
    def load_json(cls, path: str | Path) -> "EvidenceStore":
        store = cls()
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError("evidence JSON must be a list")
        for row in raw:
            store.add(Evidence(**row))
        return store

    def __len__(self) -> int:
        return len(self._items)
