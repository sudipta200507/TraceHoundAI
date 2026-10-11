"""Stable evidence IDs (Phase 3) — sequential, reproducible, no randomness, no LLM."""

from __future__ import annotations

import threading


class EvidenceIdGenerator:
    """Scan-scoped sequential ID generator: E001, E002, ...

    Thread-safe: parallel pipeline stages share one generator and IDs
    stay unique (issue order may vary under threads — uniqueness never does).
    """

    def __init__(self, start: int = 1, prefix: str = "E", width: int = 3) -> None:
        if start < 1:
            raise ValueError("start must be >= 1")
        self._next = start
        self._prefix = prefix
        self._width = width
        self._issued: set[str] = set()
        self._lock = threading.Lock()

    def next(self) -> str:
        with self._lock:
            eid = f"{self._prefix}{self._next:0{self._width}d}"
            if eid in self._issued:
                raise RuntimeError(f"duplicate evidence ID generated: {eid}")
            self._issued.add(eid)
            self._next += 1
            return eid

    def reset(self, start: int = 1) -> None:
        if start < 1:
            raise ValueError("start must be >= 1")
        self._next = start
        self._issued.clear()

    @property
    def count(self) -> int:
        return len(self._issued)


def assign_ids(items: list[dict], start: int = 1) -> list[dict]:
    """Deterministically assign E001... to dicts lacking an 'id' (in list order)."""
    gen = EvidenceIdGenerator(start=start)
    out: list[dict] = []
    for item in items:
        row = dict(item)
        row.setdefault("id", gen.next())
        out.append(row)
    return out
