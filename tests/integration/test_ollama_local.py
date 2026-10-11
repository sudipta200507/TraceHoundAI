"""Optional local Ollama integration test (Phase 9) — skipped without qwen3:8b.

Uses ONLY synthetic fixture data. Never performs recon. The full suite
never depends on this test.
"""

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.ai.context_builder import build_context
from backend.app.ai.ollama_client import OllamaClient, load_llm_config


def _snapshot() -> dict:
    return json.loads(
        (PROJECT_ROOT / "tests" / "fixtures" / "ai" / "ai_sample_context.json")
        .read_text(encoding="utf-8"))


def _local_model_ready() -> bool:
    try:
        client = OllamaClient(load_llm_config())
    except Exception:
        return False
    try:
        return client.model_available()
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _local_model_ready(),
    reason="Ollama/qwen3:8b unavailable — optional local integration test")


def test_ollama_local_synthetic_prompt():
    client = OllamaClient(load_llm_config())
    context = build_context(_snapshot(), max_chars=2000)
    answer = client.generate(
        "Reply with exactly: TraceHoundAI local AI OK. Context length "
        f"received: {len(context)} chars.",
        system="You are a test assistant. Follow instructions exactly.")
    assert "TraceHoundAI local AI OK" in answer
