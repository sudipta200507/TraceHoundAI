"""Local Ollama client (Phase 9) — Qwen3 8B, localhost only.

No cloud APIs. No subprocess. Plain stdlib HTTP (urllib) with timeouts and
structured errors. Model selection always flows from config/llm.yaml.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

import yaml


@dataclass
class LLMConfig:
    provider: str = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    model: str = "qwen3:8b"
    temperature: float = 0.2
    top_p: float = 0.9
    num_ctx: int = 8192
    num_predict: int = 2048
    health_timeout: int = 10
    generate_timeout: int = 300
    max_chars: int = 12000


class OllamaError(RuntimeError):
    pass


class OllamaTimeout(OllamaError):
    pass


class OllamaUnavailable(OllamaError):
    pass


def get_default_llm_path() -> Path:
    return Path(__file__).resolve().parents[3] / "config" / "llm.yaml"


def load_llm_config(path: Optional[str | Path] = None) -> LLMConfig:
    cfg_path = Path(path) if path else get_default_llm_path()
    try:
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise OllamaError(f"LLM config not found: {cfg_path}") from exc
    options = data.get("options", {}) or {}
    timeouts = data.get("timeouts", {}) or {}
    context = data.get("context", {}) or {}
    return LLMConfig(
        provider=str(data.get("provider", "ollama")),
        base_url=str(data.get("base_url", "http://127.0.0.1:11434")).rstrip("/"),
        model=str(data.get("model", "qwen3:8b")),
        temperature=float(options.get("temperature", 0.2)),
        top_p=float(options.get("top_p", 0.9)),
        num_ctx=int(options.get("num_ctx", 8192)),
        num_predict=int(options.get("num_predict", 2048)),
        health_timeout=int(timeouts.get("health_seconds", 10)),
        generate_timeout=int(timeouts.get("generate_seconds", 300)),
        max_chars=int(context.get("max_chars", 12000)),
    )


class OllamaClient:
    """Minimal local Ollama HTTP client. `opener` is injectable for tests."""

    def __init__(
        self,
        config: Optional[LLMConfig] = None,
        opener: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.config = config or load_llm_config()
        if self.config.provider != "ollama":
            raise OllamaError(f"unsupported LLM provider: {self.config.provider}")
        if not self.config.base_url.startswith("http://127.0.0.1:"):
            raise OllamaError("Ollama base_url must stay on local 127.0.0.1")
        self._opener = opener or urllib.request.urlopen

    def _post(self, path: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
        url = f"{self.config.base_url}{path}"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json",
                     "User-Agent": "TraceHoundAI-lab"})
        try:
            with self._opener(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except TimeoutError as exc:
            raise OllamaTimeout(f"Ollama request timed out: {exc}") from exc
        except urllib.error.URLError as exc:
            raise OllamaUnavailable(f"Ollama unavailable at {url}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise OllamaError(f"invalid Ollama response: {exc}") from exc

    def _get(self, path: str, timeout: int) -> dict[str, Any]:
        url = f"{self.config.base_url}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "TraceHoundAI-lab"})
        try:
            with self._opener(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except TimeoutError as exc:
            raise OllamaTimeout(f"Ollama request timed out: {exc}") from exc
        except urllib.error.URLError as exc:
            raise OllamaUnavailable(f"Ollama unavailable at {url}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise OllamaError(f"invalid Ollama response: {exc}") from exc

    def health(self) -> bool:
        try:
            self._get("/api/tags", self.config.health_timeout)
            return True
        except OllamaError:
            return False

    def model_available(self, model: Optional[str] = None) -> bool:
        wanted = (model or self.config.model).strip().lower()
        try:
            data = self._get("/api/tags", self.config.health_timeout)
        except OllamaError:
            return False
        for entry in data.get("models", []) or []:
            name = str(entry.get("name", "") or entry.get("model", "")).lower()
            if name == wanted or name.startswith(wanted + ":"):
                return True
        return False

    def generate(self, prompt: str, system: str = "") -> str:
        data = self._post("/api/generate", {
            "model": self.config.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            # Structured extraction must be machine-readable: disable the
            # chain-of-thought trace so it cannot consume the token budget
            # and truncate the JSON answer.
            "think": False,
            "options": {"temperature": self.config.temperature,
                        "top_p": self.config.top_p,
                        "num_ctx": self.config.num_ctx,
                        "num_predict": self.config.num_predict},
        }, self.config.generate_timeout)
        text = str(data.get("response", "") or "")
        if not text.strip():
            raise OllamaError("empty response from Ollama model")
        return text

    def chat(self, messages: list[dict[str, str]]) -> str:
        data = self._post("/api/chat", {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "think": False,
            "options": {"temperature": self.config.temperature,
                        "top_p": self.config.top_p,
                        "num_ctx": self.config.num_ctx,
                        "num_predict": self.config.num_predict},
        }, self.config.generate_timeout)
        message = data.get("message", {}) or {}
        text = str(message.get("content", "") or "")
        if not text.strip():
            raise OllamaError("empty response from Ollama model")
        return text
