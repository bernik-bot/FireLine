"""
Ollama runtime client — pure text-in / text-out.

Invariant (brief #1): the local AI is a reasoning component, not an agent. This
client therefore exposes exactly one capability: send a prompt string, get a
completion string back. No tool-calling loop, no function/JSON-tool schema, no
streaming-of-actions, no shell. It does not import `subprocess`, `os.system`,
or any actuator. The only network it speaks to is the local Ollama daemon on
loopback (a model runtime), never a customer endpoint.

Model placement (architecture): the LOCAL APPLIANCE agent runs Gemma 4 on an
NVIDIA RTX machine under Ollama. The CLOUD BRAIN is a separate frontier model
(Claude or equivalent) living in the advisory/orchestration layer — it is NOT
this client and never runs on the appliance.

The appliance defaults to Gemma 4 26B-A4B: a Mixture-of-Experts model with 26B
total parameters (all resident in VRAM for routing) but only ~4B active per
token, giving larger-model reasoning at near-4B latency — the right trade for
the real-time path. A model tier is still exposed so a heavier dense model
(e.g. gemma4:31b) can be selected for periodic/daily deep passes; both default
to Gemma 4 and are overridable via OLLAMA_MODEL_* env vars.

If Ollama is unreachable (CI, offline pilot, smoke demo), the client falls back
to a deterministic offline stub so the *boundary* and *advisory* guarantees can
be tested without a GPU. The stub is clearly labelled in its output.
"""
from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from enum import Enum
from urllib.error import URLError


class ModelTier(str, Enum):
    """Which local model to use on the appliance. Real-time work uses the
    latency-optimized MoE model; the periodic tier may point at a heavier dense
    model for daily/batch deep passes."""
    continuous = "continuous"   # Gemma 4 26B-A4B (MoE, ~4B active) — real-time
    periodic = "periodic"       # heavier dense pass (e.g. gemma4:31b) — daily/batch


# Loopback only. This is the model runtime, not an endpoint. Overridable for a
# sidecar container, but never points at a customer host.
_DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
_MODEL_BY_TIER = {
    # Appliance defaults to Gemma 4. Continuous = 26B-A4B MoE for low latency.
    # Periodic defaults to the same model but can be pointed at the dense 31B
    # for daily deep passes via OLLAMA_MODEL_PERIODIC.
    ModelTier.continuous: os.environ.get("OLLAMA_MODEL_CONTINUOUS", "gemma4:26b"),
    ModelTier.periodic: os.environ.get("OLLAMA_MODEL_PERIODIC", "gemma4:26b"),
}


@dataclass
class Completion:
    text: str
    model: str
    offline_stub: bool = False


class OllamaClient:
    """Thin, capability-minimal wrapper around the local Ollama generate API."""

    def __init__(self, host: str | None = None, *, timeout: float = 30.0,
                 allow_stub: bool = True, thinking: bool = True) -> None:
        self.host = (host or _DEFAULT_HOST).rstrip("/")
        self.timeout = timeout
        # When False, an unreachable daemon raises instead of stubbing — used in
        # production so a missing model is loud, not silently degraded.
        self.allow_stub = allow_stub
        # Gemma 4 reasons better with thinking enabled. We let the model think,
        # then strip the trace before returning so only the final answer (the
        # JSON the analyst parses) survives. The trace is never persisted.
        self.thinking = thinking

    def model_for(self, tier: ModelTier) -> str:
        return _MODEL_BY_TIER[tier]

    def complete(self, prompt: str, *, tier: ModelTier = ModelTier.continuous,
                 system: str | None = None) -> Completion:
        """Text in, text out. No tools, no actions."""
        model = self.model_for(tier)
        # Gemma 4: thinking is enabled by prefixing the system prompt with the
        # <|think|> control token. (No effect on non-Gemma models — it is just
        # leading text they ignore.)
        sys_prompt = system or ""
        if self.thinking:
            sys_prompt = "<|think|>\n" + sys_prompt
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            # Hard ceiling on context the model can self-direct: it cannot call
            # back out. options kept minimal on purpose.
            "options": {"temperature": 0.2},
        }
        if sys_prompt:
            payload["system"] = sys_prompt

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            return Completion(text=_strip_thinking(body.get("response", "")),
                              model=model)
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            if not self.allow_stub:
                raise
            return Completion(text=_offline_stub(prompt), model=f"{model}+stub",
                              offline_stub=True)


def _strip_thinking(text: str) -> str:
    """Remove a Gemma-style thinking trace, leaving only the final answer.

    The model emits its reasoning inside think tags before the answer. The
    analyst only wants the final JSON, and the trace must never be persisted
    (it can echo poisoned log content). Strips a leading <think>...</think>
    block (and tolerates the unclosed/streaming variant) without touching the
    answer body.
    """
    import re
    if not text:
        return text
    # Closed block: <think> ... </think>
    text = re.sub(r"(?is)<think>.*?</think>", "", text)
    # Defensive: a stray opening tag with no close — drop everything up to it.
    text = re.sub(r"(?is)^.*?</think>", "", text) if "</think>" in text else text
    return text.strip()


def _offline_stub(prompt: str) -> str:
    """Deterministic, content-free placeholder for offline/CI runs.

    It intentionally does NOT parse or trust the prompt's embedded telemetry —
    it just returns a fixed advisory shell. This keeps tests deterministic and
    makes clear the stub adds no real analysis.
    """
    return json.dumps({
        "summary": "[offline-stub] Local model unavailable; no AI annotation produced.",
        "suggested_priority": None,
        "nominations": [],
    })
