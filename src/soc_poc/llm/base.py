"""The LLM client contract.

One method, one shape: send messages plus a JSON schema, get text back. Every
implementation logs the full interaction to a TranscriptLogger it was constructed
with -- there is no unlogged path (see transcript.py).

SEAM: this protocol is where a future eval harness plugs in. A judge client, a
record/replay client, or a cost-accounting decorator all satisfy the same interface.
"""

from __future__ import annotations

from typing import Any, Callable, Protocol

from pydantic import BaseModel, ConfigDict

from soc_poc.config import ModelConfig

# (channel, text) where channel is "reasoning" or "content". Passing one of these to
# complete_json opts into the streaming transport; omitting it keeps the simpler
# request/response path, which is the one the tests exercise.
TokenCallback = Callable[[str, str], None]


class LLMTransportError(RuntimeError):
    """Network, HTTP, timeout, or malformed-envelope failure.

    Raised inside a client and caught at the nearest agent boundary, where it becomes
    an explicit failure record. Exceptions do not cross agent boundaries in this
    system; see grunt.py and orchestrator.py.
    """


class LLMResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str
    model: str
    finish_reason: str
    usage: dict[str, Any]
    latency_ms: float
    # Reasoning-channel output, when the server separates it. Kept because it is the
    # part of the corpus that shows *how* a conclusion was reached, which is what makes
    # these transcripts worth collecting.
    reasoning: str = ""


class LLMClient(Protocol):
    """Structured-output client. `role` is the transcript label (commander/grunt)."""

    role: str
    config: ModelConfig

    async def complete_json(
        self,
        *,
        messages: list[dict[str, str]],
        schema_name: str,
        json_schema: dict[str, Any],
        state: str,
        attempt: int,
        task_id: str | None = None,
        parent_task_id: str | None = None,
        on_token: TokenCallback | None = None,
    ) -> LLMResponse: ...

    async def aclose(self) -> None: ...
