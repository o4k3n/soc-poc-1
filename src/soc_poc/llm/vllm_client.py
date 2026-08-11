"""httpx client for a vLLM OpenAI-compatible server, with guided decoding.

Structured output spellings (checked against vLLM docs, August 2026):

  * PORTABLE -- OpenAI-compatible:
        "response_format": {"type": "json_schema",
                            "json_schema": {"name": ..., "schema": ..., "strict": true}}
  * vLLM-NATIVE:
        extra_body: {"structured_outputs": {"json": <schema>}}
    This replaced the older top-level `guided_json` field, which is deprecated and is
    deliberately not implemented here.

  Backend selection is a *server* flag (`--structured-outputs-config.backend`), not a
  request field -- see deploy/commander.env. Flag spelling has changed across vLLM
  releases; VERIFY against the image tag you pinned.

A note on gpt-oss/Harmony (vLLM issue #37030, open as of this writing): on GB10/SM121
the MXFP4 Marlin fallback path can return `content: null` with a populated
`reasoning_content`, and `--reasoning-parser openai_gptoss` has separately been
reported to route all output into the reasoning field. Both look identical from here:
an empty `content`. So this client treats an empty `content` as a transport error and
says which of the two it probably is, rather than handing an empty string to a JSON
parser and reporting a confusing schema failure three frames later. `make health`
exercises exactly this path before an investigation starts.
"""

from __future__ import annotations

from typing import Any

import httpx

from soc_poc.config import ModelConfig, StructuredOutputConfig
from soc_poc.llm.base import LLMResponse, LLMTransportError
from soc_poc.transcript import Stopwatch, TranscriptLogger


class VLLMClient:
    """One client per role. Holds no investigation state."""

    def __init__(
        self,
        config: ModelConfig,
        structured_output: StructuredOutputConfig,
        transcript: TranscriptLogger,  # required: there is no unlogged construction
    ) -> None:
        self.config = config
        self.role = config.role
        self._structured_output = structured_output
        self._transcript = transcript
        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            timeout=httpx.Timeout(config.request_timeout_s),
            headers={"Authorization": f"Bearer {config.resolved_api_key()}"},
        )

    # -- request construction -------------------------------------------------------

    def _payload(
        self,
        messages: list[dict[str, str]],
        schema_name: str,
        json_schema: dict[str, Any],
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "top_p": self.config.top_p,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }
        if self._structured_output.mode == "response_format":
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": schema_name,
                    "schema": json_schema,
                    "strict": self._structured_output.strict,
                },
            }
        else:
            payload["structured_outputs"] = {"json": json_schema}
        payload.update(self.config.extra_body)
        return payload

    # -- the one call ---------------------------------------------------------------

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
    ) -> LLMResponse:
        payload = self._payload(messages, schema_name, json_schema)
        logged_params = {
            k: v for k, v in payload.items() if k not in ("messages", "response_format")
        }
        watch = Stopwatch()

        def _log(
            *,
            response_text: str | None,
            raw: dict[str, Any] | None,
            finish_reason: str | None,
            usage: dict[str, Any] | None,
            error: str | None = None,
        ) -> None:
            self._transcript.log_llm_call(
                role=self.role,
                model=self.config.model,
                endpoint=self.config.base_url,
                task_id=task_id,
                parent_task_id=parent_task_id,
                state=state,
                attempt=attempt,
                schema_name=schema_name,
                params=logged_params,
                request_messages=messages,
                response_text=response_text,
                raw_response=raw,
                finish_reason=finish_reason,
                usage=usage,
                latency_ms=watch.elapsed_ms,
                error=error,
            )

        try:
            response = await self._client.post("/chat/completions", json=payload)
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            # Transport failures are logged before they are raised: a failed call is
            # part of the corpus too.
            _log(
                response_text=None,
                raw=None,
                finish_reason=None,
                usage=None,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise LLMTransportError(f"{self.role} call failed: {exc}") from exc

        choice = (body.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        text = message.get("content")
        finish_reason = choice.get("finish_reason", "")
        usage = body.get("usage", {})

        if not text:
            reasoning = message.get("reasoning_content") or message.get("reasoning")
            hint = (
                "content was empty but reasoning_content was populated -- the server is "
                "routing everything into the reasoning channel (check --reasoning-parser)"
                if reasoning
                else "content was empty and no reasoning channel was returned -- on "
                "GB10/SM121 this is the signature of the MXFP4 Marlin/Harmony bug "
                "(vLLM issue #37030); run `make health` and see README > Known issues"
            )
            _log(
                response_text=text,
                raw=body,
                finish_reason=finish_reason,
                usage=usage,
                error=f"empty content: {hint}",
            )
            raise LLMTransportError(f"{self.role} returned empty content: {hint}")

        _log(response_text=text, raw=body, finish_reason=finish_reason, usage=usage)
        return LLMResponse(
            text=text,
            model=body.get("model", self.config.model),
            finish_reason=finish_reason,
            usage=usage,
            latency_ms=watch.elapsed_ms,
        )

    async def aclose(self) -> None:
        await self._client.aclose()
