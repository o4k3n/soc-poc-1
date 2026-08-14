"""httpx client for a vLLM OpenAI-compatible server, with guided decoding.

Structured output spellings (checked against vLLM 0.24.0, the build inside
nvcr.io/nvidia/vllm:26.07-py3):

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

Empty `content` is treated as a transport error rather than being passed to a JSON
parser, because it has two very different causes that look identical from here:

  * a reasoning-parser mismatch, where the whole response is routed into
    `reasoning_content` and `content` comes back empty. This is the likely one -- it is
    a configuration mistake, and the server is otherwise perfectly healthy.
  * a broken quantization kernel emitting a wrong first control token. This was the
    story on community images for gpt-oss MXFP4 on SM121 (vllm-project/vllm#37030); the
    NGC image ships a dedicated `gpt_oss_mxfp4` path, so it is not expected here.

Reporting "empty content, and here is which one it probably is" beats reporting a
confusing schema failure three frames later. `make health` exercises this path with a
real guided-JSON round trip before any investigation starts.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from soc_poc.config import ModelConfig, StructuredOutputConfig
from soc_poc.llm.base import LLMResponse, LLMTransportError, TokenCallback
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
        stream: bool = False,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "top_p": self.config.top_p,
            "max_tokens": self.config.max_tokens,
            "stream": stream,
        }
        if stream:
            # Without this the final chunk carries no usage and the transcript loses
            # token counts, which are part of what makes the corpus analysable later.
            payload["stream_options"] = {"include_usage": True}
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
        on_token: TokenCallback | None = None,
    ) -> LLMResponse:
        payload = self._payload(messages, schema_name, json_schema, stream=on_token is not None)
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
            if on_token is None:
                body = await self._post(payload)
            else:
                body = await self._post_streaming(payload, on_token)
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
        reasoning_text = message.get("reasoning_content") or message.get("reasoning") or ""
        finish_reason = choice.get("finish_reason", "")
        usage = body.get("usage", {})

        if not text:
            reasoning = reasoning_text
            hint = (
                "content was empty but reasoning_content was populated -- the server is "
                "routing everything into the reasoning channel (check --reasoning-parser)"
                if reasoning
                else "content was empty and no reasoning channel was returned -- the "
                "model produced no usable output at all; run `make health` and see "
                "README > Known issues"
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
            reasoning=reasoning_text,
        )

    # -- transports ------------------------------------------------------------------

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        """The plain path: one request, one response body."""
        response = await self._client.post("/chat/completions", json=payload)
        response.raise_for_status()
        return response.json()

    async def _post_streaming(
        self, payload: dict[str, Any], on_token: TokenCallback
    ) -> dict[str, Any]:
        """The streaming path, used only when something is watching.

        Deltas are accumulated and reassembled into the same body shape the plain path
        returns, so everything downstream -- validation, the transcript, the empty-content
        check -- is identical either way. The reassembled body is tagged `streamed: true`
        and carries the accumulated reasoning, which the non-streaming path also keeps;
        that channel is the most interesting part of the corpus and used to be discarded.

        Field naming: this server emits `delta.reasoning`, but other vLLM builds and
        other models emit `delta.reasoning_content`. Both are accepted.
        """
        content: list[str] = []
        reasoning: list[str] = []
        finish_reason = ""
        usage: dict[str, Any] = {}
        model = self.config.model

        async with self._client.stream("POST", "/chat/completions", json=payload) as response:
            if response.status_code >= 400:
                # The body has not been read yet on a streaming response; read it so the
                # error says what the server actually complained about.
                await response.aread()
                response.raise_for_status()

            async for line in response.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[len("data:") :].strip()
                if not data or data == "[DONE]":
                    continue
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    # A malformed chunk is not worth killing a long generation over.
                    continue

                model = chunk.get("model", model)
                if chunk.get("usage"):
                    usage = chunk["usage"]
                for choice in chunk.get("choices") or []:
                    delta = choice.get("delta") or {}
                    if choice.get("finish_reason"):
                        finish_reason = choice["finish_reason"]
                    piece = delta.get("reasoning") or delta.get("reasoning_content")
                    if piece:
                        reasoning.append(piece)
                        on_token("reasoning", piece)
                    if delta.get("content"):
                        content.append(delta["content"])
                        on_token("content", delta["content"])

        return {
            "model": model,
            "streamed": True,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "".join(content),
                        "reasoning": "".join(reasoning),
                    },
                    "finish_reason": finish_reason,
                }
            ],
            "usage": usage,
        }

    async def aclose(self) -> None:
        await self._client.aclose()
