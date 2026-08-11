"""Endpoint preflight. The orchestrator does not start until this passes.

Three checks per endpoint, in increasing order of how much they tell you:

  1. GET /health          -- the server is up.
  2. GET /v1/models       -- it is serving the model this config names. Catches the
                             "you edited config.toml but restarted the wrong container"
                             class of confusion immediately.
  3. a real guided-JSON round trip -- the model actually produces schema-conformant,
                             non-empty content.

Check 3 is the one that earns its keep on this box. On GB10/SM121 the gpt-oss MXFP4
path can fall back to Marlin kernels that corrupt the first Harmony token, and the
symptom is `content: null` with everything else looking healthy (vLLM issue #37030,
open at time of writing). A reasoning-parser misconfiguration produces the same
symptom. Either way you want to learn it here, in five seconds, rather than halfway
through an investigation with a confusing schema error.

Preflight calls are logged to the transcript like any other LLM interaction.
"""

from __future__ import annotations

import httpx
from pydantic import BaseModel, ConfigDict, Field

from soc_poc.config import ModelConfig, StructuredOutputConfig
from soc_poc.llm.base import LLMTransportError
from soc_poc.llm.vllm_client import VLLMClient
from soc_poc.parsing import ParseFailure, parse_model_json
from soc_poc.schemas.jsonschema import schema_for
from soc_poc.transcript import TranscriptLogger


class ProbeAnswer(BaseModel):
    """Deliberately tiny: we are testing the plumbing, not the model."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    engine: str


class CheckResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    endpoint: str
    role: str
    name: str
    ok: bool
    detail: str = ""


class PreflightResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    checks: list[CheckResult] = Field(default_factory=list)

    def report(self) -> str:
        lines = [
            f"[{'PASS' if c.ok else 'FAIL'}] {c.role:<9} {c.name:<22} {c.endpoint}"
            + (f"\n         {c.detail}" if c.detail else "")
            for c in self.checks
        ]
        return "\n".join(lines)


async def _http_checks(config: ModelConfig) -> list[CheckResult]:
    base = config.base_url
    # /health lives at the server root, not under /v1.
    root = base[: -len("/v1")] if base.endswith("/v1") else base
    results: list[CheckResult] = []
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.get(f"{root}/health")
            ok = response.status_code == 200
            results.append(
                CheckResult(
                    endpoint=root,
                    role=config.role,
                    name="server_health",
                    ok=ok,
                    detail="" if ok else f"HTTP {response.status_code}",
                )
            )
        except httpx.HTTPError as exc:
            return [
                CheckResult(
                    endpoint=root,
                    role=config.role,
                    name="server_health",
                    ok=False,
                    detail=f"{type(exc).__name__}: {exc} (is the container up? `make up`)",
                )
            ]

        try:
            response = await client.get(f"{base}/models")
            served = [entry.get("id", "") for entry in response.json().get("data", [])]
            ok = config.model in served
            results.append(
                CheckResult(
                    endpoint=base,
                    role=config.role,
                    name="served_model_name",
                    ok=ok,
                    detail=""
                    if ok
                    else f"config names {config.model!r}; server serves {served!r}. "
                    "Fix --served-model-name in deploy/*.env or the model in config.toml.",
                )
            )
        except (httpx.HTTPError, ValueError) as exc:
            results.append(
                CheckResult(
                    endpoint=base,
                    role=config.role,
                    name="served_model_name",
                    ok=False,
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )
    return results


async def _guided_json_check(
    config: ModelConfig,
    structured_output: StructuredOutputConfig,
    transcript: TranscriptLogger,
) -> CheckResult:
    client = VLLMClient(config, structured_output, transcript)
    try:
        response = await client.complete_json(
            messages=[
                {
                    "role": "system",
                    "content": "You are a health probe. Reply with JSON matching the schema.",
                },
                {
                    "role": "user",
                    "content": "Set ok to true and engine to the name of the model serving "
                    "this request.",
                },
            ],
            schema_name="preflight_probe",
            json_schema=schema_for(ProbeAnswer),
            state="PREFLIGHT",
            attempt=1,
        )
    except LLMTransportError as exc:
        return CheckResult(
            endpoint=config.base_url,
            role=config.role,
            name="guided_json_roundtrip",
            ok=False,
            detail=str(exc),
        )
    finally:
        await client.aclose()

    try:
        parse_model_json(response.text, ProbeAnswer)
    except ParseFailure as exc:
        return CheckResult(
            endpoint=config.base_url,
            role=config.role,
            name="guided_json_roundtrip",
            ok=False,
            detail=f"guided decoding produced non-conformant output: {exc}. Check the "
            "structured-outputs backend flag on this container.",
        )
    return CheckResult(
        endpoint=config.base_url,
        role=config.role,
        name="guided_json_roundtrip",
        ok=True,
        detail=f"{response.latency_ms:.0f} ms",
    )


async def preflight(
    configs: list[ModelConfig],
    structured_output: StructuredOutputConfig,
    transcript: TranscriptLogger,
) -> PreflightResult:
    checks: list[CheckResult] = []
    for config in configs:
        endpoint_checks = await _http_checks(config)
        checks.extend(endpoint_checks)
        if all(check.ok for check in endpoint_checks):
            checks.append(await _guided_json_check(config, structured_output, transcript))
    result = PreflightResult(ok=all(check.ok for check in checks), checks=checks)
    transcript.log_event("preflight", {"ok": result.ok, "checks": [c.model_dump() for c in checks]})
    return result
