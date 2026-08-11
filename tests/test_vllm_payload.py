"""Request shape for the vLLM client.

The endpoints are not up in CI, so this checks the one thing that can be checked
offline and that is easy to get subtly wrong: how the JSON schema is attached to the
request, and that per-model `extra_body` knobs (Qwen's thinking toggle) survive.
"""

from __future__ import annotations

from pathlib import Path

from soc_poc.config import StructuredOutputConfig, load_config
from soc_poc.llm.vllm_client import VLLMClient
from soc_poc.schemas.grunt import GruntReport
from soc_poc.schemas.jsonschema import schema_for
from soc_poc.transcript import TranscriptLogger

ROOT = Path(__file__).resolve().parent.parent


def _client(tmp_path: Path, mode: str) -> VLLMClient:
    config = load_config(ROOT / "config" / "config.toml")
    transcript = TranscriptLogger(tmp_path / "t.jsonl", "inv-test")
    return VLLMClient(config.grunt, StructuredOutputConfig(mode=mode), transcript)


def test_response_format_mode_uses_the_openai_compatible_shape(tmp_path: Path) -> None:
    client = _client(tmp_path, "response_format")
    payload = client._payload([{"role": "user", "content": "x"}], "grunt_report", schema_for(GruntReport))

    assert payload["response_format"]["type"] == "json_schema"
    assert payload["response_format"]["json_schema"]["name"] == "grunt_report"
    assert payload["response_format"]["json_schema"]["schema"]["additionalProperties"] is False
    assert payload["stream"] is False
    # Deprecated spelling must not appear.
    assert "guided_json" not in payload


def test_structured_outputs_mode_uses_the_vllm_native_shape(tmp_path: Path) -> None:
    client = _client(tmp_path, "structured_outputs")
    payload = client._payload([{"role": "user", "content": "x"}], "grunt_report", schema_for(GruntReport))

    assert "response_format" not in payload
    assert payload["structured_outputs"]["json"]["type"] == "object"


def test_model_extra_body_is_merged(tmp_path: Path) -> None:
    """Qwen3 thinking mode is turned off per request, from config, not in code."""
    client = _client(tmp_path, "response_format")
    payload = client._payload([{"role": "user", "content": "x"}], "grunt_report", {})

    assert payload["chat_template_kwargs"] == {"enable_thinking": False}
    assert payload["model"] == "qwen3-8b"
