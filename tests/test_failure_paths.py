"""Failures must become records, not exceptions, and the cap must stop the loop."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from soc_poc.config import RunConfig, load_config
from soc_poc.llm.base import LLMResponse, LLMTransportError
from soc_poc.grunt import run_grunt_task
from soc_poc.messages import GruntFailure, GruntTasking
from soc_poc.runner import run_investigation
from soc_poc.schemas.slice import LogLine, LogSlice
from soc_poc.schemas.sweep import SweepDirective
from soc_poc.states import InvestigationState
from soc_poc.transcript import TranscriptLogger

ROOT = Path(__file__).resolve().parent.parent

SLICE = LogSlice(
    slice_id="ps-test-w1",
    file="dns_resolver.log",
    source="dns_resolver",
    host="wks-4471",
    time_range="t0/t1",
    reason="unit test",
    start_line=1,
    end_line=1,
    lines=[LogLine(ref="dns_resolver.log:L1", text="a line")],
)

DIRECTIVE = SweepDirective(
    alert_restatement="a detector flagged something",
    indicators=["example.net"],
    relevance_criteria="anything involving the indicator",
    explicitly_irrelevant=[],
    time_window="",
)

TASKING = GruntTasking(
    task_id="t-1",
    investigation_id="inv-test",
    iteration=0,
    instruction="read it",
    commander_intent="testing the boundary",
    directive=DIRECTIVE,
    data_slice=SLICE,
)


class _Client:
    """Minimal LLMClient stand-in whose behaviour each test chooses."""

    def __init__(self, config: Any, behaviour: str) -> None:
        self.config = config
        self.role = "grunt"
        self._behaviour = behaviour

    async def complete_json(self, **kwargs: Any) -> LLMResponse:
        if self._behaviour == "transport":
            raise LLMTransportError("connection reset by peer")
        return LLMResponse(
            text="{not json at all",
            model="fake",
            finish_reason="stop",
            usage={},
            latency_ms=1.0,
        )

    async def aclose(self) -> None:
        return None


@pytest.fixture()
def transcript(tmp_path: Path) -> TranscriptLogger:
    logger = TranscriptLogger(tmp_path / "t.jsonl", "inv-test")
    yield logger
    logger.close()


async def test_transport_failure_becomes_a_record(transcript: TranscriptLogger) -> None:
    config = load_config(ROOT / "config" / "config.toml")
    outcome = await run_grunt_task(
        TASKING, _Client(config.grunt, "transport"), config.run, transcript
    )
    assert isinstance(outcome, GruntFailure)
    assert outcome.reason == "transport"
    assert outcome.task_id == "t-1"
    # The commander must still be able to see what was attempted and why.
    assert outcome.commander_intent == "testing the boundary"


async def test_unparseable_output_is_retried_once_then_recorded(
    transcript: TranscriptLogger,
) -> None:
    config = load_config(ROOT / "config" / "config.toml")
    run = RunConfig(max_validation_retries=1)
    outcome = await run_grunt_task(TASKING, _Client(config.grunt, "garbage"), run, transcript)
    assert isinstance(outcome, GruntFailure)
    assert outcome.reason == "schema"
    assert outcome.attempts == 2  # one try, one feedback retry, then an explicit failure
    assert outcome.validation_errors


async def test_iteration_cap_stops_the_loop_and_still_produces_a_brief(tmp_path: Path) -> None:
    """A cap hit is a coverage gap on the brief, not a failed run."""
    config = load_config(ROOT / "config" / "config.toml")
    config = config.model_copy(
        update={
            "run": config.run.model_copy(
                update={"output_dir": str(tmp_path), "max_iterations": 1}
            )
        }
    )
    result, paths = await run_investigation(config, backend="stub", investigation_id="inv-cap")

    assert result.terminal_state is InvestigationState.DONE
    assert result.brief is not None

    states = [
        record["to_state"]
        for record in (json.loads(line) for line in paths.transcript.read_text().splitlines())
        if record["kind"] == "state_transition"
    ]
    assert "ABORTED_ITERATION_CAP" in states
    assert states[-1] == "DONE"
