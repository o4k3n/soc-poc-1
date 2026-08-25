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
from soc_poc.schemas.directive import TaskDirective
from soc_poc.schemas.slice import LogLine, LogSlice
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

DIRECTIVE = TaskDirective(
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


# -- a crash inside the machine must not cost the run ------------------------------------


async def test_a_handler_crash_routes_to_a_legal_state_and_keeps_the_evidence(
    tmp_path: Path, monkeypatch
) -> None:
    """A real run died at step 22 and produced no brief at all.

    A malformed reference ("L978", missing the file prefix) reached `reproduce_command`,
    `int("")` raised, and the exception went straight through the orchestrator loop —
    discarding 21 completed steps that had already been paid for and recorded. "Failures
    are values" was only enforced at the worker boundary; this pins the general rule.
    """
    from soc_poc import orchestrator as orch

    config = load_config(ROOT / "config" / "config.toml")
    config = config.model_copy(
        update={"run": config.run.model_copy(update={"output_dir": str(tmp_path)})}
    )

    real = orch.execute_readonly
    calls = {"n": 0}

    def explode_on_the_third(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 3:
            raise ValueError("invalid literal for int() with base 10: ''")
        return real(*args, **kwargs)

    monkeypatch.setattr(orch, "execute_readonly", explode_on_the_third)

    result, paths = await run_investigation(
        config, backend="stub", investigation_id="inv-crash"
    )

    # The run survives and still produces the artifact.
    assert result.terminal_state is InvestigationState.DONE
    assert result.brief is not None

    records = [json.loads(line) for line in paths.transcript.read_text().splitlines()]
    crashes = [r for r in records if r["kind"] == "handler_crashed"]
    assert len(crashes) == 1
    assert crashes[0]["payload"]["routed_to"] == "INVESTIGATING"

    # The failed step is in the ledger as a failure, not silently missing.
    failed = [e for e in result.brief.step_ledger if e.error]
    assert len(failed) == 1
    assert "invalid literal" in failed[0].error
    # And the steps taken before it are still there.
    assert result.brief.steps_taken > len(failed)


def test_an_identical_action_is_recognised_as_a_repeat() -> None:
    """The backstop for the loop.

    A graded run issued `search /<addr>/ in dhcp.log` twice, byte for byte, because the
    first answer had aged out of the rendered ledger. The rendering is fixed; this makes a
    repeat cost no work and, more usefully, tells the commander it is repeating itself.
    """
    from soc_poc.corpus import Corpus
    from soc_poc.evidence import Evidence
    from soc_poc.actions import execute_readonly
    from soc_poc.orchestrator import Orchestrator
    from soc_poc.schemas.action import ActionKind, InvestigativeAction

    corpus = Corpus({"dhcp.log": ["ACK 10.0.0.5 wks-2291", "ACK 10.0.0.6 wks-1100"]})
    ask = lambda why: InvestigativeAction(  # noqa: E731 - reasoning differs, question does not
        reasoning=why, expectation="a hostname", action=ActionKind.SEARCH,
        pattern="10.0.0.5", file="dhcp.log",
    )
    first, again = ask("who is this host"), ask("I still do not know the host")

    orchestrator = Orchestrator.__new__(Orchestrator)  # no servers needed for this
    orchestrator._evidence = Evidence()
    orchestrator._evidence.add(execute_readonly(first, corpus, index=1))

    # Prose differs, the question does not.
    assert orchestrator._previous_identical(again) is not None
    assert orchestrator._previous_identical(again).index == 1

    # A genuinely different question is not suppressed.
    other = ask("who is this host").model_copy(update={"file": "dns.log"})
    assert orchestrator._previous_identical(other) is None


def test_a_failed_step_is_not_treated_as_an_answer() -> None:
    """Re-asking after an error is legitimate — the first attempt produced nothing."""
    from soc_poc.evidence import Evidence, Step
    from soc_poc.orchestrator import Orchestrator
    from soc_poc.schemas.action import ActionKind, InvestigativeAction

    action = InvestigativeAction(
        reasoning="r", expectation="e", action=ActionKind.SEARCH, pattern="a[", file="dns.log"
    )
    orchestrator = Orchestrator.__new__(Orchestrator)
    orchestrator._evidence = Evidence()
    orchestrator._evidence.add(
        Step(index=1, action=action, summary="failed", error="bad regex")
    )
    assert orchestrator._previous_identical(action) is None
