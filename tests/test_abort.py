"""Operator abort: both modes, and the guarantee that cancelled work is still recorded."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from soc_poc.config import load_config
from soc_poc.control import (
    ABORT_SENTINEL,
    RUNNING_MARKER,
    AbortMode,
    active_runs,
    read_abort,
    request_abort,
    stale_runs,
    write_marker,
)
from soc_poc.llm.stub_client import StubClient
from soc_poc.loader import load_run_inputs, scan_catalog_for_injection
from soc_poc.orchestrator import Orchestrator
from soc_poc.progress import NullProgress
from soc_poc.runner import make_paths, run_investigation
from soc_poc.states import InvestigationState
from soc_poc.transcript import TranscriptLogger

ROOT = Path(__file__).resolve().parent.parent


def _config(tmp_path: Path):
    cfg = load_config(ROOT / "config" / "config.toml")
    return cfg.model_copy(update={"run": cfg.run.model_copy(update={"output_dir": str(tmp_path)})})


class _AbortOnFirstOutcome(NullProgress):
    """Requests an abort the moment the first grunt report lands.

    This is how the test reaches the interesting state: an abort that arrives when work
    has been collected but the investigation is not finished. Using the progress sink as
    the trigger keeps the orchestrator untouched by test scaffolding.
    """

    def __init__(self, run_dir: Path, mode: AbortMode) -> None:
        self.run_dir = run_dir
        self.mode = mode
        self.fired = False

    def task_outcome(self, task_id: str, slice_id: str, summary: str, ok: bool) -> None:
        if not self.fired:
            self.fired = True
            request_abort(self.run_dir, self.mode, requested_by="test")


# -- graceful --------------------------------------------------------------------------


async def test_graceful_abort_still_produces_a_brief(tmp_path: Path) -> None:
    config = _config(tmp_path)
    paths = make_paths(config, "inv-abort-graceful")
    paths.run_dir.mkdir(parents=True, exist_ok=True)

    result, paths = await run_investigation(
        config,
        backend="stub",
        investigation_id="inv-abort-graceful",
        progress=_AbortOnFirstOutcome(paths.run_dir, AbortMode.GRACEFUL),
    )

    assert result.terminal_state is InvestigationState.DONE
    assert result.brief is not None, "a graceful abort owes the operator a brief"
    assert "aborted by operator" in result.failure_reason

    states = [
        record["to_state"]
        for record in (json.loads(l) for l in paths.transcript.read_text().splitlines())
        if record["kind"] == "state_transition"
    ]
    assert "ABORTING" in states
    assert states[-1] == "DONE"


async def test_graceful_abort_before_any_work_stops_without_a_brief(tmp_path: Path) -> None:
    """Synthesizing over zero reports spends two minutes to say nothing."""
    config = _config(tmp_path)
    paths = make_paths(config, "inv-abort-early")
    paths.run_dir.mkdir(parents=True, exist_ok=True)
    request_abort(paths.run_dir, AbortMode.GRACEFUL, requested_by="test")

    result, _ = await run_investigation(
        config, backend="stub", investigation_id="inv-abort-early"
    )

    assert result.terminal_state is InvestigationState.ABORTED_BY_OPERATOR
    assert result.brief is None


# -- hard ------------------------------------------------------------------------------


async def test_hard_abort_writes_no_brief_but_keeps_the_transcript(tmp_path: Path) -> None:
    config = _config(tmp_path)
    paths = make_paths(config, "inv-abort-hard")
    paths.run_dir.mkdir(parents=True, exist_ok=True)

    result, paths = await run_investigation(
        config,
        backend="stub",
        investigation_id="inv-abort-hard",
        progress=_AbortOnFirstOutcome(paths.run_dir, AbortMode.HARD),
    )

    assert result.terminal_state is InvestigationState.ABORTED_BY_OPERATOR
    assert result.brief is None
    assert not paths.brief.exists()
    # The transcript is written as the run goes, so an interrupted run still has one.
    records = [json.loads(l) for l in paths.transcript.read_text().splitlines()]
    assert any(r["kind"] == "llm_call" for r in records)
    assert any(r["kind"] == "abort_requested" for r in records)


class _StaggeredStub(StubClient):
    """Makes the second grunt task slow, so it is still running when the abort lands.

    The delay is keyed to the task id rather than a call counter, because the timing
    that matters is specific: the orchestrator drains its registry in order, and the
    task it is *already awaiting* always runs to completion. Cancellation can only bite
    a task later in the queue, so that is the one that has to still be in flight.
    """

    async def complete_json(self, **kwargs):  # type: ignore[override]
        if str(kwargs.get("task_id", "")).endswith("t1"):
            await asyncio.sleep(30)  # cancelled long before this elapses
        return await super().complete_json(**kwargs)


async def test_hard_abort_records_cancelled_work_as_aborted(tmp_path: Path) -> None:
    """Unexamined ground must be visible as unexamined, never as absence of evidence."""
    config = _config(tmp_path)
    paths = make_paths(config, "inv-abort-records")
    paths.run_dir.mkdir(parents=True, exist_ok=True)

    transcript = TranscriptLogger(paths.transcript, "inv-abort-records")
    alert, summaries, catalog = load_run_inputs(
        config.path(config.fixtures.alert),
        config.path(config.fixtures.patterns_dir),
        config.path(config.fixtures.logs_dir),
    )
    orchestrator = Orchestrator(
        config=config,
        commander_client=_StaggeredStub(config.commander, transcript),
        grunt_client=_StaggeredStub(config.grunt, transcript),
        transcript=transcript,
        alert=alert,
        summaries=summaries,
        catalog=catalog,
        injection_signals=scan_catalog_for_injection(catalog),
        investigation_id="inv-abort-records",
        progress=_AbortOnFirstOutcome(paths.run_dir, AbortMode.HARD),
        run_dir=paths.run_dir,
    )
    result = await orchestrator.run()
    transcript.close()

    assert result.terminal_state is InvestigationState.ABORTED_BY_OPERATOR
    finished = [
        json.loads(line)
        for line in paths.transcript.read_text().splitlines()
        if json.loads(line)["kind"] == "investigation_finished"
    ][0]
    assert "aborted" in finished["payload"]["failure_reasons"]


async def test_work_that_already_finished_is_not_relabelled_as_aborted(tmp_path: Path) -> None:
    """A hard abort must not discard a report a grunt had already produced.

    The instant stub finishes every task before the orchestrator drains the registry, so
    a naive implementation cancels completed tasks and files real reports as "aborted" --
    losing evidence and lying about it in the ledger.
    """
    config = _config(tmp_path)
    paths = make_paths(config, "inv-abort-nolie")
    paths.run_dir.mkdir(parents=True, exist_ok=True)

    result, paths = await run_investigation(
        config,
        backend="stub",
        investigation_id="inv-abort-nolie",
        progress=_AbortOnFirstOutcome(paths.run_dir, AbortMode.HARD),
    )

    finished = [
        json.loads(line)
        for line in paths.transcript.read_text().splitlines()
        if json.loads(line)["kind"] == "investigation_finished"
    ][0]
    assert result.terminal_state is InvestigationState.ABORTED_BY_OPERATOR
    assert "aborted" not in finished["payload"]["failure_reasons"]
    assert finished["payload"]["outcomes"] == 2


# -- control files ---------------------------------------------------------------------


def test_marker_liveness_distinguishes_running_from_crashed(tmp_path: Path) -> None:
    live = tmp_path / "inv-live"
    dead = tmp_path / "inv-dead"
    live.mkdir()
    dead.mkdir()
    write_marker(live, investigation_id="inv-live", case="c", backend="stub")

    # A pid that cannot exist: marker left behind by a run that was killed.
    marker = json.loads((live / RUNNING_MARKER).read_text())
    marker["pid"] = 2**31 - 1
    marker["investigation_id"] = "inv-dead"
    marker["run_dir"] = str(dead)
    (dead / RUNNING_MARKER).write_text(json.dumps(marker), encoding="utf-8")

    assert [m.investigation_id for m in active_runs(tmp_path)] == ["inv-live"]
    assert [m.investigation_id for m in stale_runs(tmp_path)] == ["inv-dead"]


def test_an_unparseable_sentinel_still_stops_the_run(tmp_path: Path) -> None:
    """Refusing to stop because the stop request was malformed is the wrong failure."""
    (tmp_path / ABORT_SENTINEL).write_text("", encoding="utf-8")
    request = read_abort(tmp_path)
    assert request is not None
    assert request.mode is AbortMode.GRACEFUL


async def test_the_brief_itself_records_that_the_run_was_interrupted(tmp_path: Path) -> None:
    """A graceful abort ends in DONE, so the artifact must say so structurally.

    Asking the commander to mention the abort in coverage_gaps is a request, not a
    guarantee; someone reading brief.json alone must not mistake an interrupted run for
    a complete one.
    """
    config = _config(tmp_path)
    paths = make_paths(config, "inv-abort-flag")
    paths.run_dir.mkdir(parents=True, exist_ok=True)

    result, _ = await run_investigation(
        config,
        backend="stub",
        investigation_id="inv-abort-flag",
        progress=_AbortOnFirstOutcome(paths.run_dir, AbortMode.GRACEFUL),
    )

    assert result.brief is not None
    assert result.brief.terminal_state == "DONE"
    assert result.brief.aborted_by_operator is True


async def test_an_uninterrupted_brief_is_not_flagged(tmp_path: Path) -> None:
    result, _ = await run_investigation(
        _config(tmp_path), backend="stub", investigation_id="inv-clean"
    )
    assert result.brief is not None
    assert result.brief.aborted_by_operator is False
