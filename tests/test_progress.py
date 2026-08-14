"""The progress sink: tokens reach the console layer, and the transcript is unaffected."""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

from soc_poc.config import load_config
from soc_poc.progress import ConsoleProgress, NullProgress
from soc_poc.runner import run_investigation

ROOT = Path(__file__).resolve().parent.parent


class _Recorder(NullProgress):
    """Wants tokens, and remembers everything it was told."""

    wants_tokens = True

    def __init__(self) -> None:
        self.tokens: list[tuple[str, str]] = []
        self.states: list[tuple[str, str]] = []
        self.outcomes: list[tuple[str, bool]] = []

    def token(self, channel: str, text: str) -> None:
        self.tokens.append((channel, text))

    def state_changed(self, from_state: str, to_state: str, iteration: int) -> None:
        self.states.append((from_state, to_state))

    def task_outcome(self, task_id: str, slice_id: str, summary: str, ok: bool) -> None:
        self.outcomes.append((task_id, ok))


def _config(tmp_path: Path):
    cfg = load_config(ROOT / "config" / "config.toml")
    return cfg.model_copy(update={"run": cfg.run.model_copy(update={"output_dir": str(tmp_path)})})


async def test_reasoning_tokens_reach_the_sink(tmp_path: Path) -> None:
    recorder = _Recorder()
    await run_investigation(
        _config(tmp_path), backend="stub", investigation_id="inv-prog", progress=recorder
    )

    assert any(channel == "reasoning" for channel, _ in recorder.tokens)
    assert ("RECEIVED", "TASKING") in recorder.states
    assert ("TASKING", "SWEEPING") in recorder.states
    assert recorder.outcomes, "grunt outcomes must be reported to the sink"


async def test_a_silent_sink_changes_nothing_about_the_record(tmp_path: Path) -> None:
    """Progress output is a convenience. The transcript is the record, either way."""
    loud, _ = await run_investigation(
        _config(tmp_path / "a"), backend="stub", investigation_id="inv-loud", progress=_Recorder()
    )
    quiet, quiet_paths = await run_investigation(
        _config(tmp_path / "b"), backend="stub", investigation_id="inv-quiet"
    )

    assert loud.terminal_state == quiet.terminal_state
    kinds = {
        json.loads(line)["kind"] for line in quiet_paths.transcript.read_text().splitlines()
    }
    assert {"llm_call", "state_transition", "investigation_finished"} <= kinds


def test_console_writes_to_its_stream_and_wraps() -> None:
    buffer = io.StringIO()
    console = ConsoleProgress(buffer)
    console.state_changed("PLANNING", "DISPATCHED", 0)
    console.token("reasoning", "word " * 80)
    console.token("content", '{"ignored": true}')
    console.task_outcome("t-1", "slice-1", "2 observations", ok=True)

    output = buffer.getvalue()
    assert "PLANNING → DISPATCHED" in output
    assert "word" in output
    # Content is the artifact; it belongs in the brief, not scrolling past the operator.
    assert "ignored" not in output
    assert "t-1" in output


def test_null_sink_declines_tokens() -> None:
    """The transport checks this to decide whether to stream at all."""
    assert NullProgress().wants_tokens is False


async def test_concurrent_runs_get_distinct_directories(tmp_path: Path) -> None:
    """Two runs in the same second must not share an output directory.

    A timestamp alone is second-resolution; a collision would interleave two runs'
    transcripts into one file and quietly corrupt the corpus.
    """
    config = _config(tmp_path)
    (_, first), (_, second) = await asyncio.gather(
        run_investigation(config, backend="stub"),
        run_investigation(config, backend="stub"),
    )
    assert first.run_dir != second.run_dir
