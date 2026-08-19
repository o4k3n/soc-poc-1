"""The two convenience artifacts: a readable transcript, and comparable run counters."""

from __future__ import annotations

import json
from pathlib import Path

from soc_poc.config import load_config
from soc_poc.runner import run_investigation
from soc_poc.stats import ResourceSampler, _metric_delta, build_stats, format_summary
from soc_poc.transcript import TranscriptLogger, render_pretty

ROOT = Path(__file__).resolve().parent.parent


def _config(tmp_path: Path):
    cfg = load_config(ROOT / "config" / "config.toml")
    return cfg.model_copy(update={"run": cfg.run.model_copy(update={"output_dir": str(tmp_path)})})


# -- readable transcript ---------------------------------------------------------------


def test_multiline_strings_become_arrays_of_lines(tmp_path: Path) -> None:
    """Indenting alone leaves prompts as one escaped line, which is the whole problem."""
    log = TranscriptLogger(tmp_path / "t.jsonl", "inv-1")
    log.log_llm_call(
        role="grunt", model="m", endpoint="e", task_id="t", parent_task_id=None,
        state="COLLECTING", attempt=1, schema_name="grunt_report", params={},
        request_messages=[{"role": "system", "content": "line one\nline two\nline three"}],
        response_text='{"ok": true}', raw_response=None, finish_reason="stop",
        usage={}, latency_ms=1.0,
    )
    log.close()

    assert render_pretty(tmp_path / "t.jsonl", tmp_path / "t.json") == 2
    records = json.loads((tmp_path / "t.json").read_text())
    content = records[1]["request_messages"][0]["content"]
    assert content == ["line one", "line two", "line three"]
    # Reversible: joining recovers the canonical string.
    assert "\n".join(content) == "line one\nline two\nline three"


def test_single_line_strings_are_left_alone(tmp_path: Path) -> None:
    log = TranscriptLogger(tmp_path / "t.jsonl", "inv-1")
    log.log_event("thing", {"note": "no newlines here"})
    log.close()
    render_pretty(tmp_path / "t.jsonl", tmp_path / "t.json")
    assert json.loads((tmp_path / "t.json").read_text())[1]["payload"]["note"] == "no newlines here"


def test_a_truncated_final_line_does_not_lose_the_rest(tmp_path: Path) -> None:
    """Exactly what a killed run leaves behind; the readable view must still render."""
    path = tmp_path / "t.jsonl"
    path.write_text('{"kind": "a", "ts": "x"}\n{"kind": "b", "trunc', encoding="utf-8")
    assert render_pretty(path, tmp_path / "t.json") == 2
    records = json.loads((tmp_path / "t.json").read_text())
    assert records[0]["kind"] == "a"
    assert records[1]["kind"] == "unparseable_line"


def test_a_missing_transcript_is_survivable(tmp_path: Path) -> None:
    assert render_pretty(tmp_path / "nope.jsonl", tmp_path / "out.json") == 0


# -- stats -----------------------------------------------------------------------------


async def test_a_run_writes_stats_and_a_readable_transcript(tmp_path: Path) -> None:
    _, paths = await run_investigation(
        _config(tmp_path), backend="stub", investigation_id="inv-stats"
    )
    assert paths.transcript_pretty.exists()
    assert paths.stats.exists()

    stats = json.loads(paths.stats.read_text())
    assert stats["backend"] == "stub"
    assert stats["terminal_state"] == "DONE"
    assert stats["work"]["slices"] > 0
    assert stats["work"]["lines_swept"] > 0
    assert stats["roles"]["grunt"]["calls"] > 0
    assert stats["quality"]["slices_swept"] == stats["work"]["slices"]
    # Phases are derived from transition timestamps and must name real states.
    assert set(stats["time"]["by_phase_s"]) <= {
        "RECEIVED", "TASKING", "SWEEPING", "COLLECTING", "PLANNING",
        "DISPATCHED", "SYNTHESIZING", "ABORTING", "ABORTED_ITERATION_CAP",
    }
    assert format_summary(stats)


async def test_stats_degrade_rather_than_fail_without_a_gpu(tmp_path: Path) -> None:
    """Stub runs have no endpoints to scrape and CI has no GPU; neither is an error."""
    _, paths = await run_investigation(
        _config(tmp_path), backend="stub", investigation_id="inv-nogpu"
    )
    stats = json.loads(paths.stats.read_text())
    assert stats["server"] == {}
    assert stats["machine"] is None


def test_rejection_reasons_are_counted_per_report_not_per_problem() -> None:
    """A report citing six fabricated references is one rejection, not six."""
    from soc_poc.transcript import TranscriptLogger as TL

    tmp = Path("/tmp/claude-1000") if Path("/tmp/claude-1000").exists() else Path("/tmp")
    log_path = tmp / "reasons.jsonl"
    log = TL(log_path, "inv-r")
    log.log_event(
        "grunt_validation",
        {"task_id": "t", "attempt": 1, "ok": False, "problems": [
            "findings[0] cites 'a:L1', which is not in slice s",
            "findings[0] cites 'a:L2', which is not in slice s",
            "findings[0] cites 'a:L3', which is not in slice s",
        ]},
    )
    log.close()
    stats = build_stats(
        transcript_path=log_path, investigation_id="inv-r", case="c", backend="stub",
        terminal_state="DONE", wall_clock_s=1.0, metrics_before={}, metrics_after={},
        sampler=None, brief=None, inventory=[], slice_count=0,
    )
    assert stats["work"]["rejection_reasons"] == {"fabricated_reference": 1}
    log_path.unlink(missing_ok=True)


def test_server_counters_are_reported_as_deltas() -> None:
    """They are monotonic since server start, so a run is the difference."""
    before = {"grunt": {"vllm:prompt_tokens_total": 1000.0,
                        "vllm:prefix_cache_queries_total": 100.0,
                        "vllm:prefix_cache_hits_total": 20.0}}
    after = {"grunt": {"vllm:prompt_tokens_total": 3000.0,
                       "vllm:prefix_cache_queries_total": 300.0,
                       "vllm:prefix_cache_hits_total": 120.0}}
    delta = _metric_delta(before, after)["grunt"]
    assert delta["prompt_tokens"] == 2000
    assert delta["prefix_cache_hit_rate"] == 0.5


def test_absent_measurements_are_null_not_zero() -> None:
    """GB10 reports GPU memory as [N/A]; reporting 0 would be a lie."""
    summary = ResourceSampler().summary()
    assert summary["gpu_memory_used_gb"] is None
    assert summary["gpu_utilization_pct"] is None


# -- the estimate ----------------------------------------------------------------------


def _fake_history(tmp_path: Path, *, slices: int, collecting_s: float, concurrency: int = 8):
    run = tmp_path / "inv-20260101T000000Z-aaaa"
    run.mkdir(parents=True)
    (run / "stats.json").write_text(
        json.dumps({
            "investigation_id": "inv-20260101T000000Z-aaaa",
            "backend": "vllm",
            "concurrency_configured": concurrency,
            "time": {"by_phase_s": {"COLLECTING": collecting_s}},
            "work": {"slices": slices},
            "roles": {"grunt": {"calls": slices}},
        }),
        encoding="utf-8",
    )
    return tmp_path


def test_the_estimate_uses_observed_seconds_per_slice(tmp_path: Path) -> None:
    """The old estimate modelled call latency and concurrency separately and was 8x out.
    Observed wall-clock per slice already contains retries, stragglers and the tail."""
    from soc_poc.stats import estimate_sweep

    out = _fake_history(tmp_path, slices=83, collecting_s=1880.0)
    minutes, basis = estimate_sweep(out, slices=83, concurrency=8)
    assert 30 < minutes < 33  # the run this is modelled on took 31.3 min collecting
    assert "per slice observed" in basis


def test_the_estimate_scales_with_slice_count(tmp_path: Path) -> None:
    from soc_poc.stats import estimate_sweep

    out = _fake_history(tmp_path, slices=83, collecting_s=1880.0)
    small, _ = estimate_sweep(out, slices=10, concurrency=8)
    large, _ = estimate_sweep(out, slices=500, concurrency=8)
    assert large > small * 40


def test_raising_concurrency_lowers_the_estimate(tmp_path: Path) -> None:
    from soc_poc.stats import estimate_sweep

    out = _fake_history(tmp_path, slices=83, collecting_s=1880.0, concurrency=8)
    base, _ = estimate_sweep(out, slices=83, concurrency=8)
    doubled, basis = estimate_sweep(out, slices=83, concurrency=16)
    assert doubled < base
    assert "scaled for concurrency" in basis


def test_stub_runs_are_not_used_as_history(tmp_path: Path) -> None:
    """A stub run takes milliseconds and says nothing about GPU wall clock."""
    from soc_poc.stats import estimate_sweep

    run = tmp_path / "inv-stub"
    run.mkdir(parents=True)
    (run / "stats.json").write_text(
        json.dumps({"backend": "stub", "time": {"by_phase_s": {"COLLECTING": 0.1}},
                    "work": {"slices": 83}, "roles": {"grunt": {"calls": 83}}}),
        encoding="utf-8",
    )
    _, basis = estimate_sweep(tmp_path, slices=83, concurrency=8)
    assert "no previous run" in basis
