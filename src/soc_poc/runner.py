"""Wiring: config + fixtures + clients + transcript -> one investigation on disk.

This is the only place that decides which client implementation is in play, so the
orchestrator, commander and grunt code never learn whether they are talking to a GPU or
to the offline stub.

Output layout, one directory per run:

    out/<investigation_id>/
        transcript.jsonl   canonical: every LLM call, transition and validation, one
                           JSON object per line, flushed as it goes
        transcript.json    readable view of the same thing, written at close
        brief.json         the artifact for the operator (absent if the run failed)
        run_meta.json      what produced it: config, models, git sha, terminal state
        stats.json         performance counters, for comparing runs
"""

from __future__ import annotations

import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from soc_poc.config import AppConfig
from soc_poc.control import clear_marker, write_marker
from soc_poc.llm.base import LLMClient
from soc_poc.llm.stub_client import StubClient
from soc_poc.llm.vllm_client import VLLMClient
from soc_poc.loader import load_run_inputs, scan_catalog_for_injection, write_json
from soc_poc.orchestrator import Orchestrator, RunResult
from soc_poc.preflight import preflight
from soc_poc.progress import NullProgress, ProgressSink
from soc_poc.states import InvestigationState
from soc_poc.stats import ResourceSampler, build_stats, capture_vllm_metrics
from soc_poc.transcript import TranscriptLogger, render_pretty

Backend = Literal["vllm", "stub"]


class RunPaths(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    run_dir: Path
    transcript: Path
    transcript_pretty: Path
    brief: Path
    meta: Path
    stats: Path


def _git_sha(root: Path) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def make_paths(config: AppConfig, investigation_id: str) -> RunPaths:
    run_dir = config.path(config.run.output_dir) / investigation_id
    return RunPaths(
        run_dir=run_dir,
        transcript=run_dir / "transcript.jsonl",
        transcript_pretty=run_dir / "transcript.json",
        brief=run_dir / "brief.json",
        meta=run_dir / "run_meta.json",
        stats=run_dir / "stats.json",
    )


def _build_clients(
    config: AppConfig, backend: Backend, transcript: TranscriptLogger
) -> tuple[LLMClient, LLMClient]:
    if backend == "stub":
        return (
            StubClient(config.commander, transcript),
            StubClient(config.grunt, transcript),
        )
    return (
        VLLMClient(config.commander, config.structured_output, transcript),
        VLLMClient(config.grunt, config.structured_output, transcript),
    )


async def run_investigation(
    config: AppConfig,
    *,
    backend: Backend = "vllm",
    investigation_id: str | None = None,
    progress: ProgressSink | None = None,
    case_name: str = "",
) -> tuple[RunResult, RunPaths]:
    # Timestamp for sorting, random suffix because a timestamp alone is only
    # second-resolution: two runs started in the same second would share an output
    # directory and interleave their transcripts, which would quietly corrupt the one
    # artifact this PoC exists to produce.
    investigation_id = investigation_id or (
        f"inv-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:4]}"
    )
    paths = make_paths(config, investigation_id)
    progress = progress or NullProgress()
    transcript = TranscriptLogger(paths.transcript, investigation_id)

    alert, inventory, catalog = load_run_inputs(
        config.path(config.fixtures.alert),
        config.path(config.fixtures.logs_dir),
        slice_token_budget=config.run.slice_token_budget,
        chars_per_token=config.run.chars_per_token,
    )
    # Injection scan runs once over all raw content at load time; hits ride along to
    # the brief because an attempt to address an AI system is itself a signal.
    injection_signals = scan_catalog_for_injection(catalog)
    transcript.log_event(
        "inputs_loaded",
        {
            "alert_id": alert.alert_id,
            "files": [item.model_dump() for item in inventory],
            "slices": len(catalog),
            "injection_signals": [s.model_dump() for s in injection_signals],
            "backend": backend,
        },
    )

    endpoints = {"commander": config.commander.base_url, "grunt": config.grunt.base_url}
    metrics_before = capture_vllm_metrics(endpoints) if backend == "vllm" else {}
    sampler = ResourceSampler().start() if backend == "vllm" else None
    started = time.monotonic()

    commander_client, grunt_client = _build_clients(config, backend, transcript)
    write_marker(
        paths.run_dir,
        investigation_id=investigation_id,
        case=case_name or str(config.path(config.fixtures.logs_dir).parent),
        backend=backend,
    )

    try:
        if backend == "vllm":
            # Hard gate: no investigation starts against endpoints that have not proved
            # they can round-trip guided JSON.
            check = await preflight(
                [config.commander, config.grunt], config.structured_output, transcript
            )
            if not check.ok:
                result = RunResult(
                    terminal_state=InvestigationState.FAILED_PREFLIGHT,
                    brief=None,
                    failure_reason=check.report(),
                )
                _write_meta(config, paths, investigation_id, backend, result)
                return result, paths

        orchestrator = Orchestrator(
            config=config,
            commander_client=commander_client,
            grunt_client=grunt_client,
            transcript=transcript,
            alert=alert,
            inventory=inventory,
            catalog=catalog,
            injection_signals=injection_signals,
            investigation_id=investigation_id,
            progress=progress,
            run_dir=paths.run_dir,
        )
        result = await orchestrator.run()
    finally:
        await commander_client.aclose()
        await grunt_client.aclose()
        transcript.close()
        # The marker is how abort.py knows this run is alive. Leaving one behind would
        # make a finished run look abortable forever.
        clear_marker(paths.run_dir)

    wall_clock_s = time.monotonic() - started
    if sampler is not None:
        sampler.stop()

    if result.brief is not None:
        write_json(paths.brief, result.brief.model_dump())
    _write_meta(config, paths, investigation_id, backend, result)

    # Convenience artifacts, written last and guarded: a run that has already produced
    # its brief must not fail because a readable view or a counter could not be written.
    try:
        render_pretty(paths.transcript, paths.transcript_pretty)
        write_json(
            paths.stats,
            build_stats(
                transcript_path=paths.transcript,
                investigation_id=investigation_id,
                case=case_name or str(config.path(config.fixtures.logs_dir).parent),
                backend=backend,
                terminal_state=result.terminal_state.value,
                wall_clock_s=wall_clock_s,
                metrics_before=metrics_before,
                metrics_after=capture_vllm_metrics(endpoints) if backend == "vllm" else {},
                sampler=sampler,
                brief=result.brief,
                inventory=inventory,
                slice_count=len(catalog),
                concurrency_configured=config.run.max_concurrent_grunts,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - a stats file is never worth a failed run
        transcript_note = f"could not write run artifacts: {type(exc).__name__}: {exc}"
        write_json(paths.run_dir / "artifacts_error.txt", transcript_note)

    return result, paths


def _write_meta(
    config: AppConfig,
    paths: RunPaths,
    investigation_id: str,
    backend: str,
    result: RunResult,
) -> None:
    write_json(
        paths.meta,
        {
            "investigation_id": investigation_id,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "backend": backend,
            "terminal_state": result.terminal_state.value,
            "failure_reason": result.failure_reason,
            "git_sha": _git_sha(config.root),
            "models": {
                name: model.model_dump(exclude={"api_key"})
                for name, model in config.models.items()
            },
            "run": config.run.model_dump(),
            "structured_output": config.structured_output.model_dump(),
        },
    )
