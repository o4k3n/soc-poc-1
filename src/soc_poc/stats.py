"""Performance counters for a run, written to stats.json when it finishes.

The point is comparing runs: change a prompt, a model, a chunk size, and see what it did
to cost, coverage and quality. So the numbers are grouped by what you would actually
compare — time, tokens, work done, quality, machine — and every one of them is derived
from something already recorded rather than estimated.

Three sources:

  * **the transcript** — per-call latency, token usage, retries, validation outcomes, and
    the state-transition timestamps that give per-phase wall clock;
  * **vLLM's /metrics** — server-side counters, snapshotted before and after the run and
    reported as deltas. This is where prefix-cache hit rate comes from, which is the
    number to watch for a sweep: every grunt shares a long identical prefix, so a low hit
    rate means the batching is not doing what the design assumes;
  * **nvidia-smi and /proc/meminfo** — sampled during the run.

Nothing here is allowed to fail a run. Every collector degrades to null: the stub backend
has no endpoints to scrape, CI has no GPU, and a stats file is a convenience, not the
artifact. `capture_*` functions swallow their own errors by design.

GB10 note: `memory.used`/`memory.total` come back as [N/A] from nvidia-smi because the
GPU shares the host's unified pool. Host memory from /proc/meminfo is the real signal and
GPU memory is reported as null rather than zero — an absent measurement and a measurement
of zero are different things.
"""

from __future__ import annotations

import json
import statistics
import subprocess
import threading
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

# Server-side counters worth a delta. Names are stable across recent vLLM releases; any
# that a build does not export are simply absent from the output.
_VLLM_COUNTERS = (
    "vllm:prompt_tokens_total",
    "vllm:generation_tokens_total",
    "vllm:request_success_total",
    "vllm:prefix_cache_queries_total",
    "vllm:prefix_cache_hits_total",
    "vllm:e2e_request_latency_seconds_count",
    "vllm:e2e_request_latency_seconds_sum",
    "vllm:time_to_first_token_seconds_count",
    "vllm:time_to_first_token_seconds_sum",
    "vllm:iteration_tokens_total_sum",
)

_SAMPLE_INTERVAL_S = 5.0


# -- machine sampling ------------------------------------------------------------------


class ResourceSampler:
    """Polls GPU and host memory on a background thread for the life of a run."""

    def __init__(self, interval_s: float = _SAMPLE_INTERVAL_S) -> None:
        self._interval = interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.gpu_util: list[float] = []
        self.gpu_power_w: list[float] = []
        self.gpu_temp_c: list[float] = []
        self.host_mem_used_gb: list[float] = []

    def start(self) -> ResourceSampler:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> ResourceSampler:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 2)
        return self

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._sample_gpu()
            self._sample_host()
            self._stop.wait(self._interval)

    def _sample_gpu(self) -> None:
        try:
            out = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=utilization.gpu,power.draw,temperature.gpu",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return
        for line in out.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) != 3:
                continue
            for value, sink in zip(parts, (self.gpu_util, self.gpu_power_w, self.gpu_temp_c)):
                try:
                    sink.append(float(value))
                except ValueError:
                    pass  # "[N/A]" -- absent, not zero
            break

    def _sample_host(self) -> None:
        try:
            fields = dict(
                (parts[0].rstrip(":"), int(parts[1]))
                for parts in (
                    line.split() for line in Path("/proc/meminfo").read_text().splitlines()
                )
                if len(parts) >= 2 and parts[1].isdigit()
            )
        except OSError:
            return
        total, available = fields.get("MemTotal"), fields.get("MemAvailable")
        if total and available is not None:
            self.host_mem_used_gb.append((total - available) / 1024 / 1024)

    def summary(self) -> dict[str, Any]:
        return {
            "samples": len(self.host_mem_used_gb),
            "sample_interval_s": self._interval,
            "gpu_utilization_pct": _spread(self.gpu_util),
            "gpu_power_w": _spread(self.gpu_power_w),
            "gpu_temp_c": _spread(self.gpu_temp_c),
            "host_memory_used_gb": _spread(self.host_mem_used_gb),
            # Unified memory: nvidia-smi reports [N/A] on GB10, so there is no separate
            # GPU memory figure to give. Null, not zero.
            "gpu_memory_used_gb": None,
        }


def _spread(values: list[float]) -> dict[str, float] | None:
    if not values:
        return None
    return {
        "mean": round(statistics.fmean(values), 1),
        "peak": round(max(values), 1),
        "min": round(min(values), 1),
    }


# -- server counters -------------------------------------------------------------------


def capture_vllm_metrics(endpoints: dict[str, str]) -> dict[str, dict[str, float]]:
    """Snapshot the counters we care about from each endpoint. Never raises."""
    snapshot: dict[str, dict[str, float]] = {}
    for role, base_url in endpoints.items():
        root = base_url[: -len("/v1")] if base_url.endswith("/v1") else base_url
        try:
            body = httpx.get(f"{root}/metrics", timeout=10.0).text
        except httpx.HTTPError:
            continue
        values: dict[str, float] = defaultdict(float)
        for line in body.splitlines():
            if not line.startswith("vllm:"):
                continue
            name = line.split("{")[0].split(" ")[0]
            if name not in _VLLM_COUNTERS:
                continue
            try:
                values[name] += float(line.rsplit(" ", 1)[1])
            except (IndexError, ValueError):
                continue
        if values:
            snapshot[role] = dict(values)
    return snapshot


def _metric_delta(
    before: dict[str, dict[str, float]], after: dict[str, dict[str, float]]
) -> dict[str, Any]:
    """Counters are monotonic since server start, so a run is the difference."""
    out: dict[str, Any] = {}
    for role, end in after.items():
        start = before.get(role, {})
        delta = {k: end[k] - start.get(k, 0.0) for k in end}
        prompt = delta.get("vllm:prompt_tokens_total", 0.0)
        gen = delta.get("vllm:generation_tokens_total", 0.0)
        queries = delta.get("vllm:prefix_cache_queries_total", 0.0)
        hits = delta.get("vllm:prefix_cache_hits_total", 0.0)
        e2e_n = delta.get("vllm:e2e_request_latency_seconds_count", 0.0)
        e2e_s = delta.get("vllm:e2e_request_latency_seconds_sum", 0.0)
        ttft_n = delta.get("vllm:time_to_first_token_seconds_count", 0.0)
        ttft_s = delta.get("vllm:time_to_first_token_seconds_sum", 0.0)
        out[role] = {
            "requests": int(delta.get("vllm:request_success_total", 0.0)),
            "prompt_tokens": int(prompt),
            "generation_tokens": int(gen),
            # The number to watch on a sweep: every grunt shares a long identical prefix
            # (system prompt + directive), so a low hit rate means that prefix is being
            # recomputed per call.
            "prefix_cache_hit_rate": round(hits / queries, 3) if queries else None,
            "mean_e2e_latency_s": round(e2e_s / e2e_n, 2) if e2e_n else None,
            "mean_time_to_first_token_s": round(ttft_s / ttft_n, 2) if ttft_n else None,
        }
    return out


# -- transcript-derived ----------------------------------------------------------------


def _parse_ts(value: str) -> float | None:
    try:
        return datetime.fromisoformat(value).timestamp()
    except (TypeError, ValueError):
        return None


def _phase_durations(records: list[dict]) -> dict[str, float]:
    """Seconds spent in each state, from the transition timestamps.

    A transition record is written when a state is *left*, so the time in a state is the
    gap between entering it and the transition out of it.
    """
    phases: Counter[str] = Counter()
    entered: float | None = None
    current = "RECEIVED"
    for record in records:
        if record.get("kind") != "state_transition":
            continue
        left_at = _parse_ts(record.get("ts", ""))
        if left_at is None:
            continue
        if entered is not None:
            phases[current] += left_at - entered
        entered, current = left_at, record["to_state"]
    return {state: round(seconds, 1) for state, seconds in phases.most_common()}


def _latency_spread(values: list[float]) -> dict[str, float] | None:
    if not values:
        return None
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "median_s": round(statistics.median(ordered), 1),
        "p95_s": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 1),
        "max_s": round(ordered[-1], 1),
        "total_s": round(sum(ordered), 1),
    }


def build_stats(
    *,
    transcript_path: Path,
    investigation_id: str,
    case: str,
    backend: str,
    terminal_state: str,
    wall_clock_s: float,
    metrics_before: dict,
    metrics_after: dict,
    sampler: ResourceSampler | None,
    brief: Any | None,
    inventory: list[Any],
    concurrency_configured: int = 0,
) -> dict[str, Any]:
    records = []
    try:
        with transcript_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass

    calls = [r for r in records if r.get("kind") == "llm_call"]
    by_role: dict[str, list[dict]] = defaultdict(list)
    for call in calls:
        by_role[call.get("role", "unknown")].append(call)

    def _tokens(subset: list[dict], key: str) -> int:
        return sum(int((c.get("usage") or {}).get(key, 0) or 0) for c in subset)

    roles = {
        role: {
            "calls": len(subset),
            "retries": sum(1 for c in subset if (c.get("attempt") or 1) > 1),
            "errors": sum(1 for c in subset if c.get("error")),
            "latency": _latency_spread([c.get("latency_ms", 0) / 1000 for c in subset]),
            "prompt_tokens": _tokens(subset, "prompt_tokens"),
            "completion_tokens": _tokens(subset, "completion_tokens"),
        }
        for role, subset in sorted(by_role.items())
    }

    validations = [r for r in records if r.get("kind") == "grunt_validation"]
    rejected = [v for v in validations if not v["payload"]["ok"]]
    # Counted once per rejected report per distinct reason: a report that cites six
    # fabricated references has one problem, not six, and reporting otherwise makes the
    # reason counts incomparable with the rejection count next to them.
    reasons: Counter[str] = Counter()
    for v in rejected:
        seen: set[str] = set()
        problems = v["payload"]["problems"]
        # A truncated reply is also an unparseable one. Counting both would inflate the
        # reason totals and hide which failure is actually worth fixing.
        truncated = any("cut off at the token limit" in p for p in problems)
        for problem in problems:
            if truncated:
                seen.add("truncated_at_token_limit")
                break
            if "representative_refs" in problem and "limit is" in problem:
                seen.add("refs_over_cap")
            elif "match_count" in problem:
                seen.add("match_count_inconsistent")
            elif "not in slice" in problem:
                seen.add("fabricated_reference")
            elif "positive result" in problem:
                seen.add("hit_recorded_as_check")
            elif "no representative_refs" in problem:
                seen.add("uncited_finding")
            elif "none of the lines it cites contain" in problem:
                seen.add("description_not_supported_by_lines")
            elif "slice_metadata.slice_id" in problem:
                seen.add("wrong_slice_id")
            elif "not valid JSON" in problem:
                seen.add("invalid_json")
            else:
                seen.add("other")
        reasons.update(seen)

    finished = next(
        (r["payload"] for r in records if r.get("kind") == "investigation_finished"), {}
    )
    grunt_latency = roles.get("grunt", {}).get("latency") or {}
    # Worker time now happens inside EXECUTING (close_read only), not across a whole
    # COLLECTING phase. On a run with no close_reads this is legitimately zero.
    executing_seconds = _phase_durations(records).get("EXECUTING", 0.0)
    steps = finished.get("steps_taken", 0)

    stats: dict[str, Any] = {
        "investigation_id": investigation_id,
        "concurrency_configured": concurrency_configured,
        "case": case,
        "backend": backend,
        "terminal_state": terminal_state,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "time": {
            "wall_clock_s": round(wall_clock_s, 1),
            "by_phase_s": _phase_durations(records),
            # Sum of worker time over the wall time they ran in: how much of the
            # configured concurrency was actually realised.
            # Kept for continuity with earlier runs, but it means something narrower
            # now: close_reads are issued one at a time, so this should sit near 1.0.
            # The sweep architecture's 6-8x figure has no counterpart here, because
            # there is no longer a fleet to run in parallel.
            "effective_parallelism": (
                round(grunt_latency.get("total_s", 0) / executing_seconds, 1)
                if executing_seconds
                else None
            ),
            "seconds_per_step": (
                round(wall_clock_s / steps, 1) if steps else None
            ),
        },
        "work": {
            "files": len(inventory),
            # What was searchable, not what was read. Under the sweep this was
            # lines_swept and claimed every line had been examined by a model; the
            # honest version of the number is the size of the corpus.
            "lines_available": sum(getattr(i, "line_count", 0) for i in inventory),
            "steps_taken": steps,
            "steps_with_errors": finished.get("steps_with_errors"),
            "refs_shown": finished.get("refs_shown"),
            "llm_calls": len(calls),
            "grunt_validations": len(validations),
            "grunt_rejections": len(rejected),
            "grunt_rejection_rate": (
                round(len(rejected) / len(validations), 3) if validations else None
            ),
            "rejection_reasons": dict(reasons.most_common()),
            "task_failures": finished.get("failures"),
            "task_failure_reasons": finished.get("failure_reasons"),
        },
        "roles": roles,
        "quality": {
            "steps_taken": getattr(brief, "steps_taken", None),
            "unresolved_citations": len(getattr(brief, "unresolved_citations", []) or []),
            "uncited_claims": len(getattr(brief, "uncited_claims", []) or []),
            "timeline_events": len(getattr(getattr(brief, "body", None), "timeline", []) or []),
            "hypotheses": len(getattr(getattr(brief, "body", None), "hypotheses", []) or []),
            "narrative_chars": len(
                getattr(getattr(brief, "body", None), "investigation_narrative", "") or ""
            ),
        },
        "server": _metric_delta(metrics_before, metrics_after),
        "machine": sampler.summary() if sampler else None,
    }
    return stats


# Fallbacks for the very first run on a machine, before there is any history to learn
# from. Deliberately pessimistic: an estimate that under-promises is a nuisance, one that
# over-promises makes people walk away from a run that was about to finish.
DEFAULT_SECONDS_PER_STEP = 45.0


def estimate_investigation(output_dir: Path, *, max_steps: int) -> tuple[float, str]:
    """Estimate worst-case minutes, calibrated from this machine's own last real run.

    Cost no longer scales with the corpus. A 1 MB case and a 40 MB case cost the same
    here, because searching is free and the only thing being paid for is commander turns
    -- which is the largest practical consequence of dropping the sweep.

    So the estimate is per-STEP, and it is a ceiling rather than a prediction: most
    investigations conclude before the cap. Calibrated on wall-clock seconds per step
    from the last real run, which carries retries and the latency tail by construction.
    Returns (minutes, basis).
    """
    previous = _latest_stats(output_dir)
    if previous:
        try:
            per_step = previous["time"]["seconds_per_step"]
            if per_step:
                return (
                    max_steps * per_step / 60,
                    f"last real run {previous['investigation_id']}: "
                    f"{per_step:.0f}s per step observed",
                )
        except (KeyError, TypeError, ZeroDivisionError):
            pass

    # No history: deliberately pessimistic. An estimate that under-promises is a
    # nuisance; one that over-promises makes people kill a run that was about to finish.
    return (
        max_steps * DEFAULT_SECONDS_PER_STEP / 60,
        "defaults (no previous run on this machine)",
    )


def _latest_stats(output_dir: Path) -> dict[str, Any] | None:
    """Most recent completed real run's stats, if there is one. Stub runs are skipped --
    their timings say nothing about how long a GPU run takes."""
    if not output_dir.exists():
        return None
    candidates = sorted(output_dir.glob("*/stats.json"), reverse=True)
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # Gated on commander calls, not grunt calls: a perfectly good investigation can
        # now run without dispatching a single worker, and gating on grunts would make
        # those runs invisible to the estimator.
        if data.get("backend") == "vllm" and data.get("roles", {}).get("commander", {}).get("calls"):
            return data
    return None


def format_summary(stats: dict[str, Any]) -> str:
    """Compact console rendering -- the handful of numbers worth seeing immediately."""
    time_block = stats["time"]
    work = stats["work"]
    lines = [
        f"  wall clock     : {time_block['wall_clock_s'] / 60:.1f} min",
        f"  steps / lines  : {work['steps_taken']} / {work['lines_available']}",
        f"  llm calls      : {work['llm_calls']}"
        + (
            f"  ({work['grunt_rejections']} rejected, "
            f"{work['grunt_rejection_rate']:.0%} of grunt reports)"
            if work.get("grunt_rejection_rate")
            else ""
        ),
    ]
    if time_block.get("effective_parallelism"):
        lines.append(f"  parallelism    : {time_block['effective_parallelism']}x effective")
    for role, server in (stats.get("server") or {}).items():
        rate = server.get("prefix_cache_hit_rate")
        lines.append(
            f"  {role:<14} : {server['prompt_tokens']:,} prompt + "
            f"{server['generation_tokens']:,} generated tokens"
            + (f", prefix cache {rate:.0%}" if rate is not None else "")
        )
    machine = stats.get("machine") or {}
    if machine.get("gpu_utilization_pct"):
        gpu, mem = machine["gpu_utilization_pct"], machine.get("host_memory_used_gb") or {}
        lines.append(
            f"  gpu / memory   : {gpu['mean']:.0f}% mean, {gpu['peak']:.0f}% peak"
            + (f"  |  host {mem.get('peak', 0):.0f} GB peak" if mem else "")
        )
    return "\n".join(lines)
