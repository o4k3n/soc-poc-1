"""One grunt task: an isolated unit of work.

Everything this function needs arrives in the `GruntTasking` message. It holds no
reference to the investigation, other tasks, or previous iterations, and it returns a
value in every case -- a report or an explicit failure record. No exception leaves this
function.

That shape is not Python taste; it is the Elixir port's shape. In OTP this is a
supervised Task under a Task.Supervisor: it runs to completion, it returns a tagged
result, and if it dies the supervisor and the caller both know, without taking the
caller down with it.

The retry loop is bounded and feedback-carrying: on a schema or citation failure the
worker is shown the validator's exact complaint once, and then it is done.
"""

from __future__ import annotations

import re

from soc_poc.config import RunConfig
from soc_poc.llm.base import LLMClient, LLMTransportError
from soc_poc.messages import GruntFailure, GruntOutcome, GruntSuccess, GruntTasking
from soc_poc.parsing import ParseFailure, parse_model_json
from soc_poc.progress import NullProgress, ProgressSink
from soc_poc.prompting.grunt import build_grunt_messages, build_retry_messages
from soc_poc.schemas.grunt import GruntReport
from soc_poc.schemas.jsonschema import schema_for
from soc_poc.states import InvestigationState
from soc_poc.transcript import TranscriptLogger
from soc_poc.validation.citations import validate_report_citations

GRUNT_SCHEMA_NAME = "grunt_report"


def _truncation_hint(response) -> list[str]:
    """A reply cut off at max_tokens is not a malformed reply.

    Observed live: a grunt hit the 3072-token cap emitting indentation and the parser
    reported "not valid JSON", so the retry told it to return one JSON object -- which is
    exactly what it had been doing. Naming the real cause is the difference between a
    useful retry and a wasted one.
    """
    if response.finish_reason != "length":
        return []
    return [
        f"Your reply was cut off at the token limit "
        f"({response.usage.get('completion_tokens', 'max')} tokens) -- it was not "
        f"rejected for being malformed. Almost always this means you listed too much: "
        f"report an aggregate (match_count plus at most a handful of "
        f"representative_refs) instead of enumerating lines."
    ]


_FINDING_PROBLEM = re.compile(r"^findings\[(\d+)\]")


def _drop_failed_findings(report: GruntReport, problems: list[str]) -> GruntReport | None:
    """Return the report with the objectionable findings removed, or None if unsalvageable.

    Only every problem being attributable to a specific finding makes a report salvageable.
    A slice_id mismatch or a malformed envelope means the worker lost track of what it was
    reading, and nothing in that report should be trusted.

    `relevant` is recomputed rather than preserved: if every finding was dropped, the
    honest statement is that this slice showed nothing, and its negatives still count.
    """
    indices = {int(m.group(1)) for p in problems if (m := _FINDING_PROBLEM.match(p))}
    if not indices or len(indices) != len({p.split(" ")[0] for p in problems}):
        # Some problem was not about a finding -- do not paper over it.
        if any(not _FINDING_PROBLEM.match(p) for p in problems):
            return None
    kept = [f for i, f in enumerate(report.findings) if i not in indices]
    if len(kept) == len(report.findings):
        return None
    return report.model_copy(update={"findings": kept, "relevant": bool(kept)})


def _failure(
    tasking: GruntTasking,
    reason: str,
    detail: str,
    attempts: int,
    validation_errors: list[str] | None = None,
) -> GruntFailure:
    return GruntFailure(
        task_id=tasking.task_id,
        iteration=tasking.iteration,
        slice_id=tasking.data_slice.slice_id,
        instruction=tasking.instruction,
        commander_intent=tasking.commander_intent,
        reason=reason,  # type: ignore[arg-type]
        detail=detail,
        attempts=attempts,
        validation_errors=validation_errors or [],
    )


async def run_grunt_task(
    tasking: GruntTasking,
    client: LLMClient,
    run_config: RunConfig,
    transcript: TranscriptLogger,
    progress: ProgressSink | None = None,
) -> GruntOutcome:
    """Run one task to completion. Always returns; never raises."""
    progress = progress or NullProgress()
    schema = schema_for(GruntReport)
    messages = build_grunt_messages(tasking)
    max_attempts = run_config.max_validation_retries + 1
    problems: list[str] = []

    for attempt in range(1, max_attempts + 1):
        try:
            response = await client.complete_json(
                messages=messages,
                schema_name=GRUNT_SCHEMA_NAME,
                json_schema=schema,
                state=InvestigationState.EXECUTING.value,
                attempt=attempt,
                task_id=tasking.task_id,
                parent_task_id=tasking.investigation_id,
            )
        except LLMTransportError as exc:
            # Transport failures are not retried here: the orchestrator's timeout and
            # the operator's patience are the budget, and a dead endpoint will not
            # revive within one re-prompt.
            progress.task_outcome(
                tasking.task_id, tasking.data_slice.slice_id, f"transport: {exc}", ok=False
            )
            return _failure(tasking, "transport", str(exc), attempt)

        try:
            report = parse_model_json(response.text, GruntReport)
            problems = validate_report_citations(
                report, tasking.data_slice, tasking.directive.indicators
            )
        except ParseFailure as exc:
            problems = _truncation_hint(response) + exc.problems
            report = None  # type: ignore[assignment]

        transcript.log_event(
            "grunt_validation",
            {
                "task_id": tasking.task_id,
                "attempt": attempt,
                "ok": not problems,
                "problems": problems,
            },
        )

        if not problems and report is not None:
            progress.task_outcome(
                tasking.task_id,
                tasking.data_slice.slice_id,
                (
                    f"{sum(f.match_count for f in report.findings)} matching line(s) in "
                    f"{len(report.findings)} finding(s)"
                    if report.relevant
                    else "nothing relevant"
                )
                + (f", {attempt} attempts" if attempt > 1 else ""),
                ok=True,
            )
            return GruntSuccess(
                task_id=tasking.task_id,
                iteration=tasking.iteration,
                slice_id=tasking.data_slice.slice_id,
                instruction=tasking.instruction,
                commander_intent=tasking.commander_intent,
                report=report,
                attempts=attempt,
            )

        if attempt < max_attempts:
            messages = build_retry_messages(tasking, response.text, problems)

    # Last attempt failed. Before writing the slice off, see whether the failure is
    # confined to particular findings -- if it is, drop those and keep the rest.
    #
    # Discarding a whole report because one finding was fabricated throws away that
    # worker's other findings AND its negatives, and turns 70 read lines into "unexamined
    # ground" in the brief. In the run that motivated this, ten slices were lost that way.
    # They happened to contain no tunnel traffic; nothing guaranteed that.
    if report is not None:
        salvaged = _drop_failed_findings(report, problems)
        if salvaged is not None:
            transcript.log_event(
                "grunt_partial_accept",
                {
                    "task_id": tasking.task_id,
                    "dropped_findings": len(report.findings) - len(salvaged.findings),
                    "kept_findings": len(salvaged.findings),
                    "problems": problems,
                },
            )
            progress.task_outcome(
                tasking.task_id,
                tasking.data_slice.slice_id,
                f"partial: {len(report.findings) - len(salvaged.findings)} finding(s) "
                f"dropped as unsupported, rest kept",
                ok=True,
            )
            return GruntSuccess(
                task_id=tasking.task_id,
                iteration=tasking.iteration,
                slice_id=tasking.data_slice.slice_id,
                instruction=tasking.instruction,
                commander_intent=tasking.commander_intent,
                report=salvaged,
                attempts=max_attempts,
            )

    reason = (
        "citations"
        if any("cite" in p or "representative_refs" in p for p in problems)
        else "schema"
    )
    progress.task_outcome(
        tasking.task_id,
        tasking.data_slice.slice_id,
        f"rejected ({reason}): {problems[0] if problems else 'unknown'}",
        ok=False,
    )
    return _failure(
        tasking,
        reason,
        f"report rejected after {max_attempts} attempt(s)",
        max_attempts,
        problems,
    )
