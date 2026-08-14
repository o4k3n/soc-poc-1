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
                state=InvestigationState.COLLECTING.value,
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
            problems = validate_report_citations(report, tasking.data_slice)
        except ParseFailure as exc:
            problems = exc.problems
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
