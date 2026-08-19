"""Commander-side calls: write the sweep directive, request drill-downs, synthesize.

Like the grunt worker, these return values rather than raising across the agent
boundary, and each gets exactly one feedback-carrying retry. The validation they apply is
the part the grammar cannot: a directive must actually say something, and a drill-down
plan must name slices that exist.

What is deliberately absent: any code path that lets a commander response influence the
alert's status, and any code path that puts a log line in front of the commander. The
brief's AlertRef is stamped by the orchestrator from the inbound alert, and the prompts in
prompting/commander.py carry the alert, the file inventory, and worker reports -- never
raw data.
"""

from __future__ import annotations

from soc_poc.chunking import FileInventory
from soc_poc.config import RunConfig
from soc_poc.llm.base import LLMClient, LLMTransportError
from soc_poc.messages import GruntOutcome, PlanningResult, TaskingResult
from soc_poc.parsing import ParseFailure, parse_model_json
from soc_poc.progress import NullProgress, ProgressSink
from soc_poc.prompting import commander as prompts
from soc_poc.schemas.alert import Alert
from soc_poc.schemas.brief import BriefBody, CommanderPlan
from soc_poc.schemas.jsonschema import schema_for
from soc_poc.schemas.slice import LogSlice
from soc_poc.schemas.sweep import SweepDirective
from soc_poc.states import InvestigationState
from soc_poc.transcript import TranscriptLogger


def _truncation_hint(response) -> list[str]:
    """See grunt._truncation_hint -- a reply cut off at max_tokens is not malformed."""
    if response.finish_reason != "length":
        return []
    return [
        f"Your reply was cut off at the token limit "
        f"({response.usage.get('completion_tokens', 'max')} tokens) -- it was not "
        f"rejected for being malformed. Be more concise rather than restructuring."
    ]


TASKING_SCHEMA_NAME = "sweep_directive"
PLAN_SCHEMA_NAME = "commander_plan"
BRIEF_SCHEMA_NAME = "investigation_brief"


async def _call_with_retry(
    *,
    client: LLMClient,
    transcript: TranscriptLogger,
    progress: ProgressSink,
    base: list[dict[str, str]],
    schema_name: str,
    model: type,
    state: InvestigationState,
    run_config: RunConfig,
    validate,
    event_kind: str,
):
    """Shared shape: call, parse, validate, re-prompt once with the error, give up.

    Returns (parsed | None, problems, error). Exactly one of parsed / error is meaningful.
    """
    schema = schema_for(model)
    messages = base
    max_attempts = run_config.max_validation_retries + 1
    problems: list[str] = []

    for attempt in range(1, max_attempts + 1):
        progress.call_started("commander", schema_name, None)
        try:
            response = await client.complete_json(
                messages=messages,
                schema_name=schema_name,
                json_schema=schema,
                state=state.value,
                attempt=attempt,
                on_token=progress.token if progress.wants_tokens else None,
            )
        except LLMTransportError as exc:
            return None, problems, str(exc)
        progress.call_finished("commander", response.latency_ms, attempt)

        try:
            parsed = parse_model_json(response.text, model)
            problems = validate(parsed)
        except ParseFailure as exc:
            parsed, problems = None, _truncation_hint(response) + exc.problems

        transcript.log_event(
            event_kind, {"attempt": attempt, "ok": not problems, "problems": problems}
        )
        if parsed is not None and not problems:
            return parsed, [], ""
        if attempt < max_attempts:
            messages = prompts.build_retry_messages(base, response.text, problems)

    return None, problems, f"rejected after {max_attempts} attempt(s): {problems}"


def _validate_directive(directive: SweepDirective) -> list[str]:
    problems: list[str] = []
    if not directive.relevance_criteria.strip():
        problems.append(
            "relevance_criteria is empty. It is the field the workers actually reason "
            "with; without it they can only string-match."
        )
    if not directive.indicators and not directive.relevance_criteria.strip():
        problems.append("give the workers at least one indicator or a relevance rule.")
    return problems


async def write_directive(
    *,
    client: LLMClient,
    transcript: TranscriptLogger,
    run_config: RunConfig,
    alert: Alert,
    inventory: list[FileInventory],
    total_slices: int,
    progress: ProgressSink | None = None,
) -> TaskingResult:
    """TASKING: the alert goes in, a notion of relevance comes out. No log data."""
    progress = progress or NullProgress()
    base = prompts.build_tasking_messages(
        alert=alert, inventory=inventory, total_slices=total_slices
    )
    directive, _, error = await _call_with_retry(
        client=client,
        transcript=transcript,
        progress=progress,
        base=base,
        schema_name=TASKING_SCHEMA_NAME,
        model=SweepDirective,
        state=InvestigationState.TASKING,
        run_config=run_config,
        validate=_validate_directive,
        event_kind="commander_directive_validation",
    )
    if directive is None:
        return TaskingResult(ok=False, error=error)
    return TaskingResult(ok=True, directive=directive)


async def plan_drilldown(
    *,
    client: LLMClient,
    transcript: TranscriptLogger,
    run_config: RunConfig,
    alert: Alert,
    directive: SweepDirective,
    catalog: dict[str, LogSlice],
    outcomes: list[GruntOutcome],
    iteration: int,
    progress: ProgressSink | None = None,
) -> PlanningResult:
    """PLANNING: after the sweep, ask for closer reads of specific slices."""
    progress = progress or NullProgress()
    base = prompts.build_drilldown_messages(
        alert=alert,
        directive=directive,
        outcomes=outcomes,
        iteration=iteration,
        max_tasks=run_config.max_tasks_per_iteration,
        remaining_iterations=run_config.max_iterations - iteration,
    )

    def validate(plan: CommanderPlan) -> list[str]:
        problems: list[str] = []
        if len(plan.tasks) > run_config.max_tasks_per_iteration:
            problems.append(
                f"plan requests {len(plan.tasks)} tasks but the limit for this round is "
                f"{run_config.max_tasks_per_iteration}."
            )
        for index, task in enumerate(plan.tasks):
            if task.slice_id not in catalog:
                problems.append(
                    f"tasks[{index}].slice_id {task.slice_id!r} is not a slice in this "
                    f"case. Dispatch only against slice_ids that appear in the sweep "
                    f"results."
                )
            if not task.commander_intent.strip():
                problems.append(
                    f"tasks[{index}].commander_intent is empty; state the hypothesis."
                )
        return problems

    plan, _, error = await _call_with_retry(
        client=client,
        transcript=transcript,
        progress=progress,
        base=base,
        schema_name=PLAN_SCHEMA_NAME,
        model=CommanderPlan,
        state=InvestigationState.PLANNING,
        run_config=run_config,
        validate=validate,
        event_kind="commander_plan_validation",
    )
    if plan is None:
        return PlanningResult(ok=False, error=error)
    return PlanningResult(ok=True, plan=plan)


async def synthesize_brief(
    *,
    client: LLMClient,
    transcript: TranscriptLogger,
    run_config: RunConfig,
    alert: Alert,
    directive: SweepDirective,
    outcomes: list[GruntOutcome],
    coverage_note: str,
    progress: ProgressSink | None = None,
) -> tuple[BriefBody | None, str]:
    """Return (body, error). Exactly one of the two is meaningful."""
    progress = progress or NullProgress()
    base = prompts.build_synthesis_messages(
        alert=alert, directive=directive, outcomes=outcomes, coverage_note=coverage_note
    )
    body, _, error = await _call_with_retry(
        client=client,
        transcript=transcript,
        progress=progress,
        base=base,
        schema_name=BRIEF_SCHEMA_NAME,
        model=BriefBody,
        state=InvestigationState.SYNTHESIZING,
        run_config=run_config,
        validate=lambda _: [],
        event_kind="commander_brief_validation",
    )
    return body, error
