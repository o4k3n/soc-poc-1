"""Commander-side calls: plan a round, synthesize the brief.

Like the grunt worker, these functions return values rather than raising across the
agent boundary, and each gets exactly one feedback-carrying retry. The validation they
apply is the part the grammar cannot: a plan must name slices that exist, and must not
exceed the dispatch budget the orchestrator set.

What is deliberately absent: any code path that lets a commander response influence the
alert's status. The brief's AlertRef is stamped by the orchestrator from the inbound
alert (see orchestrator.py), and BriefBody has no field for it.
"""

from __future__ import annotations

from soc_poc.config import RunConfig
from soc_poc.llm.base import LLMClient, LLMTransportError
from soc_poc.messages import GruntOutcome, PlanningResult
from soc_poc.parsing import ParseFailure, parse_model_json
from soc_poc.prompting import commander as prompts
from soc_poc.schemas.alert import Alert
from soc_poc.schemas.brief import BriefBody, CommanderPlan
from soc_poc.schemas.jsonschema import schema_for
from soc_poc.schemas.pattern_summary import PatternSummary
from soc_poc.schemas.slice import LogSlice
from soc_poc.states import InvestigationState
from soc_poc.transcript import TranscriptLogger

PLAN_SCHEMA_NAME = "commander_plan"
BRIEF_SCHEMA_NAME = "investigation_brief"


def _validate_plan(
    plan: CommanderPlan, catalog: dict[str, LogSlice], max_tasks: int
) -> list[str]:
    problems: list[str] = []
    if len(plan.tasks) > max_tasks:
        problems.append(
            f"plan requests {len(plan.tasks)} tasks but the limit for this round is "
            f"{max_tasks}. Keep the {max_tasks} that would most change the brief."
        )
    for index, task in enumerate(plan.tasks):
        if task.slice_id not in catalog:
            problems.append(
                f"tasks[{index}].slice_id {task.slice_id!r} is not in the catalog. "
                f"Dispatch only against the listed slice_ids."
            )
        if not task.commander_intent.strip():
            problems.append(f"tasks[{index}].commander_intent is empty; state the hypothesis.")
    return problems


async def plan_round(
    *,
    client: LLMClient,
    transcript: TranscriptLogger,
    run_config: RunConfig,
    alert: Alert,
    summaries: list[PatternSummary],
    catalog: dict[str, LogSlice],
    outcomes: list[GruntOutcome],
    iteration: int,
) -> PlanningResult:
    base = prompts.build_planning_messages(
        alert=alert,
        summaries=summaries,
        catalog=catalog,
        outcomes=outcomes,
        iteration=iteration,
        max_tasks=run_config.max_tasks_per_iteration,
        remaining_iterations=run_config.max_iterations - iteration - 1,
    )
    schema = schema_for(CommanderPlan)
    messages = base
    max_attempts = run_config.max_validation_retries + 1
    problems: list[str] = []

    for attempt in range(1, max_attempts + 1):
        try:
            response = await client.complete_json(
                messages=messages,
                schema_name=PLAN_SCHEMA_NAME,
                json_schema=schema,
                state=InvestigationState.PLANNING.value,
                attempt=attempt,
            )
        except LLMTransportError as exc:
            return PlanningResult(ok=False, error=str(exc), attempts=attempt)

        try:
            plan = parse_model_json(response.text, CommanderPlan)
            problems = _validate_plan(plan, catalog, run_config.max_tasks_per_iteration)
        except ParseFailure as exc:
            plan, problems = None, exc.problems

        transcript.log_event(
            "commander_plan_validation",
            {"iteration": iteration, "attempt": attempt, "ok": not problems, "problems": problems},
        )

        if plan is not None and not problems:
            return PlanningResult(ok=True, plan=plan, attempts=attempt)
        if attempt < max_attempts:
            messages = prompts.build_retry_messages(base, response.text, problems)

    return PlanningResult(
        ok=False, error=f"plan rejected after {max_attempts} attempt(s): {problems}", attempts=max_attempts
    )


async def synthesize_brief(
    *,
    client: LLMClient,
    transcript: TranscriptLogger,
    run_config: RunConfig,
    alert: Alert,
    summaries: list[PatternSummary],
    outcomes: list[GruntOutcome],
    iteration_note: str,
) -> tuple[BriefBody | None, str]:
    """Return (body, error). Exactly one of the two is meaningful."""
    base = prompts.build_synthesis_messages(
        alert=alert,
        summaries=summaries,
        outcomes=outcomes,
        iteration_note=iteration_note,
    )
    schema = schema_for(BriefBody)
    messages = base
    max_attempts = run_config.max_validation_retries + 1
    problems: list[str] = []

    for attempt in range(1, max_attempts + 1):
        try:
            response = await client.complete_json(
                messages=messages,
                schema_name=BRIEF_SCHEMA_NAME,
                json_schema=schema,
                state=InvestigationState.SYNTHESIZING.value,
                attempt=attempt,
            )
        except LLMTransportError as exc:
            return None, str(exc)

        try:
            body = parse_model_json(response.text, BriefBody)
            problems = []
        except ParseFailure as exc:
            body, problems = None, exc.problems

        transcript.log_event(
            "commander_brief_validation",
            {"attempt": attempt, "ok": not problems, "problems": problems},
        )

        if body is not None:
            return body, ""
        if attempt < max_attempts:
            messages = prompts.build_retry_messages(base, response.text, problems)

    return None, f"brief rejected after {max_attempts} attempt(s): {problems}"
