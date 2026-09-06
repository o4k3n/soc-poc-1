"""Commander-side calls: decide the next action, and synthesize the brief.

Like the grunt worker, these return values rather than raising across the agent boundary,
and each gets exactly one feedback-carrying retry. The validation they apply is the part
the grammar cannot: an action must name a file that exists and carry the arguments its
verb needs.

The commander now reads log lines, which is a deliberate reversal. Under the sweep
architecture it never saw data -- the argument being that a commander which picks what to
read cannot produce a meaningful negative. That argument was sound and the implementation
still failed, because the workers doing the reading did not reliably notice what they read.
Coverage now comes from `corpus.count()`, which is exact and re-runnable by hand, so
letting the analyst see its own evidence costs nothing it was actually buying.

What remains deliberately absent: any code path that lets a commander response influence
the alert's status. The brief's AlertRef is stamped by the orchestrator from the inbound
alert and never passes through a model.
"""

from __future__ import annotations

from soc_poc.coercion import coerce_action_payload
from soc_poc.config import RunConfig
from soc_poc.evidence import Evidence
from soc_poc.llm.base import LLMClient, LLMTransportError
from soc_poc.messages import ActionResult
from soc_poc.parsing import ParseFailure, parse_model_json
from soc_poc.profiling import CaseProfile
from soc_poc.progress import NullProgress, ProgressSink
from soc_poc.prompting import investigate as prompts
from soc_poc.schemas.action import InvestigativeAction, validate_action
from soc_poc.schemas.alert import Alert
from soc_poc.schemas.brief import BriefBody
from soc_poc.schemas.jsonschema import schema_for
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


ACTION_SCHEMA_NAME = "investigative_action"
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
    retry_builder=None,
    coerce=None,
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
            parsed = parse_model_json(response.text, model, coerce=coerce)
            problems = validate(parsed)
        except ParseFailure as exc:
            parsed, problems = None, _truncation_hint(response) + exc.problems

        transcript.log_event(
            event_kind, {"attempt": attempt, "ok": not problems, "problems": problems}
        )
        if parsed is not None and not problems:
            return parsed, [], ""
        if attempt < max_attempts:
            build = retry_builder or prompts.build_action_retry_messages
            messages = build(base, response.text, problems)

    return None, problems, f"rejected after {max_attempts} attempt(s): {problems}"


async def decide_action(
    *,
    client: LLMClient,
    transcript: TranscriptLogger,
    run_config: RunConfig,
    alert: Alert,
    profile: CaseProfile,
    evidence: Evidence,
    file_names: list[str],
    line_counts: dict[str, int],
    steps_remaining: int,
    steps_taken: int = 0,
    min_steps: int = 0,
    enabled_skills: frozenset[str] = frozenset(),
    field_headers: dict[str, list[str]] | None = None,
    json_files: frozenset[str] = frozenset(),
    progress: ProgressSink | None = None,
) -> ActionResult:
    """INVESTIGATING: alert + profile + everything seen so far goes in, one action comes out."""
    progress = progress or NullProgress()
    base = prompts.build_investigate_messages(
        alert=alert,
        profile=profile,
        evidence=evidence,
        file_names=file_names,
        line_counts=line_counts,
        steps_remaining=steps_remaining,
        enabled_skills=enabled_skills,
        field_headers=field_headers,
        json_files=json_files,
    )

    def validate(action: InvestigativeAction) -> list[str]:
        # ActionProblem carries a field name the retry prompt uses; _call_with_retry
        # speaks in plain strings, so flatten here and let the retry builder re-split.
        return [
            f"{problem.field}: {problem.message}"
            for problem in validate_action(
                action,
                known_files=file_names,
                steps_taken=steps_taken,
                min_steps=min_steps,
                enabled_skills=enabled_skills,
            )
        ]

    action, _, error = await _call_with_retry(
        client=client,
        transcript=transcript,
        progress=progress,
        base=base,
        schema_name=ACTION_SCHEMA_NAME,
        model=InvestigativeAction,
        state=InvestigationState.INVESTIGATING,
        run_config=run_config,
        validate=validate,
        event_kind="commander_action_validation",
        retry_builder=_plain_retry,
        coerce=coerce_action_payload,
    )
    if action is None:
        return ActionResult(ok=False, error=error)
    return ActionResult(ok=True, action=action)


def _plain_retry(
    base: list[dict[str, str]], previous_output: str, problems: list[str]
) -> list[dict[str, str]]:
    listed = "\n".join(f"  - {problem}" for problem in problems)
    return base + [
        {"role": "assistant", "content": previous_output},
        {
            "role": "user",
            "content": (
                "That action could not be executed:\n"
                f"{listed}\n\nIssue a corrected action."
            ),
        },
    ]


async def synthesize_brief(
    *,
    client: LLMClient,
    transcript: TranscriptLogger,
    run_config: RunConfig,
    alert: Alert,
    profile: CaseProfile,
    evidence: Evidence,
    coverage_note: str,
    progress: ProgressSink | None = None,
) -> tuple[BriefBody | None, str]:
    """Return (body, error). Exactly one of the two is meaningful."""
    progress = progress or NullProgress()
    base = prompts.build_synthesis_messages(
        alert=alert,
        profile=profile,
        evidence=evidence,
        coverage_note=coverage_note,
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
        retry_builder=_plain_retry,
    )
    return body, error
