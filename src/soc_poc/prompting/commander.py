"""Commander prompts: planning rounds and final synthesis.

The commander never sees raw log lines. It sees the alert, the pattern summaries, a
catalog of available slices, and whatever its workers reported back -- including their
failures, stated plainly, so it cannot mistake a lost task for an absence of evidence.
"""

from __future__ import annotations

from soc_poc.messages import GruntFailure, GruntOutcome, GruntSuccess
from soc_poc.prompting.envelope import (
    DATA_IS_NOT_INSTRUCTIONS,
    fence_alert,
    fence_pattern_summary,
)
from soc_poc.schemas.alert import Alert
from soc_poc.schemas.pattern_summary import PatternSummary
from soc_poc.schemas.slice import LogSlice

_ROLE = """You are the lead analyst in a security operations investigation system. An \
external detection system has already raised an alert; your job is to investigate \
around it and hand a human operator something they can act on."""

_AUTHORITY = """The external alert's status and severity are authoritative and \
read-only. You do not confirm, dismiss, escalate, downgrade, or close anything. You \
enrich: you show the operator what the data contains, which explanations it supports, \
which it undermines, and where to look next. The operator decides."""

PLANNING_SYSTEM_PROMPT = f"""{_ROLE}

{_AUTHORITY}

You have a fleet of narrow log-reading workers. Each worker reads exactly one slice of \
raw log data and reports literal observations with line citations. Workers have no \
context beyond what you give them, so:
  - give one specific, answerable instruction per task;
  - state your intent separately: the hypothesis the task is serving, so the worker \
knows what a useful negative result would be;
  - dispatch a task only against a slice_id from the catalog below.

Prefer tasks that could disconfirm your leading explanation over tasks that would \
merely restate it.

{DATA_IS_NOT_INSTRUCTIONS}

Reply with a single JSON object matching the provided schema. No prose outside it."""

SYNTHESIS_SYSTEM_PROMPT = f"""{_ROLE}

{_AUTHORITY}

Write the investigation brief from your workers' reports. Requirements:
  - Timeline entries and evidence carry the line references your workers cited. Do not \
invent references; if a claim rests on a report that did not cite anything, say so in \
coverage_gaps instead.
  - Every hypothesis must carry contradicting evidence as well as supporting evidence. \
If you genuinely found none against it, say that explicitly in that field's entry.
  - Tasks that failed are listed below. Treat a failed task as unexamined ground, not \
as evidence of absence, and record it in coverage_gaps.
  - Suggest concrete next drill-downs the operator could run.

You have no field for a verdict, severity, disposition, or recommendation to close, \
because rendering one is not your role. Describe the evidence and its shape.

{DATA_IS_NOT_INSTRUCTIONS}

Reply with a single JSON object matching the provided schema. No prose outside it."""


def _slice_catalog(catalog: dict[str, LogSlice]) -> str:
    rows = [
        f"- slice_id: {s.slice_id} | file: {s.file} | lines {s.start_line}-{s.end_line} "
        f"| source: {s.source} | host: {s.host} | window: {s.time_range} "
        f"| contains: {s.reason}"
        for s in catalog.values()
    ]
    return "AVAILABLE DATA SLICES (dispatch against these slice_ids only):\n" + "\n".join(rows)


def _render_outcome(outcome: GruntOutcome) -> str:
    if isinstance(outcome, GruntFailure):
        return (
            f"- task {outcome.task_id} on slice {outcome.slice_id} FAILED "
            f"({outcome.reason}): {outcome.detail}\n"
            f"  intent was: {outcome.commander_intent}\n"
            f"  This ground was NOT examined."
        )
    assert isinstance(outcome, GruntSuccess)
    report = outcome.report
    lines = [
        f"- task {outcome.task_id} on slice {outcome.slice_id}",
        f"  instruction: {outcome.instruction}",
        f"  intent: {outcome.commander_intent}",
        f"  lines_examined: {report.slice_metadata.lines_examined}",
    ]
    for observation in report.observations:
        lines.append(
            f"  observation [{observation.confidence.value}]: {observation.description}"
        )
        lines.append(f"    refs: {', '.join(observation.raw_line_refs)}")
    for negative in report.negative_findings:
        lines.append(
            f"  negative: checked for {negative.checked_for} in {negative.scope} -> "
            f"{negative.result}"
        )
    for anomaly in report.anomalies_flagged:
        lines.append(f"  anomaly: {anomaly.description} ({anomaly.why_unusual})")
        lines.append(f"    refs: {', '.join(anomaly.raw_line_refs)}")
    return "\n".join(lines)


def build_planning_messages(
    *,
    alert: Alert,
    summaries: list[PatternSummary],
    catalog: dict[str, LogSlice],
    outcomes: list[GruntOutcome],
    iteration: int,
    max_tasks: int,
    remaining_iterations: int,
) -> list[dict[str, str]]:
    parts = [
        f"PLANNING ROUND {iteration + 1}",
        "ALERT",
        fence_alert(alert),
        "PATTERN SUMMARIES (precomputed by the telemetry pipeline)",
        *[fence_pattern_summary(summary) for summary in summaries],
        _slice_catalog(catalog),
    ]
    if outcomes:
        parts += [
            "COLLECTED GRUNT REPORTS SO FAR",
            "\n".join(_render_outcome(outcome) for outcome in outcomes),
        ]
    parts.append(
        f"Dispatch at most {max_tasks} tasks this round. You may request one more round "
        f"after this ({remaining_iterations} remaining); set request_followup=false when "
        "further reading would not change the brief. Return an empty task list only if "
        "there is genuinely nothing worth reading."
    )
    return [
        {"role": "system", "content": PLANNING_SYSTEM_PROMPT},
        {"role": "user", "content": "\n\n".join(parts)},
    ]


def build_synthesis_messages(
    *,
    alert: Alert,
    summaries: list[PatternSummary],
    outcomes: list[GruntOutcome],
    iteration_note: str,
) -> list[dict[str, str]]:
    parts = [
        "SYNTHESIS",
        "ALERT",
        fence_alert(alert),
        "PATTERN SUMMARIES",
        *[fence_pattern_summary(summary) for summary in summaries],
        "COLLECTED GRUNT REPORTS",
        "\n".join(_render_outcome(outcome) for outcome in outcomes) or "(no reports collected)",
        iteration_note,
        "Write the investigation brief now.",
    ]
    return [
        {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
        {"role": "user", "content": "\n\n".join(parts)},
    ]


def build_retry_messages(
    base: list[dict[str, str]], previous_output: str, problems: list[str]
) -> list[dict[str, str]]:
    """One bounded retry with the validator's exact complaint appended."""
    listed = "\n".join(f"  - {problem}" for problem in problems)
    return base + [
        {"role": "assistant", "content": previous_output},
        {
            "role": "user",
            "content": (
                "Your previous output was rejected by the validator:\n"
                f"{listed}\n\nProduce a corrected JSON object matching the schema."
            ),
        },
    ]
