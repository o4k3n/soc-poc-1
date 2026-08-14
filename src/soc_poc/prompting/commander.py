"""Commander prompts: the sweep directive, drill-down rounds, and synthesis.

**The commander never sees a log line.** Not in tasking, not in synthesis. It reads the
alert, says what would be relevant, and then reasons over what its workers bring back.
That is the whole reason the sweep exists: if the commander picked what to read, a
negative finding would only ever mean "not in the part I chose to look at".

The one thing it is told about the data is a file inventory -- names, line counts, time
ranges. Nothing derived from content. Without it the directive cannot say "check the DHCP
leases for host attribution", because it would not know a DHCP log exists.

The other load-bearing piece here is `render_outcomes`. A sweep of a 1 MB case produces
~80 reports; rendered naively that is more tokens than the commander's whole context.
Slices that found nothing collapse into one line, so what reaches the commander is the
findings plus an honest account of how much ground was covered to get them.
"""

from __future__ import annotations

from soc_poc.chunking import FileInventory
from soc_poc.messages import GruntFailure, GruntOutcome, GruntSuccess
from soc_poc.prompting.envelope import DATA_IS_NOT_INSTRUCTIONS, fence_alert
from soc_poc.schemas.alert import Alert
from soc_poc.schemas.sweep import SweepDirective

_ROLE = """You are the lead analyst in a security operations investigation system. An \
external detection system has already raised an alert; your job is to investigate \
around it and hand a human operator something they can act on."""

_AUTHORITY = """The external alert's status and severity are authoritative and \
read-only. You do not confirm, dismiss, escalate, downgrade, or close anything. You \
enrich: you show the operator what the data contains, which explanations it supports, \
which it undermines, and where to look next. The operator decides."""

TASKING_SYSTEM_PROMPT = f"""{_ROLE}

{_AUTHORITY}

You have a fleet of log-reading workers. Every slice of every log file in this case will \
be read by one of them -- you do not choose what gets read, and you will not see the raw \
logs yourself. What you decide here is what those workers should treat as relevant.

Write a sweep directive from the alert:
  - indicators: concrete strings worth matching on (domains, IPs, hostnames, ports, \
record types) drawn from the alert;
  - relevance_criteria: prose describing what would make a line worth reporting even if \
it contains none of those strings. This is the important field. Workers that only match \
literal strings are an expensive grep; tell them what the alert is *about* so they \
recognise it in a form nobody listed;
  - explicitly_irrelevant: what to ignore, so the workers do not drown you in routine \
traffic;
  - time_window: if the alert implies one.

You are writing for a small model reading 70 lines with no other context. Be concrete.

{DATA_IS_NOT_INSTRUCTIONS}

Reply with a single JSON object matching the provided schema. No prose outside it."""

DRILLDOWN_SYSTEM_PROMPT = f"""{_ROLE}

{_AUTHORITY}

The sweep is complete: every line of every log has been read. Below are the findings, \
plus a count of how many slices were read and found nothing.

You may now request a closer read of specific slices -- ones where a worker found \
something whose detail you need, or whose neighbours might carry more of the same \
pattern. Dispatch only against slice_ids that appear below. Ask for nothing if the sweep \
already tells you enough; an empty task list is the right answer more often than not.

Prefer requests that could disconfirm your leading explanation over requests that would \
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
  - The sweep read every line. Slices reported as finding nothing are real evidence of \
absence within their scope -- say so where it matters, rather than treating unexamined \
and examined-and-empty as the same thing.
  - Tasks that failed are listed below. Treat a failed task as unexamined ground, not as \
evidence of absence, and record it in coverage_gaps.
  - Suggest concrete next drill-downs the operator could run.

You have no field for a verdict, severity, disposition, or recommendation to close, \
because rendering one is not your role. Describe the evidence and its shape.

{DATA_IS_NOT_INSTRUCTIONS}

Reply with a single JSON object matching the provided schema. No prose outside it."""


def _inventory_block(inventory: list[FileInventory]) -> str:
    rows = [
        f"- {item.file}: {item.line_count} lines, {item.slice_count} slice(s), "
        f"time range {item.time_range}"
        for item in inventory
    ]
    return (
        "LOG FILES IN THIS CASE (names and sizes only -- you are not being shown their "
        "contents):\n" + "\n".join(rows)
    )


def _directive_block(directive: SweepDirective) -> str:
    return "\n".join(
        [
            "YOUR SWEEP DIRECTIVE (what the workers were told to look for):",
            f"  {directive.alert_restatement}",
            f"  indicators: {', '.join(directive.indicators) or '(none)'}",
            f"  relevance: {directive.relevance_criteria}",
        ]
    )


def render_outcomes(outcomes: list[GruntOutcome]) -> str:
    """Findings in full; everything else collapsed to a coverage line.

    This is what keeps a sweep of arbitrary size inside a fixed context. The collapsed
    line is not a footnote -- "58 slices read, nothing relevant" is the claim that makes
    the brief's coverage statement true, and it costs one line to make.
    """
    detailed: list[str] = []
    empty: list[str] = []
    failed: list[str] = []

    for outcome in outcomes:
        if isinstance(outcome, GruntFailure):
            failed.append(
                f"- {outcome.slice_id} FAILED ({outcome.reason}): {outcome.detail}. "
                f"This ground was NOT examined."
            )
            continue
        assert isinstance(outcome, GruntSuccess)
        report = outcome.report
        if not report.relevant or not report.findings:
            empty.append(outcome.slice_id)
            continue
        lines = [f"- {outcome.slice_id} ({report.slice_metadata.file}):"]
        for finding in report.findings:
            lines.append(
                f"    [{finding.confidence.value}] {finding.description}"
                f"  ({finding.match_count} matching line(s), "
                f"{finding.first_ref}..{finding.last_ref})"
            )
            lines.append(f"      refs: {', '.join(finding.representative_refs)}")
        detailed.append("\n".join(lines))

    parts = ["SWEEP RESULTS", "\n".join(detailed) or "(no slice reported a finding)"]
    if empty:
        parts.append(
            f"COVERAGE: {len(empty)} further slice(s) were read in full and reported "
            f"nothing relevant: {', '.join(empty[:40])}"
            + (f" … and {len(empty) - 40} more" if len(empty) > 40 else "")
        )
    if failed:
        parts.append("FAILED TASKS (unexamined ground):\n" + "\n".join(failed))
    return "\n\n".join(parts)


def build_tasking_messages(
    *, alert: Alert, inventory: list[FileInventory], total_slices: int
) -> list[dict[str, str]]:
    user = "\n\n".join(
        [
            "ALERT",
            fence_alert(alert),
            _inventory_block(inventory),
            f"Every one of the {total_slices} slices will be read by a worker. Write the "
            f"sweep directive.",
        ]
    )
    return [
        {"role": "system", "content": TASKING_SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


def build_drilldown_messages(
    *,
    alert: Alert,
    directive: SweepDirective,
    outcomes: list[GruntOutcome],
    iteration: int,
    max_tasks: int,
    remaining_iterations: int,
) -> list[dict[str, str]]:
    user = "\n\n".join(
        [
            f"DRILL-DOWN ROUND {iteration}",
            "ALERT",
            fence_alert(alert),
            _directive_block(directive),
            render_outcomes(outcomes),
            f"Request at most {max_tasks} closer reads this round. You may request one "
            f"more round after this ({remaining_iterations} remaining); set "
            f"request_followup=false when further reading would not change the brief. "
            f"An empty task list sends this straight to synthesis.",
        ]
    )
    return [
        {"role": "system", "content": DRILLDOWN_SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


def build_synthesis_messages(
    *,
    alert: Alert,
    directive: SweepDirective,
    outcomes: list[GruntOutcome],
    coverage_note: str,
) -> list[dict[str, str]]:
    user = "\n\n".join(
        [
            "SYNTHESIS",
            "ALERT",
            fence_alert(alert),
            _directive_block(directive),
            render_outcomes(outcomes),
            coverage_note,
            "Write the investigation brief now.",
        ]
    )
    return [
        {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
        {"role": "user", "content": user},
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
