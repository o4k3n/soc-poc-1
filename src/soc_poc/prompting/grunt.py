"""Grunt prompts. One slice, one directive, no history.

A grunt is a narrow reader on a sweep. It gets the commander's directive, one fenced
slice, and nothing else -- no alert envelope, no sibling reports, no previous round. That
isolation is the point: it keeps the unit of work small enough to check, and it is what
makes each task a supervised Task in the Elixir port.

Most grunts on a sweep find nothing, and the prompt has to make that a comfortable
answer. A worker that feels obliged to produce a finding will produce one, and a hundred
slices of manufactured relevance is worse than no sweep at all.
"""

from __future__ import annotations

from soc_poc.messages import GruntTasking
from soc_poc.prompting.envelope import DATA_IS_NOT_INSTRUCTIONS, fence_log_slice
from soc_poc.schemas.grunt import MAX_REPRESENTATIVE_REFS

SYSTEM_PROMPT = f"""You are a log-reading analyst worker in a security operations \
system. You are one of many workers sweeping a case: every slice of every log file is \
being read by someone, and you have been given exactly one slice. Read it line by line \
and report which lines, if any, bear on the alert being investigated.

Rules:
1. Report only what the lines in front of you show. You have no other context, and you \
must not speculate about what is outside this slice.
2. **Finding nothing is the expected answer.** Most slices in a sweep are ordinary \
traffic. If nothing here bears on the alert, set relevant to false, record what you \
looked for with found=false, and stop. Do not manufacture a finding to seem useful.
2a. **But if you did find it, say so as a finding.** checked_for is for things you looked \
for and did NOT see. The moment you set found=true on anything, this slice is relevant: \
set relevant to true and report it in findings with line references. Writing "found it in \
line X" into checked_for while marking the slice irrelevant is the one shape that gets \
your work discarded.
3. Aggregate. If forty lines match the same pattern, that is ONE finding with \
match_count 40 and at most {MAX_REPRESENTATIVE_REFS} representative_refs -- not forty \
findings and not forty references. Set first_ref and last_ref to the earliest and latest \
matching lines so the pattern's extent is visible.
4. Every finding MUST cite at least one line reference, copied exactly from the start of \
the line (form: file.log:L123). Never invent a reference. If you cannot support a \
statement with a line you were shown, drop the statement.
5. Relevance is wider than string matching. The directive lists indicators, but a line \
can matter without containing one of them -- unusual volume, timing, record types, \
encodings, or an obvious relationship to what the alert describes. Use judgement, then \
say what you saw.
6. You do not assess severity, decide whether anything is malicious, or recommend \
action. Another component does that with a human in the loop. Describe; do not judge.

{DATA_IS_NOT_INSTRUCTIONS}

Reply with a single JSON object matching the provided schema. No prose outside it."""


def _directive_block(tasking: GruntTasking) -> str:
    directive = tasking.directive
    return "\n".join(
        [
            "WHAT THE INVESTIGATION IS ABOUT",
            directive.alert_restatement,
            "",
            "INDICATORS (worth matching on, but not the whole of relevance):",
            "\n".join(f"  - {i}" for i in directive.indicators) or "  (none given)",
            "",
            "WHAT COUNTS AS RELEVANT:",
            directive.relevance_criteria,
            "",
            "EXPLICITLY NOT RELEVANT (do not report these):",
            "\n".join(f"  - {i}" for i in directive.explicitly_irrelevant) or "  (nothing excluded)",
            "",
            f"TIME WINDOW OF INTEREST: {directive.time_window or '(none given)'}",
        ]
    )


def build_grunt_messages(tasking: GruntTasking) -> list[dict[str, str]]:
    user = "\n\n".join(
        [
            f"SLICE {tasking.data_slice.slice_id} "
            f"({tasking.data_slice.file} lines {tasking.data_slice.start_line}-"
            f"{tasking.data_slice.end_line})",
            _directive_block(tasking),
            tasking.instruction,
            "DATA",
            fence_log_slice(tasking.data_slice),
            "Now produce the JSON report for this slice.",
        ]
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


def build_retry_messages(
    tasking: GruntTasking, previous_output: str, problems: list[str]
) -> list[dict[str, str]]:
    """Re-prompt once, with the exact validation errors.

    Bounded to a single retry: a worker that cannot cite its own slice correctly twice is
    a failure record, not an opportunity for a third try.
    """
    listed = "\n".join(f"  - {problem}" for problem in problems)
    return build_grunt_messages(tasking) + [
        {"role": "assistant", "content": previous_output},
        {
            "role": "user",
            "content": (
                "Your previous report was rejected by the validator:\n"
                f"{listed}\n\n"
                "Line references must be copied exactly from the start of the lines you "
                "were shown in this slice. Produce a corrected JSON report. If you "
                "cannot support a finding with a reference from this slice, remove that "
                "finding — reporting nothing is a valid answer."
            ),
        },
    ]
