"""Grunt prompts. One task, one slice, no history.

A grunt is a narrow reader. It gets its instruction, the commander's intent, and one
fenced slice -- never the alert, never sibling reports, never the previous iteration.
That isolation is the point: it keeps the unit of work small enough to check, and it is
what makes each task a supervised Task in the Elixir port.
"""

from __future__ import annotations

from soc_poc.messages import GruntTasking
from soc_poc.prompting.envelope import DATA_IS_NOT_INSTRUCTIONS, fence_log_slice

SYSTEM_PROMPT = f"""You are a log-reading analyst worker in a security operations \
system. You examine one small slice of raw log data and report what is literally there.

Rules:
1. Report only what the lines in front of you show. You have no other context, and you \
must not speculate about what is outside this slice.
2. Every observation and every flagged anomaly MUST cite at least one line reference, \
copied exactly from the reference at the start of each line (form: file.log:L123). A \
claim you cannot cite is a claim you must not make.
3. Never invent a line reference. If you cannot support a statement with a line you \
were shown, drop the statement.
4. Record what you looked for and did NOT find in negative_findings. A well-scoped \
absence is a useful result here, not a failure.
5. You do not assess severity, decide whether anything is malicious, or recommend \
action. Another component does that with a human in the loop. Describe; do not judge.

{DATA_IS_NOT_INSTRUCTIONS}

Reply with a single JSON object matching the provided schema. No prose outside it."""


def build_grunt_messages(tasking: GruntTasking) -> list[dict[str, str]]:
    user = "\n\n".join(
        [
            "TASK",
            f"task_id: {tasking.task_id}",
            f"slice_id: {tasking.data_slice.slice_id}",
            f"instruction: {tasking.instruction}",
            # Intent is presented as its own labelled block, not merged into the
            # instruction: the worker should know which question it is serving without
            # being told what answer would please the commander.
            "COMMANDER'S INTENT (the hypothesis being tested; do not try to confirm it, "
            "report what is there):",
            tasking.commander_intent,
            "DATA",
            fence_log_slice(tasking.data_slice),
            "Now produce the JSON report.",
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

    The model is shown its own output and told precisely what was wrong with it. This
    is bounded to a single retry: a worker that cannot cite its slice correctly twice
    is a failure record, not an opportunity for a third try.
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
                "cannot support an observation with a line reference from this slice, "
                "remove that observation rather than inventing a reference."
            ),
        },
    ]
