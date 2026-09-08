"""One investigative step, as a structured value the orchestrator executes deterministically.

This replaces the sweep directive. The commander no longer describes relevance up front and
hand it to 83 workers; it asks one question at a time and is shown the answer.

**Why an action loop rather than native tool-calling.** vLLM can parse gpt-oss harmony
tool-calls, and that would be the fashionable choice. Guided decoding against a flat schema
has been the single most reliable component of this stack across seven runs, while every
model-side parsing convention we have touched has produced a silent failure mode at least
once (`--reasoning-parser` routing the whole response into the reasoning channel, and the
Marlin fallback returning `"content": null`, both of which look identical to a dead kernel
from the client side). Tool-calling would put the newest and most fragile parser in the hot
path of every single step. The action loop puts a JSON object there instead, and the
orchestrator -- not the model -- decides what running it means.

**Flat, not a discriminated union.** `oneOf` on a discriminator is the correct JSON Schema
for this and is exactly the construct schemas/jsonschema.py warns about: backends handle it
inconsistently, and inconsistently means "silently ignored" half the time. So every field
exists on every action, unused ones come back empty, and `validate_action` enforces in
Python what the grammar is not asked to. Shape from the grammar, meaning from Python.

There is no field here in which a verdict can be written. `conclude` ends the loop; it does
not decide anything. Deciding happens in the brief, which has no verdict field either, and
validation/no_verdict.py asserts both at import time.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ActionKind(str, Enum):
    """What the commander wants done next.

    The read-only verbs mirror corpus.py exactly, because the value of this design is that
    the operator can re-run any step by hand. `close_read` is the only one that spends a
    model: it hands a bounded line range to a worker for a question that counting cannot
    answer.

    tally/timeline/stats/extremes are the aggregation skills (aggregation.py): numbers
    about a pattern's matches without fetching the lines -- except extremes, which fetches
    the ten lines with the largest value so they can be cited. They are gated by `run.enabled_skills`
    so each can be trialled on its own; a disabled one is rejected by `validate_action`,
    not by the grammar -- shape from the grammar, meaning from Python, as everywhere else.
    """

    SEARCH = "search"
    COUNT = "count"
    TALLY = "tally"
    TIMELINE = "timeline"
    STATS = "stats"
    EXTREMES = "extremes"
    DECODE = "decode"
    CONTEXT = "context"
    READ_LINES = "read_lines"
    CLOSE_READ = "close_read"
    CONCLUDE = "conclude"


# The verbs run.enabled_skills may name, and the set the prompt only describes when
# enabled. Config validates against this at startup so a typo fails with a path, and the
# prompt and the validator draw from the same set so they can never disagree.
OPTIONAL_SKILLS = frozenset({
    ActionKind.TALLY.value,
    ActionKind.TIMELINE.value,
    ActionKind.STATS.value,
    ActionKind.EXTREMES.value,
    ActionKind.DECODE.value,
})

# The verbs that take the `field=`/`extract=` value selectors. timeline works off
# timestamps and takes none.
SELECTOR_KINDS = (ActionKind.TALLY, ActionKind.STATS, ActionKind.EXTREMES, ActionKind.DECODE)
# The fetch verbs whose `where`-filtered reproduce is a jq/awk field match (search/count
# render lines, context a window). The selectors below build their own reproduce.
FILTER_KINDS = (ActionKind.SEARCH, ActionKind.COUNT, ActionKind.CONTEXT)


def parse_predicate(entry: str) -> tuple[str, str, str] | str:
    """Parse one `where` entry into (field, op, value), or return an error string.

    A predicate is `<field><op><value>`, op one of: `=` (equals, case-insensitive), `!=`
    (not equals), `~` (regex matches the value), `!~` (regex does not match). The op is the
    first one found; the value may itself contain any of these characters. Shared by the
    validator (to reject a malformed predicate before the run) and the executor.
    """
    op = None
    cut = -1
    for i, ch in enumerate(entry):
        if ch == "!" and i + 1 < len(entry) and entry[i + 1] in "=~":
            op, cut = entry[i:i + 2], i
            break
        if ch in "=~":
            op, cut = ch, i
            break
    if op is None or cut == 0:
        return f"predicate {entry!r} needs '<field><op>value', op one of = != ~ !~"
    field, value = entry[:cut].strip(), entry[cut + len(op):]
    if not field:
        return f"predicate {entry!r} has an empty field name"
    if "~" in op:
        try:
            re.compile(value, re.IGNORECASE)
        except re.error as exc:
            return f"predicate {entry!r} has a bad regex: {exc}"
    return (field, op, value)

# Verbs whose argument is a regex in `pattern`.
PATTERN_KINDS = (
    ActionKind.SEARCH,
    ActionKind.COUNT,
    ActionKind.TALLY,
    ActionKind.TIMELINE,
    ActionKind.STATS,
    ActionKind.EXTREMES,
    ActionKind.DECODE,
)

# Every verb that reads lines through a pattern accepts `where` too, so the model can scope
# a tally/decode/timeline to one record kind the same way it scopes a search -- context is
# included (its window is anchored on a ref, but the ref's line still honours predicates).
WHERE_KINDS = PATTERN_KINDS + (ActionKind.CONTEXT,)

# Entity types `extract=` accepts. Kept in lockstep with aggregation.ENTITY_PATTERNS by a
# test, rather than imported, so the schema module stays free of runtime dependencies.
_EXTRACT_TYPES = frozenset({"ip", "domain", "hash", "email"})


class InvestigativeAction(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    reasoning: str = Field(
        description=(
            "Why you are taking this step, in one or two sentences. This is shown live to "
            "the SOC operator and written to the transcript."
        )
    )
    expectation: str = Field(
        description=(
            "What you expect to find, and what it would mean if you find nothing. State "
            "this BEFORE you see the result."
        )
    )
    action: ActionKind

    pattern: str = Field(
        default="",
        description=(
            "Regex, for search/count/tally/timeline/stats/extremes. Case-insensitive. It "
            "is the line FILTER; for tally/stats/extremes the value defaults to the first "
            "capture group unless 'field' or 'extract' selects it instead. Empty otherwise."
        ),
    )
    where: list[str] = Field(
        default_factory=list,
        description=(
            "Field predicates, ANDed, order-independent -- for any verb that reads lines "
            "through a pattern (search/count/context and tally/timeline/stats/extremes/"
            "decode), so an aggregate can be scoped to one record kind too. Each is "
            "'<field><op><value>' with op '=' (exact, case-insensitive), '!=', '~' (regex on "
            "the field's value) or '!~'. 'field' is a JSON key (dotted, e.g. 'Details.User') "
            "or a #fields column name. Use this to pin a record on a structured log instead "
            "of a regex that lists \"key\":\"value\" pairs in order -- key order does not "
            "matter here. Requires 'file'. Empty otherwise, e.g. [\"event_id=10\", "
            "\"computer=WKS-3355\"]."
        ),
    )
    file: str = Field(
        default="",
        description=(
            "Restrict to one log file by name. Empty means every file in the case. "
            "Required for read_lines and close_read, and for tally/stats/extremes with "
            "'field'."
        ),
    )
    field: str = Field(
        default="",
        description=(
            "For tally/stats/extremes: the delimited column to aggregate, by #fields name (e.g. "
            "'qtype_name') or 1-based number; for a JSON-lines file, a key (nested via "
            "dots, e.g. 'Details.User'). Removes the need for a column-counting regex -- "
            "the pattern only has to match the line. Empty otherwise."
        ),
    )
    extract: str = Field(
        default="",
        description=(
            "For tally/stats/extremes: pull every entity of this type from each matching line "
            "instead of a capture group. One of 'ip', 'domain', 'hash', 'email'. Empty "
            "otherwise."
        ),
    )
    ref: str = Field(
        default="",
        description="A '<file>:L<n>' reference, for context. Empty otherwise.",
    )
    start_line: int = Field(default=0, description="First line, for read_lines/close_read.")
    end_line: int = Field(default=0, description="Last line, for read_lines/close_read.")
    question: str = Field(
        default="",
        description=(
            "For close_read: the single specific question the worker must answer about "
            "that line range. Empty otherwise."
        ),
    )


# `expectation` is not decoration. A commander that states what a null result would mean
# before seeing the result cannot quietly reinterpret a miss as support afterwards -- and
# the transcript shows the operator whether it did. Two earlier runs built a hypothesis on
# absent evidence; this makes that visible at the step where it happens.


# A reference is "<file>:L<n>". Requiring only that `ref` be non-empty let "L978" through,
# and the file-less form then crashed the step that renders it.
_REF_SHAPE = re.compile(r"^[\w.\-/]+:L\d+$")


class ActionProblem(BaseModel):
    """A reason an action cannot be executed as written, phrased so it can be fixed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str
    message: str


def validate_action(
    action: InvestigativeAction,
    *,
    known_files: list[str],
    steps_taken: int = 0,
    min_steps: int = 0,
    enabled_skills: frozenset[str] | None = None,
) -> list[ActionProblem]:
    """Everything the grammar cannot check. Messages are fed back verbatim on a retry.

    `enabled_skills` gates the optional aggregation verbs so they can be hooked up one at
    a time; None means all of them are available (library use and tests). The grammar
    still admits every verb -- a disabled one is rejected here, with a message that
    redirects rather than merely refuses.
    """
    problems: list[ActionProblem] = []
    kind = action.action

    if (
        enabled_skills is not None
        and kind.value in OPTIONAL_SKILLS
        and kind.value not in enabled_skills
    ):
        problems.append(
            ActionProblem(
                field="action",
                message=(
                    f"'{kind.value}' is not available in this run. Use the verbs your "
                    f"instructions list -- a count or search usually answers the same "
                    f"question, one value at a time."
                ),
            )
        )

    # Concluding early is the loop's characteristic failure. The first real run stopped
    # after two steps -- having confirmed the alert and nothing else -- and then wrote
    # five unexamined avenues into coverage_gaps, including the two that would have
    # identified the host and the attacker's nameserver. Restating the alert is not an
    # investigation, and an unspent step is worth nothing to the operator.
    if kind is ActionKind.CONCLUDE and steps_taken < min_steps:
        problems.append(
            ActionProblem(
                field="action",
                message=(
                    f"you have taken only {steps_taken} step(s) and the budget is a "
                    f"ceiling, not a cost -- an unspent step is worth nothing. Before "
                    f"concluding, establish what the alert did NOT already tell you. "
                    f"Open questions worth a step each: which record kinds and low-cardinality "
                    f"fields you have not examined (the profile's record-type "
                    f"scope lists them), which host and (if the logs "
                    f"record one) which user, whether the "
                    f"pattern is confined to that host or estate-wide, what the RESPONSES "
                    f"carried, what the domain resolves to and what else touches that "
                    f"address, how the activity is distributed in time, and whether "
                    f"benign traffic of the same shape exists. Issue the most valuable of "
                    f"those instead, or conclude again only if every one is genuinely "
                    f"answered or unanswerable from these logs. A clean negative you "
                    f"already established counts as answered; record it in "
                    f"coverage_gaps rather than re-asking."
                ),
            )
        )

    def require(value: object, field: str, message: str) -> None:
        if not value:
            problems.append(ActionProblem(field=field, message=message))

    # A pattern verb normally needs a regex, but a `where`-only filter is a complete
    # question on its own -- for any verb that accepts `where` -- so the pattern is
    # optional then (a where-only tally counts a record kind; a where-only search fetches
    # it). timeline is the exception: its subject IS the pattern, so it always needs one.
    if kind in PATTERN_KINDS and not (
        kind is not ActionKind.TIMELINE and action.where
    ):
        require(action.pattern, "pattern", f"{kind.value} needs a regex in 'pattern'.")

    if action.where:
        if kind not in WHERE_KINDS:
            problems.append(
                ActionProblem(
                    field="where",
                    message=(
                        "'where' filters apply only to the verbs that read lines through a "
                        "pattern (search, count, context, tally, timeline, stats, extremes, "
                        "decode); leave it empty for this action."
                    ),
                )
            )
        if not action.file:
            problems.append(
                ActionProblem(
                    field="file",
                    message=(
                        "'where' names fields resolved against one file's header/keys -- "
                        "set 'file' too."
                    ),
                )
            )
        for entry in action.where:
            parsed = parse_predicate(entry)
            if isinstance(parsed, str):
                problems.append(ActionProblem(field="where", message=parsed))

    # The value selectors belong only to tally/stats/extremes, and only one at a time.
    # field-by-name needs a single file to resolve the header against; entity extraction
    # works estate-wide.
    if action.field or action.extract:
        if kind not in SELECTOR_KINDS:
            problems.append(
                ActionProblem(
                    field="field" if action.field else "extract",
                    message=(
                        "'field' and 'extract' apply only to tally, stats and extremes; "
                        "leave them empty for this action."
                    ),
                )
            )
        if action.field and action.extract:
            problems.append(
                ActionProblem(
                    field="extract",
                    message="set only one of 'field' or 'extract', not both.",
                )
            )
        if action.extract and action.extract not in _EXTRACT_TYPES:
            problems.append(
                ActionProblem(
                    field="extract",
                    message=(
                        f"extract must be one of {', '.join(sorted(_EXTRACT_TYPES))}; "
                        f"got {action.extract!r}."
                    ),
                )
            )
        if action.field and not action.file:
            problems.append(
                ActionProblem(
                    field="file",
                    message=(
                        "'field' names a column, which is resolved against one file's "
                        "header -- set 'file' too."
                    ),
                )
            )

    if kind is ActionKind.CONTEXT:
        if not action.ref:
            problems.append(
                ActionProblem(
                    field="ref", message="context needs a '<file>:L<n>' reference in 'ref'."
                )
            )
        elif not _REF_SHAPE.match(action.ref):
            # Built from what the model actually wrote. A fixed example from an unrelated
            # line ("'dns.log:L978', not 'L978'") is a worse hint: a run emitted the same
            # malformed ref twice against it and the loop gave up with most of its budget
            # unspent. coercion.repair_ref now fixes the common case before we get here.
            # Derived with the same helper that repairs it, so the hint and the repair can
            # never disagree about what the right answer is.
            from soc_poc.coercion import repair_ref

            fixed = repair_ref({"ref": action.ref, "file": action.file})["ref"]
            suggestion = (
                f" You appear to mean {fixed} -- write that."
                if fixed != action.ref
                else " Prefix it with the file it came from, exactly as shown."
            )
            problems.append(
                ActionProblem(
                    field="ref",
                    message=(
                        f"ref {action.ref!r} is not a reference. It must be the whole "
                        f"thing, file included, exactly as it was shown to you."
                        f"{suggestion}"
                    ),
                )
            )
        elif action.ref.partition(":L")[0] not in known_files:
            problems.append(
                ActionProblem(
                    field="ref",
                    message=(
                        f"ref {action.ref!r} names a file this case does not have. "
                        f"Available: {', '.join(known_files)}."
                    ),
                )
            )
    if kind in (ActionKind.READ_LINES, ActionKind.CLOSE_READ):
        require(action.file, "file", f"{kind.value} needs a 'file'.")
        if action.start_line < 1 or action.end_line < action.start_line:
            problems.append(
                ActionProblem(
                    field="start_line",
                    message=(
                        f"{kind.value} needs 1 <= start_line <= end_line; got "
                        f"{action.start_line}..{action.end_line}."
                    ),
                )
            )
    if kind is ActionKind.CLOSE_READ:
        require(
            action.question,
            "question",
            "close_read needs the specific question the worker should answer.",
        )

    # A named file that does not exist is the one mistake worth spending a retry on: the
    # fix is mechanical and the alternative is a confident conclusion drawn from a search
    # that never ran.
    if action.file and action.file not in known_files:
        problems.append(
            ActionProblem(
                field="file",
                message=(
                    f"no file named {action.file!r} in this case. Available: "
                    f"{', '.join(known_files)}."
                ),
            )
        )
    return problems
