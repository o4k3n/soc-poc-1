"""The append-only record of what the commander asked and what it was shown.

This is the run's memory and the run's audit trail, and it is deliberately the same
object for both. Two properties follow from that:

  * **Nothing is asserted that was not shown.** `shown_refs()` is the exact set of line
    references that passed in front of the commander. The brief's citations are checked
    against it, so "cited" continues to mean "read", which is the property the sweep
    architecture bought with 4,300 GPU-seconds of total coverage and then lost anyway
    when a worker reported a line it had not understood.
  * **The operator can re-run any step.** Every step is a regex or a line range against
    files on disk. The `grep` equivalent is printed in the transcript. A brief whose
    evidence can be reproduced by hand in three seconds is a different kind of artifact
    from one that can only be taken on trust.

Rendering is budgeted, because a 30-step investigation cannot be replayed verbatim into a
24k context. Recent steps stay whole; older ones keep their summary AND a sample of their
lines.

That sample is load-bearing, and an earlier version of this file got it wrong. The
reasoning used to be "counts survive collapse deliberately -- a step's match count is most
of its value and costs one line". That is true of `count`, whose entire product IS a
number, and false of `search`, where the lines are the answer and the count is merely how
many there were. Dropping the lines dropped the answer.

The failure it caused is worth stating plainly, because it is invisible from the code. A
run searched for a host address in dhcp.log at step 3 and was shown two lines naming the
workstation. By step 8 that step had aged out and rendered as:

    3. search /<addr>/ in dhcp.log -> 2 match(es) in dhcp.log; all shown

The hostname appeared nowhere in the prompt. So the commander correctly concluded it still
did not know it, and asked the identical question again -- and that fresh answer would have
aged out four steps later in turn. An unbounded loop, built out of a rendering choice. It
burned half that run's step budget and cost it two findings it never got around to looking
for, and it very nearly cost the brief the hostname: the fact reached synthesis only
because the loop happened to re-fetch it late enough to still be visible.

So a collapsed step keeps up to COLLAPSED_LINE_SAMPLE of its lines, elided harder than a
recent step's. Over 24 steps of 40-line searches that takes the rendering from ~2,700
tokens to ~5,100 against a 24,384 context, which is the right trade: the entire point of
the ledger is that the commander does not have to ask twice.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from soc_poc.corpus import Hit
from soc_poc.schemas.action import PATTERN_KINDS, ActionKind, InvestigativeAction

# Recent steps are replayed with all their lines; older ones keep their summary and a
# sample. Four is enough to hold a train of thought (search -> context -> count ->
# close_read) without the prompt growing without bound.
STEPS_RENDERED_IN_FULL = 4
# Lines an older step keeps when it collapses. This is not a nicety -- it is the fix for a
# loop that cost a graded run half its budget. See the module docstring.
COLLAPSED_LINE_SAMPLE = 3
COLLAPSED_LINE_MAX_CHARS = 130
# Per-step line budget. A step that matched 800 lines shows the first 40 (corpus.MAX_RESULTS
# caps that) and says so; this bounds the characters those 40 can spend.
STEP_LINE_BUDGET_CHARS = 3_000
LINE_MAX_CHARS = 260
LINE_HEAD_CHARS = 150


def elide(text: str, max_chars: int = LINE_MAX_CHARS) -> str:
    """Shorten from the middle, keeping both ends.

    Cutting the tail off a wide record throws away the column that usually settles the
    question. Zeek's dns.log puts `answers` last, so truncating from the right hid every
    TXT payload in the case -- and the commander, shown queries with their responses cut
    off, wrote "no DNS response payloads were captured" into a brief about a tunnel whose
    entire exfiltration channel was those payloads.
    """
    if len(text) <= max_chars:
        return text
    # Clamp the head so a small max_chars cannot drive the tail slice negative, which
    # silently returns most of the string instead of shortening it.
    head = min(LINE_HEAD_CHARS, max_chars // 2)
    tail = max(1, max_chars - head)
    return f"{text[:head]} …[{len(text) - head - tail} chars elided]… {text[-tail:]}"


@dataclass(frozen=True)
class Step:
    """One action and its result, as a value."""

    index: int
    action: InvestigativeAction
    summary: str
    lines: tuple[Hit, ...] = ()
    total_matches: int = 0
    truncated: int = 0
    error: str = ""
    # The shell command that reproduces this step, for the transcript and the brief.
    reproduce: str = ""
    # An aggregate's product (tally/timeline/stats): pre-rendered rows of counted
    # numbers, never log lines. Kept whole through collapse for the same reason count's
    # summary is -- the numbers ARE the answer, and dropping them on age-out is exactly
    # the rendering mistake that built the search loop this module documents.
    table: str = ""


@dataclass
class Evidence:
    steps: list[Step] = field(default_factory=list)

    def add(self, step: Step) -> None:
        self.steps.append(step)

    @property
    def next_index(self) -> int:
        return len(self.steps) + 1

    def shown_refs(self) -> set[str]:
        """Every line reference the commander has actually been shown.

        Used to validate the brief. A citation outside this set is not a citation; it is
        the model writing down a plausible-looking reference, which happened in run 3 and
        was only caught because the ref did not resolve.
        """
        return {hit.ref for step in self.steps for hit in step.lines}

    def line_text(self) -> dict[str, str]:
        return {hit.ref: hit.text for step in self.steps for hit in step.lines}

    def render(self) -> str:
        """The investigation so far, newest steps in full, older ones collapsed."""
        if not self.steps:
            return "(no steps taken yet)"

        cutoff = max(0, len(self.steps) - STEPS_RENDERED_IN_FULL)
        blocks: list[str] = []

        if cutoff:
            blocks.append(
                "EARLIER STEPS (counts are exact; lines are a sample of what you were "
                "shown -- if the answer you need is here, do not ask again):"
            )
            for step in self.steps[:cutoff]:
                blocks.append(f"  {step.index}. {_headline(step)} -> {step.summary}")
                blocks.extend(_table_lines(step, indent="       "))
                blocks.extend(_collapsed_lines(step))
            blocks.append("")

        blocks.append("RECENT STEPS (with the lines you were shown):")
        for step in self.steps[cutoff:]:
            blocks.append(f"\n  {step.index}. {_headline(step)}")
            blocks.append(f"     expected: {step.action.expectation}")
            blocks.append(f"     result:   {step.summary}")
            if step.error:
                blocks.append(f"     ERROR:    {step.error}")
            blocks.extend(_table_lines(step, indent="       "))
            blocks.extend(_render_lines(step))
        return "\n".join(blocks)


def _headline(step: Step) -> str:
    """The action as a one-liner, in the vocabulary the commander used to write it."""
    action = step.action
    kind = action.action
    scope = f" in {action.file}" if action.file else ""
    if kind in PATTERN_KINDS:
        return f"{kind.value} /{action.pattern}/{scope}"
    if kind is ActionKind.CONTEXT:
        return f"context around {action.ref}"
    if kind in (ActionKind.READ_LINES, ActionKind.CLOSE_READ):
        span = f"{action.file}:L{action.start_line}-L{action.end_line}"
        if kind is ActionKind.CLOSE_READ:
            return f"close_read {span} -- {action.question}"
        return f"read_lines {span}"
    return kind.value


def _table_lines(step: Step, *, indent: str) -> list[str]:
    """An aggregate's table, rendered identically whether the step is recent or aged.

    Deliberately exempt from collapse: it is counted numbers, bounded in size by
    construction (aggregation.py caps its rows), and re-deriving it would cost a step.
    """
    if not step.table:
        return []
    return [f"{indent}{line}" for line in step.table.splitlines()]


def _collapsed_lines(step: Step) -> list[str]:
    """The sample an aged-out step keeps. `count` has no lines and needs none."""
    if not step.lines:
        return []
    out = [
        f"       {hit.ref}  {elide(hit.text, COLLAPSED_LINE_MAX_CHARS)}"
        for hit in step.lines[:COLLAPSED_LINE_SAMPLE]
    ]
    withheld = len(step.lines) - len(out) + step.truncated
    if withheld:
        out.append(
            f"       … {withheld} further matching line(s) not shown here; "
            f"the count above is exact"
        )
    return out


def _render_lines(step: Step) -> list[str]:
    if not step.lines:
        return []
    out: list[str] = []
    spent = 0
    for hit in step.lines:
        entry = f"     {hit.ref}  {elide(hit.text)}"
        if spent + len(entry) > STEP_LINE_BUDGET_CHARS:
            out.append(f"     … {len(step.lines) - len(out)} more shown line(s) omitted here")
            break
        out.append(entry)
        spent += len(entry)
    if step.truncated:
        # Said out loud on every render. A silently truncated result is indistinguishable
        # from a complete one, and that is how a partial answer becomes a false negative.
        out.append(
            f"     … {step.truncated} further match(es) exist and were NOT shown. "
            f"The count {step.total_matches} is exact; the listing is not complete."
        )
    return out
