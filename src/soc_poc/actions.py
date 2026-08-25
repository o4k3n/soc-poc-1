"""Executing an action against the corpus. Deterministic, and reproducible by hand.

The verbs here spend no GPU and no model. That is the entire argument for this
architecture: the questions the sweep answered badly and expensively ("does 10.12.34.56
appear in dhcp.log?", "how many queries went to this domain?") are questions with exact
answers, and an exact answer cannot be talked out of itself.

`close_read` is handled by the orchestrator instead, because it is the one verb that
spends a worker. It survives because some questions genuinely need reading rather than
counting -- "what do these 30 lines have in common?" is not a regex -- but it is now
requested deliberately at a bounded line range, rather than issued 83 times at everything.
"""

from __future__ import annotations

import re
import shlex

from soc_poc.corpus import Corpus, SearchResult
from soc_poc.evidence import Step
from soc_poc.schemas.action import ActionKind, InvestigativeAction


def reproduce_command(action: InvestigativeAction, logs_dir: str = "logs") -> str:
    """The shell equivalent, so a reader can check the machine's work.

    Printed into the transcript for every step. An investigation whose evidence can be
    re-derived with grep is auditable in a way that "a language model read it and said so"
    is not, and that difference is the deliverable.
    """
    target = f"{logs_dir}/{action.file}" if action.file else f"{logs_dir}/*"
    if action.action is ActionKind.SEARCH:
        return f"grep -niE {shlex.quote(action.pattern)} {target}"
    if action.action is ActionKind.COUNT:
        return f"grep -ciE {shlex.quote(action.pattern)} {target}"
    if action.action is ActionKind.CONTEXT:
        name, _, number = action.ref.partition(":L")
        if not number.isdigit():
            # A malformed ref reached here once ("L978", missing the file prefix) and the
            # int() raised straight through the orchestrator loop, ending a 21-step
            # investigation with no brief. The validator now rejects that shape, but this
            # function renders a string for a human and must never be able to end a run.
            return f"# unparseable reference {action.ref!r}"
        return f"sed -n '{max(1, int(number) - 5)},{int(number) + 5}p' {logs_dir}/{name}"
    if action.action in (ActionKind.READ_LINES, ActionKind.CLOSE_READ):
        return f"sed -n '{action.start_line},{action.end_line}p' {target}"
    return ""


# Regex metacharacters, and the escapes that are really metacharacters. `\.` is a literal
# dot and belongs in a literal run; `\t` is a tab and ends one.
_META_CHARS = set(".^$*+?{}[]()|")
_ESCAPED_LITERALS = set(".^$*+?{}[]()|/-\\\"'`~@#%&=:;,_<> ")
# Below this a "literal" is too short to mean anything -- `\tTXT\t` reduces to "TXT",
# which occurs in every DNS log ever written and would produce a useless hint on every
# miss. A warning printed on every miss is a warning nobody reads.
_MIN_LITERAL = 8


def _longest_literal(pattern: str) -> str:
    """The longest run of characters the data must contain verbatim.

    Splitting on backslashes is not enough: `\twks-2291` would yield `twks-2291`, taking
    the `t` from the tab escape into the literal and probing for a string that cannot
    occur. So this walks the pattern and decides per escape whether it is a character or
    a metacharacter.
    """
    runs: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            following = pattern[index + 1]
            if following in _ESCAPED_LITERALS:
                current.append(following)
            else:
                runs.append("".join(current))
                current = []
            index += 2
            continue
        if char in _META_CHARS:
            runs.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    runs.append("".join(current))
    best = max(runs, key=len) if runs else ""
    return best if len(best) >= _MIN_LITERAL else ""


def zero_result_hint(pattern: str, file: str, corpus: Corpus) -> str:
    r"""Distinguish "the data does not contain this" from "your pattern is wrong".

    This exists because of a graded run. The commander searched
    `\tTXT\t.*t\.api-sync-telemetry\.net`, got zero, and wrote that zero into the brief
    as *contradicting evidence against the tunnel hypothesis*. There are 649 such queries.
    Zeek's dns.log puts the query before the qtype, so that pattern can never match however
    much tunnelling is going on -- the zero was an artifact of column order.

    The prompt already says a zero is only a zero for the pattern you typed. It said that
    during this run. So the check moves into code: on any empty result, count the longest
    literal in the pattern on its own. If the literal is there and the pattern is not, the
    pattern is what is wrong, and the step says so where the commander cannot miss it.
    """
    literal = _longest_literal(pattern)
    if not literal:
        return ""
    probe = corpus.count(re.escape(literal), file=file)
    if probe.total_matches == 0:
        return ""
    return (
        f" NOTE: the literal {literal!r} on its own occurs {probe.total_matches} time(s) "
        f"here, so this zero is about your PATTERN, not about the data. Check field order "
        f"and separators before treating it as absence."
    )


def _summarise(result: SearchResult, kind: ActionKind) -> str:
    if result.error:
        return f"failed: {result.error}"
    scope = result.file or f"{len(result.files_searched)} file(s)"
    if kind is ActionKind.COUNT:
        return f"{result.total_matches} match(es) in {scope}"
    if result.total_matches == 0:
        # Worth stating in full every time. This is the negative the whole redesign exists
        # to make trustworthy, and it should read as a result, not as a silence.
        return f"0 matches in {scope} -- this pattern does not occur there"
    shown = len(result.returned)
    if result.truncated:
        return (
            f"{result.total_matches} match(es) in {scope}; showing the first {shown}"
        )
    return f"{result.total_matches} match(es) in {scope}; all shown"


def execute_readonly(
    action: InvestigativeAction, corpus: Corpus, *, index: int, logs_dir: str = "logs"
) -> Step:
    """Run one deterministic action. Never raises: a bad request becomes a Step with an error."""
    kind = action.action
    if kind is ActionKind.SEARCH:
        result = corpus.search(action.pattern, file=action.file)
    elif kind is ActionKind.COUNT:
        result = corpus.count(action.pattern, file=action.file)
    elif kind is ActionKind.CONTEXT:
        result = corpus.context(action.ref)
    elif kind is ActionKind.READ_LINES:
        hits = corpus.slice_lines(action.file, action.start_line, action.end_line)
        result = SearchResult(
            pattern=f"lines {action.start_line}-{action.end_line}",
            file=action.file,
            total_matches=len(hits),
            returned=hits,
            files_searched=[action.file],
            error="" if hits else f"{action.file} has no lines in that range",
        )
    else:  # pragma: no cover - the orchestrator routes close_read/conclude itself
        raise ValueError(f"{kind.value} is not a read-only action")

    summary = (
        _summarise(result, kind)
        if kind is not ActionKind.READ_LINES
        else f"{len(result.returned)} line(s) returned"
    )
    if result.total_matches == 0 and not result.error and action.pattern:
        summary += zero_result_hint(action.pattern, action.file, corpus)
    return Step(
        index=index,
        action=action,
        summary=summary,
        # count deliberately carries no lines: its whole purpose is a cheap exact number,
        # and returning lines would make it a search with extra steps.
        lines=tuple(result.returned) if kind is not ActionKind.COUNT else (),
        total_matches=result.total_matches,
        truncated=result.truncated if kind is not ActionKind.COUNT else 0,
        error=result.error,
        reproduce=reproduce_command(action, logs_dir),
    )
