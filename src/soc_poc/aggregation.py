"""Aggregation verbs: the numbers a pattern's matches make, without fetching the lines.

Lines are the scarce resource in this architecture. Every line a search returns lands in
the evidence ledger and is re-rendered on every later commander turn; a number costs a
sentence. These verbs exist so the commander can learn the *shape* of a result set --
which values, how many of each, when, how big -- before deciding which few lines are
actually worth fetching. The alternative is what the transcripts show today: a
distribution enumerated one `count` per guess, eight steps for one `tally`.

Everything here is counted, not inferred, exactly like profiling.py: no model produces
any number, and every result can be re-derived with grep, sort and awk. The shell
equivalent is printed in the step ledger by actions.reproduce_command.

None of these return log lines, so nothing here enters `shown_refs()` -- an aggregate is
not a citation and must never be mistaken for one. Its product is the number itself,
which survives ledger collapse in full for the same reason `count`'s summary does: the
number IS the answer, and keeping it is what stops the commander asking twice.
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone

from soc_poc.corpus import Corpus
from soc_poc.profiling import BURST_GAP_FACTOR, _humanise, _timestamp

# How much of a distribution a tally shows. Top values say what dominates; the rarest
# say what is unusual, and in this codebase the unusual is where the answer usually is
# (the NS delegation was 1 occurrence among 5,586 lines). Between the two ends the
# middle is summarised as a count, never silently dropped.
TALLY_TOP_SHOWN = 12
TALLY_RARE_SHOWN = 5
# A tally value can be a 40-character tunnel label; clip for rendering, keeping both
# ends -- the same lesson as evidence.elide, where cutting tails hid every payload.
VALUE_MAX_CHARS = 80
# Sessions reported by timeline. More than this is not session structure, it is noise.
TIMELINE_MAX_SESSIONS = 12

_NUMERIC = re.compile(r"^-?\d+(\.\d+)?$")


def _clip(value: str) -> str:
    if len(value) <= VALUE_MAX_CHARS:
        return value
    half = VALUE_MAX_CHARS // 2 - 2
    return f"{value[:half]}…{value[-half:]}"


def _extract(
    corpus: Corpus, pattern: str, file: str
) -> tuple[list[str], int, str] | tuple[None, int, str]:
    """Every extracted value in corpus order, plus how many lines matched.

    The value is the first capture group when the pattern has one, otherwise the whole
    match -- the same convention as `grep -oE` piped through `sed s//\\1/`, which is what
    the reproduce command prints. All occurrences per line count, not just the first.
    """
    if file and file not in corpus.file_names:
        return None, 0, f"no such file {file!r}; this case has {', '.join(corpus.file_names)}"
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return None, 0, f"bad regex: {exc}"
    group = 1 if regex.groups else 0
    values: list[str] = []
    matched_lines = 0
    for name in [file] if file else corpus.file_names:
        for text in corpus.file_lines(name):
            found = [m.group(group) or "" for m in regex.finditer(text)]
            if found:
                matched_lines += 1
                values.extend(found)
    return values, matched_lines, ""


@dataclass(frozen=True)
class Aggregate:
    """One aggregate result: a one-line headline and the table behind it.

    `matched_lines` is what a Step reports as its match count, so an aggregate's zero
    gets the same zero_result_hint treatment a search's does -- a zero from a wrong
    pattern must not read as absence here either.
    """

    headline: str
    matched_lines: int = 0
    table: tuple[str, ...] = field(default=())
    error: str = ""


def tally(corpus: Corpus, pattern: str, *, file: str = "") -> Aggregate:
    """Distinct values of a pattern with exact counts: a distribution in one step.

    "Which hosts query this domain, and how often each" is one tally. The transcripts
    show the alternative: runs spending 20+ `count` actions enumerating a distribution
    one guessed value at a time.
    """
    values, matched_lines, error = _extract(corpus, pattern, file)
    if values is None:
        return Aggregate(headline=f"failed: {error}", error=error)
    scope = file or f"{len(corpus.file_names)} file(s)"
    if not values:
        return Aggregate(
            headline=f"0 matches in {scope} -- this pattern does not occur there"
        )

    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))

    rows = [f"{count:>7}x  {_clip(value)}" for value, count in ranked[:TALLY_TOP_SHOWN]]
    hidden = ranked[TALLY_TOP_SHOWN:]
    if hidden:
        rare = hidden[-TALLY_RARE_SHOWN:]
        middle = len(hidden) - len(rare)
        if middle:
            rows.append(f"        … {middle} further distinct value(s) not listed …")
        rows.append("rarest (a value occurring once among many is worth a look):")
        rows.extend(f"{count:>7}x  {_clip(value)}" for value, count in rare)
    return Aggregate(
        headline=(
            f"{len(values)} occurrence(s) of {len(counts)} distinct value(s) "
            f"across {matched_lines} line(s) in {scope}"
        ),
        matched_lines=matched_lines,
        table=tuple(rows),
    )


def _to_epoch(stamp: str) -> float | None:
    """A comparable number for any stamp shape profiling._timestamp recognises.

    Syslog stamps carry no year; they land in 1900, which keeps ordering and gaps
    correct within one capture and is wrong across a New Year -- the render shows the
    stamps themselves, so the reader sees the assumption rather than inheriting it.
    """
    if stamp.replace(".", "", 1).isdigit():
        return float(stamp)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
        try:
            return datetime.strptime(stamp, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def timeline(corpus: Corpus, pattern: str, *, file: str = "") -> Aggregate:
    """When a pattern's matches happen: span, gap statistics, session structure.

    Bursty and periodic are different signatures, and briefs have repeatedly described
    one as the other. profiling.py settles this once, for the one subject it picks
    itself; this lets the commander ask it of any pattern. Same gap logic, same
    threshold, so the two can never disagree about what a burst is.
    """
    if file and file not in corpus.file_names:
        error = f"no such file {file!r}; this case has {', '.join(corpus.file_names)}"
        return Aggregate(headline=f"failed: {error}", error=error)
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return Aggregate(headline=f"failed: bad regex: {exc}", error=f"bad regex: {exc}")

    stamps: list[str] = []
    matched_lines = 0
    for name in [file] if file else corpus.file_names:
        for text in corpus.file_lines(name):
            if regex.search(text):
                matched_lines += 1
                stamp = _timestamp(text)
                if stamp is not None:
                    stamps.append(stamp)
    scope = file or f"{len(corpus.file_names)} file(s)"
    if not matched_lines:
        return Aggregate(
            headline=f"0 matches in {scope} -- this pattern does not occur there"
        )

    headline = (
        f"{matched_lines} matching line(s) in {scope}, "
        f"{len(stamps)} with a recognisable timestamp"
    )
    numeric = sorted(v for v in (_to_epoch(s) for s in stamps) if v is not None)
    if len(numeric) < 2:
        return Aggregate(
            headline=headline,
            matched_lines=matched_lines,
            table=("not enough timestamps to characterise timing",),
        )

    rows = [f"span: {_humanise_epoch(numeric[0])} .. {_humanise_epoch(numeric[-1])}"]
    gaps = sorted(b - a for a, b in zip(numeric, numeric[1:]))
    median = statistics.median(gaps)
    rows.append(
        f"inter-event gaps: median {median:.1f}s, "
        f"p95 {gaps[min(len(gaps) - 1, int(len(gaps) * 0.95))]:.1f}s, "
        f"max {gaps[-1]:.1f}s"
    )

    threshold = (median or 1.0) * BURST_GAP_FACTOR
    sessions: list[tuple[float, float, int]] = []
    start = 0
    for index, (a, b) in enumerate(zip(numeric, numeric[1:])):
        if b - a > threshold:
            sessions.append((numeric[start], numeric[index], index - start + 1))
            start = index + 1
    sessions.append((numeric[start], numeric[-1], len(numeric) - start))

    if len(sessions) == 1:
        rows.append(
            f"no idle gap exceeds {BURST_GAP_FACTOR:g}x the median: activity is "
            f"continuous or evenly paced across the span, not bursty"
        )
    else:
        rows.append(
            f"{len(sessions)} burst(s) separated by idle gaps > "
            f"{BURST_GAP_FACTOR:g}x median ({threshold:.0f}s):"
        )
        for begin, end, events in sessions[:TIMELINE_MAX_SESSIONS]:
            rows.append(
                f"  {_humanise_epoch(begin)} .. {_humanise_epoch(end)}   {events} event(s)"
            )
        if len(sessions) > TIMELINE_MAX_SESSIONS:
            rows.append(f"  … {len(sessions) - TIMELINE_MAX_SESSIONS} further burst(s)")
    return Aggregate(headline=headline, matched_lines=matched_lines, table=tuple(rows))


def _humanise_epoch(value: float) -> str:
    return _humanise(str(int(value))) if value > 1_000_000_000 else f"t+{value:.0f}s"


def stats(corpus: Corpus, pattern: str, *, file: str = "") -> Aggregate:
    """Size statistics over a pattern's extracted values: "how big" without lines.

    Numeric when every extracted value is a number (byte counts, ports, durations);
    otherwise statistics over the values' LENGTHS, stated as such -- which is the mode
    that answers "are these query labels abnormally long" for a tunnel.
    """
    values, matched_lines, error = _extract(corpus, pattern, file)
    if values is None:
        return Aggregate(headline=f"failed: {error}", error=error)
    scope = file or f"{len(corpus.file_names)} file(s)"
    if not values:
        return Aggregate(
            headline=f"0 matches in {scope} -- this pattern does not occur there"
        )

    if all(_NUMERIC.match(value) for value in values):
        mode = "numeric values"
        series = sorted(float(value) for value in values)
    else:
        mode = "value lengths in characters (values are not all numeric)"
        series = sorted(float(len(value)) for value in values)

    p95 = series[min(len(series) - 1, int(len(series) * 0.95))]
    rows = (
        f"statistic over: {mode}",
        f"n={len(series)}, distinct values={len(set(values))}",
        f"min {series[0]:g}, median {statistics.median(series):g}, "
        f"mean {statistics.fmean(series):.1f}, p95 {p95:g}, max {series[-1]:g}"
        + (f", sum {sum(series):g}" if mode.startswith("numeric") else ""),
    )
    return Aggregate(
        headline=(
            f"{len(values)} value(s) from {matched_lines} line(s) in {scope}"
        ),
        matched_lines=matched_lines,
        table=rows,
    )
