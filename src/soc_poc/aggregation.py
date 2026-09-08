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

tally, timeline and stats return no log lines, so nothing they produce enters
`shown_refs()` -- a number is not a citation and must never be mistaken for one. Their
product is the number itself, which survives ledger collapse in full for the same reason
`count`'s summary does: the number IS the answer, and keeping it is what stops the
commander asking twice.

`extremes` is the deliberate exception. Its product is the lines BEHIND a number -- the
ten matches with the largest value -- and those lines are returned with their references
precisely so they can be cited. It is the bridge from "max request_body_len is 46392" to
the line that says so; without it the transcripts show the commander hand-rolling
digit-range regexes for four steps to fetch "the big ones".
"""

from __future__ import annotations

import base64
import re
import statistics
from dataclasses import dataclass, field

from soc_poc.corpus import Corpus, Hit, _json_value, _resolve_field
from soc_poc.profiling import (
    _DOMAIN,
    _IP,
    _LONG_TOKEN,
    BURST_GAP_FACTOR,
    _entropy,
    _humanise,
    _timestamp,
    _to_epoch,
)

# Entity recognisers for `extract=`, reusing the exact shapes profiling.py already counts,
# plus email. All are non-capturing, so `findall` returns whole matches. This is what turns
# a tally into IOC extraction: "every IP in lines mentioning the C2", in one step, with no
# column-counting regex to get wrong.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
ENTITY_PATTERNS: dict[str, re.Pattern[str]] = {
    "ip": _IP,
    "domain": _DOMAIN,
    "hash": _LONG_TOKEN,
    "email": _EMAIL,
}

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
# Lines extremes returns. These are real lines entering the ledger, so the cap is a
# context cost, not a rendering nicety: ten is enough to see the shape of a tail (the 14
# exfil POSTs in http-c2 fill it with one signal) and small enough to fit a step's line
# budget in evidence.py.
EXTREMES_SHOWN = 10

# Decimal, or a 0x-prefixed hex literal: Windows access masks (Sysmon GrantedAccess
# 0x1010, 0x1FFFFF) are numbers an analyst compares, and ranking them by string length
# would put every six-character mask on a par.
_NUMERIC = re.compile(r"^(-?\d+(\.\d+)?|0[xX][0-9a-fA-F]+)$")


def _as_number(value: str) -> float:
    """The number a _NUMERIC-matching value denotes."""
    if value[:2].lower() == "0x":
        return float(int(value, 16))
    return float(value)


def _fmt_number(value: float) -> str:
    """Plain digits for whole numbers however large: `44210880`, never `4.42109e+07` --
    a byte count in scientific notation is a number the reader has to decode."""
    if float(value).is_integer():
        return str(int(value))
    return f"{value:g}"


def _clip(value: str) -> str:
    if len(value) <= VALUE_MAX_CHARS:
        return value
    half = VALUE_MAX_CHARS // 2 - 2
    return f"{value[:half]}…{value[-half:]}"


def _selected_rows(
    corpus: Corpus,
    pattern: str,
    file: str,
    *,
    field: str = "",
    extract: str = "",
    where: list[tuple[str, str, str]] | None = None,
) -> tuple[list[tuple[str, Hit]], int, str] | tuple[None, int, str]:
    """Every selected value in corpus order, each paired with the line it came from, plus
    how many lines the pattern matched.

    `pattern` is always the line filter. What it selects as the *value* depends on the
    selector, in precedence order:

      * `extract="ip|domain|hash|email"` -- every entity of that type on the line. This is
        the IOC-extraction mode, and it needs no capture group.
      * `field="<name or 1-based number>"` -- one delimited column, resolved through the
        file's `#fields` header. This is what removes the column-counting regex: the
        pattern only has to MATCH the line, and the field picks the value exactly. On a
        JSON-lines file the field is a key (dotted for nesting) and there are no
        numbered columns.
      * otherwise -- the first capture group, or the whole match. The original behaviour,
        byte-for-byte, so nothing that worked before changes.

    Comment/header lines are skipped only in the selector modes, where splitting the
    `#fields` line into columns would otherwise pollute the result.

    The `Hit` is built exactly as `corpus.search` builds one, so a reference from here
    resolves like any other. tally/stats discard it (see `_extract`); extremes keeps it.
    """
    if file and file not in corpus.file_names:
        return None, 0, f"no such file {file!r}; this case has {', '.join(corpus.file_names)}"
    if extract and extract not in ENTITY_PATTERNS:
        return None, 0, (
            f"unknown extract type {extract!r}; use one of {', '.join(sorted(ENTITY_PATTERNS))}"
        )
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return None, 0, f"bad regex: {exc}"

    selecting = bool(field or extract)
    rows: list[tuple[str, Hit]] = []
    matched_lines = 0
    for name in [file] if file else corpus.file_names:
        index = None
        separator = "\t"
        objects = corpus.json_objects(name) if field else None
        # `where` predicates are resolved against the line's PARSED fields, the same way
        # a search's are, and independently of the value selector -- so a tally/decode can
        # be scoped to one record kind without a key-order regex.
        where_objects = corpus.json_objects(name) if where else None
        where_fmap = corpus.field_map(name) if (where and where_objects is None) else {}
        where_sep = corpus.separator(name) if (where and where_objects is None) else "\t"
        if field and objects is not None:
            if field.strip().isdigit():
                keys = ", ".join(k for k, _ in corpus.json_keys(name)[:12])
                return None, 0, (
                    f"{name} is JSON lines: it has keys, not numbered columns; name a key "
                    f"(e.g. {keys})"
                )
        elif field:
            field_map = corpus.field_map(name)
            index = _resolve_field(field, field_map)
            if index is None:
                available = ", ".join(sorted(field_map, key=lambda k: field_map[k]))
                return None, 0, (
                    f"no field {field!r} in {name}; "
                    + (f"available: {available}" if available
                       else "this file has no #fields header, so name a 1-based column number")
                )
            separator = corpus.separator(name)
        for number, text in enumerate(corpus.file_lines(name), start=1):
            if selecting and text.startswith("#"):
                continue
            if not regex.search(text):
                continue
            if where and not corpus._line_matches(
                number, text, where, fmap=where_fmap, sep=where_sep, objects=where_objects
            ):
                continue
            matched_lines += 1
            hit = Hit(f"{name}:L{number}", text)
            if extract:
                rows.extend((v, hit) for v in ENTITY_PATTERNS[extract].findall(text))
            elif field and objects is not None:
                obj = objects[number - 1]
                value = _json_value(obj, field) if obj else None
                if value is not None:
                    rows.append((value, hit))
            elif field:
                columns = text.split(separator)
                if index is not None and 0 <= index < len(columns):
                    rows.append((columns[index], hit))
            else:
                group = 1 if regex.groups else 0
                rows.extend((m.group(group) or "", hit) for m in regex.finditer(text))
        if field and objects is not None and matched_lines and not rows:
            # Keys vary by event type in a JSON log, so an absent key is not known until
            # the lines are read. Silence here would read as "the value is empty".
            keys = ", ".join(k for k, _ in corpus.json_keys(name)[:12])
            return None, matched_lines, (
                f"{matched_lines} line(s) in {name} match, but none carries the key "
                f"{field!r}; keys seen in this file: {keys}"
            )
    return rows, matched_lines, ""


def _extract(
    corpus: Corpus,
    pattern: str,
    file: str,
    *,
    field: str = "",
    extract: str = "",
    where: list[tuple[str, str, str]] | None = None,
) -> tuple[list[str], int, str] | tuple[None, int, str]:
    """`_selected_rows` without the references: the values alone, for the verbs whose
    product is a number. Byte-for-byte the pre-extremes behaviour."""
    rows, matched_lines, error = _selected_rows(
        corpus, pattern, file, field=field, extract=extract, where=where
    )
    if rows is None:
        return None, matched_lines, error
    return [value for value, _ in rows], matched_lines, ""


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
    # Only extremes fills this. Its rows are real lines with references, and actions.py
    # puts them on the Step as `lines` so they enter shown_refs() and can be cited.
    hits: tuple[Hit, ...] = field(default=())


def tally(
    corpus: Corpus,
    pattern: str,
    *,
    file: str = "",
    field: str = "",
    extract: str = "",
    where: list[tuple[str, str, str]] | None = None,
) -> Aggregate:
    """Distinct values of a pattern with exact counts: a distribution in one step.

    "Which hosts query this domain, and how often each" is one tally. The transcripts
    show the alternative: runs spending 20+ `count` actions enumerating a distribution
    one guessed value at a time. `field=` and `extract=` choose the value without a
    capture group -- see `_extract`.
    """
    values, matched_lines, error = _extract(
        corpus, pattern, file, field=field, extract=extract, where=where
    )
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


def timeline(
    corpus: Corpus,
    pattern: str,
    *,
    file: str = "",
    where: list[tuple[str, str, str]] | None = None,
) -> Aggregate:
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
        where_objects = corpus.json_objects(name) if where else None
        where_fmap = corpus.field_map(name) if (where and where_objects is None) else {}
        where_sep = corpus.separator(name) if (where and where_objects is None) else "\t"
        for number, text in enumerate(corpus.file_lines(name), start=1):
            if not regex.search(text):
                continue
            if where and not corpus._line_matches(
                number, text, where, fmap=where_fmap, sep=where_sep, objects=where_objects
            ):
                continue
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


def stats(
    corpus: Corpus,
    pattern: str,
    *,
    file: str = "",
    field: str = "",
    extract: str = "",
    where: list[tuple[str, str, str]] | None = None,
) -> Aggregate:
    """Size statistics over a pattern's selected values: "how big" without lines.

    Numeric when every selected value is a number (byte counts, ports, durations);
    otherwise statistics over the values' LENGTHS, stated as such -- which is the mode
    that answers "are these query labels abnormally long" for a tunnel. `field=` selects a
    numeric column directly (`field="response_body_len"`), which is the usual way in.
    """
    values, matched_lines, error = _extract(
        corpus, pattern, file, field=field, extract=extract, where=where
    )
    if values is None:
        return Aggregate(headline=f"failed: {error}", error=error)
    scope = file or f"{len(corpus.file_names)} file(s)"
    if not values:
        return Aggregate(
            headline=f"0 matches in {scope} -- this pattern does not occur there"
        )

    if all(_NUMERIC.match(value) for value in values):
        mode = "numeric values"
        series = sorted(_as_number(value) for value in values)
    else:
        mode = "value lengths in characters (values are not all numeric)"
        series = sorted(float(len(value)) for value in values)

    p95 = series[min(len(series) - 1, int(len(series) * 0.95))]
    rows = (
        f"statistic over: {mode}",
        f"n={len(series)}, distinct values={len(set(values))}",
        f"min {_fmt_number(series[0])}, median {_fmt_number(statistics.median(series))}, "
        f"mean {statistics.fmean(series):.1f}, p95 {_fmt_number(p95)}, "
        f"max {_fmt_number(series[-1])}"
        + (f", sum {_fmt_number(sum(series))}" if mode.startswith("numeric") else ""),
    )
    return Aggregate(
        headline=(
            f"{len(values)} value(s) from {matched_lines} line(s) in {scope}"
        ),
        matched_lines=matched_lines,
        table=rows,
    )


def _rank_key(values: list[str]) -> tuple[str, bool]:
    """The mode stats and extremes share: numeric when every value is a number, else
    lengths, and the caller says which."""
    if all(_NUMERIC.match(value) for value in values):
        return "numeric value", True
    return "value length in characters (values are not all numeric)", False


def extremes(
    corpus: Corpus,
    pattern: str,
    *,
    file: str = "",
    field: str = "",
    extract: str = "",
    where: list[tuple[str, str, str]] | None = None,
) -> Aggregate:
    """The matching lines with the largest selected value, with references: the evidence
    behind a stats maximum or a tally's long tail, in one step.

    Same selectors as stats. Numeric when every selected value is a number (byte counts,
    ports); otherwise ranked by the value's LENGTH, stated as such -- the mode that hands
    over the longest DNS labels or the longest TXT answers. One row per line: a line that
    yields several values contributes its largest, so the ten rows are ten distinct
    citations. Ties keep corpus order.

    This is the one aggregate that returns lines. It is also the one that costs context,
    so the table ends with where the top ten sit in the whole distribution (the next
    value, median, min) -- the commander should be able to tell from that whether the
    tail it fetched is a cliff or a slope without fetching more.
    """
    rows, matched_lines, error = _selected_rows(
        corpus, pattern, file, field=field, extract=extract, where=where
    )
    if rows is None:
        return Aggregate(headline=f"failed: {error}", error=error)
    scope = file or f"{len(corpus.file_names)} file(s)"
    if not rows:
        return Aggregate(
            headline=f"0 matches in {scope} -- this pattern does not occur there"
        )

    mode, numeric = _rank_key([value for value, _ in rows])
    measure = _as_number if numeric else (lambda v: float(len(v)))

    # Best value per line, in corpus order, so a sort (stable) breaks ties by position.
    best: dict[str, tuple[float, str, Hit]] = {}
    for value, hit in rows:
        key = measure(value)
        if hit.ref not in best or key > best[hit.ref][0]:
            best[hit.ref] = (key, value, hit)
    ranked = sorted(best.values(), key=lambda item: item[0], reverse=True)
    top = ranked[:EXTREMES_SHOWN]
    series = [item[0] for item in ranked]

    fmt = _fmt_number

    # Value first, ref last: the stub client cites anything that starts with a ref, and
    # these rows are a table, not the lines themselves (those follow via Step.lines).
    table = [f"ranked by: {mode}, largest first"]
    for rank, (key, value, hit) in enumerate(top, start=1):
        if numeric:
            # The value as written, and its number when they differ (0x1010 -> 4112), so a
            # hex access mask stays recognisable and still reads as the size it is.
            shown = value if fmt(key) == value else f"{value} (={fmt(key)})"
        else:
            shown = f"{fmt(key)} chars  {_clip(value)}"
        table.append(f"#{rank:<2} {shown}  <- {hit.ref}")
    tail = f"n={len(ranked)} line(s)"
    if len(ranked) > len(top):
        tail += (
            f", showing top {len(top)}; next value {fmt(series[len(top)])}, "
            f"median {fmt(statistics.median(series))}, min {fmt(series[-1])}"
        )
    else:
        tail += f", all {len(ranked)} shown; min {fmt(series[-1])}"
    table.append(tail)

    return Aggregate(
        headline=(
            f"top {len(top)} of {len(ranked)} line(s) in {scope} by {mode.split(' (')[0]}"
        ),
        matched_lines=matched_lines,
        table=tuple(table),
        hits=tuple(hit for _, _, hit in top),
    )


# A base64 run worth trying: standard alphabet, long enough to be a payload not an id or a
# stray token. Padding is optional in the middle of a field, required at the end of a whole
# value, so it is matched but not relied on.
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
DECODE_SHOWN = 10


def _looks_base64(run: str) -> bool:
    """Does a run have base64's SHAPE, beyond merely being 16+ alphanumeric characters?

    The `_B64_RUN` regex alone flags ordinary long tokens -- a task name like
    `HealthTelemetryUpdater`, a Windows path segment, a CamelCase field -- and a graded run
    then reported 233 such tokens as "looked base64 but did not validate", burying the one
    genuine truncated-payload signal that phrase is meant to carry. Real base64 of
    non-trivial bytes (a UTF-16LE PowerShell payload above all) is high-entropy and mixes
    character classes: it carries digits or `+`/`/`, or at least varied case, and does not
    read as an English/identifier word. A plain word has neither. This gate decides only
    whether a NON-decoding run is worth flagging; it never blocks a run from being decoded.
    """
    if len(run) < 16:
        return False
    body = run.rstrip("=")
    # The clean discriminator: real base64 of non-trivial bytes carries digits (or `+`/`/`)
    # -- a UTF-16LE PowerShell payload above all, whose null high bytes and varied ASCII
    # both encode to runs that include digits -- whereas an English word, a CamelCase
    # field, or a Windows path segment does not, however long or mixed-case it is. A
    # modest entropy floor then drops the degenerate case of a long digit-bearing run that
    # is really just repetition.
    has_digit_or_symbol = any(ch.isdigit() or ch in "+/" for ch in body)
    return has_digit_or_symbol and _entropy(body) >= 3.0


def _try_b64_decode(candidate: str) -> str | None:
    """Decode a base64 candidate to text, or None if it is not genuinely base64.

    Deliberately strict, because a bad decode presented as a finding is worse than no
    decode: the charset is guaranteed by the caller's regex, but this also requires a
    length that is a multiple of four and a decode that yields mostly-printable text.
    PowerShell `-Enc` is base64 of UTF-16LE; ordinary base64 is UTF-8; both are tried, and
    anything that decodes to bytes rather than text is rejected, not shown.
    """
    if len(candidate) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(candidate, validate=True)
    except ValueError:
        return None
    if not raw:
        return None
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if not text:
            continue
        # ASCII, not merely "printable": a command is ASCII, whereas random bytes read as
        # UTF-16LE decode to printable CJK and would sail past a printable-only test.
        ascii_ok = sum(32 <= ord(ch) <= 126 or ch in "\t\n\r" for ch in text)
        if ascii_ok / len(text) >= 0.9:
            return text.replace("\r", " ").replace("\n", " ").strip()
    return None


def decode(
    corpus: Corpus,
    pattern: str,
    *,
    file: str = "",
    field: str = "",
    extract: str = "",
    where: list[tuple[str, str, str]] | None = None,
) -> Aggregate:
    """Decode the base64 a pattern selects -- verified, never mangled.

    For each matching line's selected value (a `field=`, a capture group, or an
    `extract=` entity), the base64 runs inside it are found and the genuinely-base64 ones
    decoded into text; a run that does not validate is COUNTED, not decoded. This turns an
    encoded PowerShell command line into the command it actually runs, in one step and with
    a citable reference, instead of the commander decoding it in its head -- which is a
    guess, and a wrong guess about what a script does is the expensive kind.
    """
    rows, matched_lines, error = _selected_rows(
        corpus, pattern, file, field=field, extract=extract, where=where
    )
    if rows is None:
        return Aggregate(headline=f"failed: {error}", error=error)
    scope = file or f"{len(corpus.file_names)} file(s)"
    if not rows:
        return Aggregate(
            headline=f"0 matches in {scope} -- this pattern does not occur there"
        )
    decoded: list[tuple[Hit, str]] = []
    not_base64 = 0
    for value, hit in rows:
        got = False
        looked = False
        for match in _B64_RUN.finditer(value):
            run = match.group(0)
            text = _try_b64_decode(run)
            if text is not None:
                decoded.append((hit, text))
                got = True
            elif _looks_base64(run):
                # A run that has base64's shape (mixed classes, high entropy) but does not
                # decode is the real "looked base64 but did not validate" signal -- a
                # truncated or mis-copied payload worth flagging. A plain long token
                # (a task name, a path, a CamelCase field) is NOT that, and counting it
                # buried the signal under dozens of false hits in a graded run.
                looked = True
        if not got and looked:
            not_base64 += 1
    if not decoded:
        note = f" ({not_base64} looked base64 but did not validate)" if not_base64 else ""
        return Aggregate(
            headline=(
                f"0 valid base64 value(s) among {matched_lines} matching line(s) in "
                f"{scope}{note}"
            ),
            matched_lines=matched_lines,
        )
    shown = decoded[:DECODE_SHOWN]
    table = ["decoded base64 (verified; a run that did not validate is not shown):"]
    for hit, text in shown:
        table.append(f"  {_clip(text)}  <- {hit.ref}")
    tail = f"{len(decoded)} value(s) decoded"
    if len(decoded) > len(shown):
        tail += f", showing {len(shown)}"
    if not_base64:
        tail += (
            f"; {not_base64} matching value(s) looked base64 but did NOT validate and were "
            f"left encoded"
        )
    table.append(tail)
    return Aggregate(
        headline=f"decoded {len(shown)} of {len(decoded)} base64 value(s) in {scope}",
        matched_lines=matched_lines,
        table=tuple(table),
        hits=tuple(hit for hit, _ in shown),
    )
