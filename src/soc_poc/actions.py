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
import json
import shlex

from soc_poc import aggregation
from soc_poc.corpus import Corpus, SearchResult
from soc_poc.evidence import Step
from soc_poc.schemas.action import (
    SELECTOR_KINDS,
    ActionKind,
    InvestigativeAction,
    parse_predicate,
)

# The timestamp shapes profiling/aggregation recognise, as one grep -oE alternation, so
# a timeline's reproduce command extracts the same stamps the code did.
_TS_ANY = (
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"|[0-9]{10}\.[0-9]{3,6}"
    r"|[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}"
)


def _has_group(pattern: str) -> bool:
    try:
        return re.compile(pattern).groups > 0
    except re.error:
        return False


# The entity regexes `extract=` reproduces with, mirroring aggregation.ENTITY_PATTERNS.
_EXTRACT_GREP = {
    "ip": r"\b([0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "domain": r"\b([a-z0-9_-]+\.)+[a-z]{2,}\b",
    "hash": r"\b[a-z0-9]{16,}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
}


def _awk_var(regex: str) -> str:
    """A regex as an `awk -v` value, shell-quoted.

    awk applies escape processing to -v assignments, so `\\.` arrives as `.` and `\\?` as
    `?` (with a warning) and the pattern silently matches something else. Doubling the
    backslashes survives that pass intact. grep's `\\b` is a backspace to gawk's regex
    engine; its word boundary is `\\y`.
    """
    return shlex.quote(regex.replace("\\b", "\\y").replace("\\", "\\\\"))


def _jq_path(field: str) -> str:
    """A dotted key path as a jq path expression, each segment quoted so keys with odd
    characters (`id.orig_h` is a single Zeek key, not a path) still resolve when the
    caller means one level."""
    return "".join(f'."{part.strip()}"' for part in field.split("."))


def _is_json_target(action: InvestigativeAction, json_files: frozenset[str]) -> bool:
    return bool(action.field) and action.file in json_files


def _value_stream(
    action: InvestigativeAction, target: str, json_files: frozenset[str] = frozenset()
) -> str:
    """The pipeline that isolates the aggregated value, matching `_extract`'s three modes.

    * extract: grep the matching lines, then grep -o the entity shape out of them.
    * field:   grep the matching lines (dropping comments), then awk the column -- by
               1-based number directly, or by resolving a #fields name in the header; on
               a JSON-lines file, jq the key instead (`// empty` also drops false/null,
               a small divergence from the code, which counts them as words).
    * capture group / whole match: the original grep -o (+ sed for the group).
    """
    matching = f"grep -hE {shlex.quote(action.pattern)} {target}"
    if action.extract:
        entity = _EXTRACT_GREP.get(action.extract, r"\S+")
        return f"{matching} | grep -oE {shlex.quote(entity)}"
    if _is_json_target(action, json_files):
        return f"{matching} | jq -r {shlex.quote(_jq_path(action.field) + ' // empty')}"
    if action.field:
        body = f"{matching} | grep -v '^#'"
        if action.field.strip().isdigit():
            return f"{body} | awk -F'\\t' '{{print ${int(action.field)}}}'"
        # Resolve the column from the #fields header in one awk pass over the file. The
        # header's first token is '#fields', so a data column is one left of the name.
        prog = (
            f"/^#fields/{{for(i=2;i<=NF;i++)if($i==name)c=i-1}} "
            f"!/^#/&&$0~pat{{print $c}}"
        )
        return (
            f"awk -F'\\t' -v name={shlex.quote(action.field.strip())} "
            f"-v pat={_awk_var(action.pattern)} {shlex.quote(prog)} {target}"
        )
    stream = f"grep -hoiE {shlex.quote(action.pattern)} {target}"
    if _has_group(action.pattern):
        stream += f" | sed -E {shlex.quote(f's/{action.pattern}/\\1/I')}"
    return stream


# awk's numeric test for extremes. Stricter than /^[0-9.]+$/ on purpose so an IP like
# 1.2.3.4 ranks by length, as aggregation._NUMERIC does; the mode is decided at run time
# from the data, so the shell equivalent has to decide it per value.
_AWK_KEY = (
    'k=(v~/^-?[0-9]+(\\.[0-9]+)?$/)?v:(v~/^0[xX][0-9a-fA-F]+$/)?strtonum(v):length(v)'
)
_AWK_EMIT = 'print k, FILENAME":L"FNR, $0'

# The same three-way key in jq, for JSON-lines files: decimal, 0x-hex (folded by hand;
# jq has no hex parser), else the value's length. `$v` is the selected value as text.
_JQ_KEY = (
    '(if ($v|test("^-?[0-9]+(\\\\.[0-9]+)?$")) then ($v|tonumber) '
    'elif ($v|test("^0[xX][0-9a-fA-F]+$")) then '
    '($v|ascii_downcase|ltrimstr("0x")|explode'
    '|map(if . > 96 then .-87 else .-48 end)|reduce .[] as $d (0; .*16+$d)) '
    'else ($v|length) end)'
)


def _extremes_command(
    action: InvestigativeAction, target: str, json_files: frozenset[str] = frozenset()
) -> str:
    """The pipeline behind extremes: value, reference and line per match, largest first.

    Unlike `_value_stream`, this has to keep the LINE and its number, so every mode is one
    awk pass printing `key  file:Ln  line`, then `sort -rn | head`. Two known divergences
    from the Python, stated rather than hidden: awk's `$0 ~ pat` is case-sensitive where
    the code matches case-insensitively (pre-existing in the field-mode awk of
    `_value_stream`), and in extract mode this prints one row per value where the code
    keeps one row per line. On a JSON-lines file the pass is jq in raw mode (`-R`), which
    matches the raw line case-insensitively like the code and numbers lines from 1.
    """
    head = f"| sort -rn | head -{aggregation.EXTREMES_SHOWN}"
    if _is_json_target(action, json_files):
        prog = (
            'select(test($pat;"i")) | (fromjson? // empty) as $o | '
            f'($o | {_jq_path(action.field)} | tostring) as $v | {_JQ_KEY} as $k | '
            '"\\($k)\\t\\(input_filename):L\\(input_line_number)\\t\\(.)"'
        )
        return (
            f"jq -rR --arg pat {shlex.quote(action.pattern)} {shlex.quote(prog)} "
            f"{target} {head}"
        )
    pat = _awk_var(action.pattern)
    if action.field:
        if action.field.strip().isdigit():
            prog = f"!/^#/&&$0~pat{{v=${int(action.field)};{_AWK_KEY};{_AWK_EMIT}}}"
            return f"awk -F'\\t' -v pat={pat} {shlex.quote(prog)} {target} {head}"
        prog = (
            f"/^#fields/{{for(i=2;i<=NF;i++)if($i==name)c=i-1}} "
            f"!/^#/&&$0~pat{{v=$c;{_AWK_KEY};{_AWK_EMIT}}}"
        )
        return (
            f"awk -F'\\t' -v name={shlex.quote(action.field.strip())} -v pat={pat} "
            f"{shlex.quote(prog)} {target} {head}"
        )
    if action.extract:
        entity = _EXTRACT_GREP.get(action.extract, r"\S+")
        prog = (
            f"$0~pat{{s=$0;while(match(s,ent)){{v=substr(s,RSTART,RLENGTH);"
            f"{_AWK_KEY};{_AWK_EMIT};s=substr(s,RSTART+RLENGTH)}}}}"
        )
        return (
            f"awk -v pat={pat} -v ent={_awk_var(entity)} {shlex.quote(prog)} "
            f"{target} {head}"
        )
    if _has_group(action.pattern):
        # gawk's three-argument match() fills m[1] with the first capture group.
        prog = f"match($0,pat,m){{v=m[1];{_AWK_KEY};{_AWK_EMIT}}}"
    else:
        prog = f"match($0,pat){{v=substr($0,RSTART,RLENGTH);{_AWK_KEY};{_AWK_EMIT}}}"
    return f"awk -v pat={pat} {shlex.quote(prog)} {target} {head}"


def _filter_command(
    action: InvestigativeAction, target: str, json_files: frozenset[str], *, count: bool
) -> str:
    """The shell equivalent of a `where`-filtered search/count: an order-independent field
    match, jq on a JSON file and header-resolving awk on a TSV one, so the reproduce keeps
    the same property the verb has -- key order does not matter."""
    preds = [parse_predicate(e) for e in action.where]
    preds = [p for p in preds if not isinstance(p, str)]
    grep = f"grep -hE {shlex.quote(action.pattern)} {target} | "         if action.pattern else ""
    if action.file in json_files:
        # `g` looks a key up case-insensitively (jq's own `.key` is case-sensitive, and the
        # model may type a key in any case, as the Python filter tolerates); a dotted path
        # chains it. This keeps the printed command's result identical to the verb's.
        prelude = "def g(k): (to_entries[]|select((.key|ascii_downcase)==(k|ascii_downcase)).value);"
        clauses = []
        for field, op, value in preds:
            getter = "|".join(f"g({json.dumps(seg.strip())})" for seg in field.split("."))
            base = f"({getter})|tostring"
            if op == "=":
                clauses.append(f"({base}|ascii_downcase=={json.dumps(value.lower())})")
            elif op == "!=":
                clauses.append(f"({base}|ascii_downcase!={json.dumps(value.lower())})")
            elif op == "~":
                clauses.append(f'({base}|test({json.dumps(value)};"i"))')
            else:  # !~
                clauses.append(f'(({base}|test({json.dumps(value)};"i"))|not)')
        prog = f"{prelude} select({' and '.join(clauses)})"
        body = f"{grep}jq -c {shlex.quote(prog)}" if grep else f"jq -c {shlex.quote(prog)} {target}"
        return f"{body} | wc -l" if count else body
    # TSV: resolve each field to a column via the #fields header (case-insensitively, as the
    # code does), then compare.
    setup = " ".join(f"-v v{i}={shlex.quote(v)}" for i, (_f, _o, v) in enumerate(preds))
    resolve = "".join(
        f'for(i=2;i<=NF;i++)if(tolower($i)==tolower({json.dumps(f)}))c{i2}=i-1; '
        for i2, (f, _o, _v) in enumerate(preds)
    )
    _AWK_OP = {"=": "==", "!=": "!=", "~": "~", "!~": "!~"}
    tests = " && ".join(
        f"tolower($c{i}){_AWK_OP[o]}tolower(v{i})" for i, (_f, o, _v) in enumerate(preds)
    )
    pat = _awk_var(action.pattern) if action.pattern else None
    guard = "$0~pat&&" if pat else ""
    prog = f"/^#fields/{{{resolve}}} !/^#/&&{guard}({tests}){{print}}"
    patarg = f"-v pat={pat} " if pat else ""
    awk = f"awk -F'\t' {setup} {patarg}{shlex.quote(prog)} {target}"
    return f"{awk} | wc -l" if count else awk


def reproduce_command(
    action: InvestigativeAction,
    logs_dir: str = "logs",
    *,
    json_files: frozenset[str] = frozenset(),
) -> str:
    """The shell equivalent, so a reader can check the machine's work.

    Printed into the transcript for every step. An investigation whose evidence can be
    re-derived with grep is auditable in a way that "a language model read it and said so"
    is not, and that difference is the deliverable. `json_files` names the case's
    JSON-lines files, whose field= selectors reproduce with jq rather than awk.
    """
    target = f"{logs_dir}/{action.file}" if action.file else f"{logs_dir}/*"
    if action.where and action.action in (ActionKind.SEARCH, ActionKind.COUNT):
        return _filter_command(action, target, json_files, count=action.action is ActionKind.COUNT)
    if action.action is ActionKind.SEARCH:
        return f"grep -niE {shlex.quote(action.pattern)} {target}"
    if action.action is ActionKind.COUNT:
        return f"grep -ciE {shlex.quote(action.pattern)} {target}"
    if action.action is ActionKind.TALLY:
        return f"{_value_stream(action, target, json_files)} | sort | uniq -c | sort -rn"
    if action.action is ActionKind.STATS:
        return f"{_value_stream(action, target, json_files)} | sort -n | uniq -c"
    if action.action is ActionKind.EXTREMES:
        return _extremes_command(action, target, json_files)
    if action.action is ActionKind.TIMELINE:
        # Stamp frequencies at native granularity; the burst arithmetic is over these.
        return (
            f"grep -hiE {shlex.quote(action.pattern)} {target} "
            f"| grep -oE {shlex.quote(_TS_ANY)} | sort | uniq -c"
        )
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


def _literal_runs(pattern: str) -> list[str]:
    """Every maximal run of characters the data must contain verbatim, in pattern order.

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
    return [run for run in runs if run]


def longest_literal(pattern: str) -> str:
    """The longest literal run, if it is long enough to mean anything."""
    runs = _literal_runs(pattern)
    best = max(runs, key=len) if runs else ""
    return best if len(best) >= _MIN_LITERAL else ""


# An anchor this short ("0", "F") is structure, not evidence; three characters ("TXT",
# "udp", "ACK") is where a run starts identifying a field.
_MIN_ANCHOR = 3


def _co_occurrence(anchors: list[str], file: str, corpus: Corpus) -> tuple[int, int]:
    """(lines containing every anchor, lines containing them in pattern order).

    Substring containment, case-insensitive -- deliberately looser than the regex whose
    zero we are diagnosing, because the question is "is the data there at all, and in
    what order", not "does the pattern match".
    """
    lows = [anchor.lower() for anchor in anchors]
    together = ordered = 0
    for name in [file] if file else corpus.file_names:
        for text in corpus.file_lines(name):
            low = text.lower()
            if not all(anchor in low for anchor in lows):
                continue
            together += 1
            position = -1
            for anchor in lows:
                position = low.find(anchor, position + 1)
                if position < 0:
                    break
            else:
                ordered += 1
    return together, ordered


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
    # With two or more anchors the diagnosis can be exact instead of general. A graded
    # run burned 8 of 24 steps writing `TXT`-then-domain counts against a format that
    # puts the query before the qtype -- reading real lines between attempts and
    # re-emitting the wrong order anyway. "Check field order" was demonstrably not
    # enough; "your anchors occur in the OPPOSITE order on 649 lines" is checkable
    # arithmetic and names the one edit that fixes the pattern.
    #
    # This runs before the single-literal probe and without its 8-character floor: two
    # anchors that must BOTH sit on one line are already specific ("TXT" alone is noise;
    # "TXT" and "NOERROR" together on 649 lines is a finding), and any absent anchor
    # zeroes `together`, which keeps a genuine absence silent.
    anchors = [run for run in dict.fromkeys(_literal_runs(pattern)) if len(run) >= _MIN_ANCHOR]
    if len(anchors) >= 2:
        together, ordered = _co_occurrence(anchors, file, corpus)
        named = " and ".join(repr(anchor) for anchor in anchors[:3])
        if together and ordered * 4 < together:
            return (
                f" NOTE: this zero is about your PATTERN, not about the data: {named} "
                f"all occur together on {together} line(s) here, but mostly NOT in the "
                f"order your pattern requires -- the field order is different. Swap the "
                f"anchors."
            )
        if together:
            return (
                f" NOTE: this zero is about your PATTERN, not about the data: {named} "
                f"occur in this order on {ordered} line(s) here, so the mismatch is the "
                f"text BETWEEN them. Join the anchors with .* and only tighten once it "
                f"matches."
            )
    literal = longest_literal(pattern)
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


# The marker orchestrator.py greps a summary for to know the partial-coverage hint
# fired. A shared constant, so the producer and the consumer cannot drift apart.
OVER_ANCHORED_MARKER = "the pattern is over-anchored"


def coverage_hint(pattern: str, file: str, corpus: Corpus, matched_lines: int) -> str:
    """The aggregate-verb generalisation of zero_result_hint: partial coverage is a
    result that must carry its own refutation.

    This exists because of a graded run. A tally meant to answer "which hosts query this
    domain" was over-anchored by one separator, matched exactly 1 of the 788 lines
    containing the domain, and answered "1x 10.12.34.56" -- not zero, so the zero hint
    stayed silent, and the ledger then held 788-vs-1 for the same question. The
    commander spent six more steps re-asking it. A zero was protected; a wrong small
    number was not.

    Fires only when the pattern reaches under a quarter of the lines its own anchor
    literal appears on. Moderate deliberate narrowing (649 TXT among 788 domain lines)
    stays silent, because a warning printed on every narrowing is a warning nobody reads.
    """
    if matched_lines == 0:
        return zero_result_hint(pattern, file, corpus)
    literal = longest_literal(pattern)
    if not literal:
        return ""
    probe = corpus.count(re.escape(literal), file=file)
    if matched_lines * 4 >= probe.total_matches:
        return ""
    return (
        f" NOTE: your pattern matched {matched_lines} of the {probe.total_matches} "
        f"line(s) containing {literal!r}. If you meant all of them, "
        f"{OVER_ANCHORED_MARKER} -- check the separators around the literal. If the "
        f"narrowing is deliberate, ignore this."
    )


def _summarise(result: SearchResult, kind: ActionKind) -> str:
    if result.error:
        return f"failed: {result.error}"
    scope = result.file or f"{len(result.files_searched)} file(s)"
    if kind is ActionKind.COUNT:
        base = f"{result.total_matches} match(es) in {scope}"
        if 1 <= result.total_matches <= 3:
            # A count this small is usually a rare, decisive line -- and a count cannot
            # be cited, because nothing was shown. A graded run counted the attacker
            # nameserver (1 match, twice) and never fetched it; the brief then could not
            # cite the strongest evidence in the case.
            base += (
                " -- few enough to read: re-run this pattern as a search to see the "
                "line(s); only lines you have been shown can be cited in the brief"
            )
        return base
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


# The aggregation skills, dispatched by verb. All deterministic, all reproducible; see
# aggregation.py for why their product is a table rather than lines.
_AGGREGATES = {
    ActionKind.TALLY: aggregation.tally,
    ActionKind.TIMELINE: aggregation.timeline,
    ActionKind.STATS: aggregation.stats,
    ActionKind.EXTREMES: aggregation.extremes,
}


def execute_readonly(
    action: InvestigativeAction, corpus: Corpus, *, index: int, logs_dir: str = "logs"
) -> Step:
    """Run one deterministic action. Never raises: a bad request becomes a Step with an error."""
    kind = action.action
    if kind in _AGGREGATES:
        # timeline works off timestamps, so it takes no value selector; the others do.
        # validate_action has already rejected field/extract on anything else.
        selectors = (
            {"field": action.field, "extract": action.extract}
            if kind in SELECTOR_KINDS
            else {}
        )
        outcome = _AGGREGATES[kind](corpus, action.pattern, file=action.file, **selectors)
        summary = outcome.headline
        if not outcome.error:
            summary += coverage_hint(
                action.pattern, action.file, corpus, outcome.matched_lines
            )
        return Step(
            index=index,
            action=action,
            summary=summary,
            # tally/timeline/stats carry no lines on purpose: they produce numbers, and a
            # number is not a citation, so nothing of theirs enters shown_refs(). extremes
            # is the exception by design -- its product IS the lines behind a number, and
            # `hits` are real references the brief may cite. `truncated` is the honest gap
            # between what matched and what was shown, so the ledger never says "the
            # count above is exact" over a top-10 of 649.
            lines=tuple(outcome.hits),
            truncated=(
                max(0, outcome.matched_lines - len(outcome.hits)) if outcome.hits else 0
            ),
            table="\n".join(outcome.table),
            total_matches=outcome.matched_lines,
            error=outcome.error,
            reproduce=reproduce_command(action, logs_dir, json_files=corpus.json_files),
        )
    where = None
    if action.where:
        parsed = [parse_predicate(entry) for entry in action.where]
        errors = [p for p in parsed if isinstance(p, str)]
        if errors:
            return Step(
                index=index,
                action=action,
                summary=f"failed: {errors[0]}",
                error=errors[0],
                reproduce=reproduce_command(action, logs_dir, json_files=corpus.json_files),
            )
        where = [p for p in parsed if not isinstance(p, str)]

    if kind is ActionKind.SEARCH:
        result = corpus.search(action.pattern, file=action.file, where=where)
    elif kind is ActionKind.COUNT:
        result = corpus.count(action.pattern, file=action.file, where=where)
    elif kind is ActionKind.CONTEXT:
        result = corpus.context(action.ref, where=where)
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
        reproduce=reproduce_command(action, logs_dir, json_files=corpus.json_files),
    )
