"""The case's log files, searchable by line, with every result carrying its reference.

This replaces the sweep. For six runs an 83-call, 4,300-GPU-second pass over every slice
produced descriptions that mostly restated the directive back, missed the NS delegation
entirely, and reported "10.12.34.56 not found" for an eight-line DHCP file with the lease
on lines 4 and 8. The same questions answered here are exact, instant, and reproducible.

The coverage argument changed shape rather than weakening. The sweep's claim was "every
line was read by a model, so a negative means something" -- but reading is not noticing,
and the DHCP case is proof it was never true. A `count` over this corpus is a negative
that is deterministically correct and that anyone can re-run.

Every returned line carries its `<file>:L<n>` reference, so validation/citations.py works
unchanged: the commander now cites lines it has actually been shown.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


# -- field value extraction (shared by aggregation's selectors and the profile's scope) --
#
# These live here, not in aggregation, because profiling.py needs them too and importing
# aggregation from profiling would be a cycle (aggregation imports profiling).


def _resolve_field(selector: str, field_map: dict[str, int]) -> int | None:
    """A field selector -> 0-based column index, or None if it cannot be resolved.

    A selector is a `#fields` name (resolved through the map) or a 1-based column number
    (for a delimited file with no header). Everything else is unresolvable, and the caller
    turns that into an error that lists the available names.
    """
    name = selector.strip().lower()
    if name in field_map:
        return field_map[name]
    if name.isdigit() and int(name) >= 1:
        return int(name) - 1
    return None


def _json_value(obj: dict, path: str) -> str | None:
    """The value at a dotted key path in a JSON object, as the string the selectors
    aggregate, or None when the path is absent.

    Keys match case-insensitively at each level (`field="ipaddress"` finds `IpAddress`,
    the way #fields names are lowercased). Numbers keep their JSON spelling so a numeric
    selector still sees them; booleans and null become their JSON words; nested containers
    are re-serialised compactly so a tally over them still counts shapes.
    """
    current: object = obj
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        lowered = {k.lower(): k for k in current}
        key = lowered.get(part.strip().lower())
        if key is None:
            return None
        current = current[key]
    if current is None:
        return "null"
    if isinstance(current, bool):
        return "true" if current else "false"
    if isinstance(current, (int, float)):
        return str(current)
    if isinstance(current, str):
        return current
    return json.dumps(current, separators=(",", ":"))


# -- record-type scope: which low-cardinality fields partition a file into record kinds ---
#
# A host log's event_id, a DNS log's qtype_name, an HTTP log's method are the axes an
# analyst reads first: they say what KINDS of record the file holds and how many of each.
# The profile precomputes these so the commander is handed the map instead of having to
# think to tally for it. Detection is by shape, not by name, so it serves any log format;
# a name match only breaks ties.
CATEGORICAL_MIN_DISTINCT = 2       # one value is not an axis (drops channel/provider)
CATEGORICAL_MAX_DISTINCT = 24      # above this it is an identifier space, not a record kind
CATEGORICAL_CONSTANT_FRAC = 0.98   # top value >= 98% of a field's occurrences: effectively constant
CATEGORICAL_MAX_UNIQUE_RATIO = 0.5 # distinct/occurrences: rejects uid, GUIDs, bare timestamps
CATEGORICAL_MAX_MEAN_LEN = 48      # mean value length: rejects CommandLine, CallTrace, answers
CATEGORICAL_MIN_COVERAGE = 0.02    # a field must appear on >= 2% of event lines
CATEGORICAL_MAX_FIELDS = 4         # axes surfaced per file
CATEGORICAL_TOP_VALUES = 12        # values shown per field before a "+N more" tail
_CAT_TS = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\d{10}\.\d|[A-Z][a-z]{2}\s+\d{1,2}\s)"
)
# A mild first-tiebreak: when several fields qualify, lead with the one an analyst names.
CATEGORICAL_PREFERRED_NAMES = frozenset({
    "event_id", "eventid", "type", "logontype", "grantedaccess", "status", "status_code",
    "action", "method", "qtype", "qtype_name", "rcode", "rcode_name", "proto", "service",
    "conn_state",
})


def _categorical_rank(
    field: str, values: list[str], total: int, max_distinct: int, min_coverage: float
) -> tuple | None:
    """A sort key if `field` is a record-type axis over `values`, else None (rejected).

    total is the file's event-line count; coverage is how many of those carry the field.
    The gates, in order: enough coverage, a small-but-plural distinct count, not
    effectively constant, not near-unique (ids/timestamps), not timestamp-shaped, not
    freetext by mean length.
    """
    occ = len(values)
    if occ == 0 or occ / total < min_coverage:
        return None
    counts = Counter(values)
    distinct = len(counts)
    if not (CATEGORICAL_MIN_DISTINCT <= distinct <= max_distinct):
        return None
    top_value, top_count = counts.most_common(1)[0]
    if top_count / occ >= CATEGORICAL_CONSTANT_FRAC:
        return None
    if distinct / occ >= CATEGORICAL_MAX_UNIQUE_RATIO:
        return None
    if _CAT_TS.match(top_value):
        return None
    if sum(len(v) for v in values) / occ > CATEGORICAL_MAX_MEAN_LEN:
        return None
    preferred = 0 if field.lower() in CATEGORICAL_PREFERRED_NAMES else 1
    coverage_bucket = -round(occ / total, 1)  # descending: full-coverage master axis first
    return (preferred, coverage_bucket, distinct, -occ)


# Bounds. A search that returns everything is a search that overflows the context, and the
# commander cannot reason about 800 lines any better than it could about 83 reports.
MAX_RESULTS = 40
MAX_CONTEXT_SPAN = 60


@dataclass(frozen=True)
class Hit:
    ref: str
    text: str


@dataclass(frozen=True)
class SearchResult:
    """What a query found, and honestly how much of it was withheld."""

    pattern: str
    file: str
    total_matches: int
    returned: list[Hit]
    files_searched: list[str]
    error: str = ""

    @property
    def truncated(self) -> int:
        return max(0, self.total_matches - len(self.returned))


class Corpus:
    """Every line of every log file in a case, addressable by reference."""

    def __init__(self, files: dict[str, list[str]]) -> None:
        self._files = files
        self._by_ref = {
            f"{name}:L{n}": text
            for name, lines in files.items()
            for n, text in enumerate(lines, start=1)
        }
        # JSON-lines files, parsed once on first use: None marks "not JSON". Every
        # tally/stats/extremes in a run shares this, so a 5,000-line file is decoded once.
        self._json_cache: dict[str, list[dict | None] | None] = {}

    @classmethod
    def from_dir(cls, logs_dir: Path) -> Corpus:
        files = {
            path.name: path.read_text(encoding="utf-8", errors="replace").splitlines()
            for path in sorted(logs_dir.iterdir())
            if path.is_file() and not path.name.startswith(".")
        }
        if not files:
            raise FileNotFoundError(f"no log files found in {logs_dir}")
        return cls(files)

    @property
    def file_names(self) -> list[str]:
        return list(self._files)

    def line_counts(self) -> dict[str, int]:
        """Lines per file. What the commander uses to pick a legal line range."""
        return {name: len(lines) for name, lines in self._files.items()}

    def file_lines(self, name: str) -> list[str]:
        """One file's lines, for code that aggregates over them (aggregation.py)."""
        return self._files.get(name, [])

    def line(self, ref: str) -> str | None:
        return self._by_ref.get(ref)

    def refs(self) -> set[str]:
        return set(self._by_ref)

    def _targets(self, file: str) -> list[str]:
        if not file:
            return list(self._files)
        return [name for name in self._files if name == file]

    def search(
        self,
        pattern: str,
        *,
        file: str = "",
        max_results: int = MAX_RESULTS,
        where: list[tuple[str, str, str]] | None = None,
    ) -> SearchResult:
        """Regex search, optionally narrowed by ANDed field predicates.

        `pattern` is the whole-line regex (empty matches every line, so a `where`-only
        search filters purely on fields). `where` is a list of (field, op, value) tuples
        resolved against each line's PARSED fields -- JSON key or #fields column -- so the
        order of keys in a record is irrelevant, unlike a regex that lists them in sequence.
        """
        targets = self._targets(file)
        if file and not targets:
            return SearchResult(
                pattern, file, 0, [], [],
                error=f"no such file {file!r}; this case has {', '.join(self._files)}",
            )
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return SearchResult(pattern, file, 0, [], targets, error=f"bad regex: {exc}")

        hits: list[Hit] = []
        total = 0
        cap = min(max_results, MAX_RESULTS)
        for name in targets:
            # Resolve the file's parse mode once, not per line.
            objects = self.json_objects(name) if where else None
            fmap = self.field_map(name) if (where and objects is None) else {}
            sep = self.separator(name) if (where and objects is None) else "\t"
            for number, text in enumerate(self._files[name], start=1):
                if not regex.search(text):
                    continue
                if where and not self._line_matches(
                    number, text, where, fmap=fmap, sep=sep, objects=objects
                ):
                    continue
                total += 1
                if len(hits) < cap:
                    hits.append(Hit(f"{name}:L{number}", text))
        return SearchResult(pattern, file, total, hits, targets)

    def _line_matches(
        self,
        number: int,
        text: str,
        preds: list[tuple[str, str, str]],
        *,
        fmap: dict[str, int],
        sep: str,
        objects: list[dict | None] | None,
    ) -> bool:
        """Does one line satisfy every (field, op, value) predicate? Order-independent.

        JSON: the field is a key resolved through `_json_value` on the line's parsed
        object. TSV: the field is a #fields column resolved through `field_map`. A field
        absent from the line fails the predicate; `=` is case-insensitive equality, `~` is
        a case-insensitive regex over the field's value.
        """
        obj = objects[number - 1] if objects is not None else None
        for field, op, value in preds:
            if objects is not None:
                got = _json_value(obj, field) if obj is not None else None
            else:
                index = _resolve_field(field, fmap)
                columns = text.split(sep)
                got = columns[index] if (index is not None and 0 <= index < len(columns)) else None
            if got is None:
                return False
            negate = op.startswith("!")
            if op in ("=", "!="):
                if (got.lower() == value.lower()) == negate:
                    return False
            elif op in ("~", "!~"):
                if bool(re.search(value, got, re.IGNORECASE)) == negate:
                    return False
        return True

    def count(
        self, pattern: str, *, file: str = "", where: list[tuple[str, str, str]] | None = None
    ) -> SearchResult:
        """Match count with no lines returned -- the cheap way to test a hypothesis.

        This is the deterministic negative the sweep only pretended to give: zero here
        means the pattern does not occur, not that nobody noticed it.
        """
        return self.search(pattern, file=file, max_results=0, where=where)

    def context(
        self, ref: str, *, before: int = 5, after: int = 5,
        where: list[tuple[str, str, str]] | None = None,
    ) -> SearchResult:
        """The lines around a reference -- for reading what surrounds a hit.

        A `where` filter keeps only the neighbours that satisfy the predicates, which is
        how the commander reads "the events in this window that are event_id 10".
        """
        if ref not in self._by_ref:
            return SearchResult("", "", 0, [], [], error=f"no such line {ref!r}")
        name, _, number = ref.partition(":L")
        centre = int(number)
        lines = self._files[name]
        span = min(before + after + 1, MAX_CONTEXT_SPAN)
        start = max(1, centre - before)
        end = min(len(lines), start + span - 1)
        hits = [Hit(f"{name}:L{n}", lines[n - 1]) for n in range(start, end + 1)]
        if where:
            objects = self.json_objects(name)
            fmap = self.field_map(name) if objects is None else {}
            sep = self.separator(name) if objects is None else "\t"
            hits = [
                h for h in hits
                if self._line_matches(
                    int(h.ref.rpartition("L")[2]), h.text, where, fmap=fmap, sep=sep, objects=objects
                )
            ]
        return SearchResult(f"context around {ref}", name, len(hits), hits, [name])

    def format_header(self, file: str, max_lines: int = 12) -> list[str]:
        """The contiguous run of leading comment lines, if any.

        Zeek's dns.log opens with #separator/#fields/#types; syslog and JSONL have none.
        Only `#`-prefixed lines are taken, which is conservative: a format whose header is
        a bare first row is left alone rather than guessed at.

        This rides along on a close_read. A worker handed lines 4000-4060 with no #fields
        row is reading anonymous tab-separated columns, and that produced a brief claiming
        the logs held no DNS answers while column 22 was full of them.
        """
        header: list[str] = []
        for line in self._files.get(file, [])[:max_lines]:
            if not line.startswith("#"):
                break
            header.append(line)
        return header

    def separator(self, file: str) -> str:
        r"""The field separator a delimited file declares, defaulting to a tab.

        Zeek writes `#separator \x09` (a space-separated header line whose value is the
        literal escape). Anything without the declaration is treated as tab-delimited,
        which is what every log format the field selector is useful on actually is.
        """
        for line in self.format_header(file):
            if line.startswith("#separator"):
                parts = line.split(None, 1)
                token = parts[1].strip() if len(parts) > 1 else ""
                return token.replace("\\x09", "\t").replace("\\x20", " ") or "\t"
        return "\t"

    def field_map(self, file: str) -> dict[str, int]:
        """Column name -> 0-based index, from a `#fields` header line, or empty.

        The header's first token is the literal `#fields`, so a data column sits one to
        the left of its name's position in that line; the map already accounts for it.
        Names are lowercased so `field="qtype_name"` matches regardless of case.
        """
        sep = self.separator(file)
        for line in self.format_header(file):
            if line.startswith("#fields"):
                names = line.split(sep)[1:]  # drop the "#fields" label
                return {name.strip().lower(): index for index, name in enumerate(names)}
        return {}

    # -- JSON lines ---------------------------------------------------------------------
    #
    # A `.jsonl` file has no #fields header; its columns are its keys. These give the
    # field= selector, the `keys:` line the commander is shown, and the jq reproduce
    # commands one shared view of the file, without touching the TSV path above.

    def json_objects(self, file: str) -> list[dict | None] | None:
        """Every line parsed as JSON, or None if the file is not JSON lines.

        Index i is line i+1, so a value found here cites `file:L{i+1}` exactly like a
        search hit does. Blank, unparseable and non-object lines are None: they carry no
        value but still count as matches for the line filter, the way a short TSV row does.
        A file is JSON lines when its first non-blank line is a JSON object.
        """
        if file in self._json_cache:
            return self._json_cache[file]
        lines = self._files.get(file, [])
        first = next((line for line in lines if line.strip()), "")
        parsed: list[dict | None] | None = None
        if first.lstrip().startswith("{"):
            try:
                probe = json.loads(first)
            except ValueError:
                probe = None
            if isinstance(probe, dict):
                parsed = []
                for line in lines:
                    try:
                        obj = json.loads(line) if line.strip() else None
                    except ValueError:
                        obj = None
                    parsed.append(obj if isinstance(obj, dict) else None)
        self._json_cache[file] = parsed
        return parsed

    def is_json(self, file: str) -> bool:
        return self.json_objects(file) is not None

    @property
    def json_files(self) -> frozenset[str]:
        return frozenset(name for name in self.file_names if self.is_json(name))

    def json_keys(self, file: str) -> list[tuple[str, int]]:
        """Top-level keys of a JSON-lines file with how many lines carry each, most
        common first (ties keep first-seen order). Empty for a non-JSON file."""
        objects = self.json_objects(file)
        if not objects:
            return []
        counts: dict[str, int] = {}
        for obj in objects:
            if obj:
                for key in obj:
                    counts[key] = counts.get(key, 0) + 1
        return sorted(counts.items(), key=lambda kv: -kv[1])

    def column_values(self, file: str, field: str) -> list[str]:
        """Every present value of one field, in line order, as the string a tally counts.

        JSON: a key (dotted) via json_objects + _json_value. TSV: a `#fields` name or a
        1-based column via separator + field_map. Absent keys, short rows, unparsable
        lines and `#` header lines contribute nothing -- exactly what `_selected_rows`
        does, factored out so the profile can reuse it without importing aggregation.
        """
        objects = self.json_objects(file)
        if objects is not None:
            out: list[str] = []
            for obj in objects:
                if obj is not None:
                    value = _json_value(obj, field)
                    if value is not None:
                        out.append(value)
            return out
        index = _resolve_field(field, self.field_map(file))
        if index is None:
            return []
        separator = self.separator(file)
        out = []
        for text in self._files.get(file, []):
            if text.startswith("#") or not text.strip():
                continue
            columns = text.split(separator)
            if 0 <= index < len(columns):
                out.append(columns[index])
        return out

    def categorical_fields(
        self,
        file: str,
        *,
        max_distinct: int = CATEGORICAL_MAX_DISTINCT,
        min_coverage: float = CATEGORICAL_MIN_COVERAGE,
    ) -> list[tuple[str, list[tuple[str, int]]]]:
        """The file's record-type axes -- its low-cardinality fields -- best first, each
        with its (value, count) distribution most-common-first.

        Candidate fields are the JSON keys (for a .jsonl file) or the `#fields` names (for
        a delimited one); `_categorical_rank` decides which qualify and in what order. The
        result is what the profile shows as "record-type scope" and what the commander
        would otherwise have to think to `tally field=` for.
        """
        objects = self.json_objects(file)
        if objects is not None:
            candidates = [key for key, _ in self.json_keys(file)]
            total = sum(1 for obj in objects if obj is not None)
        else:
            field_map = self.field_map(file)
            candidates = sorted(field_map, key=lambda k: field_map[k])
            total = sum(1 for text in self._files.get(file, [])
                        if text.strip() and not text.startswith("#"))
        if total == 0:
            return []
        scored: list[tuple[tuple, str, list[tuple[str, int]]]] = []
        for field in candidates:
            values = self.column_values(file, field)
            rank = _categorical_rank(field, values, total, max_distinct, min_coverage)
            if rank is not None:
                scored.append((rank, field, Counter(values).most_common()))
        scored.sort(key=lambda item: item[0])
        return [(field, distribution) for _, field, distribution in scored[:CATEGORICAL_MAX_FIELDS]]

    def slice_lines(self, file: str, start: int, end: int) -> list[Hit]:
        """A contiguous range, for handing to a worker for a close read."""
        lines = self._files.get(file, [])
        start = max(1, start)
        end = min(len(lines), end)
        return [Hit(f"{file}:L{n}", lines[n - 1]) for n in range(start, end + 1)]
