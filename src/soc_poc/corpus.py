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
from dataclasses import dataclass
from pathlib import Path

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
        self, pattern: str, *, file: str = "", max_results: int = MAX_RESULTS
    ) -> SearchResult:
        """Regex search. Case-insensitive, because log data is not consistent about it."""
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
            for number, text in enumerate(self._files[name], start=1):
                if regex.search(text):
                    total += 1
                    if len(hits) < cap:
                        hits.append(Hit(f"{name}:L{number}", text))
        return SearchResult(pattern, file, total, hits, targets)

    def count(self, pattern: str, *, file: str = "") -> SearchResult:
        """Match count with no lines returned -- the cheap way to test a hypothesis.

        This is the deterministic negative the sweep only pretended to give: zero here
        means the pattern does not occur, not that nobody noticed it.
        """
        result = self.search(pattern, file=file, max_results=0)
        return result

    def context(self, ref: str, *, before: int = 5, after: int = 5) -> SearchResult:
        """The lines around a reference -- for reading what surrounds a hit."""
        if ref not in self._by_ref:
            return SearchResult("", "", 0, [], [], error=f"no such line {ref!r}")
        name, _, number = ref.partition(":L")
        centre = int(number)
        lines = self._files[name]
        span = min(before + after + 1, MAX_CONTEXT_SPAN)
        start = max(1, centre - before)
        end = min(len(lines), start + span - 1)
        hits = [Hit(f"{name}:L{n}", lines[n - 1]) for n in range(start, end + 1)]
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

    def slice_lines(self, file: str, start: int, end: int) -> list[Hit]:
        """A contiguous range, for handing to a worker for a close read."""
        lines = self._files.get(file, [])
        start = max(1, start)
        end = min(len(lines), end)
        return [Hit(f"{file}:L{n}", lines[n - 1]) for n in range(start, end + 1)]
