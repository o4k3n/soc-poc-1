"""Mechanical chunking: every log line lands in exactly one slice.

This replaces the old pattern-summary path. There is no selection here and no analysis
-- the commander does not choose what gets read, because a "not found" is only worth
something if everything was looked at. Coverage is total by construction; the slice count
is whatever the data says it is.

The one number that matters is **window size**, and it is derived from the grunt's
context window rather than from a target slice count:

    lines_per_slice = slice_token_budget / (tokens_per_line + ref_overhead)

Getting this wrong is not a tuning issue, it is a total failure: a slice that exceeds the
model's context is rejected by the server, so every grunt in the sweep fails with a
transport error and the run produces nothing. The previous implementation sized windows
to keep the slice count under 24 with no notion of context at all, which worked only
because the fixtures were small.

Token estimation is deliberately pessimistic. Measured against the actual Qwen3 tokenizer
via vLLM's /tokenize endpoint:

    Zeek TSV with a high-entropy DNS label   182 bytes -> 131 tokens   1.39 chars/token
    Suricata EVE JSON, tunnel label          343 bytes -> 178 tokens   1.93
    Suricata EVE JSON, benign                302 bytes -> 151 tokens   2.00

Random-looking labels -- exactly what tunnelling and beaconing data is full of -- tokenize
close to 1.4 chars/token, so that is the default. Ordinary prose-ish logs come in cheaper
and simply get smaller slices than they strictly need, which costs a few extra grunt calls
and nothing else. Erring the other way costs the whole run.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from soc_poc.schemas.slice import LogLine, LogSlice

# Worst-case chars per token for high-entropy log content. See module docstring.
DEFAULT_CHARS_PER_TOKEN = 1.4
# 16384 context, minus system+task prompt scaffolding (~900), minus room for the report
# the grunt has to write (~2500), minus margin. Configurable in config.toml.
DEFAULT_SLICE_TOKEN_BUDGET = 10_000
# Each rendered line is prefixed with "<file>:L<n>\t", which is not free.
REF_OVERHEAD_TOKENS = 12
# Below this, slices get so small that prompt scaffolding dominates the call.
MIN_LINES_PER_SLICE = 10

_ISO_TS = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
_SYSLOG_TS = re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")
_EPOCH_TS = re.compile(r"^\d{10}\.\d{3,6}\b")


class FileInventory(BaseModel):
    """What the commander is told exists -- names and sizes, never content.

    This is the only thing derived from the log files that reaches the commander, and it
    is deliberately non-analytical: it says a `dhcp.log` exists with 40 lines covering a
    time range, so the sweep directive can mention host attribution. It does not say what
    is in it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    file: str
    line_count: int
    time_range: str
    slice_count: int


def _time_range(lines: list[str]) -> str:
    stamps: list[str] = []
    for line in lines:
        match = _ISO_TS.search(line) or _SYSLOG_TS.search(line) or _EPOCH_TS.search(line)
        if match:
            stamps.append(match.group(0))
    if not stamps:
        return "unknown (no timestamps recognised)"
    return f"{min(stamps)}/{max(stamps)}"


def estimate_tokens_per_line(lines: list[str], chars_per_token: float) -> float:
    """Mean tokens per line, estimated from character count.

    Sampling the whole file rather than a head slice: log files are frequently
    front-loaded with a quiet period, and sizing every window off the calm opening is how
    you get an overflow two thirds of the way through a sweep.
    """
    if not lines:
        return 1.0
    mean_chars = sum(len(line) for line in lines) / len(lines)
    return max(1.0, mean_chars / chars_per_token)


def lines_per_slice(
    tokens_per_line: float,
    *,
    slice_token_budget: int = DEFAULT_SLICE_TOKEN_BUDGET,
) -> int:
    per_line = tokens_per_line + REF_OVERHEAD_TOKENS
    return max(MIN_LINES_PER_SLICE, int(slice_token_budget // per_line))


def _pack(lines: list[str], budget: int, chars_per_token: float) -> list[tuple[int, int]]:
    """Greedily pack lines into windows that fit the budget. Returns 1-based (start, end).

    Fixed-width windows sized off the *mean* line are not safe: log files mix short
    routine lines with long ones, and a window that happens to land on a dense run of the
    long kind blows the budget even though the file's average is comfortable. Measured on
    the DNS-tunnel case, mean-based sizing produced a 13.4k-token slice against a 10k
    budget -- every grunt reading it would have failed.

    So windows are variable-length: accumulate until the next line would not fit, then
    cut. Coverage is still total and slice order is still the file's order; only the
    window size varies, and it varies exactly with the density of what is in it.
    """
    windows: list[tuple[int, int]] = []
    start = 1
    running = 0.0
    for number, line in enumerate(lines, start=1):
        cost = len(line) / chars_per_token + REF_OVERHEAD_TOKENS
        # A single line bigger than the whole budget cannot be split -- line integrity is
        # what makes a citation resolvable -- so it gets a slice to itself and overflows.
        if running and running + cost > budget:
            windows.append((start, number - 1))
            start, running = number, 0.0
        running += cost
    if lines:
        windows.append((start, len(lines)))
    return windows or [(1, 0)]


def chunk_file(
    path: Path,
    *,
    slice_token_budget: int = DEFAULT_SLICE_TOKEN_BUDGET,
    chars_per_token: float = DEFAULT_CHARS_PER_TOKEN,
) -> tuple[list[LogSlice], FileInventory]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    windows = _pack(lines, slice_token_budget, chars_per_token)
    time_range = _time_range(lines)
    total = len(lines)

    slices = [
        LogSlice(
            slice_id=f"{path.stem}-{index:04d}",
            file=path.name,
            source=path.stem,
            host="",  # unknown by construction; attribution is the investigation's job
            time_range=time_range,
            reason=(
                f"systematic sweep, window {index} of {len(windows)}: lines "
                f"{first}-{last} of {total} in {path.name}"
            ),
            start_line=first,
            end_line=last,
            lines=[LogLine(ref=f"{path.name}:L{n}", text=lines[n - 1])
                   for n in range(first, last + 1)],
        )
        for index, (first, last) in enumerate(windows, start=1)
    ]
    return slices, FileInventory(
        file=path.name, line_count=total, time_range=time_range, slice_count=len(slices)
    )


def chunk_logs(
    logs_dir: Path,
    *,
    slice_token_budget: int = DEFAULT_SLICE_TOKEN_BUDGET,
    chars_per_token: float = DEFAULT_CHARS_PER_TOKEN,
) -> tuple[dict[str, LogSlice], list[FileInventory]]:
    """Chunk every log file in the directory. Returns (catalog, inventory)."""
    paths = sorted(p for p in logs_dir.iterdir() if p.is_file() and not p.name.startswith("."))
    if not paths:
        raise FileNotFoundError(f"no log files found in {logs_dir}")

    catalog: dict[str, LogSlice] = {}
    inventory: list[FileInventory] = []
    for path in paths:
        slices, file_inventory = chunk_file(
            path, slice_token_budget=slice_token_budget, chars_per_token=chars_per_token
        )
        for log_slice in slices:
            catalog[log_slice.slice_id] = log_slice
        inventory.append(file_inventory)
    return catalog, inventory
