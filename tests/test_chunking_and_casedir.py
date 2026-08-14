"""Chunking guarantees and case-folder discovery.

The two chunking properties everything else rests on: no slice exceeds the grunt's
context, and every line lands in exactly one slice. Break the first and the whole sweep
fails with transport errors; break the second and "we read everything" is a lie.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_poc.casedir import ALERT_TEMPLATE, CaseLoadError, discover_case, scaffold_case
from soc_poc.chunking import (
    DEFAULT_CHARS_PER_TOKEN,
    MIN_LINES_PER_SLICE,
    REF_OVERHEAD_TOKENS,
    chunk_logs,
    estimate_tokens_per_line,
    lines_per_slice,
)

ROOT = Path(__file__).resolve().parent.parent


def _make_case(tmp_path: Path, logs: dict[str, str]) -> Path:
    case = tmp_path / "case"
    (case / "logs").mkdir(parents=True)
    (case / "alert.json").write_text(json.dumps(ALERT_TEMPLATE), encoding="utf-8")
    for name, body in logs.items():
        (case / "logs" / name).write_text(body, encoding="utf-8")
    return case


def _estimated_tokens(log_slice, chars_per_token: float = DEFAULT_CHARS_PER_TOKEN) -> float:
    return sum(
        len(line.text) / chars_per_token + REF_OVERHEAD_TOKENS for line in log_slice.lines
    )


# -- the two guarantees ----------------------------------------------------------------


@pytest.mark.parametrize("line_width", [40, 200, 800])
def test_no_slice_exceeds_the_token_budget(tmp_path: Path, line_width: int) -> None:
    """The failure this prevents is total: an oversized slice fails every grunt."""
    body = "\n".join("x" * line_width for _ in range(500))
    catalog, _ = chunk_logs(_make_case(tmp_path, {"a.log": body}) / "logs", slice_token_budget=10_000)

    assert catalog
    for log_slice in catalog.values():
        assert _estimated_tokens(log_slice) <= 10_000


def test_budget_holds_when_long_lines_cluster(tmp_path: Path) -> None:
    """Real logs are not uniform, and the average is not the constraint.

    Short routine lines interleaved with dense bursts is the normal shape of a log during
    an incident. Sizing a fixed window off the file's mean puts the whole burst in one
    slice; on the DNS-tunnel case that produced a 13.4k-token slice against a 10k budget.
    """
    lines = []
    for block in range(20):
        lines += ["short line"] * 40
        lines += ["y" * 900] * 25  # a dense burst, well above the file average
    catalog, _ = chunk_logs(
        _make_case(tmp_path, {"a.log": "\n".join(lines)}) / "logs", slice_token_budget=10_000
    )
    assert catalog
    for log_slice in catalog.values():
        assert _estimated_tokens(log_slice) <= 10_000, (
            f"{log_slice.slice_id} is {_estimated_tokens(log_slice):.0f} tokens"
        )


def test_a_single_oversized_line_gets_its_own_slice(tmp_path: Path) -> None:
    """It cannot be split -- line integrity is what makes a citation resolvable -- so it
    is isolated rather than dragging neighbours over the budget with it."""
    body = "\n".join(["short", "z" * 60_000, "short"])
    catalog, _ = chunk_logs(
        _make_case(tmp_path, {"a.log": body}) / "logs", slice_token_budget=5_000
    )
    sizes = [len(s.lines) for s in catalog.values()]
    assert 1 in sizes
    assert sum(sizes) == 3


def test_every_line_lands_in_exactly_one_slice(tmp_path: Path) -> None:
    """Total coverage is the claim the whole design rests on."""
    body = "\n".join(f"line {n}" for n in range(1, 1001))
    catalog, inventory = chunk_logs(
        _make_case(tmp_path, {"a.log": body}) / "logs", slice_token_budget=2_000
    )

    refs = [line.ref for s in catalog.values() for line in s.lines]
    assert len(refs) == len(set(refs)) == 1000
    assert inventory[0].line_count == 1000
    assert inventory[0].slice_count == len(catalog)


def test_coverage_holds_across_multiple_files(tmp_path: Path) -> None:
    catalog, inventory = chunk_logs(
        _make_case(
            tmp_path,
            {
                "a.log": "\n".join(f"a {n}" for n in range(300)),
                "b.jsonl": "\n".join(f'{{"n": {n}}}' for n in range(150)),
            },
        )
        / "logs",
        slice_token_budget=1_500,
    )
    per_file: dict[str, int] = {}
    for log_slice in catalog.values():
        per_file[log_slice.file] = per_file.get(log_slice.file, 0) + len(log_slice.lines)
    assert per_file == {"a.log": 300, "b.jsonl": 150}
    assert sum(item.slice_count for item in inventory) == len(catalog)


def test_a_bigger_budget_means_fewer_slices(tmp_path: Path) -> None:
    """Slice count follows the context, not a fixed target."""
    logs = _make_case(tmp_path, {"a.log": "\n".join("x" * 100 for _ in range(400))}) / "logs"
    small, _ = chunk_logs(logs, slice_token_budget=2_000)
    large, _ = chunk_logs(logs, slice_token_budget=20_000)
    assert len(large) < len(small)


def test_window_sizing_is_driven_by_line_width() -> None:
    narrow = lines_per_slice(20, slice_token_budget=10_000)
    wide = lines_per_slice(400, slice_token_budget=10_000)
    assert narrow > wide >= MIN_LINES_PER_SLICE


def test_absurdly_long_lines_still_produce_a_slice() -> None:
    """One 50k-character line cannot fit, but returning zero slices would drop data."""
    assert lines_per_slice(50_000, slice_token_budget=10_000) == MIN_LINES_PER_SLICE


def test_token_estimate_uses_the_pessimistic_ratio() -> None:
    # 140 characters at 1.4 chars/token is 100 tokens.
    assert estimate_tokens_per_line(["x" * 140], DEFAULT_CHARS_PER_TOKEN) == pytest.approx(100)


def test_slice_ids_are_stable_and_ordered(tmp_path: Path) -> None:
    """The commander names slice_ids for drill-down; they must be predictable."""
    catalog, _ = chunk_logs(
        _make_case(tmp_path, {"a.log": "\n".join(str(n) for n in range(100))}) / "logs",
        slice_token_budget=600,
    )
    ids = list(catalog)
    assert ids == sorted(ids)
    assert all(i.startswith("a-") for i in ids)


def test_time_range_is_detected_or_admitted(tmp_path: Path) -> None:
    dated = "\n".join(
        ["2026-08-14T09:00:00Z start", "2026-08-14T10:30:00Z middle", "2026-08-14T11:00:00Z end"]
    )
    _, inventory = chunk_logs(_make_case(tmp_path, {"a.log": dated})/ "logs")
    assert inventory[0].time_range == "2026-08-14T09:00:00Z/2026-08-14T11:00:00Z"

    _, undated = chunk_logs(_make_case(tmp_path / "two", {"b.log": "no dates\n"}) / "logs")
    assert "unknown" in undated[0].time_range


# -- case discovery --------------------------------------------------------------------


def test_the_bundled_fixture_case_is_valid() -> None:
    """`./analyze.py fixtures` must work: it is what `make demo` runs."""
    case = discover_case(ROOT / "fixtures")
    assert "dns_resolver.log" in case.log_files


def test_missing_alert_names_the_required_fields(tmp_path: Path) -> None:
    case = _make_case(tmp_path, {"a.log": "x\n"})
    (case / "alert.json").unlink()
    with pytest.raises(CaseLoadError, match="alert.json"):
        discover_case(case)


def test_invalid_alert_reports_the_offending_field(tmp_path: Path) -> None:
    case = _make_case(tmp_path, {"a.log": "x\n"})
    (case / "alert.json").write_text(json.dumps({"alert_id": "only-this"}), encoding="utf-8")
    with pytest.raises(CaseLoadError, match="detector"):
        discover_case(case)


def test_empty_logs_directory_is_caught_at_the_edge(tmp_path: Path) -> None:
    with pytest.raises(CaseLoadError, match="no log files"):
        discover_case(_make_case(tmp_path, {}))


def test_scaffold_produces_something_discover_accepts(tmp_path: Path) -> None:
    layout = scaffold_case(tmp_path / "fresh")
    (layout.logs_dir / "a.log").write_text("hello\n", encoding="utf-8")
    assert discover_case(layout.root).log_files == ("a.log",)
