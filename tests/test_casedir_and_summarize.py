"""Case-folder discovery and the fallback summarizer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_poc.casedir import ALERT_TEMPLATE, CaseLoadError, discover_case, scaffold_case
from soc_poc.loader import build_slice_catalog
from soc_poc.summarize import summarize_logs

ROOT = Path(__file__).resolve().parent.parent


def _make_case(tmp_path: Path, *, logs: dict[str, str], patterns: bool = False) -> Path:
    case = tmp_path / "case"
    (case / "logs").mkdir(parents=True)
    (case / "alert.json").write_text(json.dumps(ALERT_TEMPLATE), encoding="utf-8")
    for name, body in logs.items():
        (case / "logs" / name).write_text(body, encoding="utf-8")
    if patterns:
        (case / "patterns").mkdir()
        (case / "patterns" / "p.json").write_text(
            json.dumps(
                {
                    "summary_id": "hand-written",
                    "title": "t",
                    "source": "s",
                    "host": "h",
                    "time_range": "r",
                    "description": "d",
                    "stats": {},
                    "log_pointers": [
                        {"file": next(iter(logs)), "start_line": 1, "end_line": 2, "why": "w"}
                    ],
                }
            ),
            encoding="utf-8",
        )
    return case


# -- discovery ------------------------------------------------------------------------


def test_the_bundled_fixture_case_is_a_valid_case_folder() -> None:
    """`./analyze.py fixtures` must work: it is what `make demo` runs."""
    case = discover_case(ROOT / "fixtures")
    assert case.has_handwritten_patterns
    assert "dns_resolver.log" in case.log_files


def test_logs_only_case_asks_for_generated_summaries(tmp_path: Path) -> None:
    case = discover_case(_make_case(tmp_path, logs={"a.log": "one\ntwo\n"}))
    assert case.patterns_dir is None
    assert not case.has_handwritten_patterns


def test_handwritten_patterns_win(tmp_path: Path) -> None:
    case = discover_case(_make_case(tmp_path, logs={"a.log": "one\ntwo\n"}, patterns=True))
    assert case.has_handwritten_patterns


def test_missing_alert_names_the_required_fields(tmp_path: Path) -> None:
    case = _make_case(tmp_path, logs={"a.log": "x\n"})
    (case / "alert.json").unlink()
    with pytest.raises(CaseLoadError, match="alert.json"):
        discover_case(case)


def test_invalid_alert_reports_the_offending_field(tmp_path: Path) -> None:
    case = _make_case(tmp_path, logs={"a.log": "x\n"})
    (case / "alert.json").write_text(json.dumps({"alert_id": "only-this"}), encoding="utf-8")
    with pytest.raises(CaseLoadError, match="detector"):
        discover_case(case)


def test_empty_logs_directory_is_caught_at_the_edge(tmp_path: Path) -> None:
    case = _make_case(tmp_path, logs={})
    with pytest.raises(CaseLoadError, match="no log files"):
        discover_case(case)


def test_scaffold_produces_something_discover_accepts(tmp_path: Path) -> None:
    layout = scaffold_case(tmp_path / "fresh")
    (layout.logs_dir / "a.log").write_text("hello\n", encoding="utf-8")
    assert discover_case(layout.root).log_files == ("a.log",)


# -- summarizer -----------------------------------------------------------------------


def test_generated_summaries_produce_a_usable_slice_catalog(tmp_path: Path) -> None:
    case = _make_case(tmp_path, logs={"a.log": "\n".join(f"line {n}" for n in range(1, 61))})
    summaries = summarize_logs(case / "logs")
    catalog = build_slice_catalog(summaries, case / "logs")

    assert len(summaries) == 1
    assert catalog, "auto summaries must yield dispatchable slices"
    # Every generated pointer resolves to lines that actually exist.
    for log_slice in catalog.values():
        assert log_slice.lines
        assert log_slice.lines[0].ref.startswith("a.log:L")


def test_windows_cover_every_line_exactly_once(tmp_path: Path) -> None:
    case = _make_case(tmp_path, logs={"a.log": "\n".join(f"line {n}" for n in range(1, 121))})
    catalog = build_slice_catalog(summarize_logs(case / "logs"), case / "logs")
    refs = [line.ref for s in catalog.values() for line in s.lines]
    assert len(refs) == len(set(refs)) == 120


def test_slice_budget_is_respected_by_widening_windows(tmp_path: Path) -> None:
    """A huge log must not produce hundreds of slices the commander cannot read."""
    case = _make_case(tmp_path, logs={"big.log": "\n".join(str(n) for n in range(5000))})
    catalog = build_slice_catalog(summarize_logs(case / "logs", max_slices=8), case / "logs")
    assert len(catalog) <= 8


def test_stats_are_real_and_labelled_as_fallback(tmp_path: Path) -> None:
    body = "\n".join(
        [
            "2026-08-03T11:04:12Z host app: connect to 10.0.0.1 failed",
            "2026-08-03T11:09:12Z host app: connect to 10.0.0.2 failed",
            "2026-08-03T11:14:12Z host app: something else entirely",
        ]
    )
    summary = summarize_logs(_make_case(tmp_path, logs={"a.log": body}) / "logs")[0]

    assert summary.stats["generated_by"] == "fallback_summarizer"
    assert summary.stats["line_count"] == "3"
    # The two connect lines collapse to one template; the odd one out stays separate.
    assert summary.stats["distinct_line_templates"] == "2"
    assert summary.stats["most_common_template_count"] == "2"
    assert summary.time_range == "2026-08-03T11:04:12Z/2026-08-03T11:14:12Z"
    # The commander must be told these are not pipeline-grade statistics.
    assert "NOT by the telemetry pipeline" in summary.description


def test_files_without_timestamps_say_so_rather_than_inventing_a_range(tmp_path: Path) -> None:
    summary = summarize_logs(_make_case(tmp_path, logs={"a.log": "no dates here\n"}) / "logs")[0]
    assert "unknown" in summary.time_range
