"""Fixture loading and slice construction.

SEAM: today this reads JSON fixtures off disk. Tomorrow the telemetry pipeline writes
the same shapes -- `Alert`, `PatternSummary`, and log files with stable line numbering.
Everything downstream depends on the schemas, not on the filesystem, so the pipeline
lands here and nowhere else.

The line-ref index built here is what makes citations checkable: a slice knows exactly
which lines it contains, each tagged `<file>:L<n>` with 1-based numbering that matches
what a human sees in an editor.
"""

from __future__ import annotations

import json
from pathlib import Path

from soc_poc.schemas.alert import Alert
from soc_poc.schemas.pattern_summary import LogPointer, PatternSummary
from soc_poc.schemas.slice import LogLine, LogSlice
from soc_poc.validation.injection import InjectionSignal, scan_for_ai_directed_content


def load_alert(path: Path) -> Alert:
    return Alert.model_validate_json(path.read_text(encoding="utf-8"))


def load_pattern_summaries(directory: Path) -> list[PatternSummary]:
    summaries = [
        PatternSummary.model_validate_json(p.read_text(encoding="utf-8"))
        for p in sorted(directory.glob("*.json"))
    ]
    if not summaries:
        raise FileNotFoundError(f"no pattern summaries found in {directory}")
    return summaries


def _read_window(log_path: Path, pointer: LogPointer) -> list[LogLine]:
    """Physical 1-based lines, inclusive of both endpoints.

    Physical lines on purpose: one of the fixture logs is an ugly multiline format, and
    a citation must point at something a human can find with `sed -n '142p'`. A
    record-aware reader would be nicer to the model and worse for the operator.
    """
    all_lines = log_path.read_text(encoding="utf-8").splitlines()
    start = max(1, pointer.start_line)
    end = min(len(all_lines), pointer.end_line)
    return [
        LogLine(ref=f"{log_path.name}:L{n}", text=all_lines[n - 1])
        for n in range(start, end + 1)
    ]


def build_slice_catalog(
    summaries: list[PatternSummary], logs_dir: Path
) -> dict[str, LogSlice]:
    """One slice per log pointer. Slice ids are the commander's only handle on data."""
    catalog: dict[str, LogSlice] = {}
    for summary in summaries:
        for index, pointer in enumerate(summary.log_pointers, start=1):
            log_path = logs_dir / pointer.file
            if not log_path.exists():
                raise FileNotFoundError(
                    f"pattern summary {summary.summary_id} points at missing log {log_path}"
                )
            slice_id = f"{summary.summary_id}-w{index}"
            lines = _read_window(log_path, pointer)
            catalog[slice_id] = LogSlice(
                slice_id=slice_id,
                file=log_path.name,
                source=summary.source,
                host=summary.host,
                time_range=summary.time_range,
                reason=pointer.why or summary.title,
                start_line=pointer.start_line,
                end_line=pointer.end_line,
                lines=lines,
            )
    if not catalog:
        raise ValueError("pattern summaries produced no log slices")
    return catalog


def scan_catalog_for_injection(catalog: dict[str, LogSlice]) -> list[InjectionSignal]:
    """Run the cheap AI-directed-content pass over every raw line, once, at load.

    Hits are attached to the brief for the operator. They are not removed from the
    slices: a grunt reading the line and citing it is fine -- the structural defenses
    do not depend on the model having been shielded from the text.
    """
    signals: list[InjectionSignal] = []
    for log_slice in catalog.values():
        for line in log_slice.lines:
            signals.extend(scan_for_ai_directed_content(line.text, line.ref))
    return signals


def all_known_refs(catalog: dict[str, LogSlice]) -> set[str]:
    refs: set[str] = set()
    for log_slice in catalog.values():
        refs |= log_slice.refs()
    return refs


def load_run_inputs(
    alert_path: Path, patterns_dir: Path, logs_dir: Path
) -> tuple[Alert, list[PatternSummary], dict[str, LogSlice]]:
    alert = load_alert(alert_path)
    summaries = load_pattern_summaries(patterns_dir)
    catalog = build_slice_catalog(summaries, logs_dir)
    return alert, summaries, catalog


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
