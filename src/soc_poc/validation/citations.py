"""Citation enforcement: every claim must point at a line that actually exists.

This is the check the grammar cannot make. Guided decoding guarantees that
`raw_line_refs` is a list of strings; only Python can know whether
`dns_resolver.log:L142` was in the slice this particular grunt was handed.

Two failure modes are caught here:
  * an observation with no citation at all -- an assertion, not an observation;
  * a citation that does not resolve inside the slice -- a fabricated reference, which
    is the more interesting one, because it is exactly what a model does when it is
    pattern-matching rather than reading.

Both are validation failures. The caller re-prompts once with the message below (the
model is told precisely which reference did not resolve) and, failing that, records an
explicit failure instead of accepting an uncheckable report.
"""

from __future__ import annotations

import re

from soc_poc.schemas.grunt import GruntReport
from soc_poc.schemas.slice import LogSlice

# "<file>:L<n>" -- the only citation form this system accepts.
LINE_REF_PATTERN = re.compile(r"^[\w.\-/]+:L\d+$")


class CitationError(ValueError):
    """Report references lines it was not shown, or claims things it did not cite."""


def _malformed(refs: list[str]) -> list[str]:
    return [ref for ref in refs if not LINE_REF_PATTERN.match(ref)]


def validate_report_citations(report: GruntReport, log_slice: LogSlice) -> list[str]:
    """Return a list of human-readable problems; empty means the report is citable."""
    available = log_slice.refs()
    problems: list[str] = []

    for index, observation in enumerate(report.observations):
        label = f"observations[{index}]"
        if not observation.raw_line_refs:
            problems.append(
                f"{label} has no raw_line_refs. Every observation must cite at least "
                f"one line from slice {log_slice.slice_id}."
            )
            continue
        for bad in _malformed(observation.raw_line_refs):
            problems.append(
                f"{label} citation {bad!r} is malformed; the required form is "
                f"'{log_slice.file}:L<line-number>'."
            )
        for ref in observation.raw_line_refs:
            if LINE_REF_PATTERN.match(ref) and ref not in available:
                problems.append(
                    f"{label} cites {ref!r}, which is not in slice "
                    f"{log_slice.slice_id} (lines {log_slice.start_line}-"
                    f"{log_slice.end_line} of {log_slice.file}). Cite only lines you "
                    f"were shown."
                )

    # Anomalies are held to the same standard: flagging something unusual without
    # showing the operator where it is wastes their time.
    for index, anomaly in enumerate(report.anomalies_flagged):
        label = f"anomalies_flagged[{index}]"
        if not anomaly.raw_line_refs:
            problems.append(f"{label} has no raw_line_refs; every flag must cite a line.")
        for ref in anomaly.raw_line_refs:
            if LINE_REF_PATTERN.match(ref) and ref not in available:
                problems.append(
                    f"{label} cites {ref!r}, which is not in slice {log_slice.slice_id}."
                )

    if report.slice_metadata.slice_id != log_slice.slice_id:
        problems.append(
            f"slice_metadata.slice_id is {report.slice_metadata.slice_id!r} but this "
            f"task's slice is {log_slice.slice_id!r}."
        )

    return problems


def unresolved_brief_citations(refs: list[str], known: set[str]) -> list[str]:
    """Brief-level citation audit.

    The commander never sees raw log lines, only grunt reports, so its citations are
    second-hand. We do not block the brief on them -- an operator would rather have a
    brief with a flagged bad reference than no brief -- but every unresolvable one is
    listed on the artifact so the reader knows which claims cannot be checked.
    """
    return sorted({ref for ref in refs if ref not in known})
