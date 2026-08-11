"""Citation enforcement: the check guided decoding cannot make."""

from __future__ import annotations

from soc_poc.schemas.grunt import (
    AnomalyFlag,
    Confidence,
    GruntReport,
    Observation,
    SliceMetadata,
)
from soc_poc.schemas.slice import LogLine, LogSlice
from soc_poc.validation.citations import (
    unresolved_brief_citations,
    validate_report_citations,
)

SLICE = LogSlice(
    slice_id="ps-test-w1",
    file="dns_resolver.log",
    source="dns_resolver",
    host="wks-4471",
    time_range="2026-08-03T11:00:00Z/2026-08-03T12:00:00Z",
    reason="unit test",
    start_line=5,
    end_line=7,
    lines=[
        LogLine(ref="dns_resolver.log:L5", text="line five"),
        LogLine(ref="dns_resolver.log:L6", text="line six"),
        LogLine(ref="dns_resolver.log:L7", text="line seven"),
    ],
)


def _report(observations: list[Observation], anomalies: list[AnomalyFlag] | None = None) -> GruntReport:
    return GruntReport(
        slice_metadata=SliceMetadata(slice_id="ps-test-w1", file="dns_resolver.log", lines_examined=3),
        observations=observations,
        negative_findings=[],
        anomalies_flagged=anomalies or [],
    )


def test_a_well_cited_report_passes() -> None:
    report = _report(
        [
            Observation(
                description="two queries one second apart",
                raw_line_refs=["dns_resolver.log:L5", "dns_resolver.log:L6"],
                confidence=Confidence.medium,
            )
        ]
    )
    assert validate_report_citations(report, SLICE) == []


def test_observation_without_citation_is_rejected() -> None:
    report = _report(
        [Observation(description="something happened", raw_line_refs=[], confidence=Confidence.high)]
    )
    problems = validate_report_citations(report, SLICE)
    assert len(problems) == 1
    assert "no raw_line_refs" in problems[0]


def test_fabricated_citation_is_rejected() -> None:
    """The interesting failure: a plausible reference to a line never shown."""
    report = _report(
        [
            Observation(
                description="a line that does not exist",
                raw_line_refs=["dns_resolver.log:L4000"],
                confidence=Confidence.high,
            )
        ]
    )
    problems = validate_report_citations(report, SLICE)
    assert any("not in slice ps-test-w1" in problem for problem in problems)


def test_citation_from_a_different_file_is_rejected() -> None:
    report = _report(
        [
            Observation(
                description="cross-slice leak",
                raw_line_refs=["proxy_events.jsonl:L5"],
                confidence=Confidence.low,
            )
        ]
    )
    assert any("not in slice" in problem for problem in validate_report_citations(report, SLICE))


def test_malformed_citation_is_rejected() -> None:
    report = _report(
        [
            Observation(
                description="prose instead of a reference",
                raw_line_refs=["the fifth line"],
                confidence=Confidence.low,
            )
        ]
    )
    assert any("malformed" in problem for problem in validate_report_citations(report, SLICE))


def test_anomalies_must_cite_too() -> None:
    report = _report(
        [
            Observation(
                description="fine", raw_line_refs=["dns_resolver.log:L5"], confidence=Confidence.low
            )
        ],
        [AnomalyFlag(description="odd", raw_line_refs=[], why_unusual="vibes")],
    )
    assert any("anomalies_flagged[0]" in problem for problem in validate_report_citations(report, SLICE))


def test_slice_id_mismatch_is_reported() -> None:
    report = GruntReport(
        slice_metadata=SliceMetadata(slice_id="some-other-slice", file="dns_resolver.log", lines_examined=3),
        observations=[
            Observation(
                description="fine", raw_line_refs=["dns_resolver.log:L5"], confidence=Confidence.low
            )
        ],
    )
    assert any("slice_metadata.slice_id" in problem for problem in validate_report_citations(report, SLICE))


def test_brief_level_audit_lists_unknown_refs_without_blocking() -> None:
    known = {"dns_resolver.log:L5"}
    assert unresolved_brief_citations(["dns_resolver.log:L5"], known) == []
    assert unresolved_brief_citations(
        ["dns_resolver.log:L5", "dns_resolver.log:L900"], known
    ) == ["dns_resolver.log:L900"]
