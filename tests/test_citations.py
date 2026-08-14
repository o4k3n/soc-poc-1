"""Citation enforcement: the check guided decoding cannot make."""

from __future__ import annotations

from soc_poc.schemas.grunt import (
    MAX_REPRESENTATIVE_REFS,
    Confidence,
    Finding,
    GruntReport,
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


def _finding(refs: list[str], *, description: str = "a pattern", count: int | None = None) -> Finding:
    return Finding(
        description=description,
        match_count=len(refs) if count is None else count,
        representative_refs=refs,
        first_ref=refs[0] if refs else "",
        last_ref=refs[-1] if refs else "",
        confidence=Confidence.medium,
    )


def _report(findings: list[Finding], *, relevant: bool = True) -> GruntReport:
    return GruntReport(
        slice_metadata=SliceMetadata(
            slice_id="ps-test-w1", file="dns_resolver.log", lines_examined=3
        ),
        relevant=relevant,
        findings=findings,
        checked_for=[],
    )


def test_a_well_cited_report_passes() -> None:
    report = _report([_finding(["dns_resolver.log:L5", "dns_resolver.log:L6"])])
    assert validate_report_citations(report, SLICE) == []


def test_a_slice_with_nothing_in_it_passes() -> None:
    """The common answer on a sweep, and it must be cheap and valid."""
    assert validate_report_citations(_report([], relevant=False), SLICE) == []


def test_finding_without_citation_is_rejected() -> None:
    problems = validate_report_citations(_report([_finding([])]), SLICE)
    assert any("no representative_refs" in p for p in problems)


def test_fabricated_citation_is_rejected() -> None:
    """The interesting failure: a plausible reference to a line never shown."""
    problems = validate_report_citations(_report([_finding(["dns_resolver.log:L4000"])]), SLICE)
    assert any("not in slice ps-test-w1" in p for p in problems)


def test_citation_from_a_different_file_is_rejected() -> None:
    problems = validate_report_citations(_report([_finding(["proxy_events.jsonl:L5"])]), SLICE)
    assert any("not in slice" in p for p in problems)


def test_malformed_citation_is_rejected() -> None:
    problems = validate_report_citations(_report([_finding(["the fifth line"])]), SLICE)
    assert any("malformed" in p for p in problems)


def test_more_refs_than_the_contract_allows_is_rejected() -> None:
    """The schema declares a cap; a grammar cannot count, so Python re-checks it."""
    refs = ["dns_resolver.log:L5"] * (MAX_REPRESENTATIVE_REFS + 1)
    problems = validate_report_citations(_report([_finding(refs)]), SLICE)
    assert any("the limit is" in p for p in problems)


def test_match_count_below_the_number_cited_is_rejected() -> None:
    """An aggregate that claims fewer matches than it cites is not an aggregate."""
    finding = _finding(["dns_resolver.log:L5", "dns_resolver.log:L6"], count=1)
    problems = validate_report_citations(_report([finding]), SLICE)
    assert any("match_count" in p for p in problems)


def test_findings_while_claiming_irrelevance_is_rejected() -> None:
    report = _report([_finding(["dns_resolver.log:L5"])], relevant=False)
    problems = validate_report_citations(report, SLICE)
    assert any("relevant is false" in p for p in problems)


def test_endpoints_must_resolve_too() -> None:
    finding = Finding(
        description="x",
        match_count=1,
        representative_refs=["dns_resolver.log:L5"],
        first_ref="dns_resolver.log:L5",
        last_ref="dns_resolver.log:L900",
        confidence=Confidence.low,
    )
    problems = validate_report_citations(_report([finding]), SLICE)
    assert any("endpoints" in p for p in problems)


def test_slice_id_mismatch_is_reported() -> None:
    report = GruntReport(
        slice_metadata=SliceMetadata(
            slice_id="some-other-slice", file="dns_resolver.log", lines_examined=3
        ),
        relevant=True,
        findings=[_finding(["dns_resolver.log:L5"])],
    )
    assert any(
        "slice_metadata.slice_id" in p for p in validate_report_citations(report, SLICE)
    )


def test_brief_level_audit_lists_unknown_refs_without_blocking() -> None:
    known = {"dns_resolver.log:L5"}
    assert unresolved_brief_citations(["dns_resolver.log:L5"], known) == []
    assert unresolved_brief_citations(
        ["dns_resolver.log:L5", "dns_resolver.log:L900"], known
    ) == ["dns_resolver.log:L900"]
