"""Regressions for the three information-loss bugs the first DNS-tunnel run exposed.

Each of these corresponds to a specific false statement that reached the operator in
`out/inv-20260814T091742Z-d8f6/brief.json`. The fixtures are the real shapes from that
run, not invented ones.
"""

from __future__ import annotations

from pathlib import Path

from soc_poc.chunking import chunk_logs
from soc_poc.messages import GruntSuccess
from soc_poc.prompting.commander import render_outcomes
from soc_poc.prompting.envelope import fence_log_slice
from soc_poc.schemas.grunt import CheckedFor, GruntReport, SliceMetadata
from soc_poc.schemas.slice import LogLine, LogSlice
from soc_poc.validation.citations import validate_report_citations

SLICE = LogSlice(
    slice_id="dhcp-0001",
    file="dhcp.log",
    source="dhcp",
    host="",
    time_range="t0/t1",
    reason="systematic sweep",
    start_line=1,
    end_line=8,
    lines=[LogLine(ref=f"dhcp.log:L{n}", text=f"lease line {n}") for n in range(1, 9)],
)

# The report that produced "DHCP logs contain no lease entry for 10.12.34.56", verbatim
# in shape: a positive result recorded as a check, on a slice marked irrelevant.
DHCP_REPORT = GruntReport(
    slice_metadata=SliceMetadata(slice_id="dhcp-0001", file="dhcp.log", lines_examined=8),
    relevant=False,
    findings=[],
    checked_for=[
        CheckedFor(checked_for="api-sync-telemetry.net", found=False, result="Not found"),
        CheckedFor(
            checked_for="DHCP lease for 10.12.34.56",
            found=True,
            result="Found in line dhcp.log:L4 and dhcp.log:L8",
        ),
    ],
)


def _success(report: GruntReport) -> GruntSuccess:
    return GruntSuccess(
        task_id="t-1",
        iteration=0,
        slice_id=report.slice_metadata.slice_id,
        instruction="sweep",
        commander_intent="find it",
        report=report,
        attempts=1,
    )


# -- 1. a hit recorded as a check must not be swallowed --------------------------------


def test_positive_check_on_an_irrelevant_slice_is_rejected() -> None:
    """The exact shape that made the brief deny a lease a worker had found."""
    problems = validate_report_citations(DHCP_REPORT, SLICE)
    assert any("positive result" in p for p in problems)
    assert any("DHCP lease for 10.12.34.56" in p for p in problems)


def test_ordinary_negatives_are_still_fine() -> None:
    report = GruntReport(
        slice_metadata=SliceMetadata(slice_id="dhcp-0001", file="dhcp.log", lines_examined=8),
        relevant=False,
        findings=[],
        checked_for=[CheckedFor(checked_for="anything", found=False, result="Not found")],
    )
    assert validate_report_citations(report, SLICE) == []


def test_the_collapse_surfaces_a_stray_positive_rather_than_dropping_it() -> None:
    """Second line of defence: even if a hit gets past the validator, it must be visible.

    Before the fix this rendered as the bare string "dhcp-0001" and nothing else.
    """
    rendered = render_outcomes([_success(DHCP_REPORT)])
    assert "POSITIVE RESULT" in rendered
    assert "dhcp.log:L4" in rendered
    assert "DHCP lease for 10.12.34.56" in rendered


def test_negatives_reach_the_commander_as_an_aggregate() -> None:
    """They used to reach it not at all, which made the whole contract decorative."""
    outcomes = [
        _success(
            GruntReport(
                slice_metadata=SliceMetadata(
                    slice_id=f"dns-{n:04d}", file="dns.log", lines_examined=70
                ),
                relevant=False,
                findings=[],
                checked_for=[
                    CheckedFor(checked_for="TXT answers", found=False, result="not present")
                ],
            )
        )
        for n in range(1, 13)
    ]
    rendered = render_outcomes(outcomes)
    assert "CHECKED FOR AND DID NOT FIND" in rendered
    assert "'TXT answers': looked for in 12 slice(s)" in rendered


def test_the_aggregate_stays_bounded() -> None:
    """A 500-slice sweep must not render 500 negative lines into a 16k context."""
    outcomes = [
        _success(
            GruntReport(
                slice_metadata=SliceMetadata(
                    slice_id=f"dns-{n:04d}", file="dns.log", lines_examined=70
                ),
                relevant=False,
                findings=[],
                checked_for=[
                    CheckedFor(checked_for=f"subject {n}", found=False, result="no")
                ],
            )
        )
        for n in range(200)
    ]
    rendered = render_outcomes(outcomes)
    assert rendered.count("looked for in") <= 25


# -- 2. the format header must reach every slice ---------------------------------------


ZEEK_PREAMBLE = [
    "#separator \\x09",
    "#fields\tts\tuid\tid.orig_h\tquery\tqtype_name\tanswers",
    "#types\ttime\tstring\taddr\tstring\tstring\tvector[string]",
]


def _zeek_case(tmp_path: Path, rows: int) -> Path:
    logs = tmp_path / "logs"
    logs.mkdir(parents=True)
    body = ZEEK_PREAMBLE + [f"17867{n:05d}.0\tCabc\t10.0.0.1\tq{n}.example.com\tTXT\tpayload{n}"
                            for n in range(rows)]
    (logs / "dns.log").write_text("\n".join(body), encoding="utf-8")
    return logs


def test_every_slice_carries_the_format_header(tmp_path: Path) -> None:
    """78 of 79 slices had no header in the first run, so workers read anonymous columns
    and the brief claimed the logs contained no DNS answers."""
    catalog, _ = chunk_logs(_zeek_case(tmp_path, 400), slice_token_budget=2_000)
    assert len(catalog) > 1
    for log_slice in catalog.values():
        assert log_slice.format_header
        assert any("#fields" in line for line in log_slice.format_header)


def test_the_header_is_rendered_as_context_not_as_citable_lines(tmp_path: Path) -> None:
    catalog, _ = chunk_logs(_zeek_case(tmp_path, 400), slice_token_budget=2_000)
    last = list(catalog.values())[-1]
    rendered = fence_log_slice(last)
    assert "#fields" in rendered
    assert "NOT citable" in rendered
    # The header lines are not part of the slice's reference set, so a citation to one
    # would correctly fail to resolve.
    assert not any(line.text.startswith("#") for line in last.lines)


def test_the_header_is_charged_against_the_budget(tmp_path: Path) -> None:
    """Reintroducing the header without paying for it would push slices back over the
    context limit -- the exact failure chunking exists to prevent."""
    catalog, _ = chunk_logs(_zeek_case(tmp_path, 400), slice_token_budget=2_000)
    for log_slice in catalog.values():
        cost = sum(len(l.text) / 1.4 + 12 for l in log_slice.lines)
        cost += sum(len(h) / 1.4 for h in log_slice.format_header)
        assert cost <= 2_000


def test_files_without_a_preamble_are_left_alone(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir(parents=True)
    (logs / "plain.log").write_text("\n".join(f"line {n}" for n in range(50)), encoding="utf-8")
    catalog, _ = chunk_logs(logs)
    assert all(not s.format_header for s in catalog.values())


# -- 3. uncited brief claims are flagged -----------------------------------------------


async def test_uncited_evidence_is_listed_on_the_brief(tmp_path: Path) -> None:
    """In the first real run every false statement was uncited and every cited one was
    true. The operator should be able to see which claims cannot be checked."""
    from soc_poc.config import load_config
    from soc_poc.runner import run_investigation

    root = Path(__file__).resolve().parent.parent
    cfg = load_config(root / "config" / "config.toml")
    cfg = cfg.model_copy(update={"run": cfg.run.model_copy(update={"output_dir": str(tmp_path)})})

    result, _ = await run_investigation(cfg, backend="stub", investigation_id="inv-uncited")
    assert result.brief is not None
    # The stub's canned brief carries one contradicting-evidence entry with no refs.
    assert result.brief.uncited_claims
    assert all(":" in claim for claim in result.brief.uncited_claims)
    assert any(claim.startswith(("timeline[", "hypotheses[")) for claim in result.brief.uncited_claims)
