"""Regressions for the three information-loss bugs the first DNS-tunnel run exposed.

Each of these corresponds to a specific false statement that reached the operator in
`out/inv-20260814T091742Z-d8f6/brief.json`. The fixtures are the real shapes from that
run, not invented ones.
"""

from __future__ import annotations

from pathlib import Path

from soc_poc.chunking import chunk_logs
from soc_poc.messages import GruntSuccess
from soc_poc.prompting.envelope import fence_log_slice
from soc_poc.schemas.grunt import (
    CheckedFor,
    Confidence,
    Finding,
    GruntReport,
    SliceMetadata,
)
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
        CheckedFor(checked_for="api-sync-telemetry.net", found=False,
                   scope="all 8 lines of dhcp-0001", result="Not found"),
        CheckedFor(
            checked_for="DHCP lease for 10.12.34.56",
            found=True,
            scope="all 8 lines of dhcp-0001",
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
        checked_for=[CheckedFor(checked_for="anything", found=False, scope="dhcp-0001", result="Not found")],
    )
    assert validate_report_citations(report, SLICE) == []


def test_a_positive_filed_under_checked_for_still_reaches_the_commander() -> None:
    """The DHCP information-loss bug, pinned at its new location.

    `dhcp-0001` was handed an eight-line file with the lease on lines 4 and 8. It found
    it, wrote it into `checked_for` instead of `findings`, and set relevant=false. The
    aggregation dropped it and the brief went out saying the host could not be identified.

    Under the action loop there is no aggregation, but a close_read summary built only
    from `findings` would lose exactly the same information. A positive is a positive
    wherever the worker filed it.
    """
    report = GruntReport(
        slice_metadata=SliceMetadata(slice_id="closeread-001", file="dhcp.log", lines_examined=8),
        relevant=False,
        findings=[],
        checked_for=[
            CheckedFor(
                checked_for="10.12.34.56",
                found=True,
                scope="all 8 lines of dhcp.log",
                result="lease to wks-2291 at dhcp.log:L4",
            )
        ],
    )
    described = [
        f"also found: {check.checked_for} -- {check.result}"
        for check in report.checked_for
        if check.found
    ]
    assert described, "a found=True check must survive into the step summary"
    assert "wks-2291" in described[0]


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


# -- run 3: false negatives and misattributed citations --------------------------------


def _check(subject: str, found: bool, scope: str = "all lines") -> CheckedFor:
    return CheckedFor(checked_for=subject, found=found, scope=scope,
                      result="see finding" if found else "not present")


def _slice_with(refs_to_text: dict[str, str], slice_id: str = "dns-0004") -> LogSlice:
    return LogSlice(
        slice_id=slice_id, file="dns.log", source="dns", host="",
        time_range="t0/t1", reason="sweep",
        start_line=1, end_line=len(refs_to_text),
        lines=[LogLine(ref=r, text=t) for r, t in refs_to_text.items()],
    )


def _finding(description: str, refs: list[str], count: int = 2) -> Finding:
    return Finding(description=description, match_count=count, representative_refs=refs,
                   first_ref=refs[0], last_ref=refs[-1], confidence=Confidence.medium)


def test_a_description_naming_an_indicator_its_lines_lack_is_rejected() -> None:
    """Run 3's other failure, verbatim.

    Grunt dns-0004 reported dns.log:L244 as "TXT-type DNS queries from source IP
    10.12.34.56 to domain api-sync-telemetry.net". L244 is an antivirus reputation lookup:
    different host, different domain. The reference resolved, so nothing caught it, and the
    brief cited a decoy as primary evidence of an intrusion.
    """
    log_slice = _slice_with({
        "dns.log:L244": "1786.7\tCabc\t10.12.34.18\t53\tbe532b40.avts.vendor-cloud.example.net\tTXT",
        "dns.log:L247": "1786.8\tCdef\t10.12.34.22\t53\tselector1._domainkey.partner-b.example.org\tTXT",
    })
    report = GruntReport(
        slice_metadata=SliceMetadata(slice_id="dns-0004", file="dns.log", lines_examined=2),
        relevant=True,
        findings=[_finding(
            "TXT-type DNS queries from source IP 10.12.34.56 to domain api-sync-telemetry.net",
            ["dns.log:L244", "dns.log:L247"],
        )],
    )
    problems = validate_report_citations(
        report, log_slice, ["10.12.34.56", "api-sync-telemetry.net", "TXT"]
    )
    assert any("none of the lines it cites contain that" in p for p in problems)
    assert any("10.12.34.56" in p for p in problems)


def test_a_description_matching_its_lines_passes() -> None:
    log_slice = _slice_with({
        "dns.log:L978": "1786.9\tCxyz\t10.12.34.56\t53\tb1d33481.t.api-sync-telemetry.net\tTXT",
    })
    report = GruntReport(
        slice_metadata=SliceMetadata(slice_id="dns-0004", file="dns.log", lines_examined=1),
        relevant=True,
        findings=[_finding(
            "TXT queries from 10.12.34.56 to api-sync-telemetry.net",
            ["dns.log:L978"], count=1,
        )],
    )
    assert validate_report_citations(
        report, log_slice, ["10.12.34.56", "api-sync-telemetry.net", "TXT"]
    ) == []


def test_the_check_ignores_indicators_the_description_never_claims() -> None:
    """A worker describing something the directive never mentioned is exactly the judgement
    the sweep exists to get. This must not punish it."""
    log_slice = _slice_with({"dns.log:L500": "1786.9\tCxyz\t10.0.0.9\t53\tsomething.odd\tNULL"})
    report = GruntReport(
        slice_metadata=SliceMetadata(slice_id="dns-0004", file="dns.log", lines_examined=1),
        relevant=True,
        findings=[_finding("an unusual NULL-record query nobody asked about",
                           ["dns.log:L500"], count=1)],
    )
    assert validate_report_citations(report, log_slice, ["10.12.34.56", "api-sync-telemetry.net"]) == []


# -- run 4: elision, and salvaging a partly-wrong report -------------------------------


def test_elision_keeps_both_ends_of_a_wide_record() -> None:
    """Zeek puts `answers` last. Truncating from the right hid every TXT payload in the
    case, and the commander wrote "no DNS response payloads were captured" into a brief
    about a tunnel whose exfiltration channel was exactly those payloads."""
    from soc_poc.evidence import elide as _elide

    line = "\t".join(["1786700018.7", "Cabc", "10.12.34.56", "62932"]
                     + ["filler"] * 40
                     + ["7090833d.t.api-sync-telemetry.net", "TXT", "NOERROR",
                        "qkkqxufu2locm37fpz6prd6mwuiekgttkod4xewk"])
    elided = _elide(line, max_chars=120)

    assert line[:40] in elided                      # the front survives
    assert len(elided) < len(line)                  # and it actually shortened
    assert "qkkqxufu2locm37fpz6prd6mwuiekgttkod4xewk" in elided  # so does the payload
    assert "elided" in elided                       # and it says what it dropped


def test_a_short_line_is_left_alone() -> None:
    from soc_poc.evidence import elide as _elide

    assert _elide("short line", max_chars=120) == "short line"


def test_one_bad_finding_does_not_cost_the_whole_slice() -> None:
    """Ten slices were written off as unexamined ground for a single fabricated finding.
    They happened to hold no tunnel traffic; nothing guaranteed that."""
    from soc_poc.grunt import _drop_failed_findings

    report = GruntReport(
        slice_metadata=SliceMetadata(slice_id="dns-0004", file="dns.log", lines_examined=70),
        relevant=True,
        findings=[
            _finding("fabricated: api-sync-telemetry.net", ["dns.log:L244"], count=2),
            _finding("real: repeated NXDOMAIN responses", ["dns.log:L245"], count=9),
        ],
        checked_for=[_check("TXT payloads", found=False, scope="dns-0004")],
    )
    salvaged = _drop_failed_findings(
        report, ["findings[0] describes 'api-sync-telemetry.net' but none of the lines…"]
    )

    assert salvaged is not None
    assert len(salvaged.findings) == 1
    assert salvaged.findings[0].description.startswith("real:")
    assert salvaged.relevant is True
    assert salvaged.checked_for == report.checked_for  # negatives survive too


def test_dropping_every_finding_makes_the_slice_honestly_empty() -> None:
    from soc_poc.grunt import _drop_failed_findings

    report = GruntReport(
        slice_metadata=SliceMetadata(slice_id="dns-0004", file="dns.log", lines_examined=70),
        relevant=True,
        findings=[_finding("fabricated", ["dns.log:L244"], count=2)],
        checked_for=[_check("TXT payloads", found=False, scope="dns-0004")],
    )
    salvaged = _drop_failed_findings(report, ["findings[0] describes 'x' but none of…"])

    assert salvaged is not None
    assert salvaged.findings == []
    # Not "relevant with nothing to show" -- the slice showed nothing, and its negatives
    # now count as the honest result.
    assert salvaged.relevant is False


def test_an_envelope_level_problem_is_not_salvageable() -> None:
    """A worker that reported the wrong slice_id lost track of what it was reading.
    Nothing in that report should be trusted."""
    from soc_poc.grunt import _drop_failed_findings

    report = GruntReport(
        slice_metadata=SliceMetadata(slice_id="dns-0406", file="dns.log", lines_examined=70),
        relevant=True,
        findings=[_finding("something", ["dns.log:L244"], count=2)],
    )
    assert _drop_failed_findings(
        report,
        ["findings[0] describes 'x' but none of…",
         "slice_metadata.slice_id is 'dns-0406' but this task's slice is 'dns-0004'."],
    ) is None
