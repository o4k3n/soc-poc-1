"""Citation enforcement: every claim must point at a line that actually exists.

This is the check the grammar cannot make. Guided decoding guarantees that
`representative_refs` is a list of strings; only Python can know whether
`dns.log:L142` was in the slice this particular grunt was handed.

Three failure modes are caught here:

  * a finding with no citation at all -- an assertion, not an observation;
  * a citation that does not resolve inside the slice -- a fabricated reference, the more
    interesting one, because it is exactly what a model does when it is pattern-matching
    rather than reading;
  * more references than the contract allows -- the schema declares a cap, but a grammar
    constrains shape and cannot count, so the cap is re-checked here;
  * a report that claims the slice is irrelevant while recording a hit in `checked_for`.
    That one is not hypothetical: it is how the first real run produced a brief denying a
    DHCP lease that a worker had correctly found.

All are validation failures. The caller re-prompts once with the message below (the model
is told precisely which reference did not resolve) and, failing that, records an explicit
failure instead of accepting an uncheckable report.
"""

from __future__ import annotations

import re

from soc_poc.schemas.grunt import MAX_REPRESENTATIVE_REFS, GruntReport
from soc_poc.schemas.slice import LogSlice

# "<file>:L<n>" -- the only citation form this system accepts.
LINE_REF_PATTERN = re.compile(r"^[\w.\-/]+:L\d+$")


class CitationError(ValueError):
    """Report references lines it was not shown, or claims things it did not cite."""


def _check_refs(
    refs: list[str], label: str, log_slice: LogSlice, problems: list[str]
) -> None:
    for ref in refs:
        if not LINE_REF_PATTERN.match(ref):
            problems.append(
                f"{label} citation {ref!r} is malformed; the required form is "
                f"'{log_slice.file}:L<line-number>'."
            )
        elif ref not in log_slice.refs():
            problems.append(
                f"{label} cites {ref!r}, which is not in slice {log_slice.slice_id} "
                f"(lines {log_slice.start_line}-{log_slice.end_line} of {log_slice.file}). "
                f"Cite only lines you were shown."
            )


def validate_report_citations(report: GruntReport, log_slice: LogSlice) -> list[str]:
    """Return a list of human-readable problems; empty means the report is citable."""
    problems: list[str] = []

    if not report.relevant and report.findings:
        problems.append(
            "relevant is false but findings were returned. Set relevant to true if this "
            "slice contains anything bearing on the alert, or remove the findings."
        )

    # The DHCP case: a worker recorded "Found in line dhcp.log:L4" as a check and marked
    # the slice irrelevant anyway. The collapse then dropped it and the brief asserted the
    # opposite. A hit is a finding, and a finding needs citations -- so this is rejected
    # and the retry turns it into one.
    hits = [c.checked_for for c in report.checked_for if c.found]
    if not report.relevant and hits:
        problems.append(
            f"relevant is false, but checked_for records a positive result for "
            f"{', '.join(repr(h) for h in hits)}. If you found it, this slice IS relevant: "
            f"set relevant to true and report it as a finding with line references. Use "
            f"found=false only for things you looked for and did not see."
        )

    for index, finding in enumerate(report.findings):
        label = f"findings[{index}]"
        if not finding.representative_refs:
            problems.append(
                f"{label} has no representative_refs. Every finding must cite at least "
                f"one line from slice {log_slice.slice_id}."
            )
        if len(finding.representative_refs) > MAX_REPRESENTATIVE_REFS:
            problems.append(
                f"{label} returned {len(finding.representative_refs)} representative_refs; "
                f"the limit is {MAX_REPRESENTATIVE_REFS}. Report the count in match_count "
                f"and cite only the most illustrative lines."
            )
        if finding.match_count < len(finding.representative_refs):
            problems.append(
                f"{label} has match_count {finding.match_count} but cites "
                f"{len(finding.representative_refs)} lines; match_count must be the total "
                f"number of matching lines in this slice."
            )
        _check_refs(finding.representative_refs, label, log_slice, problems)
        _check_refs(
            [r for r in (finding.first_ref, finding.last_ref) if r],
            f"{label} endpoints",
            log_slice,
            problems,
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
