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
# The same reference when it has the line's text stuck to it. The evidence ledger renders
# each line as "<ref>  <text>", and the commander copies the whole rendering into
# raw_line_refs -- 22 of them in one run. That is a real citation with debris attached,
# not prose in a citation field, and throwing it away loses a claim the operator could
# otherwise have checked.
_LEADING_REF = re.compile(r"^([\w.\-/]+:L\d+)(?:\s|$)")


def normalise_ref(ref: str) -> str:
    """Trim a citation down to the reference, if it starts with one."""
    match = _LEADING_REF.match(ref.strip())
    return match.group(1) if match else ref.strip()


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


def _check_description_matches_lines(
    finding, indicators: list[str], label: str, log_slice: LogSlice, problems: list[str]
) -> None:
    """A citation that resolves is not the same as a citation that supports.

    The failure this exists for: a worker reported `dns.log:L244` as "TXT-type DNS queries
    from source IP 10.12.34.56 to domain api-sync-telemetry.net". L244 is an antivirus
    reputation lookup -- different host, different domain. The reference resolved, so every
    check passed, and the brief cited a decoy as its primary evidence for an intrusion.

    The worker had matched "TXT query" and then described the *directive* instead of the
    line. That is checkable in code precisely because the directive's indicators are exact
    strings: if a description names one, at least one cited line had better contain it.

    Deliberately narrow. It only fires on indicators the description itself invokes, so a
    worker describing something the directive never mentioned is unaffected -- that is the
    judgement the sweep is there to get, and this must not punish it.
    """
    described = [i for i in indicators if i and i.lower() in finding.description.lower()]
    if not described:
        return
    cited_text = " ".join(
        line.text.lower()
        for line in log_slice.lines
        if line.ref in set(finding.representative_refs)
    )
    if not cited_text:
        return
    missing = [i for i in described if i.lower() not in cited_text]
    if missing:
        problems.append(
            f"{label} describes {', '.join(repr(m) for m in missing)} but none of the "
            f"lines it cites contain that. Either cite lines that actually show what you "
            f"are describing, or describe what those lines really are. Do not restate the "
            f"indicators you were given as though you had observed them."
        )


def validate_report_citations(
    report: GruntReport, log_slice: LogSlice, indicators: list[str] | None = None
) -> list[str]:
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
        _check_description_matches_lines(
            finding, indicators or [], label, log_slice, problems
        )

    if report.slice_metadata.slice_id != log_slice.slice_id:
        problems.append(
            f"slice_metadata.slice_id is {report.slice_metadata.slice_id!r} but this "
            f"task's slice is {log_slice.slice_id!r}."
        )

    return problems


def unresolved_brief_citations(refs: list[str], known: set[str]) -> tuple[list[str], list[str]]:
    """Brief-level citation audit. Returns (unresolved, malformed).

    The commander's citations are second-hand -- it works from what its workers reported,
    plus a sample of their lines. We do not block the brief on a bad reference; an operator
    would rather have a brief with a flagged citation than no brief. But the reader has to
    be able to tell which claims they can chase.

    Malformed entries are separated because they are a different failure. A real run
    emitted these into a `raw_line_refs` array:

        '... (additional line refs omitted for brevity, see full list in evidence sections) ...'
        '... (representative sample) ...'

    That is prose in a citation field. Listing it next to genuine unresolvable references
    would suggest someone could go and look it up.
    """
    unresolved: set[str] = set()
    malformed: set[str] = set()
    for raw in refs:
        ref = normalise_ref(raw)
        if not LINE_REF_PATTERN.match(ref):
            malformed.add(ref)
        elif ref not in known:
            unresolved.add(ref)
    return sorted(unresolved), sorted(malformed)
