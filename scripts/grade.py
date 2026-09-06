#!/usr/bin/env python3
"""Grade a brief against a case's ground truth. Mechanical checks only.

    ./scripts/grade.py out/inv-xxxx [--case cases/dns-tunnel]

This does not judge whether the brief reads well. It checks the things that are
objectively true of `cases/dns-tunnel` and were graded by hand four times: whether the
brief reached each planted fact, whether it cited it rather than merely asserting it, and
whether it flagged any of the four decoys as malicious.

The decoy check is the one worth explaining, and it took two attempts. Each decoy is
benign and tunnel-shaped, so merely *mentioning* one is fine -- GROUND_TRUTH.md asks the
brief not to flag them "or if it mentions them, explicitly distinguish them". What is not
fine is naming one as evidence *for the intrusion*.

The first version looked for a decoy anywhere in any hypothesis's supporting evidence, and
promptly failed a run for good analysis: the brief had cited the CDN and AV domains as a
benign BASELINE -- "used by 12 distinct hosts each, which is the expected shape for
legitimate vendor services" -- in support of the hypothesis that the alerted traffic might
be a similar service. That is the decoys doing exactly the job they were planted for.

So the check now asks which hypothesis the evidence supports. A decoy supporting a
*benign* hypothesis is sound reasoning; a decoy supporting a hypothesis that asserts
malice is the false positive worth catching.

Findings are reported as REACHED / CITED / MISSED rather than a score, because "found the
NS delegation but cited no line for it" and "never found it" are different failures with
different fixes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# The planted facts per case, and what counts as having reached each one. A check passes
# if any of its `needles` appears anywhere in the brief's prose; it is CITED if any of its
# `refs` appears in a raw_line_refs array. The registry is keyed by case-folder name
# (cases/<name>), so a new scenario is a new entry here plus a generator -- no change to
# the grading machinery below.
#
# The check whose name starts with "records what" is the coverage-gaps structural check,
# handled specially in main(); its needles/refs are ignored. Every case should carry one.
CASES: dict[str, dict] = {
    "dns-tunnel": {
        "checks": [
            {
                "name": "attributes traffic to 10.12.34.56",
                "needles": [r"10\.12\.34\.56"],
                "refs": [],
            },
            {
                "name": "identifies the host as wks-2291 (via dhcp.log)",
                "needles": [r"wks-2291"],
                "refs": ["dhcp.log:L4", "dhcp.log:L8"],
            },
            {
                "name": "cites the NS delegation",
                # Deliberately generous on wording: "an NS record for the domain is
                # present" is reaching the fact even though it stops short of calling it a
                # delegation. The `refs` requirement separates reaching it from citing it.
                "needles": [r"\bNS\b[ -]?record|delegat|ns1\.api-sync-telemetry"],
                "refs": ["dns.log:L975", "dns.log:L976"],
            },
            {
                "name": "names the attacker nameserver 45.77.203.118",
                "needles": [r"45\.77\.203\.118"],
                "refs": ["dns.log:L976"],
            },
            {
                "name": "notes the answers succeeded and carried payload",
                "needles": [
                    r"answer.{0,60}(payload|data|base32|carr)",
                    r"(payload|base32).{0,60}answer",
                    # The example payload string a good brief quotes can sit between
                    # "contain" and "payload"; keep the window wide enough to see past it.
                    r"TXT (record|response)s? .{0,140}(carr|contain).{0,140}(data|payload)",
                ],
                "refs": [],
                # Any tunnel TXT line is the evidence for this; there are ~650 of them,
                # so they are matched against the log at grade time, not listed.
                "ref_lines": {"file": "dns.log",
                              "pattern": r"\.t\.api-sync-telemetry\.net\t.*\tTXT\t"},
            },
            {
                "name": "describes timing as bursty sessions, not a fixed interval",
                "needles": [r"burst|session"],
                "refs": [],
            },
            {
                "name": "records what it could not determine (coverage gaps)",
                "needles": [],  # structural, checked separately
                "refs": [],
            },
        ],
        "decoys": {
            "DNSBL": r"spamhaus",
            "AV reputation": r"vendor-cloud|avts",
            "CDN cache keys": r"cdn-assets",
            "DKIM": r"_domainkey|DKIM",
        },
    },
    "http-c2": {
        "checks": [
            {
                "name": "attributes the beaconing to 10.12.34.72",
                "needles": [r"10\.12\.34\.72"],
                "refs": [],
            },
            {
                "name": "identifies the host as wks-4471 (via dhcp.log)",
                "needles": [r"wks-4471"],
                "refs": ["dhcp.log:L4", "dhcp.log:L8"],
            },
            {
                "name": "names the C2 destination and its rarity",
                "needles": [r"185\.243\.115\.94|cdn-metric-collector"],
                "refs": [],
                "ref_lines": {"file": "http.log", "pattern": r"cdn-metric-collector\.net"},
            },
            {
                # The scenario's whole point: periodic, NOT bursty. Either the correct
                # vocabulary (beacon/periodic/regular interval) or a stated ~60 s cadence.
                "name": "describes timing as periodic beaconing, not bursts",
                "needles": [
                    r"beacon|periodic|regular(ly)?[ -](interval|spaced|timed)|"
                    r"fixed[ -]interval|every ?~?\d+ ?s|~?60 ?s|cadence|metronom"
                ],
                "refs": [],
            },
            {
                "name": "flags the anomalous, constant User-Agent",
                "needles": [
                    r"user[- ]?agent|\bUA\b|MSIE|Trident|Mozilla/4\.0",
                ],
                "refs": [],
            },
            {
                # Direction matters: exfil is large OUTBOUND request bodies, not just
                # "large transfers" (the update-poller decoy has large downloads).
                "name": "notes outbound POST volume (exfiltration direction)",
                "needles": [
                    r"POST.{0,80}(upload|exfil|outbound|large|body)",
                    r"(exfil|outbound|upload).{0,80}POST",
                    r"request[_ ]body.{0,40}(large|bytes|volume)",
                ],
                "refs": [],
                # The 14 /cm/upload POSTs are the exfiltration; citing any one of them is
                # citing the direction.
                "ref_lines": {"file": "http.log",
                              "pattern": r"POST\tcdn-metric-collector\.net\t/cm/upload"},
            },
            {
                "name": "records what it could not determine (coverage gaps)",
                "needles": [],  # structural, checked separately
                "refs": [],
            },
        ],
        "decoys": {
            # The killer decoy first: an internal heartbeat that is beacon-shaped and benign.
            "monitoring agent": r"collector\.corp|10\.12\.34\.5\b|/heartbeat|corp-monitor",
            "OCSP": r"ocsp|digicert",
            "telemetry": r"data\.microsoft|OneCollector|delivery-optimization",
            "update poller": r"windowsupdate|ctldl|Microsoft-BITS",
        },
    },
}


# gpt-oss writes non-breaking and en dashes into prose: `wks‑2291`, `api‑sync‑telemetry`.
# Matching ASCII patterns against that silently under-grades the brief -- it cost a wrong
# MISSED on the hostname before this was noticed.
_DASHES = str.maketrans({"\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
                         "\u2014": "-", "\u2212": "-", "\u00a0": " "})


def _normalise(text: str) -> str:
    return text.translate(_DASHES)


def _prose(body: dict) -> str:
    """Everything the commander wrote, as one blob."""
    parts = [body.get("investigation_narrative", "")]
    for event in body.get("timeline", []):
        parts.append(event.get("description", ""))
    for hypothesis in body.get("hypotheses", []):
        parts.append(hypothesis.get("statement", ""))
        for field in ("supporting_evidence", "contradicting_evidence"):
            for item in hypothesis.get(field, []):
                parts.append(item.get("description", ""))
    for drill in body.get("suggested_drilldowns", []):
        parts.extend([drill.get("question", ""), drill.get("why", "")])
    parts.extend(body.get("open_questions", []))
    parts.extend(body.get("coverage_gaps", []))
    return _normalise("\n".join(parts))


def _all_refs(body: dict) -> set[str]:
    refs: set[str] = set()
    for event in body.get("timeline", []):
        refs.update(event.get("raw_line_refs", []))
    for hypothesis in body.get("hypotheses", []):
        for field in ("supporting_evidence", "contradicting_evidence"):
            for item in hypothesis.get(field, []):
                refs.update(item.get("raw_line_refs", []))
    # A ref may arrive with the line's text stuck to it; grade the reference, not the debris.
    return {re.split(r"\s", r.strip(), 1)[0] for r in refs}


# A hypothesis asserting the activity IS an intrusion. Only evidence supporting one of
# these can constitute a decoy false positive.
_MALICE = re.compile(
    r"exfiltrat|tunnel|c2\b|command[- ]and[- ]control|malicious|beacon|compromis|"
    r"attacker|trojan|implant",
    re.I,
)


def _supporting_prose(body: dict) -> str:
    """Evidence offered in support of a hypothesis that asserts malice.

    Scoped deliberately: a decoy cited under a benign hypothesis is the brief using it as
    a baseline, which is what the decoys exist to enable. See the module docstring.
    """
    out = []
    for hypothesis in body.get("hypotheses", []):
        if not _MALICE.search(_normalise(hypothesis.get("statement", ""))):
            continue
        for item in hypothesis.get("supporting_evidence", []):
            out.append(item.get("description", ""))
    return _normalise("\n".join(out))


def _resolve_ref_lines(case_dir: Path, spec: dict | None) -> tuple[set[str], str]:
    """Expand a check's `ref_lines` into the `<file>:L<n>` refs it accepts.

    Some facts are carried by hundreds of interchangeable lines (any tunnel TXT answer,
    any beacon to the C2 host). Listing those refs by hand would be wrong the day the case
    is regenerated, so the rubric names the file and a regex and the refs are derived from
    the log at grade time -- numbered exactly as corpus.py numbers them, header lines
    included. Returns the refs and a one-line description for the "wanted" message; an
    absent or unreadable log yields no refs, and the literal `refs` still apply.
    """
    if not spec:
        return set(), ""
    path = case_dir / "logs" / spec["file"]
    if not path.exists():
        return set(), f"(could not read {path} to resolve line refs)"
    regex = re.compile(spec["pattern"], re.I)
    refs = {
        f"{spec['file']}:L{number}"
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        if regex.search(line)
    }
    examples = ", ".join(sorted(refs, key=lambda r: int(r.rsplit("L", 1)[1]))[:3])
    return refs, (
        f"any of {len(refs)} {spec['file']} line(s) matching /{spec['pattern']}/"
        + (f", e.g. {examples}" if examples else "")
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--case", type=Path, default=Path("cases/dns-tunnel"))
    args = parser.parse_args()

    brief_path = args.run_dir / "brief.json"
    if not brief_path.exists():
        print(f"no brief at {brief_path} — the run produced none", file=sys.stderr)
        return 2
    case_name = args.case.name
    if case_name not in CASES:
        print(f"no grading rubric for case {case_name!r}; known: "
              f"{', '.join(sorted(CASES))}", file=sys.stderr)
        return 2
    checks = CASES[case_name]["checks"]
    decoys = CASES[case_name]["decoys"]

    brief = json.loads(brief_path.read_text())
    body = brief["body"]
    prose = _prose(body)
    refs = _all_refs(body)

    print(f"grading {brief_path}  (against {args.case}/GROUND_TRUTH.md)\n")
    reached = 0
    for check in checks:
        if check["name"].startswith("records what"):
            ok = bool(body.get("coverage_gaps"))
            cited = False
        else:
            ok = any(re.search(n, prose, re.I) for n in check["needles"])
            derived, derived_note = _resolve_ref_lines(args.case, check.get("ref_lines"))
            wanted = set(check["refs"]) | derived
            cited = any(r in refs for r in wanted)
        reached += ok
        mark = "CITED " if ok and cited else ("REACHED" if ok else "MISSED ")
        detail = ""
        if ok and (check["refs"] or check.get("ref_lines")) and not cited:
            wants = list(check["refs"]) + ([derived_note] if derived_note else [])
            detail = f"   (no line ref; wanted one of {', '.join(wants)})"
        print(f"  [{mark}] {check['name']}{detail}")

    print("\n  decoys (flagging one as evidence is a false positive):")
    false_positives = 0
    supporting = _supporting_prose(body)
    for name, pattern in decoys.items():
        in_support = bool(re.search(pattern, supporting, re.I))
        mentioned = bool(re.search(pattern, prose, re.I))
        false_positives += in_support
        state = (
            "FALSE POSITIVE — cited as supporting evidence"
            if in_support
            else ("mentioned (fine — check it is distinguished)" if mentioned else "not flagged")
        )
        print(f"    {name:<16} {state}")

    print("\n  mechanics:")
    for field in ("unresolved_citations", "malformed_citations", "uncited_claims"):
        print(f"    {field:<22} {len(brief.get(field) or [])}")
    print(f"    {'steps_taken':<22} {brief.get('steps_taken')}")
    print(f"    {'terminal_state':<22} {brief.get('terminal_state')}")
    print(f"    {'alert status unchanged':<22} {brief['alert_ref']['status']}")

    print(f"\n  {reached}/{len(checks)} ground-truth items reached, "
          f"{false_positives} decoy false positive(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
