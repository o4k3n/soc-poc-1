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
    "wmi-lsass": {
        "checks": [
            {
                "name": "names the source of the type-3 logon (10.12.34.71 / WKS-2208)",
                "needles": [r"10\.12\.34\.71", r"WKS-2208"],
                "refs": ["dhcp.log:L6"],
                # The attacker's source IP appears on exactly one 4624 in the estate.
                "ref_lines": {"file": "security.jsonl",
                              "pattern": r'"IpAddress":"10\.12\.34\.71"'},
            },
            {
                "name": "names the account svc_deploy and that it is privileged/out of place",
                "needles": [r"svc[_-]?deploy"],
                "refs": [],
                "ref_lines": {"file": "security.jsonl", "pattern": r'"TargetUserName":"svc_deploy"'},
            },
            {
                # The logon id is what joins the 4624 to the 4688; a brief that makes the
                # link either names the id or says it tied logon to process.
                # The logon-id is the exact mechanism, but a brief that ties the logon to
                # the exec by the account and the immediate sequence has made the same link;
                # the ref requirement (citing the 4688 lines) keeps a loose match honest.
                "name": "ties the logon to the WmiPrvSE->cmd process (logon id, or account+sequence)",
                "needles": [
                    r"logon\s?id|SubjectLogonId|TargetLogonId|same session",
                    r"\b0x0*[0-9a-f]{4,}\b[^.]{0,60}(logon|session)",
                    # "immediately after the logon ... spawned/executed ..."
                    r"(after|following|then)[^.]{0,50}(logon|authenticat)[^.]{0,120}"
                    r"(spawn|creat|execut|ran|launch|cmd|rundll|process)",
                    # the exec attributed to the same account that logged on
                    r"(spawn|creat|execut|ran|launch)[^.]{0,120}svc_deploy",
                    r"svc_deploy[^.]{0,120}(spawn|creat|execut|ran|launch|cmd|rundll|minidump)",
                ],
                "refs": [],
                "ref_lines": {"file": "security.jsonl", "pattern": r"comsvcs\.dll, MiniDump"},
            },
            {
                "name": "quotes the WmiPrvSE->cmd command line (comsvcs MiniDump of lsass)",
                "needles": [r"comsvcs|MiniDump|WmiPrvSE.{0,40}cmd|cmd.{0,40}WmiPrvSE"],
                "refs": [],
                "ref_lines": {"file": "security.jsonl", "pattern": r"comsvcs\.dll, MiniDump"},
            },
            {
                # 0x1010 alone is not the tell (svchost uses it too); the SourceImage is.
                "name": "identifies the lsass access (0x1010 by the dumper), distinct from AV",
                "needles": [r"lsass.{0,60}(0x1010|granted)", r"(0x1010|granted).{0,60}lsass",
                            r"rundll32.{0,60}lsass|lsass.{0,60}rundll32"],
                "refs": [],
                "ref_lines": {"file": "sysmon.jsonl",
                              "pattern": r'"SourceImage":"[^"]*rundll32\.exe".*"GrantedAccess":"0x1010"'},
            },
            {
                # The scenario's timing tell: one short chain, the opposite of the other
                # two cases' periodic/bursty signatures.
                "name": "describes the timing as a single short chain, not periodic/repeating",
                "needles": [r"single|one[- ]off|once|one short|a short chain|~?\d+\s?s(ec)?\b|"
                            r"not (periodic|repeating|recurring)|in (one|a single)"],
                "refs": [],
            },
            {
                "name": "records what it could not determine (coverage gaps)",
                "needles": [],  # structural
                "refs": [],
            },
        ],
        "decoys": {
            # The killer decoy first: the exact WmiPrvSE->cmd pair the alert matches, benign.
            "SCCM management agent": r"svc_sccm|SRV-SCCM01|10\.12\.34\.8\b|quickfixengineering|CCM\\\\inventory",
            "antivirus lsass access": r"MsMpEng|Windows Defender",
            "admin RDP": r"SRV-JUMP01|10\.12\.34\.9\b|t\.admin",
            "backup service": r"SRV-FS01|10\.12\.34\.10\b",
        },
    },
    "schtask-persist": {
        "checks": [
            {
                "name": "names the source of the type-3 logon (10.12.34.75 / WKS-2190)",
                "needles": [r"10\.12\.34\.75", r"WKS-2190"],
                "refs": ["dhcp.log:L6"],
                "ref_lines": {"file": "security.jsonl", "pattern": r'"IpAddress":"10\.12\.34\.75"'},
            },
            {
                "name": "names the account svc_helpdesk and that it is out of place",
                "needles": [r"svc[_-]?helpdesk"],
                "refs": [],
                "ref_lines": {"file": "security.jsonl", "pattern": r'"TargetUserName":"svc_helpdesk"'},
            },
            {
                "name": "identifies the task registration and its encoded PowerShell action",
                "needles": [
                    r"HealthTelemetryUpdater",
                    r"(4698|scheduled task|task regist)[^.]{0,80}"
                    r"(powershell|encod|-enc|base64|payload)",
                    r"(powershell|encod|-enc|base64|payload)[^.]{0,80}(task|4698|action)",
                ],
                "refs": [],
                "ref_lines": {"file": "security.jsonl", "pattern": r'"event_id":4698.*powershell\.exe -NoP'},
            },
            {
                # The join across the hour: same payload registered then run. Credit either
                # the payload-identity linkage or the temporal install->fire phrasing.
                "name": "ties the registration to the later execution (install-then-fire)",
                "needles": [
                    r"same (payload|command|base64|task)",
                    r"(regist|install|task)[^.]{0,90}(later|then|subsequent|fired|ran|execut)",
                    r"(fired|ran|execut)[^.]{0,90}(task|registered|payload|scheduled)",
                    r"(install|regist)[^.]{0,60}(then|and )[^.]{0,60}(fire|ran|execut)",
                ],
                "refs": [],
                "ref_lines": {"file": "security.jsonl", "pattern": r'"event_id":4688.*-Enc JABjAD0'},
            },
            {
                "name": "describes timing as install-then-fire across a gap, not one chain",
                "needles": [
                    r"install[- ]then[- ]fire", r"two[- ]phase",
                    r"(an? hour|~?\d+\s?(min|hour)|later|gap|delay)[^.]{0,80}"
                    r"(fire|ran|execut|task|schedul|register|install)",
                    # the common phrasing is the other order: "executed ... one hour later"
                    r"(fire|ran|execut|register|install|task)[^.]{0,80}"
                    r"(an? hour|~?\d+\s?(min|hour)|later|gap|delay)",
                ],
                "refs": [],
            },
            {
                "name": "records what it could not determine (coverage gaps)",
                "needles": [],  # structural
                "refs": [],
            },
        ],
        "decoys": {
            # The killer decoy first: benign task registrations, the exact 4698 the alert fires on.
            "benign scheduled tasks": r"GoogleUpdate|EdgeUpdate|ccmeval|ScheduledDefrag|usoclient|UpdateOrchestrator",
            "admin schtasks": r"NightlyCleanup|cleanmgr",
            "admin RDP": r"SRV-JUMP01|10\.12\.34\.9\b|t\.admin",
            "backup service": r"SRV-FS01|10\.12\.34\.10\b",
        },
    },
    # A five-stage intrusion across two workstations and the DC. The alert fires on the
    # MIDDLE (WmiPrvSE->cmd on WKS-5590); the brief has to extend it backward (foothold +
    # LSASS dump on WKS-5581 that produced svc_backup) and forward (scheduled task + DCSync).
    # svc_backup is the thread through all three machines.
    "full-chain": {
        "checks": [
            {
                "name": "names the source of the lateral logon (10.12.34.81 / WKS-5581)",
                "needles": [r"10\.12\.34\.81", r"WKS-5581"],
                "refs": ["dhcp.log:L4"],
                "ref_lines": {"file": "security.jsonl",
                              "pattern": r'"computer":"WKS-5590".*"IpAddress":"10\.12\.34\.81"'},
            },
            {
                # The single thread: the stolen account drives the lateral hop, the task and
                # the DC access across all three machines. Credit naming it as the pivot, or
                # the cross-host linkage phrasing (same account on WKS-5590 and the DC).
                "name": "names svc_backup as the account threading the three machines",
                "needles": [
                    r"svc[_-]?backup",
                    r"(same|one) (account|credential|user)[^.]{0,80}(WKS-5590|WKS-5581|dc|domain controller|SRV-DC01)",
                ],
                "refs": [],
                "ref_lines": {"file": "security.jsonl", "pattern": r'"TargetUserName":"svc_backup"'},
            },
            {
                # Backward stage 1: the encoded-PowerShell foothold on WKS-5581.
                "name": "identifies the encoded-PowerShell foothold on WKS-5581 (OUTLOOK -> powershell -Enc)",
                "needles": [
                    r"(outlook|office|document|phish)[^.]{0,80}(powershell|-enc|encod)",
                    r"(powershell|-enc|encod)[^.]{0,80}(outlook|office|foothold|beacon)",
                    r"foothold|initial access|encoded (powershell|command)",
                ],
                "refs": [],
                "ref_lines": {"file": "security.jsonl",
                              "pattern": r'OUTLOOK\.EXE".*powershell\.exe -NoP -W Hidden -Enc'},
            },
            {
                # Backward stage 2: the LSASS dump that produced svc_backup.
                "name": "identifies the LSASS dump on WKS-5581 (comsvcs MiniDump, 0x1010)",
                "needles": [
                    r"comsvcs|MiniDump",
                    r"lsass[^.]{0,60}(0x1010|dump|granted|memory)",
                    r"(0x1010|dump|credential)[^.]{0,60}lsass",
                ],
                "refs": [],
                "ref_lines": {"file": "security.jsonl", "pattern": r"comsvcs\.dll, MiniDump"},
            },
            {
                # Forward stage 4: the scheduled task, and that it fires later with the same payload.
                "name": "identifies the scheduled task on WKS-5590 and that it fires later (same payload)",
                "needles": [
                    r"HealthTelemetryUpdater",
                    r"(4698|scheduled task|task regist|persist)[^.]{0,90}(powershell|encod|-enc|base64|payload)",
                    r"(same (payload|base64|command))",
                    r"(task|regist|install)[^.]{0,90}(later|then|fired|ran|execut|hour)",
                ],
                "refs": [],
                "ref_lines": {"file": "security.jsonl",
                              "pattern": r'"event_id":4698.*HealthTelemetryUpdater.*-Enc'},
            },
            {
                # Forward stage 5: the DCSync against the DC.
                "name": "identifies the DCSync against SRV-DC01 (4662, replication rights by a non-DC account)",
                "needles": [
                    r"dcsync|dc[- ]?sync",
                    r"(4662|replicat|ds-replication|directory replicat)[^.]{0,80}(svc[_-]?backup|non-dc|workstation|not a dc)",
                    r"(replicat|4662)[^.]{0,60}(get-changes|control access|1131f6aa)",
                ],
                "refs": [],
                "ref_lines": {"file": "security.jsonl",
                              "pattern": r'"event_id":4662.*"SubjectUserName":"svc_backup".*1131f6aa'},
            },
            {
                "name": "records what it could not determine (coverage gaps)",
                "needles": [],  # structural
                "refs": [],
            },
        ],
        "decoys": {
            # Killer decoy first: benign WMI (WmiPrvSE->cmd), the exact shape the alert fired on.
            "benign WMI (SCCM)": r"triggerschedule|gpupdate|CcmExec|svc_sccm",
            "benign LSASS reads (AV)": r"MsMpEng|Windows Defender|0x1000",
            "benign scheduled tasks": r"GoogleUpdate|EdgeUpdate|ccmeval|ScheduledDefrag|usoclient",
            "benign encoded PowerShell": r"EncodedCommand|CcmExec",
            "benign DC replication": r"SRV-DC02",
            "admin RDP": r"SRV-JUMP01|10\.12\.34\.9\b|t\.admin",
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
