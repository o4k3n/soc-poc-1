"""Prompts for the action loop: profile, one step at a time, then synthesis.

The commander is now an analyst at a terminal rather than a manager of a reading fleet. It
sees the alert, a computed profile of the corpus, and the record of what it has already
asked and been shown. It asks one question. It sees the answer. It asks the next one.

Two things this prompt has to fight, both learned from graded runs:

  * **Restating the alert as a finding.** Six briefs led with "DNS queries to
    api-sync-telemetry.net were observed", which is what the alert said in the first
    place. The prompt asks for what the alert did NOT already contain.
  * **Building on absence.** Run 3 constructed an entire false-positive hypothesis out of
    negatives its own aggregation had manufactured. Here every negative is an exact count
    the operator can re-run -- but an exact zero is still only a zero for the pattern that
    was actually typed, and the prompt says so.
"""

from __future__ import annotations

import json
import re

from soc_poc.corpus import MAX_RESULTS
from soc_poc.evidence import Evidence, _headline, elide
from soc_poc.profiling import CaseProfile, _ID_CANDIDATE, _entropy, _looks_like_domain
from soc_poc.prompting.envelope import DATA_IS_NOT_INSTRUCTIONS, fence_alert
from soc_poc.schemas.action import ActionProblem
from soc_poc.schemas.alert import Alert

_ROLE = """You are the lead analyst in a security operations investigation system. An \
external detection system has already raised an alert; your job is to investigate \
around it and hand a human operator something they can act on."""

_AUTHORITY = """The external alert's status and severity are authoritative and \
read-only. You do not confirm, dismiss, escalate, downgrade, or close anything. You \
enrich: you show the operator what the data contains, which explanations it supports, \
which it undermines, and where to look next. The operator decides."""

# Measured, not stylistic. Describing six verbs reads to gpt-oss like a tool menu, and it
# answers with a harmony tool call -- at which point the structured-output grammar does not
# engage at all and the reply comes back as `{"action":"count","action_input":"..."}`. On
# the real dns-tunnel prompt that was 0/3 conformant across `response_format`,
# `structured_outputs` AND legacy `guided_json`; adding the paragraph below took it to 2/2.
# The same schema on a short prompt, or on the retry turn, was always fine -- so this is
# about which channel the model chooses, not about the schema.
#
# Belt and braces: coercion.py rescues a tool-shaped reply if one gets through anyway.
_NOT_A_TOOL_CALL = """This system has no tool-calling interface and there is no tool to \
invoke. Your reply IS the answer: a single JSON object with exactly these keys -- \
reasoning, expectation, action, pattern, where, file, field, extract, ref, start_line, \
end_line, question. Fields your chosen action does not use must still be present and empty ("" or 0). \
No prose outside the object."""

# The optional aggregation skills, hooked up one at a time via run.enabled_skills. Each
# entry is the whole of what the commander is told about the verb; a verb not listed here
# for this run is also rejected by validate_action, so the menu and the gate agree.
#
# tally and stats describe the field/extract selectors, which are how the commander picks
# a value WITHOUT a column-counting regex: the pattern only has to match the line. The
# field names come from the "fields:" line under each log file that has a header.
_SKILL_MENU: dict[str, str] = {
    "tally": (
        "  tally       regex, case-insensitive. Returns the DISTINCT values with an exact "
        "count for each. Choose the value with (a) field=\"<name-or-number-or-JSON-key>\" to take a "
        "delimited column -- the surest way, the pattern then only has to MATCH the line; "
        "or (b) extract=\"ip|domain|hash|email\" to pull every such entity from the line "
        "(this is how you list the IOCs in a set of lines); or (c) a capture group in the "
        "pattern. One tally answers \"which hosts, and how often each\" -- do not enumerate "
        "a distribution with repeated counts, and prefer field= over a full-line column "
        "regex, which silently matches nothing on one wrong separator. On a .jsonl file "
        "field= names a JSON key from its keys: line (nested via dots)."
    ),
    "timeline": (
        "  timeline    regex, case-insensitive. Returns when the matching lines happen: "
        "exact time span, gap statistics, and burst structure. Answers \"bursty or "
        "steady, and when\" without fetching any lines."
    ),
    "stats": (
        "  stats       regex, plus field=\"<name-or-number-or-JSON-key>\" (or a capture group) to pick "
        "the value. Returns min/median/p95/max over it -- numeric when the values are "
        "numbers (e.g. field=\"response_body_len\"), otherwise over their lengths. Answers "
        "\"how big\" without fetching any lines."
    ),
    "extremes": (
        "  extremes    regex, plus field=\"<name-or-number-or-JSON-key>\", extract=\"...\" or a capture "
        "group to pick the value, exactly as for stats. Returns the 10 matching LINES with "
        "the largest value -- numeric when the values are numbers, otherwise the longest -- "
        "each with a reference you can cite, plus where those ten sit in the whole "
        "distribution. This is the bridge from a number to its evidence: after stats says "
        "\"max request_body_len 46392\" or a tally shows 790 distinct labels, extremes hands "
        "you the lines behind the top end in one step instead of a hand-built digit-range "
        "regex. Unlike the other aggregates it DOES fetch lines (ten of them) into your "
        "record, so narrow the filter first, and mind the direction of a size column: the "
        "largest response bodies are downloads, the largest request bodies are uploads."
    ),
}

# The verbs that size a result set without fetching lines. extremes is on the menu but not
# in this list: it fetches ten lines, so "aggregate before you fetch" must not name it.
_SIZING_SKILLS = frozenset({"tally", "timeline", "stats"})

# The selectors are usable only when the commander knows the column names; those are shown
# in the files block, but only when a selector verb is on -- so this gates that display and
# keeps a run without the aggregation skills byte-for-byte as it was.
_SELECTOR_SKILLS = frozenset({"tally", "stats", "extremes"})


def investigate_system_prompt(enabled_skills: frozenset[str] = frozenset()) -> str:
    """The system prompt for the action loop, with only this run's verbs on the menu.

    Built per-run rather than a constant because the optional skills are trialled one at
    a time: describing a verb the validator would reject teaches the model a lie, and
    gpt-oss already treats the verb menu as load-bearing (see _NOT_A_TOOL_CALL).
    """
    skills = [text for name, text in _SKILL_MENU.items() if name in enabled_skills]
    skill_block = ("\n" + "\n".join(skills)) if skills else ""
    aggregate_verbs = "/".join(
        ["count"]
        + [name for name in _SKILL_MENU if name in enabled_skills and name in _SIZING_SKILLS]
    )
    return f"""{_ROLE}

{_AUTHORITY}

You are working at a terminal with direct read access to this case's log files. Each turn \
you issue exactly ONE action and are shown its result. Work like an analyst: form a \
question, ask it, look at what came back, then ask the next question.

Your actions:
  search      regex, case-insensitive. Returns the exact total match count plus up to \
{MAX_RESULTS} matching lines with their references.
  count       the same match count with no lines. Cheap. Use it to test a guess before \
spending a search on it.{skill_block}
  context     the lines surrounding one reference. Use it when a line implies a \
neighbour -- an NS record names a nameserver, and the address it resolves to is usually \
the next line.
  read_lines  a specific line range, verbatim.
  close_read  hand a line range to a worker model with one specific question. Use this \
only for questions counting cannot answer, e.g. "what do these 30 lines have in common?". \
It is slow. Most questions are not this.
  conclude    stop and write the brief.

How to work:
  - Scope before you drill. The profile's record-type section lists, per file, which \
kinds of record it holds and how many of each -- a file of Windows events is mostly \
event_id 4624 (a logon), 4688 (a process starting), and so on. Different facts live in \
different record kinds: who logged on is in one, what they ran is in another, what a \
process touched is in a third. Read that section first, and before you conclude, account \
for the record kinds the alert did NOT point you at -- the alert names one line; the \
answer is usually in a kind of record it never mentions. A `tally field="<name>"` over \
one of those fields is one step and turns a guessed regex into an exact distribution.
  - Aggregate before you fetch. Lines are your scarce resource: every line a search \
returns stays in your working record for the rest of the run, and a broad search fills \
that space with neighbourhood instead of answers. Numbers are nearly free. Before any \
search you expect to match more than a handful of lines, size it with {aggregate_verbs}; \
then narrow the pattern until the lines you fetch are the ones that settle the question. \
A result reading "showing the first {MAX_RESULTS} of 700" means the question was too \
broad -- aggregate the 700 down to the discriminating value, then fetch that.
  - On a structured log (JSON lines, or a #fields table), pin a record by FIELD, not by \
key order. `where=["event_id=10","computer=WKS-3355"]` on search/count/context matches \
those fields wherever they sit in the line; a regex that lists "key":"value" pairs in \
sequence silently returns nothing when the record orders its keys differently. Name the \
fields exactly as the record-type scope / keys line above spells them. Four operators: \
`=` equals, `!=` not-equal, `~` the field's value matches this regex, `!~` it does not -- \
so `where=["event_id=10","TargetImage~lsass","SourceImage!~MsMpEng"]` finds lsass access \
that is NOT the antivirus, in one step.
  - The profile below is computed, not inferred: every number in it is arithmetic over \
the corpus and can be re-derived with grep. Trust it and start from it. Read the record-type scope of each file first to learn its vocabulary. The rare shapes \
and the entropy groups are there because they are where the answer usually is.
  - Establish quantities before narrative. "788 of 5,586 queries, from one host" is worth \
more to an operator than any adjective.
  - Anchor on what a count can settle. If you can distinguish two explanations with a \
count, do that before you reason about which is more likely.
  - Look for what the alert did NOT already tell you: which host, which user, what the \
answers contained, what the timing looks like, what the domain resolves to, what else \
that address or domain touches. Restating the alert is not investigation.
  - A benign lookalike is the expensive mistake here. Encoded-looking labels are also \
produced by antivirus reputation lookups, CDN cache keys and DKIM records. Before \
concluding a shape is malicious, check how many distinct hosts emit it -- one host is a \
finding, forty hosts is a vendor service.
  - Deliberately try to break your leading explanation. A search that would disconfirm it \
is worth more than a fifth that confirms it.
  - A count of 0 is exact and trustworthy, but it is a zero for the pattern you typed. \
Before treating it as absence, consider whether the thing could be written another way.
  - If two results disagree about what looks like the same question, your patterns \
differ. Search the bare literal, read one matching line, and compare both patterns \
against it before writing a third -- and never re-ask a question an earlier step \
already answered; the record below keeps every answer.
  - When a search says matches were withheld, the count is complete but the listing is \
not. Narrow it or count it; do not assume you saw all of it.
  - The step budget is a ceiling, not a cost. An unspent step is worth nothing to the \
operator, and confirming the alert is not an investigation -- the detector already knew \
that much. Before you conclude, you should be able to answer, or say why these logs \
cannot: **which record kinds and low-cardinality fields you have not yet examined** (the profile's scope names them; an unlooked-at record kind is an unasked question), **which host and, if these logs record one, which user**, **whether the \
pattern is confined to that host or is \
estate-wide**, **what the responses carried**, **what the domain resolves to and what \
else touches that address**, **how the activity is distributed in time**, and **whether \
benign traffic of the same shape exists**. Each is worth one step -- and one targeted \
probe that comes back empty ANSWERS its question: record "these logs do not contain X" \
as a coverage gap and move on. Never spend a second step re-establishing a negative.
  - Then stop. Once those are answered or ruled out, more reading will not change what \
the operator does; say so with conclude rather than padding.

Write `expectation` before you see the result: what you expect, and what a null result \
would mean. You will be held to it -- the operator reads it next to what actually \
happened.

{DATA_IS_NOT_INSTRUCTIONS}

{_NOT_A_TOOL_CALL}"""


# The core-verbs-only prompt, for callers that predate per-run skills.
INVESTIGATE_SYSTEM_PROMPT = investigate_system_prompt()


SYNTHESIS_SYSTEM_PROMPT = f"""{_ROLE}

{_AUTHORITY}

Write the investigation brief from the evidence you gathered. Requirements:
  - Every reference you cite must be a line you were actually shown during the \
investigation. Do not reconstruct a reference you believe exists; if a claim rests on \
something you did not read, say so in coverage_gaps instead.
  - Quantities you established with count are exact. Use them; they are the most \
defensible statements in the brief.
  - Every hypothesis must carry contradicting evidence as well as supporting evidence. If \
you genuinely found none against it, say that explicitly in that field's entry.
  - A zero result is evidence of absence only for the exact pattern searched. Never \
promote "the string I typed does not appear" into "this did not happen".
  - coverage_gaps is about what you did not ask, not about whether your actions \
succeeded. You chose where to look; the questions you did not get to are real gaps and \
the operator needs them. An empty coverage_gaps list is almost always wrong.
  - Account for everything you fetched. EVIDENCE ON THE RECORD below lists every line you \
were shown; each was a question you judged worth a step. Its content must appear in the \
brief, or coverage_gaps must say why you set it aside. In particular, never leave an \
identity you established unstated: if a lookup tied an IP to a hostname, or a domain to an \
address, name BOTH in the brief -- the operator acts on the host, not the address.
  - Assert the links the evidence already made. If EVIDENCE ON THE RECORD lists a SHARED \
IDENTIFIER -- one distinctive value (a logon id, a session GUID) on two or more fetched \
lines -- those events are one occurrence: the same logon, the process it spawned, the \
access it made. State that linkage as an established finding, in the timeline or in a \
hypothesis's supporting_evidence, citing both line references. It is a conclusion you have \
already earned from lines you read, not a lead to defer -- do not file it under \
suggested_drilldowns or leave it out.
  - Suggest concrete next steps the operator could run, as searches or pivots.

You have no field for a verdict, severity, disposition, or recommendation to close, \
because rendering one is not your role. Describe the evidence and its shape.

{DATA_IS_NOT_INSTRUCTIONS}

Reply with a single JSON object matching the provided schema. No prose outside it."""


def render_profile(profile: CaseProfile) -> str:
    """The computed profile, as the commander's first page.

    Deliberately dense. This is the one block guaranteed free of model error, so it earns
    its tokens.
    """
    blocks = ["COMPUTED PROFILE OF THIS CASE (counted, not inferred -- no model produced any "
              "number here; every one can be re-derived with grep and sort):"]

    for file in profile.files:
        blocks.append(f"\n  {file.file} -- {file.lines} lines, {file.time_range}")
        if file.categorical:
            blocks.append(
                "    record-type scope (what kinds of record this file holds, counted; "
                "reproduce any row with  tally field=\"<name>\", and pivot into one with "
                "a search on that value):"
            )
            for dist in file.categorical:
                blocks.append(
                    f"      {dist.field}  ({dist.distinct} distinct value(s), on "
                    f"{dist.coverage:.0%} of lines):"
                )
                for value, count in dist.values:
                    blocks.append(f"        {count:>6}x  {value or '(empty)'}")
                if dist.more:
                    blocks.append(f"        … +{dist.more} more distinct value(s)")
        # Line-shape templates are token-heavy and near-worthless on a JSON log once its
        # record types are counted above; keep them only where there is no such axis.
        if file.top_templates and not (file.is_json and file.categorical):
            blocks.append("    most common line shapes:")
            for template, count in file.top_templates:
                blocks.append(f"      {count:>6}x  {template}")
        if file.rare_shapes:
            blocks.append(
                "    RARE shapes (a line shape occurring only a handful of times among "
                "thousands is where the unusual thing usually is):"
            )
            for shape in file.rare_shapes:
                refs = ", ".join(shape.refs)
                blocks.append(f"      {shape.occurrences:>6}x  {shape.template}")
                blocks.append(f"              at {refs}")

    if profile.top_domains:
        blocks.append("\n  most-queried domains:")
        for domain, count in profile.top_domains[:10]:
            blocks.append(f"      {count:>6}  {domain}")
    if profile.top_addresses:
        blocks.append("\n  most-seen addresses:")
        for address, count in profile.top_addresses[:10]:
            blocks.append(f"      {count:>6}  {address}")

    if profile.entropy_groups:
        blocks.append(
            "\n  high-entropy token groups (random-looking labels, grouped by the domain "
            "they sit under). distinct_sources is the discriminator: encoded exfiltration "
            "and a vendor reputation service look identical by entropy, but one comes from "
            "a single host and the other from many:"
        )
        for group in profile.entropy_groups:
            blocks.append(
                f"      {group.suffix}: {group.occurrences} occurrence(s), "
                f"mean entropy {group.mean_entropy}, mean length {group.mean_length}, "
                f"from {group.distinct_sources} distinct source(s) {group.sources}"
            )
            blocks.append(f"        e.g. {', '.join(group.example_refs)}")

    if profile.bursts:
        blocks.append(
            f"\n  activity bursts for {profile.burst_subject} (contiguous clusters "
            "separated by idle gaps -- bursty and periodic are different signatures):"
        )
        for burst in profile.bursts:
            blocks.append(f"      {burst.start} .. {burst.end}   {burst.events} events")

    return "\n".join(blocks)


def _files_block(
    names: list[str],
    line_counts: dict[str, int],
    field_headers: dict[str, list[str]] | None = None,
    json_files: frozenset[str] = frozenset(),
) -> str:
    field_headers = field_headers or {}
    rows: list[str] = []
    for name in names:
        rows.append(f"  {name}: {line_counts.get(name, 0)} lines")
        fields = field_headers.get(name)
        if fields:
            # The column names the field= selector references. Shown only when a selector
            # skill is on (the caller decides), so a run without them is unchanged. A
            # JSON-lines file has keys rather than columns, and says so.
            label = "keys (JSON lines)" if name in json_files else "fields"
            rows.append(f"      {label}: {', '.join(fields)}")
    return "LOG FILES YOU CAN SEARCH (use these names exactly):\n" + "\n".join(rows)


def build_investigate_messages(
    *,
    alert: Alert,
    profile: CaseProfile,
    evidence: Evidence,
    file_names: list[str],
    line_counts: dict[str, int],
    steps_remaining: int,
    enabled_skills: frozenset[str] = frozenset(),
    field_headers: dict[str, list[str]] | None = None,
    json_files: frozenset[str] = frozenset(),
) -> list[dict[str, str]]:
    # Field names are only useful, and only shown, when a selector skill is available.
    shown_headers = field_headers if (enabled_skills & _SELECTOR_SKILLS) else None
    budget = (
        f"You have {steps_remaining} action(s) left before the investigation is cut off "
        "and the brief is written from what you have. They cost the operator nothing if "
        "unused, so spend them on what the alert did not already tell you."
        if steps_remaining > 3
        else (
            f"ONLY {steps_remaining} action(s) remain. Use them on the single most "
            "important open question, or conclude now if the brief would not change."
        )
    )
    user = "\n\n".join(
        [
            "ALERT",
            fence_alert(alert),
            _files_block(file_names, line_counts, shown_headers, json_files),
            render_profile(profile),
            "INVESTIGATION SO FAR",
            evidence.render(),
            budget,
            "Issue your next action.",
        ]
    )
    return [
        {"role": "system", "content": investigate_system_prompt(enabled_skills)},
        {"role": "user", "content": user},
    ]


def build_action_retry_messages(
    base: list[dict[str, str]], previous_output: str, problems: list[ActionProblem]
) -> list[dict[str, str]]:
    listed = "\n".join(f"  - {p.field}: {p.message}" for p in problems)
    return base + [
        {"role": "assistant", "content": previous_output},
        {
            "role": "user",
            "content": (
                "That action could not be executed:\n"
                f"{listed}\n\nIssue a corrected action."
            ),
        },
    ]


# Characters the fetched-lines recap may spend. Big enough to hold every citable line of a
# normal run flat and uncollapsed; a runaway is truncated with the count said out loud.
# Sized for a run that used extremes: one such step puts ten ~240-char rows here (~2.4k),
# and at 5_000 two of them pushed every later search's lines into "not repeated here".
_ON_RECORD_BUDGET_CHARS = 8_000


_GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_HEXISH = re.compile(r"^(?:0[xX])?[0-9a-fA-F]+$")
_SHARED_IDS_SHOWN = 5
_SHARED_REFS_PER_ID = 6


def _value_text(text: str) -> str:
    """The scannable content of a fetched line: for a JSON object, only its values
    (recursively), space-joined, so key names are not mistaken for identifiers; for any
    other line, the text unchanged."""
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return text
    out: list[str] = []
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
        elif cur is not None and not isinstance(cur, bool):
            out.append(str(cur))
    return " ".join(out)


def _distinctive(token: str) -> bool:
    """Is this token an identifier worth reporting as a cross-event link?

    A decimal is a count or an epoch, not an id. A hex run (with or without 0x) is an
    access mask or a logon id. Otherwise it must look random (entropy) or be long. The
    `_ID_CANDIDATE` class already splits on '-'/'_' and '.', so IPs, dashed hostnames
    (WKS-3355) and underscore accounts (svc_deploy) never reach here -- only the values
    that actually tie two events together do.
    """
    if token.isdigit():
        return False
    if _HEXISH.match(token):
        return True
    return _entropy(token) >= 3.2 or len(token) >= 12


def _shared_identifiers(evidence: Evidence) -> list[str]:
    """Distinctive tokens that appear on >=2 fetched lines, as cross-event links.

    The commander hand-picked every fetched line, so a distinctive value shared by two of
    them usually means those events are one thing -- a logon and the process it spawned
    carrying the same logon id, say. Surfacing it hands synthesis the join it keeps
    dropping. Iterates all fetched lines regardless of the render budget -- a link can sit
    on a line the row budget elided.
    """
    by_token: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()
    for step in evidence.steps:
        for hit in step.lines:
            # On a JSON line, scan the VALUES only -- the key names (computer,
            # TokenElevationType, ...) are structure shared by every line, not evidence.
            scanned = _value_text(hit.text)
            tokens = set(_GUID.findall(scanned))
            tokens |= {t for t in _ID_CANDIDATE.findall(scanned) if _distinctive(t)}
            for token in tokens:
                if _looks_like_domain(token.split(".")):
                    continue
                if (token, hit.ref) in seen:
                    continue
                seen.add((token, hit.ref))
                by_token.setdefault(token, []).append(hit.ref)
    shared = [(t, refs) for t, refs in by_token.items() if len(refs) >= 2]
    shared.sort(key=lambda tr: (-len(tr[1]), -len(tr[0])))
    return [
        f"    {token} on {', '.join(refs[:_SHARED_REFS_PER_ID])}"
        for token, refs in shared[:_SHARED_IDS_SHOWN]
    ]


def _evidence_on_record(evidence: Evidence) -> str:
    """A flat, uncollapsed index of every line the commander fetched, for synthesis.

    This exists because of a specific failure: a run searched dhcp.log, was shown the two
    lease lines that name the host, and wrote a brief that never mentioned the hostname.
    The line was in the collapsed ledger -- the model saw it and dropped it anyway -- so
    re-presenting the text is not enough on its own; it is paired with a synthesis
    requirement to reconcile against this list. Every fetched line was a question the
    commander judged worth a step, so it is either in the brief or named in coverage_gaps.

    Only steps that fetched real lines appear (search/context/read_lines/close_read, and
    extremes, whose ranked rows are real lines with references). The number-only
    aggregates carry no citable lines and are already emphasised in the ledger.
    """
    rows: list[str] = []
    spent = 0
    omitted = 0
    for step in evidence.steps:
        if not step.lines:
            continue
        header = f"  step {step.index} -- {_headline(step)} ({step.action.reasoning}):"
        rows.append(header)
        spent += len(header)
        for hit in step.lines:
            if spent > _ON_RECORD_BUDGET_CHARS:
                omitted += 1
                continue
            entry = f"    {hit.ref}  {elide(hit.text, 200)}"
            rows.append(entry)
            spent += len(entry)
    if not rows:
        return ""
    if omitted:
        rows.append(
            f"  ... {omitted} further fetched line(s) not repeated here; they are in the "
            f"ledger above and remain on the record."
        )
    links = _shared_identifiers(evidence)
    if links:
        rows.append(
            "  SHARED IDENTIFIERS across the lines you fetched (a distinctive value on "
            "several fetched lines usually ties those events into one -- a logon and the "
            "process it spawned, say; state the link in the brief or rule it out):"
        )
        rows.extend(links)
    return (
        "EVIDENCE ON THE RECORD (every line you fetched during the investigation -- each "
        "was worth a step, so each must appear in the brief or be set aside in "
        "coverage_gaps with a reason):\n" + "\n".join(rows)
    )


def build_synthesis_messages(
    *,
    alert: Alert,
    profile: CaseProfile,
    evidence: Evidence,
    coverage_note: str,
) -> list[dict[str, str]]:
    user = "\n\n".join(
        block for block in [
            "SYNTHESIS",
            "ALERT",
            fence_alert(alert),
            render_profile(profile),
            "THE INVESTIGATION YOU RAN",
            evidence.render(),
            _evidence_on_record(evidence),
            coverage_note,
            "Write the investigation brief now.",
        ] if block
    )
    return [
        {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]
