"""The aggregation skills: numbers about a pattern's matches, without fetching lines.

The property under test is the same one profiling.py lives by: everything is counted,
nothing is inferred, a zero from a wrong pattern must not read as absence, and nothing a
number-only aggregate (tally/timeline/stats) produces can ever enter shown_refs() -- a
number is not a citation. `extremes` is the deliberate exception and is tested as one:
its rows ARE lines, with references, and they must be citable.
"""

from __future__ import annotations

import pytest

from soc_poc.actions import execute_readonly, reproduce_command
from soc_poc.aggregation import EXTREMES_SHOWN, extremes, stats, tally, timeline
from soc_poc.coercion import coerce_action_payload
from soc_poc.config import RunConfig
from soc_poc.corpus import Corpus
from soc_poc.evidence import STEPS_RENDERED_IN_FULL, Evidence
from soc_poc.prompting.investigate import investigate_system_prompt
from soc_poc.schemas.action import ActionKind, InvestigativeAction, validate_action


def _action(kind: ActionKind, **kwargs) -> InvestigativeAction:
    return InvestigativeAction(
        reasoning="because", expectation="something or nothing", action=kind, **kwargs
    )


@pytest.fixture
def corpus() -> Corpus:
    """Three hosts querying one domain unevenly, with epoch timestamps in two bursts."""
    lines = []
    base = 1_700_000_000
    for index in range(20):
        # Two 10-event bursts separated by ~3 hours; 1 s inside a burst.
        stamp = base + index if index < 10 else base + 10_000 + index
        host = "10.0.0.5" if index < 17 else ("10.0.0.6" if index < 19 else "10.0.0.7")
        lines.append(f"{stamp}.000\t{host}\tquery lbl{index:02d}.tunnel.example\tbytes={index * 10}")
    return Corpus({"dns.log": lines, "dhcp.log": ["ACK 10.0.0.5 wks-2291"]})


# --- tally ----------------------------------------------------------------------------


def test_tally_counts_distinct_values_of_a_capture_group(corpus: Corpus) -> None:
    result = tally(corpus, r"\t(10\.0\.0\.\d+)\t", file="dns.log")
    assert result.error == ""
    assert result.matched_lines == 20
    assert "3 distinct value(s)" in result.headline
    # Exact counts, dominant first -- the distribution in one step.
    assert any("17x" in row and "10.0.0.5" in row for row in result.table)
    assert any("1x" in row and "10.0.0.7" in row for row in result.table)


def test_tally_without_a_group_counts_whole_matches(corpus: Corpus) -> None:
    result = tally(corpus, r"wks-\d+", file="dhcp.log")
    assert result.matched_lines == 1
    assert any("wks-2291" in row for row in result.table)


def test_tally_shows_both_ends_of_a_wide_distribution() -> None:
    """Top values say what dominates; the rarest say what is unusual. The middle is
    summarised as a count, never silently dropped -- a tally that hid the rare end would
    bury exactly the kind of outlier this codebase exists to surface."""
    corpus = Corpus(
        {"a.log": [f"host-{n:03}" for n in range(30) for _ in range(30 - n)]}
    )
    result = tally(corpus, r"host-\d+")
    listed = "\n".join(result.table)
    assert "host-000" in listed  # most common
    assert "host-029" in listed  # rarest
    assert "further distinct value(s) not listed" in listed
    assert "rarest" in listed


def test_tally_failures_are_values(corpus: Corpus) -> None:
    assert "bad regex" in tally(corpus, "a[", file="dns.log").error
    assert "no such file" in tally(corpus, "x", file="nope.log").error


# --- timeline -------------------------------------------------------------------------


def test_timeline_finds_burst_structure(corpus: Corpus) -> None:
    result = timeline(corpus, r"tunnel\.example", file="dns.log")
    assert result.error == ""
    assert result.matched_lines == 20
    assert "20 with a recognisable timestamp" in result.headline
    listed = "\n".join(result.table)
    assert "2 burst(s)" in listed
    assert listed.count("10 event(s)") == 2
    assert "median 1.0s" in listed


def test_timeline_reports_steady_activity_as_not_bursty() -> None:
    corpus = Corpus(
        {"a.log": [f"{1_700_000_000 + n * 60}.000\tbeacon" for n in range(20)]}
    )
    listed = "\n".join(timeline(corpus, "beacon").table)
    assert "not bursty" in listed


def test_timeline_with_no_timestamps_says_so() -> None:
    corpus = Corpus({"a.log": ["hello", "hello again"]})
    result = timeline(corpus, "hello")
    assert result.matched_lines == 2
    assert "0 with a recognisable timestamp" in result.headline
    assert "not enough timestamps" in "\n".join(result.table)


def test_timeline_zero_matches_reads_as_a_result(corpus: Corpus) -> None:
    assert "does not occur" in timeline(corpus, "nonesuch", file="dns.log").headline


# --- stats ----------------------------------------------------------------------------


def test_stats_is_numeric_when_every_value_is_a_number(corpus: Corpus) -> None:
    result = stats(corpus, r"bytes=(\d+)", file="dns.log")
    listed = "\n".join(result.table)
    assert "numeric values" in listed
    assert "min 0" in listed and "max 190" in listed and "sum 1900" in listed


def test_stats_falls_back_to_lengths_and_says_so(corpus: Corpus) -> None:
    result = stats(corpus, r"(lbl\d+)\.tunnel", file="dns.log")
    listed = "\n".join(result.table)
    # Every label is "lblNN" -- 5 characters -- and the mode is stated, not implied.
    assert "lengths" in listed
    assert "min 5" in listed and "max 5" in listed


# --- as actions -----------------------------------------------------------------------


def test_an_aggregate_step_carries_a_table_and_no_lines(corpus: Corpus) -> None:
    """A number is not a citation. Nothing an aggregate returns may enter shown_refs()."""
    step = execute_readonly(
        _action(ActionKind.TALLY, pattern=r"(10\.0\.0\.\d+)", file="dns.log"),
        corpus,
        index=1,
    )
    assert step.lines == ()
    assert step.table
    assert step.total_matches == 20
    evidence = Evidence()
    evidence.add(step)
    assert evidence.shown_refs() == set()


def test_an_aggregate_zero_gets_the_pattern_or_data_hint(corpus: Corpus) -> None:
    """The tally variant of the run-6 lesson: a zero from a broken pattern must say it
    is about the pattern, not the data, before it becomes contradicting evidence."""
    step = execute_readonly(
        _action(ActionKind.TALLY, pattern=r"bytes=\d+\ttunnel\.example", file="dns.log"),
        corpus,
        index=1,
    )
    assert step.total_matches == 0
    assert "about your PATTERN" in step.summary


def test_aggregate_tables_survive_ledger_collapse(corpus: Corpus) -> None:
    """The whole point of an aggregate is that its numbers keep being true. Ageing a
    tally out of the window and dropping its table would re-create the loop that
    evidence.py documents, one distribution at a time."""
    evidence = Evidence()
    evidence.add(
        execute_readonly(
            _action(ActionKind.TALLY, pattern=r"(10\.0\.0\.\d+)", file="dns.log"),
            corpus,
            index=1,
        )
    )
    for index in range(2, STEPS_RENDERED_IN_FULL + 3):
        evidence.add(
            execute_readonly(
                _action(ActionKind.COUNT, pattern="query", file="dns.log"),
                corpus,
                index=index,
            )
        )
    rendered = evidence.render()
    earlier = rendered.split("RECENT STEPS")[0]
    assert "10.0.0.7" in earlier  # the rare host is still visible after collapse


def test_reproduce_commands_for_aggregates() -> None:
    plain = reproduce_command(_action(ActionKind.TALLY, pattern=r"wks-\d+", file="dhcp.log"))
    assert plain.startswith("grep -hoiE") and "| sort | uniq -c | sort -rn" in plain
    assert "sed" not in plain  # no capture group, nothing to reduce
    grouped = reproduce_command(_action(ActionKind.TALLY, pattern=r"ACK (\S+)"))
    assert "sed -E" in grouped
    timed = reproduce_command(_action(ActionKind.TIMELINE, pattern="tunnel"))
    assert "grep -oE" in timed and "uniq -c" in timed
    sized = reproduce_command(_action(ActionKind.STATS, pattern=r"bytes=(\d+)"))
    assert "sort -n" in sized


# --- gating ---------------------------------------------------------------------------


def test_a_disabled_skill_is_rejected_with_a_redirect() -> None:
    problems = validate_action(
        _action(ActionKind.TALLY, pattern="x"),
        known_files=["dns.log"],
        enabled_skills=frozenset(),
    )
    assert any("not available in this run" in p.message for p in problems)


def test_an_enabled_skill_passes_and_still_needs_its_pattern() -> None:
    assert (
        validate_action(
            _action(ActionKind.TALLY, pattern="x"),
            known_files=["dns.log"],
            enabled_skills=frozenset({"tally"}),
        )
        == []
    )
    problems = validate_action(
        _action(ActionKind.TALLY),
        known_files=["dns.log"],
        enabled_skills=frozenset({"tally"}),
    )
    assert any(p.field == "pattern" for p in problems)


def test_no_gate_means_everything_is_available() -> None:
    """Library use and older tests pass no gate; that must keep meaning 'all verbs'."""
    assert (
        validate_action(_action(ActionKind.STATS, pattern="x"), known_files=["dns.log"])
        == []
    )


def test_the_prompt_menu_matches_the_gate() -> None:
    """Describing a verb the validator would reject teaches the model a lie; omitting an
    enabled one hides a paid-for capability. Menu and gate must agree exactly."""
    without = investigate_system_prompt(frozenset())
    assert "tally  " not in without and "timeline  " not in without
    with_tally = investigate_system_prompt(frozenset({"tally"}))
    assert "tally  " in with_tally and "timeline  " not in with_tally
    # The discipline the skills exist to serve is stated regardless of which are on.
    assert "Aggregate before you fetch" in without
    assert "count/tally" in with_tally and "count/tally" not in without


def test_config_rejects_an_unknown_skill_name() -> None:
    with pytest.raises(Exception, match="unknown skill"):
        RunConfig(enabled_skills=("tallly",))
    assert RunConfig(enabled_skills=("tally", "stats")).enabled_skills == ("tally", "stats")


def test_a_tool_call_shaped_tally_is_coerced() -> None:
    coerced = coerce_action_payload({"action": "tally", "action_input": r"(10\.0\.0\.\d+)"})
    assert coerced is not None
    assert coerced["pattern"] == r"(10\.0\.0\.\d+)"


# --- loop-breaking: coverage hints and same-literal cross-references -------------------
#
# Pinned against run inv-20260825T103734Z-f66a, which spent 8 of 24 steps re-asking
# "which hosts query this domain" with regex variants that shared one anchor literal:
# six over-anchored to zero, two matching only the bare-domain line and answering
# "1x" against a true 788x. The zero hint fired six times and was ignored six times;
# the 1x results carried no hint at all. These tests pin the two mechanisms that make
# a failed re-ask carry its own refutation.


@pytest.fixture
def anchored_corpus() -> Corpus:
    """Ten label-prefixed queries and one bare-domain line, dns-tunnel-shaped: the
    character before `t.example-domain.net` is a dot on 10 of 11 lines, so a pattern
    anchored `\\tt\\.` matches exactly one line while the literal occurs on eleven."""
    lines = [f"{n}\tlbl{n}.t.example-domain.net\tTXT" for n in range(10)]
    lines.append("10\tt.example-domain.net\tNS")
    return Corpus({"dns.log": lines, "other.log": ["t.example-domain.net elsewhere"]})


def test_partial_coverage_carries_its_own_refutation(anchored_corpus: Corpus) -> None:
    """The 1x-vs-788x failure: not zero, so the zero hint stayed silent, and a wrong
    small number entered the ledger unchallenged."""
    step = execute_readonly(
        _action(ActionKind.TALLY, pattern=r"^(\d+)\tt\.example-domain\.net", file="dns.log"),
        anchored_corpus,
        index=1,
    )
    assert step.total_matches == 1
    assert "matched 1 of the 11 line(s)" in step.summary
    assert "over-anchored" in step.summary


def test_full_coverage_gets_no_hint(anchored_corpus: Corpus) -> None:
    step = execute_readonly(
        _action(ActionKind.TALLY, pattern=r"(\d+)\t.*t\.example-domain\.net", file="dns.log"),
        anchored_corpus,
        index=1,
    )
    assert step.total_matches == 11
    assert "over-anchored" not in step.summary


def test_deliberate_moderate_narrowing_stays_silent(anchored_corpus: Corpus) -> None:
    """A warning printed on every narrowing is a warning nobody reads. 6 of 10 lines
    containing the literal is a deliberate subset, not a broken pattern."""
    step = execute_readonly(
        _action(
            ActionKind.TALLY,
            pattern=r"lbl([0-5])\.t\.example-domain\.net",
            file="dns.log",
        ),
        anchored_corpus,
        index=1,
    )
    assert step.total_matches == 6
    assert "over-anchored" not in step.summary


def _evidence_with(corpus: Corpus, *actions: InvestigativeAction):
    from soc_poc.evidence import Evidence

    evidence = Evidence()
    for action in actions:
        evidence.add(execute_readonly(action, corpus, index=evidence.next_index))
    return evidence


_BROKEN = r"^\d+\t\S+\tudp\t.*\s+t\.example-domain\.net"  # \s+ before t. cannot match
_LOOSE = r"^(\d+)\t.*\bt\.example-domain\.net"


def test_precedent_is_found_by_literal_not_by_pattern(anchored_corpus: Corpus) -> None:
    from soc_poc.orchestrator import same_literal_precedent

    evidence = _evidence_with(
        anchored_corpus,
        _action(ActionKind.TALLY, pattern=_BROKEN, file="dns.log"),
        _action(ActionKind.TALLY, pattern=_LOOSE, file="dns.log"),
    )
    retry = _action(ActionKind.TALLY, pattern=_BROKEN + r"\t", file="dns.log")
    precedent = same_literal_precedent(evidence, retry)
    assert precedent is not None and precedent.index == 2  # the step that answered

    # A different file, or a different literal, is a different question.
    assert same_literal_precedent(
        evidence, _action(ActionKind.TALLY, pattern=_BROKEN, file="other.log")
    ) is None
    assert same_literal_precedent(
        evidence, _action(ActionKind.TALLY, pattern=r"unrelated-literal-here", file="dns.log")
    ) is None


def test_a_failed_reask_names_the_step_that_answered(anchored_corpus: Corpus) -> None:
    from soc_poc.orchestrator import same_literal_note

    evidence = _evidence_with(
        anchored_corpus,
        _action(ActionKind.TALLY, pattern=_LOOSE, file="dns.log"),
    )
    retry = _action(ActionKind.TALLY, pattern=_BROKEN, file="dns.log")
    step = execute_readonly(retry, anchored_corpus, index=2)
    assert step.total_matches == 0
    note = same_literal_note(evidence, retry, step)
    assert "step 1 anchored on the same literal" in note
    assert "11 occurrence(s)" in note  # the precedent's answer, inline


def test_the_third_zero_attempt_is_told_to_stop(anchored_corpus: Corpus) -> None:
    from soc_poc.orchestrator import same_literal_note

    evidence = _evidence_with(
        anchored_corpus,
        _action(ActionKind.TALLY, pattern=_BROKEN, file="dns.log"),
        _action(ActionKind.TALLY, pattern=_BROKEN + r"$", file="dns.log"),
        _action(ActionKind.TALLY, pattern=_LOOSE, file="dns.log"),
    )
    retry = _action(ActionKind.COUNT, pattern=_BROKEN + r"\S*", file="dns.log")
    step = execute_readonly(retry, anchored_corpus, index=4)
    note = same_literal_note(evidence, retry, step)
    assert "attempt #3" in note
    assert "use step 3's answer" in note
    assert "Stop varying the frame" in note


def test_a_successful_step_gets_no_note(anchored_corpus: Corpus) -> None:
    from soc_poc.orchestrator import same_literal_note

    evidence = _evidence_with(
        anchored_corpus,
        _action(ActionKind.TALLY, pattern=_BROKEN, file="dns.log"),
    )
    good = _action(ActionKind.TALLY, pattern=_LOOSE, file="dns.log")
    step = execute_readonly(good, anchored_corpus, index=2)
    assert same_literal_note(evidence, good, step) == ""


def test_checklist_wording_admits_absent_facts() -> None:
    prompt = investigate_system_prompt(frozenset({"tally"}))
    assert "if these logs record one, which user" in prompt
    assert "Never spend a second step re-establishing a negative" in prompt
    assert "never re-ask a question an earlier step" in prompt
    gate = validate_action(
        _action(ActionKind.CONCLUDE), known_files=["dns.log"], steps_taken=1, min_steps=6
    )
    assert "counts as answered" in gate[0].message
    # The tokens older tests and graded-run notes rely on are preserved.
    assert "estate-wide" in gate[0].message and "RESPONSES" in gate[0].message


# --- exact zero diagnosis: order vs glue ----------------------------------------------
#
# Pinned against run inv-20260825T105718Z-2833: eight count steps wrote TXT-then-domain
# patterns against a format that puts the query before the qtype -- reading real lines
# between attempts and re-emitting the wrong order anyway. "Check field order" was not
# enough; the hint now states which of the two possible mistakes was made, counted.


@pytest.fixture
def zeek_corpus() -> Corpus:
    return Corpus(
        {
            "dns.log": [
                f"17000{n}\tuid{n}\t10.0.0.5\tlbl{n}.domain-example.net\t16\tTXT\t0\tNOERROR"
                for n in range(10)
            ]
        }
    )


def test_a_wrong_order_zero_names_the_swap(zeek_corpus: Corpus) -> None:
    step = execute_readonly(
        _action(ActionKind.COUNT, pattern=r"\tTXT\t.*domain-example\.net", file="dns.log"),
        zeek_corpus,
        index=1,
    )
    assert step.total_matches == 0
    assert "about your PATTERN, not about the data" in step.summary
    assert "NOT in the order" in step.summary and "Swap" in step.summary


def test_a_wrong_glue_zero_says_loosen_between(zeek_corpus: Corpus) -> None:
    """Anchors in the right order, wrong fields between them: the third failure shape
    (step 23 of the same run), previously silent because no single literal was long
    enough to probe."""
    step = execute_readonly(
        _action(
            ActionKind.COUNT, pattern=r"domain-example\.net\tTXT", file="dns.log"
        ),
        zeek_corpus,
        index=1,
    )
    assert step.total_matches == 0
    assert "occur in this order" in step.summary
    assert "BETWEEN" in step.summary


def test_a_genuine_zero_still_stands_with_multiple_anchors(zeek_corpus: Corpus) -> None:
    step = execute_readonly(
        _action(ActionKind.COUNT, pattern=r"\tMX\t.*absent-domain\.example", file="dns.log"),
        zeek_corpus,
        index=1,
    )
    assert "NOTE" not in step.summary


def test_a_tiny_count_is_nudged_toward_fetching(zeek_corpus: Corpus) -> None:
    """A count of 1 is usually the rare, decisive line -- and a count cannot be cited.
    The same run counted the attacker nameserver twice and never fetched it, so the
    brief could not cite the strongest evidence in the case."""
    one = execute_readonly(
        _action(ActionKind.COUNT, pattern=r"lbl3\.domain-example\.net", file="dns.log"),
        zeek_corpus,
        index=1,
    )
    assert one.total_matches == 1
    assert "few enough to read" in one.summary
    many = execute_readonly(
        _action(ActionKind.COUNT, pattern=r"domain-example\.net", file="dns.log"),
        zeek_corpus,
        index=1,
    )
    assert many.total_matches == 10
    assert "few enough" not in many.summary


def test_two_short_anchors_are_still_diagnosable(zeek_corpus: Corpus) -> None:
    """No single literal reaches the 8-char probe floor, but two anchors that must share
    a line are already specific. Step 23 of run 2833 was this shape and got silence."""
    step = execute_readonly(
        _action(ActionKind.COUNT, pattern=r"\tTXT\t9\tNOERROR", file="dns.log"),
        zeek_corpus,
        index=1,
    )
    assert step.total_matches == 0
    assert "occur in this order" in step.summary and "BETWEEN" in step.summary


# --- value selectors: field= and extract= ---------------------------------------------
#
# The point of the selectors is to kill the column-counting regex loop: the pattern only
# has to MATCH the line, and field=/extract= pick the value exactly. See aggregation._extract.


@pytest.fixture
def zeek_http() -> Corpus:
    """A tiny Zeek http.log with a real #fields header, for column selection."""
    lines = [
        "#separator \\x09",
        "#fields\tts\tid.orig_h\tmethod\thost\tuser_agent\tresponse_body_len",
        "#types\ttime\taddr\tstring\tstring\tstring\tcount",
        "1\t10.0.0.5\tGET\tevil.example\tMSIE-8\t40",
        "2\t10.0.0.5\tPOST\tevil.example\tMSIE-8\t5000",
        "3\t10.0.0.6\tGET\tgood.example\tChrome\t120",
    ]
    return Corpus({"http.log": lines})


def test_field_by_name_selects_the_column(zeek_http: Corpus) -> None:
    r = tally(zeek_http, r"evil\.example", file="http.log", field="method")
    assert r.matched_lines == 2
    assert any("1x" in row and "GET" in row for row in r.table)
    assert any("1x" in row and "POST" in row for row in r.table)


def test_field_by_number_is_one_based(zeek_http: Corpus) -> None:
    # Column 3 is 'method' (1-based over data columns).
    r = tally(zeek_http, r"evil", file="http.log", field="3")
    assert any("GET" in row for row in r.table) and any("POST" in row for row in r.table)


def test_field_stats_reads_a_numeric_column(zeek_http: Corpus) -> None:
    r = stats(zeek_http, r"evil", file="http.log", field="response_body_len")
    listed = "\n".join(r.table)
    assert "numeric values" in listed and "max 5000" in listed and "sum 5040" in listed


def test_a_bad_field_name_lists_the_available_ones(zeek_http: Corpus) -> None:
    r = tally(zeek_http, r"evil", file="http.log", field="nope")
    assert r.error and "no field 'nope'" in r.error and "user_agent" in r.error


def test_extract_pulls_entities_without_a_capture_group() -> None:
    corpus = Corpus({"dns.log": [
        "10.12.34.56 queried ns1.api-sync.net -> 45.77.203.118",
        "10.12.34.56 queried cdn.example.com -> 93.1.2.3",
    ]})
    ips = tally(corpus, r"api-sync", file="dns.log", extract="ip")
    vals = "\n".join(ips.table)
    assert "45.77.203.118" in vals and "10.12.34.56" in vals and "93.1.2.3" not in vals
    domains = tally(corpus, r"api-sync", file="dns.log", extract="domain")
    assert any("api-sync.net" in row for row in domains.table)


def test_extract_precedes_field_and_capture() -> None:
    corpus = Corpus({"f.log": ["a\tb\t1.2.3.4 and 5.6.7.8"]})
    # extract wins even with a capture group present and field set.
    r = tally(corpus, r"(a)", file="f.log", field="1", extract="ip")
    assert any("1.2.3.4" in row for row in r.table)


def test_the_header_line_is_not_counted_in_selector_mode(zeek_http: Corpus) -> None:
    # A pattern that also matches the #fields line must not pull 'method' from the header.
    r = tally(zeek_http, r"method|GET|POST", file="http.log", field="method")
    assert all("method" != row.split()[-1] for row in r.table if row.strip())


# --- corpus header parsing ------------------------------------------------------------


def test_corpus_parses_fields_and_separator(zeek_http: Corpus) -> None:
    assert zeek_http.separator("http.log") == "\t"
    fm = zeek_http.field_map("http.log")
    assert fm["method"] == 2 and fm["response_body_len"] == 5
    assert Corpus({"plain.log": ["no header here"]}).field_map("plain.log") == {}


# --- validation and wiring ------------------------------------------------------------


def test_selectors_are_rejected_off_the_selector_verbs() -> None:
    for kind in (ActionKind.SEARCH, ActionKind.COUNT, ActionKind.TIMELINE):
        problems = validate_action(
            _action(kind, pattern="x", field="foo"), known_files=["dns.log"]
        )
        assert any("apply only to tally, stats and extremes" in p.message for p in problems)
    # extremes takes them exactly as stats does.
    assert validate_action(
        _action(ActionKind.EXTREMES, pattern="x", file="dns.log", field="2"),
        known_files=["dns.log"],
    ) == []


def test_field_and_extract_are_mutually_exclusive() -> None:
    problems = validate_action(
        _action(ActionKind.TALLY, pattern="x", file="dns.log", field="a", extract="ip"),
        known_files=["dns.log"],
    )
    assert any("only one of 'field' or 'extract'" in p.message for p in problems)


def test_unknown_extract_type_is_rejected() -> None:
    problems = validate_action(
        _action(ActionKind.TALLY, pattern="x", extract="mac"), known_files=["dns.log"]
    )
    assert any("extract must be one of" in p.message for p in problems)


def test_field_by_name_requires_a_file() -> None:
    problems = validate_action(
        _action(ActionKind.TALLY, pattern="x", field="method"), known_files=["dns.log"]
    )
    assert any(p.field == "file" for p in problems)


def test_extract_types_match_the_recognisers() -> None:
    """The schema's allowed set and the runtime's recogniser set must not drift."""
    from soc_poc.aggregation import ENTITY_PATTERNS
    from soc_poc.schemas.action import _EXTRACT_TYPES
    assert set(ENTITY_PATTERNS) == set(_EXTRACT_TYPES)


def test_field_names_are_shown_only_when_a_selector_skill_is_on() -> None:
    from soc_poc.prompting.investigate import _files_block, build_investigate_messages
    from soc_poc.schemas.alert import Alert
    from soc_poc.profiling import CaseProfile
    headers = {"http.log": ["ts", "method", "host"]}
    assert "fields: ts, method, host" in _files_block(["http.log"], {"http.log": 3}, headers)
    # The gate: build_investigate_messages hides them unless tally/stats is enabled.
    alert = Alert(alert_id="A", detector="d", rule_name="r", status="open", severity="high",
                  first_seen="t0", last_seen="t1", summary="s")
    def msg(skills):
        return build_investigate_messages(
            alert=alert, profile=CaseProfile(), evidence=Evidence(),
            file_names=["http.log"], line_counts={"http.log": 3}, steps_remaining=10,
            enabled_skills=skills, field_headers=headers,
        )[1]["content"]
    assert "fields: ts, method, host" in msg(frozenset({"tally"}))
    assert "fields: ts, method, host" not in msg(frozenset())


def test_selector_reproduce_commands() -> None:
    name = reproduce_command(
        _action(ActionKind.TALLY, pattern="evil", file="http.log", field="method"))
    assert "awk -F" in name and "name=method" in name and "uniq -c" in name
    num = reproduce_command(
        _action(ActionKind.STATS, pattern="evil", file="http.log", field="6"))
    assert "print $6" in num
    ip = reproduce_command(
        _action(ActionKind.TALLY, pattern="evil", file="dns.log", extract="ip"))
    assert "grep -oE" in ip and "uniq -c" in ip


# --- synthesis: fetched lines stay on the record --------------------------------------
#
# Pinned against inv-20260906T095354Z-b8d4: a run searched dhcp.log, was shown the two
# lease lines naming the host, and the brief never mentioned the hostname. The line was in
# the collapsed ledger; the fix is a flat accountability recap plus a synthesis rule.


def test_evidence_on_record_lists_fetched_lines_not_aggregates(corpus: Corpus) -> None:
    from soc_poc.prompting.investigate import _evidence_on_record
    ev = Evidence()
    ev.add(execute_readonly(
        _action(ActionKind.SEARCH, pattern="wks-2291", file="dhcp.log"), corpus, index=1))
    ev.add(execute_readonly(
        _action(ActionKind.TALLY, pattern=r"(10\.0\.0\.\d+)", file="dhcp.log"), corpus, index=2))
    block = _evidence_on_record(ev)
    assert "EVIDENCE ON THE RECORD" in block
    assert "wks-2291" in block                    # the fetched line is surfaced flat
    assert "dhcp.log:L1" in block                 # with its citable ref
    assert "step 2" not in block                  # the tally (no lines) is not listed


def test_evidence_on_record_is_empty_without_fetched_lines(corpus: Corpus) -> None:
    from soc_poc.prompting.investigate import _evidence_on_record
    ev = Evidence()
    ev.add(execute_readonly(
        _action(ActionKind.COUNT, pattern="query", file="dns.log"), corpus, index=1))
    assert _evidence_on_record(ev) == ""          # nothing fetched -> no block, no empty header


def test_synthesis_prompt_demands_reconciliation_and_identities() -> None:
    from soc_poc.prompting.investigate import SYNTHESIS_SYSTEM_PROMPT
    assert "EVIDENCE ON THE RECORD" in SYNTHESIS_SYSTEM_PROMPT
    assert "IP to a hostname" in SYNTHESIS_SYSTEM_PROMPT


# --- extremes: the one aggregate that returns lines ------------------------------------
#
# Pinned against inv-20260906T161604Z-0d1c (http-c2), which spent 4 of 23 steps building
# digit-range regexes to fetch "the big ones" after a tally said big values existed, and
# against the dns-tunnel runs whose tallies over label columns returned 790 distinct
# values across 790 lines. The ten largest, with refs, is the question both were asking.


def test_extremes_ranks_numeric_values_largest_first_with_refs(zeek_http: Corpus) -> None:
    r = extremes(zeek_http, r"\.example", file="http.log", field="response_body_len")
    assert r.matched_lines == 3 and not r.error
    assert [h.ref for h in r.hits] == ["http.log:L5", "http.log:L6", "http.log:L4"]
    assert r.table[0].startswith("ranked by: numeric value")
    assert "5000" in r.table[1] and "http.log:L5" in r.table[1]
    assert "all 3 shown" in r.table[-1]           # n <= 10: no cliff to report
    assert r.headline.startswith("top 3 of 3 line(s) in http.log")


def test_extremes_falls_back_to_length_and_says_so(corpus: Corpus) -> None:
    r = extremes(corpus, r"query (\S+)", file="dns.log")
    assert r.table[0].startswith("ranked by: value length")
    assert len(r.hits) == EXTREMES_SHOWN and r.matched_lines == 20
    # Every label is the same length, so ties keep corpus order.
    assert r.hits[0].ref == "dns.log:L1" and r.hits[-1].ref == f"dns.log:L{EXTREMES_SHOWN}"
    assert "showing top 10" in r.table[-1] and "next value" in r.table[-1]


def test_extremes_keeps_one_row_per_line(corpus: Corpus) -> None:
    """A line with several selected values contributes its largest, once: ten rows are
    ten distinct citations, never the same line twice."""
    r = extremes(corpus, r"bytes=(\d+)", file="dns.log", field="")
    assert len({h.ref for h in r.hits}) == len(r.hits) == EXTREMES_SHOWN
    assert r.hits[0].ref == "dns.log:L20"            # bytes=190 is the largest
    r2 = extremes(corpus, "10.0.0", file="dns.log", extract="ip")
    assert len({h.ref for h in r2.hits}) == len(r2.hits)


def test_extremes_failures_are_values_and_zero_is_a_result(corpus: Corpus) -> None:
    assert "bad regex" in extremes(corpus, "(", file="dns.log").headline
    assert "no such file" in extremes(corpus, "x", file="nope.log").headline
    assert "no field" in extremes(corpus, "x", file="dns.log", field="nope").headline
    r = extremes(corpus, "does-not-occur", file="dns.log")
    assert r.matched_lines == 0 and r.hits == () and not r.error


def test_an_extremes_step_carries_lines_that_are_citable(corpus: Corpus) -> None:
    """The counter-invariant. tally's step has no lines (tested above); extremes' rows are
    real lines with refs and MUST enter shown_refs(), or the verb has no point."""
    step = execute_readonly(
        _action(ActionKind.EXTREMES, pattern=r"bytes=(\d+)", file="dns.log"), corpus, index=1
    )
    assert step.table and len(step.lines) == EXTREMES_SHOWN
    assert step.total_matches == 20
    assert step.truncated == 20 - EXTREMES_SHOWN     # the honest gap, said on every render
    evidence = Evidence()
    evidence.add(step)
    assert "dns.log:L20" in evidence.shown_refs()
    rendered = evidence.render()
    assert "further match(es) exist and were NOT shown" in rendered
    assert "the count above is exact" not in rendered
    assert "extremes /bytes=(\\d+)/ in dns.log" in rendered


def test_extremes_rows_reach_the_synthesis_record(corpus: Corpus) -> None:
    from soc_poc.prompting.investigate import _evidence_on_record
    ev = Evidence()
    ev.add(execute_readonly(
        _action(ActionKind.EXTREMES, pattern=r"bytes=(\d+)", file="dns.log"), corpus, index=1))
    block = _evidence_on_record(ev)
    assert "step 1" in block and "dns.log:L20" in block and "bytes=190" in block


def test_all_extremes_rows_survive_the_line_budget() -> None:
    """Ten ~300-char Zeek lines must all render in the recent window; at the old budget the
    tenth ranked line -- often the one that mattered -- was the one dropped."""
    lines = ["#fields\tts\tsize\tpayload"]
    lines += [f"{i}\t{1000 - i}\t" + "x" * 280 for i in range(1, 15)]
    corpus = Corpus({"http.log": lines})
    ev = Evidence()
    ev.add(execute_readonly(
        _action(ActionKind.EXTREMES, pattern="x", file="http.log", field="size"), corpus, index=1))
    rendered = ev.render()
    assert "more shown line(s) omitted" not in rendered
    for n in range(2, 12):                            # rows 1..10 are L2..L11
        assert f"http.log:L{n}" in rendered


def test_extremes_headline_shows_the_selector(corpus: Corpus) -> None:
    from soc_poc.evidence import _headline
    step = execute_readonly(
        _action(ActionKind.EXTREMES, pattern="query", file="dns.log", field="4"), corpus, index=1)
    assert _headline(step).endswith("in dns.log field=4")


def test_selectors_make_two_aggregates_different_questions(zeek_http: Corpus) -> None:
    """`extremes field=a` and `field=b` over the same filter must not be suppressed as a
    repeat of each other; the same selector with different prose must."""
    from soc_poc.orchestrator import Orchestrator
    ask = lambda why, col: InvestigativeAction(  # noqa: E731
        reasoning=why, expectation="the big ones", action=ActionKind.EXTREMES,
        pattern=r"\.example", file="http.log", field=col,
    )
    orchestrator = Orchestrator.__new__(Orchestrator)
    orchestrator._evidence = Evidence()
    orchestrator._evidence.add(
        execute_readonly(ask("how big", "response_body_len"), zeek_http, index=1))
    assert orchestrator._previous_identical(ask("still how big", "response_body_len")) is not None
    assert orchestrator._previous_identical(ask("how big", "method")) is None


def test_extremes_is_gated_and_on_the_menu_only_when_enabled() -> None:
    problems = validate_action(
        _action(ActionKind.EXTREMES, pattern="x"), known_files=["dns.log"],
        enabled_skills=frozenset({"tally"}))
    assert any("not available in this run" in p.message for p in problems)
    without = investigate_system_prompt(frozenset({"tally"}))
    with_it = investigate_system_prompt(frozenset({"tally", "extremes"}))
    assert "extremes  " not in without and "extremes  " in with_it
    # It fetches lines, so it must not be offered as a way to size a result set.
    assert "count/tally;" in with_it and "extremes;" not in with_it
    assert "DOES fetch lines" in with_it
    assert RunConfig(enabled_skills=("extremes",)).enabled_skills == ("extremes",)


def test_extremes_reproduce_and_coercion() -> None:
    by_name = reproduce_command(
        _action(ActionKind.EXTREMES, pattern="evil", file="http.log", field="request_body_len"))
    assert "awk -F" in by_name and "name=request_body_len" in by_name
    assert by_name.endswith(f"| sort -rn | head -{EXTREMES_SHOWN}")
    assert 'FILENAME":L"FNR' in by_name
    by_number = reproduce_command(
        _action(ActionKind.EXTREMES, pattern="evil", file="http.log", field="14"))
    assert "v=$14" in by_number
    grouped = reproduce_command(_action(ActionKind.EXTREMES, pattern=r"bytes=(\d+)"))
    assert "match($0,pat,m)" in grouped
    entity = reproduce_command(_action(ActionKind.EXTREMES, pattern="evil", extract="ip"))
    assert "ent=" in entity and "head -10" in entity
    coerced = coerce_action_payload({"action": "extremes", "action_input": r"bytes=(\d+)"})
    assert coerced is not None and coerced["pattern"] == r"bytes=(\d+)"


def test_awk_reproduce_values_survive_awk_escape_processing() -> None:
    """awk -v turns `\\.` into `.`; a reproduce command that matched the wrong thing would
    be worse than none. Backslashes are doubled and grep's \\b becomes gawk's \\y."""
    cmd = reproduce_command(
        _action(ActionKind.EXTREMES, pattern=r"evil\.example\t/up\?x=([0-9]+)", file="http.log"))
    assert r"evil\\.example\\t/up\\?x=([0-9]+)" in cmd
    ent = reproduce_command(_action(ActionKind.EXTREMES, pattern="evil", extract="domain"))
    assert r"\\y(" in ent and r"\b(" not in ent
    named = reproduce_command(
        _action(ActionKind.TALLY, pattern=r"\.t\.example", file="dns.log", field="query"))
    assert r"pat='\\.t\\.example'" in named
