"""The action loop's two halves: what an action means, and what the record of one says.

The property under test throughout is that nothing is quietly lost or quietly invented.
A truncated result must say it was truncated, a count must not masquerade as a listing,
and the brief must be unable to cite a line the commander was never shown.
"""

from __future__ import annotations

import pytest

from soc_poc.actions import execute_readonly, reproduce_command
from soc_poc.corpus import MAX_RESULTS, Corpus
from soc_poc.evidence import STEPS_RENDERED_IN_FULL, Evidence, elide
from soc_poc.schemas.action import (
    ActionKind,
    InvestigativeAction,
    validate_action,
)


def _action(kind: ActionKind, **kwargs) -> InvestigativeAction:
    return InvestigativeAction(
        reasoning="because", expectation="something or nothing", action=kind, **kwargs
    )


@pytest.fixture
def corpus() -> Corpus:
    return Corpus(
        {
            "dns.log": [f"line {n} query{n % 7} answer" for n in range(1, 101)],
            "dhcp.log": ["ACK 10.0.0.5 wks-2291", "ACK 10.0.0.6 wks-1100"],
        }
    )


# --- validation -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "kwargs", "field"),
    [
        (ActionKind.SEARCH, {}, "pattern"),
        (ActionKind.COUNT, {}, "pattern"),
        (ActionKind.CONTEXT, {}, "ref"),
        (ActionKind.READ_LINES, {"start_line": 1, "end_line": 5}, "file"),
        (ActionKind.CLOSE_READ, {"file": "dns.log", "start_line": 1, "end_line": 5}, "question"),
    ],
)
def test_an_action_missing_its_argument_is_rejected(kind, kwargs, field) -> None:
    problems = validate_action(_action(kind, **kwargs), known_files=["dns.log"])
    assert field in {problem.field for problem in problems}


def test_an_inverted_line_range_is_rejected() -> None:
    action = _action(ActionKind.READ_LINES, file="dns.log", start_line=90, end_line=10)
    problems = validate_action(action, known_files=["dns.log"])
    assert any("start_line <= end_line" in problem.message for problem in problems)


def test_a_misnamed_file_is_told_what_the_options_are() -> None:
    """The one mistake worth spending a retry on: the fix is mechanical, and the
    alternative is a confident conclusion drawn from a search that never ran."""
    action = _action(ActionKind.COUNT, pattern="x", file="dnss.log")
    problems = validate_action(action, known_files=["dns.log", "dhcp.log"])
    assert len(problems) == 1
    assert "dns.log" in problems[0].message and "dhcp.log" in problems[0].message


def test_conclude_needs_nothing() -> None:
    assert validate_action(_action(ActionKind.CONCLUDE), known_files=["dns.log"]) == []


def test_concluding_before_the_floor_is_pushed_back_once() -> None:
    """The loop's characteristic failure, pinned.

    The first real run concluded at step 2 of a 24-step budget, having confirmed the
    alert and nothing else -- then listed five unexamined avenues in coverage_gaps,
    including the two that would have identified the host and the attacker's nameserver.
    It knew what it had skipped. Being told a budget is available is not the same as
    being told an unspent step is worth nothing.
    """
    problems = validate_action(
        _action(ActionKind.CONCLUDE), known_files=["dns.log"], steps_taken=2, min_steps=6
    )
    assert len(problems) == 1
    # The pushback has to name the open questions, or it is just "try harder".
    assert "only 2 step(s)" in problems[0].message
    assert "estate-wide" in problems[0].message
    assert "RESPONSES" in problems[0].message


def test_concluding_after_the_floor_is_allowed() -> None:
    """The floor is a floor, not a quota: a real investigation must be able to end."""
    assert (
        validate_action(
            _action(ActionKind.CONCLUDE),
            known_files=["dns.log"],
            steps_taken=6,
            min_steps=6,
        )
        == []
    )


def test_the_floor_never_blocks_an_investigative_action() -> None:
    """Only conclude is gated. Blocking real work would be the opposite of the point."""
    assert (
        validate_action(
            _action(ActionKind.COUNT, pattern="x"),
            known_files=["dns.log"],
            steps_taken=0,
            min_steps=6,
        )
        == []
    )


def test_a_well_formed_action_passes() -> None:
    action = _action(ActionKind.SEARCH, pattern=r"\bwks-\d+", file="dhcp.log")
    assert validate_action(action, known_files=["dns.log", "dhcp.log"]) == []


# --- execution ------------------------------------------------------------------------


def test_count_returns_a_number_and_no_lines(corpus: Corpus) -> None:
    """count exists to be cheap. Returning lines would make it a search with extra steps."""
    step = execute_readonly(
        _action(ActionKind.COUNT, pattern="query1", file="dns.log"), corpus, index=1
    )
    assert step.total_matches == 15  # n % 7 == 1 for 15 of lines 1..100
    assert step.lines == ()
    assert step.truncated == 0


def test_a_zero_count_reads_as_a_result_not_a_silence(corpus: Corpus) -> None:
    """This is the negative the whole redesign exists to make trustworthy."""
    step = execute_readonly(
        _action(ActionKind.SEARCH, pattern="nonesuch", file="dns.log"), corpus, index=1
    )
    assert step.total_matches == 0
    assert "does not occur" in step.summary


def test_a_truncated_search_says_so_every_time_it_is_rendered(corpus: Corpus) -> None:
    """A silently truncated result is indistinguishable from a complete one, and that is
    how a partial answer becomes a false negative."""
    step = execute_readonly(_action(ActionKind.SEARCH, pattern="line"), corpus, index=1)
    assert step.total_matches == 100
    assert len(step.lines) == MAX_RESULTS
    assert step.truncated == 100 - MAX_RESULTS

    evidence = Evidence()
    evidence.add(step)
    rendered = evidence.render()
    assert "were NOT shown" in rendered
    assert "The count 100 is exact" in rendered


def test_a_bad_regex_becomes_a_step_not_an_exception(corpus: Corpus) -> None:
    step = execute_readonly(_action(ActionKind.SEARCH, pattern="a["), corpus, index=1)
    assert "bad regex" in step.error
    assert "failed" in step.summary


def test_read_lines_outside_the_file_reports_rather_than_returning_nothing(
    corpus: Corpus,
) -> None:
    step = execute_readonly(
        _action(ActionKind.READ_LINES, file="dhcp.log", start_line=50, end_line=60),
        corpus,
        index=1,
    )
    assert step.lines == ()
    assert "no lines in that range" in step.error


def test_every_step_carries_a_command_that_reproduces_it() -> None:
    """A brief whose evidence can be re-derived with grep is auditable in a way that
    "a language model read it and said so" is not."""
    assert reproduce_command(
        _action(ActionKind.SEARCH, pattern="10.0.0.5", file="dhcp.log")
    ) == "grep -niE 10.0.0.5 logs/dhcp.log"
    assert reproduce_command(_action(ActionKind.COUNT, pattern="x")).startswith("grep -ciE")
    assert reproduce_command(_action(ActionKind.CONTEXT, ref="dns.log:L20")) == (
        "sed -n '15,25p' logs/dns.log"
    )


def test_a_pattern_with_shell_metacharacters_is_quoted() -> None:
    """The command is printed for a human to paste. An unquoted `;` in a regex would
    make the printed line do something other than what the step did."""
    command = reproduce_command(_action(ActionKind.SEARCH, pattern="a; rm -rf /"))
    assert "'a; rm -rf /'" in command


# --- evidence -------------------------------------------------------------------------


def test_the_brief_may_only_cite_lines_the_commander_was_shown(corpus: Corpus) -> None:
    """`shown_refs` is what makes "cited" continue to mean "read".

    A reference that resolves in the corpus but was never displayed is not a citation, it
    is a plausible-looking guess -- and under this architecture that is the failure mode
    worth catching, because the commander now knows the file names and the line counts.
    """
    evidence = Evidence()
    evidence.add(
        execute_readonly(
            _action(ActionKind.SEARCH, pattern="query1", file="dns.log"), corpus, index=1
        )
    )
    shown = evidence.shown_refs()
    assert "dns.log:L1" in shown
    # Real line, real file, never displayed.
    assert corpus.line("dns.log:L2") is not None
    assert "dns.log:L2" not in shown


def test_a_count_contributes_no_citable_refs(corpus: Corpus) -> None:
    """Establishing that 788 lines match does not entitle the brief to cite any of them."""
    evidence = Evidence()
    evidence.add(execute_readonly(_action(ActionKind.COUNT, pattern="line"), corpus, index=1))
    assert evidence.shown_refs() == set()


def test_older_steps_collapse_but_keep_their_counts(corpus: Corpus) -> None:
    """A 30-step investigation cannot be replayed verbatim into a 24k context. Counts
    survive collapse deliberately: they are most of the value and cost one line."""
    evidence = Evidence()
    for index in range(1, 9):
        evidence.add(
            execute_readonly(
                _action(ActionKind.COUNT, pattern=f"query{index % 7}", file="dns.log"),
                corpus,
                index=index,
            )
        )
    rendered = evidence.render()
    assert "EARLIER STEPS" in rendered
    # The first step is summarised, not replayed...
    assert "1. count /query1/ in dns.log -> 15 match(es) in dns.log" in rendered
    # ...and only the last few keep their full rendering.
    assert rendered.count("expected:") == STEPS_RENDERED_IN_FULL


def test_an_empty_ledger_says_so_rather_than_rendering_nothing() -> None:
    """The first turn must not look like a turn where everything came back empty."""
    assert Evidence().render() == "(no steps taken yet)"


def test_elision_keeps_both_ends_of_a_wide_record() -> None:
    """Zeek puts `answers` last. Truncating from the right hid every TXT payload in the
    case, and the brief said no DNS response payloads had been captured."""
    text = "ts\tuid\t" + "x" * 400 + "\tPAYLOAD_AT_THE_END"
    shortened = elide(text, max_chars=120)
    assert shortened.startswith("ts\tuid")
    assert shortened.endswith("PAYLOAD_AT_THE_END")
    assert len(shortened) < len(text)


def test_elision_never_returns_more_than_it_was_asked_for() -> None:
    """A head longer than max_chars drove the tail slice negative, which silently
    returned most of the string instead of shortening it."""
    text = "y" * 1000
    for budget in (10, 40, 149, 150, 300):
        shortened = elide(text, max_chars=budget)
        assert len(shortened) < len(text), budget


# --- coercion ---------------------------------------------------------------------------
#
# Every payload below was emitted by gpt-oss-120b against the real dns-tunnel prompt while
# guided decoding was silently not engaging. They are verbatim.


@pytest.mark.parametrize(
    ("payload", "verb", "pattern", "file"),
    [
        ({"action": "count", "action_input": r"t\.api-sync-telemetry\.net"},
         "count", r"t\.api-sync-telemetry\.net", ""),
        ({"action": "search", "action_args": {"regex": r"t\.api\.net", "case_insensitive": True}},
         "search", r"t\.api\.net", ""),
        ({"action": "count", "parameters": {"regex": r"api-sync\.net"}},
         "count", r"api-sync\.net", ""),
        ({"action": "search", "action_input": r"10\.12\.34\.56", "path": "dhcp.log"},
         "search", r"10\.12\.34\.56", "dhcp.log"),
        ({"action": "count", "tool": "search", "parameters": {"regex": "x"}},
         "count", "x", ""),
    ],
)
def test_a_tool_call_shaped_reply_is_rescued(payload, verb, pattern, file) -> None:
    from soc_poc.coercion import coerce_action_payload

    out = coerce_action_payload(payload)
    assert out is not None
    assert out["action"] == verb
    assert out["pattern"] == pattern
    assert out["file"] == file
    # And the rescued object must satisfy the real contract, not a looser one.
    action = InvestigativeAction.model_validate(out)
    assert validate_action(action, known_files=["dns.log", "dhcp.log"]) == []


def test_a_bare_positional_argument_follows_the_verb() -> None:
    """`{"action": "read_lines", "action_input": "dns.log"}` means a file, not a regex;
    the same string under `search` means a regex. Only the verb disambiguates."""
    from soc_poc.coercion import coerce_action_payload

    assert coerce_action_payload(
        {"action": "search", "action_input": "dns.log"}
    )["pattern"] == "dns.log"
    assert coerce_action_payload(
        {"action": "read_lines", "action_input": "dns.log"}
    )["file"] == "dns.log"


def test_a_well_formed_action_is_left_completely_alone() -> None:
    """Coercion must be unable to affect the normal path -- it fires only on payloads
    that would otherwise have failed."""
    from soc_poc.coercion import coerce_action_payload

    good = {
        "reasoning": "r", "expectation": "e", "action": "count", "pattern": "x",
        "file": "", "ref": "", "start_line": 0, "end_line": 0, "question": "",
    }
    assert coerce_action_payload(good) is None


def test_coercion_declines_what_is_not_an_action() -> None:
    from soc_poc.coercion import coerce_action_payload

    assert coerce_action_payload({"findings": [], "relevant": False}) is None
    assert coerce_action_payload({}) is None


def test_a_rescued_action_never_invents_analyst_reasoning() -> None:
    """The model did not write reasoning in this shape, so the ledger must not pretend
    it did -- the operator reads `reasoning` as the analyst's stated intent."""
    from soc_poc.coercion import coerce_action_payload

    out = coerce_action_payload({"action": "count", "action_input": "x"})
    assert "recovered" in out["reasoning"]
    assert "not stated" in out["expectation"]


def test_a_rescued_action_that_is_still_wrong_is_still_rejected() -> None:
    """Coercion is not a bypass: the validator sees the coerced object, not the raw one."""
    from soc_poc.coercion import coerce_action_payload

    out = coerce_action_payload({"action": "count"})  # no argument anywhere
    action = InvestigativeAction.model_validate(out)
    problems = validate_action(action, known_files=["dns.log"])
    assert any(p.field == "pattern" for p in problems)


# --- close_read bounds -------------------------------------------------------------------


def test_a_close_read_range_is_bounded_by_tokens_not_just_lines() -> None:
    """A line cap alone is not a context bound.

    120 lines of Zeek dns.log is ~19,000 tokens against the grunt's 16k context, and an
    oversized slice is rejected by the server — so a line-only cap would have failed
    precisely on the widest, most interesting records.
    """
    from soc_poc.corpus import Hit
    from soc_poc.orchestrator import _fit_token_budget

    wide = [Hit(ref=f"dns.log:L{n}", text="x" * 280) for n in range(1, 121)]
    kept = _fit_token_budget(wide, budget_tokens=10_000, chars_per_token=1.4)
    assert len(kept) < len(wide)
    assert sum(len(h.text) for h in kept) / 1.4 <= 10_000


def test_a_single_oversized_line_is_still_returned() -> None:
    """A record wider than the whole budget cannot be split without breaking its
    reference, and one oversized slice is a better failure than an empty one."""
    from soc_poc.corpus import Hit
    from soc_poc.orchestrator import _fit_token_budget

    huge = [Hit(ref="dns.log:L1", text="y" * 50_000)]
    assert _fit_token_budget(huge, budget_tokens=100, chars_per_token=1.4) == huge


def test_a_reference_without_its_file_is_rejected() -> None:
    """`ref: "L978"` passed the old presence-only check and then crashed the step that
    renders it, ending a 21-step investigation. The shape is now checked."""
    problems = validate_action(
        _action(ActionKind.CONTEXT, ref="L978", file="dns.log"), known_files=["dns.log"]
    )
    assert len(problems) == 1
    assert problems[0].field == "ref"
    # The hint is built from the action's own fields, not a fixed example from an
    # unrelated line -- a run emitted the same malformed ref twice against the old wording.
    assert "You appear to mean dns.log:L978" in problems[0].message


def test_a_reference_naming_an_unknown_file_is_rejected() -> None:
    problems = validate_action(
        _action(ActionKind.CONTEXT, ref="nope.log:L5"), known_files=["dns.log"]
    )
    assert any(p.field == "ref" and "does not have" in p.message for p in problems)


def test_a_well_formed_reference_passes() -> None:
    assert validate_action(
        _action(ActionKind.CONTEXT, ref="dns.log:L978"), known_files=["dns.log"]
    ) == []


def test_rendering_a_malformed_reference_never_raises() -> None:
    """A display helper that can end a run is a defect regardless of what fed it."""
    assert "unparseable" in reproduce_command(_action(ActionKind.CONTEXT, ref="L978"))
    assert "unparseable" in reproduce_command(_action(ActionKind.CONTEXT, ref=""))


# --- zero-result diagnosis ---------------------------------------------------------------


def test_a_zero_caused_by_the_pattern_says_so(corpus: Corpus) -> None:
    """The failure this exists to stop, verbatim from a graded run.

    The commander searched `\\tTXT\\t.*t\\.api-sync-telemetry\\.net`, got zero, and wrote
    that zero into the brief as contradicting evidence against the tunnel hypothesis.
    There are 649 such queries — Zeek puts the query before the qtype, so the pattern
    could never match however much tunnelling was happening. The prompt already warned
    about this and the model did it anyway, so the check belongs in code.
    """
    # Same shape as the real failure: a real literal, wrapped in field separators that
    # do not occur in that order. The host is in the file; the pattern cannot match.
    step = execute_readonly(
        _action(ActionKind.COUNT, pattern=r"\twks-2291\t.*ACK", file="dhcp.log"),
        corpus,
        index=1,
    )
    assert step.total_matches == 0
    assert "about your PATTERN, not about the data" in step.summary
    assert "wks-2291" in step.summary


def test_a_genuine_zero_is_left_to_stand(corpus: Corpus) -> None:
    """A real absence must not be second-guessed — that negative is the point of count."""
    step = execute_readonly(
        _action(ActionKind.COUNT, pattern="definitely-not-present-anywhere", file="dns.log"),
        corpus,
        index=1,
    )
    assert step.total_matches == 0
    assert "NOTE" not in step.summary


def test_a_pattern_with_no_meaningful_literal_gets_no_hint(corpus: Corpus) -> None:
    """`\\tTXT\\t` reduces to "TXT", which occurs in every DNS log ever written. A hint on
    every miss is noise, and noise is how a real warning stops being read."""
    from soc_poc.actions import longest_literal

    assert longest_literal(r"\t\d+\t") == ""
    assert longest_literal(r"\tTXT\t") == ""  # too short to be evidence of anything
    # `\.` is a literal dot and stays in the run; `\t` is a tab and ends one.
    assert longest_literal(r"t\.api-sync-telemetry\.net") == "t.api-sync-telemetry.net"
    assert longest_literal(r"\tTXT\t.*t\.api-sync\.net") == "t.api-sync.net"
    # Splitting on backslashes alone took the `t` out of `\t` into the literal, probing
    # for `twks-2291` — a string that cannot occur — and silently suppressing the hint.
    assert longest_literal(r"\twks-2291\t.*ACK") == "wks-2291"


# --- the collapse must not erase the answer -----------------------------------------------


def test_an_aged_out_step_still_shows_what_it_found(corpus: Corpus) -> None:
    """The loop, pinned. This test fails on the code that produced it.

    A run searched dhcp.log for a host address at step 3 and was shown two lines naming
    `wks-2291`. By step 8 that step had collapsed to
    `search /…/ in dhcp.log -> 2 match(es); all shown` — the count survived, the answer did
    not, `wks-2291` was nowhere in the prompt, and the commander asked the identical
    question again. It would have kept asking: every fresh answer ages out in four steps.
    """
    evidence = Evidence()
    evidence.add(
        execute_readonly(
            _action(ActionKind.SEARCH, pattern="10.0.0.5", file="dhcp.log"), corpus, index=1
        )
    )
    for index in range(2, 8):  # push it well past STEPS_RENDERED_IN_FULL
        evidence.add(
            execute_readonly(
                _action(ActionKind.COUNT, pattern=f"query{index % 7}", file="dns.log"),
                corpus,
                index=index,
            )
        )
    rendered = evidence.render()
    assert "EARLIER STEPS" in rendered  # it really did collapse
    assert "wks-2291" in rendered, "the collapsed step dropped the answer it found"


def test_a_collapsed_step_says_what_it_withheld(corpus: Corpus) -> None:
    """A sample must not read as the whole result — that is how a partial answer becomes
    a false negative, the same failure the truncation notice exists to prevent."""
    evidence = Evidence()
    evidence.add(
        execute_readonly(_action(ActionKind.SEARCH, pattern="line"), corpus, index=1)
    )
    for index in range(2, 8):
        evidence.add(
            execute_readonly(
                _action(ActionKind.COUNT, pattern="line", file="dns.log"), corpus, index=index
            )
        )
    earlier = evidence.render().split("RECENT STEPS")[0]
    assert "further matching line(s) not shown here" in earlier
    assert "the count above is exact" in earlier


def test_a_collapsed_count_stays_a_single_line(corpus: Corpus) -> None:
    """`count` has no lines, and its number really is its whole product."""
    evidence = Evidence()
    for index in range(1, 8):
        evidence.add(
            execute_readonly(
                _action(ActionKind.COUNT, pattern="query1", file="dns.log"), corpus, index=index
            )
        )
    earlier = evidence.render().split("RECENT STEPS")[0]
    # One headline per collapsed step, plus the section header. No line samples.
    assert earlier.count("count /query1/") == 3
    assert "dns.log:L" not in earlier


def test_the_ledger_grows_sublinearly_with_the_sample() -> None:
    """The sample is affordable, which is the only reason it may exist.

    The guarantee is not a small number, it is a *bounded* one: the collapsed section adds
    a fixed few lines per step, so tripling the step count must not triple the prompt.
    This fixture is deliberately harsher than any real case — every step is a 400-match
    search over 240-character records.
    """
    big = Corpus({"f.log": [f"{n} " + "x" * 240 for n in range(400)]})

    def render_after(steps: int) -> int:
        evidence = Evidence()
        for index in range(1, steps + 1):
            evidence.add(
                execute_readonly(
                    _action(ActionKind.SEARCH, pattern="x", file="f.log"), big, index=index
                )
            )
        return len(evidence.render())

    eight, twentyfour = render_after(8), render_after(24)
    # 3x the steps must cost well under 2x the prompt...
    assert twentyfour < eight * 2
    # ...and the whole thing still fits comfortably in the 24,384-token context.
    assert twentyfour / 3.5 < 9_000


# --- a file-less reference is repaired, not fatal -----------------------------------------


def test_a_bare_line_number_is_repaired_from_the_action_itself() -> None:
    """A run died on this: `ref: "L975"` with `file: "dns.log"` was rejected, the model
    repeated it verbatim on the retry, and the loop gave up with 16 of 24 steps unspent.
    The correct reference was fully determined the whole time."""
    from soc_poc.coercion import coerce_action_payload

    out = coerce_action_payload(
        {
            "reasoning": "r", "expectation": "e", "action": "context",
            "ref": "L975", "file": "dns.log", "pattern": "",
            "start_line": 0, "end_line": 0, "question": "",
        }
    )
    assert out is not None and out["ref"] == "dns.log:L975"
    assert validate_action(
        InvestigativeAction.model_validate(out), known_files=["dns.log"]
    ) == []


def test_repair_never_invents_a_filename() -> None:
    """With no `file` to fall back on there is nothing to concatenate, and guessing one
    would produce a reference to a line the commander was never shown."""
    from soc_poc.coercion import repair_ref

    assert repair_ref({"ref": "L975", "file": ""})["ref"] == "L975"
    assert repair_ref({"ref": "dns.log:L975", "file": "dhcp.log"})["ref"] == "dns.log:L975"


def test_an_unrepairable_reference_is_rejected_naming_what_was_written() -> None:
    problems = validate_action(
        _action(ActionKind.CONTEXT, ref="somewhere in the log"), known_files=["dns.log"]
    )
    assert len(problems) == 1
    assert "'somewhere in the log'" in problems[0].message


def test_long_json_lines_keep_their_tail_visible() -> None:
    """A Windows event serialised as JSON is 400-600 chars with the command line near the
    end. The default elision must keep enough of the tail to show it."""
    from soc_poc.evidence import LINE_HEAD_CHARS, LINE_MAX_CHARS
    line = '{"ts":"2026-09-07T08:00:00Z",' + '"pad":"' + "x" * 300 + '",' + \
           '"CommandLine":"cmd.exe /c whoami /all > C:\\\\Users\\\\Public\\\\out.txt"}'
    shown = elide(line)
    assert len(line) > LINE_MAX_CHARS and "elided" in shown
    assert line[:LINE_HEAD_CHARS] in shown
    assert "whoami /all" in shown
