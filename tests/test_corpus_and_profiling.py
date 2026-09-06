"""The deterministic layer: search that cannot miss, and a profile that cannot invent.

These are regressions with receipts. Every assertion here corresponds to something that
actually went wrong in a real run against `cases/dns-tunnel` -- the DHCP lease six sweeps
reported as absent, and the NS delegation none of them ever cited. Both are now questions
with arithmetic answers, and the tests pin the arithmetic.
"""

from __future__ import annotations

import pytest

from soc_poc.corpus import MAX_RESULTS, Corpus
from soc_poc.profiling import (
    RARE_MIN_EVENTS,
    _humanise,
    _prenormalise,
    _templatize,
    _unique_tokens,
    build_profile,
)

ZEEK_HEADER = [
    "#separator \\x09",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tquery\tqtype_name\tanswers",
]


def _zeek(ts: str, uid: str, source: str, query: str, qtype: str, answer: str) -> str:
    return f"{ts}\t{uid}\t{source}\t51402\t{query}\t{qtype}\t{answer}"


@pytest.fixture
def corpus() -> Corpus:
    # Padded to a realistic denominator on purpose: "rare" is a statement about a
    # population, and two lines out of six is not one. The NS delegation sits at L5-L6.
    dns = [
        *ZEEK_HEADER,
        _zeek("1786694407.100000", "Caaaaaaaaaaaa", "10.12.34.9", "www.example.com", "A", "93.184.1.1"),
        _zeek("1786694408.100000", "Cbbbbbbbbbbbb", "10.12.34.9", "mail.example.com", "A", "93.184.1.2"),
        _zeek("1786694409.100000", "Cccccccccccc1", "10.12.34.56", "api-sync.net", "NS", "ns1.api-sync.net"),
        _zeek("1786694410.100000", "Cddddddddddd1", "10.12.34.56", "ns1.api-sync.net", "A", "45.77.203.118"),
        *[
            _zeek(f"17866945{n:02d}.100000", f"Cn{n:011d}", f"10.12.34.{n % 40 + 10}",
                  f"host{n}.example.com", "A", f"93.184.2.{n % 250}")
            for n in range(60)
        ],
    ]
    dhcp = [
        "2026-08-14 07:02:11 ACK 10.12.34.9 aa:bb:cc:dd:ee:01 wks-1100 lease=3600",
        "2026-08-14 07:14:02 ACK 10.12.34.56 aa:bb:cc:dd:ee:02 wks-2291 lease=3600",
    ]
    return Corpus({"dns.log": dns, "dhcp.log": dhcp})


# --- corpus ---------------------------------------------------------------------------


def test_every_hit_carries_a_resolvable_reference(corpus: Corpus) -> None:
    """Citation validation is unchanged only if refs mean the same thing they used to."""
    result = corpus.search("NOERROR|NS")
    assert result.returned
    for hit in result.returned:
        assert corpus.line(hit.ref) == hit.text
        assert hit.ref in corpus.refs()


def test_the_dhcp_lease_the_sweep_said_did_not_exist(corpus: Corpus) -> None:
    """`dhcp-0001` reported `10.12.34.56 -> found: false` for a file containing it.

    A model read the file and did not notice. This cannot not-notice.
    """
    result = corpus.search("10.12.34.56", file="dhcp.log")
    assert result.total_matches == 1
    assert result.returned[0].ref == "dhcp.log:L2"
    assert "wks-2291" in result.returned[0].text


def test_count_is_a_negative_you_can_trust(corpus: Corpus) -> None:
    """Zero here means absent, not unnoticed -- the distinction the sweep could never make."""
    assert corpus.count("10.99.99.99").total_matches == 0
    assert corpus.count("10.12.34.56").total_matches == 3


def test_search_reports_what_it_withheld(corpus: Corpus) -> None:
    """Silent truncation is how a partial answer becomes a false negative."""
    big = Corpus({"f.log": [f"line {n} match" for n in range(200)]})
    result = big.search("match")
    assert result.total_matches == 200
    assert len(result.returned) == MAX_RESULTS
    assert result.truncated == 200 - MAX_RESULTS


def test_bad_regex_and_missing_file_explain_themselves(corpus: Corpus) -> None:
    """The commander has to be able to correct itself from the error alone."""
    assert "bad regex" in corpus.search("a[").error
    missing = corpus.search("x", file="nope.log")
    assert "no such file" in missing.error
    assert "dns.log" in missing.error  # tells it what it *can* ask for


def test_context_reaches_the_line_after_a_hit(corpus: Corpus) -> None:
    """The NS record names a nameserver; the address is on the NEXT line."""
    result = corpus.context("dns.log:L5", before=0, after=1)
    assert [h.ref for h in result.returned] == ["dns.log:L5", "dns.log:L6"]
    assert "45.77.203.118" in result.returned[1].text


# --- templating -----------------------------------------------------------------------


def test_identifiers_collapse_before_numbers_do() -> None:
    """The ordering bug, pinned.

    Collapsing digits first shreds `cd7yikpgnxglwk3ysx` into fragments too short to look
    like an identifier, so two records of identical shape template differently and both
    look 'rare'. Three hundred DKIM records did exactly that and buried the NS delegation.
    """
    lines = [
        "host TXT v=DKIM1; k=rsa; p=cd7yikpgnxglwk3ysx7x8d",
        "host TXT v=DKIM1; k=rsa; p=9dlhztm4k2lfuqnhnm8x1",
    ]
    unique = _unique_tokens([_prenormalise(line) for line in lines])
    templates = {_templatize(line, unique) for line in lines}
    assert len(templates) == 1, f"same shape templated {len(templates)} ways: {templates}"
    assert "<ID>" in templates.pop()


def test_repeated_tokens_are_structure_not_identifiers() -> None:
    """Uniqueness, not entropy. `C_INTERNET` is 10 chars and must survive verbatim."""
    lines = ["a C_INTERNET x9f2kd81ha", "b C_INTERNET p0q3ms77bz"]
    unique = _unique_tokens([_prenormalise(line) for line in lines])
    assert "C_INTERNET" not in unique
    assert all("C_INTERNET" in _templatize(line, unique) for line in lines)


def test_counting_and_substituting_see_the_same_text() -> None:
    """Both passes run on pass-1 output. Counting raw and substituting normalised finds
    tokens that no longer exist by substitution time, and silently collapses nothing."""
    line = "2026-08-14T08:00:07Z host 10.0.0.1 abcdef123456"
    assert _unique_tokens([_prenormalise(line)]) == {"abcdef123456"}


# --- profile --------------------------------------------------------------------------


def test_the_ns_delegation_is_the_rare_shape(corpus: Corpus) -> None:
    """The whole reason this module exists.

    An NS record among a majority of A records is rare by count. No model is asked to
    notice it; a frequency table cannot help but.
    """
    profile = build_profile(corpus)
    dns = next(f for f in profile.files if f.file == "dns.log")
    rare_templates = " ".join(shape.template for shape in dns.rare_shapes)
    assert "NS" in rare_templates
    assert "dns.log:L5" in {ref for shape in dns.rare_shapes for ref in shape.refs}


def test_zeek_header_lines_are_not_events(corpus: Corpus) -> None:
    """Eight `#` lines each occur exactly once and outrank every genuine rarity."""
    profile = build_profile(corpus)
    dns = next(f for f in profile.files if f.file == "dns.log")
    for shape in dns.rare_shapes:
        assert not shape.template.startswith("#")


def test_rare_shapes_are_suppressed_when_there_is_no_denominator(corpus: Corpus) -> None:
    """In an eight-line file, 'rare' only means 'small file'."""
    profile = build_profile(corpus)
    dhcp = next(f for f in profile.files if f.file == "dhcp.log")
    assert dhcp.lines < RARE_MIN_EVENTS
    assert dhcp.rare_shapes == []


def test_entropy_groups_separate_a_tunnel_from_a_vendor_service() -> None:
    """Entropy alone cannot tell an encoded label from an AV hash lookup, and pretending
    otherwise is how this produced a false positive. `distinct_sources` can."""
    lines = [*ZEEK_HEADER]
    for n in range(30):  # one host, many encoded labels: a tunnel
        lines.append(_zeek(f"17866944{n:02d}.100000", f"Ct{n:011d}", "10.12.34.56",
                           f"{'7f3a9c2e1b8d4a6f0e5c':.20}{n:04d}.t.tunnel.net", "TXT", "-"))
    for n in range(30):  # thirty hosts, same shape: a vendor service
        lines.append(_zeek(f"17866945{n:02d}.100000", f"Cv{n:011d}", f"10.12.34.{n + 100}",
                           f"{'e2b7d14f9a3c6082b5d1':.20}{n:04d}.avts.vendor.net", "TXT", "-"))
    profile = build_profile(Corpus({"dns.log": lines}))
    by_suffix = {g.suffix: g for g in profile.entropy_groups}
    tunnel = next(g for s, g in by_suffix.items() if "tunnel" in s)
    vendor = next(g for s, g in by_suffix.items() if "vendor" in s)
    assert tunnel.distinct_sources == 1
    assert vendor.distinct_sources == 30
    assert tunnel.sources == ["10.12.34.56"]


def test_bursts_are_reported_not_asserted_to_be_periodic() -> None:
    """Two clusters separated by an idle hour are two sessions, not a 5-second interval."""
    lines = [*ZEEK_HEADER]
    base = 1786694400
    for offset in [*range(0, 40, 5), *range(3600, 3640, 5)]:
        lines.append(_zeek(f"{base + offset}.100000", f"C{offset:012d}", "10.12.34.56",
                           f"{'a9f2c7e4b1d8':.12}{offset:04d}.t.tunnel.net", "TXT", "-"))
    profile = build_profile(Corpus({"dns.log": lines}))
    assert len(profile.bursts) == 2
    assert [b.events for b in profile.bursts] == [8, 8]


def test_timestamps_are_rendered_for_a_reader_not_a_machine() -> None:
    """Zeek writes bare epochs. Asking a model to subtract ten-digit integers invites
    a guess; the raw form stays authoritative wherever it is actually compared."""
    assert _humanise("1786697233") == "2026-08-14T08:47:13Z"
    assert _humanise("2026-08-14T08:47:13") == "2026-08-14T08:47:13"


def test_the_profile_is_arithmetic_over_the_corpus(corpus: Corpus) -> None:
    """Nothing here passes through a model, so nothing here can be a hallucination.
    Every count must be independently reproducible from the same corpus."""
    profile = build_profile(corpus)
    for address, count in profile.top_addresses:
        assert corpus.count(re_escape(address)).total_matches == count


def re_escape(text: str) -> str:
    import re

    return re.escape(text)


def test_bursts_are_computed_for_iso_timestamps_too() -> None:
    """Windows event exports carry ISO stamps, not Zeek epochs. The same two sessions
    must come out; before this the profile silently had no burst section on such logs."""
    lines = [*ZEEK_HEADER]
    for offset in [*range(0, 40, 5), *range(3600, 3640, 5)]:
        hh, mm, ss = 8 + offset // 3600, (offset % 3600) // 60, offset % 60
        lines.append(_zeek(f"2026-09-07T{hh:02d}:{mm:02d}:{ss:02d}Z", f"C{offset:012d}",
                           "10.12.34.56", f"{'a9f2c7e4b1d8':.12}{offset:04d}.t.tunnel.net",
                           "TXT", "-"))
    profile = build_profile(Corpus({"dns.log": lines}))
    assert [b.events for b in profile.bursts] == [8, 8]
    assert profile.bursts[0].start == "2026-09-07T08:00:00"


def test_file_names_are_not_counted_as_domains() -> None:
    """`cmd.exe` matches the domain shape. On a host log it would top a list the prompt
    labels "most-queried domains"; the profile filters file extensions, the extract=domain
    recogniser deliberately does not (it must stay identical to its grep mirror)."""
    from soc_poc.aggregation import ENTITY_PATTERNS
    lines = [f"2026-09-07T08:00:{i:02d}Z\tWKS-1\tC:\\Windows\\cmd.exe\tevil.example.net" for i in range(50)]
    profile = build_profile(Corpus({"w.log": lines}))
    assert [d for d, _ in profile.top_domains] == ["example.net"]
    assert "cmd.exe" in ENTITY_PATTERNS["domain"].findall(lines[0])
