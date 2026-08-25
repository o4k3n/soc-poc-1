"""A computed profile of the case, handed to the commander before it asks anything.

Everything here is counted, not inferred. No model sees the data to produce it, so
nothing in it can be a hallucination -- it is arithmetic over the corpus, and a reader
can re-derive every number with `grep` and `sort`.

The point is to put on the first page the things six runs of LLM sweeping never found:

  * **rare templates.** The NS delegation that ties the tunnel domain to attacker
    infrastructure occurs twice in 5,586 lines. Every sweep walked straight past it. A
    frequency table cannot: two occurrences among hundreds of a repeated shape is exactly
    what "rare" means.
  * **entropy outliers.** Encoded labels score near the top of the character-entropy
    range. This deliberately surfaces the benign lookalikes too -- antivirus hash lookups
    and CDN cache keys score the same, and pretending otherwise is how a heuristic becomes
    a false positive. What separates them is reported alongside: how many distinct source
    addresses use each shape. One host is a tunnel; forty hosts is a vendor service.
  * **activity gaps.** Bursts separated by idle are a different signature from a fixed
    interval, and briefs have repeatedly described one as the other.

Format-agnostic on purpose. It knows about timestamps, IP-shaped tokens, domain-shaped
tokens and character entropy -- nothing about Zeek, Suricata or DNS. A profiler that has
to be taught each format is a profiler that is wrong on the format nobody taught it.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from soc_poc.corpus import Corpus

_ISO_TS = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:\.\d+)?Z?\b")
_EPOCH_TS = re.compile(r"^(\d{10})\.\d{3,6}\b")
_SYSLOG_TS = re.compile(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9_-]+\.){1,}[a-z]{2,}\b", re.IGNORECASE)
_LONG_TOKEN = re.compile(r"\b[a-z0-9]{16,}\b", re.IGNORECASE)

# A shape seen this many times or fewer is worth showing individually.
RARE_TEMPLATE_MAX = 3
# ...but only in a file big enough for "rare" to mean anything. In an eight-line DHCP log
# three lines qualify, which says nothing except that the file is small. Below this the
# commander is told the line count and can simply read the whole thing.
RARE_MIN_EVENTS = 40
# Bursts: a gap this many times the median inter-event gap starts a new session.
BURST_GAP_FACTOR = 8.0

# Templating runs in three ordered passes, and the order is the whole trick.
#
# Pass 1 collapses things recognisable by shape alone. Pass 2 collapses identifiers, which
# can only be recognised by counting the whole file first. Pass 3 collapses bare numbers,
# and it has to go LAST: run it early and `cd7yikpgnxglwk3ysx` becomes `cd<N>yikpgnxglwk<N>ysx`
# -- three fragments, two of them too short to look like an identifier, and the leftovers
# differ on every line. That is exactly how 300 identically-shaped DKIM records each became
# their own "rare" template and buried the NS delegation this file exists to find.
_STRUCTURE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (_ISO_TS, "<TS>"),
    (_SYSLOG_TS, "<TS>"),
    (re.compile(r"^\d{10}\.\d{3,6}"), "<TS>"),
    (_IP, "<IP>"),
    (re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I), "<MAC>"),
    # Domains are values, not structure. Collapsing them is what lets "a query for NS"
    # stand out from five thousand queries for TXT, which is the whole job here. The
    # actual domain values are reported separately in top_domains.
    (_DOMAIN, "<DOMAIN>"),
)
_NUMBER_RULE = re.compile(r"\d+")

# Identifier-shaped leftovers: per-connection uids, encoded payloads and the like. Zeek's
# uid is 13 characters, which slipped under an earlier 16-character threshold and made
# every line its own template -- so everything looked rare and nothing was.
_ID_CANDIDATE = re.compile(r"\b[A-Za-z0-9]{8,}\b")


def _prenormalise(line: str) -> str:
    """Pass 1 only: shapes. Numbers survive so pass 2 can still see whole identifiers."""
    for pattern, replacement in _STRUCTURE_RULES:
        line = pattern.sub(replacement, line)
    return line


def _unique_tokens(prenormalised: list[str]) -> set[str]:
    """Tokens that occur once across the file, counted on pass-1 output.

    Entropy was the obvious test for "is this an identifier" and it is the wrong one:
    these uids come from a small alphabet and score *below* ordinary protocol words like
    INTERNET, so half normalised and half did not. Uniqueness needs no threshold, and it
    leaves `C_INTERNET` alone for free -- a token that appears 5,000 times is structure.

    Counting and substituting must see the same text, which is why both run between passes
    1 and 3 rather than on either side of them.
    """
    counts: Counter[str] = Counter()
    for line in prenormalised:
        counts.update(_ID_CANDIDATE.findall(line))
    return {token for token, count in counts.items() if count == 1}


def _templatize(line: str, unique: set[str] | None = None) -> str:
    line = _prenormalise(line)
    if unique:
        line = _ID_CANDIDATE.sub(
            lambda m: "<ID>" if m.group(0) in unique else m.group(0), line
        )
    return _NUMBER_RULE.sub("<N>", line).strip()[:160]


def _entropy(token: str) -> float:
    """Shannon entropy per character. Random hex ~4 bits, English words ~3."""
    if not token:
        return 0.0
    counts = Counter(token.lower())
    total = len(token)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _humanise(stamp: str) -> str:
    """Render a stamp for a reader. Display only -- gap arithmetic uses the raw form.

    Zeek writes bare Unix epochs. `1786697233` tells a reader nothing, and asking a model
    to reason about the interval between two ten-digit integers invites it to guess. The
    raw value stays authoritative everywhere it is compared or sorted.
    """
    if stamp.isdigit() and len(stamp) == 10:
        return datetime.fromtimestamp(int(stamp), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    return stamp


def _timestamp(line: str) -> str | None:
    for pattern in (_ISO_TS, _EPOCH_TS, _SYSLOG_TS):
        match = pattern.search(line)
        if match:
            return match.group(1)
    return None


class RareShape(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    template: str
    occurrences: int
    refs: list[str] = Field(default_factory=list)


class EntropyGroup(BaseModel):
    """A family of high-entropy tokens sharing a suffix, with who uses it.

    `distinct_sources` is the field that matters. Encoded tunnel labels and antivirus
    hash lookups are indistinguishable by entropy alone; they are trivially separable by
    how many hosts emit them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    suffix: str
    occurrences: int
    mean_entropy: float
    mean_length: int
    distinct_sources: int
    sources: list[str] = Field(default_factory=list)
    example_refs: list[str] = Field(default_factory=list)


class Burst(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    start: str
    end: str
    events: int


class FileProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    file: str
    lines: int
    time_range: str
    top_templates: list[tuple[str, int]] = Field(default_factory=list)
    rare_shapes: list[RareShape] = Field(default_factory=list)


class CaseProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    files: list[FileProfile] = Field(default_factory=list)
    top_domains: list[tuple[str, int]] = Field(default_factory=list)
    top_addresses: list[tuple[str, int]] = Field(default_factory=list)
    entropy_groups: list[EntropyGroup] = Field(default_factory=list)
    bursts: list[Burst] = Field(default_factory=list)
    burst_subject: str = ""


def _is_event(line: str) -> bool:
    """Comment/preamble lines are format metadata, not events.

    Zeek writes eight `#`-prefixed header lines. Each occurs exactly once, so a naive
    rarity ranking puts all eight above the genuinely rare *events* -- which is how the
    first version of this buried the NS delegation, the one shape it was written to find,
    under `#separator \\x09`.
    """
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#")


def _profile_file(name: str, lines: list[str]) -> FileProfile:
    unique = _unique_tokens([_prenormalise(line) for line in lines if _is_event(line)])
    templates = Counter(_templatize(line, unique) for line in lines if _is_event(line))
    first_ref: dict[str, list[str]] = defaultdict(list)
    for number, line in enumerate(lines, start=1):
        if _is_event(line):
            key = _templatize(line, unique)
            if len(first_ref[key]) < 3:
                first_ref[key].append(f"{name}:L{number}")

    stamps = [t for t in (_timestamp(line) for line in lines) if t]
    events = sum(templates.values())
    rare = [
        RareShape(template=template, occurrences=count, refs=first_ref[template])
        for template, count in templates.items()
        if count <= RARE_TEMPLATE_MAX
    ]
    rare.sort(key=lambda r: r.occurrences)
    return FileProfile(
        file=name,
        lines=len(lines),
        time_range=(
            f"{_humanise(min(stamps))}/{_humanise(max(stamps))}" if stamps else "unknown"
        ),
        top_templates=[(t, c) for t, c in templates.most_common(5)],
        rare_shapes=rare[:12] if events >= RARE_MIN_EVENTS else [],
    )


def _entropy_groups(files: dict[str, list[str]]) -> list[EntropyGroup]:
    """Group high-entropy tokens by the domain suffix they appear under."""
    groups: dict[str, dict] = defaultdict(
        lambda: {"entropies": [], "lengths": [], "sources": Counter(), "refs": []}
    )
    for name, lines in files.items():
        for number, line in enumerate(lines, start=1):
            for token in _LONG_TOKEN.findall(line):
                entropy = _entropy(token)
                if entropy < 3.2:  # ordinary words and hostnames sit below this
                    continue
                domains = _DOMAIN.findall(line)
                suffix = ""
                for domain in domains:
                    if token.lower() in domain.lower():
                        parts = domain.split(".")
                        suffix = ".".join(parts[-3:]) if len(parts) >= 3 else domain
                        break
                key = suffix or "(no domain context)"
                bucket = groups[key]
                bucket["entropies"].append(entropy)
                bucket["lengths"].append(len(token))
                addresses = _IP.findall(line)
                if addresses:
                    bucket["sources"][addresses[0]] += 1
                if len(bucket["refs"]) < 3:
                    bucket["refs"].append(f"{name}:L{number}")
                break  # one token per line is enough to characterise it

    result = [
        EntropyGroup(
            suffix=key,
            occurrences=len(bucket["entropies"]),
            mean_entropy=round(sum(bucket["entropies"]) / len(bucket["entropies"]), 2),
            mean_length=round(sum(bucket["lengths"]) / len(bucket["lengths"])),
            distinct_sources=len(bucket["sources"]),
            sources=[ip for ip, _ in bucket["sources"].most_common(4)],
            example_refs=bucket["refs"],
        )
        for key, bucket in groups.items()
        if bucket["entropies"]
    ]
    result.sort(key=lambda g: -g.occurrences)
    return result[:8]


def _bursts(files: dict[str, list[str]], subject: str) -> tuple[list[Burst], str]:
    """Session structure for the busiest high-entropy source, from timestamp gaps.

    Bursty and periodic are different signatures and briefs keep conflating them. This
    reports the shape rather than asserting either.
    """
    if not subject:
        return [], ""
    stamps: list[str] = []
    for lines in files.values():
        for line in lines:
            if subject in line:
                stamp = _timestamp(line)
                if stamp:
                    stamps.append(stamp)
    if len(stamps) < 4:
        return [], subject
    stamps.sort()

    numeric = [float(s) if s.replace(".", "").isdigit() else None for s in stamps]
    if any(v is None for v in numeric):
        return [], subject  # non-epoch stamps: gap arithmetic is not safe here

    gaps = [b - a for a, b in zip(numeric, numeric[1:])]
    ordered = sorted(gaps)
    median = ordered[len(ordered) // 2] or 1.0
    threshold = median * BURST_GAP_FACTOR

    bursts: list[Burst] = []
    start_index = 0
    for index, gap in enumerate(gaps):
        if gap > threshold:
            bursts.append(
                Burst(
                    start=_humanise(stamps[start_index]),
                    end=_humanise(stamps[index]),
                    events=index - start_index + 1,
                )
            )
            start_index = index + 1
    bursts.append(
        Burst(
            start=_humanise(stamps[start_index]),
            end=_humanise(stamps[-1]),
            events=len(stamps) - start_index,
        )
    )
    return bursts, subject


def build_profile(corpus: Corpus) -> CaseProfile:
    files = {name: corpus._files[name] for name in corpus.file_names}  # noqa: SLF001

    domains: Counter[str] = Counter()
    addresses: Counter[str] = Counter()
    for lines in files.values():
        for line in lines:
            for domain in _DOMAIN.findall(line):
                parts = domain.lower().split(".")
                if len(parts) >= 2:
                    domains[".".join(parts[-2:])] += 1
            for address in _IP.findall(line):
                addresses[address] += 1

    groups = _entropy_groups(files)
    # Bursts are computed for the most concentrated high-entropy group: the one shape
    # used by fewest sources is the one worth characterising in time.
    concentrated = sorted(
        (g for g in groups if g.distinct_sources), key=lambda g: (g.distinct_sources, -g.occurrences)
    )
    subject = concentrated[0].suffix if concentrated else ""
    bursts, burst_subject = _bursts(files, subject)

    return CaseProfile(
        files=[_profile_file(name, lines) for name, lines in files.items()],
        top_domains=domains.most_common(8),
        top_addresses=addresses.most_common(8),
        entropy_groups=groups,
        bursts=bursts[:12],
        burst_subject=burst_subject,
    )
