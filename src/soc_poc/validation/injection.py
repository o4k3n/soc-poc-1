"""Cheap post-pass: does this log content appear to be addressing an AI system?

STUB QUALITY, and deliberately so. This is a keyword/regex heuristic, not a detector.
It exists because the architecture wants the seam, and because of a point worth stating
plainly: log content that tries to talk to a model is *itself a detection signal*. An
attacker who plants "ignore previous instructions" in a user-agent string has told you
something about their intent. So hits are surfaced to the operator on the brief, not
silently stripped.

What this is NOT: a defense. The defenses are structural and live elsewhere --
no verdict field to flip (schemas/brief.py + validation/no_verdict.py), citations that
make every claim checkable (validation/citations.py), and an alert status that never
round-trips through a model (orchestrator stamps AlertRef by copying the input).
Assume this scanner can be evaded; the system should still be safe when it is.

Future work (out of scope): move to a classifier, score by position/context, and feed
hits back to the telemetry pipeline as their own pattern type.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

# Each pattern is paired with why it is suspicious, so the operator sees reasoning
# rather than a bare regex name.
_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "instruction_override",
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)", re.I),
        "text attempts to override earlier instructions",
    ),
    (
        "role_marker",
        re.compile(r"(^|\W)(system|assistant|user)\s*:\s*(you|please|act|respond)", re.I),
        "text imitates a chat role marker",
    ),
    (
        "prompt_reference",
        re.compile(r"(system\s+prompt|your\s+instructions|developer\s+message)", re.I),
        "text refers to the model's own prompt",
    ),
    (
        "model_address",
        re.compile(r"\b(you\s+are\s+an?\s+(ai|assistant|language\s+model)|dear\s+(ai|assistant))\b", re.I),
        "text addresses an AI system directly",
    ),
    (
        "output_steering",
        re.compile(r"(mark\s+(this|it)\s+as|classify\s+(this|it)\s+as|report\s+(this|it)\s+as)\s+\w+", re.I),
        "text tries to steer a classification or report field",
    ),
    (
        "control_tokens",
        re.compile(r"(<\|[a-z_]+\|>|\[/?INST\]|<<SYS>>)", re.I),
        "text contains chat-template control tokens",
    ),
    (
        "tool_call_shape",
        re.compile(r"\"?(tool_calls?|function_call)\"?\s*[:=]\s*[\[{]", re.I),
        "text is shaped like a tool call",
    ),
)


class InjectionSignal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    signal: str
    why: str
    location: str  # line ref if known, otherwise a description of the scanned region
    excerpt: str


def scan_for_ai_directed_content(text: str, location: str) -> list[InjectionSignal]:
    """Scan one chunk of untrusted text. `location` is usually a line ref."""
    signals: list[InjectionSignal] = []
    for name, pattern, why in _PATTERNS:
        match = pattern.search(text)
        if match:
            start = max(0, match.start() - 40)
            signals.append(
                InjectionSignal(
                    signal=name,
                    why=why,
                    location=location,
                    excerpt=text[start : match.end() + 40].strip()[:240],
                )
            )
    return signals
