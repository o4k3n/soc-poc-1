"""Rescue a tool-call-shaped reply into a valid action, deterministically.

**Why this exists.** On this build (vLLM 0.24.0, gpt-oss-120b MXFP4), guided decoding is
not reliably applied to the commander's first turn of an investigation step. Measured, on
the real dns-tunnel prompt, three requests each: `response_format` 0/3 conformant,
`structured_outputs` 0/3, legacy `guided_json` 0/3 -- while the *same schema* on the retry
prompt, and on a short prompt, comes back perfectly conformant every time. The response
carries `reasoning` separately and puts unconstrained text in `content`, so the grammar
genuinely did not engage rather than the client mis-reading a channel.

What comes back instead is always the same idea in tool-call clothing:

    {"action": "count",  "action_input": "t\\.api-sync-telemetry\\.net"}
    {"action": "search", "action_args": {"regex": "...", "case_insensitive": true}}
    {"action": "count",  "parameters": {"regex": "..."}}
    {"action": "search", "action_input": "10\\.12\\.34\\.56", "path": "dhcp.log"}

The verb is right, the argument is right, the envelope is a tool call. The prompt describes
six verbs and gpt-oss is heavily trained to reach for its harmony tool-call channel when it
sees a menu like that.

**Why coerce rather than only retry.** The retry does recover -- but it doubles the calls
per step, and in the first real run a step whose retry also came back tool-shaped ended the
investigation at step three with a budget of twenty-four. Coercion is not the fragile
model-side parsing this architecture avoids elsewhere: it is our code, over a closed set of
key names, and everything it produces still goes through `validate_action` before anything
executes. A coerced action that does not validate is rejected exactly like any other.

Anything not recognised here falls through untouched to the normal parse-failure retry.
Nothing is guessed: if no argument can be found for the verb, the field stays empty and the
validator asks for it.
"""

from __future__ import annotations

import re
from typing import Any

# Where a tool-call-shaped reply hides the actual argument.
_NESTED_KEYS = ("action_input", "action_args", "parameters", "params", "arguments", "input")
# Aliases seen for each real field, in preference order.
_ALIASES: dict[str, tuple[str, ...]] = {
    "pattern": ("pattern", "regex", "query", "search", "term", "expression"),
    "file": ("file", "path", "filename", "log", "target"),
    "field": ("field", "column", "col"),
    "extract": ("extract", "entity", "entities"),
    "ref": ("ref", "reference", "line_ref"),
    "question": ("question", "prompt", "ask"),
    "reasoning": ("reasoning", "rationale", "why", "thought"),
    "expectation": ("expectation", "expect", "expected"),
    "start_line": ("start_line", "start", "from_line", "first_line"),
    "end_line": ("end_line", "end", "to_line", "last_line"),
}
# Verbs that take their single positional argument as a regex rather than a filename.
_PATTERN_VERBS = ("search", "count", "tally", "timeline", "stats")


def _flatten(payload: dict[str, Any]) -> dict[str, Any]:
    """Merge one level of tool-call nesting up into the top level."""
    flat = {k: v for k, v in payload.items() if k not in _NESTED_KEYS}
    for key in _NESTED_KEYS:
        nested = payload.get(key)
        if isinstance(nested, dict):
            for name, value in nested.items():
                flat.setdefault(name, value)
        elif isinstance(nested, str) and nested:
            # A bare positional argument. Which field it is depends on the verb: for
            # search/count it is the regex, for the range verbs it is the filename.
            verb = str(payload.get("action", "")).lower()
            flat.setdefault("pattern" if verb in _PATTERN_VERBS else "file", nested)
    return flat


# `L975` on its own: a line number the model wrote without the file it came from.
_BARE_LINE = re.compile(r"^L?(\d+)$")


def repair_ref(payload: dict[str, Any]) -> dict[str, Any]:
    """Put the file back on a reference that lost it.

    A run died on this. The commander emitted `{"action": "context", "ref": "L975",
    "file": "dns.log"}`; `validate_action` rejected it, the model produced the identical
    thing on the retry, and the loop gave up with 16 of 24 steps unspent. The correct
    reference was fully determined by the action's own fields the whole time -- there is
    nothing to infer, only something to concatenate.

    Only fires when `file` is present, so it can never invent a filename.
    """
    ref, file = str(payload.get("ref", "")), str(payload.get("file", ""))
    if not file or ":" in ref:
        return payload
    match = _BARE_LINE.match(ref.strip())
    if not match:
        return payload
    return {**payload, "ref": f"{file}:L{match.group(1)}"}


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def coerce_action_payload(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Map a tool-call-shaped reply onto the action schema, or None if it is not one.

    Returns None when the payload already looks like a well-formed action, so the normal
    path is untouched and this can only ever fire on something that would have failed.
    """
    if not isinstance(payload, dict) or "action" not in payload:
        return None
    # Already conformant enough for pydantic: leave it alone, except for a reference that
    # lost its file -- that is repairable in place and would otherwise cost the whole run.
    if {"reasoning", "expectation"} <= set(payload) and not (
        set(payload) & set(_NESTED_KEYS)
    ):
        repaired = repair_ref(payload)
        return repaired if repaired != payload else None

    flat = _flatten(repair_ref(payload))
    out: dict[str, Any] = {"action": flat.get("action", "")}
    for field, names in _ALIASES.items():
        value = next((flat[name] for name in names if flat.get(name) not in (None, "")), "")
        out[field] = _as_int(value) if field.endswith("_line") else str(value)

    # The model was not asked for these in the shape it produced, so say so rather than
    # inventing analyst reasoning it never wrote. The transcript shows the raw reply.
    if not out["reasoning"]:
        out["reasoning"] = "(recovered from a tool-call-shaped reply; see transcript)"
    if not out["expectation"]:
        out["expectation"] = "(not stated in the model's reply)"
    return out
