"""Parse a model's JSON reply into a typed object, or say precisely what was wrong.

Guided decoding should make this trivial -- the grammar constrains the token stream to
the schema. It is still wrapped defensively, because "should" is doing real work in
that sentence: backends fall back, a stop token can truncate a response mid-object, and
a model with a chat template that emits a preamble will happily wrap valid JSON in
prose.

The error strings here are fed back to the model verbatim on the single retry, so they
are written to be actionable by a reader rather than tidy for a log.
"""

from __future__ import annotations

import json
from typing import TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class ParseFailure(ValueError):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def _strip_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[-1]
        if stripped.rstrip().endswith("```"):
            stripped = stripped.rstrip()[: -len("```")]
    return stripped.strip()


def parse_model_json(text: str, model: type[T]) -> T:
    """Return a validated `model`, or raise ParseFailure with per-field problems."""
    candidate = _strip_fences(text)
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise ParseFailure(
            [
                f"Response was not valid JSON ({exc.msg} at line {exc.lineno} column "
                f"{exc.colno}). Return one JSON object and nothing else."
            ]
        ) from exc

    if not isinstance(payload, dict):
        raise ParseFailure(["Response must be a single JSON object, not a bare value or list."])

    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        problems = [
            f"field {'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()
        ]
        raise ParseFailure(problems) from exc
