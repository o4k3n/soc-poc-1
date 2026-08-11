"""Turn a pydantic model into a JSON Schema a grammar compiler will actually accept.

Pydantic emits `$defs` + `$ref` for nested models and decorates fields with keywords
(`format`, `default`, `minItems`, ...) that structured-output backends handle
inconsistently -- xgrammar in particular rejects or silently ignores parts of the
schema, and "silently ignores" is the dangerous half. So we hand the backend a flat,
closed, boring schema and re-check everything else in Python afterwards.

Rule of thumb for this codebase: the grammar guarantees *shape*, Python guarantees
*meaning*. Citations are meaning (see validation/citations.py).

VERIFY when you bump vLLM: backend capabilities move. If a newer xgrammar handles
$ref natively you can drop the inlining, but the stripped keywords should stay
stripped -- we do not want constraints that are enforced sometimes.
"""

from __future__ import annotations

import copy
from typing import Any

from pydantic import BaseModel

# Keywords stripped before the schema is sent to the model. Anything removed here is
# either cosmetic or must be enforced by a Python validator instead.
_STRIPPED_KEYWORDS = frozenset(
    {
        "default",
        "format",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "examples",
        "$comment",
    }
)


def _inline_refs(node: Any, defs: dict[str, Any], seen: tuple[str, ...] = ()) -> Any:
    """Replace every {"$ref": "#/$defs/X"} with a copy of X.

    Recursive model definitions would loop forever here; none of our schemas are
    recursive and we fail loudly rather than hang if one ever becomes so.
    """
    if isinstance(node, list):
        return [_inline_refs(item, defs, seen) for item in node]
    if not isinstance(node, dict):
        return node

    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        name = ref.split("/")[-1]
        if name in seen:
            raise ValueError(f"recursive schema definition {name!r} cannot be inlined")
        if name not in defs:
            raise ValueError(f"unresolvable $ref {ref!r}")
        merged = _inline_refs(copy.deepcopy(defs[name]), defs, seen + (name,))
        # Sibling keys alongside a $ref (e.g. description) win over the target's.
        for key, value in node.items():
            if key != "$ref":
                merged[key] = _inline_refs(value, defs, seen)
        return merged

    return {key: _inline_refs(value, defs, seen) for key, value in node.items()}


def _prune(node: Any) -> Any:
    if isinstance(node, list):
        return [_prune(item) for item in node]
    if not isinstance(node, dict):
        return node

    out = {k: _prune(v) for k, v in node.items() if k not in _STRIPPED_KEYWORDS}

    if out.get("type") == "object":
        # Closed by construction: an open object is a place for a model to invent a
        # field we swore did not exist (see validation/no_verdict.py).
        out["additionalProperties"] = False
        props = out.get("properties", {})
        # Guided decoding treats optional fields as "may omit", which in practice means
        # "will omit". Every property is required; emptiness is expressed with [] or "".
        out["required"] = list(props.keys())
    return out


def schema_for(model: type[BaseModel]) -> dict[str, Any]:
    """The JSON Schema handed to vLLM for guided decoding."""
    raw = model.model_json_schema()
    defs = raw.pop("$defs", {})
    inlined = _inline_refs(raw, defs)
    pruned = _prune(inlined)
    pruned.pop("$defs", None)
    return pruned
