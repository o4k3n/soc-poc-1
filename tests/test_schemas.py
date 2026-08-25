"""Schema shape and the no-verdict guarantee."""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel

from soc_poc.schemas.action import InvestigativeAction
from soc_poc.schemas.brief import BriefBody
from soc_poc.schemas.grunt import GruntReport
from soc_poc.schemas.jsonschema import schema_for
from soc_poc.validation.no_verdict import (
    VerdictFieldError,
    assert_all_output_schemas_clean,
    assert_no_verdict_fields,
)


def test_shipped_output_schemas_have_no_decision_fields() -> None:
    assert_all_output_schemas_clean()


@pytest.mark.parametrize("field", ["severity", "verdict", "risk_score", "recommended_action"])
def test_a_decision_field_fails_the_guard(field: str) -> None:
    """The guard is the reason nobody can quietly add 'just a severity hint'."""
    Sneaky = type("Sneaky", (BaseModel,), {"__annotations__": {field: str}})
    with pytest.raises(VerdictFieldError):
        assert_no_verdict_fields(Sneaky)


def test_nested_decision_field_is_also_caught() -> None:
    class Inner(BaseModel):
        disposition: str

    class Outer(BaseModel):
        items: list[Inner]

    with pytest.raises(VerdictFieldError):
        assert_no_verdict_fields(Outer)


@pytest.mark.parametrize("model", [BriefBody, InvestigativeAction, GruntReport])
def test_schemas_are_closed_and_fully_required(model: type[BaseModel]) -> None:
    schema = schema_for(model)
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])


def test_refs_are_inlined_and_unsupported_keywords_stripped() -> None:
    schema = schema_for(GruntReport)
    assert "$defs" not in schema
    rendered = repr(schema)
    assert "$ref" not in rendered
    for keyword in ("minItems", "default", "format"):
        assert keyword not in rendered
    # Nested object survived inlining with its own closure.
    assert schema["properties"]["slice_metadata"]["additionalProperties"] is False


def test_recursive_schema_is_rejected_rather_than_hanging() -> None:
    class Node(BaseModel):
        children: list["Node"] = []

    Node.model_rebuild()
    with pytest.raises(ValueError, match="recursive"):
        schema_for(Node)


def test_a_field_named_like_a_schema_keyword_survives() -> None:
    """A property called `pattern` is a field, not a regex constraint.

    The pruner filtered `properties` keys against the stripped-keyword set, so the action
    schema's `pattern` field -- the regex to search for -- was deleted from both
    `properties` and `required`. The grammar then correctly enforced a schema with no way
    to express a search term, and the first real run of the action loop died on step one
    with an empty pattern. Any field named `format`, `default`, `minimum` or `examples`
    would have gone the same way.
    """
    schema = schema_for(InvestigativeAction)
    assert "pattern" in schema["properties"]
    assert schema["properties"]["pattern"]["type"] == "string"
    assert "pattern" in schema["required"]


def test_constraint_keywords_are_still_stripped_where_they_are_constraints() -> None:
    """The fix must not turn the pruner off: these are keywords, not field names."""
    rendered = json.dumps(schema_for(GruntReport))
    assert "minItems" not in rendered  # a floor forces fabrication; see jsonschema.py
    assert "maxItems" in rendered  # a cap is safe, and xgrammar does enforce it
