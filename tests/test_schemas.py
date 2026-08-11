"""Schema shape and the no-verdict guarantee."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from soc_poc.schemas.brief import BriefBody, CommanderPlan
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


@pytest.mark.parametrize("model", [BriefBody, CommanderPlan, GruntReport])
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
