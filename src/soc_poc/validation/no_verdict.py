"""Structural guarantee: no model in this system can render a verdict.

The commander enriches an investigation; the external detector owns the decision. A
prompt saying so is a courtesy. The defense is that the output schema has nowhere to
put a verdict, and this module makes that a startup-time assertion rather than a
convention someone breaks in six months while adding "just a severity hint".

Importing this module runs the check against every model-facing output schema. If a
banned field is added, the process fails to start. That is the intended behaviour: the
alternative is a brief that quietly overrules the alert.

Code-owned structures (schemas/brief.py::AlertRef) are exempt by construction -- they
are never handed to a model as an output schema, so they are not passed to this check.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

# Substrings, matched case-insensitively against field names. Deliberately blunt: a
# false positive here costs one rename, a false negative costs the whole premise.
BANNED_FIELD_SUBSTRINGS: tuple[str, ...] = (
    "verdict",
    "disposition",
    "severity",
    "risk",
    "score",
    "malicious",
    "benign",
    "threat_level",
    "priority",
    "classification",
    "recommend",
    "remediation",
    "conclusion",
    "decision",
    "triage",
    "escalat",
    "true_positive",
    "false_positive",
    "resolution",
    "confidence_overall",
)


class VerdictFieldError(AssertionError):
    """Raised at import time when an output schema grows a decision field."""


def _walk_property_names(node: Any, path: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for name, sub in node.get("properties", {}).items():
            found.append((name, f"{path}.{name}" if path else name))
            found.extend(_walk_property_names(sub, f"{path}.{name}" if path else name))
        for key in ("items", "additionalProperties"):
            sub = node.get(key)
            if isinstance(sub, dict):
                found.extend(_walk_property_names(sub, path))
        for key in ("anyOf", "oneOf", "allOf"):
            for sub in node.get(key, []) or []:
                found.extend(_walk_property_names(sub, path))
    return found


def assert_no_verdict_fields(model: type[BaseModel]) -> None:
    """Fail loudly if `model` gives a model anywhere to write a decision."""
    from soc_poc.schemas.jsonschema import schema_for

    offenders = [
        (name, path)
        for name, path in _walk_property_names(schema_for(model))
        if any(banned in name.lower() for banned in BANNED_FIELD_SUBSTRINGS)
    ]
    if offenders:
        details = ", ".join(f"{path} (matched on {name!r})" for name, path in offenders)
        raise VerdictFieldError(
            f"{model.__name__} exposes decision-shaped field(s) to a model: {details}. "
            "The external alert's status is authoritative; this system enriches and "
            "never overrules. Remove the field or, if it is genuinely code-owned, keep "
            "it out of the model-facing schema."
        )


def assert_all_output_schemas_clean() -> None:
    """Run the check over every schema this system hands to a model."""
    from soc_poc.schemas.brief import BriefBody, CommanderPlan
    from soc_poc.schemas.grunt import GruntReport

    for model in (BriefBody, CommanderPlan, GruntReport):
        assert_no_verdict_fields(model)


# Enforced on import of soc_poc.validation.no_verdict, which soc_poc.orchestrator
# imports. There is no path to running an investigation that skips this.
assert_all_output_schemas_clean()
