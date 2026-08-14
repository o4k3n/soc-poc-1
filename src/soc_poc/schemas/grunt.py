"""The grunt contract: what a sweeping worker is told, and what it must return.

Every slice in the case is read by one grunt, so most grunts find nothing. That shapes
the schema in two ways that matter:

  * **`relevant` is a first-class field.** "I read these 70 lines and none of them bear on
    the alert" is the common answer, and it has to be cheap to say and cheap to render.
    Collapsed together, those answers are what makes the brief's coverage claim true.
  * **Findings are aggregates, never line dumps.** A grunt that matches 400 lines reports
    a count and a handful of representative references. Returning 400 refs would blow the
    commander's context in a single slice, and it would not tell the operator anything the
    count and the endpoints do not.

The cap on `representative_refs` is enforced twice: declared here, and re-checked in
validation/citations.py, because a grammar constrains shape and cannot count.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

# Enough to show the operator the pattern and its endpoints; few enough that a hundred
# slices' worth of findings still fits in the commander's context.
MAX_REPRESENTATIVE_REFS = 5


class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Finding(BaseModel):
    """One aggregate observation about a slice."""

    model_config = ConfigDict(extra="forbid")

    description: str
    # How many lines in THIS slice match this finding. The commander sums these across
    # slices to get volume, which is the number that distinguishes a tunnel from a typo.
    match_count: int
    # At most MAX_REPRESENTATIVE_REFS, each resolvable inside this slice.
    representative_refs: list[str] = Field(default_factory=list)
    # Endpoints of the pattern within the slice, so the commander can build a timeline
    # without being handed every line.
    first_ref: str
    last_ref: str
    confidence: Confidence


class NegativeFinding(BaseModel):
    """An explicit "I looked for X here and it was not present".

    Load-bearing in a sweep: with total coverage, the negatives are what turn silence into
    evidence of absence rather than absence of evidence.
    """

    model_config = ConfigDict(extra="forbid")

    checked_for: str
    result: str


class SliceMetadata(BaseModel):
    """The grunt's own account of what it was handed. Cross-checked against the slice the
    orchestrator actually sent -- a mismatch means the model lost the plot."""

    model_config = ConfigDict(extra="forbid")

    slice_id: str
    file: str
    lines_examined: int


class GruntReport(BaseModel):
    """Guided-decoding target for one swept slice."""

    model_config = ConfigDict(extra="forbid")

    slice_metadata: SliceMetadata
    # False means "nothing here bears on the alert". Findings must then be empty; the
    # orchestrator collapses these into a single coverage line for the commander.
    relevant: bool
    findings: list[Finding] = Field(default_factory=list)
    checked_for: list[NegativeFinding] = Field(default_factory=list)
