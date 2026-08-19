"""The grunt contract: what a sweeping worker is told, and what it must return.

Every slice in the case is read by one grunt, so most grunts find nothing. That shapes
the schema in two ways that matter:

  * **A check that found something is not a negative.** `CheckedFor.found` makes the
    difference explicit, and the validator refuses a report that claims irrelevance while
    recording a hit.
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
    # At most MAX_REPRESENTATIVE_REFS, each resolvable inside this slice. The cap is
    # declared to the grammar (json_schema_extra, not a pydantic constraint) so the model
    # physically cannot emit a sixth -- while validation/citations.py keeps checking it,
    # so a backend that stops honouring maxItems cannot quietly uncap the contract.
    representative_refs: list[str] = Field(
        default_factory=list, json_schema_extra={"maxItems": MAX_REPRESENTATIVE_REFS}
    )
    # Endpoints of the pattern within the slice, so the commander can build a timeline
    # without being handed every line.
    first_ref: str
    last_ref: str
    confidence: Confidence


class CheckedFor(BaseModel):
    """The record of a check: what was looked for, and whether it was there.

    Load-bearing in a sweep: with total coverage, the negatives are what turn silence
    into evidence of absence rather than absence of evidence.

    `found` exists because free text was not enough. In the first real run a worker wrote
    `{"checked_for": "DHCP lease for 10.12.34.56", "result": "Found in line dhcp.log:L4"}`
    into a report it had marked irrelevant -- a true positive, phrased as a check. The
    aggregation layer dropped it and the brief went out saying the lease did not exist.
    A boolean makes that contradiction detectable (see validation/citations.py) instead of
    something a downstream string match has to guess at.
    """

    model_config = ConfigDict(extra="forbid")

    checked_for: str
    found: bool
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
    checked_for: list[CheckedFor] = Field(default_factory=list)
