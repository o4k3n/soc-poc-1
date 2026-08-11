"""The grunt contract: what a worker is told, and what it must return.

The report schema is enforced by guided decoding (shape) plus Python validation
(meaning). The meaning that matters here: an observation without a resolvable raw-line
reference is not an observation, it is an assertion, and this system does not traffic
in unciteable assertions.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str
    # Required by validation/citations.py to be non-empty and to resolve inside the
    # slice this grunt was given. The grammar cannot check that; Python does.
    raw_line_refs: list[str] = Field(default_factory=list)
    confidence: Confidence


class NegativeFinding(BaseModel):
    """An explicit "I looked for X in scope Y and it was not there".

    Negative findings are load-bearing for the operator: they turn silence into
    evidence of absence rather than absence of evidence.
    """

    model_config = ConfigDict(extra="forbid")

    checked_for: str
    scope: str
    result: str


class AnomalyFlag(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str
    raw_line_refs: list[str] = Field(default_factory=list)
    why_unusual: str


class SliceMetadata(BaseModel):
    """The grunt's own account of what it was handed. Cheap cross-check against the
    slice the orchestrator actually sent -- a mismatch means the model lost the plot."""

    model_config = ConfigDict(extra="forbid")

    slice_id: str
    file: str
    lines_examined: int


class GruntReport(BaseModel):
    """Guided-decoding target for a grunt worker."""

    model_config = ConfigDict(extra="forbid")

    slice_metadata: SliceMetadata
    observations: list[Observation] = Field(default_factory=list)
    negative_findings: list[NegativeFinding] = Field(default_factory=list)
    anomalies_flagged: list[AnomalyFlag] = Field(default_factory=list)
