"""A scoped slice of raw log lines: the only log data a grunt ever sees.

Every line carries a stable reference (`dns_resolver.log:L142`). The grunt is required
to cite those references; validation/citations.py then checks each cited reference
against *this* slice, which is why a slice is an addressable object rather than a blob
of text pasted into a prompt.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class LogLine(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ref: str  # "<file>:L<n>", 1-based
    text: str


class LogSlice(BaseModel):
    """Envelope metadata travels with the data, not in the prose around it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    slice_id: str
    file: str
    source: str
    host: str
    time_range: str
    reason: str  # why this slice is being shown to this grunt
    start_line: int
    end_line: int
    lines: list[LogLine] = Field(default_factory=list)

    def refs(self) -> set[str]:
        return {line.ref for line in self.lines}
