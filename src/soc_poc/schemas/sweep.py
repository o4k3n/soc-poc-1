"""The sweep directive: what the commander tells every grunt to look for.

This is the whole of the commander's influence over what gets read. It does not choose
slices -- every slice is read regardless -- it chooses *what counts as relevant* in them.

The directive is written from the alert alone. The commander never sees a log line before
issuing it, which is the point: its idea of relevance comes from the detector's claim, not
from having skimmed the data and formed an opinion.

`relevance_criteria` is deliberately prose and deliberately wider than `indicators`. If a
grunt only matched the literal indicator strings this would be grep with a GPU attached;
the value of putting a model on each slice is that it can recognise the thing the alert is
*about* when it appears in a form nobody listed.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class SweepDirective(BaseModel):
    """Guided-decoding target for the TASKING state."""

    model_config = ConfigDict(extra="forbid")

    # The detector's claim, restated. Gives the grunts context for what they are serving
    # without handing them the whole alert envelope.
    alert_restatement: str
    # Concrete strings worth matching on: domains, IPs, hostnames, ports, record types.
    indicators: list[str] = Field(default_factory=list)
    # Prose. What would make a line worth reporting even if it matches no indicator.
    relevance_criteria: str
    # What to ignore. Without this the tunnel-shaped haystack reports itself.
    explicitly_irrelevant: list[str] = Field(default_factory=list)
    # Free text ("2026-08-14T09:00Z/2026-08-14T11:00Z") or empty for no constraint.
    time_window: str
