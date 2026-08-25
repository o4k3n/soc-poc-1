"""What a worker is told to treat as relevant, and why it is here at all.

This was the sweep directive: the commander wrote one from the alert, and every worker in
the round carried the same copy. There is no sweep now, and no model writes this any more.
The orchestrator builds one per `close_read` in code (`orchestrator._close_read`):

  * `indicators` are the alert's entity values -- exact strings by construction. That
    matters: `validation/citations.py` checks a worker's *description* against the lines
    it cited, and that check only works with exact indicator strings. It caught a worker
    describing an antivirus reputation lookup as tunnel traffic, which is precisely the
    decoy the case was built to plant.
  * `relevance_criteria` is the commander's question, verbatim.

Kept as a struct rather than flattened into the tasking because the grunt prompt and the
citation validator both read it, and because the worker's contract should not change
shape just because its caller did.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TaskDirective(BaseModel):
    """What one worker is told to look for. Built by code, not by a model."""

    model_config = ConfigDict(extra="forbid")

    # The detector's claim, restated. Gives the worker context for what it is serving
    # without handing it the whole alert envelope.
    alert_restatement: str
    # Concrete strings worth matching on: domains, IPs, hostnames, ports, record types.
    indicators: list[str] = Field(default_factory=list)
    # Prose. What would make a line worth reporting even if it matches no indicator.
    relevance_criteria: str
    # What to ignore. Without this the tunnel-shaped haystack reports itself.
    explicitly_irrelevant: list[str] = Field(default_factory=list)
    # Free text ("2026-08-14T09:00Z/2026-08-14T11:00Z") or empty for no constraint.
    time_window: str = ""
