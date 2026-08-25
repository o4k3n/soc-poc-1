"""Messages between components. The only way anything talks to anything.

There is no shared mutable state in this system. The commander does not hold a
reference to a grunt's working set; a grunt does not see sibling reports, prior
iterations, or the alert beyond what its tasking message carries. Each grunt task is an
isolated unit of work with its own context, which is what makes it a supervised Task in
the Elixir port and what makes the transcript reconstructable.

Failures are messages too. `GruntFailure` is a value that flows back to the commander
alongside successful reports -- an exception is never allowed to cross an agent
boundary, because a lost task that nobody records is exactly the kind of hole this
system is supposed to make impossible.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from soc_poc.schemas.action import InvestigativeAction
from soc_poc.schemas.directive import TaskDirective
from soc_poc.schemas.grunt import GruntReport
from soc_poc.schemas.slice import LogSlice


class GruntTasking(BaseModel):
    """Everything one grunt is given. Nothing else reaches it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str
    investigation_id: str
    iteration: int
    instruction: str
    # The hypothesis in play, carried as its own field so the worker knows what
    # question it is serving without the commander's reasoning bleeding into the task
    # text -- and so the transcript records intent separately for later analysis.
    commander_intent: str
    # What counts as relevant for this task. Under the sweep architecture the commander
    # wrote this once and every worker in the round shared it. A close_read is dispatched
    # one at a time for one question, so it is now built per task by the orchestrator:
    # indicators come from the alert's entities (exact strings by construction, which is
    # what validation/citations.py needs to check a description against the line it cites)
    # and relevance_criteria is the commander's question verbatim.
    directive: TaskDirective
    data_slice: LogSlice


class GruntSuccess(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    outcome: Literal["report"] = "report"
    task_id: str
    iteration: int
    slice_id: str
    instruction: str
    commander_intent: str
    report: GruntReport
    attempts: int


class GruntFailure(BaseModel):
    """An explicit record of work that did not produce a usable report.

    `reason` is one of a small closed set so the commander prompt can describe the
    failure honestly, and so failure modes are countable across the corpus later.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    outcome: Literal["failure"] = "failure"
    task_id: str
    iteration: int
    slice_id: str
    instruction: str
    commander_intent: str
    # "aborted" covers work cancelled by `abort.py --hard`. Cancelled work is still
    # recorded: the commander (and the reader of the transcript) must be able to tell
    # ground that was never examined from ground that was examined and found empty.
    reason: Literal["timeout", "transport", "schema", "citations", "internal", "aborted"]
    detail: str
    attempts: int
    validation_errors: list[str] = Field(default_factory=list)


GruntOutcome = GruntSuccess | GruntFailure


class ActionResult(BaseModel):
    """Result of one INVESTIGATING call: the next action, or why there is none.

    A failure here ends the investigation rather than degrading it. Unlike a failed
    drill-down round under the old sweep architecture -- where the sweep had already
    gathered everything the brief strictly needed -- there is no background pass here. If
    the commander cannot say what to look at next, nothing has been looked at.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    action: InvestigativeAction | None = None
    error: str = ""
    attempts: int = 0
