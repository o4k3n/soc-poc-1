"""The commander's contracts: the plan it emits, and the brief it synthesizes.

Read this next to validation/no_verdict.py. The single most important property of
`BriefBody` is a field that is *absent*: there is no verdict, disposition, severity,
risk score, or recommended-action field anywhere in it. A model cannot flip a decision
that the schema gives it no place to write. The external alert's status is authoritative
and arrives in the finished brief via `AlertRef`, which orchestrator code fills in by
copying the inbound alert -- it is never generated, never round-tripped, never offered
to a model as an output field.

That absence is checked at import time, not by code review: see
validation/no_verdict.py::assert_no_verdict_fields.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------------


class PlannedTask(BaseModel):
    """One narrow unit of work the commander wants a grunt to perform."""

    model_config = ConfigDict(extra="forbid")

    instruction: str
    # The hypothesis in play, kept as its own field rather than folded into the
    # instruction: the grunt is told what the commander is trying to find out, so it
    # can report a useful negative, and the transcript records intent separately from
    # task text for later analysis of where the hierarchy loses information.
    commander_intent: str
    slice_id: str  # must name a slice from the catalog offered to the commander


class CommanderPlan(BaseModel):
    """Guided-decoding target for a planning round."""

    model_config = ConfigDict(extra="forbid")

    planning_rationale: str
    tasks: list[PlannedTask] = Field(default_factory=list)
    # The commander may drill down further; the orchestrator decides whether it is
    # allowed to, based on the iteration cap.
    request_followup: bool


# --------------------------------------------------------------------------------
# Brief
# --------------------------------------------------------------------------------


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: str
    description: str
    raw_line_refs: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str
    raw_line_refs: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    """A hypothesis with both sides shown. Contradicting evidence is a required field
    precisely because it is the part a confident model likes to omit."""

    model_config = ConfigDict(extra="forbid")

    statement: str
    supporting_evidence: list[Evidence] = Field(default_factory=list)
    contradicting_evidence: list[Evidence] = Field(default_factory=list)


class Drilldown(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str
    where_to_look: str
    why: str


class BriefBody(BaseModel):
    """Everything the commander is allowed to write. Note what is not here."""

    model_config = ConfigDict(extra="forbid")

    investigation_narrative: str
    timeline: list[TimelineEvent] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    suggested_drilldowns: list[Drilldown] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------------
# Assembled artifact (code-owned fields + model-owned body)
# --------------------------------------------------------------------------------


class AlertRef(BaseModel):
    """Copied verbatim from the inbound alert by the orchestrator.

    This exists so the operator reads the detector's own status next to the
    enrichment. No model sees this as an output field, so no model can change it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    alert_id: str
    detector: str
    rule_name: str
    status: str
    severity: str
    note: str = "Alert status and severity are owned by the external detector and are reproduced here unchanged."


class TaskLedgerEntry(BaseModel):
    """Audit row per dispatched grunt task, including the ones that failed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str
    iteration: int
    slice_id: str
    instruction: str
    commander_intent: str
    outcome: str  # "report" | "failure"
    detail: str = ""


class InvestigationBrief(BaseModel):
    """What lands on the operator's desk."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: str
    generated_at: str
    alert_ref: AlertRef
    body: BriefBody
    task_ledger: list[TaskLedgerEntry] = Field(default_factory=list)
    # Content in the logs that looked like it was addressing an AI system. An injection
    # attempt is itself a detection signal, so it is surfaced to the operator rather
    # than quietly filtered.
    injection_signals: list[dict[str, str]] = Field(default_factory=list)
    iterations_used: int = 0
    terminal_state: str = ""
    # Stamped by code, not written by the commander. A graceful abort ends in DONE --
    # synthesis really did complete -- so without this field the artifact looks like a
    # finished investigation. The commander is also asked to record the abort in
    # coverage_gaps, but asking a model to disclose a limitation is not a guarantee;
    # this is.
    aborted_by_operator: bool = False
    unresolved_citations: list[str] = Field(default_factory=list)
