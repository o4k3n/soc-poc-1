"""The commander's contract: the brief it synthesizes.

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


class StepLedgerEntry(BaseModel):
    """Audit row per investigative step: what was asked, why, and what came back.

    `reproduce` is the point of this table. It is the shell command that re-runs the step
    against the same files, so an operator can check any claim in the brief in seconds
    rather than taking it on trust. Under the previous architecture the equivalent row said
    "worker dns-0031 read slice 31 and reported 2 findings", which is only checkable by
    reading the transcript and re-running a GPU.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    step: int
    action: str
    reasoning: str
    expectation: str
    result: str
    reproduce: str = ""
    error: str = ""


class InvestigationBrief(BaseModel):
    """What lands on the operator's desk."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: str
    generated_at: str
    alert_ref: AlertRef
    body: BriefBody
    step_ledger: list[StepLedgerEntry] = Field(default_factory=list)
    # Content in the logs that looked like it was addressing an AI system. An injection
    # attempt is itself a detection signal, so it is surfaced to the operator rather
    # than quietly filtered.
    injection_signals: list[dict[str, str]] = Field(default_factory=list)
    iterations_used: int = 0
    # How many actions the commander spent. Paired with the step ledger this is the whole
    # cost of the investigation, and every one of them is reproducible from the ledger.
    steps_taken: int = 0
    # Lines in the case. Under the sweep architecture the comparable number was
    # slices_swept, which claimed total coverage; this claims only the size of the corpus
    # that was searchable, which is the honest version of the same statement.
    lines_available: int = 0
    terminal_state: str = ""
    # Stamped by code, not written by the commander. A graceful abort ends in DONE --
    # synthesis really did complete -- so without this field the artifact looks like a
    # finished investigation. The commander is also asked to record the abort in
    # coverage_gaps, but asking a model to disclose a limitation is not a guarantee;
    # this is.
    aborted_by_operator: bool = False
    unresolved_citations: list[str] = Field(default_factory=list)
    # Entries that are not references at all -- a run emitted
    # "... (representative sample) ..." into a raw_line_refs array. Kept apart from
    # unresolved_citations because they are a different failure: an unresolvable reference
    # is one a reader could try to chase, prose in a citation field is not.
    malformed_citations: list[str] = Field(default_factory=list)
    # Evidence and timeline entries the commander wrote with no line reference at all.
    # Stamped by code, non-blocking: some claims are legitimately uncitable ("no
    # host-level telemetry was in scope"). But in the first real run the correlation was
    # perfect -- every false statement in the brief was uncited and every cited statement
    # was true -- so the operator should be able to see which claims cannot be checked.
    uncited_claims: list[str] = Field(default_factory=list)
