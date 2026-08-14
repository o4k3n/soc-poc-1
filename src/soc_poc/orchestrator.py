"""The orchestrator: an explicit state machine over an immutable context.

Shape notes, because the shape is the deliverable:

  * `InvestigationContext` is frozen. Every handler returns a *new* context. There is
    no investigation state in a local variable of an async function, which is what
    makes the transcript a complete account of the run.
  * `run()` is a loop: look at the state, call its handler, assert the transition is
    legal, log it, repeat until terminal. Adding a state means adding a handler and an
    edge in states.py, not threading another flag through a call chain.
  * `_registry` maps task_id -> asyncio.Task for in-flight work. It is the one piece of
    mutable machinery, it is explicitly named, and it is empty outside a
    DISPATCHED/COLLECTING window. In the Elixir port it is a `Registry`; the handlers
    are `gen_statem` callbacks and the tasks are supervised under a Task.Supervisor.
  * Failures are values. A grunt task that times out, dies, or cannot cite its slice
    becomes a `GruntFailure` in `context.outcomes` and is shown to the commander as
    unexamined ground. Nothing is silently dropped.

Importing this module imports validation.no_verdict, which asserts at import time that
no model-facing schema has grown a decision field.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from soc_poc import commander as commander_agent
from soc_poc.config import AppConfig
from soc_poc.control import AbortMode, read_abort
from soc_poc.grunt import run_grunt_task
from soc_poc.llm.base import LLMClient
from soc_poc.loader import all_known_refs
from soc_poc.messages import GruntFailure, GruntOutcome, GruntTasking
from soc_poc.progress import NullProgress, ProgressSink
from soc_poc.schemas.alert import Alert
from soc_poc.schemas.brief import (
    AlertRef,
    BriefBody,
    InvestigationBrief,
    TaskLedgerEntry,
)
from soc_poc.chunking import FileInventory
from soc_poc.schemas.slice import LogSlice
from soc_poc.schemas.sweep import SweepDirective
from soc_poc.states import (
    TERMINAL_STATES,
    InvestigationState,
    assert_legal_transition,
)
from soc_poc.transcript import TranscriptLogger
from soc_poc.validation import no_verdict  # noqa: F401  (import-time schema assertion)
from soc_poc.validation.citations import unresolved_brief_citations
from soc_poc.validation.injection import InjectionSignal

# Backstop on top of the HTTP client's own timeout. The HTTP timeout should fire first;
# this catches a task wedged somewhere else (parsing, a retry loop, a hung socket).
TASK_TIMEOUT_MARGIN_S = 30.0


class InvestigationContext(BaseModel):
    """The whole investigation, in one immutable value."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: str
    state: InvestigationState
    iteration: int = 0
    pending_taskings: tuple[GruntTasking, ...] = ()
    outcomes: tuple[GruntOutcome, ...] = ()
    directive: SweepDirective | None = None
    swept_slices: int = 0
    request_followup: bool = False
    iteration_cap_hit: bool = False
    aborted_by_operator: bool = False
    failure_reason: str = ""
    body: BriefBody | None = None


class RunResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    terminal_state: InvestigationState
    brief: InvestigationBrief | None
    failure_reason: str = ""


class Orchestrator:
    def __init__(
        self,
        *,
        config: AppConfig,
        commander_client: LLMClient,
        grunt_client: LLMClient,
        transcript: TranscriptLogger,  # required: an unlogged run is not constructible
        alert: Alert,
        inventory: list[FileInventory],
        catalog: dict[str, LogSlice],
        injection_signals: list[InjectionSignal],
        investigation_id: str | None = None,
        progress: ProgressSink | None = None,
        run_dir: Path | None = None,
    ) -> None:
        self._config = config
        self._run = config.run
        self._commander = commander_client
        self._grunt = grunt_client
        self._transcript = transcript
        self._alert = alert
        self._inventory = inventory
        self._catalog = catalog
        self._injection_signals = injection_signals
        self._progress = progress or NullProgress()
        # Where abort.py leaves its sentinel. None disables abort entirely (library use).
        self._run_dir = run_dir
        self._known_refs = all_known_refs(catalog)
        self.investigation_id = investigation_id or f"inv-{uuid.uuid4().hex[:12]}"
        # The Registry: in-flight work, addressable by task id.
        self._registry: dict[str, asyncio.Task[GruntOutcome]] = {}
        # Backpressure. A sweep dispatches every slice, which on a large case is hundreds
        # of tasks; without this they all open HTTP connections at once against a server
        # doing max-num-seqs 8. It also gives a graceful abort a meaningful boundary --
        # "let the running ones finish" means something when only N are running.
        self._slots = asyncio.Semaphore(config.run.max_concurrent_grunts)

    # -- driver -----------------------------------------------------------------------

    async def run(self) -> RunResult:
        context = InvestigationContext(
            investigation_id=self.investigation_id, state=InvestigationState.RECEIVED
        )
        self._transcript.log_event(
            "investigation_started",
            {
                "alert_id": self._alert.alert_id,
                "detector": self._alert.detector,
                "alert_status": self._alert.status,
                "slices_available": sorted(self._catalog),
                "max_iterations": self._run.max_iterations,
            },
        )

        while context.state not in TERMINAL_STATES:
            previous = context.state
            # Abort is polled at the state boundary, where the machine is quiescent:
            # nothing is in flight, the context is a complete value, and routing to
            # SYNTHESIZING or stopping outright is a normal transition rather than an
            # interruption. SYNTHESIZING itself is exempt -- see states.py.
            abort = self._check_abort(context)
            context = abort if abort is not None else await self._step(context)
            assert_legal_transition(previous, context.state)
            self._transcript.log_state_transition(
                from_state=previous.value,
                to_state=context.state.value,
                iteration=context.iteration,
                note=context.failure_reason,
            )
            self._progress.state_changed(
                previous.value, context.state.value, context.iteration
            )

        brief = self._assemble_brief(context) if context.body is not None else None
        self._transcript.log_event(
            "investigation_finished",
            {
                "terminal_state": context.state.value,
                "iterations_used": context.iteration,
                "outcomes": len(context.outcomes),
                "swept_slices": context.swept_slices,
                "failures": sum(1 for o in context.outcomes if isinstance(o, GruntFailure)),
                # Countable across the corpus later: which failure modes actually bite.
                "failure_reasons": sorted(
                    {o.reason for o in context.outcomes if isinstance(o, GruntFailure)}
                ),
                "failure_reason": context.failure_reason,
            },
        )
        return RunResult(
            terminal_state=context.state, brief=brief, failure_reason=context.failure_reason
        )

    # -- abort ------------------------------------------------------------------------

    # States where nothing is in flight, so an abort can be honoured by returning a new
    # context and nothing leaks. DISPATCHED and COLLECTING own live asyncio tasks and
    # handle abort themselves in _on_collecting; SYNTHESIZING runs to completion.
    _ABORTABLE_AT_BOUNDARY = frozenset(
        {
            InvestigationState.RECEIVED,
            InvestigationState.TASKING,
            InvestigationState.PLANNING,
        }
    )

    def _check_abort(self, context: InvestigationContext) -> InvestigationContext | None:
        if self._run_dir is None or context.state not in self._ABORTABLE_AT_BOUNDARY:
            return None
        request = read_abort(self._run_dir)
        if request is None:
            return None
        return self._abort_context(context, request.mode)

    def _abort_context(
        self, context: InvestigationContext, mode: AbortMode
    ) -> InvestigationContext:
        """Route an abort to the right state.

        A graceful abort still owes the operator a brief -- that is the whole difference
        between it and --hard. But synthesizing over zero collected reports spends two
        minutes to say nothing, so an abort that lands before any outcome exists stops
        outright regardless of mode.
        """
        hard = mode is AbortMode.HARD or not context.outcomes
        reason = (
            f"aborted by operator ({mode.value})"
            + ("" if context.outcomes else "; no reports had been collected")
        )
        self._transcript.log_event(
            "abort_requested",
            {
                "mode": mode.value,
                "state": context.state.value,
                "outcomes_collected": len(context.outcomes),
                "brief_will_be_written": not hard,
            },
        )
        self._progress.note(
            f"abort ({mode.value}): "
            + (
                "stopping without a brief"
                if hard
                else f"synthesizing from {len(context.outcomes)} collected report(s)"
            )
        )
        return context.model_copy(
            update={
                "state": InvestigationState.ABORTED_BY_OPERATOR
                if hard
                else InvestigationState.ABORTING,
                "aborted_by_operator": True,
                "failure_reason": reason,
            }
        )

    async def _step(self, context: InvestigationContext) -> InvestigationContext:
        handlers = {
            InvestigationState.RECEIVED: self._on_received,
            InvestigationState.TASKING: self._on_tasking,
            InvestigationState.SWEEPING: self._on_sweeping,
            InvestigationState.PLANNING: self._on_planning,
            InvestigationState.DISPATCHED: self._on_dispatched,
            InvestigationState.COLLECTING: self._on_collecting,
            InvestigationState.ABORTED_ITERATION_CAP: self._on_cap_reached,
            InvestigationState.ABORTING: self._on_aborting,
            InvestigationState.SYNTHESIZING: self._on_synthesizing,
        }
        return await handlers[context.state](context)

    # -- handlers ---------------------------------------------------------------------

    async def _on_received(self, context: InvestigationContext) -> InvestigationContext:
        return context.model_copy(update={"state": InvestigationState.TASKING})

    async def _on_tasking(self, context: InvestigationContext) -> InvestigationContext:
        """The commander reads the alert and says what would be relevant.

        No log content reaches it here -- only the alert and a bare file inventory. This
        is the whole of its influence over what the sweep looks for; it does not get to
        choose what is read, because a negative finding is only worth something if
        everything was read.
        """
        result = await commander_agent.write_directive(
            client=self._commander,
            transcript=self._transcript,
            run_config=self._run,
            alert=self._alert,
            inventory=self._inventory,
            total_slices=len(self._catalog),
            progress=self._progress,
        )
        if not result.ok or result.directive is None:
            # Terminal: without a notion of relevance the workers cannot sweep, and a
            # sweep that reports everything is the same as one that reports nothing.
            return context.model_copy(
                update={
                    "state": InvestigationState.FAILED_PLANNING,
                    "failure_reason": f"could not write a sweep directive: {result.error}",
                }
            )

        directive = result.directive
        self._transcript.log_event(
            "directive_accepted",
            {
                "alert_restatement": directive.alert_restatement,
                "indicators": directive.indicators,
                "relevance_criteria": directive.relevance_criteria,
                "explicitly_irrelevant": directive.explicitly_irrelevant,
                "time_window": directive.time_window,
                "slices_to_sweep": len(self._catalog),
            },
        )
        self._progress.note(
            f"directive: {len(directive.indicators)} indicator(s); sweeping "
            f"{len(self._catalog)} slice(s)"
        )
        return context.model_copy(
            update={"state": InvestigationState.SWEEPING, "directive": directive}
        )

    async def _on_sweeping(self, context: InvestigationContext) -> InvestigationContext:
        """Build one task per slice. Every line in the case gets read by someone.

        There is no selection step and no budget: the task list is the catalog. Cost is
        bounded by the semaphore, not by dropping data on the floor.
        """
        assert context.directive is not None
        taskings = tuple(
            GruntTasking(
                task_id=f"{self.investigation_id}-sweep-{index:04d}",
                investigation_id=self.investigation_id,
                iteration=context.iteration,
                instruction=(
                    "Sweep this slice: read every line and report which of them, if any, "
                    "bear on the investigation described above."
                ),
                commander_intent=context.directive.alert_restatement,
                directive=context.directive,
                data_slice=log_slice,
            )
            for index, log_slice in enumerate(self._catalog.values(), start=1)
        )
        self._transcript.log_event(
            "sweep_dispatched",
            {"slices": len(taskings), "concurrency": self._run.max_concurrent_grunts},
        )
        self._launch(taskings)
        return context.model_copy(
            update={
                "state": InvestigationState.COLLECTING,
                "pending_taskings": taskings,
                "swept_slices": context.swept_slices + len(taskings),
                # The sweep is one pass. Whether to look closer is decided after it, in
                # PLANNING, from what came back.
                "request_followup": True,
            }
        )

    async def _on_planning(self, context: InvestigationContext) -> InvestigationContext:
        """Drill-down: the commander asks for closer reads of slices the sweep flagged."""
        assert context.directive is not None
        result = await commander_agent.plan_drilldown(
            client=self._commander,
            transcript=self._transcript,
            run_config=self._run,
            alert=self._alert,
            directive=context.directive,
            catalog=self._catalog,
            outcomes=list(context.outcomes),
            iteration=context.iteration,
            progress=self._progress,
        )

        if not result.ok or result.plan is None:
            # The sweep already produced everything the brief strictly needs, so a failed
            # drill-down is a degraded round, not a failed investigation.
            return context.model_copy(
                update={
                    "state": InvestigationState.SYNTHESIZING,
                    "failure_reason": (
                        f"drill-down round {context.iteration} failed: {result.error}"
                    ),
                }
            )

        plan = result.plan
        taskings = tuple(
            GruntTasking(
                task_id=f"{self.investigation_id}-i{context.iteration}-t{index}",
                investigation_id=self.investigation_id,
                iteration=context.iteration,
                instruction=task.instruction,
                commander_intent=task.commander_intent,
                directive=context.directive,
                data_slice=self._catalog[task.slice_id],
            )
            for index, task in enumerate(plan.tasks)
        )
        self._transcript.log_event(
            "plan_accepted",
            {
                "iteration": context.iteration,
                "rationale": plan.planning_rationale,
                "tasks": [
                    {
                        "task_id": t.task_id,
                        "slice_id": t.data_slice.slice_id,
                        "instruction": t.instruction,
                        "commander_intent": t.commander_intent,
                    }
                    for t in taskings
                ],
                "request_followup": plan.request_followup,
            },
        )

        if not taskings:
            return context.model_copy(
                update={"state": InvestigationState.SYNTHESIZING, "request_followup": False}
            )
        return context.model_copy(
            update={
                "state": InvestigationState.DISPATCHED,
                "pending_taskings": taskings,
                "request_followup": plan.request_followup,
            }
        )

    def _launch(self, taskings: tuple[GruntTasking, ...]) -> None:
        """Register one asyncio task per tasking, each gated by the concurrency semaphore.

        Every task is created immediately -- the registry is the complete record of work
        in flight for this round -- but only max_concurrent_grunts of them hold a slot and
        talk to the server at a time. On a 500-slice sweep that is the difference between
        backpressure and 500 open sockets.
        """

        async def _bounded(tasking: GruntTasking) -> GruntOutcome:
            async with self._slots:
                return await run_grunt_task(
                    tasking, self._grunt, self._run, self._transcript, self._progress
                )

        for tasking in taskings:
            self._registry[tasking.task_id] = asyncio.create_task(
                _bounded(tasking), name=tasking.task_id
            )

    async def _on_dispatched(self, context: InvestigationContext) -> InvestigationContext:
        """Launch a drill-down round. The sweep launches from _on_sweeping instead.

        Dispatch and collection are separate states so the transcript shows work leaving
        the commander before results come back, which is the distinction that matters when
        reconstructing a run.
        """
        self._launch(context.pending_taskings)
        self._transcript.log_event(
            "tasks_dispatched",
            {"iteration": context.iteration, "task_ids": list(self._registry)},
        )
        return context.model_copy(update={"state": InvestigationState.COLLECTING})

    async def _on_collecting(self, context: InvestigationContext) -> InvestigationContext:
        timeout = self._grunt.config.request_timeout_s + TASK_TIMEOUT_MARGIN_S
        by_id = {tasking.task_id: tasking for tasking in context.pending_taskings}
        collected: list[GruntOutcome] = []

        hard_abort = False
        for task_id, task in self._registry.items():
            tasking = by_id[task_id]

            # A hard abort cancels the rest of the round rather than waiting it out.
            # A graceful abort deliberately does not: letting in-flight readers finish
            # is most of the difference between the two modes, and a grunt that is
            # already running costs seconds.
            if not hard_abort and self._run_dir is not None:
                request = read_abort(self._run_dir)
                if request is not None and request.mode is AbortMode.HARD:
                    hard_abort = True

            # Only work still running is cancelled. A task that already finished has a
            # real report sitting in it, and throwing that away to label it "aborted"
            # would be losing evidence the system paid for -- and lying about it in the
            # ledger, which is worse.
            if hard_abort and not task.done():
                task.cancel()
                collected.append(
                    self._task_failure(tasking, "aborted", "cancelled by operator (--hard)")
                )
                continue

            try:
                collected.append(await asyncio.wait_for(task, timeout=timeout))
            except asyncio.TimeoutError:
                task.cancel()
                collected.append(
                    self._task_failure(tasking, "timeout", f"exceeded {timeout:.0f}s")
                )
            except Exception as exc:  # noqa: BLE001 - the boundary is the point
                # An exception must never propagate out of a worker into the
                # orchestrator; it becomes a record the commander is shown.
                collected.append(
                    self._task_failure(tasking, "internal", f"{type(exc).__name__}: {exc}")
                )
        self._registry.clear()

        outcomes = context.outcomes + tuple(collected)
        self._transcript.log_event(
            "tasks_collected",
            {
                "iteration": context.iteration,
                "collected": len(collected),
                "failed": sum(1 for o in collected if isinstance(o, GruntFailure)),
            },
        )

        next_iteration = context.iteration + 1

        # An abort seen during collection decides the run's fate now that the registry
        # is drained and every task has a record.
        if self._run_dir is not None:
            request = read_abort(self._run_dir)
            if request is not None:
                return self._abort_context(
                    context.model_copy(
                        update={
                            "outcomes": outcomes,
                            "pending_taskings": (),
                            "iteration": next_iteration,
                        }
                    ),
                    request.mode,
                )

        if context.request_followup and next_iteration >= self._run.max_iterations:
            return context.model_copy(
                update={
                    "state": InvestigationState.ABORTED_ITERATION_CAP,
                    "outcomes": outcomes,
                    "pending_taskings": (),
                    "iteration": next_iteration,
                    "iteration_cap_hit": True,
                }
            )
        if context.request_followup:
            return context.model_copy(
                update={
                    "state": InvestigationState.PLANNING,
                    "outcomes": outcomes,
                    "pending_taskings": (),
                    "iteration": next_iteration,
                }
            )
        return context.model_copy(
            update={
                "state": InvestigationState.SYNTHESIZING,
                "outcomes": outcomes,
                "pending_taskings": (),
                "iteration": next_iteration,
            }
        )

    async def _on_aborting(self, context: InvestigationContext) -> InvestigationContext:
        """Graceful abort acknowledged: write up what we have."""
        return context.model_copy(update={"state": InvestigationState.SYNTHESIZING})

    async def _on_cap_reached(self, context: InvestigationContext) -> InvestigationContext:
        """Hitting the cap is not an error; it is a coverage gap the brief must state."""
        self._transcript.log_event(
            "iteration_cap_reached",
            {"max_iterations": self._run.max_iterations, "iterations_used": context.iteration},
        )
        return context.model_copy(update={"state": InvestigationState.SYNTHESIZING})

    async def _on_synthesizing(self, context: InvestigationContext) -> InvestigationContext:
        swept = context.swept_slices
        note = (
            f"COVERAGE: the sweep read all {swept} slice(s) of this case -- every line of "
            f"every log file was examined by a worker. You then used {context.iteration} "
            f"of {self._run.max_iterations} allowed drill-down round(s). Slices reported "
            f"as finding nothing were genuinely read and genuinely empty; that is "
            f"evidence, not a gap."
        )
        if context.iteration_cap_hit:
            note += (
                " You requested a further round and the hard cap stopped you, so lines "
                "you wanted read were not read. Say so in coverage_gaps."
            )
        if context.aborted_by_operator:
            note += (
                " The operator aborted this investigation before it finished. Anything "
                "not already read was not read; record that in coverage_gaps so nobody "
                "mistakes an interrupted run for a complete one."
            )
        body, error = await commander_agent.synthesize_brief(
            client=self._commander,
            transcript=self._transcript,
            run_config=self._run,
            alert=self._alert,
            directive=context.directive,
            outcomes=list(context.outcomes),
            coverage_note=note,
            progress=self._progress,
        )
        if body is None:
            return context.model_copy(
                update={
                    "state": InvestigationState.FAILED_SYNTHESIS,
                    "failure_reason": error,
                }
            )
        return context.model_copy(update={"state": InvestigationState.DONE, "body": body})

    # -- helpers ----------------------------------------------------------------------

    def _task_failure(self, tasking: GruntTasking, reason: str, detail: str) -> GruntFailure:
        return GruntFailure(
            task_id=tasking.task_id,
            iteration=tasking.iteration,
            slice_id=tasking.data_slice.slice_id,
            instruction=tasking.instruction,
            commander_intent=tasking.commander_intent,
            reason=reason,  # type: ignore[arg-type]
            detail=detail,
            attempts=0,
        )

    def _assemble_brief(self, context: InvestigationContext) -> InvestigationBrief:
        """Code owns the parts a model must not.

        AlertRef is built here by copying the inbound alert. The status the operator
        reads is the status the detector emitted -- it did not pass through a model on
        the way to this file.
        """
        assert context.body is not None
        body = context.body

        cited: list[str] = []
        for event in body.timeline:
            cited.extend(event.raw_line_refs)
        for hypothesis in body.hypotheses:
            for evidence in (*hypothesis.supporting_evidence, *hypothesis.contradicting_evidence):
                cited.extend(evidence.raw_line_refs)

        ledger = [
            TaskLedgerEntry(
                task_id=outcome.task_id,
                iteration=outcome.iteration,
                slice_id=outcome.slice_id,
                instruction=outcome.instruction,
                commander_intent=outcome.commander_intent,
                outcome=outcome.outcome,
                detail=(
                    f"{outcome.reason}: {outcome.detail}"
                    if isinstance(outcome, GruntFailure)
                    else (
                        f"{sum(f.match_count for f in outcome.report.findings)} matching "
                        f"line(s) in {len(outcome.report.findings)} finding(s)"
                        if outcome.report.relevant
                        else "swept, nothing relevant"
                    )
                    + f", {outcome.attempts} attempt(s)"
                ),
            )
            for outcome in context.outcomes
        ]

        return InvestigationBrief(
            investigation_id=self.investigation_id,
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            alert_ref=AlertRef(
                alert_id=self._alert.alert_id,
                detector=self._alert.detector,
                rule_name=self._alert.rule_name,
                status=self._alert.status,
                severity=self._alert.severity,
            ),
            body=body,
            task_ledger=ledger,
            injection_signals=[signal.model_dump() for signal in self._injection_signals],
            iterations_used=context.iteration,
            slices_swept=context.swept_slices,
            terminal_state=context.state.value,
            aborted_by_operator=context.aborted_by_operator,
            unresolved_citations=unresolved_brief_citations(cited, self._known_refs),
        )
