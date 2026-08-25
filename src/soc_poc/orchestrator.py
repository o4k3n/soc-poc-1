"""The orchestrator: an explicit state machine over an immutable context.

Shape notes, because the shape is the deliverable:

  * `InvestigationContext` is frozen. Every handler returns a *new* context. There is
    no investigation state in a local variable of an async function, which is what
    makes the transcript a complete account of the run.
  * `run()` is a loop: look at the state, call its handler, assert the transition is
    legal, log it, repeat until terminal. Adding a state means adding a handler and an
    edge in states.py, not threading another flag through a call chain.
  * The commander proposes; this module disposes. An action is a data structure the model
    emits and the orchestrator executes -- the model never runs anything, and the set of
    things that CAN be run is the six verbs in schemas/action.py. That boundary is why
    there is no sandbox here: `corpus.search` takes a regex and returns lines from files
    already in memory.
  * Failures are values. A close_read that times out, dies, or cannot cite its slice
    becomes a recorded step with an error, shown to the commander on its next turn.
    Nothing is silently dropped.

`_registry` (task_id -> asyncio.Task) survives from the sweep architecture because
close_read still dispatches real work, but it now holds at most one task at a time. In the
Elixir port it is a `Registry`; the handlers are `gen_statem` callbacks and close_reads are
supervised under a Task.Supervisor.

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
from soc_poc.actions import execute_readonly, reproduce_command
from soc_poc.chunking import FileInventory
from soc_poc.config import AppConfig
from soc_poc.control import AbortMode, read_abort
from soc_poc.corpus import Corpus
from soc_poc.evidence import Evidence, Step
from soc_poc.grunt import run_grunt_task
from soc_poc.llm.base import LLMClient
from soc_poc.messages import GruntFailure, GruntSuccess, GruntTasking
from soc_poc.profiling import CaseProfile, build_profile
from soc_poc.progress import NullProgress, ProgressSink
from soc_poc.schemas.action import ActionKind, InvestigativeAction
from soc_poc.schemas.alert import Alert
from soc_poc.schemas.brief import (
    AlertRef,
    BriefBody,
    InvestigationBrief,
    StepLedgerEntry,
)
from soc_poc.schemas.directive import TaskDirective
from soc_poc.schemas.slice import LogLine, LogSlice
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

# A close_read is the one action that spends a worker, so the line range it may hand over
# is capped independently of the commander's request. Without this, "close_read
# dns.log:L1-L5586" would reinstate the sweep one action at a time.
MAX_CLOSE_READ_LINES = 120


class InvestigationContext(BaseModel):
    """The whole investigation, in one immutable value."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: str
    state: InvestigationState
    iteration: int = 0
    profile: CaseProfile | None = None
    # The action decided in INVESTIGATING and executed in EXECUTING. Carried on the
    # context rather than in a local so the transition between the two states is visible
    # in the transcript with its payload.
    pending_action: InvestigativeAction | None = None
    concluded: bool = False
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
        corpus: Corpus,
        inventory: list[FileInventory],
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
        self._corpus = corpus
        self._inventory = inventory
        self._injection_signals = injection_signals
        self._progress = progress or NullProgress()
        # Where abort.py leaves its sentinel. None disables abort entirely (library use).
        self._run_dir = run_dir
        # Straight from the corpus, not the inventory. The inventory is built by a
        # separate chunking pass, and an earlier version fell back to it in a way that
        # reported the file *count* as every file's line count -- a number the commander
        # would have used to choose line ranges.
        self._line_counts = corpus.line_counts()
        # The ledger of what was asked and shown. This is the run's memory AND its audit
        # trail; see evidence.py for why those are deliberately the same object.
        self._evidence = Evidence()
        self.investigation_id = investigation_id or f"inv-{uuid.uuid4().hex[:12]}"
        # The Registry: in-flight work, addressable by task id. At most one close_read.
        self._registry: dict[str, asyncio.Task[GruntSuccess | GruntFailure]] = {}

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
                "files_available": self._corpus.file_names,
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
                "steps_taken": len(self._evidence.steps),
                "steps_with_errors": sum(1 for s in self._evidence.steps if s.error),
                "refs_shown": len(self._evidence.shown_refs()),
                "failure_reason": context.failure_reason,
            },
        )
        return RunResult(
            terminal_state=context.state, brief=brief, failure_reason=context.failure_reason
        )

    # -- abort ------------------------------------------------------------------------

    # States where nothing is in flight, so an abort can be honoured by returning a new
    # context and nothing leaks. EXECUTING may own a live close_read and handles abort
    # itself; SYNTHESIZING runs to completion.
    _ABORTABLE_AT_BOUNDARY = frozenset(
        {
            InvestigationState.RECEIVED,
            InvestigationState.PROFILING,
            InvestigationState.INVESTIGATING,
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
        between it and --hard. But synthesizing over zero gathered steps spends two
        minutes to say nothing, so an abort that lands before any evidence exists stops
        outright regardless of mode.
        """
        hard = mode is AbortMode.HARD or not self._evidence.steps
        reason = (
            f"aborted by operator ({mode.value})"
            + ("" if self._evidence.steps else "; no evidence had been gathered")
        )
        self._transcript.log_event(
            "abort_requested",
            {
                "mode": mode.value,
                "state": context.state.value,
                "steps_taken": len(self._evidence.steps),
                "brief_will_be_written": not hard,
            },
        )
        self._progress.note(
            f"abort ({mode.value}): "
            + (
                "stopping without a brief"
                if hard
                else f"synthesizing from {len(self._evidence.steps)} step(s)"
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

    # Where an unexpected exception in each state should leave the machine. Every target
    # is a legal transition from its source; `assert_legal_transition` still checks.
    _CRASH_ROUTE: dict[InvestigationState, InvestigationState] = {
        # A step that blew up is one failed question, not a failed investigation. Hand the
        # commander the error and let it ask something else.
        InvestigationState.EXECUTING: InvestigationState.INVESTIGATING,
        InvestigationState.INVESTIGATING: InvestigationState.SYNTHESIZING,
        InvestigationState.PROFILING: InvestigationState.FAILED_INVESTIGATION,
        InvestigationState.SYNTHESIZING: InvestigationState.FAILED_SYNTHESIS,
    }

    async def _step(self, context: InvestigationContext) -> InvestigationContext:
        handlers = {
            InvestigationState.RECEIVED: self._on_received,
            InvestigationState.PROFILING: self._on_profiling,
            InvestigationState.INVESTIGATING: self._on_investigating,
            InvestigationState.EXECUTING: self._on_executing,
            InvestigationState.ABORTED_ITERATION_CAP: self._on_cap_reached,
            InvestigationState.ABORTING: self._on_aborting,
            InvestigationState.SYNTHESIZING: self._on_synthesizing,
        }
        try:
            return await handlers[context.state](context)
        except Exception as exc:  # noqa: BLE001 - the boundary is the point
            # "Failures are values" was only enforced at the worker boundary, and a bug in
            # a one-line display helper (`reproduce_command` on a malformed reference)
            # raised straight through this loop and ended a 21-step investigation with no
            # brief -- the single worst outcome the system can produce, because every one
            # of those steps was already paid for and recorded.
            #
            # The specific bug is fixed and validated against. This is the general rule it
            # should never have been able to break: a crash routes to a legal state, is
            # recorded, and the run still owes the operator whatever it had.
            return self._crash_context(context, exc)

    def _crash_context(
        self, context: InvestigationContext, exc: Exception
    ) -> InvestigationContext:
        detail = f"{type(exc).__name__}: {exc}"
        target = self._CRASH_ROUTE.get(context.state)
        if target is None:
            raise exc
        # Nothing gathered yet: there is no brief to salvage, so fail honestly rather than
        # synthesizing over an empty ledger.
        if target is InvestigationState.SYNTHESIZING and not self._evidence.steps:
            target = InvestigationState.FAILED_INVESTIGATION
        self._transcript.log_event(
            "handler_crashed",
            {
                "state": context.state.value,
                "routed_to": target.value,
                "error": detail,
                "steps_taken": len(self._evidence.steps),
            },
        )
        self._progress.note(f"  !! {context.state.value} raised {detail}")

        if target is InvestigationState.INVESTIGATING:
            # Record the crash as the step it was, so the commander sees it went wrong
            # rather than silently getting a turn back with nothing to show for it.
            action = context.pending_action
            if action is not None:
                self._evidence.add(
                    Step(
                        index=self._evidence.next_index,
                        action=action,
                        summary="this action could not be executed",
                        error=detail,
                    )
                )
            return context.model_copy(
                update={
                    "state": target,
                    "iteration": context.iteration + 1,
                    "pending_action": None,
                }
            )
        return context.model_copy(
            update={"state": target, "failure_reason": f"internal error: {detail}"}
        )

    # -- handlers ---------------------------------------------------------------------

    async def _on_received(self, context: InvestigationContext) -> InvestigationContext:
        return context.model_copy(update={"state": InvestigationState.PROFILING})

    async def _on_profiling(self, context: InvestigationContext) -> InvestigationContext:
        """Count the corpus. No model runs here, so nothing here can be a hallucination.

        This is the first page the commander reads, and on the dns-tunnel case it puts the
        NS delegation -- the single piece of evidence six full sweeps never once cited --
        on that page in under a second, because a shape occurring twice among 5,586 lines
        is rare by arithmetic and no noticing is required.
        """
        profile = build_profile(self._corpus)
        rare = sum(len(f.rare_shapes) for f in profile.files)
        self._transcript.log_event(
            "profile_built",
            {
                "files": [
                    {
                        "file": f.file,
                        "lines": f.lines,
                        "time_range": f.time_range,
                        "top_templates": f.top_templates,
                        "rare_shapes": [s.model_dump() for s in f.rare_shapes],
                    }
                    for f in profile.files
                ],
                "top_domains": profile.top_domains[:10],
                "top_addresses": profile.top_addresses[:10],
                "entropy_groups": [g.model_dump() for g in profile.entropy_groups],
                "bursts": [b.model_dump() for b in profile.bursts],
                "burst_subject": profile.burst_subject,
            },
        )
        self._progress.note(
            f"profile: {rare} rare shape(s), {len(profile.entropy_groups)} entropy "
            f"group(s), {len(profile.bursts)} activity burst(s)"
        )
        return context.model_copy(
            update={"state": InvestigationState.INVESTIGATING, "profile": profile}
        )

    async def _on_investigating(
        self, context: InvestigationContext
    ) -> InvestigationContext:
        """The commander asks one question."""
        assert context.profile is not None
        remaining = self._run.max_iterations - context.iteration
        result = await commander_agent.decide_action(
            client=self._commander,
            transcript=self._transcript,
            run_config=self._run,
            alert=self._alert,
            profile=context.profile,
            evidence=self._evidence,
            file_names=self._corpus.file_names,
            line_counts=self._line_counts,
            steps_remaining=remaining,
            steps_taken=len(self._evidence.steps),
            min_steps=self._run.min_steps_before_conclude,
            progress=self._progress,
        )

        if not result.ok or result.action is None:
            # Terminal only while there is nothing to write up. Once evidence exists, a
            # commander that cannot phrase its next question should still produce a brief
            # from what it has rather than throw the run away.
            if self._evidence.steps:
                return context.model_copy(
                    update={
                        "state": InvestigationState.SYNTHESIZING,
                        "failure_reason": (
                            f"could not decide action {context.iteration + 1}: "
                            f"{result.error}; synthesizing from "
                            f"{len(self._evidence.steps)} completed step(s)"
                        ),
                    }
                )
            return context.model_copy(
                update={
                    "state": InvestigationState.FAILED_INVESTIGATION,
                    "failure_reason": f"could not decide a first action: {result.error}",
                }
            )

        action = result.action
        self._transcript.log_event(
            "action_decided",
            {
                "step": self._evidence.next_index,
                "action": action.action.value,
                "reasoning": action.reasoning,
                "expectation": action.expectation,
                "pattern": action.pattern,
                "file": action.file,
                "ref": action.ref,
                "lines": f"{action.start_line}-{action.end_line}",
                "question": action.question,
                "reproduce": reproduce_command(action),
            },
        )
        self._progress.note(f"step {self._evidence.next_index}: {action.reasoning}")

        if action.action is ActionKind.CONCLUDE:
            return context.model_copy(
                update={"state": InvestigationState.SYNTHESIZING, "concluded": True}
            )
        return context.model_copy(
            update={"state": InvestigationState.EXECUTING, "pending_action": action}
        )

    async def _on_executing(self, context: InvestigationContext) -> InvestigationContext:
        """Run the action. Deterministic, except close_read, which dispatches a worker."""
        action = context.pending_action
        assert action is not None

        repeat = self._previous_identical(action)
        if repeat is not None:
            # Do not spend the work again, and say so where it cannot be missed. With the
            # collapse now keeping a line sample this should be rare; when it happens
            # anyway, the note is the useful part, not the result.
            step = Step(
                index=self._evidence.next_index,
                action=action,
                summary=(
                    f"you already ran this as step {repeat.index}; it returned: "
                    f"{repeat.summary}"
                ),
                lines=repeat.lines,
                total_matches=repeat.total_matches,
                truncated=repeat.truncated,
                reproduce=repeat.reproduce,
            )
        elif action.action is ActionKind.CLOSE_READ:
            step = await self._close_read(action, context.iteration)
        else:
            step = execute_readonly(action, self._corpus, index=self._evidence.next_index)

        self._evidence.add(step)
        self._transcript.log_event(
            "action_executed",
            {
                "step": step.index,
                "action": action.action.value,
                "summary": step.summary,
                "total_matches": step.total_matches,
                "lines_shown": len(step.lines),
                "truncated": step.truncated,
                "error": step.error,
                "reproduce": step.reproduce,
                # The refs, not the text: the transcript already grows fast, and every
                # line shown is recoverable from the file plus the ref.
                "refs": [hit.ref for hit in step.lines],
            },
        )
        self._progress.note(f"  -> {step.summary}")

        next_iteration = context.iteration + 1

        # An abort seen during execution decides the run's fate now that the step is
        # recorded. Evidence already paid for is never discarded to label the run aborted.
        if self._run_dir is not None:
            request = read_abort(self._run_dir)
            if request is not None:
                return self._abort_context(
                    context.model_copy(
                        update={"iteration": next_iteration, "pending_action": None}
                    ),
                    request.mode,
                )

        if next_iteration >= self._run.max_iterations:
            return context.model_copy(
                update={
                    "state": InvestigationState.ABORTED_ITERATION_CAP,
                    "iteration": next_iteration,
                    "pending_action": None,
                    "iteration_cap_hit": True,
                }
            )
        return context.model_copy(
            update={
                "state": InvestigationState.INVESTIGATING,
                "iteration": next_iteration,
                "pending_action": None,
            }
        )

    @staticmethod
    def _identity(action: InvestigativeAction) -> tuple:
        """What makes two actions the same question. Reasoning and expectation are prose
        the model rewrites every turn, so they are deliberately excluded."""
        return (
            action.action,
            action.pattern,
            action.file,
            action.ref,
            action.start_line,
            action.end_line,
            action.question,
        )

    def _previous_identical(self, action: InvestigativeAction) -> Step | None:
        """The earliest step that asked exactly this, if any.

        A graded run issued `search /<addr>/ in dhcp.log` twice, byte for byte, because
        the first answer had aged out of the rendered ledger. The rendering is fixed; this
        is the backstop, and it also means a repeat costs no work.
        """
        wanted = self._identity(action)
        for step in self._evidence.steps:
            if not step.error and self._identity(step.action) == wanted:
                return step
        return None

    async def _close_read(self, action: InvestigativeAction, iteration: int) -> Step:
        """Hand a bounded line range to a worker for one specific question.

        This is the only surviving use of the grunt fleet, and the difference from the
        sweep is the whole point: one range, chosen because the commander has a reason,
        asked one question it wrote itself, with the answer landing in the same evidence
        ledger as everything else.
        """
        index = self._evidence.next_index
        requested_end = min(action.end_line, action.start_line + MAX_CLOSE_READ_LINES - 1)
        hits = self._corpus.slice_lines(action.file, action.start_line, requested_end)
        if not hits:
            return Step(
                index=index,
                action=action,
                summary="no lines in that range",
                error=f"{action.file} has no lines {action.start_line}-{action.end_line}",
                reproduce=reproduce_command(action),
            )

        # A line cap alone is not a context bound. 120 Zeek dns.log lines are ~17k tokens
        # against a 16k grunt context, and an oversized slice is rejected by the server --
        # so the cheap-looking cap would have failed exactly on the widest, most
        # interesting records. Trim by the same token budget chunking uses.
        hits = _fit_token_budget(
            hits, self._run.slice_token_budget, self._run.chars_per_token
        )
        end = int(hits[-1].ref.rpartition(":L")[2])
        if end < action.end_line:
            reason = (
                f"at most {MAX_CLOSE_READ_LINES} lines"
                if end == requested_end
                else f"~{self._run.slice_token_budget} tokens of context"
            )
            capped = f" (capped at L{end} from L{action.end_line}; a close_read reads {reason})"
        else:
            capped = ""
        log_slice = LogSlice(
            slice_id=f"closeread-{index:03d}",
            source="case",
            host="",
            file=action.file,
            time_range="",
            start_line=action.start_line,
            end_line=end,
            reason=action.question,
            # The column header rides along, exactly as it did on every sweep slice.
            format_header=self._corpus.format_header(action.file),
            lines=[LogLine(ref=hit.ref, text=hit.text) for hit in hits],
        )
        tasking = GruntTasking(
            task_id=f"{self.investigation_id}-step{index:03d}-closeread",
            investigation_id=self.investigation_id,
            iteration=iteration,
            instruction=action.question,
            commander_intent=action.expectation,
            # Built in code from the alert rather than written by a model. The indicators
            # are the alert's entity values -- exact strings by construction, which is what
            # validation/citations.py needs to check a worker's description against the
            # line it cited. That check caught a worker describing an antivirus lookup as
            # tunnel traffic, and it only works with exact indicator strings.
            directive=TaskDirective(
                alert_restatement=self._alert.summary,
                indicators=[entity.value for entity in self._alert.entities],
                relevance_criteria=action.question,
                explicitly_irrelevant=[],
                time_window="",
            ),
            data_slice=log_slice,
        )

        timeout = self._grunt.config.request_timeout_s + TASK_TIMEOUT_MARGIN_S
        task = asyncio.create_task(
            run_grunt_task(
                tasking, self._grunt, self._run, self._transcript, self._progress
            ),
            name=tasking.task_id,
        )
        self._registry[tasking.task_id] = task
        try:
            outcome = await asyncio.wait_for(task, timeout=timeout)
        except asyncio.TimeoutError:
            task.cancel()
            outcome = self._task_failure(tasking, "timeout", f"exceeded {timeout:.0f}s")
        except Exception as exc:  # noqa: BLE001 - the boundary is the point
            # An exception must never propagate out of a worker into the orchestrator;
            # it becomes a step the commander is shown on its next turn.
            outcome = self._task_failure(
                tasking, "internal", f"{type(exc).__name__}: {exc}"
            )
        finally:
            self._registry.clear()

        if isinstance(outcome, GruntFailure):
            return Step(
                index=index,
                action=action,
                summary=f"close_read failed ({outcome.reason})",
                error=f"{outcome.reason}: {outcome.detail}",
                reproduce=reproduce_command(action),
            )

        report = outcome.report
        # The worker's findings are the answer; the lines it cited are carried into the
        # evidence ledger so the brief can cite them and the operator can check them.
        cited = {ref for finding in report.findings for ref in finding.representative_refs}
        cited.update(
            finding.first_ref for finding in report.findings if finding.first_ref
        )
        shown = tuple(hit for hit in hits if hit.ref in cited) or tuple(hits[:20])
        described = [
            f"{finding.description} ({finding.match_count} line(s))"
            for finding in report.findings
        ]
        # A worker that records a hit under checked_for rather than findings is the exact
        # shape of the worst information loss this system has had: `dhcp-0001` found the
        # lease, wrote it into checked_for, set relevant=false, and the aggregation dropped
        # it -- so the brief asserted the host could not be identified from a file whose
        # fourth line named it. A positive is a positive wherever the worker filed it.
        described.extend(
            f"also found: {check.checked_for} -- {check.result}"
            for check in report.checked_for
            if check.found
        )
        summary = (
            f"worker read {len(hits)} line(s){capped} and reported: "
            + ("; ".join(described) or "nothing relevant to the question")
        )
        return Step(
            index=index,
            action=action,
            summary=summary,
            lines=shown,
            total_matches=len(hits),
            reproduce=reproduce_command(action),
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
        assert context.profile is not None
        total_lines = sum(self._line_counts.values())
        steps = len(self._evidence.steps)
        note = (
            f"COVERAGE: you ran {steps} investigative step(s) over a case of "
            f"{total_lines} line(s) across {len(self._corpus.file_names)} file(s). You "
            f"chose what to look at. Counts you obtained are exact for the patterns you "
            f"searched; everything you did not search is unexamined, and that is a real "
            f"gap even though no step failed."
        )
        if context.concluded:
            note += " You ended the investigation yourself, judging that you had enough."
        if context.iteration_cap_hit:
            note += (
                f" You hit the hard cap of {self._run.max_iterations} action(s), so there "
                "were questions you did not get to ask. Say so in coverage_gaps."
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
            profile=context.profile,
            evidence=self._evidence,
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

    def _task_failure(
        self, tasking: GruntTasking, reason: str, detail: str
    ) -> GruntFailure:
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
        uncited: list[str] = []
        for index, event in enumerate(body.timeline):
            cited.extend(event.raw_line_refs)
            if not event.raw_line_refs:
                uncited.append(f"timeline[{index}]: {event.description[:120]}")
        for h_index, hypothesis in enumerate(body.hypotheses):
            for field in ("supporting_evidence", "contradicting_evidence"):
                for e_index, evidence in enumerate(getattr(hypothesis, field)):
                    cited.extend(evidence.raw_line_refs)
                    if not evidence.raw_line_refs:
                        uncited.append(
                            f"hypotheses[{h_index}].{field}[{e_index}]: "
                            f"{evidence.description[:120]}"
                        )

        # Checked against what the commander was SHOWN, not against every line in the
        # case. A reference that resolves in the corpus but was never displayed is not a
        # citation -- it is a plausible-looking guess, and under this architecture that is
        # the failure mode worth catching.
        unresolved, malformed = unresolved_brief_citations(
            cited, self._evidence.shown_refs()
        )

        ledger = [
            StepLedgerEntry(
                step=step.index,
                action=_action_line(step.action),
                reasoning=step.action.reasoning,
                expectation=step.action.expectation,
                result=step.summary,
                reproduce=step.reproduce,
                error=step.error,
            )
            for step in self._evidence.steps
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
            step_ledger=ledger,
            injection_signals=[signal.model_dump() for signal in self._injection_signals],
            iterations_used=context.iteration,
            steps_taken=len(self._evidence.steps),
            lines_available=sum(self._line_counts.values()),
            terminal_state=context.state.value,
            aborted_by_operator=context.aborted_by_operator,
            unresolved_citations=unresolved,
            malformed_citations=malformed,
            uncited_claims=uncited,
        )


def _fit_token_budget(hits: list, budget_tokens: int, chars_per_token: float) -> list:
    """The longest prefix of `hits` that fits the worker's slice budget.

    Always returns at least one line: a single record wider than the whole budget cannot
    be split without breaking its reference, and one oversized slice is a better failure
    than an empty one -- the worker's own truncation handling covers it, and the step
    records what happened either way.
    """
    kept: list = []
    spent = 0.0
    for hit in hits:
        spent += len(hit.text) / chars_per_token + 8  # +8 ≈ the "<file>:L<n>\t" prefix
        if kept and spent > budget_tokens:
            break
        kept.append(hit)
    return kept


def _action_line(action: InvestigativeAction) -> str:
    kind = action.action
    scope = f" in {action.file}" if action.file else ""
    if kind in (ActionKind.SEARCH, ActionKind.COUNT):
        return f"{kind.value} /{action.pattern}/{scope}"
    if kind is ActionKind.CONTEXT:
        return f"context around {action.ref}"
    if kind in (ActionKind.READ_LINES, ActionKind.CLOSE_READ):
        return f"{kind.value} {action.file}:L{action.start_line}-L{action.end_line}"
    return kind.value
