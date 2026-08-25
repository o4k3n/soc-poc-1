# Porting to Elixir/OTP

This Python skeleton is written to be thrown away. It exists to find out where the
hierarchy loses information; the production shape is Elixir/OTP. Every structural decision
here was made to survive that translation, which is why some of it looks over-formal for
Python.

It found what it was built to find. The commander/grunt sweep lost information at the
worker layer — see "Why the sweep is gone" in the README — and the architecture is now an
action loop over a deterministic corpus, with workers surviving only as an on-demand
`close_read`. **Port the loop, not the fleet.** The concurrency machinery below is
correspondingly less load-bearing than it was: at most one worker runs at a time.

## Mapping

| Python | OTP | Why it was written this way |
|---|---|---|
| `orchestrator.Orchestrator` + `states.InvestigationState` | `gen_statem` (state functions mode) | States are already named and the legal-transition table already exists in `states.LEGAL_TRANSITIONS`. Each `_on_*` handler becomes a state callback. There is no state hidden in local variables to discover during the port. |
| `orchestrator.InvestigationContext` (frozen pydantic) | `gen_statem` data term | Already immutable and replaced wholesale on every transition, so it maps to the `Data` argument with no rewriting. |
| `states.assert_legal_transition` | the `gen_statem` callback structure itself | In OTP an illegal transition is unrepresentable; here it is asserted at runtime to get the same guarantee. |
| `grunt.run_grunt_task` | `Task.Supervisor.async_nolink/2`, one Task per tasking | Already an isolated function over one immutable message that always returns a value. `async_nolink` because a worker crash must not take the orchestrator with it. |
| `Orchestrator._registry` (`dict[task_id, asyncio.Task]`) | `Registry` (`:unique` keys), or the supervisor's child list | Explicitly named and cleared at the end of each collection round rather than being implicit in a list of awaitables. |
| `asyncio.wait_for(task, timeout)` in `_close_read` | `Task.yield/2` + `Task.shutdown/2` | Same semantics: bounded wait, then kill the worker and record a failure. |
| `INVESTIGATING` / `EXECUTING` | two `gen_statem` states | The loop. One is the model deciding, the other is code acting on a value it produced; keeping them apart is what makes the transcript show the boundary, and that boundary is the security property — everything on the EXECUTING side is code the model cannot influence beyond handing it a regex. |
| `schemas/action.InvestigativeAction` | a struct + explicit JSON Schema map | A flat schema with `validate_action/2` in code, deliberately **not** a discriminated union and deliberately not native tool-calling. Same reasoning ports: grammars handle `oneOf` inconsistently, and a model-side parser in the hot path of every step is the most fragile thing available. |
| `actions.execute_readonly` | a pure function over the corpus | No state, no processes, no I/O beyond files already read. It is the whole "the model proposes, the runtime disposes" boundary; keep it a pure function so it stays obvious that a model cannot reach past it. |
| `evidence.Evidence` | an accumulator in the `gen_statem` data term | Append-only. It is the run's memory *and* its audit trail, deliberately the same object: `shown_refs/1` is what the brief's citations are checked against, so a citation cannot outrun what was displayed. |
| `profiling.build_profile` | a plain module — pure functions over the corpus | Format-agnostic by design: it knows timestamps, IP-shaped and domain-shaped tokens, and character entropy, and nothing about Zeek, Suricata or DNS. Port the three-pass templating order exactly (shapes, then unique identifiers, then bare numbers) — getting it wrong is subtle and produces a profile that looks fine and finds nothing. |
| `messages.GruntFailure` | `{:error, %GruntFailure{}}` tagged tuple | Failures are already values that flow to the commander, never exceptions crossing a boundary. `GruntOutcome` is the sum type. |
| `messages.GruntTasking` | a message sent to a Task, or a `%Tasking{}` struct in its args | Already carries everything the worker needs; there is no shared state to untangle. |
| `llm/base.LLMClient` protocol | a behaviour (`@callback complete_json/1`) | `VLLMClient` and `StubClient` become two modules implementing it. |
| `transcript.TranscriptLogger` | a `GenServer` with `handle_cast/2` writes, one per investigation, under the investigation's supervisor | Writes are already serialized behind a lock and fire-and-forget in spirit. Keep the flush-per-line behaviour: a crashed run must leave a readable transcript. |
| `config.AppConfig` (frozen pydantic) | application env + a config struct, read once at boot | Nothing reads a raw map anywhere in either version. |
| `commander.plan_round` / `commander.synthesize_brief` | plain functions called from the orchestrator process | Deliberately not processes: they are synchronous request/response steps of the state machine, not concurrent activities. |
| retry-with-feedback loops (`for attempt in range(...)`) | explicit retry count in the state data, with `{:next_event, :internal, :retry}` | The attempt counter is already an explicit parameter rather than a closure variable. |
| `validation.no_verdict` import-time assertion | a compile-time check, or a test in the release pipeline | The guarantee ("no model-facing schema has a decision field") must fail the build, not a review. |
| `progress.ProgressSink` | a pid the machine `send`s events to, or `:telemetry` events | Already a protocol with two implementations and no I/O inside the state machine. |
| `control.py` sentinel polling | `gen_statem.call/2` — a real message, checked between states | The file sentinel exists because a Python asyncio process has no mailbox. OTP does: abort becomes `{:abort, mode}` handled in whichever state is current, and the polling disappears. Keep the two-mode distinction and the "no outcomes means no brief" rule. |
| `ABORTING` / `ABORTED_BY_OPERATOR` | two `gen_statem` states, same as here | Split for the same reason: one state that means both "stop and write up" and "stop dead" is a state that means nothing. |
| `corpus.Corpus` | an ETS table, or just a map held by the investigation | Loaded once, read-only thereafter. Every result carries its `<file>:L<n>` reference; that is what keeps citations checkable. |
| `chunking.py` | a plain module — pure functions over a file | Reduced to the file inventory and the injection scan now that nothing dispatches per slice. The packing rule still matters for `close_read` ranges: sized against the worker's context, not a fixed count. |
| `evidence.render/1` collapse | same rendering | Recent steps in full, older ones collapsed to their summary with counts kept. This is what makes the prompt flat in the number of steps — 4 steps and 24 steps differ by ~600 tokens — and it is not an optimisation to drop during the port. |

## Supervision tree the port should land on

```
SocPoc.Application
└── SocPoc.InvestigationSupervisor          (:simple_one_for_one / DynamicSupervisor)
    └── SocPoc.Investigation                (per alert)
        ├── SocPoc.Investigation.Machine    (gen_statem — orchestrator.py)
        ├── SocPoc.Investigation.Transcript (GenServer — transcript.py)
        ├── SocPoc.Investigation.Registry   (Registry — _registry)
        └── Task.Supervisor                 (close_read tasks — grunt.py)
```

One investigation is one supervised subtree. It can crash and be restarted without
touching any other investigation, and a close_read task can crash without touching its
investigation. The Task.Supervisor is still worth having even though it now supervises at
most one task at a time: the reason for it was never throughput, it was that a worker
crash must not take the investigation with it.

## What deliberately does not port

- **Fleet-shaped concurrency.** The semaphore and the registry-draining loop were built
  for an 83-way sweep that no longer exists. Port the per-task timeout and the
  "failures are values" rule; do not port the fan-out machinery until something needs it.
- **The stub client's canned bodies.** They exist to exercise this skeleton offline. The
  Elixir version wants a record/replay client built on the transcript corpus instead --
  which is one of the reasons the corpus is being collected.
- **Pydantic-derived JSON Schema** (`schemas/jsonschema.py`). Elixir has no equivalent
  reflection, so the schemas become explicit maps. Keep the same discipline: flat, no
  `$ref`, closed objects, everything required, and semantic constraints checked in code
  rather than declared in the schema.

## Things to preserve in the port, in priority order

1. **No verdict field.** If the brief schema ever grows `severity` or `disposition`, the
   architecture's main safety property is gone, and no prompt will restore it.
2. **Citations required and checked against what was actually shown.** For the brief that
   is `Evidence.shown_refs/1`; for a `close_read` it is the range the worker was handed
   (`validation/citations.py`). Both are small; together they are most of the reason the
   output can be trusted enough to put in front of an operator.
3. **The alert's status never round-trips through a model.** It is copied by code in
   `orchestrator._assemble_brief` and nowhere else.
4. **Transcript logging that cannot be turned off.** In Elixir, make the transcript pid a
   required field of the investigation state, not an option with a default.
5. **A crash must not cost the evidence.** "Failures are values" was originally enforced
   only at the worker boundary, and a bug in a one-line display helper raised straight
   through the orchestrator loop, ending a 21-step investigation with no brief — every one
   of those steps already paid for and already in the transcript. `_step` now routes an
   unexpected exception to a legal state (a crashed *step* returns the commander its turn
   with the error recorded; a crashed *decision* goes to synthesis) rather than unwinding.

   This needs thought in the port rather than a direct translation. "Let it crash" is
   right for the process and wrong for the ledger: a `gen_statem` that dies loses its data
   term, so the evidence must either live somewhere the restart can recover it, or the
   handler must catch and route exactly as it does here. The transcript is written
   line-by-line as the run goes precisely so a dead run still leaves something usable —
   preserve that.
6. **Every step reproducible by hand.** `actions.reproduce_command/2` puts the equivalent
   `grep` or `sed` in the brief's ledger. An investigation whose evidence can be
   re-derived in seconds is a different kind of artifact from one that must be taken on
   trust, and it costs one function.
