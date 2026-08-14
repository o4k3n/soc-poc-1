# Porting to Elixir/OTP

This Python skeleton is written to be thrown away. It exists to find out where the
commander/grunt hierarchy loses information; the production shape is Elixir/OTP. Every
structural decision here was made to survive that translation, which is why some of it
looks over-formal for Python.

## Mapping

| Python | OTP | Why it was written this way |
|---|---|---|
| `orchestrator.Orchestrator` + `states.InvestigationState` | `gen_statem` (state functions mode) | States are already named and the legal-transition table already exists in `states.LEGAL_TRANSITIONS`. Each `_on_*` handler becomes a state callback. There is no state hidden in local variables to discover during the port. |
| `orchestrator.InvestigationContext` (frozen pydantic) | `gen_statem` data term | Already immutable and replaced wholesale on every transition, so it maps to the `Data` argument with no rewriting. |
| `states.assert_legal_transition` | the `gen_statem` callback structure itself | In OTP an illegal transition is unrepresentable; here it is asserted at runtime to get the same guarantee. |
| `grunt.run_grunt_task` | `Task.Supervisor.async_nolink/2`, one Task per tasking | Already an isolated function over one immutable message that always returns a value. `async_nolink` because a worker crash must not take the orchestrator with it. |
| `Orchestrator._registry` (`dict[task_id, asyncio.Task]`) | `Registry` (`:unique` keys), or the supervisor's child list | Explicitly named and cleared at the end of each collection round rather than being implicit in a list of awaitables. |
| `asyncio.wait_for(task, timeout)` in `_on_collecting` | `Task.yield/2` + `Task.shutdown/2` | Same semantics: bounded wait, then kill the worker and record a failure. |
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
| `summarize.py` | a `GenServer` or plain module the pipeline later replaces | It is a stand-in either way; the contract (`PatternSummary` with `log_pointers`) is what ports. |

## Supervision tree the port should land on

```
SocPoc.Application
└── SocPoc.InvestigationSupervisor          (:simple_one_for_one / DynamicSupervisor)
    └── SocPoc.Investigation                (per alert)
        ├── SocPoc.Investigation.Machine    (gen_statem — orchestrator.py)
        ├── SocPoc.Investigation.Transcript (GenServer — transcript.py)
        ├── SocPoc.Investigation.Registry   (Registry — _registry)
        └── Task.Supervisor                 (grunt tasks — grunt.py)
```

One investigation is one supervised subtree. It can crash and be restarted without
touching any other investigation, and a grunt task can crash without touching its
investigation.

## What deliberately does not port

- **`asyncio.gather`-shaped concurrency.** `_on_collecting` iterates the registry in
  order because that is the clearest thing to read in Python. In OTP, collect with
  `Task.yield_many/2` and keep the per-task timeout.
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
2. **Citations required and checked against the slice that was actually sent.**
   `validation/citations.py` is small; it is also most of the reason the output can be
   trusted enough to put in front of an operator.
3. **The alert's status never round-trips through a model.** It is copied by code in
   `orchestrator._assemble_brief` and nowhere else.
4. **Transcript logging that cannot be turned off.** In Elixir, make the transcript pid a
   required field of the investigation state, not an option with a default.
