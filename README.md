# SOC log-analysis PoC — serving layer + orchestrator skeleton

A lab proof of concept on a single NVIDIA DGX Spark (GB10, 128 GB unified memory,
~273 GB/s). An external detection system raises an alert; this system investigates
around it. A **commander** model reads the alert plus precomputed pattern summaries and
dispatches narrow tasks to **grunt** workers that read raw log slices; the commander
synthesizes an investigation brief for a human SOC operator.

The brief supports the operator. **It never renders a verdict.**

Latency is explicitly not a concern here. Correctness, auditability, and an architecture
that survives being ported to Elixir/OTP are.

---

## Architecture

```
   ./analyze.py <case>              external detector
        │  alert.json + logs/              │  status + severity: authoritative, read-only
        └──────────────┬───────────────────┘
                       ▼
    ┌──────────────────────────────────────────────────────────┐
    │  orchestrator  (explicit state machine, states.py)        │
    │                                                          │
    │  RECEIVED → PLANNING → DISPATCHED → COLLECTING ─┐         │
    │                 ▲                               │         │
    │                 └──────── drill-down ───────────┘         │
    │                              │ (iteration cap)            │
    │                              ▼                            │
    │                        SYNTHESIZING → DONE                │
    │                              ▲                            │
    │        ./abort.py ─► ABORTING┘   ABORTED_BY_OPERATOR      │
    │                     (write up)   (--hard: stop dead)      │
    └───────┬───────────────────────────────┬──────────────────┘
            │ typed messages only           │
            ▼                               ▼
   commander (port 8000)            grunt fleet (port 8001)
   gpt-oss-120b, MXFP4              Qwen3-8B-FP8, ONE instance
   plan + synthesize                continuous batching
            │                               │
            └──────► every call ────────────┘
                     transcript.jsonl (full prompt + response, always)
```

**Commander** sees: the alert, pattern summaries, a catalog of available slices, and its
workers' reports — including their failures. It never sees a raw log line.

**Each grunt** sees: one instruction, the commander's intent, and one fenced slice.
Nothing else — no sibling reports, no alert, no history. Isolation is what makes each
task checkable and what makes it a supervised Task in the Elixir port.

Read `PORTING.md` next; it explains why several things are shaped the way they are.

### Module map

| Path | What it is |
|---|---|
| `analyze.py` / `abort.py` | the two entry points; everything else is library code |
| `src/soc_poc/casedir.py` | case-folder discovery and validation, with fixable errors |
| `src/soc_poc/summarize.py` | fallback summarizer, standing in for the telemetry pipeline |
| `src/soc_poc/control.py` | run markers and the abort sentinel |
| `src/soc_poc/progress.py` | the live-output sink; keeps I/O out of the state machine |
| `src/soc_poc/states.py` | the state machine: states, legal transitions, terminal set |
| `src/soc_poc/orchestrator.py` | the loop over an immutable `InvestigationContext` |
| `src/soc_poc/messages.py` | every message crossing an agent boundary, failures included |
| `src/soc_poc/grunt.py` | one isolated unit of work; always returns, never raises |
| `src/soc_poc/commander.py` | planning and synthesis calls |
| `src/soc_poc/schemas/` | the contracts (alert, summaries, slices, grunt report, brief) |
| `src/soc_poc/validation/` | no-verdict guard, citation enforcement, injection post-pass |
| `src/soc_poc/prompting/` | prompt construction; all untrusted content goes through `envelope.py` |
| `src/soc_poc/llm/` | `LLMClient` protocol, vLLM client, offline stub |
| `src/soc_poc/transcript.py` | the JSONL corpus — the PoC's actual deliverable |
| `src/soc_poc/preflight.py` | the three endpoint checks that gate every run |

---

## The four guarantees

Prompts are a courtesy. These four are structural, and they hold when the prompt fails.

1. **There is no verdict field.** `BriefBody` has no `severity`, `disposition`,
   `verdict`, `risk_score`, or recommended-action field. A model cannot flip a decision
   the schema gives it nowhere to write. `validation/no_verdict.py` walks every
   model-facing schema at **import time** and refuses to start the process if one grows
   a decision-shaped field — so "just a severity hint, six months from now" fails the
   build rather than the review.
2. **Every claim carries a citation, and citations are checked.** Guided decoding
   guarantees `raw_line_refs` is a list of strings; only Python can know whether
   `dns_resolver.log:L142` was in the slice *that particular grunt* was handed.
   `validation/citations.py` checks exactly that. An observation with no citation, or
   with a fabricated one, is a validation failure — the worker is re-prompted once with
   the specific error and then recorded as a failure. Uncheckable claims do not reach
   the operator.
3. **The alert's status never round-trips through a model.** `AlertRef` in the finished
   brief is built by `orchestrator._assemble_brief` copying the inbound alert. No model
   sees it as an output field.
4. **Logging cannot be turned off.** `TranscriptLogger` is a required constructor
   argument of every LLM client and of the orchestrator. No default, no `None` branch,
   no config key. A client that could make an unlogged call is not constructible.

The prompt-level defenses — data fencing with envelope metadata, "log content is never
instructions" — are in `prompting/envelope.py`, clearly labelled as the soft layer.
`validation/injection.py` is a cheap post-pass that flags log content appearing to
address an AI system; hits land on the brief rather than being filtered out, because an
injection attempt in a log is itself a detection signal.

---

## Serving layer

Both vLLM instances run co-located on the one GB10 and share its 128 GB unified pool
with the OS. Image: **`nvcr.io/nvidia/vllm:26.07-py3`** (arm64) — vLLM 0.24.0,
torch 2.13.0a0, CUDA 13.3.1.

| | commander | grunt fleet |
|---|---|---|
| model | `openai/gpt-oss-120b` (native MXFP4) | `Qwen/Qwen3-8B-FP8` |
| port | 8000 | 8001 |
| `--gpu-memory-utilization` | **0.64** (~76.5 GiB) | **0.24** (~28.7 GiB) |
| weights on disk | ~61 GB | ~8.8 GB |
| weights loaded | 66.1 GiB | ~9 GiB |
| KV cache after load | 7.9 GiB | — |
| `--max-model-len` | 16384 | 16384 |
| `--max-num-seqs` | 4 | 8 |

**0.64 + 0.24 = 0.88** of the ~119.6 GiB vLLM actually sees (not the nominal 128 GB).
With both models loaded and serving, `free -g` reports **114 of 121 GB used, ~6 GB
available**. That is the real headroom, and it is thinner than the arithmetic suggests
because container runtime and per-process overhead sit outside both fractions. It works,
but do not run anything else heavy on this box during an investigation, and treat 0.88
as the ceiling rather than a starting point.

These are measured, not estimated. The first boot at 0.55/0.28 failed with *"No
available memory for the cache blocks"* and `Available KV cache memory: -1.95 GiB`. Two
things had been underestimated: gpt-oss-120b loads to **66.1 GiB**, ~5 GiB more than its
on-disk size (MXFP4 scales and padding), and CUDA graph capture reserves another 1.6 GiB.
The floor for this model is ~0.57 just to start. `--max-model-len` came down to 16384 at
the same time — the KV cache must hold at least one full-length sequence, and the largest
prompt the commander ever builds is a few thousand tokens, so 32k of headroom bought
nothing out of an 8 GiB budget.

The lines to watch on every boot are `Available KV cache memory` and `maximum
concurrency`; they move when the model, the context length, or the vLLM version changes.
At this split they read 7.9 GiB / 12.39x for the commander and 18.03 GiB / 8.01x for the
grunt, both comfortably above what `--max-num-seqs` asks for.

Why static fractions — this is the shipped flag's own help text, not folklore:

> This is a per-instance limit, and only applies to the current vLLM instance. It does
> not matter if you have another vLLM instance running on the same GPU. For example, if
> you have two vLLM instances running on the same GPU, you can set the GPU memory
> utilization to 0.5 for each instance.

So two static fractions coexist by construction. The default is **0.92**, and NVIDIA's
release notes name that as the cause of OOM on unified-memory systems (DGX Spark,
Jetson) — explicit fractions are the documented fix, not a preference. Neither instance
is allowed to autodetect "all available memory": on this box that starves the OS, and
whichever instance starts second loses.

The commander gets the larger share because its weights are ~7× bigger. The grunt's 0.24
is still generous relative to its ~9 GiB of weights, because the rest is KV cache and
that is what absorbs a whole batch of concurrent workers reading long slices — it is the
instance that actually sees concurrency.

**GB10 specifics**, verified inside the pulled image rather than assumed: torch reports
compute capability `(12, 1)` (sm_121), served by the sm_120-family binaries and
`compute_120` PTX the image ships; the registered quantization methods include both
`mxfp4` and a dedicated `gpt_oss_mxfp4` path. Quantization is auto-detected from each
model's config, so neither service passes `--quantization`.

**Start order matters.** vLLM has a known memory-accounting issue when a second instance
starts while another is still profiling (vllm-project/vllm#10643), so
`deploy/docker-compose.yml` gates the grunt service on the commander's healthcheck. Big
model first, always.

**One grunt instance serves every grunt.** Concurrency comes from vLLM's continuous
batching. One instance per agent would duplicate the weights and buy nothing.

The fractions live in `deploy/commander.env` and `deploy/grunt.env` and are deliberately
not repeated in `config/config.toml` — one place to be wrong instead of two.

---

## Running it

### Bringing the endpoints up

`make setup` and `make weights` are one-time; the rest is the service lifecycle.

```bash
make setup          # venv + editable install
make weights        # fetch ~72 GB of weights into the shared HF cache
make up             # start both vLLM instances (commander first)
make health         # /health, served model name, guided-JSON round trip, both ports
make ps             # service state, including health
make down           # when you want the GPU back
```

`make weights` is not optional convenience. `openai/gpt-oss-120b` is 195.8 GB in full,
but vLLM loads only the root `model-*-of-00014.safetensors` (~62 GB) — the rest is
`metal/model.bin` (65 GB, Apple silicon) and `original/` (67 GB). Letting the server
fetch the repo blind downloads three times what it needs, and a cold download inside the
container outlasts the commander's healthcheck window — which the grunt service gates
on, so you would end up with one server instead of two and no obvious reason why. The
target filters the patterns and is resumable.

### Investigating

`analyze.py` starts nothing heavy: it assumes `make up` already brought the endpoints
online, and it preflights them before the orchestrator leaves `RECEIVED`.

```bash
./analyze.py cases/my-case          # investigate
./analyze.py cases/my-case --stub   # same code path, no GPU
./analyze.py --init cases/new-case  # scaffold an empty case folder
./abort.py                          # stop a run in progress, keep the brief
```

A **case folder** is the whole input format:

```
cases/my-case/
    alert.json      the alert an external detector already raised — required
    logs/           your raw logs, any text format — required
    patterns/       optional; hand-written summaries override the generated ones
```

`fixtures/` is itself a case folder, so `./analyze.py fixtures` runs the bundled demo —
that is all `make demo` and `make demo-offline` do now.

**How logs become visible.** The commander never reads a log file; it dispatches workers
against *slices*, and slices come from pattern summaries. If a case has no `patterns/`,
`summarize.py` generates summaries by chunking each log into windows and computing
generic statistics (line counts, detected time range, repeated-template counts). Those
are honest but weak, and the prompt says so — there is no cross-host prevalence, no
baseline, no real first-seen, because that is the telemetry pipeline's job and the
pipeline is out of scope. Generated summaries are saved to
`out/<id>/generated_patterns/` so a good one can be promoted into the case's own
`patterns/`, which then wins.

`analyze.py` prints the slice count against the read budget
(`max_tasks_per_iteration × max_iterations`) before it starts. If there are more slices
than the commander can read, some data goes unread — raise `--max-tasks` /
`--max-iterations`, or narrow the case.

Output, one directory per run:

```
out/<investigation_id>/
    transcript.jsonl        every LLM call, every state transition, every validation
    brief.json              the artifact for the operator (absent if the run failed)
    run_meta.json           config snapshot, model ids, git sha, terminal state
    generated_patterns/     the summaries used, when they were generated
```

### Watching a run

`analyze.py` streams the commander's reasoning live to stderr as it plans and
synthesizes, and prints one line per grunt task with its observation count and whether
its citations held up. `--quiet` turns it off. Progress goes to stderr and results to
stdout, so `./analyze.py case > result.txt` still behaves.

### Stopping a run

```bash
./abort.py            # graceful: finish in-flight readers, then synthesize what we have
./abort.py --hard     # cancel in-flight work, write no brief
./abort.py --list     # what is running
```

Graceful is the useful one: you get a brief from the reports already collected. Cancelled
tasks are recorded as failures with reason `aborted`, so unexamined ground stays visible
as unexamined rather than turning into absence of evidence. The transcript is complete
either way, because it is written as the run goes rather than at the end.

A graceful abort ends in `DONE` — synthesis really did complete — so the brief carries a
code-stamped `aborted_by_operator` flag as well. The commander is *asked* to record the
abort in `coverage_gaps` and generally does, but asking a model to disclose a limitation
is not a guarantee; the flag is. Nobody reading `brief.json` alone should mistake an
interrupted run for a complete one.

Two more things to know: an abort that lands before any report exists stops without a
brief (synthesizing over nothing wastes two minutes), and once the run reaches
`SYNTHESIZING` it finishes — interrupting the single call that produces the artifact
would throw away the run's product.

### Swapping models

`config/config.toml` holds every endpoint and model name. Commander and grunt models are
swappable without touching code — the contract is a JSON schema, not a model. There is a
stubbed `[models.evaluator]` entry (`enabled = false`) as the seam for a future cloud
frontier judge; nothing reads it yet beyond the config loader.

---

## Known issues on this hardware

**An endpoint can be healthy and still produce nothing usable.** A 200 OK with
`"content": null` has two unrelated causes: a reasoning-parser mismatch routing the
whole response into `reasoning_content` (the likely one — a config mistake on an
otherwise fine server), or a broken quantization kernel emitting a wrong first control
token. The latter is the story behind vllm-project/vllm#37030 for gpt-oss MXFP4 on
SM121, which affected the community `vllm/vllm-openai` images; the NGC image ships a
dedicated `gpt_oss_mxfp4` path, so it is not the expected failure mode here.

This is why `make health` round-trips real guided JSON rather than just pinging
`/health`, and why `llm/vllm_client.py` treats empty content as a transport error that
names the likely suspect instead of handing an empty string to a JSON parser.

If it fires: work through the flag ladder in `deploy/commander.env`, and if none of it
works, swap the commander model (commented fallback block in `config/config.toml`). The
investigation loop does not care which model is behind the schema.

**If the commander OOMs** — `No available memory for the cache blocks`, which is what
0.55 did — the ladder is: raise `COMMANDER_GPU_FRACTION` (taking it from
`GRUNT_GPU_FRACTION`) → drop `COMMANDER_MAX_MODEL_LEN` → add `--kv-cache-dtype fp8` to
`COMMANDER_EXTRA_ARGS`. The current 0.64/0.24 leaves 7.9 GiB of KV cache; the memory
profiler prints the exact shortfall, including a suggested fraction, so read it rather
than guessing.

Because a memory misconfiguration fails at engine init, both services use
`restart: on-failure:3` rather than `unless-stopped` — otherwise the failure presents as
an endlessly "starting" container that looks like a slow load.

**FP8 block scales need DeepGEMM off.** `Qwen/Qwen3-8B-FP8` ships block-wise FP8 scales,
which vLLM routes through DeepGEMM by default; on GB10 that dies at weight load with
`Unknown SF transformation` from `layout.hpp` — DeepGEMM's scale-factor layout transform
has no case for this architecture. `deploy/grunt.env` sets `VLLM_USE_DEEP_GEMM=0`, which
falls back to the generic FP8 path. Recheck on a vLLM bump.

**Two host-level gotchas**, both already handled in `deploy/`:

- This host registers no `nvidia` Docker runtime (only `runc`), so the compose file must
  not ask for one; GPU access comes through the device reservation block.
- The NGC image's `ENTRYPOINT` is the generic `nvidia_entrypoint.sh`, which just execs
  its arguments — unlike upstream `vllm/vllm-openai`, whose entrypoint *is* `vllm serve`.
  So the compose `command:` must begin with `vllm serve`. Passing bare flags gets you an
  exec failure, not a server.

**`deploy/` is still version-sensitive.** Flag names here churn across vLLM releases
(`--structured-outputs-config.backend` was once `--guided-decoding-backend`; the
`--mxfp4-backend` / `--mxfp4-layers` recipes widely posted online are from earlier builds
and are rejected by 0.24.0). Everything in `deploy/` was verified against
`26.07-py3` by inspecting the image; re-verify when you bump the tag, and let
`make health` be the arbiter.

---

## Non-goals

Explicitly not in this build, with the seam each one will land on:

- **Telemetry pipeline.** `summarize.py` is a deliberate stand-in: it chunks and counts,
  and computes none of the statistics that make summaries valuable (cross-host
  prevalence, baselines, interval regularity scored against a population, real
  first-seen). The pipeline replaces that module and touches nothing else — everything
  downstream depends on the `PatternSummary` contract, not on where summaries came from.
- **Eval harness.** Seam: the `LLMClient` protocol (`llm/base.py`) plus the
  `[models.evaluator]` config entry. The transcript corpus is the eval set.
- **Synthetic scenario generation.** Seam: a case folder is just `alert.json` + `logs/`,
  so a generator writes one and `./analyze.py` runs it unchanged.
- **Multi-machine serving.** Endpoints are per-role in config rather than assumed
  co-located, so a second box is a config edit.
- **Latency and throughput tuning.** Deliberate. This box is bandwidth-bound and the
  work is not interactive.
- **Any UI.** The brief is JSON.

Also not attempted: retrieval over the full log estate (grunts read only what the
summaries point at), alert triage or correlation across alerts, and any write path back
to the detection system.

---

## What the real runs showed

Typical timings on this box: commander plan 28–39 s, synthesis 84–119 s, grunt reports
8–52 s, ~9 minutes for a full 8-task investigation over 2 drill-down rounds. The briefs
are decent — competing hypotheses with evidence on both sides, concrete drill-downs, and
coverage gaps that accurately name what went unread.

Four findings worth carrying into the next iteration. All of them are the kind of thing
this skeleton exists to surface, and all of them are visible *because* claims have to
cite something checkable.

1. **The citation contract leaks at the commander level.** Grunts cite correctly —
   across several runs, essentially every grunt report passed the citation validator on
   its first attempt. The commander does not, and produces unresolvable references in at
   least three shapes: *ranges* (`dns_resolver.log:L5-L24`), *pattern-summary ids*
   (`ps-dns-beacon-interval`), and *alert-envelope fields* (`external_alert:domain`,
   `proxy_events.jsonl:negative`). Mostly this is not the model's fault: the evidence
   genuinely came from a precomputed statistic, an alert field, or a whole window, and
   `raw_line_refs` is the only field on offer, so everything gets jammed into it. **The
   brief schema needs an evidence-source union** — cite a line as a line, a summary as a
   summary, the alert as the alert. This is the clearest next change.
2. **An 8B grunt writes labels, not observations.** Descriptions came back as
   `"DNS query record"`, `"Timestamps of beacon queries"` — schema-valid, correctly
   cited, and informationally empty. Guided decoding guarantees a string; nothing
   guarantees the string says anything.
3. **A grunt emitted a confidently wrong negative finding**, reporting
   `"Regular interval pattern between beacon queries — Not found"` for a slice in which
   it had *simultaneously* listed the beacon timestamps five minutes apart. The commander
   propagated it into the brief as contradicting evidence. Negative findings are
   load-bearing for the operator, and this one was false — the most useful failure so far.
4. **The commander reasons about its own constraints.** With reasoning streamed live, an
   aborted run shows it working through *"the operator aborted before finishing
   investigation; we need to note that remaining logs not examined"* — the abort notice
   in the synthesis prompt reached it and shaped the coverage gaps. Encouraging, and also
   the reason the structural `aborted_by_operator` flag exists: behaviour that good is
   still behaviour, not a guarantee.

Both abort paths have been exercised against the live endpoints. Graceful: four in-flight
readers finished, `COLLECTING → ABORTING → SYNTHESIZING → DONE`, brief written with
accurate gaps. Hard: four in-flight tasks cancelled and recorded with reason `aborted`,
no brief, transcript intact.
