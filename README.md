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
        external detector
               │  alert (status + severity: authoritative, read-only)
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

## Memory split

Both vLLM instances run co-located on the one GB10 and share its 128 GB unified pool
with the OS.

| | commander | grunt fleet |
|---|---|---|
| model | `openai/gpt-oss-120b` (native MXFP4) | `Qwen/Qwen3-8B-FP8` |
| port | 8000 | 8001 |
| `--gpu-memory-utilization` | **0.55** (~70 GB) | **0.28** (~36 GB) |
| weights | ~60 GB | ~8 GB |
| `--max-model-len` | 32768 | 16384 |
| `--max-num-seqs` | 4 | 8 |

**0.55 + 0.28 = 0.83**, about 106 GB, leaving ~21 GB for the OS, page cache, container
runtime and the orchestrator process.

Why static fractions: `--gpu-memory-utilization` is a per-instance fraction of *total*
device memory, not of free memory, so two static fractions coexist by construction.
Neither instance is allowed to autodetect "all available memory" — on a unified-memory
box that starves the OS, and whichever instance starts second loses. The commander gets
the larger share because its weights are 7.5× bigger; the grunt's 0.28 is deliberately
generous relative to its 8 GB of weights, because its KV cache absorbs a whole batch of
concurrent workers reading long slices.

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

```bash
make setup          # venv + editable install
make test           # unit tests + a full offline investigation
make demo-offline   # the whole state machine on the stub backend, no GPU

make up             # start both vLLM instances (commander first)
make health         # /health, served model name, guided-JSON round trip, both ports
make demo           # one real investigation over the fixtures
make down
```

Output, one directory per run:

```
out/<investigation_id>/
    transcript.jsonl   every LLM call, every state transition, every validation result
    brief.json         the artifact for the operator (absent if the run failed)
    run_meta.json      config snapshot, model ids, git sha, terminal state
```

`make demo` starts nothing heavy: it assumes `make up` already brought the endpoints
online, and it preflights them before the orchestrator moves out of `RECEIVED`.

### Swapping models

`config/config.toml` holds every endpoint and model name. Commander and grunt models are
swappable without touching code — the contract is a JSON schema, not a model. There is a
stubbed `[models.evaluator]` entry (`enabled = false`) as the seam for a future cloud
frontier judge; nothing reads it yet beyond the config loader.

---

## Known issues on this hardware

**gpt-oss-120b MXFP4 on GB10/SM121 may return empty content.** SM121 has no native FP4
compute path, so vLLM falls back to Marlin kernels written for SM80;
vllm-project/vllm#37030 (open at time of writing) reports that this corrupts the first
Harmony control token, and the visible symptom is a 200 OK with `"content": null`.
Separately, `--reasoning-parser openai_gptoss` has been reported to route the entire
response into the reasoning channel — identical symptom, different cause.

This is why `make health` round-trips real guided JSON rather than just pinging
`/health`, and why `llm/vllm_client.py` treats empty content as a transport error that
names both suspects instead of handing an empty string to a JSON parser.

If it fires: try the candidate flag combinations documented in `deploy/commander.env`
one at a time, and if none work, swap the commander model (there is a commented fallback
block in `config/config.toml`). The investigation loop does not care which model is
behind the schema.

**Everything in `deploy/` is version-sensitive.** vLLM flag names in this area have
churned across releases (`--structured-outputs-config.backend` was
`--guided-decoding-backend`; MXFP4 backend selection has moved between env vars and CLI
flags), the pinned image tag is a nightly that moves, and GB10/SM121 support is young.
Verify against the image you actually pin — `make health` is the arbiter. Comments in
`deploy/*.env` mark each flag that needs re-checking rather than asserting it is right.

---

## Non-goals

Explicitly not in this build, with the seam each one will land on:

- **Telemetry pipeline.** Pattern summaries and slices are fixtures on disk today. The
  pipeline lands in `loader.py` behind `PatternSummary` / `LogSlice` and touches nothing
  else.
- **Eval harness.** Seam: the `LLMClient` protocol (`llm/base.py`) plus the
  `[models.evaluator]` config entry. The transcript corpus is the eval set.
- **Synthetic scenario generation.** Seam: fixtures are loaded through one module, so a
  generator writes into `fixtures/` and nothing downstream changes.
- **Multi-machine serving.** Endpoints are per-role in config rather than assumed
  co-located, so a second box is a config edit.
- **Latency and throughput tuning.** Deliberate. This box is bandwidth-bound and the
  work is not interactive.
- **Any UI.** The brief is JSON.

Also not attempted: retrieval over the full log estate (grunts read only what the
summaries point at), alert triage or correlation across alerts, and any write path back
to the detection system.
