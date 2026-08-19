# SOC log-analysis PoC — serving layer + orchestrator skeleton

A lab proof of concept on a single NVIDIA DGX Spark (GB10, 128 GB unified memory,
~273 GB/s). An external detection system raises an alert; this system investigates
around it.

A **commander** model reads the alert — and only the alert — and writes a sweep
directive saying what would be relevant. Every slice of every log file is then read by a
**grunt** worker carrying that directive. The commander reasons over what they bring
back and synthesizes an investigation brief for a human SOC operator.

**The commander never sees a log line.** That is not a restriction, it is what makes the
brief's coverage claim true: if the commander chose which slices to read, "we found
nothing else" would only ever mean "nothing else in the part it picked".

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
    │  RECEIVED → TASKING      alert in, sweep directive out    │
    │                 │        (no log data reaches it here)    │
    │                 ▼                                         │
    │             SWEEPING     EVERY slice → a grunt            │
    │                 │        bounded by concurrency, not      │
    │                 ▼        by a coverage budget             │
    │             COLLECTING ──┐                                │
    │                 │        │ drill-down (commander names    │
    │                 │        └─ slice_ids the sweep flagged)  │
    │                 ▼                                         │
    │             SYNTHESIZING → DONE                           │
    │                 ▲                                         │
    │  ./abort.py ─► ABORTING   ABORTED_BY_OPERATOR             │
    │                (write up) (--hard: stop dead)             │
    └───────┬───────────────────────────────┬──────────────────┘
            │ typed messages only           │
            ▼                               ▼
   commander (port 8000)            grunt fleet (port 8001)
   gpt-oss-120b, MXFP4              Qwen3-8B-FP8, ONE instance
   directive + synthesis            continuous batching, 8 at a time
            │                               │
            └──────► every call ────────────┘
                     transcript.jsonl (full prompt + response, always)
```

**Commander** sees: the alert, a bare file inventory (names, line counts, time ranges —
never content), and its workers' reports, including their failures.

**Each grunt** sees: the sweep directive and one fenced slice. Nothing else — no sibling
reports, no alert envelope, no history. Isolation is what makes each task checkable and
what makes it a supervised Task in the Elixir port.

**Reports are aggregates.** A grunt that matches 400 lines returns a count, the first and
last reference, and at most five representative citations — never 400 refs. Slices that
found nothing collapse into a single coverage line. That is what lets a sweep of any size
land inside the commander's fixed context: ~80 reports become ~5k tokens instead of ~24k.

Read `PORTING.md` next; it explains why several things are shaped the way they are.

### Module map

| Path | What it is |
|---|---|
| `analyze.py` / `abort.py` | the two entry points; everything else is library code |
| `src/soc_poc/casedir.py` | case-folder discovery and validation, with fixable errors |
| `src/soc_poc/chunking.py` | token-aware chunking; every line lands in exactly one slice |
| `src/soc_poc/control.py` | run markers and the abort sentinel |
| `src/soc_poc/progress.py` | the live-output sink; keeps I/O out of the state machine |
| `src/soc_poc/states.py` | the state machine: states, legal transitions, terminal set |
| `src/soc_poc/orchestrator.py` | the loop over an immutable `InvestigationContext` |
| `src/soc_poc/messages.py` | every message crossing an agent boundary, failures included |
| `src/soc_poc/grunt.py` | one isolated unit of work; always returns, never raises |
| `src/soc_poc/commander.py` | directive, drill-down and synthesis calls |
| `src/soc_poc/schemas/` | the contracts (alert, sweep directive, slices, grunt report, brief) |
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
   guarantees `representative_refs` is a list of strings; only Python can know whether
   `dns.log:L142` was in the slice *that particular grunt* was handed.
   `validation/citations.py` checks exactly that, plus the reference cap, that
   `match_count` is consistent with what was cited, and that a report claiming the slice
   is irrelevant has not simultaneously recorded a hit — a grammar constrains shape and
   cannot count or cross-check. A finding with no citation, or a fabricated one, is a
   validation failure: the worker is re-prompted once with the specific error and then
   recorded as a failure. At brief level, evidence written with no reference at all is
   listed in `uncited_claims` — non-blocking, because some claims are legitimately
   uncitable, but visible.
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
```

That is it. There is nothing to hand-author and nothing to configure: every line of every
file in `logs/` is read. `fixtures/` is itself a case folder, so `./analyze.py fixtures`
runs the bundled demo — that is all `make demo` and `make demo-offline` do now.

**How logs become visible.** `chunking.py` packs every file into slices sized against
the grunt's context, and each slice is read by one worker. Windows are variable-length,
packed greedily by estimated tokens rather than a fixed line count: log files mix short
routine lines with dense bursts, and a fixed window landing on a burst overflows the
model's context even when the file's average is comfortable. That failure is total — an
oversized slice is rejected by the server, so every grunt in the sweep fails.

Token estimation is deliberately pessimistic (1.4 chars/token, measured against the real
tokenizer on high-entropy DNS labels). Cheaper log formats simply get smaller slices than
they strictly need, which costs a few extra calls; erring the other way costs the run.

`analyze.py` prints the slice count and an estimated wall-clock before starting, and asks
to proceed. Nothing is skipped and nothing is sampled, so a large case is slow rather
than partial — `./abort.py` is there when you change your mind.

Output, one directory per run:

```
out/<investigation_id>/
    transcript.jsonl        every LLM call, every state transition, every validation
    brief.json              the artifact for the operator (absent if the run failed)
    run_meta.json           config snapshot, model ids, git sha, terminal state
```

`brief.json` carries two audit fields worth reading first: `unresolved_citations`
(references that do not resolve to a real line) and `uncited_claims` (evidence written
with no reference at all).

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

- **Telemetry pipeline.** Precomputed pattern summaries were in the original design and
  have been **deliberately removed**: the commander must not read data, and summaries are
  data. What a pipeline would still buy is prioritisation (sweep the interesting slices
  first) and enrichment for the brief — not deciding what gets read, because that is the
  choice this architecture exists to take away.
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

Typical timings: commander directive ~20 s, drill-down plan ~31 s, synthesis ~95 s, grunt
reports median 43 s. A 1 MB case (83 slices) is ~16 minutes end to end at 8-way batching.

### The DNS-tunnel run, and what it cost to be wrong

`cases/dns-tunnel`, 81 slices, **zero task failures**, `DONE`. The sweep worked: 33 slices
reported findings covering the tunnel, 52 correctly reported nothing, and only one decoy
produced a grunt-level false positive that never reached the brief.

The brief still contained two confidently false statements, and **both were mine, not the
model's**:

1. *"DHCP logs contain no lease entry for 10.12.34.56."* The DHCP worker had found it, and
   said so: `{"checked_for": "DHCP lease for 10.12.34.56", "result": "Found in line
   dhcp.log:L4 and dhcp.log:L8"}` — but marked the slice `relevant: false`, and the
   collapse rendered irrelevant slices as a bare slice id. A worker read the evidence
   correctly and the aggregation layer inverted it. Fixed three ways: `CheckedFor.found`
   makes the contradiction expressible, the validator rejects it, and the collapse
   surfaces a stray positive rather than dropping it.
2. *"No DNS response payloads were captured; the logs only contain query records."* Every
   tunnel query carries a base32 TXT answer — the exfiltration channel itself. Zeek's
   `#fields` preamble existed only in slice 1, so 78 of 79 slices were 23 anonymous
   tab-separated columns. Fixed: the format header now rides on every slice, charged
   against the token budget so reintroducing it cannot push slices over the context limit.

Also observed, and the reason `uncited_claims` exists: **every false claim in the brief
had `raw_line_refs: []`, and every cited claim was true.** The correlation was perfect.

### Still open

- **Grunts restate the indicator instead of describing what they saw.** ~30 findings
  shared one near-identical sentence. Across every report: `base32` 0 mentions, `encod` 0,
  `hex` 0, `burst` 0, `interval` 0. The "expensive grep" outcome the prompt warns against.
- **The timeline had 2 entries**, both restating the alert's own timestamps, both uncited,
  from 788 tunnel queries across 5 sessions. The narrative was 172 characters.
- **`explicitly_irrelevant` suppressed the best evidence.** The directive excluded
  "DNS queries of type A, AAAA, MX, CNAME, **NS**, SOA that are not to
  api-sync-telemetry.net" — a qualifier a small model drops. The
  NS → `ns1.` → `45.77.203.118` delegation chain at `dns.log:L975-976` is the strongest
  evidence in the case; `dns-0013` cited L975 but described it as a TXT query, and the
  nameserver IP appears in no report at all.
- **22% grunt validation failure rate** (24 of 109), almost all refs-cap violations
  (25–38 references against a cap of 5). All recovered on retry, at ~24 extra calls.
- **Findings double-count within a slice** — totals came to 817 against a ground truth of
  788.
