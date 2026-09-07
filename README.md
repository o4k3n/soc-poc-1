# SOC log-analysis PoC — an auditable investigation loop

A lab proof of concept on a single NVIDIA DGX Spark (GB10, 128 GB unified memory,
~273 GB/s). An external detection system raises an alert; this system investigates around
it and hands a human SOC operator a brief they can act on. It never renders a verdict.

A **commander** model reads the alert and a **computed profile** of the case — record-type
scope, line-shape frequencies, rare shapes, high-entropy token groups, activity bursts,
all counted in code with no model involved. It then investigates one action at a time
against the raw logs: it asks a question, sees the exact result, and decides the next
question, building an append-only evidence ledger as it goes. When it has what it needs it
concludes and synthesizes the brief. Every step is a regex or a field filter over files on
disk, and every step prints the `grep`/`jq`/`awk` that reproduces it, so the brief is
checkable by hand without a GPU.

**Coverage is arithmetic, not attendance.** A `count` over the corpus is exact and the
operator can re-run it with `grep` in milliseconds. The earlier design instead swept every
slice of every file through a fleet of **grunt** workers, on the argument that if every
line is read by a model then a negative means something. Six graded runs disproved the
premise — reading is not noticing (see "Why the sweep is gone"). Grunts survive as
`close_read`: a bounded line range handed to a worker for one specific question the
commander wrote, when counting genuinely cannot answer it. In 10+ graded runs on the
current stack it has fired zero times.

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
    │  RECEIVED → PROFILING    count the corpus. No model runs  │
    │                 │        here, so nothing it produces     │
    │                 ▼        can be a hallucination.          │
    │           INVESTIGATING ◄─┐  commander emits ONE action    │
    │                 │         │                                │
    │                 ▼         │  we execute it and append the  │
    │             EXECUTING ────┘  result to the evidence ledger │
    │                 │                                          │
    │                 ▼  (conclude, or the step budget)          │
    │             SYNTHESIZING → DONE                            │
    │                 ▲                                          │
    │  ./abort.py ─► ABORTING   ABORTED_BY_OPERATOR              │
    │                (write up) (--hard: stop dead)              │
    └───────┬───────────────────────────────┬──────────────────┘
            │ typed messages only           │
            ▼                               ▼
   commander (SGLang, :18400)       grunt (same endpoint)
   Qwen3.8-Flash-Next, NVFP4        close_read only, on demand
   actions + synthesis              (has fired 0× on this stack)
            │                               │
            └──────► every call ────────────┘
                     transcript.jsonl (full prompt + response, always)
```

The commander is a JSON contract, not a particular model: `actions.py` executes a JSON
object the model emits, over the files already in memory, and nothing in the orchestrator
knows which engine satisfies the schema. The current commander is
**Qwen3.8-Flash-Next served by SGLang on `:18400`** (see "Serving layer"); the grunt points
at the same endpoint. Guided decoding against a flat schema, not native tool-calling:
guided decoding has been the most reliable component of this stack, while every
model-side parsing convention touched here has produced a silent failure at least once.

---

## What the commander can do

**The core verbs.** `search` (regex, case-insensitive; exact total count plus up to 40
lines with their references), `count` (the number alone — cheap, use it to test a guess),
`context` (the lines around a reference), `read_lines` (a range verbatim), `close_read`
(hand a bounded range to a worker for one question counting cannot answer), `conclude`
(stop and write the brief). The model never runs anything; the set of things that *can* be
run is these verbs over the case's files.

**The `where` field filter on `search`, `count` and `context`.** A structured log invites a
regex that lists `"key":"value"` pairs in sequence to pin one record — and on JSON that
silently matches nothing, because the record may order its keys differently. Graded runs
burned three steps each recovering from exactly that. `where=["event_id=10",
"computer=WKS-3355"]` instead matches by *parsed field*, ANDed, order-independent: a JSON
key (dotted for nesting) or a `#fields` column, resolved the same way `field=` resolves.
Four operators — `=` (exact, case-insensitive), `!=`, `~` (regex on the value), `!~` — so
`where=["event_id=10","TargetImage~lsass","SourceImage!~MsMpEng"]` isolates a credential
dump from the antivirus's own lsass reads in one step. `pattern` stays an optional extra
whole-line regex, and the reproduce command is a `jq -c 'select(...)'` (JSON) or a
header-resolving `awk` (TSV) that re-derives the same lines by hand. In its first graded
run the commander reached for `where` in 18 of 24 steps and the key-order wall vanished.

**The optional skills**, gated by `run.enabled_skills` so each can be trialled on its own
graded runs and judged one at a time:

- `tally` — the distinct values of a regex with an exact count each: a distribution in one
  step instead of one `count` per guess.
- `timeline` — span, gap statistics and burst structure of a pattern's matches, the same
  gap arithmetic as the profile.
- `stats` — min/median/p95/max over a captured value; the value's length when it is not
  numeric.
- `extremes` — the ten matching *lines* with the largest value, each with a citable
  reference, plus where those ten sit in the distribution. This is the bridge from a number
  to its evidence: after `stats` says "max request_body_len 46392" it hands you the lines
  behind the top end, instead of the hand-built digit-range regexes the transcripts showed
  the commander writing for four steps.
- `decode` — the base64 a pattern selects, decoded to text, **verified**: a value that is
  not genuinely base64 is left alone, never mangled. A PowerShell `-Enc` payload becomes the
  command it runs, with a citable reference, instead of being decoded in the model's head —
  where a wrong guess about what a script does is the expensive kind.

`tally`, `timeline` and `stats` return numbers, not lines: nothing they produce enters
`shown_refs()`, because a number is not a citation. `extremes` and `decode` are the
deliberate exceptions — their product *is* lines behind a number, so their rows enter the
ledger and the synthesis recap like a search's would. All five live in `aggregation.py`,
spend no GPU, and print their shell equivalent in the step ledger like every other action.
The prompt teaches the discipline the number-only skills exist for: **aggregate before you
fetch** — size a result set with numbers before spending context on its lines.

**Value selectors** on `tally`, `stats`, `extremes` and `decode`. The pattern is always the
line *filter*; how it picks the *value* has three modes, because "first capture group"
alone forced a brittle column-counting regex that was the single most expensive failure in
the transcripts. `field="<name-or-number>"` takes a delimited column, resolved through the
log's own `#fields` header, so the pattern only has to match the line and one wrong
separator can no longer silently match nothing. `extract="ip|domain|hash|email"` pulls
every entity of that type from each matching line, reusing `profiling.py`'s recognisers. A
capture group remains the fallback. On a **JSON-lines** file (`*.jsonl`, one object per
line — the shape Windows host events take) there are no columns: `field=` names a **key**
instead, dotted for nesting (`field="Details.User"`), matched case-insensitively, and the
commander is shown each JSON file's keys the way it is shown a Zeek header. Values keep
their JSON type, so a numeric key stays numeric for `stats`/`extremes` and a hex access
mask like `0x1010` is ranked by its value, not its length. The reproduce becomes `jq`
rather than `awk`, so a JSON aggregate is re-derivable by hand too.

**The computed profile** is the commander's first page, and it is the one block guaranteed
free of model error — arithmetic over the corpus, re-derivable with `grep` and `sort`. Per
file it shows the **record-type scope** (the distribution of the low-cardinality fields that
say what *kinds* of record the file holds — `event_id`, `LogonType`, `GrantedAccess` on a
Windows log; `qtype_name`, `method` on a network one — detected generically by cardinality,
so no format is special-cased), the most common line shapes, and the **rare shapes** (a
line shape occurring a handful of times among thousands, which is where the unusual thing
usually is — the NS delegation that occurs once in 5,586 lines lands here). Globally it
shows the most-queried domains and addresses, high-entropy token groups (with how many
distinct hosts emit each — one host is a tunnel, forty is a vendor service), and activity
bursts. The scope section exists because a commander handed a Windows JSON log used to
regex-crawl it without ever tallying `event_id` to learn what record kinds it held; now
that map is computed and handed over.

**The synthesis recap.** Before the brief is written, `_evidence_on_record` re-presents a
flat, uncollapsed list of every line the commander fetched, paired with a requirement to
account for each in the brief or in `coverage_gaps` — the fix for a run that searched
dhcp.log, was shown the two lease lines naming the host, and wrote a brief that never
mentioned the hostname. It also computes **shared identifiers**: a distinctive value (a
logon id, a session GUID, a base64 payload) appearing on two or more fetched lines usually
ties those events into one, so it is surfaced by name for the brief to state or rule out —
the join a logon and the process it spawned share, or the payload a scheduled task
registers and later fires.

---

### Module map

| Path | What it is |
|---|---|
| `analyze.py` / `abort.py` | the two entry points; everything else is library code |
| `src/soc_poc/casedir.py` | case-folder discovery and validation, with fixable errors |
| `src/soc_poc/corpus.py` | the case's log files, searchable by line; JSON detection, `where` field matching, categorical scope; every result carries its ref |
| `src/soc_poc/profiling.py` | the computed profile: record-type scope, rarities, entropy groups, bursts. No model |
| `src/soc_poc/aggregation.py` | the optional skills: tally, timeline, stats, extremes, decode. Counted, never inferred |
| `src/soc_poc/actions.py` | executing one action, plus the `grep`/`jq`/`awk` that reproduces it |
| `src/soc_poc/evidence.py` | the append-only ledger: the run's memory *and* its audit trail; the synthesis recap and shared-identifier scan |
| `src/soc_poc/chunking.py` | token-aware chunking; still used for the inventory and injection scan |
| `src/soc_poc/control.py` | run markers and the abort sentinel |
| `src/soc_poc/progress.py` | the live-output sink; keeps I/O out of the state machine |
| `src/soc_poc/states.py` | the state machine: states, legal transitions, terminal set |
| `src/soc_poc/orchestrator.py` | the loop over an immutable `InvestigationContext` |
| `src/soc_poc/messages.py` | every message crossing an agent boundary, failures included |
| `src/soc_poc/grunt.py` | one isolated unit of work; always returns, never raises |
| `src/soc_poc/commander.py` | the decide-action and synthesis calls |
| `src/soc_poc/coercion.py` | rescues a tool-call-shaped reply onto the flat action schema |
| `src/soc_poc/schemas/` | the contracts (alert, action, slices, grunt report, brief) |
| `src/soc_poc/validation/` | no-verdict guard, citation enforcement, injection post-pass |
| `src/soc_poc/prompting/` | prompt construction; all untrusted content goes through `envelope.py` |
| `src/soc_poc/llm/` | `LLMClient` protocol, vLLM/SGLang client, offline stub |
| `src/soc_poc/transcript.py` | the JSONL transcript — the PoC's actual deliverable |
| `src/soc_poc/preflight.py` | the three endpoint checks that gate every run |
| `scripts/make_*_case.py` | the seeded scenario generators (dns-tunnel, http-c2, wmi-lsass, schtask-persist) |
| `scripts/fetch_evtx_samples.sh` | fetch the EVTX attack samples the Windows cases derive from |
| `scripts/grade.py` | scores a brief against a case-keyed ground-truth rubric |
| `deploy/flashnext/` | scripts to serve Qwen3.8-Flash-Next via SGLang (the current commander) |

---

## The four guarantees

Prompts are a courtesy. These four are structural, and they hold when the prompt fails.

1. **There is no verdict field.** `BriefBody` has no `severity`, `disposition`, `verdict`,
   `risk_score`, or recommended-action field. A model cannot flip a decision the schema
   gives it nowhere to write. `validation/no_verdict.py` walks every model-facing schema at
   **import time** and refuses to start the process if one grows a decision-shaped field —
   so "just a severity hint, six months from now" fails the build rather than the review.
2. **Every claim carries a citation, and citations are checked.** The brief's references are
   validated against `Evidence.shown_refs()` — the exact set of lines that passed in front
   of the commander — not against the corpus. A reference that resolves in the files but was
   never displayed is not a citation, it is a plausible-looking guess. `validation/citations.py`
   also checks a `close_read` worker's `representative_refs` against the range that worker
   was actually handed, the reference cap, and that a report calling a slice irrelevant has
   not simultaneously recorded a hit — a grammar constrains shape and cannot cross-check. A
   finding with a fabricated or missing citation is a validation failure; evidence written
   with no reference at all lands in `uncited_claims` — non-blocking, because some claims are
   legitimately uncitable, but visible.
3. **The alert's status never round-trips through a model.** `AlertRef` in the finished
   brief is built by `orchestrator._assemble_brief` copying the inbound alert. No model sees
   it as an output field.
4. **Logging cannot be turned off.** `TranscriptLogger` is a required constructor argument
   of every LLM client and of the orchestrator. No default, no `None` branch, no config key.
   A client that could make an unlogged call is not constructible.

The prompt-level defenses — data fencing with envelope metadata, "log content is never
instructions" — are in `prompting/envelope.py`, clearly labelled as the soft layer.
`validation/injection.py` is a cheap post-pass that flags log content appearing to address
an AI system; hits land on the brief rather than being filtered out, because an injection
attempt in a log is itself a detection signal.

---

## Serving layer

The commander is a JSON contract; any engine that passes `make health`'s guided-JSON round
trip satisfies it. Two stacks have run on this box. **Flash-Next via SGLang is the current
one**; the co-located vLLM pair is documented after it, because its memory-split saga is a
hard-won GB10 lesson worth keeping.

### Current: Qwen3.8-Flash-Next on SGLang (commander-only)

The 125B ultra-sparse MoE `Qwen3.8-Flash-Next` (6B active params, nvidia NVFP4 tree) runs
as the commander via **SGLang** on `:18400`, with the grunt pointed at the same endpoint
and the vLLM pair down. `deploy/flashnext/` holds the scripts, adapted from
single-spark-ai's DGX-Spark recipe. Cutover: `make down`, then
`bash deploy/flashnext/probe-image.sh` (CPU-only, confirms the pinned image knows
`qwen4_exp`), then `bash deploy/flashnext/launch-flash-next.sh`, then swap the
`[models.commander]` / `[models.grunt]` blocks in `config.toml` to the Flash-Next pair and
run `make health`. Rollback is `docker stop flashnext-commander && make up` plus reverting
the config. Sampling is Qwen's instruct recommendation (temp 0.7, top_p 0.8), not the 0.2
used for gpt-oss: Qwen MoEs repetition-loop at low temperature. Thinking is disabled via the
chat template, because guided JSON and a think-block fight over the first token.

**Grunt-off, not gone.** The model's resident set (~80 GiB weights + KV + the mmap'd PLE
table's page cache) leaves ~21 GiB — no room for a second model. Both roles point at the
one endpoint; `close_read` has fired zero times in 10+ graded runs, so nothing real is lost.

**Three GB10-specific pitfalls are baked into `launch-flash-next.sh` and must not be
"optimized away"** — each cost a failed load to find:

1. **The PLE n-gram table must be file-backed, not pinned.** Native `--ple-offload-embedding`
   pins the ~48 GiB table in host memory, which on unified memory *is* the GPU pool —
   80 + 48 OOMs the box at load. A 30-line patch (`deploy/flashnext/overlay-native/qwen4_exp.py`)
   makes it a `MAP_SHARED` file-backed tensor instead: evictable page cache, and coherent
   unified memory makes a pageable pointer as GPU-readable as a pinned one.
2. **`ple_embedding_dtype=float8_e4m3fn` must be declared** via `--json-model-override-args`,
   or the loader refuses the fp8→bf16 auto-switch under PLE offload (and the table balloons
   to 95 GiB as bf16).
3. **KV cache must stay bf16.** The image's native SM121 QSA kernel is gated to BF16 KV;
   `--kv-cache-dtype fp8_e4m3` is rejected at CUDA-graph capture. At 131k tokens the cost of
   bf16 KV is 1.5 GB — irrelevant here.

Docker on this box needs `sg docker -c "..."` from a fresh shell until the login session
picks up the docker group.

### Previous: the co-located vLLM pair, and the memory-split lesson

The original stack ran two vLLM instances co-located on the one GB10, sharing its 128 GB
unified pool with the OS. Image **`nvcr.io/nvidia/vllm:26.07-py3`** (arm64) — vLLM 0.24.0,
torch 2.13.0a0, CUDA 13.3.1. `config.toml` keeps this block commented as the fallback: if
Flash-Next fails to load, uncommenting it and `make up` brings back `openai/gpt-oss-120b`
(commander, `:8000`) and `Qwen/Qwen3-8B-FP8` (grunt, `:8001`).

| | commander | grunt fleet |
|---|---|---|
| model | `openai/gpt-oss-120b` (native MXFP4) | `Qwen/Qwen3-8B-FP8` |
| port | 8000 | 8001 |
| `--gpu-memory-utilization` | **0.64** (~76.5 GiB) | **0.24** (~28.7 GiB) |
| `--max-model-len` / `--max-num-seqs` | 16384 / 4 | 16384 / 8 |

**0.64 + 0.24 = 0.88** of the ~119.6 GiB vLLM actually sees (not the nominal 128 GB). With
both loaded and serving, `free -g` reports 114 of 121 GB used, ~6 GB available — thinner
than the arithmetic, because container and per-process overhead sit outside both fractions.

These fractions are measured, not estimated, and that is the lesson. The first boot at
0.55/0.28 failed with *"No available memory for the cache blocks"* and
`Available KV cache memory: -1.95 GiB`: gpt-oss-120b loads to **66.1 GiB**, ~5 GiB more than
its on-disk size (MXFP4 scales and padding), and CUDA graph capture reserves another
1.6 GiB — a ~0.57 floor just to start. The lines to watch on every boot are `Available KV
cache memory` and `maximum concurrency`; they move when the model, context length, or vLLM
version changes. Static fractions are the documented fix, not a preference — vLLM's default
0.92 is named in NVIDIA's release notes as the cause of OOM on unified-memory systems, and
the flag's own help text says two instances coexist by construction at explicit fractions.
Neither instance may autodetect "all available memory": on this box that starves the OS and
whichever starts second loses. **Start order matters** (vllm#10643): `docker-compose.yml`
gates the grunt on the commander's healthcheck. Big model first, always. One grunt instance
serves every grunt — concurrency is vLLM's continuous batching; duplicating the weights
would buy nothing.

The fractions live in `deploy/commander.env` and `deploy/grunt.env`, deliberately not
repeated in `config/config.toml` — one place to be wrong instead of two.

---

## Running it

`make setup` and (for the vLLM stack) `make weights` are one-time; the rest is the service
lifecycle. To bring the current commander up, see "Serving layer" above; to bring the vLLM
pair up:

```bash
make setup          # venv + editable install
make weights        # fetch ~72 GB of weights into the shared HF cache (vLLM stack)
make up             # start both vLLM instances (commander first)
make health         # /health, served model name, guided-JSON round trip
make ps             # service state, including health
make down           # when you want the GPU back
```

**The commander cannot be restarted on its own** on the vLLM stack. `make restart
SERVICE=commander` refuses; `make restart-commander` cycles the whole stack. Its checkpoint
is 62 GB against 121 GB shared with the OS; if the grunt is resident it holds ~28 GiB,
leaving less room than the checkpoint needs, and the load thrashes indefinitely — no crash,
no OOM kill, just "Starting to load model" forever with memory sawtoothing. That is worse
than an error because it looks like progress. `make restart-grunt` bounces just the grunt
after an env edit and prints the command line it is serving so you can confirm a flag took.

### Investigating

`analyze.py` starts nothing heavy: it assumes the endpoint is already up and preflights it
before the orchestrator leaves `RECEIVED`.

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
    logs/           your raw logs, any text format (TSV, JSON lines, syslog) — required
```

That is it. There is nothing to hand-author and nothing to configure: every file in
`logs/` becomes searchable, and a `.jsonl` file's keys are read exactly as a Zeek header's
columns are. `fixtures/` is itself a case folder, so `./analyze.py fixtures` runs the
bundled demo — that is all `make demo` and `make demo-offline` do.

Output, one directory per run:

```
out/<investigation_id>/
    transcript.jsonl        canonical: every LLM call, transition and validation, one JSON
                            object per line, flushed as it goes
    transcript.json         readable view of the same, written at close
    brief.json              the artifact for the operator (absent if the run failed)
    run_meta.json           config snapshot, model ids, git sha, terminal state
    stats.json              performance counters, for comparing runs
```

`transcript.jsonl` stays canonical because it is the only form a dying run can leave usable
— a single pretty-printed array cannot be written incrementally. `brief.json` carries a
`step_ledger`: every question the commander asked, why, what it expected *before* the
result, what came back, and the shell command that reproduces it. Read that first — it is
what makes the brief checkable without a GPU. Two audit fields follow: `unresolved_citations`
(references to lines never actually shown) and `uncited_claims` (evidence written with no
reference). `stats.json` carries wall clock and per-phase time, per-role call counts,
retries, token usage, rejection rate by reason, `seconds_per_step` (which calibrates the
next run's estimate) and, from the server's `/metrics`, the prefix-cache hit rate — which
matters because consecutive commander turns share the alert, the profile and all but the
newest steps.

### Watching and stopping a run

`analyze.py` streams the commander's reasoning live to stderr as it plans and synthesizes;
`--quiet` turns it off. Results go to stdout, so `./analyze.py case > result.txt` behaves.

```bash
./abort.py            # graceful: finish in-flight readers, then synthesize what we have
./abort.py --hard     # cancel in-flight work, write no brief
./abort.py --list     # what is running
```

A graceful abort ends in `DONE` and stamps a code-level `aborted_by_operator` flag on the
brief, so nobody reading `brief.json` alone mistakes an interrupted run for a complete one.
The commander is *asked* to record the abort in `coverage_gaps` and generally does, but the
flag is the guarantee. Once a run reaches `SYNTHESIZING` it finishes — interrupting the one
call that produces the artifact would throw the run's product away.

### Swapping models

`config/config.toml` holds every endpoint and model name; commander and grunt are swappable
without touching code, because the contract is a JSON schema. It keeps commented alternates
for each model trialled (`gpt-oss-120b`, `Qwen3.8-27B`, `Qwen3.8-Flash-Next`) with exact
cutover and rollback steps inline. `make health`'s guided-JSON round trip is the arbiter for
any swap: a served model that passes it satisfies the contract regardless of the engine
behind the endpoint. A stubbed `[models.evaluator]` (`enabled = false`) is the seam for a
future cloud frontier judge; nothing reads it yet.

---

## The cases

`analyze.py` runs any case folder; the four seeded generators write *graded* cases, each
with a `GROUND_TRUTH.md` at the case root (which `analyze.py` never reads) and a rubric in
`scripts/grade.py`. Each case is built to be a different *timing signature* and to carry
benign decoys that defeat the obvious heuristic, so a brief is judged on evidence-driven
reasoning rather than template-matching. Every identifier — IPs, hosts, domains,
User-Agents, timestamps, volumes — is novel and seeded, so pattern knowledge helps the
model the way it helps a human analyst and there is no specific case to memorize;
contamination that did leak in degrades into a *visible* failure (a memorized fact the
model was never shown cannot be cited, so it lands in `uncited_claims`).

- **`cases/dns-tunnel`** (`make_dns_tunnel_case.py`) — a **bursty** DNS tunnel with
  payload-bearing answers and four tunnel-shaped benign decoys (DNSBL, AV reputation, CDN
  cache keys, DKIM).
- **`cases/http-c2`** (`make_http_c2_case.py`) — a **periodic** HTTP beacon (~60 s jittered
  check-ins), an anomalous constant User-Agent, and outbound POST exfil. Its killer decoy is
  an internal monitoring agent that heartbeats on a fixed interval from many hosts including
  the victim, so "beacons periodically to one host" is benignly true.
- **`cases/wmi-lsass`** (`make_wmi_lsass_case.py`, `make case-wmi-lsass`) — Windows **host**
  telemetry (Security + Sysmon as JSON lines), a WMI lateral-movement into an LSASS
  credential dump, timed as a **single ~80 s chain**. Derived from two public EVTX attack
  samples (sbousseaden/EVTX-ATTACK-SAMPLES, GPL-3.0) with every identifier re-seeded. Its
  killer decoy is an SCCM agent running the *exact* `WmiPrvSE.exe → cmd.exe` pair the alert
  matches, on every host all day, so the intrusion is only visible by pivoting to the logon
  source, the account, and the lsass access (`field=` on `LogonType`, `IpAddress`,
  `GrantedAccess`).
- **`cases/schtask-persist`** (`make_schtask_case.py`, `make case-schtask-persist`) — Windows
  host telemetry, a scheduled-task persistence timed as **install-then-fire**: a task
  (Security 4698) whose action is an encoded PowerShell payload is registered, and ~an hour
  later runs on its own schedule in SYSTEM context with no logon in front of it, executing
  the same payload. The two phases are joined by the base64 payload — the identical value on
  lines an hour apart, which the synthesis recap's shared-identifier note surfaces. Its
  killer decoy is the fleet of benign scheduled tasks (GoogleUpdate, Edge, SCCM) that
  register and fire on every host, so the discriminator is the task's *action*, not that a
  task exists. The `decode` skill turns its `-Enc` payload into the command it runs.

The Windows cases need the `cases` extra (`pip install -e ".[cases]"`, which adds
`python-evtx`). `make grade RUN=out/<id> CASE=cases/<name>` selects the rubric; the default
is `cases/dns-tunnel`. A new scenario is one entry in `scripts/grade.py`'s `CASES` registry
plus a generator — no change to the grading machinery.

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

If it fires: work through the flag ladder in `deploy/commander.env`, applying each
candidate with `make restart-commander` and re-running `make health` — the round trip is
the arbiter, so there is no point reasoning about which flag *should* work. If none of
them do, swap the commander model (commented fallback block in `config/config.toml`). The
investigation loop does not care which model is behind the schema.

**Guided decoding silently does not engage when the prompt looks like a tool menu.** The
worst bug of the port, because there is no error: vLLM accepts `response_format`, returns
200, puts `reasoning` in its own field, and hands back unconstrained text in `content`.

Measured on the real dns-tunnel prompt, three requests per mode: `response_format` 0/3
conformant, `structured_outputs` 0/3, legacy `guided_json` 0/3. The *same schema* on a
short prompt, or on the retry turn, came back perfectly conformant every time — so it is
not the schema and not the backend flag. What comes back instead is always a tool call:

```json
{"action": "count",  "action_input": "t\\.api-sync-telemetry\\.net"}
{"action": "search", "action_args": {"regex": "...", "case_insensitive": true}}
```

The commander prompt lists six verbs, and gpt-oss reads a verb menu as an invitation to
use its harmony tool-call channel — which the final-channel grammar never constrains.
Adding one paragraph stating that there is no tool-calling interface and naming the nine
expected keys took it to 2/2. That paragraph is `_NOT_A_TOOL_CALL` in
`prompting/investigate.py`, and it is load-bearing rather than stylistic.

Because a prompt is not a guarantee, `coercion.py` is the second line: it maps the
tool-call envelopes above onto the action schema deterministically, and the result goes
through `validate_action` like anything else. If you change the commander model or bump
vLLM, re-run the check — the failure is invisible from the client's side, and the symptom
is an investigation that ends after three steps for no stated reason.

**If the commander OOMs** — `No available memory for the cache blocks`, which is what
0.55 did — the ladder is: raise `COMMANDER_GPU_FRACTION` (taking it from
`GRUNT_GPU_FRACTION`) → drop `COMMANDER_MAX_MODEL_LEN` → add `--kv-cache-dtype fp8` to
`COMMANDER_EXTRA_ARGS`. The current 0.64/0.24 leaves 7.9 GiB of KV cache; the memory
profiler prints the exact shortfall, including a suggested fraction, so read it rather
than guessing.

Memory fractions, and anything touching the commander, need the full ordered cycle: both
instances must re-profile, and the grunt cannot claim its share until the commander has
taken its own. `make restart-commander` does this for you. Single-service restart is for
the grunt only.

Because a memory misconfiguration fails at engine init, both services use
`restart: on-failure:3` rather than `unless-stopped` — otherwise the failure presents as
an endlessly "starting" container that looks like a slow load.

**FP8 block scales need DeepGEMM off.** `Qwen/Qwen3-8B-FP8` ships block-wise FP8 scales,
which vLLM routes through DeepGEMM by default; on GB10 that dies at weight load with
`Unknown SF transformation` from `layout.hpp` — DeepGEMM's scale-factor layout transform
has no case for this architecture. `deploy/grunt.env` sets `VLLM_USE_DEEP_GEMM=0`, which
falls back to the generic FP8 path. Recheck on a vLLM bump — `make restart-grunt` and
`make health` will tell you in about two minutes, without disturbing the commander.

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
`make health` be the arbiter. `make restart SERVICE=<name>` prints the command line the
container is actually serving with, which is the quickest way to confirm a flag was
accepted rather than silently dropped.

---

## Non-goals

Explicitly not in this build, with the seam each one will land on:

- **Telemetry pipeline.** Precomputed pattern summaries were in the original design,
  removed on the grounds that the commander must not read data, and have effectively
  returned as `profiling.py` — with the difference that matters: the profile is computed
  in code, so it is arithmetic rather than a model's opinion, and every number in it can
  be re-derived with `grep` and `sort`.
- **Eval harness.** Seam: the `LLMClient` protocol (`llm/base.py`) plus the
  `[models.evaluator]` config entry. The transcript corpus is the eval set.
- **Synthetic scenario generation.** No longer a non-goal — four generators
  (`make_dns_tunnel_case.py`, `make_http_c2_case.py`, `make_wmi_lsass_case.py`,
  `make_schtask_case.py`) each write a graded case folder plus a `GROUND_TRUTH.md`, with
  `scripts/grade.py` scoring against a case-keyed rubric (see "The cases"). The seam held:
  a case folder is just `alert.json` + `logs/`, so a generator writes one and
  `./analyze.py` runs it unchanged.
- **Multi-machine serving.** Endpoints are per-role in config rather than assumed
  co-located, so a second box is a config edit.
- **Latency and throughput tuning.** Deliberate. This box is bandwidth-bound and the
  work is not interactive.
- **Any UI.** The brief is JSON.

Also not attempted: retrieval over the full log estate (a case is a folder of files),
embeddings or a vector index — spiked and rejected, since the questions here are
"how many" and "which lines", which grep answers exactly and an embedding answers
approximately — alert triage or correlation across alerts, and any write path back
to the detection system.

---

## The first runs on the action loop

`cases/dns-tunnel`, the same case the six sweeps were graded on, graded by
`scripts/grade.py` against `GROUND_TRUTH.md`. REACHED means the brief states the fact;
CITED means it states it *and* backs it with the right line reference.

| | sweep, run 6 (best of six) | action loop, run 7 |
|---|---|---|
| wall clock | 12.4 min | 5.6 min |
| model calls | 88 | 20 |
| attribute traffic to `10.12.34.56` | ✅ | ✅ |
| identify the host as `wks-2291` | ❌ | ✅ CITED |
| find the NS delegation | ❌ (0 of 6 runs) | ✅ CITED |
| name the nameserver `45.77.203.118` | ❌ | ✅ CITED |
| answers carried the payload | ❌ | ✅ |
| bursty timing, not periodic | ❌ | ✅ |
| non-empty `coverage_gaps` | ❌ `[]` | ✅ 7 entries |
| decoy false positives | 0 | 0 |
| unresolved citations | 0 | 0 |

**7/7, at a sixth of the model calls.** The run also produced a C2 hypothesis that ties
`45.77.203.118` to the delegation — the connection no earlier run made — and kept all four
decoys out of its supporting evidence.

Runs 4 and 6 scored 5/7 and 6/7 on the same checklist. Progress across them came from three
fixes, each bought by a specific failure:

1. **A crash that cost an entire run.** Run 5 died at step 22: the commander emitted
   `ref: "L978"` without the file prefix, a presence-only check let it through, and
   `int("")` raised straight through the orchestrator loop — discarding 21 completed steps
   and producing no brief. Reference *shape* is now validated, `reproduce_command` is
   total, and `_step` routes any unexpected exception to a legal state instead of
   unwinding. "Failures are values" had only ever been enforced at the worker boundary.
2. **A brief built on its own broken regexes.** Run 6 searched
   `\tTXT\t.*t\.api-sync-telemetry\.net`, got zero — Zeek puts the query *before* the
   qtype, so it cannot match — and wrote that zero into the brief as *contradicting
   evidence against the tunnel*. There are 649 such queries. The prompt already warned
   that a zero is only a zero for the pattern you typed, and the model did it anyway, so
   the check moved into code: `zero_result_hint` counts the longest literal in any empty
   pattern and says so where it cannot be missed. A genuine absence stays silent.
3. **A grader that under-read the briefs.** gpt-oss writes non-breaking hyphens
   (`wks‑2291`), so ASCII matching reported MISSED on facts the brief had stated. Two
   published grades were wrong because of it.

### The loop, and why the ledger caused it

A later run scored 5/7 and visibly looped — "no user or host, maybe in DHCP", twice. Steps
3 and 8 were byte-identical actions; four more steps were near-duplicate counts of the same
domain. The cause was `evidence.py`, and it was a rendering choice, not a model failure.

`STEPS_RENDERED_IN_FULL = 4`, so by step 8 the earlier search had collapsed to:

```
3. search /10\.12\.34\.56/ in dhcp.log -> 2 match(es) in dhcp.log; all shown
```

The count survived. The answer did not — `wks-2291` was nowhere in the prompt. So the
commander correctly concluded it still did not know the hostname and asked again, and that
fresh answer would age out four steps later in turn. An unbounded loop by construction. The
old justification in the module docstring ("counts are most of the value") is true of
`count`, whose product IS a number, and false of `search`, where the lines are the answer.

It nearly cost the brief the hostname too: `wks-2291` reached synthesis only because the
loop happened to re-fetch it late enough to still be inside the window.

Three fixes:

1. **A collapsed step keeps a sample of its lines** (`COLLAPSED_LINE_SAMPLE = 3`, elided to
   130 chars), and says how many it withheld. Over 24 steps against `cases/dns-tunnel` the
   ledger goes from ~2,700 to ~5,400 tokens against a 24,384 context — the right trade,
   since the whole point of a ledger is not having to ask twice.
2. **An identical action is answered from the ledger** rather than re-run, with a summary
   that names the earlier step. Defence in depth, and a repeat now costs no work.
3. **A file-less reference is repaired, not fatal.** `{"ref": "L975", "file": "dns.log"}`
   ended a run at step 9 with 16 of 24 steps unspent: rejected, repeated verbatim on the
   retry, loop gave up. The correct reference was fully determined by the action's own
   fields, so `coercion.repair_ref` concatenates it. When rejection is still necessary the
   message is built from what the model actually wrote, not a fixed unrelated example.

**Still wrong:** the brief cites computed facts (burst windows, exact counts) in
`raw_line_refs` because the schema has nowhere else to put them — 7 entries in run 7,
down from 22. Coercion still fires on some steps, and each one loses the model's stated
`reasoning`. See the guided-decoding note under "Known issues".

### The tally-era loops, and the advisories that break them

Enabling the `tally` skill surfaced a new loop, not in the ledger this time but in the
*regex*. A run spent 8 of 24 steps re-asking one question — "which hosts query this
domain?" — with eight different patterns, six of them over-anchored to a column layout
that cannot match, because the log puts the query before the qtype. `zero_result_hint`
fired every time and was ignored every time: a generic "check field order" is not enough
when the model has already read real lines between attempts. So the advisories got
specific, and they are advisory only — the action is always executed as written, and the
note is appended to its result where the commander cannot miss it (the runtime disposes;
it does not suppress a proposal). Four layers, each earned by a transcript:

1. **Partial coverage carries its own refutation.** A tally that matches 1 of the 788
   lines its own anchor literal appears on says so — the wrong-small-number case the
   zero-only hint never saw. (`actions.coverage_hint`)
2. **A multi-anchor zero is diagnosed exactly.** With two literals present, "your anchors
   occur together on 649 lines but in the OPPOSITE order — swap them" replaces "check
   field order", and the mirror case ("right order, the mismatch is BETWEEN them — join
   with `.*`") is named too. Both are checkable arithmetic. (`actions.zero_result_hint`)
3. **A failed re-ask names the step that already answered it.** Identity is the anchor
   *literal*, not the pattern — the eight variants shared one — so the note points at the
   earlier non-zero result, and from the third fruitless attempt escalates to "stop
   varying the frame". (`orchestrator.same_literal_note`)
4. **A tiny count is nudged toward fetching.** A `count` of 1–3 is usually the rare,
   decisive line — and a count cannot be cited. The result says "few enough to read;
   re-run as a search". (One graded run counted the attacker nameserver twice and never
   fetched it, so the brief could not cite its strongest evidence.)

The value selectors (`field=`/`extract=`, above) are the structural fix beneath these
advisories: they remove the column-counting regex that produced the loop in the first
place. Across the selector runs the commander reached for `field=` on its own four to five
times per case, and zero-result steps fell from eight to one or two. The advisories stay as
the net for the patterns a selector cannot express.

### What the selector runs also showed: the bottleneck moved

With the investigation loop healthy, the remaining graded misses were no longer failures to
*find* evidence — they were failures to *carry it into the brief*, on two fronts:

- **Synthesis dropped a fetched fact — now fixed.** One run searched `dhcp.log`, was shown
  the two lease lines that name the host, *wrote the hostname in its own step-23
  reasoning*, and then produced a brief that never mentioned it. The evidence was in the
  ledger with its refs; synthesis left it there. The fix is `_evidence_on_record` in
  `prompting/investigate.py`: a deterministic, flat, uncollapsed recap of every line the
  commander *fetched* (number-only aggregates excluded — they carry no citable lines; `extremes` rows are included), placed
  at the end of the synthesis prompt, paired with a requirement to reconcile against it —
  each fetched line appears in the brief or is set aside in `coverage_gaps` with a reason,
  and an established identity (an IP's hostname, a domain's address) is never left unstated.
  On the case that exhibited the drop, the host went from absent to **CITED** and the run
  to 7/7. It re-presents the run's own evidence, so it cannot hallucinate.
- **Mechanical grading under-reads correct analysis.** A brief that said "NS and A record
  lookups … resolving to IP 45.77.203.118" and "TXT queries … returned high-entropy …
  strings" had both the NS delegation and the payload right — but `grade.py`'s needles want
  the tokens "NS record" and "answer … payload", so both scored MISSED. Single-run scores
  are therefore noisy; the transcript is the truth, and the grader is a coarse gate, not a
  verdict. Widen a needle only when it under-reads a genuinely correct statement, never to
  make a weak brief pass.

---

## Why the sweep is gone

The previous architecture read every slice of every log file with a worker model, on an
argument that was sound: if every line is read, then "we found nothing else" means
something. Six graded runs against `cases/dns-tunnel`, each about 4,300 GPU-seconds,
established that the premise does not survive contact with the workers.

**Reading is not noticing.** Two findings settled it:

- Worker `dhcp-0001` was handed an eight-line DHCP file with the lease for the alerted
  host on lines 4 *and* 8. It reported `"10.12.34.56" → found: false`, and the brief went
  out saying the host could not be identified. `grep` finds it in 3 ms.
- The NS delegation tying the tunnel domain to attacker infrastructure
  (`dns.log:L975-976`, resolving `ns1.api-sync-telemetry.net` → `45.77.203.118`) appears
  in **no worker output across all six complete sweeps**. It is the strongest single piece
  of evidence in the case. `grep -n ' NS '` finds it in 0.003 s.

Run 6 was the best of them — mechanically clean, zero rejections, zero failures, no decoy
contamination — and still missed the host attribution, the NS delegation, the fact that
the answers carried the payload, and the bursty timing. The mechanics were an A; the
analysis was a C+, and the ceiling was the worker layer, not the commander.

**What replaced the coverage claim.** `corpus.count()` is exact, instant, and re-runnable
by anyone with the case folder. That is strictly more than "a model read it and did not
mention it" was ever worth. The claim changed hands rather than weakening.

**What the profile finds that six sweeps did not**, on the same 1 MB case, in 0.31 s:

| | |
|---|---|
| rare shapes in `dns.log` | exactly one: the NS delegation at `L975` |
| tunnel vs. decoys | `t.api-sync-telemetry.net` — 785 tokens, mean entropy 3.62, **1 source**, against `cdn-assets.example.com` (12 sources) and `vendor-cloud.example.net` (12 sources) at the same entropy |
| activity bursts | the five planted sessions exactly: 96, 210, 64, 288, 130 events |

`distinct_sources` is the field doing the work in the middle row. Encoded exfiltration and
an antivirus reputation service are indistinguishable by entropy; one host versus twelve
separates them without a model forming an opinion about either.

**What the grunts kept.** `close_read` still exists, because some questions genuinely need
reading rather than counting — "what do these 30 lines have in common?" is not a regex. It
is now requested deliberately, at a bounded range, with a question the commander wrote,
rather than issued 83 times at everything.

---

## What the real runs showed

The six runs below are the sweep architecture's history. They are kept because each one
bought a fix that is still in the code, and because the case for replacing the sweep is
made of them. Timings there: commander directive ~20 s, drill-down plan ~31 s, synthesis
~95 s, grunt reports median 43 s; a 1 MB case (83 slices) ran ~11-16 minutes end to end at
8-way batching, of which ~4,300 GPU-seconds was the sweep itself.

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

### Run 3: fast, and wrong

The efficiency work landed — 34.6 min → **11.1 min**, 60 rejections → **0**, 18 task
failures → **0**, p95 latency 338 s → 57 s. Then the brief concluded:

> "No evidence of high-entropy labels, large TXT payloads, or repeated queries to the same
> DNS server was found."

All three false, against 788 tunnel queries with 28–40 character hex labels and a base32
payload on every one. Those false negatives became the entire supporting case for a third
hypothesis — *"the Suricata signature produced a false positive"*. Two causes, both mine:

**The negative aggregate manufactured them.** The "checked for and did not find" section I
added the session before rendered per-slice negatives without scope, without denominators,
and without reconciling against the 38 slices that found exactly those things. Ten subjects
were reported both found and not-found; only the not-found side was shown. Fixed: `scope`
restored to `CheckedFor`, denominators on every line, per-file grouping, and any subject a
worker found is struck from the negative list with the suppression stated out loud.

**A worker described the directive instead of the line.** `dns.log:L244` — an antivirus
reputation lookup — was reported as *"TXT queries from 10.12.34.56 to
api-sync-telemetry.net"*, and became the brief's primary evidence for the tunnel. The
reference resolved, so every check passed. The commander could not have caught it: it had
the line *number* and nothing else.

Two fixes, because one was not enough:

- `validation/citations.py` now checks that a description's claims match its lines. The
  directive's indicators are exact strings, so if a description names one, at least one
  cited line must contain it. This catches `dns-0004` on the first attempt. It is
  deliberately narrow — it only fires on indicators the description itself invokes, so a
  worker describing something nobody asked about is untouched.
- The commander is shown the lines. Replaying run 3's reports through the new renderer, it
  now reads a 40-character hex label with a base32 answer payload directly above the claim
  that no such labels exist.

Worth being precise about what the suppression does *not* do: it caught 18 contradicted
negatives on replay, but not those three, because no worker ever *described* entropy —
there was nothing to contradict. Those now carry "looked for in 15 of 87 slices … says
nothing about slices that did not look", the synthesis prompt forbids promoting a
per-slice negative to a global one, and the evidence sample makes the contradiction
visible. Layers, not a single catch.

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
- **Findings double-count within a slice** — totals came to 817 against a ground truth of
  788.

### The efficiency problem, and what fixed it

The 83-slice run took **34.6 minutes against a 4.3-minute estimate**. Almost all of the
overrun was one pathology:

| | calls | median | total compute |
|---|---|---|---|
| normal | 112 | 39.4 s | 4,891 s |
| **truncated** | **22** | **330.6 s** | **6,372 s** |

**22 replies burned 57% of all grunt compute and every one was discarded.** They hit the
3,072-token ceiling emitting indentation — a sampled reply was 92% whitespace. Guided
decoding permits arbitrary whitespace between tokens, and a small model can fall into a
low-entropy loop producing it. Three changes:

- `--structured-outputs-config.disable_any_whitespace true` on the grunt server, which is
  what that flag exists for. Measured after: **92% → 9% whitespace**.
- Grunt `max_tokens` 3072 → **1400**, sized from data rather than guessed: across 112
  successful reports the median completion was 313 tokens, p99 971, maximum 1125. A
  runaway now fails fast and cheap instead of burning the full ceiling.
- **`maxItems` is no longer stripped from the schema.** It was removed on an untested
  assumption that xgrammar ignores it; it does not — a schema declaring `maxItems: 3`
  returns exactly 3 when asked for 20. That converts the largest remaining failure class
  (23 of 60 rejections were workers returning 25–38 references against a cap of 5) from
  "reject and retry" into "cannot happen". `minItems` stays stripped, deliberately: a cap
  stops over-production, a floor would force a worker to invent a citation it does not
  have.

**The estimate itself was the other half of the problem.** It multiplied slices by a
hardcoded 25 s and divided by configured concurrency, ignoring retries (83 slices produced
136 calls), the gap between configured and achieved concurrency (6.0 of 8), and the
latency tail (median 41 s, p95 338 s). It now calibrates from the machine's own last real
run using observed wall-clock seconds per slice, which contains all three by construction.
It retro-predicts that run at 31.3 minutes against an actual 31.3.
