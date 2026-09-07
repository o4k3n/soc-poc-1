PY := .venv/bin/python
PIP := .venv/bin/pip

# Host-side HuggingFace cache, shared by both containers. Override on the command line
# if your weights live elsewhere: `make up HF_CACHE_DIR=/data/hf`.
HF_CACHE_DIR ?= $(HOME)/.cache/huggingface

# Both env files are passed with --env-file so Compose can interpolate ${...} inside
# docker-compose.yml. `env_file:` alone would only set variables inside the containers,
# which is too late for the command line we build there.
COMPOSE := HF_CACHE_DIR=$(HF_CACHE_DIR) docker compose \
	--env-file deploy/commander.env \
	--env-file deploy/grunt.env \
	-f deploy/docker-compose.yml

VLLM_IMAGE := nvcr.io/nvidia/vllm:26.07-py3

.PHONY: setup weights weights-qwen38 weights-qwen38-int4 up down logs ps restart restart-grunt restart-commander health demo demo-offline abort grade test clean case-wmi-lsass case-schtask-persist

setup:              ## create venv and install the package (editable) + dev deps
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

# Pre-fetch weights before `make up`, for two reasons.
#
# 1. Size. `openai/gpt-oss-120b` is 195.8 GB in full, but vLLM only loads the root
#    model-*-of-00014.safetensors (~62 GB). The rest is metal/model.bin (65 GB, for
#    Apple silicon) and original/ (67 GB). Letting the server fetch the repo blind
#    downloads three times what it needs.
# 2. Timing. A cold download inside the container would outlast the commander's
#    healthcheck window, and the grunt service gates on that healthcheck -- so a slow
#    link would leave you with one server instead of two and no obvious reason why.
#
# Downloads are resumable: re-run this if it is interrupted.
#
# Note: the container runs as root, so the files it writes into $(HF_CACHE_DIR) are
# root-owned. That is fine here -- the vLLM services run as root too and only read them
# -- but it means your host user cannot prune the cache without sudo.
weights:            ## fetch just the weights vLLM needs (~72 GB) into the shared cache
	@echo ">> populating $(HF_CACHE_DIR) (~72 GB: ~62 GB commander + ~9.5 GB grunt)"
	@mkdir -p $(HF_CACHE_DIR)
	docker run --rm \
		-v $(HF_CACHE_DIR):/root/.cache/huggingface \
		--entrypoint python3 $(VLLM_IMAGE) -c "\
from huggingface_hub import snapshot_download; \
snapshot_download('openai/gpt-oss-120b', ignore_patterns=['metal/*', 'original/*']); \
snapshot_download('Qwen/Qwen3-8B-FP8'); \
print('weights ready')"

# Deliberately a separate target, not folded into `weights`. It is 55.6 GB for a model
# that is not the configured commander, so it should never be pulled as a side effect of
# preparing an ordinary run.
#
# No ignore_patterns here: unlike gpt-oss-120b (which ships metal/ and original/ copies
# vLLM never loads), this repo's 18 safetensors are all the ones that get loaded.
#
# See the "Alternative commander" blocks in config/config.toml and deploy/commander.env
# for what to change after this lands, and why 131072 rather than the native 262144.
weights-qwen38:     ## fetch Qwen/Qwen3.8-27B (~56 GB) to trial it as the commander
	@echo ">> fetching Qwen/Qwen3.8-27B (~56 GB) into $(HF_CACHE_DIR)"
	@echo ">> this is NOT the configured commander; see config/config.toml to switch"
	@mkdir -p $(HF_CACHE_DIR)
	docker run --rm \
		-v $(HF_CACHE_DIR):/root/.cache/huggingface \
		--entrypoint python3 $(VLLM_IMAGE) -c "\
from huggingface_hub import snapshot_download; \
snapshot_download('Qwen/Qwen3.8-27B'); \
print('Qwen3.8-27B ready')"

# The 4-bit build, and the one actually worth running on this box. Measured from the repo:
# 21.0 GB of compressed-tensors W4A16 against the official checkpoint's 55.6 GB of BF16.
#
# Why this rather than the official Qwen/Qwen3.8-27B-FP8 (30.9 GB): that checkpoint ships
# `weight_block_size: [128, 128]`, i.e. block-wise FP8 scales, which vLLM routes through
# DeepGEMM -- the exact path that fails at weight load on GB10 with "Unknown SF
# transformation" (see deploy/grunt.env). compressed-tensors uses Marlin kernels and never
# touches DeepGEMM, so the faster option is also the safer one here.
weights-qwen38-int4: ## fetch the 4-bit Qwen3.8-27B (~21 GB) -- the fast commander trial
	@echo ">> fetching cyankiwi/Qwen3.8-27B-AWQ-INT4 (~21 GB) into $(HF_CACHE_DIR)"
	@mkdir -p $(HF_CACHE_DIR)
	docker run --rm \
		-v $(HF_CACHE_DIR):/root/.cache/huggingface \
		--entrypoint python3 $(VLLM_IMAGE) -c "\
from huggingface_hub import snapshot_download; \
snapshot_download('cyankiwi/Qwen3.8-27B-AWQ-INT4'); \
print('Qwen3.8-27B-AWQ-INT4 ready')"

up:                 ## start both vLLM instances (commander first, grunt gated on its health)
	$(COMPOSE) up -d

ps:                 ## service state, including health
	$(COMPOSE) ps

# Restarting the GRUNT alone is safe and is the common case: it is a ~9 GB model, the
# commander is already resident, and there is room for both.
#
# Restarting the COMMANDER alone is NOT safe, and this target refuses to try. Its
# checkpoint is 62 GB against 121 GB of unified memory that the GPU and the OS share. If
# the grunt is resident it is holding ~28 GiB, which leaves less room than the checkpoint
# needs: the kernel reclaims page cache faster than the loader can stream, and the load
# thrashes forever. It does not crash, it does not OOM-kill, it does not restart -- it
# sits at "Starting to load model" with memory sawtoothing between ~28 and ~60 GB, which
# is a far worse failure than an error, because it looks like progress.
#
# The commander has to come up into an empty box, which is exactly the ordering `make up`
# already enforces via the grunt's healthcheck gate. So: full cycle, no shortcut.
restart:            ## restart one service, e.g. make restart SERVICE=grunt
	@test -n "$(SERVICE)" || { echo "usage: make restart SERVICE=grunt"; exit 2; }
	@if [ "$(SERVICE)" = "commander" ]; then \
		echo "refusing: the commander cannot be restarted on its own."; \
		echo "  Its 62 GB checkpoint does not fit alongside a resident grunt in 121 GB of"; \
		echo "  unified memory. The load will thrash indefinitely rather than fail."; \
		echo "  Use:  make restart-commander   (full ordered cycle, ~10 min)"; \
		exit 2; \
	fi
	$(COMPOSE) up -d --force-recreate --no-deps $(SERVICE)
	@echo ">> waiting for $(SERVICE) to come back healthy"
	@$(MAKE) --no-print-directory wait-healthy SERVICE=$(SERVICE)
	@$(COMPOSE) exec -T $(SERVICE) sh -lc 'echo ">> serving: $$(cat /proc/1/cmdline | tr "\0" " ")"' 2>/dev/null || true

# Progress matters here: an 8-minute silent wait is indistinguishable from a hang, which
# is how the thrashing load above got mistaken for a crash. Print what the loader is
# doing every 15s.
wait-healthy:
	@while :; do \
		state=$$($(COMPOSE) ps --format json $(SERVICE) | $(PY) -c \
			'import sys,json;print(json.loads(sys.stdin.read() or "{}").get("Health",""))'); \
		[ "$$state" = "healthy" ] && { echo ">> $(SERVICE) healthy"; break; }; \
		printf '   [%s] %s — %s\n' "$$(date +%H:%M:%S)" "$$state" \
			"$$($(COMPOSE) logs --tail 1 $(SERVICE) 2>/dev/null | tr '\r' '\n' | tail -1 | cut -c1-100)"; \
		sleep 15; \
	done

restart-grunt:      ## restart the grunt fleet only (safe; commander keeps serving)
	@$(MAKE) --no-print-directory restart SERVICE=grunt

restart-commander:  ## restart the commander (full ordered cycle — see comment above)
	@echo ">> the commander must load into an empty box; cycling the whole stack"
	$(COMPOSE) down
	$(COMPOSE) up -d
	@$(MAKE) --no-print-directory wait-healthy SERVICE=commander
	@$(MAKE) --no-print-directory wait-healthy SERVICE=grunt

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

health:             ## verify both endpoints: /health, served model name, guided-JSON round trip
	$(PY) scripts/health_check.py --config config/config.toml

demo:               ## one full investigation against the bundled fixture case
	$(PY) analyze.py fixtures

demo-offline:       ## same code path, stub LLM backend, no GPU required
	$(PY) analyze.py fixtures --stub

abort:              ## gracefully stop the running investigation (see ./abort.py --help)
	$(PY) abort.py

# Mechanical only: it checks whether each planted fact was reached, whether it was backed
# by the right line reference, and whether any decoy was cited as evidence. Whether the
# brief reads well is still a human call.
grade:              ## grade a run against its case, e.g. make grade RUN=out/inv-xxxx [CASE=cases/http-c2]
	@test -n "$(RUN)" || { echo "usage: make grade RUN=out/inv-xxxx [CASE=cases/<name>]"; exit 2; }
	$(PY) scripts/grade.py $(RUN) $(if $(CASE),--case $(CASE))

test:
	$(PY) -m pytest -q

case-wmi-lsass:     ## fetch the EVTX samples and (re)generate cases/wmi-lsass (needs the 'cases' extra)
	bash scripts/fetch_evtx_samples.sh
	$(PY) scripts/make_wmi_lsass_case.py

case-schtask-persist: ## fetch the EVTX samples and (re)generate cases/schtask-persist (needs the 'cases' extra)
	bash scripts/fetch_evtx_samples.sh
	$(PY) scripts/make_schtask_case.py

clean:
	rm -rf out/*
