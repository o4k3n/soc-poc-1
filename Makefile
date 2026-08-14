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

.PHONY: setup weights up down logs ps health demo demo-offline abort test clean

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

up:                 ## start both vLLM instances (commander first, grunt gated on its health)
	$(COMPOSE) up -d

ps:                 ## service state, including health
	$(COMPOSE) ps

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

test:
	$(PY) -m pytest -q

clean:
	rm -rf out/*
