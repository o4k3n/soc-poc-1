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

.PHONY: setup up down logs health demo demo-offline test clean

setup:              ## create venv and install the package (editable) + dev deps
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

up:                 ## start both vLLM instances (commander first, grunt gated on its health)
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

health:             ## verify both endpoints: /health, served model name, guided-JSON round trip
	$(PY) scripts/health_check.py --config config/config.toml

demo:               ## one full investigation against the fixtures, real vLLM endpoints
	$(PY) scripts/run_demo.py --config config/config.toml

demo-offline:       ## same code path, stub LLM backend, no GPU required
	$(PY) scripts/run_demo.py --config config/config.toml --backend stub

test:
	$(PY) -m pytest -q

clean:
	rm -rf out/*
