#!/usr/bin/env bash
# CPU-only preflight for launch-flash-next.sh: proves the pinned image knows the
# qwen4_exp architecture, accepts the flags we pass, and that the overlays mount
# where we think they do -- in seconds, without touching the GPU or the weights.
# The lesson behind it is this project's own: a server can come up healthy and
# still be unable to do the one thing asked of it, so probe the cheap way first.
set -Eeuo pipefail

RECIPE_DIR=${RECIPE_DIR:-$HOME/Code/spark-recipe}
IMAGE=${IMAGE:-lmsysorg/sglang:nightly-dev-cu13-20260817-d91c3682}
MODELS_OV="$RECIPE_DIR/bounded-ple/overlay"
MDIR=/sgl-workspace/sglang/python/sglang/srt/models

docker run --rm \
  -v "$MODELS_OV/qwen4_exp.py:$MDIR/qwen4_exp.py:ro" \
  -v "$MODELS_OV/qwen4_ple_nvme.py:$MDIR/qwen4_ple_nvme.py:ro" \
  --entrypoint python3 "$IMAGE" -c '
import importlib
m = importlib.import_module("sglang.srt.models.qwen4_exp")
assert hasattr(m, "Qwen4ExpForConditionalGeneration"), "overlay lacks the entry class"
from sglang.srt.server_args import ServerArgs
import dataclasses
fields = {f.name for f in dataclasses.fields(ServerArgs)}
for need in ("ple_offload_embedding", "language_only", "mamba_ssm_dtype",
             "reasoning_parser", "decode_attention_backend"):
    assert need in fields, f"ServerArgs lacks {need} -- wrong image vintage"
print("PROBE-IMAGE-OK: qwen4_exp + required server args present")
'
