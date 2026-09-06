#!/usr/bin/env bash
# Serve Qwen3.8-Flash-Next (nvidia NVFP4 tree) with SGLang on the GB10, as the
# soc-poc commander. Adapted from single-spark-ai's DGX-Spark recipe
# (bounded-ple/02-deploy-bounded-ple.sh) with these deliberate departures:
#
#   * PURE NVIDIA TREE. The RadixArk Hybrid-Sharp delta is access-gated, so no
#     FP8 dense bypass; `--quantization modelopt_fp4` on the stock tree is the
#     recipe's own documented fallback.
#   * PLE backend = mmap, not io_uring. The recipe's bounded io_uring reader
#     needs a rust extension whose source is not shipped. mmap is the overlay's
#     supported portable path; it uses page cache, which is fine HERE because we
#     run commander-only (no grunt) at small context -- the box has ~30 GB of
#     slack this deployment never touches.
#   * NO speculative decoding. MTP+xgrammar is exactly the "newest parser in the
#     hot path" class of risk this project avoids, and latency is a non-goal.
#   * Context 32768, not 262K/524K. The commander's prompts are <8K tokens; a
#     small KV pool leaves the page cache room for the mmap'd PLE table.
#   * KV cache at model default (bf16), NOT fp8: this image's native SM121 QSA
#     kernel is gated to BF16 KV ("unsupported SM121 QSA call ... expected
#     BF16"); the recipe's fp8-KV variant kernel exists only in its author's
#     private build. At 131k tokens the difference is 1.5 GB. Do not "optimize"
#     this back.
#
# Run as your own user (docker group / sudo as usual):   bash launch-flash-next.sh
# Stop:                                                  docker stop flashnext-commander
set -Eeuo pipefail

MODEL_DIR=${MODEL_DIR:-$HOME/ai-models/Qwen3.8-Flash-Next-NVFP4-hf}
RECIPE_DIR=${RECIPE_DIR:-$HOME/Code/spark-recipe}
IMAGE=${IMAGE:-lmsysorg/sglang:dev-cu13-qwen38flashnext}
NAME=${NAME:-flashnext-commander}
HOST_PORT=${HOST_PORT:-18400}
SERVED_MODEL_NAME=${SERVED_MODEL_NAME:-qwen3.8-flash-next}
CTX=${CTX:-32768}
MAX_TOTAL_TOKENS=${MAX_TOTAL_TOKENS:-131072}
MEM_FRACTION_STATIC=${MEM_FRACTION_STATIC:-0.85}

# All-native stack, one patched file. Three launch attempts established that
# (a) native --ple-offload-embedding pins the ~48 GiB n-gram table in host
# memory, which on GB10 is the same unified pool as the GPU -> OOM at load;
# (b) the recipe's model overlay is incompatible with this image's native QSA
# kernel gate; (c) the recipe's QSA overlay needs modules only present in its
# author's private build. So: native model, native kernels, and a single
# soc-poc patch to the model file that makes the PLE table a MAP_SHARED
# file-backed tensor (evictable page cache; equally GPU-readable on coherent
# unified memory) instead of a pinned allocation.
MDIR=/sgl-workspace/sglang/python/sglang/srt/models
PATCHED="$(cd -- "$(dirname -- "$0")" && pwd)/overlay-native/qwen4_exp.py"
PLE_DIR=${PLE_DIR:-$HOME/ai-models/.ple-mmap}
mkdir -p "$PLE_DIR"
# A stale table file from an aborted load has the wrong size/dtype; start clean.
rm -f "$PLE_DIR/qwen4_ple_table.bin"
test -f "$PATCHED"

# Read-only gates, recipe-style: fail before any container is touched.
test -f "$MODEL_DIR/config.json" || { echo "model tree incomplete: $MODEL_DIR" >&2; exit 1; }
test -f "$MODEL_DIR/model.safetensors.index.json" || { echo "weights not downloaded yet" >&2; exit 1; }
free_gb=$(free -g | awk '/^Mem:/{print $7}')
if (( free_gb < 90 )); then
  echo "only ${free_gb} GB available; stop the vLLM stack first (make down)" >&2
  exit 1
fi

docker rm -f "$NAME" 2>/dev/null || true
docker run -d --name "$NAME" \
  --gpus all --ipc host \
  --security-opt seccomp=unconfined \
  -p "127.0.0.1:${HOST_PORT}:30000" \
  -v "$MODEL_DIR:/model:ro" \
  -v "$PATCHED:$MDIR/qwen4_exp.py:ro" \
  -v "$PLE_DIR:/ple-mmap" \
  -e SGLANG_QWEN4_PLE_MMAP_DIR=/ple-mmap \
  -e SGLANG_RUST_BUILD_MODE=never \
  -e "PYTORCH_ALLOC_CONF=expandable_segments:True,garbage_collection_threshold:0.95" \
  "$IMAGE" \
  python3 -m sglang.launch_server \
    --model-path /model \
    --served-model-name "$SERVED_MODEL_NAME" \
    --host 0.0.0.0 --port 30000 \
    --load-format auto --tp-size 1 \
    --quantization modelopt_fp4 \
    --json-model-override-args '{"text_config": {"ple_embedding_dtype": "float8_e4m3fn"}}' \
    --attention-backend flashinfer \
    --decode-attention-backend trtllm_mha \
    --page-size 64 \
    --ple-offload-embedding --language-only \
    --weight-loader-drop-cache-after-load \
    --mamba-ssm-dtype bfloat16 \
    --mamba-radix-cache-strategy extra_buffer \
    --mamba-track-interval 64 \
    --mem-fraction-static "$MEM_FRACTION_STATIC" \
    --context-length "$CTX" \
    --max-total-tokens "$MAX_TOTAL_TOKENS" \
    --chunked-prefill-size 1024 \
    --max-prefill-tokens 2048 \
    --prefill-max-requests 1 \
    --max-running-requests 4 \
    --cuda-graph-bs-decode 1 2 3 4 \
    --disable-prefill-cuda-graph \
    --reasoning-parser qwen3 \
    --enable-metrics --enable-cache-report

echo "started $NAME on 127.0.0.1:$HOST_PORT -- follow with: docker logs -f $NAME"
echo "loading takes minutes; the lines to watch:"
echo "  'KV Cache is allocated'          (pool sized)"
echo "  'The server is fired up and ready to roll!'"
