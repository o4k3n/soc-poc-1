#!/usr/bin/env python3
"""Verify both vLLM endpoints before anything else runs.

    make health          # or: python scripts/health_check.py --config config/config.toml

Exit code 0 means the orchestrator can start. Anything else means it should not, and
the printed report says which of the three checks failed on which endpoint. See
src/soc_poc/preflight.py for what each check is actually proving.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from soc_poc.config import load_config  # noqa: E402
from soc_poc.preflight import preflight  # noqa: E402
from soc_poc.transcript import TranscriptLogger  # noqa: E402


async def _main(config_path: str) -> int:
    config = load_config(config_path)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    # Even a health probe is a logged LLM interaction: the corpus should contain the
    # boring calls too, including the ones that failed.
    transcript = TranscriptLogger(
        config.path(config.run.output_dir) / "health" / f"{stamp}.jsonl", f"health-{stamp}"
    )
    try:
        result = await preflight(
            [config.commander, config.grunt], config.structured_output, transcript
        )
    finally:
        transcript.close()

    print(result.report(), flush=True)
    if not result.ok:
        print(
            "\nEndpoints are not ready. If the commander passed /health and "
            "served_model_name but failed guided_json_roundtrip with empty content, "
            "that is the GB10/SM121 MXFP4 signature (vLLM issue #37030) -- see README "
            "> Known issues for the fallback swap.",
            file=sys.stderr,
        )
    return 0 if result.ok else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/config.toml")
    raise SystemExit(asyncio.run(_main(parser.parse_args().config)))
