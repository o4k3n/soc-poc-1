"""Thin CLI. All behaviour lives in runner.py; this only parses arguments."""

from __future__ import annotations

import argparse
import asyncio
import sys

from soc_poc.config import load_config
from soc_poc.runner import run_investigation
from soc_poc.states import InvestigationState


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soc-poc", description="Run one investigation.")
    parser.add_argument("--config", default="config/config.toml")
    parser.add_argument(
        "--backend",
        choices=("vllm", "stub"),
        default="vllm",
        help="stub runs the whole state machine offline with canned model output",
    )
    parser.add_argument("--investigation-id", default=None)
    args = parser.parse_args(argv)

    config = load_config(args.config)
    result, paths = asyncio.run(
        run_investigation(
            config, backend=args.backend, investigation_id=args.investigation_id
        )
    )

    print(f"terminal state : {result.terminal_state.value}")
    print(f"transcript     : {paths.transcript}")
    if result.brief is not None:
        print(f"brief          : {paths.brief}")
        print(f"alert status   : {result.brief.alert_ref.status} (unchanged, detector-owned)")
        print(f"tasks          : {len(result.brief.task_ledger)}")
        if result.brief.unresolved_citations:
            print(f"unresolved refs: {result.brief.unresolved_citations}")
        if result.brief.injection_signals:
            print(f"injection flags: {len(result.brief.injection_signals)}")
    if result.failure_reason:
        print(f"failure reason :\n{result.failure_reason}", file=sys.stderr)

    return 0 if result.terminal_state is InvestigationState.DONE else 1


if __name__ == "__main__":
    raise SystemExit(main())
