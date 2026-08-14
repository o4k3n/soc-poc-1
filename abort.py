#!/usr/bin/env python3
"""End a running investigation on purpose.

    ./abort.py                  # the one running investigation
    ./abort.py --id inv-...     # a specific one
    ./abort.py --hard           # cancel in-flight work, no brief
    ./abort.py --list           # what is running

Default is graceful: the orchestrator stops planning further rounds, lets in-flight
grunt tasks finish, and synthesizes a brief from whatever was collected, recording the
abort as a coverage gap. You get a readable artifact out of an interrupted run.

`--hard` cancels in-flight tasks (each recorded as a failure with reason "aborted") and
writes no brief. The transcript is complete either way -- it is written as the run goes,
not at the end.

One limitation worth knowing: once the run reaches SYNTHESIZING it finishes. Abort is
honoured at state boundaries and during collection; interrupting the single call that
produces the brief would throw away the whole run's product.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent

# See analyze.py: re-exec under the project venv so `./abort.py` works as typed.
_VENV = _ROOT / ".venv"
_VENV_PY = _VENV / "bin" / "python"
if _VENV_PY.exists() and Path(sys.prefix) != _VENV:
    os.execv(str(_VENV_PY), [str(_VENV_PY), str(Path(__file__).resolve()), *sys.argv[1:]])

sys.path.insert(0, str(_ROOT / "src"))

from soc_poc.config import load_config  # noqa: E402
from soc_poc.control import (  # noqa: E402
    AbortMode,
    RunMarker,
    active_runs,
    read_abort,
    request_abort,
    stale_runs,
)


def _describe(marker: RunMarker) -> str:
    return f"  {marker.investigation_id}  pid {marker.pid}  started {marker.started_at}\n    case: {marker.case}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="abort.py", description=__doc__.split("\n")[0])
    parser.add_argument("--config", default="config/config.toml")
    parser.add_argument("--id", dest="investigation_id", help="which run to abort")
    parser.add_argument("--all", action="store_true", help="abort every running investigation")
    parser.add_argument(
        "--hard", action="store_true", help="cancel in-flight work; write no brief"
    )
    parser.add_argument("--list", action="store_true", help="list running investigations")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    output_dir = config.path(config.run.output_dir)
    running = active_runs(output_dir)

    if args.list:
        if not running:
            print("no investigations running")
        for marker in running:
            print(_describe(marker))
        for marker in stale_runs(output_dir):
            print(f"  {marker.investigation_id}  (stale marker; pid {marker.pid} is gone)")
        return 0

    if not running:
        stale = stale_runs(output_dir)
        print("no investigations running", file=sys.stderr)
        if stale:
            print(
                f"({len(stale)} stale marker(s) from runs that died without cleaning up; "
                f"they are ignored)",
                file=sys.stderr,
            )
        return 1

    if args.investigation_id:
        targets = [m for m in running if m.investigation_id == args.investigation_id]
        if not targets:
            print(f"no running investigation named {args.investigation_id}", file=sys.stderr)
            return 1
    elif args.all:
        targets = running
    elif len(running) > 1:
        # Refuse to guess. Aborting the wrong hour-long run is not recoverable.
        print("more than one investigation is running; name one with --id, or --all:", file=sys.stderr)
        for marker in running:
            print(_describe(marker), file=sys.stderr)
        return 2
    else:
        targets = running

    mode = AbortMode.HARD if args.hard else AbortMode.GRACEFUL
    for marker in targets:
        run_dir = Path(marker.run_dir)
        existing = read_abort(run_dir)
        if existing is not None:
            print(
                f"{marker.investigation_id}: already aborting ({existing.mode.value}, "
                f"requested {existing.requested_at})"
            )
            if not (args.hard and existing.mode is AbortMode.GRACEFUL):
                continue
            print("  escalating to hard")
        request_abort(run_dir, mode, requested_by="abort.py")
        print(f"{marker.investigation_id}: abort requested ({mode.value})")
        print(
            "  it will stop without a brief"
            if mode is AbortMode.HARD
            else "  in-flight readers will finish, then it will synthesize what it has"
        )
        print(f"  watch: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
