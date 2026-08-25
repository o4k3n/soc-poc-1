"""`analyze.py` implementation: point it at a case folder and it runs.

All behaviour lives in runner.py and casedir.py; this parses arguments, prints the
things a human wants to see before a long run starts, and chooses the progress sink.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from soc_poc.casedir import CaseLayout, CaseLoadError, discover_case, scaffold_case
from soc_poc.chunking import chunk_logs
from soc_poc.config import AppConfig, FixtureConfig, load_config
from soc_poc.progress import ConsoleProgress, NullProgress, ProgressSink
from soc_poc.runner import run_investigation
from soc_poc.stats import estimate_investigation, format_summary
from soc_poc.states import InvestigationState

DEFAULT_CONFIG = "config/config.toml"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyze.py",
        description="Investigate an alert against a folder of logs.",
        epilog=(
            "A case folder is: alert.json, logs/ with your raw logs, and optionally "
            "patterns/ with hand-written summaries. Without patterns/, summaries are "
            "generated for you."
        ),
    )
    parser.add_argument("case", nargs="?", help="path to the case folder")
    parser.add_argument(
        "--init", metavar="DIR", help="scaffold an empty case folder and exit"
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="base config (endpoints, models)")
    parser.add_argument(
        "--stub", action="store_true", help="offline canned backend; no GPU needed"
    )
    parser.add_argument("--quiet", action="store_true", help="no live output")
    parser.add_argument(
        "--max-iterations",
        type=int,
        help="override the cap on investigative steps (default 24)",
    )
    parser.add_argument("--id", dest="investigation_id", help="name this run explicitly")
    parser.add_argument(
        "-y", "--yes", action="store_true", help="skip the cost confirmation"
    )
    return parser


def _apply_case(config: AppConfig, case: CaseLayout, args: argparse.Namespace) -> AppConfig:
    """Point the config at the case folder without anyone editing config.toml.

    Endpoints, models and limits still come from one place; only the inputs move.
    """
    run = config.run
    if args.max_iterations:
        run = run.model_copy(update={"max_iterations": args.max_iterations})
    return config.model_copy(
        update={
            "run": run,
            "fixtures": FixtureConfig(
                alert=str(case.alert_path), logs_dir=str(case.logs_dir)
            ),
        }
    )


def _preview(config: AppConfig, case: CaseLayout, out) -> int:
    """Show what the investigation will cost before it is spent.

    Reading the case here costs a file read and catches a broken case before any model is
    involved.

    The headline number no longer scales with the corpus. Under the sweep, 40 MB of logs
    was two hours of GPU time; searching is free, so the cost is the commander's turns and
    a bigger case mostly just means each search returns more.
    """
    catalog, inventory = chunk_logs(
        case.logs_dir,
        slice_token_budget=config.run.slice_token_budget,
        chars_per_token=config.run.chars_per_token,
    )
    total_lines = sum(item.line_count for item in inventory)
    max_steps = config.run.max_iterations
    minutes, basis = estimate_investigation(
        config.path(config.run.output_dir), max_steps=max_steps
    )

    print(f"case      : {case.root}", file=out)
    print(f"logs      : {len(case.log_files)} file(s), {total_lines} lines", file=out)
    for item in inventory:
        print(
            f"            {item.file}: {item.line_count} lines, {item.time_range}",
            file=out,
        )
    print(
        f"budget    : up to {max_steps} investigative step(s), ~{minutes:.0f} min "
        f"worst case — searching the logs is free, the commander's turns are not",
        file=out,
    )
    print(f"            estimate basis: {basis}", file=out)
    return len(catalog)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    out = sys.stderr

    if args.init:
        try:
            layout = scaffold_case(Path(args.init))
        except CaseLoadError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"created {layout.root}")
        print(f"  edit  {layout.alert_path}")
        print(f"  drop your logs in  {layout.logs_dir}")
        print(f"  then: ./analyze.py {args.init}")
        return 0

    if not args.case:
        _parser().print_usage(sys.stderr)
        print("error: a case folder is required (or use --init)", file=sys.stderr)
        return 2

    try:
        case = discover_case(Path(args.case))
    except CaseLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    config = _apply_case(load_config(args.config), case, args)
    try:
        _preview(config, case, out)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not args.yes and not args.stub and sys.stdin.isatty():
        answer = input("proceed? [Y/n] ").strip().lower()
        if answer and not answer.startswith("y"):
            print("aborted before starting", file=sys.stderr)
            return 1

    progress: ProgressSink = NullProgress() if args.quiet else ConsoleProgress(out)
    backend = "stub" if args.stub else "vllm"

    result, paths = asyncio.run(
        run_investigation(
            config,
            backend=backend,
            investigation_id=args.investigation_id,
            progress=progress,
            case_name=str(case.root),
        )
    )

    print(f"\nterminal state : {result.terminal_state.value}")
    print(f"transcript     : {paths.transcript}")
    if paths.transcript_pretty.exists():
        print(f"  readable     : {paths.transcript_pretty}")
    if result.brief is not None:
        print(f"brief          : {paths.brief}")
        print(f"alert status   : {result.brief.alert_ref.status} (unchanged, detector-owned)")
        print(f"steps taken    : {result.brief.steps_taken} over {result.brief.lines_available} line(s)")
        failed = sum(1 for e in result.brief.step_ledger if e.error)
        if failed:
            # A brief synthesized entirely from failed steps is still a brief, and it is
            # the kind of result that looks fine until you read it. Say so on the way out.
            print(
                f"FAILED STEPS   : {failed} of {len(result.brief.step_ledger)}"
                + ("  — nothing was successfully read" if failed == len(result.brief.step_ledger) else ""),
                file=sys.stderr,
            )
        if result.brief.aborted_by_operator:
            print("interrupted    : yes — this brief covers only what was read before the abort")
        if result.brief.unresolved_citations:
            print(f"unresolved refs: {len(result.brief.unresolved_citations)}")
        if result.brief.malformed_citations:
            print(f"malformed refs : {len(result.brief.malformed_citations)} (prose in a citation field)")
        if result.brief.uncited_claims:
            print(f"uncited claims : {len(result.brief.uncited_claims)} (see brief.json)")
        if result.brief.injection_signals:
            print(f"injection flags: {len(result.brief.injection_signals)}")
    if result.failure_reason:
        print(f"note           : {result.failure_reason}", file=sys.stderr)

    if paths.stats.exists():
        print(f"stats          : {paths.stats}")
        try:
            print(format_summary(json.loads(paths.stats.read_text(encoding="utf-8"))))
        except (OSError, ValueError, KeyError):
            pass

    return 0 if result.terminal_state is InvestigationState.DONE else 1


if __name__ == "__main__":
    raise SystemExit(main())
