"""`analyze.py` implementation: point it at a case folder and it runs.

All behaviour lives in runner.py and casedir.py; this parses arguments, prints the
things a human wants to see before a long run starts, and chooses the progress sink.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from soc_poc.casedir import CaseLayout, CaseLoadError, discover_case, scaffold_case
from soc_poc.config import AppConfig, FixtureConfig, load_config
from soc_poc.loader import build_slice_catalog, load_pattern_summaries
from soc_poc.progress import ConsoleProgress, NullProgress, ProgressSink
from soc_poc.runner import run_investigation
from soc_poc.states import InvestigationState
from soc_poc.summarize import summarize_logs

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
    parser.add_argument("--max-iterations", type=int, help="override the drill-down cap")
    parser.add_argument("--max-tasks", type=int, help="override tasks per planning round")
    parser.add_argument("--id", dest="investigation_id", help="name this run explicitly")
    return parser


def _apply_case(config: AppConfig, case: CaseLayout, args: argparse.Namespace) -> AppConfig:
    """Point the config at the case folder without anyone editing config.toml.

    Endpoints, models and limits still come from one place; only the inputs move.
    """
    run = config.run
    if args.max_iterations:
        run = run.model_copy(update={"max_iterations": args.max_iterations})
    if args.max_tasks:
        run = run.model_copy(update={"max_tasks_per_iteration": args.max_tasks})
    return config.model_copy(
        update={
            "run": run,
            "fixtures": FixtureConfig(
                alert=str(case.alert_path),
                patterns_dir=str(case.patterns_dir or case.root / "patterns"),
                logs_dir=str(case.logs_dir),
            ),
        }
    )


def _preview(config: AppConfig, case: CaseLayout, out) -> int:
    """Show what will be read before spending minutes reading it.

    Returns the slice count. Building the catalog here costs a file read and catches
    broken line pointers before any model is involved.
    """
    if case.has_handwritten_patterns:
        summaries = load_pattern_summaries(case.patterns_dir)  # type: ignore[arg-type]
        origin = f"{len(summaries)} hand-written summar(ies)"
    else:
        summaries = summarize_logs(case.logs_dir)
        origin = f"{len(summaries)} auto-generated summar(ies)"
    catalog = build_slice_catalog(summaries, case.logs_dir)

    readable = config.run.max_tasks_per_iteration * config.run.max_iterations
    print(f"case      : {case.root}", file=out)
    print(f"logs      : {len(case.log_files)} file(s) — {', '.join(case.log_files)}", file=out)
    print(f"summaries : {origin}", file=out)
    print(f"slices    : {len(catalog)}", file=out)
    if len(catalog) > readable:
        # Not an error. What the commander declines to read is itself a finding, but the
        # operator should know the budget was the binding constraint.
        print(
            f"  note: at most {readable} slices can be read "
            f"({config.run.max_tasks_per_iteration} tasks x "
            f"{config.run.max_iterations} rounds); {len(catalog) - readable} will go "
            f"unread. Raise --max-tasks/--max-iterations, or narrow the case.",
            file=out,
        )
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

    progress: ProgressSink = NullProgress() if args.quiet else ConsoleProgress(out)
    backend = "stub" if args.stub else "vllm"

    result, paths = asyncio.run(
        run_investigation(
            config,
            backend=backend,
            investigation_id=args.investigation_id,
            progress=progress,
            case_name=str(case.root),
            generate_patterns=not case.has_handwritten_patterns,
        )
    )

    print(f"\nterminal state : {result.terminal_state.value}")
    print(f"transcript     : {paths.transcript}")
    if result.brief is not None:
        print(f"brief          : {paths.brief}")
        print(f"alert status   : {result.brief.alert_ref.status} (unchanged, detector-owned)")
        print(f"tasks          : {len(result.brief.task_ledger)}")
        if result.brief.aborted_by_operator:
            print("interrupted    : yes — this brief covers only what was read before the abort")
        if result.brief.unresolved_citations:
            print(f"unresolved refs: {len(result.brief.unresolved_citations)}")
        if result.brief.injection_signals:
            print(f"injection flags: {len(result.brief.injection_signals)}")
    if result.failure_reason:
        print(f"note           : {result.failure_reason}", file=sys.stderr)

    return 0 if result.terminal_state is InvestigationState.DONE else 1


if __name__ == "__main__":
    raise SystemExit(main())
