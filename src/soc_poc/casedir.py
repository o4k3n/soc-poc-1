"""Case folders: what a user drops on disk, and how it is validated.

    <case>/
        alert.json          required -- the external detector's alert
        logs/*.log          required -- raw logs, any text format
        patterns/*.json     optional -- hand-written summaries; present means the
                                        fallback summarizer is skipped entirely

The whole point of this module is that mistakes are caught here, at the edge, with a
message that says what to fix. Everything downstream assumes its inputs are valid, and a
missing alert field surfacing as a pydantic traceback three layers into `load_run_inputs`
is exactly the experience this was written to remove.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from soc_poc.schemas.alert import Alert

ALERT_FILE = "alert.json"
LOGS_DIR = "logs"
PATTERNS_DIR = "patterns"

ALERT_TEMPLATE = {
    "alert_id": "EXT-0000-00-00-000000",
    "detector": "name-of-the-system-that-raised-this",
    "rule_name": "What the detector matched on",
    "status": "open",
    "severity": "medium",
    "first_seen": "2026-01-01T00:00:00Z",
    "last_seen": "2026-01-01T01:00:00Z",
    "summary": "What the detector saw, in its own words.",
    "entities": [{"kind": "ip", "value": "10.0.0.1", "note": "source host"}],
    "raw_detector_fields": {"detector_version": "1.0"},
}


class CaseLoadError(ValueError):
    """Something about the case folder is wrong, described so it can be fixed."""


class CaseLayout(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    root: Path
    alert_path: Path
    logs_dir: Path
    patterns_dir: Path | None  # None means "generate summaries"
    log_files: tuple[str, ...]

    @property
    def name(self) -> str:
        return self.root.name

    @property
    def has_handwritten_patterns(self) -> bool:
        return self.patterns_dir is not None


def _describe_alert_error(path: Path, exc: ValidationError) -> str:
    problems = "\n".join(
        f"    {'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
        for err in exc.errors()
    )
    required = ", ".join(
        name for name, field in Alert.model_fields.items() if field.is_required()
    )
    return (
        f"{path} does not match the alert schema:\n{problems}\n"
        f"  Required fields: {required}\n"
        f"  Note the schema is closed -- unknown fields are rejected rather than ignored.\n"
        f"  Run `analyze.py --init <dir>` to get a valid template."
    )


def discover_case(root: Path) -> CaseLayout:
    """Validate a case folder and report precisely what is missing."""
    root = root.resolve()
    if not root.is_dir():
        raise CaseLoadError(f"{root} is not a directory")

    alert_path = root / ALERT_FILE
    if not alert_path.is_file():
        raise CaseLoadError(
            f"{root} has no {ALERT_FILE}. Every investigation starts from an alert that "
            f"an external detector already raised -- this system enriches it, so there "
            f"is nothing to enrich without one.\n"
            f"  Run `analyze.py --init {root}` to scaffold one."
        )
    try:
        Alert.model_validate_json(alert_path.read_text(encoding="utf-8"))
    except ValidationError as exc:
        raise CaseLoadError(_describe_alert_error(alert_path, exc)) from exc
    except json.JSONDecodeError as exc:
        raise CaseLoadError(f"{alert_path} is not valid JSON: {exc}") from exc

    logs_dir = root / LOGS_DIR
    if not logs_dir.is_dir():
        raise CaseLoadError(
            f"{root} has no {LOGS_DIR}/ directory. Put the raw log files there; any text "
            f"format works, and one physical line is one citable unit."
        )
    log_files = tuple(
        sorted(p.name for p in logs_dir.iterdir() if p.is_file() and not p.name.startswith("."))
    )
    if not log_files:
        raise CaseLoadError(f"{logs_dir} contains no log files.")

    patterns_dir = root / PATTERNS_DIR
    has_patterns = patterns_dir.is_dir() and any(patterns_dir.glob("*.json"))

    return CaseLayout(
        root=root,
        alert_path=alert_path,
        logs_dir=logs_dir,
        patterns_dir=patterns_dir if has_patterns else None,
        log_files=log_files,
    )


def scaffold_case(root: Path) -> CaseLayout:
    """Create an empty case folder with a valid alert template."""
    if root.exists() and any(root.iterdir()):
        raise CaseLoadError(f"{root} already exists and is not empty")
    (root / LOGS_DIR).mkdir(parents=True, exist_ok=True)
    (root / ALERT_FILE).write_text(
        json.dumps(ALERT_TEMPLATE, indent=2) + "\n", encoding="utf-8"
    )
    (root / LOGS_DIR / ".gitkeep").touch()
    return CaseLayout(
        root=root.resolve(),
        alert_path=(root / ALERT_FILE).resolve(),
        logs_dir=(root / LOGS_DIR).resolve(),
        patterns_dir=None,
        log_files=(),
    )
