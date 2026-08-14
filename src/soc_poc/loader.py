"""Loading a case: the alert, the file inventory, the complete slice catalog.

Chunking itself lives in chunking.py; this module is the seam where inputs enter the
system. Today they come from a case folder on disk. When the telemetry pipeline exists it
lands here and nowhere else, because everything downstream depends on `Alert` and
`LogSlice`, not on the filesystem.

Line references are 1-based and match what a human sees in an editor, which is what makes
a citation checkable with `sed -n '142p'`.
"""

from __future__ import annotations

import json
from pathlib import Path

from soc_poc.chunking import FileInventory, chunk_logs
from soc_poc.schemas.alert import Alert
from soc_poc.schemas.slice import LogSlice
from soc_poc.validation.injection import InjectionSignal, scan_for_ai_directed_content


def load_alert(path: Path) -> Alert:
    return Alert.model_validate_json(path.read_text(encoding="utf-8"))


def scan_catalog_for_injection(catalog: dict[str, LogSlice]) -> list[InjectionSignal]:
    """Run the cheap AI-directed-content pass over every raw line, once, at load.

    Hits are attached to the brief for the operator. They are not removed from the
    slices: a grunt reading the line and citing it is fine -- the structural defenses
    do not depend on the model having been shielded from the text.
    """
    signals: list[InjectionSignal] = []
    for log_slice in catalog.values():
        for line in log_slice.lines:
            signals.extend(scan_for_ai_directed_content(line.text, line.ref))
    return signals


def all_known_refs(catalog: dict[str, LogSlice]) -> set[str]:
    refs: set[str] = set()
    for log_slice in catalog.values():
        refs |= log_slice.refs()
    return refs


def load_run_inputs(
    alert_path: Path,
    logs_dir: Path,
    *,
    slice_token_budget: int,
    chars_per_token: float,
) -> tuple[Alert, list[FileInventory], dict[str, LogSlice]]:
    """Load a run's inputs: the alert, a file inventory, and a complete slice catalog.

    There is no summarization step and no selection step. Every line of every file ends
    up in exactly one slice, and every slice gets read -- see chunking.py.
    """
    alert = load_alert(alert_path)
    catalog, inventory = chunk_logs(
        logs_dir, slice_token_budget=slice_token_budget, chars_per_token=chars_per_token
    )
    return alert, inventory, catalog


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
