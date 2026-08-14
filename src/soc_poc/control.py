"""Run markers and the abort sentinel: how `abort.py` talks to a running investigation.

Two files per run, both inside the run's own output directory:

    out/<investigation_id>/RUNNING.json   written at start, removed in a finally
    out/<investigation_id>/ABORT          written by abort.py, polled by the orchestrator

Files rather than signals. A signal handler inside an asyncio loop that is awaiting an
LLM call is fiddly to get right and impossible to inspect afterwards; a sentinel file
works from any shell, survives the process that wrote it, and can be read after the fact
to see what was requested and when. The cost is polling, and the orchestrator polls at
state boundaries anyway, where the state machine is already quiescent.

Liveness: RUNNING.json records a pid, and `active_runs` filters on `os.kill(pid, 0)`. A
run killed with SIGKILL leaves its marker behind, and without that check every crashed
run would look abortable forever.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

RUNNING_MARKER = "RUNNING.json"
ABORT_SENTINEL = "ABORT"


class AbortMode(str, Enum):
    # Stop planning new rounds, let in-flight grunts finish, synthesize what we have.
    GRACEFUL = "graceful"
    # Cancel in-flight grunts, write no brief. The transcript still holds everything.
    HARD = "hard"


class RunMarker(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: str
    pid: int
    case: str
    backend: str
    started_at: str
    run_dir: str

    @property
    def is_alive(self) -> bool:
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            # Owned by another user; it exists, which is what we asked.
            return True
        return True


class AbortRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: AbortMode
    requested_at: str
    requested_by: str = ""


# -- writing -------------------------------------------------------------------------


def write_marker(run_dir: Path, *, investigation_id: str, case: str, backend: str) -> RunMarker:
    marker = RunMarker(
        investigation_id=investigation_id,
        pid=os.getpid(),
        case=case,
        backend=backend,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        run_dir=str(run_dir),
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / RUNNING_MARKER).write_text(marker.model_dump_json(indent=2), encoding="utf-8")
    return marker


def clear_marker(run_dir: Path) -> None:
    (run_dir / RUNNING_MARKER).unlink(missing_ok=True)


def request_abort(run_dir: Path, mode: AbortMode, requested_by: str = "") -> AbortRequest:
    request = AbortRequest(
        mode=mode,
        requested_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        requested_by=requested_by,
    )
    (run_dir / ABORT_SENTINEL).write_text(request.model_dump_json(indent=2), encoding="utf-8")
    return request


# -- reading -------------------------------------------------------------------------


def read_abort(run_dir: Path) -> AbortRequest | None:
    """Polled by the orchestrator. Never raises: a malformed sentinel is still an abort.

    If someone writes garbage into the file (or `touch`es it, which is a reasonable
    thing to try), treat it as a graceful abort rather than ignoring it. Refusing to
    stop because the stop request was misspelt would be the wrong failure.
    """
    path = run_dir / ABORT_SENTINEL
    if not path.exists():
        return None
    try:
        return AbortRequest.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return AbortRequest(
            mode=AbortMode.GRACEFUL,
            requested_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            requested_by="unparseable sentinel",
        )


def read_marker(run_dir: Path) -> RunMarker | None:
    path = run_dir / RUNNING_MARKER
    if not path.exists():
        return None
    try:
        return RunMarker.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def active_runs(output_dir: Path) -> list[RunMarker]:
    """Every run whose process is still alive, newest first."""
    if not output_dir.exists():
        return []
    markers = [
        marker
        for run_dir in output_dir.iterdir()
        if run_dir.is_dir()
        for marker in [read_marker(run_dir)]
        if marker is not None and marker.is_alive
    ]
    return sorted(markers, key=lambda m: m.started_at, reverse=True)


def stale_runs(output_dir: Path) -> list[RunMarker]:
    """Markers left behind by runs that died without cleaning up."""
    if not output_dir.exists():
        return []
    return [
        marker
        for run_dir in output_dir.iterdir()
        if run_dir.is_dir()
        for marker in [read_marker(run_dir)]
        if marker is not None and not marker.is_alive
    ]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
