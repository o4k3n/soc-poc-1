"""Transcript logging. Not optional, by construction.

The transcript corpus is the actual deliverable of this PoC -- a future eval set and
distillation corpus -- so "we forgot to turn logging on for that run" must be an
unreachable state, not a discipline problem.

How that is enforced: `TranscriptLogger` is a *required positional* constructor
argument of every LLM client and of the orchestrator. There is no default, no `None`
branch, no `if logger:` guard, and no config key that disables it. A client that could
make an unlogged call cannot be constructed. If you are tempted to add an
`Optional[TranscriptLogger] = None` anywhere in this package, that is the change that
breaks the PoC's premise.

Every record is one JSON object on one line, appended and flushed immediately, so a
crashed run still leaves a readable partial transcript. That property is why the JSONL
stays canonical even though it is unpleasant to read: a single pretty-printed array
cannot be written incrementally, so a run that dies mid-flight would leave a truncated
document instead of a complete-up-to-here record.

`render_pretty` produces the readable view at the end of a run, as a separate file.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class TranscriptLogger:
    """Append-only JSONL sink for one investigation."""

    def __init__(self, path: Path, investigation_id: str) -> None:
        self.path = Path(path)
        self.investigation_id = investigation_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._event_counter = 0
        self._handle = self.path.open("a", encoding="utf-8")
        self.log_event("transcript_opened", {"schema_version": SCHEMA_VERSION})

    # -- core ---------------------------------------------------------------------

    def _write(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._event_counter += 1
            record = {
                "event_id": self._event_counter,
                "investigation_id": self.investigation_id,
                "ts": _utc_now(),
                **record,
            }
            self._handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            self._handle.flush()

    def log_event(self, kind: str, payload: dict[str, Any]) -> None:
        self._write({"kind": kind, "payload": payload})

    def log_state_transition(
        self, *, from_state: str, to_state: str, iteration: int, note: str = ""
    ) -> None:
        self._write(
            {
                "kind": "state_transition",
                "from_state": from_state,
                "to_state": to_state,
                "iteration": iteration,
                "note": note,
            }
        )

    def log_llm_call(
        self,
        *,
        role: str,
        model: str,
        endpoint: str,
        task_id: str | None,
        parent_task_id: str | None,
        state: str,
        attempt: int,
        schema_name: str | None,
        params: dict[str, Any],
        request_messages: list[dict[str, str]],
        response_text: str | None,
        raw_response: dict[str, Any] | None,
        finish_reason: str | None,
        usage: dict[str, Any] | None,
        latency_ms: float,
        error: str | None = None,
        validation_errors: list[str] | None = None,
    ) -> None:
        """One LLM interaction, in full. Prompts and responses are stored verbatim --
        truncating them here would destroy the corpus this PoC exists to produce."""
        self._write(
            {
                "kind": "llm_call",
                "role": role,
                "model": model,
                "endpoint": endpoint,
                "task_id": task_id,
                "parent_task_id": parent_task_id,
                "state": state,
                "attempt": attempt,
                "schema_name": schema_name,
                "params": params,
                "request_messages": request_messages,
                "response_text": response_text,
                "raw_response": raw_response,
                "finish_reason": finish_reason,
                "usage": usage,
                "latency_ms": round(latency_ms, 2),
                "error": error,
                "validation_errors": validation_errors or [],
            }
        )

    def close(self) -> None:
        with self._lock:
            if not self._handle.closed:
                self._handle.flush()
                self._handle.close()

    def __enter__(self) -> TranscriptLogger:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _split_multiline(node: Any) -> Any:
    """Render multi-line strings as arrays of lines.

    Indenting JSON does nothing for the part of a transcript anyone actually wants to
    read: prompts and responses are single strings, and `\n` inside a JSON string stays
    escaped however you format the document. A 5 MB pretty file whose every prompt is one
    unreadable line is not an improvement.

    Splitting is lossless and reversible -- join a list back with "\n" to recover the
    original string -- but it does mean the pretty file is a *view*, not a byte-identical
    copy. transcript.jsonl remains canonical.
    """
    if isinstance(node, str):
        return node.split("\n") if "\n" in node else node
    if isinstance(node, list):
        return [_split_multiline(item) for item in node]
    if isinstance(node, dict):
        return {key: _split_multiline(value) for key, value in node.items()}
    return node


def render_pretty(jsonl_path: Path, out_path: Path) -> int:
    """Write a human-readable view of a transcript. Returns the record count.

    Never raises on a malformed line: this runs at the end of a run, including an aborted
    one, and failing to produce a convenience file must not be able to take down a run
    that has already done its work.
    """
    records: list[Any] = []
    try:
        with jsonl_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(_split_multiline(json.loads(line)))
                except json.JSONDecodeError:
                    # A partial final line is exactly what a crashed run leaves behind.
                    records.append({"kind": "unparseable_line", "raw": line[:500]})
    except OSError:
        return 0

    try:
        out_path.write_text(
            json.dumps(records, indent=2, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
        )
    except OSError:
        return 0
    return len(records)


class Stopwatch:
    """Millisecond timer used to stamp latency on every call."""

    def __init__(self) -> None:
        self._start = time.perf_counter()

    @property
    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self._start) * 1000.0
