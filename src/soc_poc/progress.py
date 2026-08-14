"""Live progress output, kept out of the state machine.

The orchestrator holds a `ProgressSink`, not a set of print statements. Two reasons that
matters beyond taste: the state machine stays free of I/O so it ports cleanly (a sink is
a pid you send messages to in the Elixir version), and it keeps the distinction between
*the record* and *the display* sharp. The transcript is the record. This is a convenience
for the human watching, and nothing here is allowed to be the only place something is
written down.

`ConsoleProgress` writes to **stderr**, leaving stdout for the final machine-readable
result lines, so `./analyze.py case > result.txt` still does something sensible while you
watch the reasoning scroll past.
"""

from __future__ import annotations

import shutil
import sys
from typing import Protocol, TextIO


class ProgressSink(Protocol):
    """Everything the console layer is allowed to know about a run in flight."""

    def state_changed(self, from_state: str, to_state: str, iteration: int) -> None: ...
    def note(self, text: str) -> None: ...
    def call_started(self, role: str, schema_name: str, task_id: str | None) -> None: ...
    def token(self, channel: str, text: str) -> None: ...
    def call_finished(self, role: str, latency_ms: float, attempt: int) -> None: ...
    def task_outcome(self, task_id: str, slice_id: str, summary: str, ok: bool) -> None: ...

    @property
    def wants_tokens(self) -> bool:
        """True if this sink wants streamed tokens.

        The transport checks it: streaming costs an extra code path in the client, so
        the non-streaming path stays the default when nobody is watching.
        """
        ...


class NullProgress:
    """Records nothing, shows nothing. The default for tests and library use."""

    wants_tokens = False

    def state_changed(self, from_state: str, to_state: str, iteration: int) -> None: ...
    def note(self, text: str) -> None: ...
    def call_started(self, role: str, schema_name: str, task_id: str | None) -> None: ...
    def token(self, channel: str, text: str) -> None: ...
    def call_finished(self, role: str, latency_ms: float, attempt: int) -> None: ...
    def task_outcome(self, task_id: str, slice_id: str, summary: str, ok: bool) -> None: ...


class ConsoleProgress:
    """Human-facing view of a run: state transitions, live commander reasoning, and one
    line per grunt task.

    Grunt reasoning is deliberately not streamed. Four workers interleaving their
    thoughts token-by-token is unreadable, and the interesting question about a grunt is
    whether its citations held up, which is one line.
    """

    def __init__(self, stream: TextIO | None = None, *, show_reasoning: bool = True) -> None:
        self._out = stream or sys.stderr
        self._show_reasoning = show_reasoning
        self._column = 0
        self._in_reasoning = False
        self._width = shutil.get_terminal_size((100, 24)).columns

    @property
    def wants_tokens(self) -> bool:
        return self._show_reasoning

    # -- plumbing --------------------------------------------------------------------

    def _write(self, text: str) -> None:
        self._out.write(text)
        self._out.flush()

    def _end_stream(self) -> None:
        """Close an open reasoning block before printing a structured line."""
        if self._in_reasoning:
            self._write("\n")
            self._in_reasoning = False
            self._column = 0

    # -- sink ------------------------------------------------------------------------

    def state_changed(self, from_state: str, to_state: str, iteration: int) -> None:
        self._end_stream()
        self._write(f"\n  {from_state} → {to_state}  (round {iteration})\n")

    def note(self, text: str) -> None:
        self._end_stream()
        self._write(f"  {text}\n")

    def call_started(self, role: str, schema_name: str, task_id: str | None) -> None:
        self._end_stream()
        label = task_id or role
        self._write(f"  · {label} :: {schema_name} …\n")

    def token(self, channel: str, text: str) -> None:
        """Stream reasoning as it arrives; swallow content tokens.

        Content is the JSON artifact -- it is validated, written to the brief and stored
        in the transcript. Watching it arrive character by character tells the operator
        nothing that reading the brief will not.
        """
        if channel != "reasoning" or not self._show_reasoning:
            return
        if not self._in_reasoning:
            self._write("    ")
            self._in_reasoning = True
            self._column = 4
        for word in text.splitlines(keepends=True):
            if self._column + len(word) > self._width - 2:
                self._write("\n    ")
                self._column = 4
            self._write(word)
            self._column = 4 if word.endswith("\n") else self._column + len(word)

    def call_finished(self, role: str, latency_ms: float, attempt: int) -> None:
        self._end_stream()
        retry = f" (attempt {attempt})" if attempt > 1 else ""
        self._write(f"  · {role} done in {latency_ms / 1000:.1f}s{retry}\n")

    def task_outcome(self, task_id: str, slice_id: str, summary: str, ok: bool) -> None:
        self._end_stream()
        mark = "✓" if ok else "✗"
        self._write(f"  {mark} {task_id} [{slice_id}] {summary}\n")
