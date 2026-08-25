"""Deterministic offline client. Same interface, same transcript records, no GPU.

Why this exists:
  * `make demo-offline` exercises the whole machine -- state transitions, schema
    validation, citation checking, retry-with-feedback, transcript writing -- on a
    laptop or in CI, without waiting on two vLLM instances.
  * It is the record/replay seam the future eval harness needs.

How it stays honest: the stub does not receive the fixtures. It reads the rendered
prompt exactly as a model would, pulling slice ids and line references out of the
fenced data block. If the prompt fails to carry the information a model needs, the
stub fails too -- which is the point of testing against it.

It also *deliberately fails twice*, so every offline run exercises both retry paths:
the first action it emits names a log file that does not exist, and the first grunt
report it produces cites a line that was never shown. Look for both in the transcript.
"""

from __future__ import annotations

import json
import re
from typing import Any

from soc_poc.config import ModelConfig
from soc_poc.llm.base import LLMResponse, TokenCallback
from soc_poc.transcript import Stopwatch, TranscriptLogger

# Refs are read the way a model would read them: only from the fenced data block,
# where each line is "<ref>\t<text>". Matching bare ref-shaped tokens anywhere in the
# prompt would also pick up the citation-format example in the system prompt -- which
# is exactly the kind of near-miss a real model makes, but not what we want the stub
# doing by accident.
_SLICE_REF_RE = re.compile(r"^([\w.\-]+:L\d+)\t", re.MULTILINE)
# In an investigate or synthesis prompt the lines the commander has been shown are
# rendered by evidence.py as "     <ref>  <text>". This is how the stub cites only what
# it was actually shown, which is exactly the constraint a real commander is under.
_SHOWN_REF_RE = re.compile(r"^ +([\w.\-]+:L\d+)  ", re.MULTILINE)
# In a grunt prompt the slice is named in the header line.
_SLICE_ID_RE = re.compile(r"^SLICE (\S+)", re.MULTILINE)
# The searchable files and their sizes, read out of the block the investigate prompt
# renders. The stub picks the largest to close_read, the way an analyst would: the file
# with the most lines is where the traffic is.
_FILE_RE = re.compile(r"^  ([\w.\-]+): (\d+) lines$", re.MULTILINE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|local)\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _slice_refs(prompt: str) -> list[str]:
    return list(dict.fromkeys(_SLICE_REF_RE.findall(prompt)))


def _shown_refs(prompt: str) -> list[str]:
    return list(dict.fromkeys(_SHOWN_REF_RE.findall(prompt)))


class StubClient:
    """Canned but prompt-derived responses."""

    def __init__(
        self,
        config: ModelConfig,
        transcript: TranscriptLogger,  # required: there is no unlogged construction
    ) -> None:
        self.config = config
        self.role = config.role
        self._transcript = transcript
        self._grunt_calls = 0
        self._actions = 0

    async def complete_json(
        self,
        *,
        messages: list[dict[str, str]],
        schema_name: str,
        json_schema: dict[str, Any],
        state: str,
        attempt: int,
        task_id: str | None = None,
        parent_task_id: str | None = None,
        on_token: TokenCallback | None = None,
    ) -> LLMResponse:
        watch = Stopwatch()
        prompt = "\n".join(message.get("content", "") for message in messages)
        payload = self._respond(schema_name, prompt, attempt)
        text = json.dumps(payload, indent=2)

        # Canned reasoning, emitted word by word so `--stub` exercises the same console
        # path as a real run. Without this the offline demo would look nothing like the
        # thing it is meant to stand in for.
        reasoning = self._reasoning(schema_name, attempt)
        if on_token is not None:
            for word in reasoning.split(" "):
                on_token("reasoning", word + " ")
            on_token("content", text)

        self._transcript.log_llm_call(
            role=self.role,
            model=f"stub::{self.config.model}",
            endpoint="stub://offline",
            task_id=task_id,
            parent_task_id=parent_task_id,
            state=state,
            attempt=attempt,
            schema_name=schema_name,
            params={"stub": True, "temperature": self.config.temperature},
            request_messages=messages,
            response_text=text,
            raw_response={"stub": True, "reasoning": reasoning},
            finish_reason="stop",
            usage={"prompt_tokens": len(prompt) // 4, "completion_tokens": len(text) // 4},
            latency_ms=watch.elapsed_ms,
        )
        return LLMResponse(
            text=text,
            model=f"stub::{self.config.model}",
            finish_reason="stop",
            usage={},
            latency_ms=watch.elapsed_ms,
            reasoning=reasoning,
        )

    def _reasoning(self, schema_name: str, attempt: int) -> str:
        if attempt > 1:
            return (
                "The validator rejected the previous report because a cited line was not "
                "in the slice. Re-reading the fenced lines and citing only those."
            )
        return {
            "investigative_action": "The profile gives me exact counts to start from. "
            "Establishing the quantity before I reason about what it means.",
            "grunt_report": "Reading the slice line by line. Recording what is literally "
            "present, and noting what I checked for and did not find.",
            "investigation_brief": "Assembling the timeline from cited lines, then stating "
            "each hypothesis with the evidence on both sides. No disposition -- that is "
            "the operator's call.",
        }.get(schema_name, "Working.")

    # -- canned bodies ---------------------------------------------------------------

    def _respond(self, schema_name: str, prompt: str, attempt: int) -> dict[str, Any]:
        if schema_name == "investigative_action":
            return self._action(prompt, attempt)
        if schema_name == "grunt_report":
            return self._report(prompt, attempt)
        if schema_name == "investigation_brief":
            return self._brief(prompt)
        raise ValueError(f"stub client has no canned response for schema {schema_name!r}")

    def _action(self, prompt: str, attempt: int) -> dict[str, Any]:
        """A short fixed investigation, derived from the prompt the way a model would.

        The sequence deliberately covers every verb, so an offline run exercises the
        deterministic executor, the close_read worker path and the conclude exit.
        """
        files = sorted(
            ((name, int(count)) for name, count in _FILE_RE.findall(prompt)),
            key=lambda pair: -pair[1],
        )
        primary = files[0][0] if files else ""
        domains = list(dict.fromkeys(_DOMAIN_RE.findall(prompt)))
        shown = _shown_refs(prompt)

        # A retry re-answers the same step rather than advancing: the loop asked for a
        # correction, not for the next question.
        if attempt == 1:
            self._actions += 1
        step = self._actions

        if step == 1:
            # Deliberately names a file that does not exist, on the first attempt only.
            # validate_action rejects it, the loop re-prompts with the reason, and the
            # corrected action goes through -- so the action-retry path runs every time.
            return {
                "reasoning": "Establishing how much traffic the alerted domain accounts "
                "for before reasoning about it.",
                "expectation": "A large share of one file. Zero would mean the alert "
                "names something absent from these logs.",
                "action": "count",
                "pattern": domains[0] if domains else "example",
                # Empty means every file. Scoping this to one file is how an earlier
                # version searched a DHCP log for a domain and concluded on two zeroes.
                "file": "nosuch.log" if attempt == 1 else "",
                "ref": "",
                "start_line": 0,
                "end_line": 0,
                "question": "",
            }
        if step == 2:
            return {
                "reasoning": "Pulling actual lines so I can see who the source is.",
                "expectation": "A single source address, if this is one host.",
                "action": "search",
                "pattern": domains[0] if domains else "example",
                "file": "",
                "ref": "",
                "start_line": 0,
                "end_line": 0,
                "question": "",
            }
        if step == 3 and shown:
            return {
                "reasoning": "Reading around the first hit for neighbouring records.",
                "expectation": "Adjacent lines may resolve infrastructure the query "
                "itself only names.",
                "action": "context",
                "pattern": "",
                "file": "",
                "ref": shown[0],
                "start_line": 0,
                "end_line": 0,
                "question": "",
            }
        if step == 4 and domains:
            return {
                "reasoning": "Checking whether this shape is confined to one host or is "
                "estate-wide -- one host is a finding, forty is a vendor service.",
                "expectation": "If many distinct sources emit it, the alert is likelier "
                "to be a benign lookalike.",
                "action": "count",
                "pattern": domains[0],
                "file": "",
                "ref": "",
                "start_line": 0,
                "end_line": 0,
                "question": "",
            }
        if step == 5 and primary:
            return {
                "reasoning": "Reading a range verbatim to see what the responses carried.",
                "expectation": "Answer payloads, or confirmation that none were logged.",
                "action": "read_lines",
                "pattern": "",
                "file": primary,
                "ref": "",
                "start_line": 1,
                "end_line": 8,
                "question": "",
            }
        if step == 6 and primary:
            return {
                "reasoning": "Handing a bounded range to a worker for a question counting "
                "cannot answer.",
                "expectation": "A description of what these lines have in common.",
                "action": "close_read",
                "pattern": "",
                "file": primary,
                "ref": "",
                "start_line": 1,
                "end_line": 12,
                "question": "What do these lines have in common, and what differs?",
            }
        return {
            "reasoning": "The counts and the lines behind them are enough for the brief.",
            "expectation": "Further reading would not change what the operator does.",
            "action": "conclude",
            "pattern": "",
            "file": "",
            "ref": "",
            "start_line": 0,
            "end_line": 0,
            "question": "",
        }

    def _report(self, prompt: str, attempt: int) -> dict[str, Any]:
        refs = _slice_refs(prompt)
        slice_ids = _SLICE_ID_RE.findall(prompt)
        slice_id = slice_ids[0] if slice_ids else "unknown"
        file_name = refs[0].split(":L")[0] if refs else "unknown.log"

        self._grunt_calls += 1
        # Every third slice is "relevant", so an offline run exercises both the finding
        # path and the negative-collapse path the way a real sweep would.
        relevant = self._grunt_calls % 3 == 1 and bool(refs)
        if not relevant:
            return {
                "slice_metadata": {
                    "slice_id": slice_id,
                    "file": file_name,
                    "lines_examined": len(refs),
                },
                "relevant": False,
                "findings": [],
                "checked_for": [
                    {
                        "checked_for": "lines matching the directive's indicators",
                        "found": False,
                        "scope": f"all lines of {slice_id}",
                        "result": "none present in this slice",
                    }
                ],
            }

        # First relevant slice, first attempt: cite a line that was never shown. This
        # exercises the citation validator and the retry-with-feedback path on every
        # offline run, which is the only way that code stays honest.
        fabricate = self._grunt_calls == 1 and attempt == 1
        cited = [f"{file_name}:L999999"] if fabricate else refs[:2]
        return {
            "slice_metadata": {
                "slice_id": slice_id,
                "file": file_name,
                "lines_examined": len(refs),
            },
            "relevant": True,
            "findings": [
                {
                    "description": "Repeated outbound resolution attempts for the same "
                    "second-level domain at a near-constant interval.",
                    "match_count": max(len(cited), 3),
                    "representative_refs": cited,
                    "first_ref": cited[0] if cited else "",
                    "last_ref": cited[-1] if cited else "",
                    "confidence": "medium",
                }
            ],
            "checked_for": [
                {
                    "checked_for": "successful A-record responses with routable answers",
                    "found": False,
                    "scope": f"all lines of {slice_id}",
                    "result": "none present in this slice",
                }
            ],
        }

    def _brief(self, prompt: str) -> dict[str, Any]:
        refs = _shown_refs(prompt)
        return {
            "investigation_narrative": (
                "Searches against the case corpus established the volume attributable to "
                "the alerted domain and the lines behind it. The periodic resolution "
                "pattern is present in the raw lines; supporting egress context is "
                "thinner. This brief enriches the external alert and reaches no "
                "disposition."
            ),
            "timeline": [
                {
                    "timestamp": "2026-08-03T11:04:12Z",
                    "description": "First observed resolution for the low-prevalence domain.",
                    "raw_line_refs": refs[:1],
                }
            ],
            "hypotheses": [
                {
                    "statement": "A process on the host is beaconing over DNS.",
                    "supporting_evidence": [
                        {
                            "description": "Near-constant query interval with low jitter.",
                            "raw_line_refs": refs[:2],
                        }
                    ],
                    "contradicting_evidence": [
                        {
                            # Deliberately uncited: an absence of evidence has no line to
                            # point at, and every offline run must exercise the code that
                            # flags unciteable claims on the brief.
                            "description": "No corresponding outbound session was "
                            "confirmed in the traffic searched.",
                            "raw_line_refs": [],
                        }
                    ],
                }
            ],
            "suggested_drilldowns": [
                {
                    "question": "Which process opened the resolver socket?",
                    "where_to_look": "Endpoint telemetry for the host, same time window.",
                    "why": "Attribution to a process would separate an agent from a "
                    "misconfigured updater.",
                }
            ],
            "open_questions": ["Is the domain seen on any other host in the estate?"],
            "coverage_gaps": [
                "Only the patterns searched were examined; the rest of the corpus was "
                "not read.",
            ],
        }

    async def aclose(self) -> None:
        return None
