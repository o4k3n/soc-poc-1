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

It also *deliberately fails once*: the first grunt report it produces cites a line that
was never shown, so every offline run exercises the citation validator and the
one-shot retry-with-feedback path. Look for it in the transcript.
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
# In a synthesis prompt there is no raw data, only the refs grunts cited.
_CITED_REF_RE = re.compile(r"^\s*refs: (.+)$", re.MULTILINE)
# In a grunt prompt the slice is named in the header line; in a drill-down prompt the
# only slice ids are the ones that reported findings.
_SLICE_ID_RE = re.compile(r"^SLICE (\S+)", re.MULTILINE)
_FINDING_SLICE_RE = re.compile(r"^- (\S+) \(", re.MULTILINE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|local)\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _slice_refs(prompt: str) -> list[str]:
    return list(dict.fromkeys(_SLICE_REF_RE.findall(prompt)))


def _cited_refs(prompt: str) -> list[str]:
    refs: list[str] = []
    for group in _CITED_REF_RE.findall(prompt):
        refs.extend(ref.strip() for ref in group.split(",") if ref.strip())
    return list(dict.fromkeys(refs))


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
            "sweep_directive": "Reading the alert. The detector names a domain and a "
            "host, so those are the indicators; but I should tell the workers to flag "
            "periodicity and encoding too, or they will just grep.",
            "commander_plan": "The sweep came back. One slice looks worth a closer read.",
            "grunt_report": "Reading the slice line by line. Recording what is literally "
            "present, and noting what I checked for and did not find.",
            "investigation_brief": "Assembling the timeline from cited lines, then stating "
            "each hypothesis with the evidence on both sides. No disposition -- that is "
            "the operator's call.",
        }.get(schema_name, "Working.")

    # -- canned bodies ---------------------------------------------------------------

    def _respond(self, schema_name: str, prompt: str, attempt: int) -> dict[str, Any]:
        if schema_name == "sweep_directive":
            return self._directive(prompt)
        if schema_name == "commander_plan":
            return self._plan(prompt)
        if schema_name == "grunt_report":
            return self._report(prompt, attempt)
        if schema_name == "investigation_brief":
            return self._brief(prompt)
        raise ValueError(f"stub client has no canned response for schema {schema_name!r}")

    def _directive(self, prompt: str) -> dict[str, Any]:
        """Pull indicators straight out of the fenced alert, as a real commander would."""
        domains = list(dict.fromkeys(_DOMAIN_RE.findall(prompt)))[:4]
        ips = list(dict.fromkeys(_IP_RE.findall(prompt)))[:4]
        return {
            "alert_restatement": "An external detector flagged suspicious traffic; find "
            "lines that bear on it.",
            "indicators": domains + ips,
            "relevance_criteria": "Any line involving the named hosts or domains, plus "
            "anything showing unusual periodicity, volume, encoding or record types even "
            "if it matches none of the indicators.",
            "explicitly_irrelevant": ["routine internal name resolution"],
            "time_window": "",
        }

    def _plan(self, prompt: str) -> dict[str, Any]:
        """After a sweep the stub asks for one drill-down, then stops."""
        slice_ids = list(dict.fromkeys(_FINDING_SLICE_RE.findall(prompt)))
        is_followup = "DRILL-DOWN ROUND 2" in prompt
        chosen = [] if is_followup else slice_ids[:1]
        return {
            "planning_rationale": "Re-reading the slice with the densest findings."
            if chosen
            else "The sweep is sufficient; going to synthesis.",
            "tasks": [
                {
                    "instruction": f"Re-read {slice_id} closely and report the detail "
                    "behind the aggregate.",
                    "commander_intent": "Confirming the pattern the sweep flagged.",
                    "slice_id": slice_id,
                }
                for slice_id in chosen
            ],
            "request_followup": False,
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
                    "result": "none present in this slice",
                }
            ],
        }

    def _brief(self, prompt: str) -> dict[str, Any]:
        refs = _cited_refs(prompt)
        return {
            "investigation_narrative": (
                "Grunt workers examined the resolver, proxy and endpoint slices linked to "
                "the alert's pattern summaries. The periodic resolution pattern is "
                "present in the raw lines; supporting egress context is thinner. This "
                "brief enriches the external alert and reaches no disposition."
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
                            "description": "No corresponding outbound session was "
                            "confirmed in the proxy slice examined.",
                            "raw_line_refs": refs[2:3],
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
            "coverage_gaps": ["Only the linked windows were read, not the full day."],
        }

    async def aclose(self) -> None:
        return None
