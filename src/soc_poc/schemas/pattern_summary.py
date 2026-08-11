"""Precomputed pattern summaries.

SEAM: the telemetry pipeline (out of scope for this build) will eventually produce
these. Until then they are fixtures on disk. The contract is what matters: a summary
carries precomputed statistics the LLMs must not try to recompute, plus pointers into
raw log files that a grunt can be handed as a scoped slice.

Statistics live in a free-form `stats` map on purpose -- the pipeline will grow new
ones (entropy, NXDOMAIN rate, template ids, interval stddev, ...) faster than this
schema should churn. They are rendered as data, never interpreted as instructions.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class LogPointer(BaseModel):
    """A window into one raw log file. Line numbers are 1-based and inclusive."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    why: str = ""  # why this window is attached to this summary


class PatternSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    summary_id: str
    title: str
    source: str  # dns_resolver, proxy, edr, dhcp, ...
    host: str
    time_range: str
    description: str
    # Precomputed by the telemetry pipeline. Values are strings so the pipeline can
    # ship "0.42" and "2026-08-03T11:04:12Z" through the same channel without a schema
    # migration per statistic.
    stats: dict[str, str] = Field(default_factory=dict)
    log_pointers: list[LogPointer] = Field(default_factory=list)
