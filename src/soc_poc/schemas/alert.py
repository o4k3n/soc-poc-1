"""The inbound alert from the external detection system.

This is read-only input. The detector owns `status` and `severity`; this system
enriches the investigation around them and has no way to write them back. The fields
are carried into the final brief by orchestrator code copying them verbatim -- they
never pass through a model. See schemas/brief.py::AlertRef.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AlertEntity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str  # host, user, ip, domain, process, ...
    value: str
    note: str = ""


class Alert(BaseModel):
    """As emitted by the external detector. Never mutated by this system."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    alert_id: str
    detector: str
    rule_name: str
    # Authoritative, external, read-only. Present so the operator sees them next to the
    # enrichment; deliberately not exposed to any model output schema.
    status: str
    severity: str
    first_seen: str
    last_seen: str
    summary: str
    entities: list[AlertEntity] = Field(default_factory=list)
    raw_detector_fields: dict[str, str] = Field(default_factory=dict)
