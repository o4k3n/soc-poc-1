"""Configuration loading: TOML on disk -> typed pydantic models.

No component in this package reads a raw dict. Everything downstream takes one of
these models, so a missing or misspelled key fails at startup with a path, not three
layers into an investigation.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ModelConfig(BaseModel):
    """One addressable model endpoint. Commander, grunt and evaluator share this shape
    so a role can be repointed at a different box or a different model by config."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: str
    base_url: str
    model: str
    api_key: str = "EMPTY"
    enabled: bool = True
    temperature: float = 0.2
    top_p: float = 0.95
    max_tokens: int = 4096
    request_timeout_s: float = 600.0
    extra_body: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    def resolved_api_key(self) -> str:
        """`env:NAME` indirection so a real key never lands in the repo."""
        if self.api_key.startswith("env:"):
            return os.environ.get(self.api_key[4:], "")
        return self.api_key


class RunConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    output_dir: str = "out"
    max_iterations: int = Field(default=3, ge=1)
    max_tasks_per_iteration: int = Field(default=4, ge=1)
    max_validation_retries: int = Field(default=1, ge=0)


class StructuredOutputConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: Literal["response_format", "structured_outputs"] = "response_format"
    strict: bool = True


class FixtureConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    alert: str
    patterns_dir: str
    logs_dir: str


class AppConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    run: RunConfig
    models: dict[str, ModelConfig]
    structured_output: StructuredOutputConfig
    fixtures: FixtureConfig
    # Directory the config file lives next to; relative fixture paths resolve against
    # the project root (its parent), not the process CWD.
    root: Path

    @property
    def commander(self) -> ModelConfig:
        return self.models["commander"]

    @property
    def grunt(self) -> ModelConfig:
        return self.models["grunt"]

    def path(self, relative: str) -> Path:
        p = Path(relative)
        return p if p.is_absolute() else self.root / p


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).resolve()
    with config_path.open("rb") as fh:
        raw = tomllib.load(fh)

    models = {name: ModelConfig(**cfg) for name, cfg in raw.get("models", {}).items()}
    for required in ("commander", "grunt"):
        if required not in models:
            raise ValueError(f"config {config_path}: missing [models.{required}]")

    return AppConfig(
        run=RunConfig(**raw.get("run", {})),
        models=models,
        structured_output=StructuredOutputConfig(**raw.get("structured_output", {})),
        fixtures=FixtureConfig(**raw["fixtures"]),
        root=config_path.parent.parent,
    )
