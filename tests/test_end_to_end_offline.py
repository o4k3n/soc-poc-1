"""One full investigation on the stub backend: the loop, the artifacts, the guarantees.

This is the test that would notice if the skeleton stopped hanging together.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_poc.config import load_config
from soc_poc.runner import run_investigation
from soc_poc.states import InvestigationState

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def config(tmp_path: Path):
    cfg = load_config(ROOT / "config" / "config.toml")
    # Keep runs out of the repo's out/ directory.
    return cfg.model_copy(update={"run": cfg.run.model_copy(update={"output_dir": str(tmp_path)})})


async def test_offline_run_reaches_done_and_writes_artifacts(config) -> None:
    result, paths = await run_investigation(config, backend="stub", investigation_id="inv-test")

    assert result.terminal_state is InvestigationState.DONE
    assert paths.transcript.exists() and paths.brief.exists() and paths.meta.exists()

    brief = result.brief
    assert brief is not None
    # The detector's status arrives unchanged, having never been an output field.
    alert = json.loads((ROOT / "fixtures" / "alert.json").read_text())
    assert brief.alert_ref.status == alert["status"]
    assert brief.alert_ref.severity == alert["severity"]
    # Every reference the commander used resolves to a line it was actually shown.
    assert brief.unresolved_citations == []
    # The planted log line that addresses an AI system is surfaced, not swallowed.
    assert any(signal["signal"] == "instruction_override" for signal in brief.injection_signals)
    # Every step is in the ledger with the command that reproduces it, which is the
    # property that makes the brief checkable without re-running a GPU.
    assert brief.step_ledger
    assert brief.steps_taken == len(brief.step_ledger)
    assert all(entry.reproduce for entry in brief.step_ledger)


async def test_transcript_records_the_whole_run(config) -> None:
    _, paths = await run_investigation(config, backend="stub", investigation_id="inv-test-2")
    records = [json.loads(line) for line in paths.transcript.read_text().splitlines()]
    kinds = [record["kind"] for record in records]

    assert kinds.count("state_transition") >= 5
    assert "llm_call" in kinds

    # Every LLM interaction is stored in full: prompts included, nothing truncated.
    for record in (r for r in records if r["kind"] == "llm_call"):
        assert record["request_messages"] and record["model"] and record["schema_name"]
        assert record["latency_ms"] >= 0

    # The stub's first action names a file that does not exist; the run must show the
    # rejection, the re-prompt, and a second attempt that passes.
    actions = [r for r in records if r["kind"] == "commander_action_validation"]
    assert any(not a["payload"]["ok"] for a in actions), "action validator never fired"
    assert any(r["attempt"] > 1 for r in records if r["kind"] == "llm_call"), "no retry happened"
    assert actions[-1]["payload"]["ok"]

    # Every executed action is paired with the decision that produced it, in order.
    decided = [r for r in records if r["kind"] == "action_decided"]
    executed = [r for r in records if r["kind"] == "action_executed"]
    assert len(decided) == len(executed) + 1, "the last decision is conclude, which executes nothing"
    assert [r["payload"]["step"] for r in executed] == list(range(1, len(executed) + 1))

    # The action loop ran more than one round.
    iterations = {r["iteration"] for r in records if r["kind"] == "state_transition"}
    assert max(iterations) >= 1


async def test_run_meta_snapshots_config_without_leaking_keys(config) -> None:
    _, paths = await run_investigation(config, backend="stub", investigation_id="inv-test-3")
    meta = json.loads(paths.meta.read_text())
    assert meta["backend"] == "stub"
    assert meta["terminal_state"] == "DONE"
    assert set(meta["models"]) >= {"commander", "grunt"}
    assert "api_key" not in json.dumps(meta["models"])
