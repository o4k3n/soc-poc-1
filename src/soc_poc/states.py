r"""The investigation state machine, written out rather than implied.

This is deliberately shaped the way `gen_statem` would force it: named states, an
explicit legal-transition table, and no state that lives only in a local variable of
some async function. The orchestrator is a loop that reads the current state, does the
work for that state, and returns the next one. Nothing else decides where the
investigation is.

    RECEIVED
       |
       v
    PROFILING        deterministic. Counts the corpus -- shapes, rarities, entropy
       |             groups, activity bursts. No model runs here, so nothing produced
       |             here can be a hallucination.
       v
    INVESTIGATING <--+   the commander sees the alert, the profile, and everything it
       |  \           |  has been shown so far, and emits ONE action.
       |   \          |
       |    v         |
       |  EXECUTING --+   we run that action against the corpus and append the result
       |                  to the evidence ledger.
       v
    SYNTHESIZING
       |
       v
     DONE

**What changed, and why.** The previous machine had TASKING -> SWEEPING -> COLLECTING,
where the commander wrote a relevance directive and every slice in the case was read by a
worker. The argument for it was coverage: if every line is read, a negative means
something. Six runs disproved the premise. Reading is not noticing. A worker was handed an
eight-line DHCP file containing the lease on lines 4 and 8, reported `10.12.34.56 ->
found: false`, and the brief went on to state the host could not be identified. The NS
delegation that ties the tunnel domain to attacker infrastructure appears in no worker
output across six complete sweeps -- roughly 4,300 GPU-seconds each.

Coverage did not weaken; it changed hands. `corpus.count()` is a negative that is
deterministically correct and that the operator can re-run with grep in milliseconds,
which is strictly more than "a model read it and did not mention it" was ever worth.

INVESTIGATING and EXECUTING stay separate for the same reason TASKING and PLANNING did:
one is the commander deciding, the other is the machine acting. Collapsing them would hide
the boundary the transcript exists to show -- and that boundary is now the security
property, since everything on the EXECUTING side is code the model cannot influence beyond
handing it a regex.

Failure states are terminal and carry a reason: FAILED_INVESTIGATION (the commander could
not produce a usable action and there is nothing to write up), FAILED_SYNTHESIS (evidence
was collected but the brief could not be produced -- the transcript still holds every
step), FAILED_PREFLIGHT (endpoints were not healthy; we never started).

ABORTED_ITERATION_CAP is a real state rather than a boolean because "we stopped early" is
something the operator must be able to read off the brief, and something the transcript
must show as a transition. It now means the action budget ran out mid-investigation, which
is a coverage gap in the literal sense: there were questions left to ask.

Operator aborts (see control.py and abort.py) get two states rather than one, because
they mean two different things and a state that means two things is a bug waiting:

  ABORTING              graceful. Stop after the current action, then synthesize from
                        whatever evidence was gathered. Routes to SYNTHESIZING exactly as
                        ABORTED_ITERATION_CAP does.
  ABORTED_BY_OPERATOR   terminal, no brief. Either `abort.py --hard`, or a graceful
                        abort that arrived before a single step existed -- spending two
                        minutes synthesizing a brief about nothing helps no one.

Abort is checked at state boundaries. Once SYNTHESIZING starts it runs to completion:
interrupting the one call that produces the artifact would throw away the whole run's
product.
"""

from __future__ import annotations

from enum import Enum


class InvestigationState(str, Enum):
    RECEIVED = "RECEIVED"
    PROFILING = "PROFILING"
    INVESTIGATING = "INVESTIGATING"
    EXECUTING = "EXECUTING"
    ABORTED_ITERATION_CAP = "ABORTED_ITERATION_CAP"
    ABORTING = "ABORTING"
    SYNTHESIZING = "SYNTHESIZING"
    DONE = "DONE"
    FAILED_PREFLIGHT = "FAILED_PREFLIGHT"
    FAILED_INVESTIGATION = "FAILED_INVESTIGATION"
    FAILED_SYNTHESIS = "FAILED_SYNTHESIS"
    ABORTED_BY_OPERATOR = "ABORTED_BY_OPERATOR"


TERMINAL_STATES: frozenset[InvestigationState] = frozenset(
    {
        InvestigationState.DONE,
        InvestigationState.FAILED_PREFLIGHT,
        InvestigationState.FAILED_INVESTIGATION,
        InvestigationState.FAILED_SYNTHESIS,
        InvestigationState.ABORTED_BY_OPERATOR,
    }
)

# The only transitions this system is allowed to make. Enforced at runtime by
# assert_legal_transition, so a future edit that invents a shortcut fails immediately
# instead of producing an investigation nobody can reconstruct from the transcript.
LEGAL_TRANSITIONS: dict[InvestigationState, frozenset[InvestigationState]] = {
    InvestigationState.RECEIVED: frozenset(
        {
            InvestigationState.PROFILING,
            InvestigationState.FAILED_PREFLIGHT,
            InvestigationState.ABORTED_BY_OPERATOR,
        }
    ),
    InvestigationState.PROFILING: frozenset(
        {
            InvestigationState.INVESTIGATING,
            InvestigationState.FAILED_INVESTIGATION,
            InvestigationState.ABORTED_BY_OPERATOR,
        }
    ),
    InvestigationState.INVESTIGATING: frozenset(
        {
            InvestigationState.EXECUTING,
            # The commander said it has enough. This is the intended exit.
            InvestigationState.SYNTHESIZING,
            InvestigationState.FAILED_INVESTIGATION,
            InvestigationState.ABORTING,
            InvestigationState.ABORTED_BY_OPERATOR,
        }
    ),
    InvestigationState.EXECUTING: frozenset(
        {
            InvestigationState.INVESTIGATING,
            InvestigationState.ABORTED_ITERATION_CAP,
            InvestigationState.ABORTING,
            InvestigationState.ABORTED_BY_OPERATOR,
        }
    ),
    InvestigationState.ABORTED_ITERATION_CAP: frozenset({InvestigationState.SYNTHESIZING}),
    InvestigationState.ABORTING: frozenset({InvestigationState.SYNTHESIZING}),
    InvestigationState.SYNTHESIZING: frozenset(
        {InvestigationState.DONE, InvestigationState.FAILED_SYNTHESIS}
    ),
    InvestigationState.DONE: frozenset(),
    InvestigationState.FAILED_PREFLIGHT: frozenset(),
    InvestigationState.FAILED_INVESTIGATION: frozenset(),
    InvestigationState.FAILED_SYNTHESIS: frozenset(),
    InvestigationState.ABORTED_BY_OPERATOR: frozenset(),
}


class IllegalTransitionError(RuntimeError):
    pass


def assert_legal_transition(
    from_state: InvestigationState, to_state: InvestigationState
) -> None:
    if to_state not in LEGAL_TRANSITIONS[from_state]:
        raise IllegalTransitionError(f"{from_state.value} -> {to_state.value} is not allowed")
