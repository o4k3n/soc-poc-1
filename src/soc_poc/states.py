r"""The investigation state machine, written out rather than implied.

This is deliberately shaped the way `gen_statem` would force it: named states, an
explicit legal-transition table, and no state that lives only in a local variable of
some async function. The orchestrator is a loop that reads the current state, does the
work for that state, and returns the next one. Nothing else decides where the
investigation is.

    RECEIVED
       |
       v
    PLANNING <-------------------+
       |  \                      |
       |   \ (no tasks)          | (follow-up requested, under cap)
       |    \                    |
       v     \                   |
    DISPATCHED                   |
       |                         |
       v                         |
    COLLECTING ------------------+
       |         \
       |          \ (cap reached)
       |           v
       |     ABORTED_ITERATION_CAP
       |           |
       v           v
    SYNTHESIZING
       |
       v
     DONE

Failure states are terminal and carry a reason: FAILED_PLANNING (the first planning
round produced nothing usable, so there is no investigation to write up),
FAILED_SYNTHESIS (work was collected but the brief could not be produced -- the
transcript still holds every grunt report), FAILED_PREFLIGHT (endpoints were not
healthy; we never started).

ABORTED_ITERATION_CAP is a real state rather than a boolean because "we stopped early"
is something the operator must be able to read off the brief, and something the
transcript must show as a transition.
"""

from __future__ import annotations

from enum import Enum


class InvestigationState(str, Enum):
    RECEIVED = "RECEIVED"
    PLANNING = "PLANNING"
    DISPATCHED = "DISPATCHED"
    COLLECTING = "COLLECTING"
    ABORTED_ITERATION_CAP = "ABORTED_ITERATION_CAP"
    SYNTHESIZING = "SYNTHESIZING"
    DONE = "DONE"
    FAILED_PREFLIGHT = "FAILED_PREFLIGHT"
    FAILED_PLANNING = "FAILED_PLANNING"
    FAILED_SYNTHESIS = "FAILED_SYNTHESIS"


TERMINAL_STATES: frozenset[InvestigationState] = frozenset(
    {
        InvestigationState.DONE,
        InvestigationState.FAILED_PREFLIGHT,
        InvestigationState.FAILED_PLANNING,
        InvestigationState.FAILED_SYNTHESIS,
    }
)

# The only transitions this system is allowed to make. Enforced at runtime by
# assert_legal_transition, so a future edit that invents a shortcut fails immediately
# instead of producing an investigation nobody can reconstruct from the transcript.
LEGAL_TRANSITIONS: dict[InvestigationState, frozenset[InvestigationState]] = {
    InvestigationState.RECEIVED: frozenset(
        {InvestigationState.PLANNING, InvestigationState.FAILED_PREFLIGHT}
    ),
    InvestigationState.PLANNING: frozenset(
        {
            InvestigationState.DISPATCHED,
            InvestigationState.SYNTHESIZING,
            InvestigationState.FAILED_PLANNING,
        }
    ),
    InvestigationState.DISPATCHED: frozenset({InvestigationState.COLLECTING}),
    InvestigationState.COLLECTING: frozenset(
        {
            InvestigationState.PLANNING,
            InvestigationState.SYNTHESIZING,
            InvestigationState.ABORTED_ITERATION_CAP,
        }
    ),
    InvestigationState.ABORTED_ITERATION_CAP: frozenset({InvestigationState.SYNTHESIZING}),
    InvestigationState.SYNTHESIZING: frozenset(
        {InvestigationState.DONE, InvestigationState.FAILED_SYNTHESIS}
    ),
    InvestigationState.DONE: frozenset(),
    InvestigationState.FAILED_PREFLIGHT: frozenset(),
    InvestigationState.FAILED_PLANNING: frozenset(),
    InvestigationState.FAILED_SYNTHESIS: frozenset(),
}


class IllegalTransitionError(RuntimeError):
    pass


def assert_legal_transition(
    from_state: InvestigationState, to_state: InvestigationState
) -> None:
    if to_state not in LEGAL_TRANSITIONS[from_state]:
        raise IllegalTransitionError(f"{from_state.value} -> {to_state.value} is not allowed")
