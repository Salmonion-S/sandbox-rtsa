import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.incident_engine import (
    STATE_CONTAINED, STATE_DETECTED, STATE_DISMISSED, STATE_FALSE_POSITIVE,
    STATE_INVESTIGATING, STATE_RECOVERED, STATE_RECOVERING, STATE_RESOLVED,
    TERMINAL_STATES, IncidentEngine, IncidentEngineConfig,
)


def main():
    eng = IncidentEngine(IncidentEngineConfig())
    report = eng.report("k1", "r1", kind="test")
    inc = report.incident
    assert inc.state == STATE_DETECTED
    print("Test 1 (new Incident defaults to DETECTED) PASSED")

    assert inc.transition_state(STATE_INVESTIGATING) is True
    assert inc.state == STATE_INVESTIGATING
    print("Test 2 (DETECTED -> INVESTIGATING is a valid transition) PASSED")

    assert inc.transition_state(STATE_RECOVERED) is False
    assert inc.state == STATE_INVESTIGATING
    print("Test 3 (INVESTIGATING -> RECOVERED is invalid -- no-op, state unchanged) PASSED")

    assert eng.transition("k1", STATE_CONTAINED) is True
    assert inc.state == STATE_CONTAINED
    assert eng.transition("no-such-key", STATE_RECOVERED) is False
    print("Test 4 (IncidentEngine.transition() moves a tracked incident, no-ops on unknown key) PASSED")

    assert eng.transition("k1", STATE_RECOVERING) is True
    assert eng.transition("k1", STATE_RECOVERED) is True
    assert inc.state == STATE_RECOVERED
    print("Test 5 (CONTAINED -> RECOVERING -> RECOVERED chain) PASSED")

    closed = eng.resolve("k1", "r1")
    assert closed is not None
    assert closed.state == STATE_RESOLVED
    assert closed.state in TERMINAL_STATES
    assert len(closed.state_history) == 5, closed.state_history
    print("Test 6 (resolve() auto-transitions to RESOLVED and is terminal) PASSED")

    eng2 = IncidentEngine(IncidentEngineConfig())
    report2 = eng2.report("k2", "r2", kind="test")
    inc2 = report2.incident
    assert inc2.transition_state(STATE_FALSE_POSITIVE) is True
    assert inc2.state in TERMINAL_STATES
    assert inc2.transition_state(STATE_INVESTIGATING) is False, "terminal states must not accept further transitions"
    print("Test 7 (DETECTED -> FALSE_POSITIVE directly; terminal state rejects further transitions) PASSED")

    assert STATE_DISMISSED in TERMINAL_STATES
    print("Test 8 (DISMISSED is a recognized terminal state) PASSED")

    print("\nALL INCIDENT LIFECYCLE REGRESSION TESTS PASSED")


if __name__ == "__main__":
    main()
