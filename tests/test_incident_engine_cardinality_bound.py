import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.incident_engine import IncidentEngine, IncidentEngineConfig


def main() -> None:
    engine = IncidentEngine(IncidentEngineConfig(max_incidents=3))
    for i in range(5):
        engine.report(f"attack:1.2.3.{i}:WEB_ATTACK_SCAN", f"1.2.3.{i}", kind="scan")
    assert len(engine) == 3, (
        f"an attacker sending distinct source IPs must never grow the incident table past "
        f"max_incidents=3, got {len(engine)}"
    )
    print("Scenario 1 (unbounded distinct incident_keys -- table stays capped at max_incidents) PASSED")

    stats = IncidentEngine.aggregate_stats()
    assert stats["evicted_total"] >= 2, (
        f"5 distinct keys against a cap of 3 must evict at least 2 entries and this must be "
        f"observable via aggregate_stats, got {stats}"
    )
    print("Scenario 2 (evictions are counted and observable via aggregate_stats) PASSED")

    engine2 = IncidentEngine(IncidentEngineConfig(max_incidents=2))
    engine2.report("k1", "r1", kind="x")
    engine2.report("k2", "r2", kind="x")
    engine2.report("k1", "r1", kind="x")
    engine2.report("k3", "r3", kind="x")
    assert "k1" in engine2, (
        "k1 was touched most recently before k3 arrived -- LRU eviction must keep it and evict "
        "k2 (the least-recently-touched key) instead"
    )
    assert "k2" not in engine2, "k2 was never re-touched and must be the one evicted under LRU order"
    assert "k3" in engine2
    print("Scenario 3 (LRU order: recently-touched incidents survive eviction over stale ones) PASSED")

    engine3 = IncidentEngine(IncidentEngineConfig())
    for i in range(50):
        engine3.report(f"k{i}", f"r{i}", kind="x")
    assert len(engine3) == 50, (
        f"the default max_incidents must be large enough to never affect normal, "
        f"finite-cardinality module usage, got {len(engine3)} of 50"
    )
    print("Scenario 4 (default max_incidents is a no-op for normal, bounded-cardinality usage) PASSED")

    engine4 = IncidentEngine(IncidentEngineConfig(max_incidents=0))
    for i in range(10):
        engine4.report(f"k{i}", f"r{i}", kind="x")
    assert len(engine4) == 10, "max_incidents=0 must mean 'no bound' (opt-out), not 'zero capacity'"
    print("Scenario 5 (max_incidents=0 disables the bound entirely) PASSED")

    print("\nALL INCIDENT ENGINE CARDINALITY BOUND TESTS PASSED")


main()
