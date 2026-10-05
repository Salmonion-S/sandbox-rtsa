import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.self_health import DEGRADED, EMERGENCY, NORMAL, OVERLOADED, SelfHealthMonitor, SelfHealthThresholds


def neutral_thresholds(**overrides):
    base = dict(
        degraded_cpu_percent=101, overloaded_cpu_percent=102, emergency_cpu_percent=103,
        degraded_memory_percent=101, overloaded_memory_percent=102, emergency_memory_percent=103,
        degraded_swap_percent=101, overloaded_swap_percent=102,
        degraded_load_average_ratio=1000.0, overloaded_load_average_ratio=1001.0, emergency_load_average_ratio=1002.0,
        degraded_process_rss_mb=1e9, overloaded_process_rss_mb=2e9, emergency_process_rss_mb=3e9,
        recovery_dwell_seconds=30.0,
    )
    base.update(overrides)
    return SelfHealthThresholds(**base)


class _StubDispatcher:
    def __init__(self, state):
        self._state = state

    def get_outbound_health(self):
        return {"load_shed_state": self._state, "circuit_state": "CLOSED"}


def main() -> None:
    monitor = SelfHealthMonitor(neutral_thresholds())
    monitor.attach_dispatcher(_StubDispatcher("OVERLOADED"))
    state = monitor.evaluate(now=0.0)
    assert state == OVERLOADED, f"escalation to OVERLOADED must apply immediately, got {state}"
    print("Scenario 1 (escalation is never delayed by hysteresis -- OVERLOADED applies on the same tick) PASSED")

    monitor.attach_dispatcher(_StubDispatcher("NORMAL"))
    state = monitor.evaluate(now=1.0)
    assert state == OVERLOADED, (
        f"de-escalation must be held back by recovery_dwell_seconds even once the underlying "
        f"signal recovers -- a single good reading 1s after an OVERLOADED tick must not immediately "
        f"drop back to NORMAL (this is exactly the oscillation the spec asks to prevent), got {state}"
    )
    state = monitor.evaluate(now=15.0)
    assert state == OVERLOADED, f"still within the 30s dwell window at t=15s, got {state}"
    state = monitor.evaluate(now=31.0)
    assert state == NORMAL, f"once the dwell window has fully elapsed with a healthy reading, must recover to NORMAL, got {state}"
    print("Scenario 2 (de-escalation is held for recovery_dwell_seconds, preventing oscillation) PASSED")

    monitor2 = SelfHealthMonitor(neutral_thresholds(emergency_cpu_percent=50.0))
    monitor2._process = None

    class _FakePsutilModule:
        @staticmethod
        def cpu_percent(interval=None):
            return 90.0

        @staticmethod
        def virtual_memory():
            class _M:
                percent = 10.0
            return _M()

        @staticmethod
        def swap_memory():
            class _S:
                percent = 0.0
            return _S()

    import core.self_health as sh_module
    original_psutil = sh_module.psutil
    sh_module.psutil = _FakePsutilModule
    try:
        state = monitor2.evaluate(now=0.0)
        assert state == EMERGENCY, f"CPU past the emergency threshold must reach EMERGENCY, not just OVERLOADED, got {state}"
    finally:
        sh_module.psutil = original_psutil
    print("Scenario 3 (EMERGENCY is reachable as a distinct 4th tier above OVERLOADED) PASSED")

    monitor3 = SelfHealthMonitor(neutral_thresholds())
    monitor3.record_metric("queue_saturation", 0.95)
    state = monitor3.evaluate(now=0.0)
    assert state == OVERLOADED, f"externally-fed queue_saturation must be able to drive escalation, got {state}"
    print("Scenario 4 (externally fed metrics via record_metric can drive escalation) PASSED")

    monitor4 = SelfHealthMonitor(neutral_thresholds())
    assert monitor4.should_run("pm2_routine_poll") is True
    assert monitor4.should_run("unknown_capability_not_in_table") is True, (
        "a capability with no policy entry must fail open (always allowed) -- never silently "
        "disable detection work nobody explicitly decided to gate"
    )
    monitor4.attach_dispatcher(_StubDispatcher("OVERLOADED"))
    monitor4.evaluate(now=0.0)
    assert monitor4.should_run("pm2_routine_poll") is False, "OVERLOADED must disable pm2_routine_poll per the documented capability table"
    assert monitor4.should_run("cloudpanel_routine_discovery") is False
    assert monitor4.should_run("website_monitor_routine_check") is True, (
        "website outage detection is deliberately NEVER gated by load state -- it is the cheapest, "
        "highest-value signal (a real HTTP check with its own bounded timeout) and is exactly the "
        "kind of primary security-relevant telemetry that must survive overload, not routine noise"
    )
    print("Scenario 5 (should_run gates OVERLOADED-disabled capabilities, fails open for unlisted ones) PASSED")

    print("\nALL SELF-HEALTH EMERGENCY/HYSTERESIS TESTS PASSED")


main()
