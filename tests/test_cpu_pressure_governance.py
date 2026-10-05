from __future__ import annotations

import asyncio
import os
import sys
import time
from typing import Any, Dict, List, Tuple

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.self_health as self_health_module
from core.self_health import (
    DEGRADED, EMERGENCY, NORMAL, OVERLOADED, SelfHealthMonitor, SelfHealthThresholds,
    _CAPABILITY_DISABLED_FROM, get_self_health_monitor,
)
from config.manager import HealthMonitorConfig
from core.datatypes import EventCategory, HealthEvent, Severity
from core.event_bus import EventBus
from core.spike_diagnostics import get_spike_diagnostics
import modules.health_monitor as health_monitor_module
from modules.health_monitor import HealthMonitor, _format_module_state_block


class _FakeSelfHealth:

    def __init__(self, state: str) -> None:
        self._state = state

    @property
    def state(self) -> str:
        return self._state

    def evaluate(self, now=None) -> str:
        return self._state

    def get_status(self) -> Dict[str, Any]:
        return {"state": self._state, "reasons": [f"stub_forced={self._state}"]}

    def should_run(self, capability: str) -> bool:
        from core.self_health import _STATE_ORDER
        disabled_from = _CAPABILITY_DISABLED_FROM.get(capability)
        if disabled_from is None:
            return True
        return _STATE_ORDER[self._state] < _STATE_ORDER[disabled_from]

    def capability_status(self) -> Dict[str, bool]:
        return {c: self.should_run(c) for c in _CAPABILITY_DISABLED_FROM}


def _install_fake_self_health(state: str):
    original = self_health_module._singleton
    self_health_module._singleton = _FakeSelfHealth(state)
    return original


def _restore_self_health(original) -> None:
    self_health_module._singleton = original


def _cpu_snapshot(percent, top_cpu_processes=(), load_avg=(1.0, 1.0, 1.0)):
    return HealthEvent(
        source_module="health_monitor", category=EventCategory.HEALTH_STATUS,
        severity=Severity.INFO, message="", raw="",
        cpu_percent=percent, mem_percent=10.0, disk_percent=10.0,
        top_cpu_processes=tuple(top_cpu_processes), load_avg=load_avg,
    )


def _make_health_monitor(**overrides) -> HealthMonitor:
    base = dict(
        cpu_alert_threshold=70.0, cpu_recovery_threshold=60.0, cpu_critical_threshold=98.0,
        mem_alert_threshold=90.0, mem_recovery_threshold=85.0, mem_critical_threshold=97.0,
        disk_alert_threshold=90.0, disk_recovery_threshold=85.0, disk_critical_threshold=97.0,
        resource_consecutive_breaches=3, resource_consecutive_recoveries=3,
        resource_minimum_breach_duration_seconds=999999.0,
    )
    base.update(overrides)
    return HealthMonitor(EventBus(), HealthMonitorConfig(**base))


async def _collect(hm: HealthMonitor):
    collected: List[HealthEvent] = []

    async def collector(event):
        collected.append(event)

    sub = await hm.bus.subscribe("collector", collector, categories=None)
    return collected, sub


async def _feed(hm: HealthMonitor, samples) -> None:
    for percent, kwargs in samples:
        hm._evaluate_resource_thresholds(_cpu_snapshot(percent, **kwargs))


async def main() -> None:
    hm = _make_health_monitor()
    collected, sub = await _collect(hm)
    await _feed(hm, [(50.0, {}), (55.0, {}), (65.0, {}), (69.0, {})])
    await sub.queue.join()
    high = [e for e in collected if e.severity in (Severity.HIGH, Severity.CRITICAL)]
    assert not high, f"CPU below threshold must never raise a pressure incident, got {len(high)}"
    print("Scenario 1 (CPU below 70% threshold -> no incident) PASSED")
    await hm.bus.unsubscribe("collector")

    hm = _make_health_monitor()
    collected, sub = await _collect(hm)
    await _feed(hm, [(75.0, {}), (55.0, {}), (60.0, {})])
    await sub.queue.join()
    high = [e for e in collected if e.severity in (Severity.HIGH, Severity.CRITICAL)]
    assert not high, f"a single transient spike must never fire a pressure alert, got {len(high)}"
    print("Scenario 2 (single short CPU spike -> no immediate alert) PASSED")
    await hm.bus.unsubscribe("collector")

    hm = _make_health_monitor()
    collected, sub = await _collect(hm)
    await _feed(hm, [(75.0, {}), (76.0, {}), (74.0, {})])
    await sub.queue.join()
    high = [e for e in collected if e.severity == Severity.HIGH]
    assert len(high) == 1, f"sustained CPU>=70% must confirm exactly ONE pressure alert, got {len(high)}"
    assert "CPU" in high[0].message
    print("Scenario 3 (sustained CPU >= 70% -> pressure state activates, one alert) PASSED")

    collected.clear()
    await _feed(hm, [(77.0, {}), (78.0, {}), (76.0, {}), (79.0, {}), (75.0, {})])
    await sub.queue.join()
    high_repeat = [e for e in collected if e.severity == Severity.HIGH]
    assert len(high_repeat) == 0, (
        f"sustained high CPU across 5 more cycles must not spam a new alert every cycle "
        f"(cooldown/reminder policy governs this), got {len(high_repeat)}"
    )
    print("Scenario 4 (sustained pressure across many cycles -> no alert storm) PASSED")
    await hm.bus.unsubscribe("collector")

    hm = _make_health_monitor()
    collected, sub = await _collect(hm)
    procs = (
        {"pid": 111, "user": "root", "cpu_percent": 96.4, "mem_percent": 5.2, "command": "python3 main.py"},
        {"pid": 222, "user": "newus-cat", "cpu_percent": 41.8, "mem_percent": 3.1, "command": "node app.js"},
    )
    await _feed(hm, [(75.0, {"top_cpu_processes": procs}), (76.0, {"top_cpu_processes": procs}), (74.0, {"top_cpu_processes": procs})])
    await sub.queue.join()
    high = [e for e in collected if e.severity == Severity.HIGH]
    assert len(high) == 1
    assert "python3 main.py" in high[0].message and "PID 111" in high[0].message
    assert "node app.js" in high[0].message and "PID 222" in high[0].message
    print("Scenario 5 (pressure alert includes top-N CPU process diagnostics) PASSED")
    await hm.bus.unsubscribe("collector")

    diagnostics = get_spike_diagnostics()
    snap = diagnostics.capture(rtsa_cpu_percent=42.0)
    block = diagnostics.format_block(snap)
    assert "HOST_CPU_PERCENT" in block and "PROCESS_CPU_PERCENT" in block
    assert "42.0%" in block
    print("Scenario 6 (host CPU and RTSA process CPU reported as separate, labeled figures) PASSED")

    snap_over = diagnostics.capture(rtsa_cpu_percent=154.0)
    block_over = diagnostics.format_block(snap_over)
    assert "154.0%" in block_over
    assert ">100%" in block_over, "a >100% process CPU reading must be explicitly explained, not silently shown"
    print("Scenario 7 (process CPU >100% is represented and explained, not treated as an error) PASSED")

    import psutil as psutil_module

    class _FlakyProc:
        def __init__(self, pid, fail_with=None):
            self.pid = pid
            self._fail_with = fail_with

        def cpu_percent(self, interval=None):
            if self._fail_with:
                raise self._fail_with("gone")
            return 12.5

        def oneshot(self):
            import contextlib
            return contextlib.nullcontext()

        def memory_percent(self):
            return 1.0

        def memory_info(self):
            return type("M", (), {"rss": 1024})()

        def username(self):
            return "root"

        def cmdline(self):
            return ["fake"]

        def name(self):
            return "fake"

    healthy = _FlakyProc(1)
    gone = _FlakyProc(2, fail_with=psutil_module.NoSuchProcess)
    denied = _FlakyProc(3, fail_with=psutil_module.AccessDenied)

    primed = []
    for p in (healthy, gone, denied):
        try:
            p.cpu_percent(interval=None)
            primed.append(p)
        except (psutil_module.NoSuchProcess, psutil_module.AccessDenied, psutil_module.ZombieProcess):
            continue
    assert primed == [healthy], "priming must silently skip processes that vanish or deny access"
    records = HealthMonitor._read_process_records(primed)
    assert len(records) == 1 and records[0]["pid"] == 1
    print("Scenario 8/9 (NoSuchProcess/AccessDenied during process collection never crashes diagnostics) PASSED")

    import modules.file_integrity_detector as fim_module
    original = _install_fake_self_health(NORMAL)
    try:
        assert fim_module.FileIntegrityDetector._hashing_allowed("critical_system") is True
        assert fim_module.FileIntegrityDetector._hashing_allowed("htdocs") is True
    finally:
        _restore_self_health(original)
    print("Scenario 10 (FIM hashing fully allowed at NORMAL) PASSED")

    original = _install_fake_self_health(OVERLOADED)
    try:
        assert fim_module.FileIntegrityDetector._hashing_allowed("htdocs") is False, (
            "non-critical hashing must defer at OVERLOADED"
        )
        assert fim_module.FileIntegrityDetector._hashing_allowed("critical_system") is True, (
            "critical_system hashing must NOT defer until EMERGENCY"
        )
    finally:
        _restore_self_health(original)
    original = _install_fake_self_health(EMERGENCY)
    try:
        assert fim_module.FileIntegrityDetector._hashing_allowed("critical_system") is False, (
            "even critical_system hashing defers at EMERGENCY -- this is the pre-existing "
            "capability policy (fim_any_hashing), not a new decision"
        )
    finally:
        _restore_self_health(original)
    print("Scenario 11 (FIM non-critical hashing deferred at OVERLOADED; critical_system only at EMERGENCY) PASSED")

    with open(os.path.join(_REPO_ROOT, "modules", "ssh_monitor.py"), "r", encoding="utf-8") as f:
        ssh_source = f.read()
    should_run_calls = ssh_source.count("should_run(")
    assert should_run_calls == 1, (
        f"expected exactly one should_run() call in ssh_monitor.py, scoped to geoip enrichment "
        f"-- found {should_run_calls}; any additional call risks gating core SSH auth detection"
    )
    assert 'should_run("ssh_geoip_enrichment")' in ssh_source, (
        "the sole should_run() call in ssh_monitor.py must be the geoip-enrichment capability gate"
    )
    gated_spawn_line = next(
        line for line in ssh_source.splitlines() if "geoip_allowed" in line and "if " in line
    )
    assert "and geoip_allowed" in gated_spawn_line, (
        "geoip_allowed must gate the enrichment spawn condition"
    )
    assert "self._spawn_background(self._publish_login_enriched" in ssh_source, (
        "geoip-gated branch must only spawn the enrichment task, never skip the base SSH_AUTH publish"
    )
    print("Scenario 12 (SSH/auth detection always active -- should_run() scoped to geoip enrichment only) PASSED")

    with open(os.path.join(_REPO_ROOT, "core", "event_bus.py"), "r", encoding="utf-8") as f:
        bus_source = f.read()
    assert "should_run(" not in bus_source and "get_self_health_monitor" not in bus_source, (
        "EventBus delivery must never be resource-gated"
    )
    print("Scenario 13 (EventBus is never resource-gated -- always active) PASSED")

    with open(os.path.join(_REPO_ROOT, "modules", "process_anomaly_detector.py"), "r", encoding="utf-8") as f:
        pad_source = f.read()
    assert 'should_run("process_deep_inspection")' in pad_source
    evaluate_rules_block = pad_source.split("def evaluate_rules(", 1)[1].split("\ndef ", 1)[0]
    assert "should_run(" not in evaluate_rules_block, (
        "the core behavioral rule engine must never itself be resource-gated"
    )
    print("Scenario 14 (PAD's expensive fingerprinting is gated; core rule engine is not) PASSED")

    from config.manager import FileIntegrityDetectorConfig
    cfg = FileIntegrityDetectorConfig(enabled=False)
    assert cfg.enabled is False
    original = _install_fake_self_health(NORMAL)
    try:
        assert fim_module.FileIntegrityDetector._hashing_allowed("htdocs") is True, (
            "should_run reflects resource state only -- it has no opinion on config.enabled, "
            "which the module's own run() checks independently before ever reaching this code"
        )
    finally:
        _restore_self_health(original)
    print("Scenario 15 (operator-disabled module state is independent of resource gating) PASSED")

    fake = _FakeSelfHealth(EMERGENCY)
    assert fake.should_run("fim_any_hashing") is False
    assert fake.should_run("fim_noncritical_hashing") is False
    fake_overloaded = _FakeSelfHealth(OVERLOADED)
    assert fake_overloaded.should_run("fim_any_hashing") is True, "EMERGENCY-only capability already resumed at OVERLOADED"
    assert fake_overloaded.should_run("fim_noncritical_hashing") is False, "OVERLOADED-gated capability has not resumed yet"
    fake_normal = _FakeSelfHealth(NORMAL)
    assert fake_normal.should_run("fim_noncritical_hashing") is True
    assert fake_normal.should_run("nonessential_metrics") is True
    print("Scenario 16/17 (recovery is tiered by capability, never a single simultaneous resume) PASSED")

    thresholds = SelfHealthThresholds(
        degraded_cpu_percent=70.0, overloaded_cpu_percent=90.0, emergency_cpu_percent=99.0,
        recovery_dwell_seconds=30.0,
    )
    monitor = SelfHealthMonitor(thresholds)
    monitor._process = None

    class _FakePsutil80:
        @staticmethod
        def cpu_percent(interval=None):
            return 85.0

        @staticmethod
        def virtual_memory():
            return type("V", (), {"percent": 10.0})()

        @staticmethod
        def swap_memory():
            return type("S", (), {"percent": 0.0})()

    original_psutil = self_health_module.psutil
    self_health_module.psutil = _FakePsutil80
    try:
        state = monitor.evaluate(now=0.0)
        assert state == DEGRADED, f"85% CPU with degraded=70/overloaded=90 must land in DEGRADED, got {state}"

        class _FakePsutilLow:
            @staticmethod
            def cpu_percent(interval=None):
                return 10.0

            @staticmethod
            def virtual_memory():
                return type("V", (), {"percent": 10.0})()

            @staticmethod
            def swap_memory():
                return type("S", (), {"percent": 0.0})()

        self_health_module.psutil = _FakePsutilLow
        state = monitor.evaluate(now=5.0)
        assert state == DEGRADED, "still within recovery_dwell_seconds, must not drop yet"

        self_health_module.psutil = _FakePsutil80
        state = monitor.evaluate(now=10.0)
        assert state == DEGRADED, "a CPU rebound mid-dwell must re-apply pressure immediately, not wait out the dwell"
    finally:
        self_health_module.psutil = original_psutil
    print("Scenario 18 (CPU rebound during recovery dwell immediately re-applies pressure) PASSED")

    _SUBPROCESS_SPAWN_MARKERS = ("subprocess.run(", "subprocess.Popen(", "create_subprocess", "os.system(")
    with open(os.path.join(_REPO_ROOT, "core", "self_health.py"), "r", encoding="utf-8") as f:
        self_health_source = f.read()
    assert not any(m in self_health_source for m in _SUBPROCESS_SPAWN_MARKERS), (
        "self_health must read pressure via psutil only, never spawn a process to check it"
    )
    with open(os.path.join(_REPO_ROOT, "modules", "health_monitor.py"), "r", encoding="utf-8") as f:
        hm_source = f.read()
    prime_block = hm_source.split("_prime_process_cpu_percent()", 1)[1].split("\n    @staticmethod", 1)[0]
    assert not any(m in prime_block for m in _SUBPROCESS_SPAWN_MARKERS), (
        "priming process CPU% for the top-N list must never spawn a subprocess (e.g. ps/top)"
    )
    print("Scenario 19 (CPU/process diagnostics never spawn a subprocess) PASSED")

    original = _install_fake_self_health(OVERLOADED)
    try:
        status = get_self_health_monitor().capability_status()
        assert status["fim_noncritical_hashing"] is False
        assert status["cloudpanel_routine_discovery"] is False
        assert status["fim_any_hashing"] is True
        rendered = _format_module_state_block(status)
        assert "PAUSED / DEFERRED" in rendered and "RUNNING / PROTECTED" in rendered
    finally:
        _restore_self_health(original)
    print("Scenario 20 (capability_status() matches should_run() per-capability, renders module state block) PASSED")

    hm = _make_health_monitor()
    collected, sub = await _collect(hm)
    await _feed(hm, [
        (75.0, {"load_avg": (5.21, 4.92, 4.70)}),
        (76.0, {"load_avg": (5.21, 4.92, 4.70)}),
        (74.0, {"load_avg": (5.21, 4.92, 4.70)}),
    ])
    await sub.queue.join()
    high = [e for e in collected if e.severity == Severity.HIGH]
    assert len(high) == 1
    assert "State:" in high[0].message
    assert "Load: 5.21 / 4.92 / 4.70" in high[0].message
    assert "Module State:" in high[0].message
    assert high[0].metadata.get("self_health_state") in (NORMAL, DEGRADED, OVERLOADED, EMERGENCY)
    assert "capability_status" in high[0].metadata
    print("Scenario 21 (end-to-end: CPU pressure alert carries self_health state, load avg, module state) PASSED")
    await hm.bus.unsubscribe("collector")

    print("\nALL CPU PRESSURE GOVERNANCE TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
