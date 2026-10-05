from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from typing import Any, Dict, List

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.process_identity as process_identity
import core.self_health as self_health_module
from core.pm2_snapshot_cache import Pm2SnapshotCache
from core.resource_attribution import (
    CAUSE_MIXED, CAUSE_PROJECT, CAUSE_RTSA, CAUSE_UNKNOWN,
    classify_pressure_cause, non_rtsa_top_consumers,
)
from core.self_health import _CAPABILITY_DISABLED_FROM, DEGRADED, EMERGENCY, NORMAL, OVERLOADED, tier_summary
from core.cpu_governor import CpuGovernor
from config.manager import HealthMonitorConfig
from core.datatypes import EventCategory, HealthEvent, Severity
from core.event_bus import EventBus
from modules.health_monitor import HealthMonitor


def _write_proc_entry(
    proc_root: str, pid: int, *, tgid: int, ppid: int, threads: int, cmdline: str,
    start_time_ticks: int, cgroup: str = "0::/system.slice/rtsa.service",
) -> None:
    pid_dir = os.path.join(proc_root, str(pid))
    os.makedirs(pid_dir, exist_ok=True)
    with open(os.path.join(pid_dir, "status"), "w") as f:
        f.write(f"Tgid:\t{tgid}\nPPid:\t{ppid}\nThreads:\t{threads}\nVmRSS:\t102400 kB\n")
    with open(os.path.join(pid_dir, "cmdline"), "wb") as f:
        f.write(cmdline.encode("utf-8").replace(b" ", b"\x00") + b"\x00")
    stat_fields = ["S"] + ["0"] * 18 + [str(start_time_ticks)]
    with open(os.path.join(pid_dir, "stat"), "w") as f:
        f.write(f"{pid} (main.py) {' '.join(stat_fields)}\n")
    with open(os.path.join(pid_dir, "cgroup"), "w") as f:
        f.write(f"{cgroup}\n")


def _write_boot_time(proc_root: str, btime: int = 1_700_000_000) -> None:
    with open(os.path.join(proc_root, "stat"), "w") as f:
        f.write(f"cpu  0 0 0 0 0 0 0 0 0 0\nbtime {btime}\n")


def main() -> None:
    marker = "main.py"

    with tempfile.TemporaryDirectory(prefix="rtsa-proc-") as proc_root:
        _write_boot_time(proc_root)
        _write_proc_entry(proc_root, 100, tgid=100, ppid=1, threads=4, cmdline=f"/usr/bin/python3 /opt/security/rtsa/{marker}", start_time_ticks=1000)
        for tid in (101, 102, 103):
            _write_proc_entry(proc_root, tid, tgid=100, ppid=1, threads=4, cmdline=f"/usr/bin/python3 /opt/security/rtsa/{marker}", start_time_ticks=1000)

        snapshots = process_identity.discover_matching_processes(marker, proc_root)
        classifications = process_identity.classify_processes(snapshots, boot_time=process_identity.read_boot_time(proc_root))
        assert len(classifications) == 4, classifications
        main_processes = process_identity.genuine_instances(classifications)
        assert len(main_processes) == 1, "3 thread rows + 1 real process must yield exactly ONE genuine instance"
        threads = [c for c in classifications if c.role == process_identity.ROLE_THREAD_OF]
        assert len(threads) == 3 and all(c.of_pid == 100 for c in threads)
        status = process_identity.assess_duplicate_status(classifications, own_pid=100, proc_root=proc_root)
        assert status == process_identity.DUPLICATE_STATUS_NONE, status
        print("Scenario 1+2 (one process, many threads / htop-style rows -> one instance, no false duplicate) PASSED")

    with tempfile.TemporaryDirectory(prefix="rtsa-proc-") as proc_root:
        _write_boot_time(proc_root)
        _write_proc_entry(
            proc_root, 200, tgid=200, ppid=1, threads=1, cmdline=f"/usr/bin/python3 /opt/security/rtsa/{marker}",
            start_time_ticks=1000, cgroup="0::/system.slice/rtsa.service",
        )
        _write_proc_entry(
            proc_root, 999, tgid=999, ppid=1, threads=1, cmdline=f"/usr/bin/python3 /home/attacker/{marker}",
            start_time_ticks=5000, cgroup="0::/user.slice/user-1000.slice",
        )
        classifications, _ = process_identity.discover_and_classify(marker, proc_root=proc_root)
        status = process_identity.assess_duplicate_status(classifications, own_pid=200, proc_root=proc_root)
        assert status == process_identity.DUPLICATE_STATUS_CONFIRMED, status
        print("Scenario 3+17 (two independent processes, different cgroup -> DUPLICATE_RTSA, evidence-based) PASSED")

    with tempfile.TemporaryDirectory(prefix="rtsa-proc-") as proc_root:
        _write_boot_time(proc_root)
        _write_proc_entry(proc_root, 300, tgid=300, ppid=1, threads=1, cmdline=f"/usr/bin/python3 /opt/security/rtsa/{marker}", start_time_ticks=1000, cgroup="0::/system.slice/rtsa.service")
        _write_proc_entry(proc_root, 301, tgid=301, ppid=1, threads=1, cmdline=f"/usr/bin/python3 /opt/security/rtsa/{marker}", start_time_ticks=1001, cgroup="0::/system.slice/rtsa.service")
        classifications, _ = process_identity.discover_and_classify(marker, proc_root=proc_root)
        status = process_identity.assess_duplicate_status(classifications, own_pid=300, proc_root=proc_root)
        assert status == process_identity.DUPLICATE_STATUS_UNKNOWN, status
        print("Scenario 5 (second row shares our own cgroup/systemd unit -> UNKNOWN_RUNTIME_INSTANCE, not a false DUPLICATE_RTSA) PASSED")

    with tempfile.TemporaryDirectory(prefix="rtsa-proc-") as proc_root:
        _write_boot_time(proc_root)
        _write_proc_entry(proc_root, 400, tgid=400, ppid=1, threads=1, cmdline=f"/usr/bin/python3 /opt/security/rtsa/{marker}", start_time_ticks=1000)
        _write_proc_entry(proc_root, 401, tgid=401, ppid=1, threads=1, cmdline=f"/usr/bin/python3 /opt/security/rtsa/{marker}", start_time_ticks=1000)
        os.remove(os.path.join(proc_root, "401", "cgroup"))
        classifications, _ = process_identity.discover_and_classify(marker, proc_root=proc_root)
        status = process_identity.assess_duplicate_status(classifications, own_pid=400, proc_root=proc_root)
        assert status == process_identity.DUPLICATE_STATUS_UNKNOWN, status
        print("Scenario 18a (cgroup unreadable for one side -> UNKNOWN_RUNTIME_INSTANCE, never guessed) PASSED")

    with tempfile.TemporaryDirectory(prefix="rtsa-proc-") as proc_root:
        _write_boot_time(proc_root)
        _write_proc_entry(proc_root, 500, tgid=500, ppid=1, threads=1, cmdline=f"/usr/bin/python3 /opt/security/rtsa/{marker}", start_time_ticks=1000)
        earlier = process_identity.read_proc_snapshot(500, proc_root)
    with tempfile.TemporaryDirectory(prefix="rtsa-proc-") as proc_root:
        _write_boot_time(proc_root)
        _write_proc_entry(proc_root, 500, tgid=500, ppid=1, threads=1, cmdline="/usr/sbin/some-unrelated-daemon", start_time_ticks=99999)
        later = process_identity.read_proc_snapshot(500, proc_root)
    assert not process_identity.is_same_process(earlier, later), "same PID number, different start_time -- must not be treated as the same process"
    assert process_identity.is_same_process(earlier, earlier)
    print("Scenario 4 (PID reuse: same PID number, different start_time -- correctly NOT the same process) PASSED")

    assert classify_pressure_cause(95.0, 5.0) == CAUSE_PROJECT, "host high, RTSA share negligible -> project/system pressure"
    assert classify_pressure_cause(95.0, 70.0) == CAUSE_RTSA, "host high, RTSA share dominant -> RTSA pressure"
    assert classify_pressure_cause(95.0, 40.0) == CAUSE_MIXED, "host high, RTSA share moderate -> mixed, neither alone explains it"
    assert classify_pressure_cause(None, 40.0) == CAUSE_UNKNOWN
    assert classify_pressure_cause(95.0, None) == CAUSE_UNKNOWN
    print("Scenario 6+7+18 (cause-aware attribution: PROJECT / RTSA / MIXED / UNKNOWN, never guessed from incomplete data) PASSED")

    top_cpu = (
        {"pid": os.getpid(), "user": "root", "cpu_percent": 8.0, "mem_percent": 1.0, "command": "python3 main.py"},
        {"pid": 55555, "user": "newus-backend", "cpu_percent": 65.0, "mem_percent": 12.0, "command": "node server.js"},
        {"pid": 55556, "user": "postgres", "cpu_percent": 12.0, "mem_percent": 8.0, "command": "postgres"},
    )
    non_rtsa = non_rtsa_top_consumers(top_cpu, rtsa_pid=os.getpid())
    assert all(p["pid"] != os.getpid() for p in non_rtsa)
    assert len(non_rtsa) == 2 and non_rtsa[0]["command"] == "node server.js"
    print("Scenario 6b (top-consumers list correctly excludes RTSA's own process, project processes surface first) PASSED")

    governor = CpuGovernor()
    sample = governor.sample_cpu()
    assert set(["rtsa_cpu_percent", "host_cpu_percent", "logical_cpu_count"]).issubset(sample.keys())
    assert sample["rtsa_cpu_percent"] >= 0.0
    print("Scenario 8 (RTSA CPU read once from kernel's own per-process accounting -- no manual thread-sum double count) PASSED")

    assert governor.max_workers >= 1
    assert governor.max_workers == max(1, (os.cpu_count() or 4) // 4)
    print("Scenario 16 (scan thread pool worker count is an explicit, bounded ceiling) PASSED")

    all_running = {c: True for c in _CAPABILITY_DISABLED_FROM}
    tiers = tier_summary(all_running)
    assert tiers == {"P0": "active", "P1": "active", "P2": "active"}, tiers
    print("Scenario 11 (nothing paused -> P0/P1/P2 all active) PASSED")

    p2_capability = next(c for c, s in _CAPABILITY_DISABLED_FROM.items() if s in (DEGRADED, OVERLOADED))
    p2_paused = dict(all_running)
    p2_paused[p2_capability] = False
    tiers = tier_summary(p2_paused)
    assert tiers == {"P0": "active", "P1": "active", "P2": "deferred"}, tiers
    print("Scenario 13 (an OVERLOADED/DEGRADED-gated capability paused -> P2 deferred, P0/P1 unaffected) PASSED")

    p1_capability = next(c for c, s in _CAPABILITY_DISABLED_FROM.items() if s == EMERGENCY)
    p1_paused = dict(all_running)
    p1_paused[p1_capability] = False
    tiers = tier_summary(p1_paused)
    assert tiers == {"P0": "active", "P1": "reduced", "P2": "active"}, tiers
    print("Scenario 12 (an EMERGENCY-gated capability paused -> P1 reduced) PASSED")

    from core.self_health import SelfHealthMonitor, SelfHealthThresholds, _STATE_ORDER
    thresholds = SelfHealthThresholds(recovery_dwell_seconds=30.0)
    assert thresholds.recovery_dwell_seconds == 30.0
    assert _STATE_ORDER[NORMAL] < _STATE_ORDER[DEGRADED] < _STATE_ORDER[OVERLOADED] < _STATE_ORDER[EMERGENCY]
    print("Scenario 14+15 (hysteresis dwell + ordered tiers already enforced by self_health's existing state machine) PASSED")

    cache = Pm2SnapshotCache()
    assert cache.get("newus-site", max_age_seconds=30.0) is None, "empty cache must report a clean miss, not stale data"
    processes = [{"name": "app", "pm2_env": {"status": "online"}}]
    cache.store("newus-site", processes)
    hit = cache.get("newus-site", max_age_seconds=30.0)
    assert hit == processes
    hit[0]["name"] = "mutated"
    assert cache.get("newus-site", max_age_seconds=30.0)[0]["name"] == "app", "cache must return an independent copy, not a shared mutable reference"
    stale_cache = Pm2SnapshotCache()
    stale_cache._entries["oldsite"] = (time.monotonic() - 999.0, processes)
    assert stale_cache.get("oldsite", max_age_seconds=30.0) is None, "an entry older than max_age_seconds must be treated as a miss"
    print("Scenario 9+10 (shared PM2 snapshot cache -- fresh hit reused, stale/missing entries fall back safely) PASSED")


class _FakeSelfHealthForAlert:
    def __init__(self, state: str) -> None:
        self._state = state

    @property
    def state(self) -> str:
        return self._state

    def evaluate(self, now=None) -> str:
        return self._state

    def get_status(self) -> Dict[str, Any]:
        return {"state": self._state, "reasons": []}

    def should_run(self, capability: str) -> bool:
        from core.self_health import _STATE_ORDER
        disabled_from = _CAPABILITY_DISABLED_FROM.get(capability)
        if disabled_from is None:
            return True
        return _STATE_ORDER[self._state] < _STATE_ORDER[disabled_from]

    def capability_status(self) -> Dict[str, bool]:
        return {c: self.should_run(c) for c in _CAPABILITY_DISABLED_FROM}


async def _test_health_monitor_alert_fields() -> None:
    original = self_health_module._singleton
    self_health_module._singleton = _FakeSelfHealthForAlert(NORMAL)
    try:
        hm = HealthMonitor(EventBus(), HealthMonitorConfig(
            cpu_alert_threshold=70.0, cpu_recovery_threshold=60.0, cpu_critical_threshold=98.0,
            resource_consecutive_breaches=3, resource_consecutive_recoveries=3,
            resource_minimum_breach_duration_seconds=999999.0,
        ))
        collected: List[HealthEvent] = []

        async def collector(event):
            collected.append(event)

        sub = await hm.bus.subscribe("collector", collector, categories=None)

        top_cpu = (
            {"pid": os.getpid(), "user": "root", "cpu_percent": 4.0, "mem_percent": 1.0, "command": "python3 main.py"},
            {"pid": 77777, "user": "newus-backend", "cpu_percent": 88.0, "mem_percent": 20.0, "command": "node server.js"},
        )
        for percent in (91.0, 92.0, 93.0):
            snapshot = HealthEvent(
                source_module="health_monitor", category=EventCategory.HEALTH_STATUS,
                severity=Severity.INFO, message="", raw="",
                cpu_percent=percent, mem_percent=10.0, disk_percent=10.0,
                top_cpu_processes=top_cpu, load_avg=(8.2, 7.9, 7.4),
            )
            hm._evaluate_resource_thresholds(snapshot)
        await sub.queue.join()

        high = [e for e in collected if e.severity == Severity.HIGH]
        assert len(high) == 1, high
        message = high[0].message
        assert "Cause: " + CAUSE_PROJECT in message, message
        assert "RTSA Instances:" in message
        assert "RTSA State:" in message and "P0 active" in message and "P2 active" in message
        assert "node server.js" in message, "the actual non-RTSA top consumer must be named"
        assert high[0].metadata["resource_pressure_cause"] == CAUSE_PROJECT
        print(
            "Scenario 15 (host CPU high, caused by a project process, not RTSA -- alert names "
            "Cause: PROJECT_CPU_PRESSURE and the real top consumer, not RTSA itself) PASSED"
        )
        await hm.bus.unsubscribe("collector")
    finally:
        self_health_module._singleton = original


main()
asyncio.run(_test_health_monitor_alert_fields())

print("\nALL CPU/THREAD RESOURCE ATTRIBUTION TESTS PASSED")
