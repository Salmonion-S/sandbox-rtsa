import asyncio
import dataclasses
import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import pwd

import modules.pm2_monitor as pm2_module
from config.manager import (
    ConfigManager, ConfigValidationError, Pm2MonitorConfig, Pm2UserConfig,
    RTSAConfig, SvgUploadScannerConfig,
)
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from modules.pm2_monitor import Pm2Monitor


class _FakeProc:
    def __init__(self, returncode: int = 0, stdout: bytes = b"[]"):
        self.returncode = returncode
        self._stdout = stdout

    async def communicate(self):
        return self._stdout, b""

    def kill(self):
        pass

    async def wait(self):
        return None


class _ConcurrencyTracker:
    def __init__(self, delay: float = 0.05):
        self.current = 0
        self.peak = 0
        self.total = 0
        self.delay = delay
        self.lock = asyncio.Lock()

    async def run(self, *args, **kwargs):
        async with self.lock:
            self.current += 1
            self.total += 1
            self.peak = max(self.peak, self.current)
        await asyncio.sleep(self.delay)
        async with self.lock:
            self.current -= 1
        return _FakeProc()


class _FakeHealthMonitor:
    def __init__(self, state: str = "NORMAL"):
        self.state = state

    def should_run(self, capability: str) -> bool:
        return self.state not in ("OVERLOADED", "EMERGENCY")


def _fake_account(user: str):
    class _Acct:
        pw_uid = 1000
        pw_gid = 1000
        pw_dir = f"/home/{user}"
        pw_shell = "/bin/bash"
    return _Acct()


def _patch_pm2_env(state: str = "NORMAL"):
    original_daemon_alive = pm2_module.pm2_daemon_alive
    original_health = pm2_module.get_self_health_monitor
    original_getpwnam = pwd.getpwnam
    original_getgrouplist = os.getgrouplist

    pm2_module.pm2_daemon_alive = lambda pm2_home: True
    pm2_module.get_self_health_monitor = lambda: _FakeHealthMonitor(state=state)
    pm2_module.pwd.getpwnam = _fake_account
    os.getgrouplist = lambda user, gid: [gid]

    def restore():
        pm2_module.pm2_daemon_alive = original_daemon_alive
        pm2_module.get_self_health_monitor = original_health
        pm2_module.pwd.getpwnam = original_getpwnam
        os.getgrouplist = original_getgrouplist

    return restore


def _make_users(n: int):
    return [Pm2UserConfig(user=f"testu{i:03d}") for i in range(n)]


async def test_1_concurrency_bound_respected() -> None:
    restore = _patch_pm2_env()
    tracker = _ConcurrencyTracker(delay=0.05)
    original_create = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = tracker.run
    try:
        cfg = Pm2MonitorConfig(enabled=True, users=_make_users(40), max_concurrent_queries=3)
        mon = Pm2Monitor(EventBus(), cfg)
        await mon._poll_once()
        assert tracker.peak <= 3, f"peak simultaneous jlist={tracker.peak} exceeded configured max_concurrent_queries=3"
        assert tracker.total == 40, f"expected all 40 users queried exactly once, got {tracker.total}"
    finally:
        asyncio.create_subprocess_exec = original_create
        restore()
    print(f"Test 1 (max concurrent jlist bounded to configured max_concurrent_queries, peak={tracker.peak}) PASSED")


async def test_2_degraded_reduces_concurrency() -> None:
    restore = _patch_pm2_env(state="DEGRADED")
    tracker = _ConcurrencyTracker(delay=0.05)
    original_create = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = tracker.run
    try:
        cfg = Pm2MonitorConfig(
            enabled=True, users=_make_users(20), max_concurrent_queries=5, degraded_max_concurrent_queries=1,
        )
        mon = Pm2Monitor(EventBus(), cfg)
        assert mon._effective_concurrency() == 1
        await mon._poll_once()
        assert tracker.peak == 1, f"DEGRADED must serialize to degraded_max_concurrent_queries=1, got peak={tracker.peak}"
    finally:
        asyncio.create_subprocess_exec = original_create
        restore()
    print("Test 2 (DEGRADED state scales concurrency down to degraded_max_concurrent_queries) PASSED")


async def test_3_overloaded_pauses_routine_poll() -> None:
    restore = _patch_pm2_env(state="OVERLOADED")
    tracker = _ConcurrencyTracker(delay=0.01)
    original_create = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = tracker.run
    try:
        cfg = Pm2MonitorConfig(enabled=True, users=_make_users(10), max_concurrent_queries=5)
        mon = Pm2Monitor(EventBus(), cfg)
        await mon._poll_once()
        assert tracker.total == 0, "OVERLOADED must fully pause routine PM2 jlist polling -- zero invocations expected"
        assert mon._pm2_poll_suppressed_overload_total == 1
    finally:
        asyncio.create_subprocess_exec = original_create
        restore()
    print("Test 3 (OVERLOADED pauses routine PM2 polling entirely, pm2_poll_suppressed_overload_total increments) PASSED")


async def test_4_single_flight_guard() -> None:
    restore = _patch_pm2_env()
    tracker = _ConcurrencyTracker(delay=0.3)
    original_create = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = tracker.run
    try:
        cfg = Pm2MonitorConfig(enabled=True, users=_make_users(15), max_concurrent_queries=3)
        mon = Pm2Monitor(EventBus(), cfg)
        task1 = asyncio.create_task(mon._poll_once())
        await asyncio.sleep(0.05)
        assert mon._scan_in_progress is True
        await mon._poll_once()
        await task1
        assert mon._pm2_scan_skipped_overlap_total >= 1, (
            "a second _poll_once() call while the first cycle is still in-flight must be skipped, "
            "never run concurrently with the first (single-flight guarantee)"
        )
        assert mon._pm2_scan_cycles_total == 1, "only the first (non-overlapping) cycle should have actually run"
    finally:
        asyncio.create_subprocess_exec = original_create
        restore()
    print(
        f"Test 4 (single-flight guard: overlapping _poll_once() skipped, "
        f"scan_skipped_overlap_total={mon._pm2_scan_skipped_overlap_total}) PASSED"
    )


async def test_5_discovery_dedup_cache_hits() -> None:
    restore = _patch_pm2_env()
    tracker = _ConcurrencyTracker(delay=0.01)
    original_create = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = tracker.run
    original_discover = pm2_module.discover_cloudpanel_candidates
    pm2_module.discover_cloudpanel_candidates = lambda home_root="/home": ["testu000", "testu001"]
    try:
        cfg = Pm2MonitorConfig(enabled=True, auto_discover_cloudpanel=True, discovery_refresh_seconds=600.0)
        mon = Pm2Monitor(EventBus(), cfg)

        await mon._poll_once()
        assert set(mon._discovered_users) == {"testu000", "testu001"}
        assert mon._pm2_cache_misses_total == 2, "brand-new candidates must always be validated via a real jlist call"
        assert mon._pm2_cache_hits_total == 0

        mon._last_discovery_monotonic = None
        await mon._poll_once()

        assert mon._pm2_cache_hits_total >= 2, (
            "candidates already discovered and recently polled by the routine poll cycle must be "
            "reused (cache hit) instead of re-validated with a second, redundant 'pm2 jlist' call"
        )
        assert mon._pm2_cache_misses_total == 2, (
            "cache misses must not grow further once both candidates are already known-good and "
            "recently polled -- the second discovery refresh must reuse them, not re-query jlist"
        )
    finally:
        asyncio.create_subprocess_exec = original_create
        pm2_module.discover_cloudpanel_candidates = original_discover
        restore()
    print(
        f"Test 5 (discovery revalidation reuses recently-polled users instead of re-querying jlist, "
        f"cache_hits={mon._pm2_cache_hits_total} cache_misses={mon._pm2_cache_misses_total}) PASSED"
    )


async def test_6_metrics_exposed_in_health() -> None:
    restore = _patch_pm2_env()
    tracker = _ConcurrencyTracker(delay=0.01)
    original_create = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = tracker.run
    try:
        cfg = Pm2MonitorConfig(enabled=True, users=_make_users(5), max_concurrent_queries=3)
        mon = Pm2Monitor(EventBus(), cfg)
        await mon._poll_once()
        health = await mon.health()
        expected_keys = [
            "pm2_queries_total", "pm2_queries_completed_total", "pm2_queries_inflight",
            "pm2_query_failures_total", "pm2_skipped_no_daemon_total", "pm2_scan_cycles_total",
            "pm2_scan_skipped_overlap_total", "pm2_scan_duration_seconds_last",
            "pm2_poll_suppressed_overload_total", "pm2_cache_hits_total", "pm2_cache_misses_total",
            "pm2_max_concurrent_queries",
        ]
        for key in expected_keys:
            assert key in health, f"health() output missing mandated metric key: {key}"
        assert health["pm2_queries_total"] == 5
        assert health["pm2_queries_completed_total"] == 5
        assert health["pm2_queries_inflight"] == 0
        assert health["pm2_scan_cycles_total"] == 1
        assert health["pm2_max_concurrent_queries"] == 3
    finally:
        asyncio.create_subprocess_exec = original_create
        restore()
    print("Test 6 (all mandated PM2 metrics present and correct in health() output) PASSED")


async def test_7_security_detection_preserved_under_bounded_concurrency() -> None:
    restore = _patch_pm2_env()
    published = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        return _FakeProc(returncode=0, stdout=b'[{"name": "webapp", "pm2_env": {"status": "stopped"}}]')

    original_create = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = fake_create_subprocess_exec
    try:
        cfg = Pm2MonitorConfig(enabled=True, users=_make_users(1), max_concurrent_queries=1)
        mon = Pm2Monitor(EventBus(), cfg)
        mon.publish = lambda event: published.append(event)
        await mon._poll_once()
        assert len(published) == 1, "SERVICE_DOWN detection must still publish under a reduced/bounded concurrency limit"
        assert published[0].category == EventCategory.SERVICE_DOWN
        assert published[0].severity == Severity.HIGH
    finally:
        asyncio.create_subprocess_exec = original_create
        restore()
    print("Test 7 (SERVICE_DOWN security detection still fires correctly under bounded concurrency) PASSED")


def test_8_config_validation_rejects_out_of_range() -> None:
    base = dataclasses.replace(
        RTSAConfig(),
        discord=dataclasses.replace(RTSAConfig().discord, enabled=False),
        modules=dataclasses.replace(
            RTSAConfig().modules,
            nginx_monitor=dataclasses.replace(
                RTSAConfig().modules.nginx_monitor,
                svg_upload_scanner=SvgUploadScannerConfig(enabled=False),
            ),
        ),
    )

    def _with_pm2(max_q: int, degraded_q: int) -> RTSAConfig:
        new_pm2 = Pm2MonitorConfig(
            enabled=True, max_concurrent_queries=max_q, degraded_max_concurrent_queries=degraded_q,
        )
        new_modules = dataclasses.replace(base.modules, pm2_monitor=new_pm2)
        return dataclasses.replace(base, modules=new_modules)

    def _raises(max_q: int, degraded_q: int) -> bool:
        try:
            ConfigManager._validate_semantics(_with_pm2(max_q, degraded_q))
            return False
        except ConfigValidationError:
            return True

    assert _raises(0, 1), "max_concurrent_queries=0 must be rejected by config validation"
    assert _raises(33, 1), "max_concurrent_queries=33 (above the 32 hard cap) must be rejected"
    assert _raises(3, 5), "degraded_max_concurrent_queries greater than max_concurrent_queries must be rejected"
    assert not _raises(3, 1), "max_concurrent_queries=3 degraded_max_concurrent_queries=1 is valid and must pass"
    print("Test 8 (config validation enforces max_concurrent_queries/degraded_max_concurrent_queries bounds) PASSED")


async def main() -> None:
    await test_1_concurrency_bound_respected()
    await test_2_degraded_reduces_concurrency()
    await test_3_overloaded_pauses_routine_poll()
    await test_4_single_flight_guard()
    await test_5_discovery_dedup_cache_hits()
    await test_6_metrics_exposed_in_health()
    await test_7_security_detection_preserved_under_bounded_concurrency()
    test_8_config_validation_rejects_out_of_range()
    print("\nALL PM2 CONCURRENCY GOVERNANCE TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
