from __future__ import annotations

import asyncio
import logging
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.scheduler import ScannerPriority, SchedulerRegistry, run_periodic


class _CapturingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


async def main() -> None:
    SchedulerRegistry.reset_for_tests()
    test_logger = logging.getLogger("rtsa.test_scheduler_log_volume")
    test_logger.propagate = False
    handler = _CapturingHandler()
    handler.setLevel(logging.DEBUG)
    test_logger.addHandler(handler)

    test_logger.setLevel(logging.DEBUG)
    stop = asyncio.Event()
    cycle_count = {"n": 0}

    async def fast_cycle() -> None:
        cycle_count["n"] += 1
        if cycle_count["n"] >= 5:
            stop.set()

    await run_periodic(
        "routine_scanner", fast_cycle, interval_seconds=0.01,
        priority=ScannerPriority.LOW, stopping=stop, scan_logger=test_logger,
    )

    scheduler_records = [r for r in handler.records if r.name == "rtsa.test_scheduler_log_volume"]
    assert len(scheduler_records) >= 4, f"expected one record per completed cycle, got {len(scheduler_records)}"
    assert all(r.levelno == logging.DEBUG for r in scheduler_records), (
        f"a routine on-time cycle must log at DEBUG -- got levels "
        f"{[r.levelname for r in scheduler_records]}"
    )
    print("Test 1a (routine on-time scheduler cycles log at DEBUG) PASSED")

    handler.records.clear()
    test_logger.setLevel(logging.INFO)
    SchedulerRegistry.reset_for_tests()
    stop1b = asyncio.Event()
    cycle_count_1b = {"n": 0}

    async def fast_cycle_1b() -> None:
        cycle_count_1b["n"] += 1
        if cycle_count_1b["n"] >= 5:
            stop1b.set()

    await run_periodic(
        "routine_scanner_1b", fast_cycle_1b, interval_seconds=0.01,
        priority=ScannerPriority.LOW, stopping=stop1b, scan_logger=test_logger,
    )
    records_at_info_level = [r for r in handler.records if r.name == "rtsa.test_scheduler_log_volume"]
    assert records_at_info_level == [], (
        "at the production default level=INFO, a routine scheduler completion line must "
        "never actually be emitted -- this is the fix for the observed log-volume/CPU issue"
    )
    print(
        "Test 1b (at the production default level=INFO, routine scheduler cycles are silent "
        "-- eliminating the per-cycle log/format/write cost for every successful cycle of "
        "every periodic module) PASSED"
    )
    test_logger.setLevel(logging.DEBUG)

    handler.records.clear()
    stop2 = asyncio.Event()
    slow_count = {"n": 0}

    async def slow_cycle() -> None:
        slow_count["n"] += 1
        await asyncio.sleep(0.05)
        if slow_count["n"] >= 1:
            stop2.set()

    await run_periodic(
        "slow_scanner", slow_cycle, interval_seconds=0.01,
        priority=ScannerPriority.LOW, stopping=stop2, scan_logger=test_logger,
    )
    slow_records = [r for r in handler.records if r.name == "rtsa.test_scheduler_log_volume"]
    assert len(slow_records) >= 1
    assert slow_records[0].levelno == logging.INFO, (
        f"a cycle that ran longer than its own interval must log at INFO, not be silently "
        f"downgraded to DEBUG -- got {slow_records[0].levelname}"
    )
    assert "longer than its own interval" in slow_records[0].getMessage()
    print("Test 2 (a cycle running longer than its own configured interval still logs at INFO -- not silenced) PASSED")

    import inspect
    import core.scheduler as scheduler_module
    source = inspect.getsource(scheduler_module._execute_one_cycle)
    assert 'log.warning("[scheduler] %s: cycle melewati timeout' in source
    assert 'log.exception("[scheduler] %s: cycle gagal", name)' in source
    print("Test 3 (timeout/exception logging in _execute_one_cycle is untouched -- WARNING/ERROR visibility preserved) PASSED")

    snapshot = SchedulerRegistry.snapshot()
    assert "routine_scanner_1b" in snapshot and "slow_scanner" in snapshot
    assert snapshot["routine_scanner_1b"]["cycle_count"] >= 4
    assert snapshot["slow_scanner"]["last_duration"] is not None and snapshot["slow_scanner"]["last_duration"] >= 0.05
    print(
        "Test 4 (SchedulerRegistry -- already consumed by core/spike_diagnostics.py -- still "
        "records full per-cycle detail in memory regardless of log level; no operational "
        "visibility was lost, only the redundant duplicate log line) PASSED"
    )

    print("\nALL SCHEDULER LOG VOLUME TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
