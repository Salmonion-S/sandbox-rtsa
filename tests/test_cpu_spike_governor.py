import asyncio
import os
import resource
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiagnosticsConfig, ResourceGovernorConfig
from core.cpu_governor import (
    COST_HEAVY, COST_LIGHT, COST_MEDIUM, configure_cpu_governor, get_cpu_governor,
    run_cpu_bound, scan_slot,
)
from core.file_identity import hash_file
from core.spike_diagnostics import configure_spike_diagnostics, get_spike_diagnostics

_HASH_FILE_COUNT = 24
_HASH_FILE_BYTES = 2_000_000


def cpu_seconds():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime


async def measure(factory):
    start_cpu, start_wall = cpu_seconds(), time.monotonic()
    await factory()
    wall = max(time.monotonic() - start_wall, 1e-9)
    used = cpu_seconds() - start_cpu
    return used / wall * 100.0, used, wall


def make_corpus(directory):
    paths = []
    for index in range(_HASH_FILE_COUNT):
        path = os.path.join(directory, f"blob{index}.bin")
        with open(path, "wb") as handle:
            handle.write(os.urandom(_HASH_FILE_BYTES))
        paths.append(path)
    return paths


async def hash_unbounded(paths, tasks):
    loop = asyncio.get_running_loop()

    async def worker(subset):
        for path in subset:
            await loop.run_in_executor(None, hash_file, path)

    await asyncio.gather(*(worker(paths[i::tasks]) for i in range(tasks)))


async def hash_governed(paths, tasks):
    async def worker(subset):
        for path in subset:
            await run_cpu_bound(hash_file, path, cost=COST_MEDIUM)

    await asyncio.gather(*(worker(paths[i::tasks]) for i in range(tasks)))


async def main() -> None:
    configure_cpu_governor(ResourceGovernorConfig())
    configure_spike_diagnostics(DiagnosticsConfig())
    governor = get_cpu_governor()
    governor.reset_for_tests()

    default_pool = min(32, (os.cpu_count() or 1) + 4)
    assert governor.max_workers < default_pool, (
        f"the governed scan pool ({governor.max_workers}) must be smaller than the interpreter "
        f"default executor ({default_pool}); the default pool is what allowed RTSA to burn several "
        f"cores at once"
    )
    assert governor.max_workers >= 1
    print(
        f"Test 1 [POOL BOUND] (cpu_count={os.cpu_count()}: the shared default executor would give "
        f"{default_pool} threads for scan work, the governed pool gives {governor.max_workers} -- "
        f"this is the hard ceiling on cores RTSA can burn in parallel) PASSED"
    )

    with tempfile.TemporaryDirectory(prefix="rtsa-cpu-test-") as workdir:
        paths = make_corpus(workdir)

        serial_pct, serial_cpu, _wall = await measure(lambda: hash_unbounded(paths, 1))
        unbounded_pct, unbounded_cpu, _w = await measure(lambda: hash_unbounded(paths, 4))
        assert unbounded_pct > 150.0, (
            f"REPRODUCTION FAILED: hashing through the default executor from 4 concurrent module "
            f"tasks should exceed 150% CPU because hashlib releases the GIL, measured "
            f"{unbounded_pct:.1f}%. Without this the rest of the suite proves nothing."
        )
        print(
            f"Test 2 [SPIKE REPRODUCED] (identical work, real hash_file, default executor: "
            f"1 task = {serial_pct:.1f}% CPU, 4 concurrent module tasks = {unbounded_pct:.1f}% CPU. "
            f"An asyncio loop is single threaded and cannot exceed 100%; everything above comes "
            f"from executor threads running GIL-releasing work in parallel) PASSED"
        )

        governed_4_pct, governed_4_cpu, _w = await measure(lambda: hash_governed(paths, 4))
        governed_8_pct, governed_8_cpu, _w = await measure(lambda: hash_governed(paths, 8))
        ceiling = governor.max_workers * 100.0 + 60.0
        assert governed_4_pct < unbounded_pct, (
            f"the governed pool must reduce peak CPU: unbounded {unbounded_pct:.1f}% vs governed "
            f"{governed_4_pct:.1f}%"
        )
        assert governed_4_pct <= ceiling and governed_8_pct <= ceiling, (
            f"governed CPU must stay within {ceiling:.0f}% ({governor.max_workers} worker(s) plus "
            f"loop overhead), measured 4-task={governed_4_pct:.1f}% 8-task={governed_8_pct:.1f}%"
        )
        assert abs(governed_8_pct - governed_4_pct) < 60.0, (
            f"governed CPU must stop scaling with the number of concurrent modules, measured "
            f"4-task={governed_4_pct:.1f}% vs 8-task={governed_8_pct:.1f}%"
        )
        print(
            f"Test 3 [SPIKE BOUNDED] (same work through the governed pool: 4 tasks = "
            f"{governed_4_pct:.1f}% CPU, 8 tasks = {governed_8_pct:.1f}% -- flat instead of "
            f"scaling with module count, down from {unbounded_pct:.1f}%) PASSED"
        )

        assert abs(governed_4_cpu - unbounded_cpu) < unbounded_cpu * 0.5, (
            f"the governor must reduce parallelism, not work: unbounded used {unbounded_cpu:.2f}s "
            f"of CPU, governed used {governed_4_cpu:.2f}s. A large drop would mean files were "
            f"skipped, which would be a detection regression rather than an optimisation."
        )
        print(
            f"Test 4 [NO WORK DROPPED] (unbounded consumed {unbounded_cpu:.2f}s CPU, governed "
            f"{governed_4_cpu:.2f}s for the same {len(paths)} files -- every file is still hashed, "
            f"only the parallelism changed) PASSED"
        )

    governor.reset_for_tests()
    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    entered = []

    async def cycle(name, hold):
        async with scan_slot(name, COST_MEDIUM) as slot:
            if not slot.admitted:
                return "skipped"
            entered.append(name)
            await asyncio.sleep(hold)
            return "ran"

    results = await asyncio.gather(
        cycle("overlap_probe", 0.15),
        cycle("overlap_probe", 0.15),
        cycle("overlap_probe", 0.15),
    )
    assert results.count("ran") == 1 and results.count("skipped") == 2, (
        f"a second cycle of the same operation must be skipped, not queued, got {results}"
    )
    stats = governor.stats_for("overlap_probe")
    assert stats.skipped_overlap_count == 2, (
        f"overlap skips must be counted for diagnostics, got {stats.skipped_overlap_count}"
    )
    assert stats.active_runs == 0, "active_runs must return to zero after the cycle finishes"
    print(
        f"Test 5 [ANTI-OVERLAP] (three concurrent cycles of one operation: 1 ran, 2 skipped and "
        f"counted as skipped_overlap_count={stats.skipped_overlap_count}, and work was never "
        f"queued so it cannot pile up behind a slow cycle) PASSED"
    )

    governor.reset_for_tests()
    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))

    async def failing_cycle():
        async with scan_slot("crash_probe", COST_MEDIUM) as slot:
            assert slot.admitted
            raise RuntimeError("simulated scan crash")

    crashed = False
    try:
        await failing_cycle()
    except RuntimeError:
        crashed = True
    crash_stats = governor.stats_for("crash_probe")
    assert crashed and crash_stats.active_runs == 0, (
        f"a cycle that raises must still release its slot, got active_runs="
        f"{crash_stats.active_runs}"
    )
    async with scan_slot("crash_probe", COST_MEDIUM) as slot:
        assert slot.admitted, "the operation must be runnable again after a crashed cycle"
    print(
        "Test 6 [CRASH SAFETY] (a cycle that raises still releases its slot and its lock, so a "
        "single failure cannot permanently latch a scanner off) PASSED"
    )

    governor.reset_for_tests()
    configure_cpu_governor(ResourceGovernorConfig(
        max_heavy_scanners_concurrent=1, heavy_scan_cooldown_seconds=0.0,
        defer_when_system_busy=False,
    ))
    heavy_peak = {"value": 0}
    heavy_now = {"value": 0}

    async def heavy(name):
        async with scan_slot(name, COST_HEAVY) as slot:
            if not slot.admitted:
                return
            heavy_now["value"] += 1
            heavy_peak["value"] = max(heavy_peak["value"], heavy_now["value"])
            await asyncio.sleep(0.05)
            heavy_now["value"] -= 1

    await asyncio.gather(*(heavy(f"heavy_{i}") for i in range(6)))
    assert heavy_peak["value"] == 1, (
        f"max_heavy_scanners_concurrent=1 must allow only one heavy scan at a time, measured peak "
        f"{heavy_peak['value']}"
    )
    print(
        f"Test 7 [HEAVY CLASS LIMIT] (6 distinct heavy scanners released together reach a measured "
        f"peak of {heavy_peak['value']} concurrent execution, matching "
        f"max_heavy_scanners_concurrent=1) PASSED"
    )

    governor.reset_for_tests()
    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    light_peak = {"value": 0}
    light_now = {"value": 0}

    async def light(name):
        async with scan_slot(name, COST_LIGHT) as slot:
            assert slot.admitted, "light work must never be blocked by the governor"
            light_now["value"] += 1
            light_peak["value"] = max(light_peak["value"], light_now["value"])
            await asyncio.sleep(0.02)
            light_now["value"] -= 1

    await asyncio.gather(*(light(f"light_{i}") for i in range(8)))
    assert light_peak["value"] == 8, (
        f"light monitoring must stay fully concurrent, measured peak {light_peak['value']}"
    )
    print(
        f"Test 8 [LIGHT NEVER STARVED] (8 light operations run fully concurrently, measured peak "
        f"{light_peak['value']} -- a monitoring tool that stops watching under load would be worse "
        f"than the spike it is avoiding) PASSED"
    )

    governor.reset_for_tests()
    configure_cpu_governor(ResourceGovernorConfig(
        rtsa_cpu_hard_limit_percent=0.001, defer_when_system_busy=True,
    ))
    governor.sample_cpu()
    async with scan_slot("busy_probe", COST_MEDIUM) as slot:
        deferred = not slot.admitted
    assert deferred, "heavy work must defer when RTSA CPU is already over the hard limit"
    assert governor.stats_for("busy_probe").deferred_busy_count == 1

    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    async with scan_slot("busy_probe", COST_MEDIUM) as slot:
        assert slot.admitted, "with deferral disabled the cycle must run normally"
    print(
        "Test 9 [CPU-AWARE DEFERRAL] (with the RTSA CPU hard limit already exceeded a medium scan "
        "defers to the next cycle and is counted, and the behaviour is switchable through "
        "resource_governor.defer_when_system_busy) PASSED"
    )

    governor.reset_for_tests()
    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    async with scan_slot("diag_probe", COST_MEDIUM) as slot:
        assert slot.admitted
        snapshot = get_spike_diagnostics().capture(123.3)
    required = {
        "rtsa_cpu_percent", "host_cpu_percent", "scan_pool_workers", "active_operations",
        "total_active_runs", "active_scanner_count", "rtsa_thread_count",
        "active_subprocess_count", "busiest_operations", "total_overlap_skips",
        "total_busy_deferrals", "scanners_slower_than_interval", "running_modules",
    }
    missing = required - set(snapshot)
    assert not missing, f"the spike snapshot is missing fields: {sorted(missing)}"
    assert "diag_probe" in snapshot["active_operations"], (
        f"the snapshot must name the operation that was actually running, got "
        f"{snapshot['active_operations']}"
    )
    assert snapshot["total_active_runs"] >= 1
    block = get_spike_diagnostics().format_block(snapshot)
    assert "RTSA CPU Spike Diagnostics" in block and "diag_probe" in block, (
        f"the rendered diagnostics block must name the running operation, got:\n{block}"
    )
    print(
        f"Test 10 [SPIKE DIAGNOSTICS] (a capture taken during a live cycle names the running "
        f"operation, {len(required)} evidence fields present, thread count "
        f"{snapshot['rtsa_thread_count']}, scan pool {snapshot['scan_pool_workers']} -- RTSA can "
        f"now answer which module was busy when it spiked) PASSED"
    )

    governor.reset_for_tests()
    configure_spike_diagnostics(DiagnosticsConfig(
        rtsa_cpu_spike_threshold_percent=80.0, capture_cooldown_seconds=300.0,
    ))
    diagnostics = get_spike_diagnostics()
    diagnostics._last_capture_monotonic = None
    diagnostics._captures_total = 0
    assert diagnostics.maybe_capture(10.0) is None, "no capture below the threshold"
    assert diagnostics._last_capture_monotonic is None, (
        "a below-threshold call must not start the cooldown clock"
    )
    first = diagnostics.maybe_capture(120.0)
    assert first is not None, "crossing the threshold must capture once"
    assert diagnostics.maybe_capture(150.0) is None, "the cooldown must suppress repeat captures"
    assert diagnostics.captures_total == 1, (
        f"exactly one capture must have been taken, got {diagnostics.captures_total}"
    )
    print(
        "Test 11 [CAPTURE COOLDOWN] (below threshold captures nothing, crossing it captures once, "
        "and the cooldown suppresses repeats -- diagnostics cannot become a new source of load) "
        "PASSED"
    )

    configure_cpu_governor(ResourceGovernorConfig(enabled=True))
    governor.reset_for_tests()
    health = governor.snapshot()
    for key in ("scan_pool_workers", "rtsa_cpu_percent", "host_cpu_percent", "active_by_cost"):
        assert key in health, f"governor snapshot must expose {key}"
    assert set(health["active_by_cost"]) == {COST_LIGHT, COST_MEDIUM, COST_HEAVY}
    print(
        f"Test 12 [OBSERVABILITY] (the governor reports pool size {health['scan_pool_workers']}, "
        f"live RTSA and host CPU, and active work split across "
        f"{sorted(health['active_by_cost'])}) PASSED"
    )

    print("\nALL CPU SPIKE GOVERNOR TESTS PASSED")


asyncio.run(main())
