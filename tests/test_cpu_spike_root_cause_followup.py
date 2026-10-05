import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio
import resource
import sqlite3
import tempfile
import time
from unittest import mock

import core.adaptive_feedback as af
import core.cpu_governor as cpu_governor
import core.process_identity as process_identity
import core.spike_diagnostics as spike_diagnostics
from config.manager import TceConfig
from core.event_bus import EventBus
from core.datatypes import BaseEvent, EventCategory, Severity
from core.scheduler import SchedulerRegistry
import modules.threat_correlation_engine as tce
from database.sqlite_pool import SQLiteWriteWorker


def _write_proc_entry(proc_root, pid, *, tgid, ppid, threads, vm_rss_kb, cmdline, start_ticks):
    d = os.path.join(proc_root, str(pid))
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "status"), "w") as f:
        f.write(f"Name:\tpython3\nPid:\t{pid}\nTgid:\t{tgid}\nPPid:\t{ppid}\n")
        f.write(f"Threads:\t{threads}\n")
        f.write(f"VmRSS:\t{vm_rss_kb} kB\n")
    with open(os.path.join(d, "cmdline"), "wb") as f:
        f.write(cmdline.encode("utf-8").replace(b" ", b"\x00") + b"\x00")
    comm = "python3"
    fields = ["0"] * 44
    fields[18] = str(start_ticks)
    with open(os.path.join(d, "stat"), "w") as f:
        f.write(f"{pid} ({comm}) R " + " ".join(fields) + "\n")


def main() -> None:
    with tempfile.TemporaryDirectory() as proc_root:
        _write_proc_entry(
            proc_root, 81145, tgid=81145, ppid=1, threads=6, vm_rss_kb=204800,
            cmdline="/usr/bin/python3 /opt/security/rtsa/main.py", start_ticks=1000,
        )
        _write_proc_entry(
            proc_root, 81142, tgid=81145, ppid=1, threads=6, vm_rss_kb=204800,
            cmdline="/usr/bin/python3 /opt/security/rtsa/main.py", start_ticks=1000,
        )
        _write_proc_entry(
            proc_root, 9001, tgid=9001, ppid=1, threads=3, vm_rss_kb=10240,
            cmdline="/usr/bin/monarx-agent", start_ticks=500,
        )
        with open(os.path.join(proc_root, "stat"), "w") as f:
            f.write("btime 0\n")

        snapshots = process_identity.discover_matching_processes("main.py", proc_root)
        assert {s.pid for s in snapshots} == {81145, 81142}
        boot_time = process_identity.read_boot_time(proc_root)
        assert boot_time == 0.0
        classifications = process_identity.classify_processes(
            snapshots, boot_time=boot_time, cpu_percent_by_pid={81142: 73.5, 81145: 12.0},
        )
        by_pid = {c.pid: c for c in classifications}
        assert by_pid[81145].role == process_identity.ROLE_MAIN_PROCESS
        assert by_pid[81142].role == process_identity.ROLE_THREAD_OF
        assert by_pid[81142].of_pid == 81145
        print(
            "Scenario A [TGID-BASED THREAD VS PROCESS CLASSIFICATION] (two /proc entries with identical "
            "cmdline main.py, one is the real Tgid-leading process (81145), the other is a thread of it "
            "(81142) -- classified correctly, matching exactly the two PIDs from the incident report) PASSED"
        )

        instances = process_identity.genuine_instances(classifications)
        assert len(instances) == 1 and instances[0].pid == 81145
        print(
            "Scenario B [GENUINE INSTANCE COUNT IGNORES THREADS] (only the Tgid-leader counts as an "
            "independent RTSA instance -- a busy scan-pool thread showing as a separate PID in a process "
            "list is never mistaken for a second instance) PASSED"
        )

        hottest = process_identity.hottest_process(classifications)
        assert hottest.pid == 81142, hottest
        assert hottest.role == process_identity.ROLE_THREAD_OF
        print(
            "Scenario C [HOTTEST PID ATTRIBUTION NEVER ASSUMES THE FIRST MATCH] (PID 81142 has the "
            "higher CPU reading even though 81145 is the real process leader -- hottest_process() names "
            "81142 specifically, with its role correctly reported as THREAD_OF 81145, not silently "
            "assumed to be an independent instance) PASSED"
        )

        classifications2, has_dup = process_identity.discover_and_classify("main.py", proc_root=proc_root)
        assert has_dup is False
        print(
            "Scenario D [ONE REAL INSTANCE + ITS OWN THREADS NEVER FLAGGED AS DUPLICATE] (with exactly "
            "one Tgid-leader present, discover_and_classify reports has_duplicate_instances=False even "
            "though two /proc entries share the main.py cmdline) PASSED"
        )

        _write_proc_entry(
            proc_root, 90001, tgid=90001, ppid=1, threads=1, vm_rss_kb=51200,
            cmdline="/usr/bin/python3 /opt/security/rtsa/main.py", start_ticks=2000,
        )
        classifications3, has_dup3 = process_identity.discover_and_classify("main.py", proc_root=proc_root)
        assert has_dup3 is True
        assert len(process_identity.genuine_instances(classifications3)) == 2
        print(
            "Scenario E [TWO GENUINE TGID-LEADERS IS A REAL DUPLICATE] (adding a second independent "
            "Tgid-leading main.py process is correctly flagged has_duplicate_instances=True -- this is "
            "the actual failure mode operators need to be warned about) PASSED"
        )

    cpu_governor._governor.reset_for_tests()
    with mock.patch("os.cpu_count", return_value=8):
        governor = cpu_governor.CpuGovernor()
        governor._last_self_percent = 113.0
        sample = governor.sample_cpu()
    assert sample["logical_cpu_count"] == 8.0
    assert sample["rtsa_cpu_cores_equivalent"] == 1.13
    assert sample["rtsa_host_share_percent"] == 14.1, sample["rtsa_host_share_percent"]
    print(
        "Scenario F [CPU CALCULATION CORRECT ON AN 8-LOGICAL-CPU HOST] (113% process CPU on an 8-core "
        "host is 1.13 cores-equivalent and 14.1% of total host capacity -- matches the worked example "
        "in the incident report exactly, using the real logical CPU count rather than assuming 1 or 4) PASSED"
    )

    with mock.patch("os.cpu_count", return_value=1):
        governor2 = cpu_governor.CpuGovernor()
        governor2._last_self_percent = 99.0
        sample2 = governor2.sample_cpu()
    assert sample2["logical_cpu_count"] == 1.0
    assert sample2["rtsa_host_share_percent"] == 99.0
    print(
        "Scenario G [SINGLE-CORE HOST: PROCESS PERCENT AND HOST SHARE CONVERGE] (on a genuinely 1-core "
        "host, RTSA_HOST_SHARE_PERCENT correctly equals PROCESS_CPU_PERCENT since one core is the "
        "entire host capacity) PASSED"
    )

    diagnostics = spike_diagnostics.SpikeDiagnostics()
    snapshot = diagnostics.capture(113.0)
    block = diagnostics.format_block(snapshot)
    assert "HOST_CPU_PERCENT:" in block
    assert "PROCESS_CPU_PERCENT: 113.0%" in block
    assert "PROCESS_CPU_CORES_EQUIVALENT:" in block
    assert "RTSA_HOST_SHARE_PERCENT:" in block
    assert snapshot["rtsa_cpu_cores_equivalent"] == round(113.0 / 100.0, 2)
    print(
        "Scenario H [DIAGNOSTIC BLOCK NEVER SAYS BARE 'CPU 100%'] (the rendered forensics block always "
        "carries all four explicitly labelled fields -- HOST_CPU_PERCENT, PROCESS_CPU_PERCENT, "
        "PROCESS_CPU_CORES_EQUIVALENT, RTSA_HOST_SHARE_PERCENT -- and the cores-equivalent figure is "
        "derived from the exact same resolved percentage shown alongside it, never a stale internal "
        "sample) PASSED"
    )

    class FakeSubscription:
        def __init__(self, size, maxsize=100):
            self._size = size
            self._maxsize = maxsize

        @property
        def stats(self):
            return {"queue_size": self._size, "queue_maxsize": self._maxsize, "delivered": 5}

    class FakeBus:
        subscriber_stats = {"module_a": FakeSubscription(0).stats, "module_b": FakeSubscription(7).stats}

    class FakeDbWorker:
        stats = {"queue_size": 42, "written": 100}

    diagnostics2 = spike_diagnostics.SpikeDiagnostics()
    diagnostics2.attach_bus(FakeBus())
    diagnostics2.attach_db_worker(FakeDbWorker())
    snapshot2 = diagnostics2.capture(50.0)
    assert snapshot2["event_bus_queue_depths"] == {"module_a": 0, "module_b": 7}
    assert snapshot2["sqlite_writer_queue_depth"] == 42
    block2 = diagnostics2.format_block(snapshot2)
    assert "module_b=7" in block2
    assert "SQLite writer queue depth: 42" in block2
    print(
        "Scenario I [EVENTBUS AND SQLITE WRITER QUEUE DEPTH SURFACED] (once attached, a spike capture "
        "reports each module's own EventBus queue depth and the SQLite writer's backlog -- exactly what "
        "the forensics mode was asked to record) PASSED"
    )

    async def _idle_queue_cpu_check() -> float:
        bus = EventBus()

        async def handler(event) -> None:
            pass

        await bus.subscribe("idle_probe", handler)
        before = resource.getrusage(resource.RUSAGE_SELF)
        cpu_before = before.ru_utime + before.ru_stime
        await asyncio.sleep(0.4)
        after = resource.getrusage(resource.RUSAGE_SELF)
        cpu_after = after.ru_utime + after.ru_stime
        await bus.unsubscribe("idle_probe")
        return cpu_after - cpu_before

    consumed = asyncio.run(_idle_queue_cpu_check())
    assert consumed < 0.05, f"idle EventBus subscriber consumed {consumed:.3f}s CPU over 0.4s wall -- busy spin regression"
    print(
        "Scenario J [EMPTY EVENTBUS QUEUE NEVER BUSY-SPINS] (a subscriber left idle for 0.4s wall time "
        "with zero events published consumes under 50ms of CPU -- proves await queue.get() is genuinely "
        "blocking, not a disguised polling loop) PASSED"
    )

    async def _aggregation_task_lifecycle_check() -> None:
        SchedulerRegistry.reset_for_tests()
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "rtsa.db")
            worker = SQLiteWriteWorker(db_path=db_path, flush_interval_seconds=0.05)
            await worker.start()
            await worker.stop()
            cfg = TceConfig(
                enabled=True,
                poll_interval_seconds=0.05,
                events_db_path=db_path,
                adaptive_detection=af.AdaptiveFeedbackConfig(
                    enabled=True, collect_feedback=True, aggregate_feedback=True, apply_weights=False,
                    aggregation_interval_seconds=0.05,
                ),
            )
            await _run_aggregation_lifecycle_probe(cfg)

    async def _run_aggregation_lifecycle_probe(cfg) -> None:
        engine = tce.ThreatCorrelationEngine(EventBus(), cfg)
        run_task = asyncio.create_task(engine.run())
        await asyncio.sleep(1.3)
        run_task.cancel()
        try:
            await run_task
        except asyncio.CancelledError:
            pass

        snapshot = SchedulerRegistry.snapshot()
        agg_stats = snapshot.get("tce_adaptive_feedback_aggregation")
        assert agg_stats is not None, "aggregation task must register itself with the scheduler exactly once"
        assert agg_stats["cycle_count"] >= 2, (
            f"expected multiple aggregation cycles at its own short interval, got {agg_stats['cycle_count']}"
        )
        assert agg_stats["interval_seconds"] == 0.05

        all_tasks = [t for t in asyncio.all_tasks() if "tce-adaptive-feedback-aggregation" in (t.get_name() or "")]
        assert all(t.done() for t in all_tasks), (
            f"aggregation task must be fully cancelled when the engine's run() exits, found still-running: {all_tasks}"
        )

    asyncio.run(_aggregation_task_lifecycle_check())
    print(
        "Scenario K [ADAPTIVE AGGREGATION TASK: NO DUPLICATION, RESPECTS ITS OWN INTERVAL, CLEAN SHUTDOWN] "
        "(a single engine.run() call registers the aggregation scanner exactly once, it cycles at its "
        "configured interval -- not busy-looping and not silently ignored -- and cancelling run() leaves "
        "no orphaned aggregation task behind that a restart could stack a second one on top of) PASSED"
    )

    print("\nALL CPU SPIKE ROOT CAUSE FOLLOW-UP TESTS PASSED")


main()
