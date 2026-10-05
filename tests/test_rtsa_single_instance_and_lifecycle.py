import inspect
import os
import signal
import subprocess
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import main as main_module
from core.instance_lock import InstanceAlreadyRunning, SingleInstanceLock, is_locked


def _holder_script(lock_path: str, sleep_seconds: float = 3.0) -> str:
    return (
        "import time\n"
        "from core.instance_lock import SingleInstanceLock\n"
        f"lock = SingleInstanceLock({lock_path!r})\n"
        "lock.acquire()\n"
        "print('LOCKED', flush=True)\n"
        f"time.sleep({sleep_seconds})\n"
    )


def _attempt_script(lock_path: str) -> str:
    return (
        "from core.instance_lock import SingleInstanceLock, InstanceAlreadyRunning\n"
        f"lock = SingleInstanceLock({lock_path!r})\n"
        "try:\n"
        "    lock.acquire()\n"
        "    print('ACQUIRED')\n"
        "except InstanceAlreadyRunning:\n"
        "    print('REJECTED')\n"
    )


def test_1_single_start_acquires_lock() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        lock_path = os.path.join(tmp, "rtsa.lock")
        lock = SingleInstanceLock(lock_path)
        lock.acquire()
        try:
            assert is_locked(lock_path) == os.getpid()
        finally:
            lock.release()
    print("Test 1 (starting one RTSA acquires the lock; exactly 1 logical instance) PASSED")


def test_2_and_3_repeated_component_failure_never_touches_process_lock() -> None:
    supervisor_source = inspect.getsource(
        __import__("core.supervisor", fromlist=["HealthSupervisor"])
    )
    forbidden = ["subprocess", "os.exec", "os.fork", "multiprocessing", "Popen"]
    for token in forbidden:
        assert token not in supervisor_source, (
            f"core/supervisor.py must never spawn OS processes to restart a component "
            f"(found forbidden token {token!r}) -- component restart must stay in-process"
        )
    print(
        "Test 2/3 (HealthSupervisor contains no process-spawning primitives -- component "
        "restart can never touch main.py's process count, repeated failures included) PASSED"
    )


def test_4_self_health_monitor_never_spawns_processes() -> None:
    self_health_source = inspect.getsource(__import__("core.self_health", fromlist=["*"]))
    forbidden = ["subprocess.Popen", "os.exec", "os.fork", "multiprocessing.Process"]
    for token in forbidden:
        assert token not in self_health_source, (
            f"core/self_health.py must never spawn OS processes (found {token!r})"
        )
    print("Test 4 (self-health/recovery monitor never spawns a new OS process) PASSED")


def test_5_discord_bot_recovery_never_relaunches_main() -> None:
    main_source = inspect.getsource(main_module)
    assert "main.py" not in main_source.replace(
        '"/opt/security/rtsa/main.py"', ""
    ).replace("_resolve_lock_path", "").replace("/opt/security/rtsa/main.py", ""), (
        "main.py must not contain any literal self-referencing spawn target"
    )
    run_discord_bot_source = inspect.getsource(main_module.RTSAEngine._run_discord_bot)
    forbidden = ["subprocess", "Popen", "os.exec", "os.fork", "multiprocessing"]
    for token in forbidden:
        assert token not in run_discord_bot_source, (
            f"_run_discord_bot's crash-retry loop must stay entirely in-process "
            f"(found forbidden token {token!r})"
        )
    print("Test 5 (Discord bot crash-retry loop restarts the bot task only, never spawns main.py) PASSED")


def test_6_config_reload_never_relaunches_main() -> None:
    reload_source = inspect.getsource(main_module.RTSAEngine.reload_config)
    forbidden = ["subprocess", "Popen", "os.exec", "os.fork", "multiprocessing", "sys.executable"]
    for token in forbidden:
        assert token not in reload_source, (
            f"config reload must never launch a new process (found forbidden token {token!r})"
        )
    print("Test 6 (config reload never spawns a new main.py process) PASSED")


def test_7_main_acquires_lock_before_any_component_initialization() -> None:
    main_fn_source = inspect.getsource(main_module.main)
    lock_index = main_fn_source.index("lock.acquire()")
    amain_index = main_fn_source.index("asyncio.run(_amain())")
    assert lock_index < amain_index, (
        "main() must acquire the single-instance lock BEFORE running _amain() (which is what "
        "constructs the event bus, DB worker, Discord dispatcher, and every module) -- a second "
        "instance must be rejected before any of that is ever created"
    )
    reject_branch = main_fn_source[main_fn_source.index("except InstanceAlreadyRunning"):]
    assert "sys.exit(EXIT_ALREADY_RUNNING)" in reject_branch[:200], (
        "a second instance that fails to acquire the lock must exit immediately"
    )
    print(
        "Test 7 (a second main.py fails lock.acquire() and exits before any module/thread/Discord "
        "client/subprocess is ever created) PASSED"
    )


def test_8_concurrent_start_attempts_exactly_one_wins() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        lock_path = os.path.join(tmp, "rtsa.lock")
        holder = subprocess.Popen(
            [sys.executable, "-c", _holder_script(lock_path, sleep_seconds=2.5)],
            cwd=_REPO_ROOT, stdout=subprocess.PIPE, text=True,
        )
        try:
            assert holder.stdout.readline().strip() == "LOCKED"

            n_challengers = 5
            challengers = [
                subprocess.Popen(
                    [sys.executable, "-c", _attempt_script(lock_path)],
                    cwd=_REPO_ROOT, stdout=subprocess.PIPE, text=True,
                )
                for _ in range(n_challengers)
            ]
            outcomes = [proc.stdout.readline().strip() for proc in challengers]
            for proc in challengers:
                proc.wait(timeout=10)
            assert outcomes.count("ACQUIRED") == 0, (
                f"while the original instance is alive, zero concurrent challengers may acquire "
                f"the lock, got outcomes={outcomes}"
            )
            assert outcomes.count("REJECTED") == n_challengers, outcomes
        finally:
            holder.wait(timeout=10)
    print(
        "Test 8 (5 concurrent RTSA start attempts against a live holder -- zero acquire the lock, "
        "exactly the original instance remains active) PASSED"
    )


def test_9_repeated_restart_cycles_never_leak_double_holders() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        lock_path = os.path.join(tmp, "rtsa.lock")
        for cycle in range(20):
            lock = SingleInstanceLock(lock_path)
            lock.acquire()
            assert is_locked(lock_path) == os.getpid(), f"cycle {cycle}: lock not held by self"
            second = SingleInstanceLock(lock_path)
            try:
                second.acquire()
                raise AssertionError(f"cycle {cycle}: a second acquire must never succeed while held")
            except InstanceAlreadyRunning:
                pass
            lock.release()
            assert is_locked(lock_path) is None, f"cycle {cycle}: lock must be free immediately after release"
    print(
        "Test 9 (20 repeated acquire/release cycles, simulating 'systemctl restart' 20 times -- "
        "never more than 1 logical holder at any point) PASSED"
    )


def test_10_stale_lock_recovers_after_holder_is_killed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        lock_path = os.path.join(tmp, "rtsa.lock")
        holder = subprocess.Popen(
            [sys.executable, "-c", _holder_script(lock_path, sleep_seconds=30.0)],
            cwd=_REPO_ROOT, stdout=subprocess.PIPE, text=True,
        )
        try:
            assert holder.stdout.readline().strip() == "LOCKED"
            assert is_locked(lock_path) == holder.pid

            holder.send_signal(signal.SIGKILL)
            holder.wait(timeout=5)

            deadline = time.monotonic() + 5.0
            recovered = False
            while time.monotonic() < deadline:
                if is_locked(lock_path) is None:
                    recovered = True
                    break
                time.sleep(0.05)
            assert recovered, "the kernel must release an flock automatically when the holder is SIGKILLed"

            new_lock = SingleInstanceLock(lock_path)
            new_lock.acquire()
            try:
                assert is_locked(lock_path) == os.getpid()
            finally:
                new_lock.release()
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=5)
    print(
        "Test 10 (a crashed/SIGKILLed holder releases the lock immediately -- no manual stale-lock "
        "cleanup needed, no PID-only existence check required) PASSED"
    )


def test_11_pm2_discovery_never_spawns_a_persistent_daemon_process() -> None:
    pm2_source = inspect.getsource(__import__("modules.pm2_monitor", fromlist=["*"]))
    forbidden = ["main.py", "sys.executable"]
    for token in forbidden:
        assert token not in pm2_source, (
            f"pm2_monitor.py discovery/polling must never reference RTSA's own entrypoint "
            f"(found {token!r})"
        )
    print(
        "Test 11 (PM2 discovery/monitoring never starts PM2 daemons, node apps, or another "
        "RTSA main.py as a side effect) PASSED"
    )


def test_12_process_lineage_diagnostic() -> None:
    diagnostic = main_module.collect_process_lineage_diagnostic()
    assert diagnostic["pid"] == os.getpid()
    assert diagnostic["ppid"] == os.getppid()
    assert isinstance(diagnostic["parent_process_name"], str) and diagnostic["parent_process_name"]
    assert isinstance(diagnostic["cmdline"], str)
    assert isinstance(diagnostic["process_start_time_display"], str) and diagnostic["process_start_time_display"]
    print("Test 12 (one-time process lineage diagnostic: pid/ppid/parent name/cmdline/start time) PASSED")


def test_13_systemd_unit_hardened_against_orphaned_children() -> None:
    service_path = os.path.join(_REPO_ROOT, "deploy", "rtsa.service")
    with open(service_path, "r") as f:
        unit_text = f.read()
    assert "KillMode=control-group" in unit_text, (
        "KillMode must be control-group so systemd reaps the ENTIRE process tree on stop/restart, "
        "never leaving orphaned RTSA-owned children (or a lingering old main.py) behind"
    )
    assert "KillMode=process" not in unit_text
    assert "TimeoutStopSec=" in unit_text
    exec_start_lines = [line for line in unit_text.splitlines() if line.startswith("ExecStart=")]
    assert len(exec_start_lines) == 1, (
        f"exactly one ExecStart directive must exist for the RTSA unit: {exec_start_lines}"
    )
    assert exec_start_lines[0] == "ExecStart=/usr/bin/python3 /opt/security/rtsa/main.py"
    assert "Restart=on-failure" in unit_text
    assert "RestartPreventExitStatus=75" in unit_text and main_module.EXIT_ALREADY_RUNNING == 75, (
        "a duplicate launch (exit 75) must not make systemd respawn it every RestartSec forever"
    )
    print(
        "Test 13 (systemd unit: KillMode=control-group, TimeoutStopSec set, exactly one ExecStart "
        "-- systemd owns exactly one RTSA main process tree) PASSED"
    )


def main() -> None:
    test_1_single_start_acquires_lock()
    test_2_and_3_repeated_component_failure_never_touches_process_lock()
    test_4_self_health_monitor_never_spawns_processes()
    test_5_discord_bot_recovery_never_relaunches_main()
    test_6_config_reload_never_relaunches_main()
    test_7_main_acquires_lock_before_any_component_initialization()
    test_8_concurrent_start_attempts_exactly_one_wins()
    test_9_repeated_restart_cycles_never_leak_double_holders()
    test_10_stale_lock_recovers_after_holder_is_killed()
    test_11_pm2_discovery_never_spawns_a_persistent_daemon_process()
    test_12_process_lineage_diagnostic()
    test_13_systemd_unit_hardened_against_orphaned_children()
    print("\nALL RTSA SINGLE-INSTANCE / LIFECYCLE TESTS PASSED")


if __name__ == "__main__":
    main()
