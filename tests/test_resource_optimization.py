import asyncio
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import AuditMonitorConfig, HealthMonitorConfig
from core.event_bus import EventBus
from modules.audit_monitor import AuditMonitor
from modules.health_monitor import HealthMonitor

try:
    import psutil
except ImportError:
    psutil = None


class _FakeProc:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, self._stderr

    def kill(self):
        pass

    async def wait(self):
        return self.returncode


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.log")
        with open(log_path, "w") as f:
            f.write("initial\n")

        cfg = AuditMonitorConfig(audit_log_path=log_path, audit_log_stat_check_enabled=True)
        mon = AuditMonitor(EventBus(), cfg)

        spawn_calls = {"n": 0}
        original_create_subprocess_exec = asyncio.create_subprocess_exec

        async def counting_create_subprocess_exec(*args, **kwargs):
            spawn_calls["n"] += 1
            return _FakeProc(stdout=b"", stderr=b"", returncode=1)

        asyncio.create_subprocess_exec = counting_create_subprocess_exec
        try:
            await mon._poll_once()
            assert spawn_calls["n"] == 1, "the first poll must always run ausearch to establish a baseline"

            await mon._poll_once()
            await mon._poll_once()
            await mon._poll_once()
            assert spawn_calls["n"] == 1, (
                f"polls while the audit log file is unchanged must never spawn ausearch again, "
                f"got {spawn_calls['n']} spawns"
            )
            print("Scenario 1 (audit log unchanged across 3 more polls -- ausearch spawned only once, not 4x) PASSED")

            with open(log_path, "a") as f:
                f.write("new audit record\n")
            await mon._poll_once()
            assert spawn_calls["n"] == 2, (
                f"a genuine change to the audit log (mtime/size changed) must trigger a real ausearch "
                f"spawn, got {spawn_calls['n']} total spawns"
            )
            print("Scenario 2 (audit log file grows -- ausearch is spawned again to check the new data) PASSED")
        finally:
            asyncio.create_subprocess_exec = original_create_subprocess_exec

    cfg_missing = AuditMonitorConfig(
        audit_log_path="/this/path/does/not/exist/audit.log", audit_log_stat_check_enabled=True,
    )
    mon_missing = AuditMonitor(EventBus(), cfg_missing)
    spawn_calls2 = {"n": 0}

    async def counting2(*args, **kwargs):
        spawn_calls2["n"] += 1
        return _FakeProc(stdout=b"", stderr=b"", returncode=1)

    asyncio.create_subprocess_exec = counting2
    try:
        await mon_missing._poll_once()
        await mon_missing._poll_once()
        await mon_missing._poll_once()
        assert spawn_calls2["n"] == 3, (
            f"when the configured audit log path cannot be stat'd (wrong path, permission denied, "
            f"missing file), the module must fail SAFE by always running ausearch every poll -- "
            f"exactly today's behavior, never silently stop detecting -- got {spawn_calls2['n']} spawns for 3 polls"
        )
        print(
            "Scenario 3 (unreachable/misconfigured audit_log_path -- fails safe, ausearch runs every "
            "poll exactly as before this optimization, detection never silently degrades) PASSED"
        )
    finally:
        asyncio.create_subprocess_exec = original_create_subprocess_exec

    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.log")
        with open(log_path, "w") as f:
            f.write("x\n")
        cfg_disabled = AuditMonitorConfig(audit_log_path=log_path, audit_log_stat_check_enabled=False)
        mon_disabled = AuditMonitor(EventBus(), cfg_disabled)
        spawn_calls3 = {"n": 0}

        async def counting3(*args, **kwargs):
            spawn_calls3["n"] += 1
            return _FakeProc(stdout=b"", stderr=b"", returncode=1)

        asyncio.create_subprocess_exec = counting3
        try:
            await mon_disabled._poll_once()
            await mon_disabled._poll_once()
            assert spawn_calls3["n"] == 2, (
                f"audit_log_stat_check_enabled=false must fully restore the original always-poll "
                f"behavior -- the config knob to turn this optimization off, got {spawn_calls3['n']}"
            )
            print("Scenario 4 (audit_log_stat_check_enabled=false -- restores original always-poll behavior) PASSED")
        finally:
            asyncio.create_subprocess_exec = original_create_subprocess_exec

    if psutil is None:
        print("Scenario 5 SKIPPED (psutil not installed in this environment)")
    else:
        cfg_health = HealthMonitorConfig(watched=False)
        mon_health = HealthMonitor(EventBus(), cfg_health)
        published = []
        mon_health.publish = lambda ev: published.append(ev)

        start = time.monotonic()
        snapshot = await mon_health._collect_snapshot()
        elapsed = time.monotonic() - start
        assert snapshot.category.value == "HEALTH_STATUS"
        assert isinstance(snapshot.cpu_percent, float)
        assert elapsed < 0.9, (
            f"a single health snapshot must never block for a full second sampling CPU -- "
            f"psutil.cpu_percent must be called non-blocking (interval=None), took {elapsed:.2f}s"
        )
        print(
            f"Scenario 5 (health snapshot collection no longer blocks ~1s on psutil.cpu_percent -- "
            f"took {elapsed:.2f}s) PASSED"
        )

    print("\nALL RESOURCE OPTIMIZATION REGRESSION TESTS PASSED")


asyncio.run(main())
