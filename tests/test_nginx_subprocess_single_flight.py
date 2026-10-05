from __future__ import annotations

import asyncio
import os
import shutil
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import (
    CloudflareConfig, DiscordConfig, ModulesConfig, NginxMonitorConfig,
    ResourceGovernorConfig, ResponseEngineConfig, RTSAConfig,
)
from core.cpu_governor import configure_cpu_governor, get_cpu_governor
from core.event_bus import EventBus
from discord_integration.bot import RTSABot


class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass


def make_bot(*, detection_only: bool = False) -> RTSABot:
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=detection_only),
        modules=ModulesConfig(nginx_monitor=NginxMonitorConfig(conf_directory="/tmp/rtsa-nginx-sf-test")),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)


class _Spawns:
    def __init__(self) -> None:
        self.nginx_t_count = 0
        self.systemctl_calls: list[tuple[str, ...]] = []
        self.active = 0
        self.peak_active = 0


class _FakeProc:
    def __init__(self, spawns: _Spawns, *, returncode: int = 0, output: bytes = b"", delay: float = 0.0, hang: bool = False):
        self._spawns = spawns
        self.returncode = returncode
        self._output = output
        self._delay = delay
        self._hang = hang
        self.killed = False
        self.waited = False

    async def communicate(self):
        self._spawns.active += 1
        self._spawns.peak_active = max(self._spawns.peak_active, self._spawns.active)
        try:
            if self._hang:
                await asyncio.sleep(3600)
            if self._delay:
                await asyncio.sleep(self._delay)
            return (self._output, b"")
        finally:
            self._spawns.active -= 1

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> None:
        self.waited = True


def install_fakes(spawns: _Spawns, *, nginx_delay: float = 0.05, nginx_hang: bool = False, nginx_returncode: int = 0):
    orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec

    async def fake_exec(*args, **kwargs):
        binary = args[0]
        if binary.endswith("nginx") and len(args) > 1 and args[1] == "-t":
            spawns.nginx_t_count += 1
            return _FakeProc(
                spawns, returncode=nginx_returncode,
                output=b"nginx: configuration file /etc/nginx/nginx.conf test is successful\n",
                delay=nginx_delay, hang=nginx_hang,
            )
        if binary.endswith("systemctl"):
            spawns.systemctl_calls.append(args)
            return _FakeProc(spawns, returncode=0, output=b"OK")
        raise AssertionError(f"unexpected subprocess spawn in test: {args}")

    shutil.which = lambda name: f"/usr/sbin/{name}"
    asyncio.create_subprocess_exec = fake_exec

    def restore():
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec

    return restore


def _reset_governor(**overrides) -> None:
    settings = dict(
        max_heavy_scanners_concurrent=1,
        heavy_scan_cooldown_seconds=0.0,
        defer_when_system_busy=False,
        host_cpu_hard_limit_percent=85.0,
        rtsa_cpu_hard_limit_percent=80.0,
    )
    settings.update(overrides)
    configure_cpu_governor(ResourceGovernorConfig(**settings))
    get_cpu_governor().reset_for_tests()


async def main() -> None:
    _reset_governor()
    bot = make_bot()
    spawns = _Spawns()
    restore = install_fakes(spawns, nginx_delay=0.05)
    try:
        (ok1, msg1), (ok2, msg2) = await asyncio.gather(bot._nginx_test(), bot._nginx_test())
    finally:
        restore()
    assert spawns.nginx_t_count == 1, f"expected exactly one nginx -t subprocess, spawned {spawns.nginx_t_count}"
    outcomes = {ok1, ok2}
    coalesced = [m for ok, m in ((ok1, msg1), (ok2, msg2)) if not ok]
    assert True in outcomes or spawns.nginx_t_count == 1
    assert any("di-coalesce" in m for m in coalesced), (
        f"the losing request must get an explicit coalesce message, not silently look like a failed "
        f"config test -- got {(msg1, msg2)}"
    )
    print("Test 1 (two simultaneous nginx -t requests -> exactly one subprocess spawned, the second coalesced) PASSED")

    _reset_governor()
    bot = make_bot()
    spawns = _Spawns()
    restore = install_fakes(spawns, nginx_delay=0.05)
    try:
        results = await asyncio.gather(*(bot._nginx_test() for _ in range(10)))
    finally:
        restore()
    assert spawns.nginx_t_count == 1, f"expected exactly one subprocess for 10 concurrent callers, got {spawns.nginx_t_count}"
    succeeded = [r for r in results if r[0]]
    coalesced = [r for r in results if not r[0]]
    assert len(succeeded) == 1 and len(coalesced) == 9, (
        f"expected 1 admitted + 9 coalesced, got {len(succeeded)} admitted + {len(coalesced)} coalesced"
    )
    assert spawns.peak_active == 1, f"nginx -t must never run concurrently with itself, peak concurrent was {spawns.peak_active}"
    print("Test 2 (ten simultaneous nginx -t requests -> one subprocess runs, nine coalesced, zero overlap) PASSED")

    _reset_governor(heavy_scan_cooldown_seconds=0.0)
    bot = make_bot()
    spawns = _Spawns()
    restore = install_fakes(spawns, nginx_hang=True)
    try:
        orig_communicate = bot._communicate
        async def fast_timeout_communicate(proc, timeout=15.0):
            return await orig_communicate(proc, timeout=0.03)
        bot._communicate = fast_timeout_communicate
        ok, msg = await bot._nginx_test()
    finally:
        restore()
    assert ok is False and "timeout" in msg.lower()
    assert spawns.nginx_t_count == 1

    spawns2 = _Spawns()
    restore = install_fakes(spawns2, nginx_delay=0.0)
    try:
        ok2, msg2 = await bot._nginx_test()
    finally:
        restore()
    assert ok2 is True, f"a fresh nginx -t after a prior timeout must be able to run -- lock leaked: {msg2}"
    assert spawns2.nginx_t_count == 1
    print("Test 3 (nginx -t timeout kills/waits the hung process and releases the governor lock -- no lock leak) PASSED")

    _reset_governor()
    bot = make_bot(detection_only=False)
    spawns = _Spawns()
    restore = install_fakes(spawns, nginx_returncode=1)
    try:
        ok, msg = await bot._nginx_reload(requested_by="tester")
    finally:
        restore()
    assert ok is False and "GAGAL" in msg
    assert spawns.nginx_t_count == 1
    assert spawns.systemctl_calls == [], f"reload must not touch systemctl when nginx -t fails, got {spawns.systemctl_calls}"
    print("Test 4 (nginx -t failure blocks reload -- systemctl is never invoked) PASSED")

    _reset_governor()
    bot = make_bot(detection_only=False)
    spawns = _Spawns()
    restore = install_fakes(spawns, nginx_returncode=0)
    try:
        ok, msg = await bot._nginx_reload(requested_by="tester")
    finally:
        restore()
    assert ok is True, msg
    assert spawns.nginx_t_count == 1
    assert len(spawns.systemctl_calls) == 1 and spawns.systemctl_calls[0][1:] == ("reload", "nginx")
    print("Test 5 (valid config -> nginx -t then systemctl reload nginx, in that order, exactly once each) PASSED")

    import tempfile
    from pathlib import Path
    tmp = Path(tempfile.mkdtemp(prefix="rtsa_nginx_sf_"))
    conf_dir = tmp / "sites-enabled"
    conf_dir.mkdir(parents=True)
    conf_file = conf_dir / "already-hardened.id.conf"
    conf_file.write_text("server {\n    server_name already-hardened.id;\n}\n", encoding="utf-8")

    _reset_governor()
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False),
        modules=ModulesConfig(nginx_monitor=NginxMonitorConfig(conf_directory=str(conf_dir))),
        cloudflare=CloudflareConfig(enabled=False),
    )
    bot6 = RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)
    from discord_integration import bot as bot_module
    hardened_once, _ = bot_module._ensure_nginx_hardening_rules(conf_file.read_text(encoding="utf-8"))
    conf_file.write_text(hardened_once, encoding="utf-8")

    spawns = _Spawns()
    restore = install_fakes(spawns)
    try:
        result = await bot6._apply_sofix_to_conf_file(conf_file, requested_by="tester")
    finally:
        restore()
    assert result["status"] == "already_hardened", result
    assert spawns.nginx_t_count == 0, (
        f"a config that needed no changes must never trigger nginx -t -- spawned {spawns.nginx_t_count}"
    )
    print("Test 6 (an already-hardened / unchanged config never triggers nginx -t) PASSED")

    _reset_governor(rtsa_cpu_hard_limit_percent=0.001, defer_when_system_busy=True)
    bot = make_bot()
    get_cpu_governor().sample_cpu()
    spawns = _Spawns()
    restore = install_fakes(spawns)
    try:
        ok, msg = await bot._nginx_test()
    finally:
        restore()
    assert ok is False and "di-coalesce" in msg
    assert spawns.nginx_t_count == 0, f"an operation deferred by CPU pressure must not spawn a subprocess, got {spawns.nginx_t_count}"
    assert get_cpu_governor().stats_for("nginx_config_operation").deferred_busy_count >= 1
    print("Test 7 (RTSA/host CPU over its hard limit -> nginx operation deferred, zero subprocess spawned) PASSED")

    _reset_governor(defer_when_system_busy=False)
    bot = make_bot()
    spawns = _Spawns()
    restore = install_fakes(spawns)
    try:
        ok, msg = await bot._nginx_test()
    finally:
        restore()
    assert ok is True, msg
    assert spawns.nginx_t_count == 1
    print("Test 8 (after CPU pressure clears / deferral disabled, nginx -t runs normally again) PASSED")

    _reset_governor()
    bot = make_bot(detection_only=False)
    spawns = _Spawns()
    restore = install_fakes(spawns, nginx_delay=0.05)
    try:
        results = await asyncio.gather(
            bot._nginx_test(), bot._nginx_reload(requested_by="a"), bot._nginx_restart(requested_by="b"),
        )
    finally:
        restore()
    admitted = [r for r in results if r[0] or "GAGAL" in r[1] or "berhasil" in r[1]]
    total_subprocess_spawns = spawns.nginx_t_count + len(spawns.systemctl_calls)
    assert total_subprocess_spawns <= 2, (
        f"test/reload/restart racing concurrently must not each spawn their own subprocess chain -- "
        f"got {spawns.nginx_t_count} nginx -t + {len(spawns.systemctl_calls)} systemctl calls"
    )
    assert spawns.peak_active <= 1, f"no two nginx-related subprocesses may run concurrently, peak was {spawns.peak_active}"
    print("Test 9 (test/reload/restart racing concurrently share one slot -- no duplicate/overlapping subprocess) PASSED")

    _reset_governor()
    bot = make_bot()
    spawns = _Spawns()
    restore = install_fakes(spawns, nginx_delay=0.05)
    try:
        task = asyncio.ensure_future(bot._nginx_test())
        await asyncio.sleep(0)
        assert get_cpu_governor().stats_for("nginx_config_operation").active_runs == 1
        await task
    finally:
        restore()
    _reset_governor()
    assert get_cpu_governor().stats_for("nginx_config_operation").active_runs == 0
    spawns2 = _Spawns()
    restore = install_fakes(spawns2)
    try:
        ok, msg = await bot._nginx_test()
    finally:
        restore()
    assert ok is True, f"after a simulated restart the lock must be clean, not stuck locked: {msg}"
    print("Test 10 (governor state resets cleanly across a simulated RTSA restart -- no leaked lock) PASSED")

    print("\nALL NGINX SUBPROCESS SINGLE-FLIGHT TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
