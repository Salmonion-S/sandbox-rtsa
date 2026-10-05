import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio
import types

import psutil

import core.process_cleanup as process_cleanup
from config.manager import (
    CloudflareConfig, DiscordConfig, HostPersistenceDetectorConfig, ModulesConfig,
    ResponseEngineConfig, RTSAConfig,
)
from core.event_bus import EventBus
from discord_integration.bot import RTSABot


class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass


def make_bot():
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False, whitelist_user=["newusproud"]),
        modules=ModulesConfig(
            host_persistence_detector=HostPersistenceDetectorConfig(
                auto_remediate_protect_users=["newusproud", "root"],
            ),
        ),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)


def make_account(username="clearprosestestuser", uid=8001, home="/nonexistent/clearprosestestuser"):
    return types.SimpleNamespace(
        pw_name=username, pw_uid=uid, pw_gid=uid, pw_dir=home, pw_shell="/bin/bash",
    )


class _Uids:
    def __init__(self, real):
        self.real = real


class _Named:
    def __init__(self, name):
        self._name = name

    def name(self):
        return self._name


class FakeProc:
    def __init__(
        self, pid, uid, exe="/usr/bin/node", cwd="/home/site/app", cmdline="node server.js",
        create_time=1000.0, ppid=1, username="clearprosestestuser", status="running",
        terminal=None, parent_name=None,
    ):
        self.pid = pid
        self.info = {"pid": pid, "ppid": ppid, "uid": uid, "username": username}
        self._exe = exe
        self._cwd = cwd
        self._cmdline = cmdline
        self._create_time = create_time
        self._ppid = ppid
        self._username = username
        self._status = status
        self._terminal = terminal
        self._parent_name = parent_name

    def ppid(self):
        return self._ppid

    def username(self):
        return self._username

    def exe(self):
        return self._exe

    def cwd(self):
        return self._cwd

    def cmdline(self):
        return self._cmdline.split() if self._cmdline else []

    def create_time(self):
        return self._create_time

    def status(self):
        return self._status

    def terminal(self):
        return self._terminal

    def parent(self):
        return None if self._parent_name is None else _Named(self._parent_name)

    def uids(self):
        return _Uids(self.info["uid"])


class _PatchGuard:

    def __init__(self, obj, name, value):
        self._obj = obj
        self._name = name
        self._had = hasattr(obj, name)
        self._old = getattr(obj, name, None)
        setattr(obj, name, value)

    def restore(self):
        if self._had:
            setattr(self._obj, self._name, self._old)
        else:
            delattr(self._obj, self._name)


async def main():
    bot = make_bot()

    guard = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([]))
    try:
        discovery = await bot._clearproses_discover_and_classify(make_account())
    finally:
        guard.restore()
    assert discovery.status == process_cleanup.DISCOVERY_NO_ACTIVE_RESOURCES
    assert discovery.classified == [] and discovery.failures == []
    print("Scenario 1 (user with zero processes -> NO_ACTIVE_RESOURCES) PASSED")

    account2 = make_account(uid=8002)
    p2 = FakeProc(pid=9001, uid=8002, exe="/usr/bin/node", cmdline="node app.js")
    guard = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([p2]))
    try:
        discovery = await bot._clearproses_discover_and_classify(account2)
    finally:
        guard.restore()
    assert discovery.status == process_cleanup.DISCOVERY_SUCCESS
    assert len(discovery.classified) == 1 and discovery.classified[0].pid == 9001
    assert discovery.classified[0].record.create_time == 1000.0
    assert discovery.failures == []
    print("Scenario 2 (single process -> SUCCESS, fully classified) PASSED")

    account3 = make_account(uid=8003)
    procs3 = [
        FakeProc(pid=9101, uid=8003, exe="/usr/bin/node", cmdline="node a.js"),
        FakeProc(pid=9102, uid=8003, exe="/usr/bin/python3", cmdline="python3 worker.py"),
        FakeProc(pid=9103, uid=8003, exe="/usr/local/bin/gunicorn", cmdline="gunicorn app:app"),
    ]
    guard = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter(procs3))
    try:
        discovery = await bot._clearproses_discover_and_classify(account3)
    finally:
        guard.restore()
    assert discovery.status == process_cleanup.DISCOVERY_SUCCESS
    assert len(discovery.classified) == 3
    assert discovery.failures == []
    print("Scenario 3 (multiple processes -> SUCCESS, all classified) PASSED")

    account4 = make_account(uid=8004)
    parent4 = FakeProc(pid=9201, uid=8004, exe="/usr/bin/node", cmdline="node parent.js", ppid=1)
    child4 = FakeProc(pid=9202, uid=8004, exe="/usr/bin/node", cmdline="node child.js", ppid=9201)
    guard = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([parent4, child4]))
    try:
        discovery = await bot._clearproses_discover_and_classify(account4)
    finally:
        guard.restore()
    assert discovery.status == process_cleanup.DISCOVERY_SUCCESS
    pids4 = {c.pid for c in discovery.classified}
    assert pids4 == {9201, 9202}, "a child process owned by the same uid must be discovered alongside its parent"
    print("Scenario 4 (child process discovered alongside its parent) PASSED")

    account5 = make_account(uid=8005)
    orphan5 = FakeProc(pid=9301, uid=8005, exe="/usr/bin/node", cmdline="node orphan.js", ppid=1)
    guard = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([orphan5]))
    try:
        discovery = await bot._clearproses_discover_and_classify(account5)
    finally:
        guard.restore()
    assert discovery.status == process_cleanup.DISCOVERY_SUCCESS
    assert len(discovery.classified) == 1 and discovery.classified[0].pid == 9301
    print("Scenario 5 (orphan process, ppid=1 -> still discovered and classified) PASSED")

    account6 = make_account(uid=8006)
    ok6 = FakeProc(pid=9401, uid=8006, exe="/usr/bin/node", cmdline="node ok.js")
    vanished6 = FakeProc(pid=9402, uid=8006, exe="/usr/bin/node", cmdline="node vanished.js")

    def systemd_unit_raises_for_vanished(pid):
        if pid == 9402:
            raise ProcessLookupError("process vanished while reading /proc/9402/cgroup")
        return None

    guard_iter = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([ok6, vanished6]))
    guard_systemd = _PatchGuard(bot, "_clearproses_systemd_unit_for_pid", systemd_unit_raises_for_vanished)
    try:
        discovery = await bot._clearproses_discover_and_classify(account6)
    finally:
        guard_iter.restore()
        guard_systemd.restore()
    assert discovery.status == process_cleanup.DISCOVERY_PARTIAL_SUCCESS, discovery.status
    assert len(discovery.classified) == 2, "the vanished PID's process must still be reported, just without enrichment"
    assert len(discovery.failures) == 1 and discovery.failures[0].pid == 9402
    assert discovery.failures[0].exception_type == "ProcessLookupError"
    print("Scenario 6 (PID vanishes mid-enrichment -> PARTIAL_SUCCESS, not a total failure) PASSED")

    account7 = make_account(uid=8007)
    ok7 = FakeProc(pid=9501, uid=8007, exe="/usr/bin/node", cmdline="node ok.js")
    denied7 = FakeProc(pid=9502, uid=8007, exe="/usr/bin/node", cmdline="node denied.js")

    def systemd_unit_denied(pid):
        if pid == 9502:
            raise PermissionError("permission denied reading /proc/9502/cgroup")
        return None

    guard_iter = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([ok7, denied7]))
    guard_systemd = _PatchGuard(bot, "_clearproses_systemd_unit_for_pid", systemd_unit_denied)
    try:
        discovery = await bot._clearproses_discover_and_classify(account7)
    finally:
        guard_iter.restore()
        guard_systemd.restore()
    assert discovery.status == process_cleanup.DISCOVERY_PARTIAL_SUCCESS
    assert len(discovery.classified) == 2
    assert len(discovery.failures) == 1 and discovery.failures[0].exception_type == "PermissionError"
    print("Scenario 7 (permission denied on one PID -> logged and isolated, discovery continues) PASSED")

    account8 = make_account(uid=8008)
    procs8 = [
        FakeProc(pid=9601, uid=8008, exe="/usr/bin/node", cmdline="node a.js"),
        FakeProc(pid=9602, uid=8008, exe="/usr/bin/node", cmdline="node b.js"),
        FakeProc(pid=9603, uid=8008, exe="/usr/bin/node", cmdline="node c.js"),
    ]

    def systemd_unit_flaky(pid):
        if pid in (9601, 9603):
            raise OSError(f"transient failure for pid {pid}")
        return None

    guard_iter = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter(procs8))
    guard_systemd = _PatchGuard(bot, "_clearproses_systemd_unit_for_pid", systemd_unit_flaky)
    try:
        discovery = await bot._clearproses_discover_and_classify(account8)
    finally:
        guard_iter.restore()
        guard_systemd.restore()
    assert discovery.status == process_cleanup.DISCOVERY_PARTIAL_SUCCESS
    assert len(discovery.classified) == 3, "every resource must still surface even when 2 of 3 fail enrichment"
    assert len(discovery.failures) == 2
    assert {f.pid for f in discovery.failures} == {9601, 9603}
    print("Scenario 8 (partial discovery failure across multiple resources) PASSED")

    account9 = make_account(uid=8009, home="/nonexistent/no-pm2-user")
    proc9 = FakeProc(pid=9701, uid=8009, exe="/usr/bin/node", cmdline="node app.js")
    guard = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([proc9]))
    try:
        discovery = await bot._clearproses_discover_and_classify(account9)
    finally:
        guard.restore()
    assert discovery.status == process_cleanup.DISCOVERY_SUCCESS
    assert discovery.failures == [], "a user with no PM2 installed must not produce a discovery failure"
    assert discovery.classified[0].category != process_cleanup.CATEGORY_PM2
    print("Scenario 9 (PM2 not installed for user -> no crash, no false failure) PASSED")

    account10 = make_account(uid=8010, home="/tmp")
    proc10 = FakeProc(pid=9801, uid=8010, exe="/usr/bin/python3", cmdline="python3 worker.py")
    guard = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([proc10]))
    try:
        discovery = await bot._clearproses_discover_and_classify(account10)
    finally:
        guard.restore()
    assert discovery.status == process_cleanup.DISCOVERY_SUCCESS
    assert discovery.failures == []
    print("Scenario 10 (user home exists but has no .pm2 directory -> no crash) PASSED")

    account11 = make_account(uid=8011)
    proc11 = FakeProc(pid=9901, uid=8011, exe="/usr/bin/node", cmdline="node svc.js")
    guard_iter = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([proc11]))
    guard_systemd = _PatchGuard(bot, "_clearproses_systemd_unit_for_pid", lambda pid: "myapp-user.service")
    try:
        discovery = await bot._clearproses_discover_and_classify(account11)
    finally:
        guard_iter.restore()
        guard_systemd.restore()
    assert discovery.status == process_cleanup.DISCOVERY_SUCCESS
    assert discovery.classified[0].systemd_unit == "myapp-user.service"
    print("Scenario 11 (systemd user service resolved for an active process) PASSED")

    account12 = make_account(username="sessiononlyuser", uid=8012)
    fake_session = types.SimpleNamespace(name="sessiononlyuser")
    guard_iter = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([]))
    guard_users = _PatchGuard(psutil, "users", lambda: [fake_session, fake_session])
    try:
        discovery = await bot._clearproses_discover_and_classify(account12)
    finally:
        guard_iter.restore()
        guard_users.restore()
    assert discovery.session_count == 2
    assert discovery.status == process_cleanup.DISCOVERY_SUCCESS, (
        "an active login session must keep status out of NO_ACTIVE_RESOURCES even with zero processes"
    )
    print("Scenario 12 (active login session with zero processes -> not falsely reported clear) PASSED")

    account13 = make_account(uid=8013)
    proc13 = FakeProc(pid=9950, uid=8013, exe="/usr/bin/node", cmdline="node app.js", create_time=54321.5)
    guard = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([proc13]))
    try:
        discovery = await bot._clearproses_discover_and_classify(account13)
    finally:
        guard.restore()
    assert discovery.classified[0].record.create_time == 54321.5, (
        "discovery must preserve exact create_time so later phases can detect PID reuse"
    )
    print("Scenario 13 (discovery preserves create_time identity for later PID-reuse detection) PASSED")

    dirty_profile = {
        "system_account_reasons": [], "logged_in_sessions": [], "active_process_count": 1,
        "systemd_services": [],
    }
    assert RTSABot._deluser_hard_block_reasons(dirty_profile) == []
    process_blocks14 = RTSABot._deluser_process_block_reasons(dirty_profile)
    assert process_blocks14 and "proses aktif" in process_blocks14[0]
    print("Scenario 14 (/deluser still blocks on active resources -- security behavior unchanged) PASSED")

    account15 = make_account(uid=8015)
    proc15 = FakeProc(pid=9960, uid=8015, exe="/usr/bin/node", cmdline="node app.js")
    guard = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([proc15]))
    try:
        discovery = await bot._clearproses_discover_and_classify(account15)
    finally:
        guard.restore()
    eligible15 = [c for c in discovery.classified if c.eligible]
    assert discovery.status == process_cleanup.DISCOVERY_SUCCESS
    assert len(eligible15) == 1 and eligible15[0].pid == 9960
    print("Scenario 15 (/clearproses discovery succeeds, produces a correct eligible set) PASSED")

    account16 = make_account(uid=8016)
    guard = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([]))
    try:
        count16 = await RTSABot._deluser_engine_count_processes(account16.pw_uid)
    finally:
        guard.restore()
    assert count16 == 0, "after cleanup, /deluser's independent fresh discovery must see zero active processes"
    print("Scenario 16 (/deluser fresh re-discovery after cleanup sees zero processes) PASSED")

    account17 = make_account(uid=8017)

    def protected_usernames_raises():
        raise RuntimeError("config.modules.host_persistence_detector unexpectedly None")

    guard_iter = _PatchGuard(psutil, "process_iter", lambda attrs=None: iter([]))
    guard_protected = _PatchGuard(bot, "_clearproses_protected_usernames", protected_usernames_raises)
    try:
        discovery = await bot._clearproses_discover_and_classify(account17)
    finally:
        guard_iter.restore()
        guard_protected.restore()
    assert discovery.status == process_cleanup.DISCOVERY_FAILED
    assert len(discovery.failures) == 1
    assert discovery.failures[0].stage == "core_discovery"
    assert discovery.failures[0].exception_type == "RuntimeError"
    assert "host_persistence_detector" in discovery.failures[0].exception_message, (
        "the real exception detail must be captured server-side (structured), not just a generic label"
    )
    print("Scenario 17 (genuine core-discovery failure -> DISCOVERY_FAILED with structured detail, no bare swallow) PASSED")

    print("\nALL /clearproses DISCOVERY RESILIENCE TESTS PASSED")


asyncio.run(main())
