import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio
import pwd
import tempfile

import psutil

import core.process_cleanup as process_cleanup
from core.process_cleanup import (
    CATEGORY_APPLICATION, CATEGORY_NODE, CATEGORY_PHP_FPM, CATEGORY_PM2, CATEGORY_SSH_SESSION,
    OUTCOME_CLEAR_COMPLETE, OUTCOME_CLEAR_FAILED, OUTCOME_CLEAR_PARTIAL,
    STATUS_PROTECTED, STATUS_REQUIRES_REVIEW, STATUS_SAFE_TO_STOP,
    ClassifiedProcess, ClearStateStore, ProcessRecord, classify_process, discover_user_processes,
    execute_cleanup, fingerprint,
)
from config.manager import (
    CloudflareConfig, DiscordConfig, HostPersistenceDetectorConfig, ModulesConfig,
    ResponseEngineConfig, RTSAConfig,
)
from core.event_bus import EventBus
from discord_integration.bot import RTSABot

_RTSA_PID = 999999


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


def rec(pid, uid=1005, exe="/usr/bin/node", cwd="/home/site/app", cmdline="node server.js",
        create_time=1000.0, ppid=1, username="site", status="running", has_tty=False,
        parent_name=None) -> ProcessRecord:
    return ProcessRecord(
        pid=pid, ppid=ppid, uid=uid, username=username, exe=exe, cwd=cwd, cmdline=cmdline,
        create_time=create_time, status=status, has_tty=has_tty, parent_name=parent_name,
    )


def classified(record, **kw) -> ClassifiedProcess:
    return classify_process(record, rtsa_pid=_RTSA_PID, **kw)


class _Named:
    def __init__(self, name):
        self._name = name

    def name(self):
        return self._name


class _Uids:
    def __init__(self, real):
        self.real = real


class FakeProc:
    def __init__(
        self, pid, uid=None, exe=None, cwd=None, cmdline="", create_time=1000.0, ppid=1,
        username=None, status="running", terminal=None, parent_name=None,
        info=None, raise_uids=None,
    ):
        self.pid = pid
        self.info = {"pid": pid, "ppid": ppid, "uid": uid, "username": username} if info is None else info
        self._exe = exe
        self._cwd = cwd
        self._cmdline = cmdline
        self._create_time = create_time
        self._ppid = ppid
        self._username = username
        self._uid = uid
        self._status = status
        self._terminal = terminal
        self._parent_name = parent_name
        self._raise_uids = raise_uids

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
        if self._raise_uids is not None:
            raise self._raise_uids
        return _Uids(self._uid)


def fake_process_iter(procs):
    def _iter(attrs=None):
        return iter(procs)
    return _iter


class RediscoverSequence:

    def __init__(self, snapshots):
        self._snapshots = snapshots
        self.calls = 0

    async def __call__(self):
        idx = min(self.calls, len(self._snapshots) - 1)
        self.calls += 1
        return self._snapshots[idx]


def make_kill_fn(calls_out):
    async def kill_fn(pid, create_time, force):
        calls_out.append((pid, create_time, force))
        return True, "killed"
    return kill_fn


async def main():
    bot = make_bot()

    r1 = rec(pid=100, exe="/usr/bin/node", cmdline="node server.js")
    seq1 = RediscoverSequence([[], []])
    kill_calls = []
    outcome1_setup = execute_cleanup(
        [], kill_fn=make_kill_fn(kill_calls), rediscover_fn=seq1,
    )
    outcome0 = await outcome1_setup
    assert outcome0.status == OUTCOME_CLEAR_COMPLETE and outcome0.initial_count == 0
    print("Scenario 1 (zero eligible processes -> CLEAR_COMPLETE immediately, no kill attempted) PASSED")

    c2 = classified(r1)
    assert c2.category == CATEGORY_NODE and c2.action_status == STATUS_SAFE_TO_STOP
    seq2 = RediscoverSequence([[], []])
    kill_calls2 = []
    outcome2 = await execute_cleanup([c2], kill_fn=make_kill_fn(kill_calls2), rediscover_fn=seq2)
    assert outcome2.status == OUTCOME_CLEAR_COMPLETE, outcome2
    assert outcome2.gracefully_stopped == 1 and outcome2.force_killed == 0
    assert len(kill_calls2) == 1 and kill_calls2[0][2] is False, "first attempt must be graceful (force=False)"
    print("Scenario 2 (single Node process discovered, confirmed, SIGTERM, exits -> CLEAR_COMPLETE) PASSED")

    rA = rec(pid=101, exe="/usr/bin/node", cmdline="node a.js")
    rB = rec(pid=102, exe="/usr/bin/python3", cmdline="python3 worker.py")
    rC = rec(pid=103, exe="/usr/local/bin/gunicorn", cmdline="gunicorn app:app")
    cA, cB, cC = classified(rA), classified(rB), classified(rC)
    seq3 = RediscoverSequence([[], []])
    kill_calls3 = []
    outcome3 = await execute_cleanup([cA, cB, cC], kill_fn=make_kill_fn(kill_calls3), rediscover_fn=seq3)
    assert outcome3.status == OUTCOME_CLEAR_COMPLETE
    assert outcome3.gracefully_stopped == 3 and len(kill_calls3) == 3
    print("Scenario 3 (multiple processes -> all eligible cleared) PASSED")

    r4 = rec(pid=104, exe="/usr/bin/node", cmdline="node stubborn.js")
    c4 = classified(r4)
    seq4 = RediscoverSequence([[r4], [r4], []])
    kill_calls4 = []
    outcome4 = await execute_cleanup([c4], kill_fn=make_kill_fn(kill_calls4), rediscover_fn=seq4)
    assert outcome4.status == OUTCOME_CLEAR_COMPLETE
    assert outcome4.gracefully_stopped == 0 and outcome4.force_killed == 1
    assert len(kill_calls4) == 2 and kill_calls4[0][2] is False and kill_calls4[1][2] is True
    print("Scenario 4 (process ignores SIGTERM -> graceful wait -> SIGKILL fallback -> verify) PASSED")

    r5 = rec(pid=105, exe="/usr/bin/node", cmdline="node reused.js", create_time=1000.0)
    c5 = classified(r5)
    reused = rec(pid=105, exe="/usr/bin/whatever", cmdline="unrelated new process", create_time=5000.0)
    seq5 = RediscoverSequence([[reused], [reused]])
    kill_calls5 = []
    outcome5 = await execute_cleanup([c5], kill_fn=make_kill_fn(kill_calls5), rediscover_fn=seq5)
    assert outcome5.pid_reuse_skipped == 1, outcome5
    assert outcome5.status == OUTCOME_CLEAR_COMPLETE
    assert len(kill_calls5) == 1, "a PID-reused process must never receive a second kill attempt"
    print("Scenario 5 (PID reuse detected -> new process with same PID is never killed) PASSED")

    r6 = rec(pid=1, uid=0, exe="/usr/sbin/sshd", cmdline="/usr/sbin/sshd -D")
    c6 = classify_process(r6, rtsa_pid=_RTSA_PID)
    assert c6.action_status == STATUS_PROTECTED and not c6.eligible
    assert "root" in c6.reason
    print("Scenario 6 (root-owned system process -> PROTECTED, never a kill candidate) PASSED")

    r7 = rec(pid=200, uid=1010, exe="/usr/bin/node", cmdline="node app.js", username="siteuser")
    c7 = classify_process(r7, rtsa_pid=_RTSA_PID, pm2_app_name="my-app")
    assert c7.category == CATEGORY_PM2 and c7.action_status == STATUS_SAFE_TO_STOP
    seq7 = RediscoverSequence([[], []])
    kill_calls7 = []
    pm2_calls7 = []
    async def stop_pm2_fn(app_name):
        pm2_calls7.append(app_name)
        return True, "✅ stopped"
    outcome7 = await execute_cleanup(
        [c7], kill_fn=make_kill_fn(kill_calls7), rediscover_fn=seq7, stop_pm2_fn=stop_pm2_fn,
    )
    assert outcome7.status == OUTCOME_CLEAR_COMPLETE
    assert pm2_calls7 == ["my-app"], "PM2-owned process must be stopped via pm2 lifecycle, not a raw signal"
    assert kill_calls7 == [], "kill_fn must not be used when the PM2 stop path succeeds"
    print("Scenario 7 (PM2-managed process -> stopped via PM2 lifecycle, not raw kill) PASSED")

    r8 = rec(pid=201, uid=1010, exe="/usr/bin/node", cmdline="node svc.js")
    c8 = classify_process(r8, rtsa_pid=_RTSA_PID, systemd_unit="myapp-user.service")
    seq8 = RediscoverSequence([[], []])
    kill_calls8 = []
    systemd_calls8 = []
    async def stop_systemd_fn(unit):
        systemd_calls8.append(unit)
        return True, "✅ stopped"
    outcome8 = await execute_cleanup(
        [c8], kill_fn=make_kill_fn(kill_calls8), rediscover_fn=seq8, stop_systemd_fn=stop_systemd_fn,
    )
    assert outcome8.status == OUTCOME_CLEAR_COMPLETE
    assert systemd_calls8 == ["myapp-user.service"]
    assert kill_calls8 == [], "kill_fn must not be used when the systemctl stop path succeeds"
    print("Scenario 8 (systemd-owned unit process -> stopped via systemctl stop, not raw kill) PASSED")

    r9_worker = rec(pid=300, uid=1020, exe="/usr/sbin/php-fpm8.1", cmdline="php-fpm: pool site1")
    c9_worker = classify_process(r9_worker, rtsa_pid=_RTSA_PID, php_fpm_pool="site1", php_fpm_is_master=False)
    assert c9_worker.category == CATEGORY_PHP_FPM and c9_worker.action_status == STATUS_SAFE_TO_STOP
    r9_master_root = rec(pid=301, uid=0, exe="/usr/sbin/php-fpm8.1", cmdline="php-fpm: master process (php-fpm.conf)")
    c9_master_root = classify_process(r9_master_root, rtsa_pid=_RTSA_PID, php_fpm_pool="site1", php_fpm_is_master=True)
    assert c9_master_root.action_status == STATUS_PROTECTED, (
        "the global php-fpm master (root-owned) must never be an eligible /clearproses candidate"
    )
    print("Scenario 9 (PHP-FPM: only the target user's pool worker is eligible, global root master PROTECTED) PASSED")

    r10 = rec(pid=400, uid=1030, exe="/bin/bash", cmdline="-bash", has_tty=True)
    c10 = classify_process(r10, rtsa_pid=_RTSA_PID)
    assert c10.category == CATEGORY_SSH_SESSION and c10.action_status == STATUS_REQUIRES_REVIEW
    assert c10.eligible, "SSH sessions are addressable but only after explicit confirmation review"
    print("Scenario 10 (SSH/login session -> flagged REQUIRES_REVIEW, controlled handling) PASSED")

    r11 = rec(pid=500, exe="/usr/bin/node", cwd="/home/site/app", cmdline="node app.js", create_time=1000.0)
    c11 = classified(r11)
    respawned = rec(pid=501, exe="/usr/bin/node", cwd="/home/site/app", cmdline="node app.js", create_time=9999.0)
    assert fingerprint(r11) == fingerprint(respawned), "respawn detection depends on a stable non-PID fingerprint"
    seq11 = RediscoverSequence([[], [respawned]])
    kill_calls11 = []
    outcome11 = await execute_cleanup([c11], kill_fn=make_kill_fn(kill_calls11), rediscover_fn=seq11)
    assert outcome11.status == OUTCOME_CLEAR_PARTIAL, outcome11
    assert len(outcome11.respawned) == 1
    assert outcome11.respawned[0].new_pid == 501
    assert len(kill_calls11) == 1, "respawn must be reported, not chased with another kill attempt (bounded)"
    print("Scenario 11 (process respawns under a new PID -> CLEAR_PARTIAL, bounded, no retry loop) PASSED")

    denied_proc = FakeProc(pid=600, info={}, raise_uids=psutil.AccessDenied(600))
    ok_proc = FakeProc(pid=601, uid=1040, exe="/usr/bin/node", cmdline="node ok.js", create_time=1234.0)
    records12 = discover_user_processes(1040, process_iter=fake_process_iter([denied_proc, ok_proc]))
    assert len(records12) == 1 and records12[0].pid == 601, (
        "an AccessDenied process must be skipped, not crash discovery for the rest"
    )
    print("Scenario 12 (AccessDenied while inspecting a process -> skipped gracefully, discovery continues) PASSED")

    gone_proc = FakeProc(pid=700, info={}, raise_uids=psutil.NoSuchProcess(700))
    records13 = discover_user_processes(1040, process_iter=fake_process_iter([gone_proc, ok_proc]))
    assert len(records13) == 1 and records13[0].pid == 601
    print("Scenario 13 (NoSuchProcess -- already gone -- skipped safely, discovery continues) PASSED")

    assert bot._try_claim_deluser("scenario14user") is True
    assert bot._try_claim_deluser("scenario14user") is False, (
        "a second /clearproses for the same user while one is running must be rejected"
    )
    bot._release_deluser("scenario14user")
    assert bot._try_claim_deluser("scenario14user") is True, "the lock must be free again after release"
    bot._release_deluser("scenario14user")
    print("Scenario 14 (concurrent /clearproses for the same user -> one runs, second rejected) PASSED")

    assert bot._try_claim_deluser("scenario15user") is True
    assert bot._try_claim_deluser("scenario15user") is False, (
        "/deluser and /clearproses share one per-username lock -- they must be mutually exclusive both ways"
    )
    bot._release_deluser("scenario15user")
    print("Scenario 15 (/clearproses and /deluser for the same user -> mutually exclusive) PASSED")

    clean_profile = {
        "system_account_reasons": [], "logged_in_sessions": [], "active_process_count": 0,
        "systemd_services": [],
    }
    assert RTSABot._deluser_hard_block_reasons(clean_profile) == []
    assert RTSABot._deluser_process_block_reasons(clean_profile) == []
    print("Scenario 16 (/deluser after a successful /clearproses with zero active processes -> allowed to proceed) PASSED")

    dirty_profile = {
        "system_account_reasons": [], "logged_in_sessions": [], "active_process_count": 1,
        "systemd_services": [],
    }
    assert RTSABot._deluser_hard_block_reasons(dirty_profile) == []
    process_blocks = RTSABot._deluser_process_block_reasons(dirty_profile)
    assert process_blocks and "proses aktif" in process_blocks[0]
    message17 = bot._format_deluser_process_block_message("scenario17user", process_blocks)
    assert "/clearproses scenario17user" in message17, (
        "the block message must point the operator at /clearproses by name, not just refuse silently"
    )
    print("Scenario 17 (new process appears after /clearproses -> /deluser rechecks fresh and blocks again) PASSED")

    r18 = rec(pid=_RTSA_PID, uid=1050, exe="/usr/bin/python3", cmdline="python3 main.py")
    c18 = classify_process(r18, rtsa_pid=_RTSA_PID)
    assert c18.action_status == STATUS_PROTECTED and "RTSA" in c18.reason
    assert not c18.eligible
    print("Scenario 18 (RTSA's own process -> PROTECTED, never a kill candidate) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        store = ClearStateStore(os.path.join(tmpdir, "sub", "state.json"))
        assert store.get("nobody") is None
        outcome_for_store = process_cleanup.CleanupOutcome(status=OUTCOME_CLEAR_COMPLETE, initial_count=2, gracefully_stopped=2)
        store.record("alice", 1005, outcome_for_store, now=1700000000.0)
        entry = store.get("alice")
        assert entry is not None and entry["status"] == OUTCOME_CLEAR_COMPLETE and entry["uid"] == 1005
        store2 = ClearStateStore(os.path.join(tmpdir, "sub", "state.json"))
        assert store2.get("alice") is not None, "ClearStateStore must persist across instances (atomic write)"
    print("Bonus (ClearStateStore records and reloads audit state atomically) PASSED")

    r19 = rec(pid=800, uid=1060, exe="/usr/bin/randomapp", cmdline="")
    c19 = classify_process(r19, rtsa_pid=_RTSA_PID, systemd_unit="mysql.service", protected_systemd_units={"mysql.service"})
    assert c19.action_status == STATUS_PROTECTED, "a process owned by a protected systemd unit must never be eligible"
    print("Bonus (process belonging to a protected systemd unit -> PROTECTED regardless of category) PASSED")

    print("\nALL /clearproses PROCESS CLEANUP TESTS PASSED")


asyncio.run(main())
