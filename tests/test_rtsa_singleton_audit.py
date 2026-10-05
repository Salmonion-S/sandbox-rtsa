import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from core import singleton_audit as sa
from core.instance_lock import (
    EXIT_ALREADY_RUNNING, SingleInstanceLock, find_lock_holders, parse_lock_content, parse_proc_locks, proc_start_ticks,
    read_lock_holder, verify_holder,
)

ENGINE = (
    "import os, sys, time\n"
    f"sys.path.insert(0, {_REPO_ROOT!r})\n"
    "from core.instance_lock import EXIT_ALREADY_RUNNING, InstanceAlreadyRunning, SingleInstanceLock\n"
    "mode = sys.argv[1] if len(sys.argv) > 1 else 'engine'\n"
    "if mode == '--check':\n"
    "    print('CHECK', flush=True)\n"
    "    time.sleep(60)\n"
    "    sys.exit(0)\n"
    "lock = SingleInstanceLock(os.environ['RTSA_LOCK_PATH'])\n"
    "try:\n"
    "    lock.acquire()\n"
    "except InstanceAlreadyRunning:\n"
    "    sys.exit(EXIT_ALREADY_RUNNING)\n"
    "if mode == 'fork':\n"
    "    if os.fork() == 0:\n"
    "        print('CHILD', flush=True)\n"
    "        time.sleep(60)\n"
    "        sys.exit(0)\n"
    "if mode == 'forkfd':\n"
    "    if os.fork() == 0:\n"
    "        print('CHILD', flush=True)\n"
    "        time.sleep(60)\n"
    "        sys.exit(0)\n"
    "print('LOCKED', flush=True)\n"
    "time.sleep(60)\n"
)

CLOSE_FD_CHILD = ENGINE.replace(
    "if mode == 'fork':\n    if os.fork() == 0:\n        print('CHILD', flush=True)\n",
    "if mode == 'fork':\n    if os.fork() == 0:\n        os.close(lock._fd)\n        print('CHILD', flush=True)\n",
)


class Lab:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="rtsa_sing_")
        self.install = os.path.join(self.root, "rtsa")
        self.other = os.path.join(self.root, "disdik_app")
        self.lock = os.path.join(self.root, "data", "rtsa.lock")
        os.makedirs(self.install)
        os.makedirs(self.other)
        os.makedirs(os.path.dirname(self.lock))
        self.main = os.path.join(self.install, "main.py")
        with open(self.main, "w") as handle:
            handle.write(CLOSE_FD_CHILD)
        with open(os.path.join(self.other, "main.py"), "w") as handle:
            handle.write("import time\ntime.sleep(60)\n")
        self.procs = []

    def start(self, *args, lock=None, script=None, cwd=None, wait_line="LOCKED"):
        env = dict(os.environ, RTSA_LOCK_PATH=lock or self.lock)
        argv = [sys.executable, script or self.main, *args]
        proc = subprocess.Popen(argv, env=env, cwd=cwd or self.install, stdout=subprocess.PIPE, text=True, start_new_session=True)
        self.procs.append(proc)
        if wait_line:
            assert proc.stdout.readline().strip() == wait_line
        return proc

    def audit(self, **kwargs):
        options = dict(grace_seconds=0.0, cpu_sample_seconds=0.2, use_systemctl=False, scan_schedule_sources=False)
        options.update(kwargs)
        return sa.audit(self.main, self.lock, **options)

    def cleanup(self):
        for proc in self.procs:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.SubprocessError:
                pass
        shutil.rmtree(self.root, ignore_errors=True)


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def test_1_single_engine_passes_with_verified_lock_file():
    lab = Lab()
    try:
        proc = lab.start()
        report = lab.audit()
        assert report.status == sa.STATUS_PASS, report.render()
        assert report.legitimate_pid == proc.pid and report.duplicate_count == 0
        assert report.lock_holders == [proc.pid]
        assert report.lock_file.pid == proc.pid and report.lock_file.verified is True
        lines = report.summary_lines()
        assert [line.split("=")[0] for line in lines] == [
            "RTSA_SINGLETON_STATUS", "LEGITIMATE_PID", "DUPLICATE_COUNT", "SERVICE", "LOCK_STATUS", "CPU_OVERHEAD",
        ]
        assert "cpu" in report.cpu_overhead and "HELD by pid(s)" in report.lock_status
        assert "start-time verified" in report.lock_status
    finally:
        lab.cleanup()
    print("Test 1 (one engine holding the flock: PASS, legitimate pid, verified start time, six-line summary block) PASSED")


def test_2_second_launch_is_rejected_with_a_distinct_exit_code_and_changes_nothing():
    lab = Lab()
    try:
        holder = lab.start()
        before = open(lab.lock).read()
        started = time.monotonic()
        second = subprocess.run(
            [sys.executable, lab.main], env=dict(os.environ, RTSA_LOCK_PATH=lab.lock), cwd=lab.install, capture_output=True, text=True, timeout=20,
        )
        elapsed = time.monotonic() - started
        assert second.returncode == EXIT_ALREADY_RUNNING == 75
        assert open(lab.lock).read() == before and alive(holder.pid)
        assert lab.audit().status == sa.STATUS_PASS
        assert elapsed < 10.0
    finally:
        lab.cleanup()
    print("Test 2 (a second launch exits 75 without touching the lock or the holder; the audit still says PASS) PASSED")


def test_3_duplicate_with_another_lock_path_is_flagged_and_never_killed():
    lab = Lab()
    try:
        holder = lab.start()
        rogue = lab.start(lock=os.path.join(lab.root, "data", "other.lock"))
        report = lab.audit()
        assert report.status == sa.STATUS_FAIL, report.render()
        assert report.duplicate_count == 1 and report.legitimate_pid == holder.pid
        dup = [p for p in report.processes if p.role == sa.ROLE_DUPLICATE]
        assert dup[0].record.pid == rogue.pid and dup[0].reason == sa.REASON_DIFFERENT_LOCK
        assert alive(holder.pid) and alive(rogue.pid), "the audit must never signal a process"
        assert "DIFFERENT_LOCK_PATH" in report.reason
        assert read_lock_holder(lab.lock).pid == holder.pid
    finally:
        lab.cleanup()
    print("Test 3 (an engine running with another RTSA_LOCK_PATH is reported as DUPLICATE/DIFFERENT_LOCK_PATH, nothing is killed) PASSED")


def test_4_wrappers_readiness_checks_workers_and_other_projects_are_not_duplicates():
    lab = Lab()
    try:
        proc = subprocess.Popen(
            ["bash", "-c", f"{sys.executable} {lab.main} fork; echo finished"],
            env=dict(os.environ, RTSA_LOCK_PATH=lab.lock), cwd=lab.install, stdout=subprocess.PIPE, text=True, start_new_session=True,
        )
        lab.procs.append(proc)
        first = proc.stdout.readline()
        assert "LOCKED" in first or "CHILD" in first, repr(first)
        deadline = time.time() + 10
        while time.time() < deadline and find_lock_holders(lab.lock) in (None, []):
            time.sleep(0.05)
        time.sleep(0.4)
        lab.start("--check", wait_line="CHECK")
        lab.start(script=os.path.join(lab.other, "main.py"), cwd=lab.other, wait_line=None)
        time.sleep(0.2)
        report = lab.audit()
        roles = {p.record.pid: p.role for p in report.processes}
        assert report.status == sa.STATUS_PASS, report.render()
        assert report.duplicate_count == 0
        assert sorted(set(roles.values())) == sorted({sa.ROLE_WRAPPER, sa.ROLE_LEGITIMATE, sa.ROLE_WORKER, sa.ROLE_READINESS}), roles
        assert not any(lab.other in " ".join(p.record.argv) for p in report.processes), "another project's main.py must not be considered"
    finally:
        lab.cleanup()
    print("Test 4 (bash wrapper, --check readiness run, forked worker and another project's main.py are classified, none counted as a duplicate) PASSED")


def test_5_inherited_lock_fd_keeps_the_lock_alive_and_is_flagged():
    lab = Lab()
    try:
        with open(lab.main, "w") as handle:
            handle.write(ENGINE)
        parent = lab.start("forkfd")
        child_line = parent.stdout.readline()
        time.sleep(0.4)
        children = [r.pid for r in sa.snapshot_processes() if r.ppid == parent.pid]
        assert children
        report = lab.audit()
        assert report.status == sa.STATUS_FAIL, report.render()
        assert [p.record.pid for p in report.processes if p.role == sa.ROLE_INHERITOR] == children
        parent.kill()
        parent.wait(timeout=5)
        time.sleep(0.3)
        report = lab.audit()
        assert find_lock_holders(lab.lock), "the child keeps the flock after the parent died"
        assert report.status == sa.STATUS_FAIL and "inherited" in report.reason
        retry = subprocess.run([sys.executable, lab.main], env=dict(os.environ, RTSA_LOCK_PATH=lab.lock), cwd=lab.install, timeout=20)
        assert retry.returncode == EXIT_ALREADY_RUNNING
        assert child_line is not None
    finally:
        lab.cleanup()
    print("Test 5 (a forked child that inherited the lock fd keeps the lock after the holder dies: flagged as LOCK_INHERITOR, the exact orphan hazard) PASSED")


def test_6_crash_leaves_no_permanent_lock_and_restart_is_audited():
    lab = Lab()
    try:
        first = lab.start()
        os.kill(first.pid, signal.SIGKILL)
        first.wait(timeout=5)
        stale = lab.audit()
        assert stale.status == sa.STATUS_BLOCKED and "FREE" in stale.lock_status and stale.legitimate_pid is None
        assert read_lock_holder(lab.lock).alive is False
        second = lab.start()
        report = lab.audit()
        assert report.status == sa.STATUS_PASS and report.legitimate_pid == second.pid != first.pid
    finally:
        lab.cleanup()
    print("Test 6 (kill -9 leaves a FREE lock, the audit says BLOCKED/no instance, a restart acquires it and audits PASS with the new pid) PASSED")


def test_7_pid_reuse_is_detected_with_the_recorded_start_time():
    me = os.getpid()
    ticks = proc_start_ticks(me)
    assert ticks is not None and ticks > 0
    assert verify_holder(me, ticks).verified is True
    reused = verify_holder(me, ticks + 12345)
    assert reused.alive is True and reused.verified is False
    assert verify_holder(2 ** 22 + 7, 5).alive is False
    assert parse_lock_content("123 456\n") == (123, 456) and parse_lock_content("123") == (123, None) and parse_lock_content("junk") == (None, None)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "rtsa.lock")
        lock = SingleInstanceLock(path)
        lock.acquire()
        try:
            content = open(path).read().split()
            assert content[0] == str(me) and int(content[1]) == ticks
            with open(path, "w") as handle:
                handle.write(f"{me} {ticks + 1}\n")
            assert read_lock_holder(path).verified is False
            fd = os.open(path, os.O_RDWR)
            try:
                assert SingleInstanceLock._read_pid(fd) is None
            finally:
                os.close(fd)
        finally:
            lock.release()
    print("Test 7 (the lock file records pid + process start time: a reused pid or tampered start time is not trusted as the holder) PASSED")


def test_8_proc_locks_parser_matches_device_and_inode_only():
    sample = (
        "1: FLOCK  ADVISORY  WRITE 475 fe:00:2031738 0 EOF\n"
        "2: FLOCK  ADVISORY  READ 12 fe:00:999 0 EOF\n"
        "3: POSIX  ADVISORY  WRITE 9 fe:00:2031738 0 EOF\n"
        "4: -> FLOCK  ADVISORY  WRITE 77 fe:00:2031738 0 EOF\n"
        "5: FLOCK  ADVISORY  WRITE 475 fe:00:2031738 0 EOF\n"
        "6: FLOCK  ADVISORY  WRITE 88 08:01:2031738 0 EOF\n"
    )
    assert parse_proc_locks(sample, "fe:00", 2031738) == [475]
    assert parse_proc_locks(sample, "08:01", 2031738) == [88]
    assert parse_proc_locks(sample, "fe:00", 5) == []
    assert parse_proc_locks("", "fe:00", 1) == [] and parse_proc_locks("garbage line\n\n", "fe:00", 1) == []
    print("Test 8 (/proc/locks parsing: FLOCK only, exact device:inode, waiters and POSIX locks ignored, no duplicates) PASSED")


def test_9_launch_in_flight_is_not_a_duplicate_and_read_only_guarantees():
    lab = Lab()
    try:
        holder = lab.start()
        rogue = lab.start(lock=os.path.join(lab.root, "data", "late.lock"))
        before = os.stat(lab.lock)
        report = lab.audit(grace_seconds=3600.0)
        assert report.status == sa.STATUS_PASS and report.duplicate_count == 0
        assert [p.role for p in report.processes if p.record.pid == rogue.pid] == [sa.ROLE_IN_FLIGHT]
        after = os.stat(lab.lock)
        assert (before.st_mtime_ns, before.st_ino, before.st_size) == (after.st_mtime_ns, after.st_ino, after.st_size)
        assert alive(holder.pid) and alive(rogue.pid)
        assert find_lock_holders(lab.lock) == [holder.pid], "the audit must not have acquired the lock"
    finally:
        lab.cleanup()
    print("Test 9 (a young non-holder is LAUNCH_IN_FLIGHT, not a duplicate; the audit leaves the lock file, the lock and every process untouched) PASSED")


def test_10_unrecognized_holder_and_unreadable_proc_are_blocked_not_guessed():
    lab = Lab()
    try:
        holder = lab.start()
        elsewhere = os.path.join(lab.root, "elsewhere", "main.py")
        os.makedirs(os.path.dirname(elsewhere))
        report = sa.audit(elsewhere, lab.lock, grace_seconds=0.0, cpu_sample_seconds=0.1, use_systemctl=False, scan_schedule_sources=False)
        assert report.status == sa.STATUS_BLOCKED and "no process matching" in report.reason and report.legitimate_pid is None
        assert report.lock_holders == [holder.pid]
        missing = sa.audit(lab.main, lab.lock, proc_root="/nonexistent_proc", use_systemctl=False, scan_schedule_sources=False)
        assert missing.status == sa.STATUS_BLOCKED and missing.lock_status == "UNREADABLE"
    finally:
        lab.cleanup()
    print("Test 10 (a held lock whose process cannot be matched, or an unreadable /proc, is BLOCKED with the reason instead of a guess) PASSED")


def test_11_schedule_sources_and_unit_are_reported_read_only():
    with tempfile.TemporaryDirectory() as tmp:
        cron = os.path.join(tmp, "rtsa-cron")
        with open(cron, "w") as handle:
            handle.write("# */5 * * * * root python3 /opt/security/rtsa/main.py\n*/5 * * * * root /usr/bin/python3 /opt/security/rtsa/main.py\n")
        hits = sa.scan_schedules("/opt/security/rtsa/main.py", files=(cron,), dirs=())
        assert len(hits) == 1 and ":2:" in hits[0], hits
        assert sa.scan_schedules("/opt/security/rtsa/main.py", files=(), dirs=("/nonexistent",)) == []
    assert sa._systemctl_show("bad name; rm -rf /", 1.0) == {}
    unit, owner = sa._unit_from_cgroup("0::/system.slice/rtsa.service\n")
    assert (unit, owner) == ("rtsa.service", sa.OWNER_SYSTEMD)
    unit, owner = sa._unit_from_cgroup("0::/user.slice/user-0.slice/session-12.scope\n")
    assert (unit, owner) == ("", sa.OWNER_MANUAL)
    print("Test 11 (cron/systemd references are listed read-only, comments ignored; cgroup lineage maps to a unit or a manual session; hostile unit names never reach systemctl) PASSED")


def test_12_main_wiring_and_unit_policy():
    source = open(os.path.join(_REPO_ROOT, "main.py")).read()
    assert "--singleton-audit" in source and "run_singleton_audit" in source
    audit_branch = source[source.index("if args.singleton_audit:"):source.index("if args.check:")]
    assert "SingleInstanceLock" not in audit_branch and "lock.acquire" not in audit_branch
    unit = open(os.path.join(_REPO_ROOT, "deploy", "rtsa.service")).read()
    assert "RestartPreventExitStatus=75" in unit and unit.count("ExecStart=") == 1
    audit_source = open(os.path.join(_REPO_ROOT, "core", "singleton_audit.py")).read()
    for forbidden in ("os.kill", "signal.", "killpg", ".terminate(", ".kill(", "fcntl", "shell=True"):
        assert forbidden not in audit_source, f"the audit must stay read-only: {forbidden}"
    print("Test 12 (--singleton-audit never acquires the lock; the audit module has no kill/signal/flock/shell; the unit does not respawn a rejected duplicate) PASSED")


def main():
    test_1_single_engine_passes_with_verified_lock_file()
    test_2_second_launch_is_rejected_with_a_distinct_exit_code_and_changes_nothing()
    test_3_duplicate_with_another_lock_path_is_flagged_and_never_killed()
    test_4_wrappers_readiness_checks_workers_and_other_projects_are_not_duplicates()
    test_5_inherited_lock_fd_keeps_the_lock_alive_and_is_flagged()
    test_6_crash_leaves_no_permanent_lock_and_restart_is_audited()
    test_7_pid_reuse_is_detected_with_the_recorded_start_time()
    test_8_proc_locks_parser_matches_device_and_inode_only()
    test_9_launch_in_flight_is_not_a_duplicate_and_read_only_guarantees()
    test_10_unrecognized_holder_and_unreadable_proc_are_blocked_not_guessed()
    test_11_schedule_sources_and_unit_are_reported_read_only()
    test_12_main_wiring_and_unit_policy()
    print("\nALL RTSA SINGLETON AUDIT TESTS PASSED")


if __name__ == "__main__":
    main()
