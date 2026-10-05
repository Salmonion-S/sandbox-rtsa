import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _ssh_logout_fakes import FP, LOGIN_AT, SSH_PORT, FrozenClock, accepted, by_cat, fields_of, make_monitor
from config.manager import ActorCorrelationConfig, AuditMonitorConfig, FileIntegrityDetectorConfig
from core import actor_correlation as ac
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.pipeline_metrics import get_actor_metrics
from modules.audit_monitor import AuditMonitor
from modules.file_integrity_detector import FileIntegrityDetector

T0 = 1_800_000_000.0
_SEQ = [0]


class Clock:
    def __init__(self, t=T0 + 5000.0):
        self.t = t

    def __call__(self):
        return self.t


def make(clock=None, sessions=None, alive=None, units=None, **cfg):
    clock = clock or Clock()
    correlator = ac.ActorCorrelator()
    correlator.configure(ActorCorrelationConfig(**cfg), clock=clock)
    correlator.set_session_provider(lambda: list(sessions or []))
    alive = alive if alive is not None else {}
    correlator.set_probes(start_time=lambda pid: alive.get(pid), cgroup=lambda pid: (units or {}).get(pid, (None, None)))
    return correlator, clock


def block(kind, pid, ppid, auid, uid, euid, exe, argv, t, ses="3", key="(null)", paths=()):
    _SEQ[0] += 1
    n = _SEQ[0]
    comm = os.path.basename(exe)
    lines = ["----"]
    if kind == "exec":
        lines.append(
            f"type=SYSCALL msg=audit({t:.3f}:{n}): arch=c000003e syscall=execve success=yes exit=0 a0=55 items=2 ppid={ppid} pid={pid} "
            f"auid={auid} uid={uid} gid=root euid={euid} suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses={ses} "
            f'comm="{comm}" exe="{exe}" key={key}'
        )
        args = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
        lines.append(f"type=EXECVE msg=audit({t:.3f}:{n}): argc={len(argv)} {args}")
        lines.append(f'type=CWD msg=audit({t:.3f}:{n}): cwd="/home/{auid}"')
        lines.append(f'type=PATH msg=audit({t:.3f}:{n}): item=0 name="{exe}" inode=1 dev=fe:00 mode=0100755')
    else:
        lines.append(
            f"type=SYSCALL msg=audit({t:.3f}:{n}): arch=c000003e syscall=openat success=yes exit=3 a0=ff items=2 ppid={ppid} pid={pid} "
            f"auid={auid} uid={uid} gid=root euid={euid} suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses={ses} "
            f'comm="{comm}" exe="{exe}" key="{key}"'
        )
        lines.append(f'type=CWD msg=audit({t:.3f}:{n}): cwd="/root"')
        for index, path in enumerate(paths):
            lines.append(f'type=PATH msg=audit({t:.3f}:{n}): item={index} name="{path}" inode=2 dev=fe:00 mode=0100644')
    return "\n".join(lines)


def session(user="alice", ip="203.0.113.50", port=48988, auth=T0 + 800, pid=3800, is_open=True, logout=None, fp=FP, sid="sess-1", **extra):
    row = {
        "session_id": sid, "user": user, "uid": 1000, "source_ip": ip, "source_port": port, "ssh_port": 23109, "auth_method": "publickey",
        "fingerprint": fp, "key_owner": "tes key", "key_source": "/etc/xdg/authorized_keys", "pid": pid, "auth_time": auth,
        "logout_time": logout, "is_open": is_open,
    }
    row.update(extra)
    return row


def change(path="/etc/group", t=T0 + 1000.5, observed=None, change_type="modified", **kw):
    return ac.FileChange(path=path, change_type=change_type, change_time=t, observed_at=observed if observed is not None else t + 1, **kw)


def ingest(correlator, *blocks, observed_at=None):
    for text in blocks:
        correlator.observe_audit_block(text, observed_at if observed_at is not None else correlator._clock())


def counters():
    return get_actor_metrics().snapshot()["counters"]


def sshd_chain(correlator):
    ingest(
        correlator,
        block("exec", 3800, 1, "unset", "root", "root", "/usr/sbin/sshd", ["sshd: alice [priv]"], T0 + 800),
        block("exec", 3900, 3800, "alice", "alice", "alice", "/bin/bash", ["-bash"], T0 + 801),
    )


def test_1_a_direct_user_action_is_correlated_to_the_ssh_session_by_lineage():
    correlator, _ = make(sessions=[session()])
    sshd_chain(correlator)
    ingest(correlator, block("exec", 4000, 3900, "alice", "alice", "alice", "/usr/bin/tee", ["tee", "/etc/group"], T0 + 1000))
    ctx = correlator.correlate(change())
    assert ctx.classification == ac.CLASS_USER and ctx.actor_type == ac.TYPE_SSH_USER and ctx.confidence == ac.CONF_HIGH
    assert ctx.actor_username == "alice" and ctx.effective_actor == "alice"
    assert ctx.source_ip == "203.0.113.50" and ctx.source_port == 48988 and ctx.ssh_port == 23109 and ctx.ssh_session_id == "sess-1"
    assert ctx.ssh_auth_method == "publickey" and ctx.ssh_fingerprint == FP and ctx.ssh_key_owner == "tes key"
    assert ctx.ssh_key_source == "/etc/xdg/authorized_keys"
    assert ctx.pid == 4000 and ctx.ppid == 3900 and ctx.executable == "/usr/bin/tee" and ctx.command_line == "tee /etc/group"
    assert any("SSH_SESSION_MATCHED by=PROCESS_LINEAGE_TO_SSH_SESSION_PID" in e for e in ctx.evidence)
    assert any(e.startswith("EXEC_RECORD_MATCHED") for e in ctx.evidence) and any(e.startswith("PID_VALIDATED") for e in ctx.evidence)
    assert ctx.execution_path == "SSH → tee"
    print("Test 1 (A: ssh user -> command -> file change = CORRELATED_USER_ACTION, high; IP/ports/session/key from the logical SSH session through the PID lineage) PASSED")


def test_2_b_sudo_action_keeps_the_original_user_and_the_effective_root_apart():
    correlator, _ = make(sessions=[session(user="newusproud", ip="103.105.82.8", port=48988)])
    ingest(
        correlator,
        block("exec", 3800, 1, "unset", "root", "root", "/usr/sbin/sshd", ["sshd: newusproud [priv]"], T0 + 800),
        block("exec", 3900, 3800, "newusproud", "newusproud", "newusproud", "/bin/bash", ["-bash"], T0 + 801),
        block("exec", 3950, 3900, "newusproud", "newusproud", "root", "/usr/bin/sudo", ["sudo", "usermod", "-aG", "docker", "bob"], T0 + 998),
        block("exec", 3960, 3950, "newusproud", "root", "root", "/usr/sbin/usermod", ["usermod", "-aG", "docker", "bob"], T0 + 1000),
    )
    before = counters()
    ctx = correlator.correlate(change())
    assert ctx.classification == ac.CLASS_SUDO and ctx.actor_type == ac.TYPE_SUDO_USER and ctx.confidence == ac.CONF_HIGH
    assert ctx.actor_username == "newusproud" and ctx.effective_actor == "root" and ctx.actor_euid == "root"
    assert ctx.execution_path == "SSH → sudo → usermod" and ctx.parent == "sudo"
    assert ctx.source_ip == "103.105.82.8" and ctx.source_port == 48988 and ctx.ssh_port == 23109
    assert ctx.executable == "/usr/sbin/usermod" and ctx.command_line == "usermod -aG docker bob" and ctx.ppid == 3950
    assert "SUDO_IN_LINEAGE" in ctx.evidence and ctx.actor_username != "root"
    after = counters()
    assert after["fim_actor_correlation_sudo_match_total"] == before["fim_actor_correlation_sudo_match_total"] + 1
    assert after["fim_actor_correlation_session_match_total"] == before["fim_actor_correlation_session_match_total"] + 1
    meta = ctx.to_metadata()
    assert meta["actor"] == "newusproud" and meta["process_user"] == "root" and meta["actor_effective_user"] == "root"
    log_only, _ = make(sessions=[session(user="newusproud", auth=T0 + 700)])
    log_only.observe_sudo(ac.parse_sudo_line(
        "Oct  1 03:20:00 srv sudo[3950]: newusproud : TTY=pts/0 ; PWD=/home/newusproud ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo bob",
        T0 + 999, log_only._clock(),
    ))
    ctx2 = log_only.correlate(change())
    assert ctx2.classification == ac.CLASS_SUDO and ctx2.confidence == ac.CONF_MEDIUM and ctx2.evidence_tier == ac.TIER_SUDO_LOG
    assert ctx2.actor_username == "newusproud" and ctx2.effective_actor == "root" and ctx2.execution_path == "SSH → sudo → usermod"
    assert ctx2.pid is None and ctx2.command_line == "/usr/sbin/usermod -aG sudo bob", "no process evidence: no PID is invented"
    print("Test 2 (B: ssh -> sudo -> usermod: actor stays newusproud, effective root, path 'SSH → sudo → usermod'; sudo-log-only is medium and invents no PID) PASSED")


def test_3_c_system_service_and_d_package_manager_and_cron():
    alive = {800: T0 + 999.0}
    correlator, _ = make(alive=alive, units={800: ("certbot-renew.service", "/system.slice/certbot-renew.service")})
    ingest(correlator, block("exec", 800, 1, "unset", "root", "root", "/usr/bin/systemctl", ["systemctl", "enable", "foo"], T0 + 1000))
    ctx = correlator.correlate(change(path="/etc/systemd/system/multi-user.target.wants/foo.service"))
    assert ctx.classification == ac.CLASS_SERVICE and ctx.actor_type == ac.TYPE_SYSTEMD_UNIT and ctx.systemd_unit == "certbot-renew.service"
    assert ctx.cgroup == "/system.slice/certbot-renew.service" and ctx.actor_username == "root" and ctx.source_ip is None
    dead, _ = make()
    ingest(dead, block("exec", 801, 1, "unset", "root", "root", "/usr/bin/systemctl", ["systemctl", "enable", "foo"], T0 + 1000))
    ctx = dead.correlate(change(path="/etc/systemd/system/foo.service"))
    assert ctx.classification == ac.CLASS_SERVICE and ctx.actor_type == ac.TYPE_SYSTEM_SERVICE and ctx.systemd_unit is None
    package, _ = make(sessions=[session(user="root")])
    ingest(
        package,
        block("exec", 500, 1, "unset", "root", "root", "/usr/bin/apt-get", ["apt-get", "install", "-y", "foo"], T0 + 940),
        block("exec", 501, 500, "unset", "root", "root", "/usr/bin/dpkg", ["dpkg", "--unpack", "foo.deb"], T0 + 950),
        block("exec", 502, 501, "unset", "root", "root", "/bin/sh", ["sh", "/var/lib/dpkg/info/foo.postinst"], T0 + 960),
        block("exec", 503, 502, "unset", "root", "root", "/usr/sbin/useradd", ["useradd", "-r", "foo"], T0 + 1000),
    )
    ctx = package.correlate(change(path="/etc/passwd"))
    assert ctx.classification == ac.CLASS_PACKAGE and ctx.actor_type == ac.TYPE_PACKAGE_MANAGER and ctx.confidence == ac.CONF_HIGH
    assert ctx.source_ip is None and "SSH_SESSION_NOT_MATCHED" not in " ".join(ctx.evidence)
    assert ctx.execution_path == "apt-get → dpkg → useradd" and ctx.actor_username == "root"
    cron, _ = make()
    ingest(
        cron,
        block("exec", 600, 1, "unset", "root", "root", "/usr/sbin/cron", ["cron"], T0 + 900),
        block("exec", 601, 600, "unset", "root", "root", "/usr/bin/sed", ["sed", "-i", "s/a/b/", "/etc/ssh/sshd_config"], T0 + 1000),
    )
    ctx = cron.correlate(change(path="/etc/ssh/sshd_config"))
    assert ctx.classification == ac.CLASS_CRON and ctx.actor_type == ac.TYPE_CRON
    print("Test 3 (C/D: systemd service (unit only when the PID is alive), apt/dpkg lineage = CORRELATED_PACKAGE_MANAGER, cron lineage = CORRELATED_CRON; raw identity is never turned into a user) PASSED")


def test_4_e_unknown_actor_is_explicit_and_never_derived_from_the_file_owner_or_a_bare_session():
    correlator, _ = make(sessions=[session(user="root", pid=1)])
    before = counters()
    ctx = correlator.correlate(change(owner="root", group="root", mode="0o644"))
    assert ctx.classification == ac.CLASS_UNKNOWN and ctx.actor_type == ac.TYPE_UNKNOWN and ctx.confidence == ac.CONF_NONE
    assert ctx.actor_username is None and ctx.source_ip is None and ctx.pid is None
    meta = ctx.to_metadata()
    assert meta["actor"] == "UNKNOWN" and meta["actor_evidence"] == [ac.NO_EVIDENCE] and meta["actor_resolution"] == ac.NO_EVIDENCE
    assert counters()["fim_actor_correlation_unknown_total"] == before["fim_actor_correlation_unknown_total"] + 1
    disabled = ac.ActorCorrelator()
    assert disabled.correlate(change()).classification == ac.CLASS_UNKNOWN and not disabled.enabled
    print("Test 4 (E: a root-owned file with an open root SSH session but no process/audit/sudo evidence = UNKNOWN_ACTOR, NO_DIRECT_PROCESS_OR_SESSION_CORRELATION; File Owner != Actor) PASSED")


def test_5_f_pid_reuse_never_creates_a_false_correlation():
    correlator, _ = make(sessions=[session()])
    ingest(
        correlator,
        block("exec", 100, 90, "alice", "alice", "alice", "/usr/sbin/usermod", ["usermod", "-aG", "x", "bob"], T0 + 940),
        block("exec", 100, 55, "bob", "bob", "bob", "/bin/cat", ["cat", "/etc/hostname"], T0 + 990),
    )
    before = counters()
    ctx = correlator.correlate(change(t=T0 + 1000))
    assert ctx.classification == ac.CLASS_UNKNOWN and ctx.pid_mismatch
    assert any(e.startswith("PID_REUSE_REJECTED") for e in ctx.negative_evidence)
    assert counters()["fim_actor_correlation_pid_mismatch_total"] == before["fim_actor_correlation_pid_mismatch_total"] + 1
    chain, _ = make(sessions=[session()])
    ingest(
        chain,
        block("exec", 200, 90, "alice", "alice", "alice", "/bin/sh", ["sh", "-c", "usermod -aG x bob"], T0 + 990),
        block("exec", 200, 90, "alice", "alice", "alice", "/usr/sbin/usermod", ["usermod", "-aG", "x", "bob"], T0 + 991),
    )
    ctx = chain.correlate(change(t=T0 + 1000))
    assert ctx.classification == ac.CLASS_USER and ctx.pid == 200 and ctx.executable == "/usr/sbin/usermod", "a legitimate exec chain of one PID is not PID reuse"
    live, _ = make(sessions=[session()], alive={300: T0 + 5000.0})
    ingest(live, block("exec", 300, 90, "alice", "alice", "alice", "/usr/sbin/usermod", ["usermod", "-aG", "x", "bob"], T0 + 990))
    ctx = live.correlate(change(t=T0 + 1000))
    assert ctx.classification == ac.CLASS_UNKNOWN and ctx.pid_mismatch, "the live process with this PID started AFTER the exec record"
    consistent, _ = make(sessions=[session()], alive={301: T0 + 989.5})
    ingest(consistent, block("exec", 301, 90, "alice", "alice", "alice", "/usr/sbin/usermod", ["usermod", "-aG", "x", "bob"], T0 + 990))
    ctx = consistent.correlate(change(t=T0 + 1000))
    assert ctx.classification == ac.CLASS_USER and any("live start time consistent" in e for e in ctx.evidence)
    snap = type("Snap", (), {"pid": 77, "ppid": 1, "uid": 0, "exe": "/usr/sbin/usermod", "cwd": "/", "cmdline": "usermod x", "username": "root",
                             "start_time": T0 + 990, "start_time_ticks": 12345})()
    fallback, _ = make()
    fallback.set_snapshot_provider(lambda since: [snap])
    ac.proc_start_ticks = lambda pid: 99999
    try:
        ctx = fallback.correlate(change(t=T0 + 1000))
    finally:
        import core.instance_lock as il
        ac.proc_start_ticks = il.proc_start_ticks
    assert ctx.classification == ac.CLASS_UNKNOWN and ctx.pid_mismatch and any("start ticks differ" in e for e in ctx.negative_evidence)
    print("Test 5 (F: a reused PID (different parent/login), a live process that started after the exec record, or snapshot ticks that differ = no correlation; a normal exec chain still matches) PASSED")


def test_6_g_delayed_ssh_event_uses_event_time_not_processing_time():
    clock = Clock(T0 + 90_000.0)
    correlator, _ = make(clock=clock, sessions=[session(auth=T0 + 900, pid=None)])
    ingest(
        correlator,
        block("exec", 4000, 3900, "alice", "alice", "alice", "/usr/bin/tee", ["tee", "/etc/group"], T0 + 1000),
        observed_at=clock.t,
    )
    ctx = correlator.correlate(change(t=T0 + 1000.5, observed=clock.t))
    assert ctx.classification == ac.CLASS_USER and ctx.ssh_session_id == "sess-1"
    assert ctx.change_event_time == T0 + 1000.5 and ctx.observed_at == clock.t and ctx.processed_at == clock.t
    assert ctx.change_event_time != ctx.observed_at
    assert any("USERNAME_AND_TIME_WINDOW_UNIQUE" in e for e in ctx.evidence)
    later, _ = make(sessions=[session(auth=T0 + 1500, pid=None)])
    ingest(later, block("exec", 4001, 3900, "alice", "alice", "alice", "/usr/bin/tee", ["tee", "/etc/group"], T0 + 1000))
    ctx = later.correlate(change(t=T0 + 1000.5))
    assert ctx.ssh_session_id is None and any("SSH_SESSION_NOT_MATCHED" in e for e in ctx.negative_evidence), "a login whose EVENT time is after the change is never linked"
    stale, _ = make(sessions=[session(auth=T0 - 50_000, pid=None, is_open=False, logout=T0 - 49_000)])
    ingest(stale, block("exec", 4002, 3900, "alice", "alice", "alice", "/usr/bin/tee", ["tee", "/etc/group"], T0 + 1000))
    assert stale.correlate(change(t=T0 + 1000.5)).ssh_session_id is None
    print("Test 6 (G: correlation uses the SSH/audit EVENT times: a login processed 25 h later still matches, a login whose event time follows the change or a closed old session does not; event/observed/processed times stay separate) PASSED")


def test_7_j_unrelated_or_ambiguous_ssh_sessions_are_not_linked():
    rows = [
        session(user="alice", ip="198.51.100.9", auth=T0 - 7200, pid=None, is_open=False, logout=T0 + 100, sid="old"),
        session(user="alice", ip="192.0.2.77", auth=T0 + 2000, pid=None, sid="future"),
        session(user="bob", ip="203.0.113.1", auth=T0 + 900, pid=None, sid="other-user"),
    ]
    correlator, _ = make(sessions=rows)
    ingest(correlator, block("exec", 4100, 3900, "alice", "alice", "alice", "/usr/bin/tee", ["tee", "/etc/group"], T0 + 1000))
    ctx = correlator.correlate(change())
    assert ctx.classification == ac.CLASS_USER and ctx.actor_type == ac.TYPE_LOCAL_USER and ctx.actor_username == "alice"
    assert ctx.source_ip is None and ctx.ssh_session_id is None and any("SSH_SESSION_NOT_MATCHED" in e for e in ctx.negative_evidence)
    ambiguous, _ = make(sessions=[
        session(ip="198.51.100.1", auth=T0 + 900, pid=None, sid="a"), session(ip="198.51.100.2", auth=T0 + 910, pid=None, sid="b", fp="SHA256:other"),
    ])
    ingest(ambiguous, block("exec", 4101, 3900, "alice", "alice", "alice", "/usr/bin/tee", ["tee", "/etc/group"], T0 + 1000))
    ctx = ambiguous.correlate(change())
    assert ctx.source_ip is None and any("AMBIGUOUS_SSH_SESSIONS(2)" in e for e in ctx.negative_evidence) and len(ctx.candidate_ssh_sessions) == 2
    reconnect, _ = make(sessions=[
        session(auth=T0 + 900, pid=None, sid="first"), session(auth=T0 + 950, pid=None, sid="second", port=48990),
    ])
    ingest(reconnect, block("exec", 4102, 3900, "alice", "alice", "alice", "/usr/bin/tee", ["tee", "/etc/group"], T0 + 1000))
    ctx = reconnect.correlate(change())
    assert ctx.ssh_session_id == "second", "a reconnect of the same identity (same IP and key) is one candidate, not an ambiguity"
    print("Test 7 (J: another user, a session that ended before, one that starts after, or a long-gone IP is not linked; two different identities are ambiguous and none is picked; a normal reconnect is one identity) PASSED")


def test_8_h_duplicate_fim_events_and_i_multi_file_operation_are_one_logical_notification():
    correlator, clock = make(sessions=[session()])
    sshd_chain(correlator)
    ingest(
        correlator,
        block("exec", 3950, 3900, "alice", "alice", "root", "/usr/bin/sudo", ["sudo", "useradd", "carol"], T0 + 998),
        block("exec", 3960, 3950, "alice", "root", "root", "/usr/sbin/useradd", ["useradd", "carol"], T0 + 1000),
    )
    detector = FileIntegrityDetector(EventBus(), FileIntegrityDetectorConfig(enabled=True))
    detector._actor_correlator = correlator

    def evaluated(path, t=T0 + 1000.2):
        return {
            "path": path, "change_type": "modified", "mtime_new": t, "ctime_new": t, "sha256_old": "a" * 64, "sha256_new": path[-3:] * 21 + "x",
            "inode_new": hash(path) % 1000, "mode_new": "0o640", "gid_new": 0, "owner_username": "root", "target_class": "system_file",
            "severity": Severity.HIGH, "message": f"Isi file diubah: {path}", "actor_resolution": "NOT_AVAILABLE",
        }

    files = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"]
    before = counters()
    result = detector._correlate_actors([evaluated(f) for f in files])
    primaries = [c for c in result if c.get("notify_discord") is not False]
    assert len(primaries) == 1 and primaries[0]["path"] == "/etc/passwd"
    assert sorted(primaries[0]["operation_files"]) == sorted(files) and primaries[0]["operation_file_count"] == 4
    secondary = [c for c in result if c.get("notify_discord") is False]
    assert len(secondary) == 3 and all(c["coalesced_into_operation"] == "/etc/passwd" and c["operation_id"] == primaries[0]["operation_id"] for c in secondary)
    assert all(c["actor_classification"] == ac.CLASS_SUDO for c in result), "raw events keep their own attribution"
    assert counters()["fim_actor_correlation_operations_coalesced_total"] == before["fim_actor_correlation_operations_coalesced_total"] + 3
    later = detector._correlate_actors([evaluated("/etc/subuid")])
    assert later[0]["notify_discord"] is False and later[0]["coalesced_into_operation"] == "/etc/passwd"
    repeat = detector._correlate_actors([evaluated("/etc/group")])
    assert repeat[0]["notify_discord"] is False and repeat[0].get("actor_duplicate") is True
    assert counters()["fim_actor_correlation_duplicate_total"] == before["fim_actor_correlation_duplicate_total"] + 1
    assert all(c["file_owner"] == "root" for c in result) and result[0]["file_mode"] == "0o640" and "file_group" in result[0]
    clock.t += 600
    expired = detector._correlate_actors([evaluated("/etc/group", t=T0 + 1700.0)])
    assert expired[0].get("actor_duplicate") is not True
    print("Test 8 (H/I: useradd touching 4 account files = one Discord notification listing the files, the rest stored raw with the operation id; an identical repeated observation is one logical notification; raw events keep attribution) PASSED")


def test_9_evidence_hierarchy_confidence_and_windows():
    correlator, _ = make(sessions=[session(pid=None)])
    ingest(
        correlator,
        block("exec", 4200, 3900, "alice", "alice", "alice", "/usr/bin/vim", ["vim", "/etc/hosts"], T0 + 990),
        block("file", 4200, 3900, "alice", "alice", "alice", "/usr/bin/vim", [], T0 + 1000.1, key="rtsa_fim", paths=["/etc/group"]),
        block("exec", 4201, 3900, "bob", "bob", "bob", "/usr/bin/tee", ["tee", "/etc/group"], T0 + 1000),
    )
    ctx = correlator.correlate(change())
    assert ctx.evidence_tier == ac.TIER_AUDIT_FILE and ctx.confidence == ac.CONF_HIGH and ctx.actor_username == "alice" and ctx.pid == 4200
    assert any(e.startswith("AUDIT_FILE_EVENT_MATCHED") for e in ctx.evidence)
    editor, _ = make(sessions=[session(pid=None)])
    ingest(editor, block("exec", 4300, 3900, "alice", "alice", "alice", "/usr/bin/vim", ["vim"], T0 + 700))
    ctx = editor.correlate(change())
    assert ctx.evidence_tier == ac.TIER_EXEC and ctx.confidence == ac.CONF_MEDIUM, "an interactive editor with no file in its arguments is medium"
    far, _ = make(sessions=[session(pid=None)])
    ingest(far, block("exec", 4400, 3900, "alice", "alice", "alice", "/usr/sbin/usermod", ["usermod", "x"], T0 + 700))
    assert far.correlate(change()).classification == ac.CLASS_UNKNOWN, "a non-interactive writer older than writer_max_runtime is outside the window"
    after, _ = make(sessions=[session(pid=None)])
    ingest(after, block("exec", 4401, 3900, "alice", "alice", "alice", "/usr/sbin/usermod", ["usermod", "x"], T0 + 1030))
    assert after.correlate(change()).classification == ac.CLASS_UNKNOWN, "an exec that starts after the change cannot have caused it"
    two, _ = make(sessions=[session(pid=None)])
    ingest(
        two,
        block("exec", 4500, 3900, "alice", "alice", "alice", "/usr/sbin/usermod", ["usermod", "x"], T0 + 995),
        block("exec", 4501, 3901, "bob", "bob", "bob", "/usr/sbin/usermod", ["usermod", "y"], T0 + 996),
    )
    ctx = two.correlate(change())
    assert ctx.classification == ac.CLASS_UNKNOWN and any("AMBIGUOUS_PROCESS_CANDIDATES" in e for e in ctx.negative_evidence)
    snap = type("Snap", (), {"pid": 88, "ppid": 1, "uid": 0, "exe": "/usr/sbin/usermod", "cwd": "/", "cmdline": "usermod x", "username": "root",
                             "start_time": T0 + 990, "start_time_ticks": 0})()
    only_snapshot, _ = make(alive={}, units={88: ("useradd-helper.service", "/system.slice/useradd-helper.service")})
    only_snapshot.set_snapshot_provider(lambda since: [snap])
    bare_snapshot, _ = make(alive={})
    bare_snapshot.set_snapshot_provider(lambda since: [snap])
    import core.instance_lock as il
    ac.proc_start_ticks = lambda pid: 4242
    try:
        ctx = only_snapshot.correlate(change())
        bare = bare_snapshot.correlate(change())
    finally:
        ac.proc_start_ticks = il.proc_start_ticks
    assert ctx.evidence_tier == ac.TIER_SNAPSHOT and ctx.confidence == ac.CONF_LOW and ctx.actor_username == "root"
    assert ctx.classification == ac.CLASS_SERVICE and ctx.systemd_unit == "useradd-helper.service"
    assert bare.classification == ac.CLASS_UNKNOWN and bare.to_metadata()["actor"] == "UNKNOWN" and "process_pid" not in bare.to_metadata(), "a root process with no unit and no login identity is not attributed"
    print("Test 9 (evidence hierarchy: audit file event > exec record > sudo log > process snapshot; interactive editor = medium; outside-window, later-than-change and conflicting identities are not attributed) PASSED")


def test_10_command_lines_are_redacted_and_bounded_and_parsers_handle_both_audit_time_formats():
    correlator, _ = make(sessions=[session(pid=None)], max_command_chars=60)
    ingest(correlator, block("exec", 4600, 3900, "alice", "alice", "alice", "/usr/sbin/chpasswd", ["chpasswd", "--password", "hunter2hunter2", "x" * 200], T0 + 1000))
    ctx = correlator.correlate(change())
    assert "hunter2hunter2" not in json.dumps(ctx.to_metadata()) and "[REDACTED]" in ctx.command_line and len(ctx.command_line) <= 60
    local = (
        'type=SYSCALL msg=audit(10/01/2026 06:47:01.123:77): arch=c000003e syscall=execve ppid=10 pid=11 auid=alice uid=alice euid=alice ses=4 '
        'comm="vi" exe="/usr/bin/vi"\ntype=EXECVE msg=audit(10/01/2026 06:47:01.123:77): argc=2 a0="vi" a1="/etc/group"'
    )
    observation = ac.parse_audit_block(local, 5.0)
    assert observation.kind == "EXEC" and observation.proc.pid == 11 and observation.proc.auid == "alice" and observation.proc.cmdline == "vi /etc/group"
    assert abs(observation.proc.event_time - time.mktime((2026, 10, 1, 6, 47, 1, 0, 0, -1)) - 0.123) < 1e-6
    numeric = block("exec", 12, 1, "1000", "0", "0", "/usr/bin/sudo", ["sudo", "id"], T0 + 5)
    parsed = ac.parse_audit_block(numeric, 5.0)
    assert parsed.proc.event_time == T0 + 5 and parsed.proc.auid == "1000"
    assert ac.parse_audit_block("type=SYSCALL pid=zz", 1.0) is None and ac.parse_audit_block("garbage", 1.0) is None
    not_watched = block("file", 13, 1, "alice", "alice", "alice", "/usr/bin/vim", [], T0, key="other", paths=["/etc/group"])
    assert ac.parse_audit_block(not_watched, 1.0) is None
    record = ac.parse_sudo_line(
        "Oct  1 03:20:00 srv sudo[4200]:   newusproud : TTY=pts/0 ; PWD=/home/newusproud ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo bob", T0, T0,
    )
    assert (record.user, record.target_user, record.tty, record.pwd, record.pid, record.command) == (
        "newusproud", "root", "pts/0", "/home/newusproud", 4200, "/usr/sbin/usermod -aG sudo bob",
    )
    assert ac.parse_sudo_line("sudo: pam_unix(sudo:session): session opened", T0, T0) is None
    print("Test 10 (command lines: secrets redacted, bounded; audit blocks parse in epoch, interpreted-local and numeric-id form; sudo lines parse user/target/tty/pwd/pid/command) PASSED")


def test_11_ledgers_are_bounded_fast_and_never_scan_the_process_table():
    clock = Clock()
    probes = []
    correlator, _ = make(clock=clock, sessions=[session(pid=None)], max_exec_records=2000, max_file_records=500, max_sudo_records=100, evidence_ttl_seconds=900)
    correlator.set_probes(start_time=lambda pid: probes.append(pid))
    for index in range(30_000):
        correlator.observe_exec(ac.ProcRecord(
            pid=10_000 + index, ppid=1, uid="root", euid="root", auid="unset", ses="1", exe="/usr/bin/ls", comm="ls", cmdline="ls", cwd="/",
            event_time=T0 + 900 + index * 0.001, observed_at=clock.t,
        ))
    for index in range(2000):
        correlator.observe_sudo(ac.SudoRecord("alice", "root", "/bin/true", None, None, None, T0, clock.t))
    health = correlator.health()
    assert health["exec_records"] <= 2000 and health["sudo_records"] <= 100 and len(correlator._exec_by_pid) <= 2000
    assert sum(len(v) for v in correlator._exec_by_name.values()) <= 2000
    ingest(correlator, block("exec", 4700, 3900, "alice", "alice", "alice", "/usr/sbin/usermod", ["usermod", "x"], T0 + 1000))
    started = time.perf_counter()
    for _ in range(200):
        ctx = correlator.correlate(change())
    per_call = (time.perf_counter() - started) / 200
    assert ctx.classification == ac.CLASS_USER and per_call < 0.02, per_call
    assert len(probes) <= 400, "only the candidate PIDs are probed, never the whole ledger or /proc"
    clock.t += 5000
    correlator.observe_sudo(ac.SudoRecord("alice", "root", "/bin/true", None, None, None, T0, clock.t))
    assert correlator.health()["exec_records"] == 0, "evidence older than evidence_ttl_seconds is dropped"
    snapshot = get_actor_metrics().snapshot()
    assert snapshot["latency"]["fim_actor_correlation_latency"]["count"] >= 200 and "fim_actor_evidence_records" in snapshot["gauges"]
    print(f"        30000 exec records offered -> {health['exec_records']} kept; correlation {per_call * 1000:.2f} ms each")
    print("Test 11 (bounded ledgers (exec/file/sudo) with TTL, 30000 events -> 2000 kept, ~ms per correlation, only candidate PIDs probed, latency/size metrics exported) PASSED")


def test_12_audit_monitor_feeds_the_ledger_and_publishes_identity_metadata_without_changing_its_events():
    bus_events = []
    audit = AuditMonitor(EventBus(), AuditMonitorConfig())
    audit.publish = bus_events.append
    shared = ac.get_actor_correlator()
    shared.reset()
    shared.configure(ActorCorrelationConfig())
    text = block("exec", 4800, 3950, "newusproud", "root", "root", "/usr/sbin/usermod", ["usermod", "-aG", "docker", "bob"], T0 + 1000, ses="7")
    audit._parse_record(text)
    audit._parse_record(text)
    assert shared.health()["exec_records"] == 1, "a duplicate audit record is ingested once"
    assert len(bus_events) == 1
    event = bus_events[0]
    assert event.actor == "newusproud" and event.executable == "/usr/sbin/usermod" and event.audit_pid == 4800
    assert event.metadata["audit_ppid"] == "3950" and event.metadata["audit_euid"] == "root" and event.metadata["audit_ses"] == "7"
    assert event.metadata["audit_auid"] == "newusproud" and event.metadata["audit_event_time"] == T0 + 1000
    assert audit._resolve_actor("auid=unset uid=root") is None and audit._resolve_actor("auid=4294967295") is None
    assert audit._resolve_actor("auid=0 uid=0") == "root" and audit._resolve_actor("auid=carol uid=root") == "carol"
    shared.reset()
    shared.configure(ActorCorrelationConfig(enabled=False))
    audit._seen_event_ids = type(audit._seen_event_ids)(maxsize=10)
    audit._parse_record(text)
    assert shared.health()["exec_records"] == 0, "a disabled correlator ingests nothing"
    print("Test 12 (AuditMonitor: each audit record is ingested once into the evidence ledger, its events keep their category/fields and gain ppid/uid/euid/auid/ses/event-time metadata, interpreted login names resolve) PASSED")


def test_13_discord_alert_shows_the_actor_context_compactly_and_old_events_are_unchanged():
    correlator, _ = make(sessions=[session(user="newusproud", ip="103.105.82.8")])
    ingest(
        correlator,
        block("exec", 3800, 1, "unset", "root", "root", "/usr/sbin/sshd", ["sshd: newusproud [priv]"], T0 + 800),
        block("exec", 3950, 3800, "newusproud", "newusproud", "root", "/usr/bin/sudo", ["sudo", "usermod"], T0 + 998),
        block("exec", 3960, 3950, "newusproud", "root", "root", "/usr/sbin/usermod", ["usermod", "-aG", "docker", "bob"], T0 + 1000),
    )
    ctx = correlator.correlate(change())
    base = {"path": "/etc/group", "change_type": "modified", "owner_username": "root", "sha256_old": "a" * 64, "sha256_new": "b" * 64, "assessment": "UNKNOWN"}
    event = BaseEvent("file_integrity_detector", EventCategory.FILE_INTEGRITY_CHANGE, Severity.HIGH, "Isi file diubah: /etc/group", raw="/etc/group",
                      metadata={**base, **ctx.to_metadata(), "operation_files": ["/etc/passwd", "/etc/group"]})
    fields = {k: v.replace("\\", "") for k, v in fields_of(event).items()}
    for name in ("Actor", "Actor Type", "Effective User", "Source", "SSH Port", "SSH Session", "Authentication", "Fingerprint", "Key Owner",
                 "Key Source", "Process", "PID", "PPID", "Command", "Execution Path", "Classification", "Confidence", "Actor Evidence",
                 "Operation Files"):
        assert name in fields, name
    assert fields["Actor"].startswith("newusproud") and "(UID" not in fields["Actor"]
    assert fields["Actor Type"] == "SUDO_USER" and fields["Source"] == "103.105.82.8:48988"
    assert fields["SSH Port"] == "23109" and fields["Execution Path"] == "SSH → sudo → usermod" and fields["Classification"] == ac.CLASS_SUDO
    assert "/usr/sbin/usermod" in fields["Process"] and fields["PID"] == "3960" and fields["Confidence"] == "high"
    assert fields["Effective User"].startswith("root") and "hacker" not in json.dumps(fields).lower()
    unknown = correlator.correlate(change(path="/etc/other"))
    event = BaseEvent("file_integrity_detector", EventCategory.FILE_INTEGRITY_CHANGE, Severity.HIGH, "x", raw="/etc/other",
                      metadata={**base, "path": "/etc/other", **unknown.to_metadata()})
    fields = {k: v.replace("\\", "") for k, v in fields_of(event).items()}
    assert fields["Actor"].startswith("UNKNOWN") and fields["Actor Evidence"] == ac.NO_EVIDENCE and fields["Classification"] == "UNKNOWN_ACTOR"
    assert "Source" not in fields and "Process" not in fields and "PID" not in fields
    legacy = BaseEvent("file_integrity_detector", EventCategory.FILE_INTEGRITY_CHANGE, Severity.HIGH, "x", raw="/etc/old", metadata=dict(base))
    legacy_fields = fields_of(legacy)
    assert "Actor Type" not in legacy_fields and "Classification" not in legacy_fields
    print("Test 13 (Discord FIM alert: Actor, Actor Type, Effective User, Source, SSH Port/Session, Fingerprint, Key Owner/Source, Process/PID/PPID/Parent, Command, Execution Path, Classification, Confidence, Evidence; UNKNOWN shows the explicit reason; legacy events unchanged) PASSED")


def test_14_k_new_key_login_sudo_and_file_change_form_one_coherent_timeline_with_raw_events_preserved():
    shared = ac.get_actor_correlator()
    shared.reset()
    clock = Clock(LOGIN_AT + 400)
    shared.configure(ActorCorrelationConfig(), clock=clock)
    shared.set_probes(start_time=lambda pid: None, cgroup=lambda pid: (None, None))
    mon, pub = make_monitor(trusted=("newusproud",))
    with FrozenClock(LOGIN_AT + 20):
        mon._process_line(accepted(user="newusproud", ip="103.105.82.8", port=48988, fp="SHA256:newlyaddedkey"), event_time=LOGIN_AT, pid=4100)
    with FrozenClock(LOGIN_AT + 305):
        mon._process_line(
            "Oct  1 03:20:22 srv sudo[4200]:   newusproud : TTY=pts/0 ; PWD=/home/newusproud ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo bob",
            event_time=LOGIN_AT + 300, pid=4200,
        )
    ingest(
        shared,
        block("exec", 4100, 1, "unset", "root", "root", "/usr/sbin/sshd", ["sshd: newusproud [priv]"], LOGIN_AT + 1),
        block("exec", 4200, 4150, "newusproud", "newusproud", "root", "/usr/bin/sudo", ["sudo", "usermod"], LOGIN_AT + 299),
        block("exec", 4210, 4200, "newusproud", "root", "root", "/usr/sbin/usermod", ["usermod", "-aG", "sudo", "bob"], LOGIN_AT + 300),
    )
    ctx = shared.correlate(ac.FileChange("/etc/group", "modified", LOGIN_AT + 300.4, LOGIN_AT + 400))
    auth = by_cat(pub, EventCategory.SSH_AUTH)
    sudo = by_cat(pub, EventCategory.SUDO_ELEVATION)
    assert len(auth) == 1 and auth[0].metadata["fingerprint"] == "SHA256:newlyaddedkey", "SSH_AUTH preserved"
    assert len(sudo) == 1 and sudo[0].metadata["user"] == "newusproud" and sudo[0].metadata["command"].startswith("/usr/sbin/usermod")
    assert sudo[0].metadata["target_user"] == "root" and sudo[0].metadata["sudo_pid"] == 4200 and sudo[0].metadata["tty"] == "pts/0"
    assert ctx.classification == ac.CLASS_SUDO and ctx.actor_username == "newusproud" and ctx.effective_actor == "root"
    assert ctx.source_ip == "103.105.82.8" and ctx.source_port == 48988 and ctx.ssh_port == SSH_PORT
    assert ctx.ssh_fingerprint == "SHA256:newlyaddedkey"
    assert ctx.ssh_session_id and ctx.execution_path == "SSH → sudo → usermod" and ctx.confidence == ac.CONF_HIGH
    assert ctx.change_event_time == LOGIN_AT + 300.4 and ctx.observed_at == LOGIN_AT + 400
    shared.reset()
    shared.configure(ActorCorrelationConfig())
    print("Test 14 (K: new key -> SSH login -> sudo -> /etc/group change: SSH_AUTH and SUDO_ELEVATION raw events are preserved (sudo now carries target/tty/pwd/pid) and the FIM change links to the same session, key and IP) PASSED")


def test_15_configuration_defaults_validation_and_hygiene():
    cfg = ActorCorrelationConfig()
    assert cfg.window_before_seconds > 0 and cfg.editor_max_runtime_seconds > cfg.writer_max_runtime_seconds and cfg.max_exec_records >= 1000
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    source = open(os.path.join(root, "core", "actor_correlation.py")).read()
    for forbidden in ("subprocess", "os.system", "shell=True", "Popen", "os.listdir", "os.walk", "glob.glob", "psutil", "ps -", "create_subprocess"):
        assert forbidden not in source, forbidden
    import yaml
    for name in ("config.yaml", "config2.yaml"):
        raw = yaml.safe_load(open(os.path.join(root, "config", name)))
        block_cfg = raw["modules"]["file_integrity_detector"]["actor_correlation"]
        assert block_cfg["enabled"] is True and ActorCorrelationConfig(**block_cfg).file_audit_keys == ["rtsa_fim"]
    fim = open(os.path.join(root, "modules", "file_integrity_detector.py")).read()
    assert "FileIntegrityDetector" in fim and fim.count("class FileIntegrityDetector") == 1, "no second FIM engine"
    print("Test 15 (config defaults and YAML profiles; the correlator never executes anything, never lists /proc and never walks the filesystem; still one FIM engine) PASSED")


def main():
    test_1_a_direct_user_action_is_correlated_to_the_ssh_session_by_lineage()
    test_2_b_sudo_action_keeps_the_original_user_and_the_effective_root_apart()
    test_3_c_system_service_and_d_package_manager_and_cron()
    test_4_e_unknown_actor_is_explicit_and_never_derived_from_the_file_owner_or_a_bare_session()
    test_5_f_pid_reuse_never_creates_a_false_correlation()
    test_6_g_delayed_ssh_event_uses_event_time_not_processing_time()
    test_7_j_unrelated_or_ambiguous_ssh_sessions_are_not_linked()
    test_8_h_duplicate_fim_events_and_i_multi_file_operation_are_one_logical_notification()
    test_9_evidence_hierarchy_confidence_and_windows()
    test_10_command_lines_are_redacted_and_bounded_and_parsers_handle_both_audit_time_formats()
    test_11_ledgers_are_bounded_fast_and_never_scan_the_process_table()
    test_12_audit_monitor_feeds_the_ledger_and_publishes_identity_metadata_without_changing_its_events()
    test_13_discord_alert_shows_the_actor_context_compactly_and_old_events_are_unchanged()
    test_14_k_new_key_login_sudo_and_file_change_form_one_coherent_timeline_with_raw_events_preserved()
    test_15_configuration_defaults_validation_and_hygiene()
    print("\nALL FIM ACTOR CORRELATION TESTS PASSED")


if __name__ == "__main__":
    main()
