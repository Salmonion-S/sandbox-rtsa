import asyncio
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _ssh_logout_fakes import (
    ACCEPTED_PASSWORD, DISCONNECTED, FAILED, FP, IP, LOGIN_AT, LOGOUT_AT, RECEIVED_DISCONNECT, REALISTIC_TIMING,
    SSH_PORT, USER, FrozenClock, accepted, by_cat, closed, counters, deliver, fields_of, logouts, make_monitor,
    reset_metrics, unknown_key_meta,
)
from config.manager import SSHSessionConfig
from core.datatypes import EventCategory, Severity
from core.instance_lock import InstanceAlreadyRunning, SingleInstanceLock
from core.ssh_logout import normalize_log_signature
from core.ssh_session import (
    CLASS_CORRELATION_UNKNOWN, CLASS_NORMAL_END, CONF_EXACT, CONF_HIGH, CONF_MEDIUM, LC_AUTH_CONTEXT_MISSING,
    LC_CORRELATION_UNKNOWN, LC_DUPLICATE_LOGOUT, LC_LOGGED_OUT, LC_STALE_SESSION, METHOD_FINGERPRINT, METHOD_PID,
    METHOD_RECENT, METHOD_SESSION_ID, METHOD_TUPLE, STATUS_LOGGED_OUT, SshSessionTracker,
)


def plain(value):
    return str(value).replace("\\", "")


def test_1_normal_publickey_logout():
    reset_metrics()
    with FrozenClock(LOGIN_AT + 9 * 60 + 38) as clock:
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(), event_time=LOGIN_AT, pid=4100)
        clock.at(LOGOUT_AT + 1)
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    events = logouts(pub)
    assert len(events) == 1
    ev = events[0]
    meta = ev.metadata
    assert ev.severity == Severity.INFO and meta["ssh_logout_classification"] == CLASS_NORMAL_END
    assert meta["session_duration"] == "12m 34s" and meta["session_duration_seconds"] == 754, \
        "duration is logout EVENT time minus login EVENT time (processing 10:25:00 -> 10:27:57 would give 2m 57s)"
    assert meta["session_login_time"] == LOGIN_AT and meta["session_logout_time"] == LOGOUT_AT
    assert meta["fingerprint"] == FP and meta["key_owner"] == "owner@example.com" and meta["identity_status"] == "DISCOVERED"
    assert meta["key_source"] == "/home/newusproud/.ssh/authorized_keys" and meta["key_type"] == "ED25519"
    assert meta["source_port"] == 21509 and meta["ssh_port"] == SSH_PORT
    assert meta["ssh_logout_method"] == "EXACT_SSHD_PID" and meta["ssh_logout_state"] == LC_LOGGED_OUT
    assert meta["ssh_service"] == "sshd" and meta["hostname"] and meta["server_name"]
    assert ev.message == f"{USER} • {IP}:21509 → SSH:{SSH_PORT} • 12m 34s", ev.message
    fields = fields_of(ev)
    assert fields["Linux User"] == USER and fields["IP Sumber"] == IP and fields["Source Port"] == "21509"
    assert fields["Session Duration"] == "12m 34s" and fields["Metode Login"] == "publickey"
    assert fields["Login Time"] == "2026-10-01 10:15:22 WIB" and fields["Logout Time"] == "2026-10-01 10:27:56 WIB"
    assert fields["Fingerprint"] == "ED25519 " + FP and fields["Key Owner"] == "owner@example.com"
    assert plain(fields["Key Source"]) == "/home/newusproud/.ssh/authorized_keys"
    assert fields["Identity Status"] == "DISCOVERED" and plain(fields["Classification"]) == CLASS_NORMAL_END
    assert fields["Service"] == "sshd" and "Hostname" in fields and "Session ID" in fields and "Logout Reason" in fields
    assert "Log Mentah" in fields and "session closed for user" in fields["Log Mentah"]
    record = by_cat(pub, EventCategory.SSH_SESSION)[0].metadata["ssh_session"]
    assert record["status"] == STATUS_LOGGED_OUT and record["duration"] == 754
    store, store_pub = make_monitor()
    with FrozenClock(LOGIN_AT + 600) as clock:
        store._process_line(accepted(), event_time=LOGIN_AT, pid=4100)
        clock.at(LOGOUT_AT + 1)
        store._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    stored = logouts(store_pub)[0]
    assert stored.severity == Severity.INFO and stored.metadata["notify_discord"] is False, \
        "the default policy stores a normal logout (history/audit) without a Discord alert, never MEDIUM"
    assert stored.metadata["session_duration"] == "12m 34s"
    print("Test 1 (normal publickey logout: NORMAL_SESSION_END, INFO, 12m 34s on event time, key identity preserved) PASSED")


async def test_2_duplicate_logout_single_event():
    reset_metrics()
    with FrozenClock(LOGOUT_AT + 1) as clock:
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(), event_time=LOGIN_AT, pid=4100)
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100, cursor="c1", source="journal")
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100, cursor="c2", source="journal")
        mon._process_line(closed(), event_time=LOGOUT_AT + 0.4, pid=4100, cursor="c3", source="journal")
        mon._process_line(closed(), event_time=LOGOUT_AT + 2, pid=4100, cursor="c4", source="journal")
    assert len(logouts(pub)) == 1 and len(by_cat(pub, EventCategory.SSH_SESSION)) == 1
    snap = counters()
    assert snap["ssh_logout_total"] == 3 and snap["ssh_logout_duplicate_total"] == 3, snap
    sent = await deliver(pub)
    assert [p["embeds"][0]["fields"][1]["value"] for p in sent].count("SSH_LOGOUT") == 1, "exactly one Discord notification"
    tracker = mon._sessions
    outcome = tracker.on_logout(event_time=LOGOUT_AT + 1, user=USER, pid=4100)
    assert outcome.duplicate and outcome.state == LC_DUPLICATE_LOGOUT
    print("Test 2 (the same logout delivered repeatedly -> one logical event, one notification, duplicates counted) PASSED")


async def test_3_two_sessions_same_user():
    with FrozenClock(LOGIN_AT + 1000) as clock:
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(port=21509), event_time=LOGIN_AT, pid=4100)
        mon._process_line(accepted(port=21510), event_time=LOGIN_AT + 30, pid=4200)
        mon._process_line(closed(), event_time=LOGIN_AT + 400, pid=4200)
        mon._process_line(closed(), event_time=LOGIN_AT + 900, pid=4100)
    first, second = logouts(pub)
    sent = await deliver(logouts(pub) + [first])
    assert [p["embeds"][0]["fields"][1]["value"] for p in sent].count("SSH_LOGOUT") == 2, \
        "two different sessions of one key both notify; the same event delivered twice notifies once"
    assert first.metadata["source_port"] == 21510 and first.metadata["session_duration_seconds"] == 370
    assert second.metadata["source_port"] == 21509 and second.metadata["session_duration_seconds"] == 900
    assert first.metadata["ssh_session_id"] != second.metadata["ssh_session_id"]
    assert all(e.metadata["ssh_logout_method"] == "EXACT_SSHD_PID" for e in (first, second))
    print("Test 3a (two sessions of one user, closed by pid: each logout closes its own session) PASSED")

    with FrozenClock(LOGIN_AT + 1000):
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(port=21509), event_time=LOGIN_AT)
        mon._process_line(accepted(port=21510), event_time=LOGIN_AT + 30)
        mon._process_line(DISCONNECTED.format(user=USER, ip=IP, port=21510), event_time=LOGIN_AT + 399)
        mon._process_line(closed(), event_time=LOGIN_AT + 400)
        mon._process_line(RECEIVED_DISCONNECT.format(ip=IP, port=21509), event_time=LOGIN_AT + 899)
        mon._process_line(DISCONNECTED.format(user=USER, ip=IP, port=21509), event_time=LOGIN_AT + 899.5)
        mon._process_line(closed(), event_time=LOGIN_AT + 900)
    first, second = logouts(pub)
    assert first.metadata["source_port"] == 21510 and first.metadata["ssh_logout_method"] == METHOD_TUPLE
    assert second.metadata["source_port"] == 21509 and second.metadata["ssh_logout_method"] == METHOD_TUPLE
    assert first.metadata["session_duration_seconds"] == 370 and second.metadata["session_duration_seconds"] == 900
    assert "Disconnected by user" in second.metadata["logout_reason"]
    assert first.metadata["logout_reason"] == "Client disconnected (sshd)"
    print("Test 3b (no sshd pid: the sshd 'Disconnected from user ... port N' line correlates each close by ip+port) PASSED")

    with FrozenClock(LOGIN_AT + 1000):
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(port=21509), event_time=LOGIN_AT)
        mon._process_line(accepted(port=21510), event_time=LOGIN_AT + 30)
        mon._process_line(DISCONNECTED.format(user=USER, ip=IP, port=21510), event_time=LOGIN_AT + 399)
        mon._process_line(DISCONNECTED.format(user=USER, ip=IP, port=21509), event_time=LOGIN_AT + 399.5)
        mon._process_line(closed(), event_time=LOGIN_AT + 400)
    event = logouts(pub)[0]
    assert event.metadata["ssh_logout_classification"] == CLASS_CORRELATION_UNKNOWN
    assert event.metadata["ssh_logout_state"] == LC_CORRELATION_UNKNOWN
    assert len(mon._sessions.open_sessions()) == 2, "an ambiguous logout must not close either session"
    assert "source_port" not in event.metadata and "fingerprint" not in event.metadata
    print("Test 3c (two possible sessions and no pid: not guessed, both stay open, CORRELATION_UNKNOWN) PASSED")


def test_4_reconnect_is_two_sessions():
    with FrozenClock(LOGOUT_AT + 1):
        mon, pub = make_monitor(logout_policy="INFO", known_login_policy="COOLDOWN")
        mon._process_line(accepted(port=21509), event_time=LOGIN_AT, pid=4100)
        mon._process_line(closed(), event_time=LOGIN_AT + 20, pid=4100)
        mon._process_line(accepted(port=21777), event_time=LOGIN_AT + 25, pid=4101)
        mon._process_line(closed(), event_time=LOGIN_AT + 50, pid=4101)
    first, second = logouts(pub)
    assert first.metadata["ssh_session_id"] != second.metadata["ssh_session_id"]
    assert first.metadata["session_duration_seconds"] == 20 and second.metadata["session_duration_seconds"] == 25
    sessions = by_cat(pub, EventCategory.SSH_SESSION)
    assert len(sessions) == 2 and sessions[1].metadata["ssh_session"]["kind"] == "RECONNECT"
    assert second.metadata["ssh_security_flags"] == [] and second.severity == Severity.INFO
    assert second.metadata["incident_context"] == [], "a new session id / sshd pid alone is never suspicious"
    print("Test 4 (reconnect with a new session id and sshd pid: two distinct sessions, no suspicion from the new id) PASSED")


def test_5_unknown_session_is_not_fabricated():
    reset_metrics()
    with FrozenClock(LOGOUT_AT + 1):
        mon, pub = make_monitor()
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=9999)
    ev = logouts(pub)[0]
    meta = ev.metadata
    assert meta["ssh_logout_classification"] == CLASS_CORRELATION_UNKNOWN and meta["ssh_logout_state"] == LC_AUTH_CONTEXT_MISSING
    for key in ("fingerprint", "key_owner", "key_source", "key_type", "identity_status", "source_port", "ssh_port",
                "session_id", "ssh_session_id", "session_login_time", "session_duration_seconds"):
        assert key not in meta, f"{key} must not be invented for an unknown session"
    assert meta["session_duration"] == "Unknown" and ev.source_ip is None
    assert ev.severity == Severity.INFO and meta["notify_discord"] is False
    fields = fields_of(ev)
    assert fields["Fingerprint"] == "Unknown" and fields["Key Owner"] == "Unknown" and fields["Source Port"] == "Unknown"
    assert fields["IP Sumber"] == "Unknown" and fields["SSH Port"] == "Unknown" and fields["Session Duration"] == "Unknown"
    assert fields["Key Source"] == "Not available" and fields["Session ID"].startswith("Not available")
    assert fields["Login Time"] == "Unknown" and plain(fields["Classification"]) == CLASS_CORRELATION_UNKNOWN
    assert fields["Linux User"] == USER and "Log Mentah" in fields
    assert counters()["ssh_logout_uncorrelated_total"] == 1 and counters()["ssh_logout_correlated_total"] == 0
    with FrozenClock(LOGOUT_AT + 1):
        stranger, spub = make_monitor(trusted=())
        stranger._process_line(closed(user="deploy"), event_time=LOGOUT_AT, pid=9998)
    unknown_untrusted = logouts(spub)[0]
    assert unknown_untrusted.severity == Severity.LOW and unknown_untrusted.metadata.get("notify_discord") is not False
    print("Test 5 (logout with no matching login: SESSION_CORRELATION_UNKNOWN, no fabricated fields, severity from evidence only) PASSED")


async def test_6_delayed_logout_uses_event_time():
    reset_metrics()
    late_by = 120.0
    with FrozenClock(LOGIN_AT + 1) as clock:
        mon, pub = make_monitor(timing=REALISTIC_TIMING, logout_policy="INFO")
        mon._process_line(accepted(), event_time=LOGIN_AT, pid=4100)
        clock.at(LOGOUT_AT + late_by)
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    ev = logouts(pub)[0]
    meta = ev.metadata
    assert meta["event_timing_status"] == "DELAYED" and abs(meta["event_delay_seconds"] - late_by) < 1e-6
    assert meta["session_logout_time"] == LOGOUT_AT and ev.timestamp == LOGOUT_AT, "event time, never processing time"
    assert meta["session_duration"] == "12m 34s"
    assert meta["notify_discord"] is False and meta["ssh_notification_decision"].startswith("SUPPRESSED")
    assert counters()["ssh_logout_delayed_total"] == 1 and counters()["ssh_logout_notification_suppressed_total"] == 1

    reset_metrics()
    with FrozenClock(LOGIN_AT - 40) as clock:
        mon, pub = make_monitor(timing=REALISTIC_TIMING, logout_policy="INFO")
        for i in range(5):
            mon._process_line(FAILED.format(user="root", ip="94.10.0.1", port=7000 + i), event_time=LOGIN_AT - 40 + i)
        clock.at(LOGIN_AT + 1)
        mon._process_line(accepted(ip="94.10.0.1", port=21509), event_time=LOGIN_AT, pid=4100)
        clock.at(LOGOUT_AT + late_by)
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    delayed = logouts(pub)[0]
    assert delayed.metadata["event_timing_status"] == "DELAYED" and delayed.metadata["delayed_security_event"] is True
    assert delayed.metadata.get("notify_discord") is not False and "Delayed Security Event" in delayed.message
    sent = await deliver([delayed])
    assert len(sent) == 1 and sent[0]["embeds"][0]["title"].startswith("⏱ Delayed Security Event")
    names = [f["name"] for e in sent[0]["embeds"] for f in e["fields"]]
    assert "Event Delay" in names and "Event Status" in names and "Incident Context" in names
    print("Test 6 (delayed logout: event time and duration preserved, labelled DELAYED, security-correlated one still notifies) PASSED")


async def test_7_restart_and_replay_do_not_resend():
    reset_metrics()
    tmp = tempfile.mkdtemp()
    state = os.path.join(tmp, "ssh_state.json")
    with FrozenClock(LOGOUT_AT + 1):
        mon, pub = make_monitor(state_path=state, timing=REALISTIC_TIMING, logout_policy="INFO")
        mon._process_line(accepted(), event_time=LOGIN_AT, pid=4100, cursor="c1", source="journal")
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100, cursor="c2", source="journal")
        mon._save_state(force=True)
    assert len(logouts(pub)) == 1

    with FrozenClock(LOGOUT_AT + 3600):
        again, apub = make_monitor(state_path=state, timing=REALISTIC_TIMING, logout_policy="INFO")
        again._load_state()
        again._process_line(accepted(), event_time=LOGIN_AT, pid=4100, cursor="c1", source="journal")
        again._process_line(closed(), event_time=LOGOUT_AT, pid=4100, cursor="c2", source="journal")
    assert apub == [], "a restart that re-reads the same journal must publish nothing"

    raw = json.load(open(state))
    raw["ledger"] = {}
    json.dump(raw, open(state, "w"))
    with FrozenClock(LOGOUT_AT + 3600):
        lost, lpub = make_monitor(state_path=state, timing=REALISTIC_TIMING, logout_policy="INFO")
        lost._load_state()
        lost._process_line(accepted(), event_time=LOGIN_AT, pid=4100, cursor="c1", source="journal")
        lost._process_line(closed(), event_time=LOGOUT_AT, pid=4100, cursor="c2", source="journal")
    assert lpub == [], "even with the line ledger lost, the persisted session state recognises the closed session"
    assert counters()["ssh_logout_duplicate_total"] >= 1
    assert await deliver(apub + lpub) == []

    reset_metrics()
    with FrozenClock(LOGOUT_AT + 3600):
        old, opub = make_monitor(state_path=state, timing=REALISTIC_TIMING, logout_policy="INFO")
        old._load_state()
        old._process_line(closed(), event_time=LOGOUT_AT - 1000, pid=4555, cursor="c0", source="journal")
    event = logouts(opub)[0]
    assert event.metadata["event_timing_status"] == "REPLAYED" and event.metadata["notify_discord"] is False
    assert counters()["ssh_logout_replayed_total"] == 1
    assert await deliver(opub) == [], "a historical logout read after a restart never looks like it just happened"
    print("Test 7 (restart / journal replay: no duplicate Discord notification, historical logout stays stored and labelled) PASSED")


async def test_8_brute_force_context_survives_logout():
    with FrozenClock(LOGIN_AT - 40) as clock:
        mon, pub = make_monitor(logout_policy="STORE")
        for i in range(5):
            mon._process_line(FAILED.format(user="root", ip="94.10.0.1", port=7000 + i), event_time=LOGIN_AT - 40 + i)
        clock.at(LOGIN_AT + 1)
        mon._process_line(accepted(ip="94.10.0.1", port=21509), event_time=LOGIN_AT, pid=4100)
        clock.at(LOGOUT_AT + 1)
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    login = [e for e in by_cat(pub, EventCategory.SSH_AUTH) if e.success][0]
    assert "brute_force_correlation" in login.metadata["ssh_security_flags"]
    ev = logouts(pub)[0]
    meta = ev.metadata
    assert meta["ssh_logout_classification"] == CLASS_NORMAL_END, "the session ended normally ..."
    assert "BRUTE_FORCE_CORRELATED" in meta["incident_context"], "... but the incident context is kept"
    assert ev.severity == Severity.LOW and meta.get("notify_discord") is not False
    assert meta["auth_event_id"] == login.event_id, "the logout links back to the original SSH_AUTH event"
    fields = fields_of(ev)
    assert "BRUTE_FORCE_CORRELATED" in plain(fields["Incident Context"]) and plain(fields["Classification"]) == CLASS_NORMAL_END
    sent = await deliver([ev])
    assert len(sent) == 1

    with FrozenClock(LOGOUT_AT + 1):
        stranger, spub = make_monitor(trusted=(), logout_policy="STORE")
        stranger._process_line(accepted(user="deploy"), event_time=LOGIN_AT, pid=4100)
        stranger._process_line(closed(user="deploy"), event_time=LOGOUT_AT, pid=4100)
    risky = logouts(spub)[0]
    login_severity = by_cat(spub, EventCategory.SSH_AUTH)[0].severity
    assert risky.severity == login_severity == Severity.CRITICAL, "an incident logout keeps the incident severity"
    assert "UNTRUSTED_USER" in risky.metadata["incident_context"] and risky.metadata.get("notify_discord") is not False

    with FrozenClock(LOGOUT_AT + 1):
        odd, opub = make_monitor(meta_factory=unknown_key_meta)
        odd._process_line(accepted(fp="SHA256:neverseen"), event_time=LOGIN_AT, pid=4100)
        odd._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    assert "UNKNOWN_OR_REVOKED_KEY" in logouts(opub)[0].metadata["incident_context"]
    print("Test 8 (BRUTE_FORCE -> SSH_AUTH -> SSH_LOGOUT: incident context, severity and the auth link survive the logout) PASSED")


def test_9_known_fingerprint_maps_owner_and_source():
    with FrozenClock(LOGOUT_AT + 1):
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(), event_time=LOGIN_AT, pid=4100)
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    meta = logouts(pub)[0].metadata
    assert meta["fingerprint"] == FP and meta["key_owner"] == "owner@example.com"
    assert meta["key_source"] == "/home/newusproud/.ssh/authorized_keys" and meta["identity_status"] == "DISCOVERED"
    fields = fields_of(logouts(pub)[0])
    assert fields["Key Owner"] == "owner@example.com" and plain(fields["Key Source"]).endswith("authorized_keys")
    print("Test 9 (a known fingerprint carries its key owner, key source and identity status into the logout) PASSED")


def test_10_unknown_fingerprint_is_unknown():
    with FrozenClock(LOGOUT_AT + 1):
        mon, pub = make_monitor(logout_policy="INFO", meta_factory=unknown_key_meta)
        mon._process_line(accepted(fp="SHA256:neverseen"), event_time=LOGIN_AT, pid=4100)
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    ev = logouts(pub)[0]
    assert ev.metadata["fingerprint"] == "SHA256:neverseen" and "key_owner" not in ev.metadata
    assert "key_source" not in ev.metadata and ev.metadata["identity_status"] == "UNKNOWN_KEY"
    fields = fields_of(ev)
    assert fields["Key Owner"] == "Unknown" and fields["Key Source"] == "Not available", "owner is never guessed"
    with FrozenClock(LOGOUT_AT + 1):
        pw, ppub = make_monitor(logout_policy="INFO")
        pw._process_line(ACCEPTED_PASSWORD.format(user=USER, ip=IP, port=21509), event_time=LOGIN_AT, pid=4100)
        pw._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    pfields = fields_of(logouts(ppub)[0])
    assert pfields["Fingerprint"] == "Unknown" and pfields["Metode Login"] == "password"
    print("Test 10 (an unknown fingerprint / no key at all renders Unknown, never a guessed owner or source) PASSED")


def test_11_source_port_and_ssh_port_not_swapped():
    with FrozenClock(LOGOUT_AT + 1):
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(port=21509), event_time=LOGIN_AT, pid=4100)
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    ev = logouts(pub)[0]
    assert ev.metadata["source_port"] == 21509 and ev.metadata["ssh_port"] == SSH_PORT != 22
    fields = fields_of(ev)
    assert fields["Source Port"] == "21509" and "23109" in fields["SSH Port"] and "21509" not in fields["SSH Port"]
    assert "→ SSH:23109" in ev.message and f"{IP}:21509" in ev.message
    with FrozenClock(LOGOUT_AT + 1):
        fallback, fpub = make_monitor(logout_policy="INFO", ssh_port=22)
        fallback._ssh_dest_port_source = "default_fallback"
        fallback._process_line(accepted(port=21509), event_time=LOGIN_AT, pid=4100)
        fallback._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    unknown_port = logouts(fpub)[0]
    assert "SSH:Unknown" in unknown_port.message and fields_of(unknown_port)["SSH Port"] == "UNKNOWN", \
        "a port that was never discovered is not presented as 22"
    print("Test 11 (client source port 21509 and server SSH port 23109 never swap; an undiscovered port is not shown as 22) PASSED")


async def test_12_duplicate_rtsa_process():
    tmp = tempfile.mkdtemp()
    lock_path = os.path.join(tmp, "rtsa.lock")
    first, second = SingleInstanceLock(lock_path), SingleInstanceLock(lock_path)
    first.acquire()
    try:
        second.acquire()
        raise AssertionError("a second RTSA process must be refused")
    except InstanceAlreadyRunning:
        pass
    finally:
        first.release()
    state = os.path.join(tmp, "ssh_state.json")
    with FrozenClock(LOGOUT_AT + 1):
        one, one_pub = make_monitor(state_path=state, logout_policy="INFO")
        one._process_line(accepted(), event_time=LOGIN_AT, pid=4100, cursor="c1", source="journal")
        one._process_line(closed(), event_time=LOGOUT_AT, pid=4100, cursor="c2", source="journal")
        one._save_state(force=True)
        two, two_pub = make_monitor(state_path=state, logout_policy="INFO")
        two._load_state()
        two._process_line(accepted(), event_time=LOGIN_AT, pid=4100, cursor="c1", source="journal")
        two._process_line(closed(), event_time=LOGOUT_AT, pid=4100, cursor="c2", source="journal")
    sent = await deliver(one_pub + two_pub)
    assert [p["embeds"][0]["fields"][1]["value"] for p in sent].count("SSH_LOGOUT") == 1
    print("Test 12 (a second RTSA process is refused by the single-instance lock; an overlapping reader sharing state sends nothing twice) PASSED")


def test_13_correlation_order_and_never_username_alone():
    cfg = SSHSessionConfig(logout_recent_window_seconds=3600.0)
    tr = SshSessionTracker(cfg, server="S")
    t0 = 1_800_000_000.0

    def login(port, pid=None, ip="1.1.1.1", fp="fpA", at=t0, ssh_port=22):
        return tr.on_auth(
            event_time=at, user="u", source_ip=ip, source_port=port, ssh_port=ssh_port, method="publickey",
            fingerprint=fp, pid=pid,
        ).session

    a = login(5001, pid=11)
    out = tr.on_logout(event_time=t0 + 10, user="u", session_id=a.session_id)
    assert out.method == METHOD_SESSION_ID and out.confidence == CONF_EXACT and out.session is a

    b = login(5002, pid=12, at=t0 + 20)
    out = tr.on_logout(event_time=t0 + 30, user="u", pid=12, source_ip="9.9.9.9", source_port=1)
    assert out.method == METHOD_PID and out.session is b, "an exact pid wins over any tuple"

    c, d = login(6001, at=t0 + 40), login(6002, at=t0 + 41)
    out = tr.on_logout(event_time=t0 + 50, user="u", source_ip="1.1.1.1", source_port=6002, ssh_port=22)
    assert out.method == METHOD_TUPLE and out.session is d and out.confidence == CONF_HIGH
    out = tr.on_logout(event_time=t0 + 51, user="u", source_ip="1.1.1.1", fingerprint="fpA", ssh_port=22)
    assert out.method == METHOD_TUPLE or out.method == METHOD_FINGERPRINT or out.session is c
    assert out.session is c, "only one open session of u from 1.1.1.1 remains"

    e1, e2 = login(7001, ip="2.2.2.2", fp="fpB", at=t0 + 60), login(7002, ip="2.2.2.2", fp="fpC", at=t0 + 61)
    out = tr.on_logout(event_time=t0 + 70, user="u", source_ip="2.2.2.2", fingerprint="fpC", ssh_port=22)
    assert out.method == METHOD_FINGERPRINT and out.session is e2
    out = tr.on_logout(event_time=t0 + 71, user="u", source_ip="2.2.2.2")
    assert out.method == METHOD_RECENT and out.session is e1 and out.confidence == CONF_MEDIUM

    f1, f2 = login(8001, ip="3.3.3.3", at=t0 + 80), login(8002, ip="3.3.3.3", at=t0 + 81)
    out = tr.on_logout(event_time=t0 + 90, user="u", source_ip="3.3.3.3")
    assert out.session is None and out.ambiguous and out.state == LC_CORRELATION_UNKNOWN
    assert f1.status != STATUS_LOGGED_OUT and f2.status != STATUS_LOGGED_OUT
    out = tr.on_logout(event_time=t0 + 91, user="u")
    assert out.session is None and out.classification == CLASS_CORRELATION_UNKNOWN, "never username alone"

    old = login(9001, ip="4.4.4.4", at=t0)
    out = tr.on_logout(event_time=t0 + 7200, user="u", source_ip="4.4.4.4")
    assert out.session is None, "a login older than the recent window is never attached by ip alone"
    other_user = tr.on_logout(event_time=t0 + 100, user="somebody-else", pid=11)
    assert other_user.session is None, "a pid belonging to another user's session is never used"

    stale_cfg = SSHSessionConfig(session_ttl_seconds=100.0)
    st = SshSessionTracker(stale_cfg, server="S")
    s = st.on_auth(
        event_time=t0, user="u", source_ip="1.1.1.1", source_port=1, ssh_port=22, method="publickey", fingerprint="f", pid=5,
    ).session
    expired, _due = st.sweep(t0 + 1000)
    assert expired and s.status == "EXPIRED"
    out = st.on_logout(event_time=t0 + 1100, user="u", pid=5)
    assert out.session is s and out.state == LC_STALE_SESSION and s.status == STATUS_LOGGED_OUT and s.duration == 1100
    print("Test 13 (correlation order: session id > pid > ip+port > ip+fingerprint > bounded ip window; never username alone) PASSED")


def test_14_duration_is_never_derived_from_processing_time():
    reset_metrics()
    with FrozenClock(LOGOUT_AT) as clock:
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(), pid=4100)
        clock.at(LOGOUT_AT + 90)
        mon._process_line(closed(), pid=4100)
    untimed = logouts(pub)[0]
    assert untimed.metadata["session_duration"] == "Unknown" and "session_duration_seconds" not in untimed.metadata
    assert "session_login_time" not in untimed.metadata and "session_logout_time" not in untimed.metadata
    assert untimed.metadata["session_duration_note"]

    with FrozenClock(LOGOUT_AT + 1):
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(), event_time=LOGOUT_AT, pid=4100)
        mon._process_line(closed(), event_time=LOGOUT_AT - 3, pid=4100)
    backwards = logouts(pub)[0]
    assert backwards.metadata["session_duration"] == "Unknown" and backwards.metadata["session_duration_note"]
    assert backwards.metadata["ssh_session_id"], "a small timestamp inversion still correlates, only the duration is dropped"
    with FrozenClock(LOGOUT_AT + 1):
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(), event_time=LOGOUT_AT, pid=4100)
        mon._process_line(closed(), event_time=LOGIN_AT, pid=4100)
    far = logouts(pub)[0]
    assert far.metadata["ssh_logout_classification"] == CLASS_CORRELATION_UNKNOWN and "ssh_session_id" not in far.metadata, \
        "a logout that predates the session by minutes is not attached to it"
    assert mon._sessions.open_sessions()

    with FrozenClock(LOGIN_AT - 3600):
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(), event_time=LOGIN_AT, pid=4100)
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    skewed = logouts(pub)[0]
    assert skewed.metadata["clock_skew_suspected"] is True and skewed.metadata["session_duration"] == "Unknown"
    print("Test 14 (untimed lines, backwards timestamps and clock skew show Unknown instead of a processing-time duration) PASSED")


def test_15_policy_matrix_never_medium():
    for policy in ("STORE", "INFO", "LEGACY"):
        with FrozenClock(LOGOUT_AT + 1):
            mon, pub = make_monitor(logout_policy=policy)
            mon._process_line(accepted(), event_time=LOGIN_AT, pid=4100)
            mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
        ev = logouts(pub)[0]
        assert ev.severity == Severity.INFO, (policy, ev.severity)
        assert (ev.metadata.get("notify_discord") is False) == (policy == "STORE"), policy
        assert ev.metadata["ssh_logout_classification"] == CLASS_NORMAL_END
        assert len(by_cat(pub, EventCategory.SSH_LOGOUT)) == 1, "stored in history in every policy"
    print("Test 15 (normal logout is INFO / NORMAL_SESSION_END in every policy, always stored, notified only when opted in) PASSED")


def test_16_bounded_persisted_and_cheap():
    cfg = SSHSessionConfig(max_sessions=50, max_logout_dedup_entries=40, max_known_identities=50)
    tr = SshSessionTracker(cfg, server="S")
    t0 = 1_800_000_000.0
    for i in range(300):
        tr.on_auth(
            event_time=t0 + i, user=f"u{i}", source_ip=f"9.9.{i // 250}.{i % 250}", source_port=i, ssh_port=22,
            method="publickey", fingerprint=f"f{i}", pid=1000 + i,
        )
        tr.on_logout(event_time=t0 + i + 1, user=f"u{i}", pid=1000 + i)
        tr.on_logout(event_time=t0 + 5000 + i, user="ghost", pid=70000 + i)
    assert len(tr.all_sessions()) <= 50 and len(tr._logout_seen) <= 40 and len(tr._last_by_pid) <= 50
    restored = SshSessionTracker(cfg, server="S")
    restored.load(tr.export(t0 + 400), t0 + 400)
    assert len(restored._logout_seen) == len(tr._logout_seen) <= 40
    newest = tr.all_sessions()[-1]
    again = restored.on_logout(event_time=newest.logout_time + 0.2, user=newest.user, pid=newest.pid)
    assert again.duplicate, "the dedup memory survives a persisted restart"

    calls = {"n": 0}
    originals = (subprocess.run, subprocess.Popen, subprocess.check_output)

    def counter(*a, **k):
        calls["n"] += 1
        raise AssertionError("no subprocess per SSH logout")

    subprocess.run = subprocess.Popen = subprocess.check_output = counter
    try:
        with FrozenClock(LOGIN_AT + 1000):
            mon, pub = make_monitor(logout_policy="INFO")
            for i in range(300):
                mon._process_line(accepted(port=10000 + i), event_time=LOGIN_AT + i, pid=2000 + i)
                mon._process_line(closed(), event_time=LOGIN_AT + i + 0.5, pid=2000 + i)
    finally:
        subprocess.run, subprocess.Popen, subprocess.check_output = originals
    assert calls["n"] == 0 and len(logouts(pub)) == 300 and len(mon._sessions.all_sessions()) <= 2000
    print("Test 16 (dedup memory and sessions are bounded and persisted; 300 logouts run no ps/ss/journalctl/authorized_keys scan) PASSED")


def test_17_metrics_and_signature():
    snapshot = counters()
    names = (
        "ssh_logout_total", "ssh_logout_correlated_total", "ssh_logout_uncorrelated_total", "ssh_logout_duplicate_total",
        "ssh_logout_replayed_total", "ssh_logout_delayed_total", "ssh_session_expired_total",
        "ssh_logout_notification_suppressed_total",
    )
    for name in names:
        assert name in snapshot, name
    from core.pipeline_metrics import get_ssh_metrics

    assert "ssh_session_active" in get_ssh_metrics().snapshot()["gauges"]
    one = normalize_log_signature("Oct  1 10:27:56 srv sshd[4100]: pam_unix(sshd:session): session closed for user newusproud")
    two = normalize_log_signature("pam_unix(sshd:session): session closed for user newusproud")
    assert one == two == "pam_unix(sshd:session): session closed for user newusproud"
    with FrozenClock(LOGOUT_AT + 1):
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(), event_time=LOGIN_AT, pid=4100)
        mon._process_line(
            "Received disconnect from 182.10.36.39 port 21509:11: @everyone <script> pwned", event_time=LOGOUT_AT - 1,
        )
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    reason = logouts(pub)[0].metadata["logout_reason"]
    assert "everyone" not in reason and "script" not in reason, "client-supplied disconnect text is never echoed"
    print("Test 17 (metrics registered, log signature normalised, client-controlled disconnect text never echoed) PASSED")


def test_18_session_state_extension_is_backward_compatible():
    tr = SshSessionTracker(SSHSessionConfig(), server="S")
    t0 = 1_800_000_000.0
    tr.on_auth(
        event_time=t0, user="u", source_ip="1.1.1.1", source_port=1, ssh_port=22, method="publickey", fingerprint="f",
        pid=3,
    )
    exported = tr.export(t0 + 1)
    for values in exported["sessions"]:
        for newer in ("key_type", "identity_status", "pam_pid", "auth_time_reliable", "logout_reason", "duration_reliable"):
            values.pop(newer, None)
    exported.pop("logout_seen", None)
    legacy = SshSessionTracker(SSHSessionConfig(), server="S")
    assert legacy.load(exported, t0 + 1) == 1
    out = legacy.on_logout(event_time=t0 + 30, user="u", pid=3)
    assert out.session is not None and out.duration == 30
    print("Test 18 (state written before this change still loads; the persisted session record is extended, not replaced) PASSED")


def test_19_signature_key_and_tuple_duplicates_without_pid():
    tmp = tempfile.mkdtemp()
    state = os.path.join(tmp, "ssh_state.json")
    with FrozenClock(LOGOUT_AT + 1):
        first, fpub = make_monitor(state_path=state, logout_policy="INFO")
        first._process_line(closed(), event_time=LOGOUT_AT, pid=7777, cursor="c1", source="journal")
        first._save_state(force=True)
    assert len(logouts(fpub)) == 1
    raw = json.load(open(state))
    raw["ledger"] = {}
    json.dump(raw, open(state, "w"))
    with FrozenClock(LOGOUT_AT + 60):
        second, spub = make_monitor(state_path=state, logout_policy="INFO")
        second._load_state()
        second._process_line(closed(), event_time=LOGOUT_AT, pid=7777, cursor="c1", source="journal")
    assert spub == [], "the persisted normalised-signature key stops a replayed unknown logout"

    with FrozenClock(LOGOUT_AT + 1):
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(port=21509), event_time=LOGIN_AT)
        mon._process_line(DISCONNECTED.format(user=USER, ip=IP, port=21509), event_time=LOGOUT_AT - 1)
        mon._process_line(closed(), event_time=LOGOUT_AT)
        mon._process_line(DISCONNECTED.format(user=USER, ip=IP, port=21509), event_time=LOGOUT_AT + 1)
        mon._process_line(closed(), event_time=LOGOUT_AT + 1.5)
    assert len(logouts(pub)) == 1 and counters()["ssh_logout_duplicate_total"] >= 1
    print("Test 19 (replays without a pid are caught by the persisted signature key and by the closed ip+port session) PASSED")


def test_20_explain_shows_logout_context():
    from core.ssh_timing import explain_event_timing

    with FrozenClock(LOGOUT_AT + 1):
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(), event_time=LOGIN_AT, pid=4100)
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
    ev = logouts(pub)[0]
    text = explain_event_timing("SSH_LOGOUT", ev.metadata, ev.timestamp)
    assert "Session Classification: NORMAL_SESSION_END" in text and "EXACT_SSHD_PID" in text
    assert "Session Duration: 12m 34s" in text
    print("Test 20 (/explain timing text carries the session classification, correlation method and duration) PASSED")


def test_21_consumed_hint_is_not_reused_for_another_session():
    with FrozenClock(LOGIN_AT + 1000):
        mon, pub = make_monitor(logout_policy="INFO")
        mon._process_line(accepted(port=21509), event_time=LOGIN_AT, pid=4100)
        mon._process_line(accepted(port=21510), event_time=LOGIN_AT + 10)
        mon._process_line(DISCONNECTED.format(user=USER, ip=IP, port=21509), event_time=LOGIN_AT + 399)
        mon._process_line(closed(), event_time=LOGIN_AT + 400, pid=4100)
        mon._process_line(closed(), event_time=LOGIN_AT + 402)
    first, second = logouts(pub)
    assert first.metadata["source_port"] == 21509 and first.metadata["ssh_logout_state"] == LC_LOGGED_OUT
    assert second.metadata["ssh_logout_state"] == LC_CORRELATION_UNKNOWN, \
        "the second close is a different, unproven session -- not a duplicate of the first"
    assert len(mon._sessions.open_sessions()) == 1
    print("Test 21 (a disconnect hint is used once: it cannot turn another session's close into a false duplicate) PASSED")


async def main():
    test_1_normal_publickey_logout()
    await test_2_duplicate_logout_single_event()
    await test_3_two_sessions_same_user()
    test_4_reconnect_is_two_sessions()
    test_5_unknown_session_is_not_fabricated()
    await test_6_delayed_logout_uses_event_time()
    await test_7_restart_and_replay_do_not_resend()
    await test_8_brute_force_context_survives_logout()
    test_9_known_fingerprint_maps_owner_and_source()
    test_10_unknown_fingerprint_is_unknown()
    test_11_source_port_and_ssh_port_not_swapped()
    await test_12_duplicate_rtsa_process()
    test_13_correlation_order_and_never_username_alone()
    test_14_duration_is_never_derived_from_processing_time()
    test_15_policy_matrix_never_medium()
    test_16_bounded_persisted_and_cheap()
    test_17_metrics_and_signature()
    test_18_session_state_extension_is_backward_compatible()
    test_19_signature_key_and_tuple_duplicates_without_pid()
    test_20_explain_shows_logout_context()
    test_21_consumed_hint_is_not_reused_for_another_session()
    print("\nALL SSH LOGOUT CONTEXT TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
