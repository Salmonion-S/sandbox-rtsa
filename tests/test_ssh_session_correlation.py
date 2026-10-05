import asyncio
import os
import subprocess
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, SSHEventTimingConfig, SSHMonitorConfig, SSHNotificationsConfig, SSHSessionConfig
from core.analyzer import StatefulAnalyzer
from core.datatypes import EventCategory, Severity, SSHEvent
from core.event_bus import EventBus
from core.ssh_session import (
    CLASS_CORRELATION_UNKNOWN, CONF_EXACT, CONF_HIGH, CONF_LOW, CONF_MEDIUM, ID_COMPOSITE, ID_PID, KIND_KNOWN_IDENTITY,
    KIND_NEW_IDENTITY, KIND_RECONNECT, LC_CORRELATION_UNKNOWN, METHOD_RECENT, METHOD_TUPLE, STATUS_ACTIVE, STATUS_EXPIRED,
    STATUS_LOGGED_OUT, SshSessionTracker,
)
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.ssh_monitor import SSHMonitor

FP = "SHA256:knownkeyfingerprint"
ACCEPTED_KEY = "Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 " + FP
ACCEPTED_KEY_FP = "Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 {fp}"
ACCEPTED_PW = "Accepted password for {user} from {ip} port {port} ssh2"
LOGOUT = "pam_unix(sshd:session): session closed for user {user}"
FAILED = "Failed password for invalid user {user} from {ip} port {port} ssh2"


def known_meta(fingerprint, user, **over):
    meta = {
        "hostname": "srv", "server_name": "Server2", "ssh_service": "sshd", "ssh_port": 23109,
        "trusted_linux_user": True, "fingerprint": fingerprint, "key_type": "ED25519",
        "identity_status": "DISCOVERED", "key_owner": "owner@example.com", "key_owner_basis": "KEY_COMMENT",
        "key_user_mismatch": False, "key_source": "/home/x/.ssh/authorized_keys",
    }
    meta.update(over)
    return meta


def make_monitor(state_path="", policy="", **notes):
    cfg = SSHMonitorConfig(
        enabled=True, geoip_lookup=False, state_path=state_path, trusted_linux_users=["newusproud"], use_sshd_t=False,
        event_timing=SSHEventTimingConfig(
            realtime_max_delay_seconds=1e7, delayed_max_delay_seconds=1e7, stale_after_seconds=1e7,
        ),
        notifications=SSHNotificationsConfig(known_login_policy=policy, **notes),
        sessions=SSHSessionConfig(reconnect_window_seconds=300.0, activity_quiet_seconds=60.0),
    )
    mon = SSHMonitor(EventBus(), cfg)
    mon._ssh_dest_port, mon._ssh_dest_ports, mon._ssh_dest_port_source = 23109, {23109}, "sshd_config"
    published = []
    mon.publish = lambda ev: published.append(ev)

    def meta_for(sport, keytype, fingerprint, severity, user, ip=None):
        extra = {} if fingerprint else {"identity_status": "NOT_REGISTERED", "key_user_mismatch": None}
        return {**mon._base_metadata(sport), **known_meta(fingerprint, user, **extra)}

    mon._success_metadata = meta_for
    return mon, published


def auth(user="newusproud", ip="114.10.100.143", port=56128, fp=FP):
    return ACCEPTED_KEY_FP.format(user=user, ip=ip, port=port, fp=fp)


def by_cat(pub, category):
    return [e for e in pub if e.category == category]


def notifying(pub):
    return [e for e in pub if e.metadata.get("notify_discord") is not False]


def test_tracker_identity_and_correlation():
    cfg = SSHSessionConfig(reconnect_window_seconds=300.0, activity_quiet_seconds=60.0)
    tr = SshSessionTracker(cfg, server="S")
    t0 = 1_800_000_000.0
    a = tr.on_auth(event_time=t0, user="u", source_ip="1.1.1.1", source_port=5001, ssh_port=22, method="publickey",
                   fingerprint="fpA", pid=4242)
    assert a.session.id_source == ID_PID and a.session.correlation_confidence == CONF_EXACT
    assert a.kind == KIND_NEW_IDENTITY and a.session.status != STATUS_LOGGED_OUT
    out = tr.on_logout(event_time=t0 + 20, user="u", pid=4242)
    assert out.session is a.session and out.confidence == CONF_EXACT and abs(out.duration - 20) < 1e-6
    assert a.session.status == STATUS_LOGGED_OUT and a.session.logout_time == t0 + 20
    print("Test T1 (AUTH + LOGOUT with the same sshd pid = one session, EXACT, duration on event time) PASSED")

    tr = SshSessionTracker(cfg, server="S")
    b = tr.on_auth(event_time=t0, user="u", source_ip="1.1.1.1", source_port=5001, ssh_port=22, method="publickey",
                   fingerprint="fpA")
    assert b.session.id_source == ID_COMPOSITE and b.session.correlation_confidence == CONF_HIGH
    assert b.session.session_id.startswith("comp:"), "no pid: an inferred id, labelled COMPOSITE, never presented as a real one"
    no_port = tr.on_auth(event_time=t0 + 1, user="w", source_ip="2.2.2.2", source_port=None, ssh_port=22, method="publickey",
                         fingerprint="fpB")
    assert no_port.session.correlation_confidence == CONF_MEDIUM
    out = tr.on_logout(event_time=t0 + 30, user="u")
    assert out.session is None and out.state == LC_CORRELATION_UNKNOWN and out.classification == CLASS_CORRELATION_UNKNOWN, \
        "a username alone is never enough to attach a logout to a session"
    assert b.session.status != STATUS_LOGGED_OUT
    out = tr.on_logout(event_time=t0 + 31, user="u", source_ip="1.1.1.1", source_port=5001, ssh_port=22)
    assert out.session is b.session and out.confidence == CONF_HIGH and out.method == METHOD_TUPLE and not out.ambiguous
    print("Test T2 (no pid: composite id with an honest confidence; a username alone never correlates, ip+port does) PASSED")

    tr = SshSessionTracker(cfg, server="S")
    s1 = tr.on_auth(event_time=t0, user="u", source_ip="1.1.1.1", source_port=5001, ssh_port=22, method="publickey", fingerprint="fpA")
    s2 = tr.on_auth(event_time=t0 + 5, user="u", source_ip="3.3.3.3", source_port=6002, ssh_port=22, method="publickey", fingerprint="fpA")
    assert s1.session.session_id != s2.session.session_id and s1.session.identity_key != s2.session.identity_key
    out = tr.on_logout(event_time=t0 + 60, user="u")
    assert out.session is None and out.state == LC_CORRELATION_UNKNOWN and out.confidence == CONF_LOW, \
        "two open sessions of one user and no pid/ip: not guessed"
    out = tr.on_logout(event_time=t0 + 61, user="u", source_ip="3.3.3.3")
    assert out.session is s2.session and out.method == METHOD_RECENT and out.confidence == CONF_MEDIUM
    print("Test T3 (concurrent sessions: different IP = different identity; no evidence = unknown, never a guess) PASSED")

    tr = SshSessionTracker(cfg, server="S")
    early_logout = tr.on_logout(event_time=t0 + 20, user="u", pid=77)
    assert early_logout.orphan and early_logout.session is None
    late_login = tr.on_auth(event_time=t0, user="u", source_ip="1.1.1.1", source_port=5001, ssh_port=22, method="publickey",
                            fingerprint="fpA", pid=77)
    assert late_login.late_logout_attached and late_login.session.status == STATUS_LOGGED_OUT
    assert abs(late_login.session.duration - 20) < 1e-6 and late_login.session.logout_late
    print("Test T4 (out of order: LOGOUT processed before its delayed AUTH -> attached by pid on event time) PASSED")

    tr = SshSessionTracker(cfg, server="S")
    tr.on_auth(event_time=t0, user="u", source_ip="1.1.1.1", source_port=5001, ssh_port=22, method="publickey", fingerprint="fpA", pid=1)
    expired, _due = tr.sweep(t0 + cfg.session_ttl_seconds + 10)
    assert len(expired) == 1 and expired[0].status == STATUS_EXPIRED and expired[0].logout_time is None, \
        "a missing logout becomes EXPIRED, never a fabricated LOGGED_OUT"
    print("Test T5 (session TTL: no logout ever seen -> EXPIRED without inventing a logout) PASSED")

    tr = SshSessionTracker(cfg, server="S")
    x = tr.on_auth(event_time=t0, user="u", source_ip="1.1.1.1", source_port=1, ssh_port=22, method="publickey", fingerprint="fpA", pid=9)
    tr.on_logout(event_time=t0 + 5, user="u", pid=9)
    y = tr.on_auth(event_time=t0 + 60, user="u", source_ip="1.1.1.1", source_port=2, ssh_port=22, method="publickey", fingerprint="fpA", pid=10)
    assert y.kind == KIND_RECONNECT and y.reconnect_of == x.session.session_id
    z = tr.on_auth(event_time=t0 + 70, user="u", source_ip="1.1.1.1", source_port=3, ssh_port=22, method="publickey", fingerprint="fpDIFF", pid=11)
    assert z.different_key_for_user_ip and z.kind != KIND_RECONNECT, "same user + IP with a DIFFERENT key is a new identity"
    later = tr.on_auth(event_time=t0 + 5000, user="u", source_ip="1.1.1.1", source_port=4, ssh_port=22, method="publickey", fingerprint="fpA", pid=12)
    assert later.kind == KIND_KNOWN_IDENTITY and later.previous_sightings >= 2
    print("Test T6 (RECONNECT inside the window; different fingerprint never merged; long gap = known identity, new session) PASSED")

    tr2 = SshSessionTracker(cfg, server="S")
    tr2.load(tr.export(t0 + 6000), t0 + 6000)
    assert tr2.is_known_identity(later.session.identity_key, t0 + 6000)
    assert any(s.is_open for s in tr2.all_sessions())
    print("Test T7 (sessions + known identities survive export/load) PASSED")

    tiny = SshSessionTracker(SSHSessionConfig(max_sessions=5, max_known_identities=5), server="S")
    for i in range(50):
        tiny.on_auth(event_time=t0 + i, user=f"u{i}", source_ip=f"9.9.9.{i}", source_port=i, ssh_port=22, method="publickey", fingerprint=f"f{i}", pid=i)
    assert len(tiny.all_sessions()) <= 5 and len(tiny._identities) <= 5
    print("Test T8 (bounded: 50 identities into a 5-slot tracker stay at 5) PASSED")


def test_normal_lifecycle_and_logout_policy():
    mon, pub = make_monitor()
    t0 = time.time() - 30
    mon._process_line(auth(port=1001), event_time=t0, pid=100)
    mon._process_line(LOGOUT.format(user="newusproud"), event_time=t0 + 20, pid=100)
    logins, logouts, sessions = by_cat(pub, EventCategory.SSH_AUTH), by_cat(pub, EventCategory.SSH_LOGOUT), by_cat(pub, EventCategory.SSH_SESSION)
    assert len(logins) == len(logouts) == len(sessions) == 1
    assert logins[0].metadata["ssh_login_decision"] == "ALERT" and logins[0].metadata.get("notify_discord") is not False, \
        "the first sighting of an identity is announced once"
    assert logouts[0].severity == Severity.INFO and logouts[0].metadata["notify_discord"] is False, \
        "a normal logout is stored, never MEDIUM, never a Discord alert"
    record = sessions[0].metadata["ssh_session"]
    assert record["status"] == STATUS_LOGGED_OUT and abs(record["duration"] - 20) < 1e-6 and record["id_source"] == ID_PID
    assert sessions[0].metadata["notify_discord"] is False
    print("Test A (normal login/logout: one session record, first sighting announced once, logout stored as INFO) PASSED")

    mon._process_line(auth(port=1002), event_time=t0 + 1000, pid=101)
    second = by_cat(pub, EventCategory.SSH_AUTH)[1]
    assert second.metadata["ssh_login_kind"] == KIND_KNOWN_IDENTITY and second.metadata["ssh_login_decision"] == "STORE_KNOWN"
    assert second.metadata["notify_discord"] is False
    print("Test A2 (a known identity logging in again: stored, not announced; raw event retained) PASSED")

    legacy, pub_l = make_monitor(logout_policy="LEGACY")
    legacy.config.__class__
    legacy._process_line(auth(port=1003), event_time=t0, pid=110)
    legacy._process_line(LOGOUT.format(user="newusproud"), event_time=t0 + 5, pid=110)
    assert by_cat(pub_l, EventCategory.SSH_LOGOUT)[0].metadata.get("notify_discord") is not False
    info, pub_i = make_monitor(logout_policy="INFO")
    info._process_line(auth(port=1004), event_time=t0, pid=111)
    info._process_line(LOGOUT.format(user="newusproud"), event_time=t0 + 5, pid=111)
    lo = by_cat(pub_i, EventCategory.SSH_LOGOUT)[0]
    assert lo.severity == Severity.INFO and lo.metadata.get("notify_discord") is not False
    print("Test A3 (logout_policy LEGACY / INFO are explicit opt-ins; the default is STORE) PASSED")


def test_reconnect_coalescing_and_bounds():
    mon, pub = make_monitor(policy="COOLDOWN")
    t0 = time.time() - 600
    for i in range(4):
        base = t0 + i * 25
        mon._process_line(auth(port=2000 + i), event_time=base, pid=200 + i)
        mon._process_line(LOGOUT.format(user="newusproud"), event_time=base + 18, pid=200 + i)
    logins = by_cat(pub, EventCategory.SSH_AUTH)
    decisions = [e.metadata["ssh_login_decision"] for e in logins]
    assert decisions[0] == "ALERT" and all(d == "COALESCED_RECONNECT" for d in decisions[1:]), decisions
    assert [e.metadata["ssh_login_kind"] for e in logins][1:] == [KIND_RECONNECT] * 3
    assert len(notifying([e for e in pub if e.category in (EventCategory.SSH_AUTH, EventCategory.SSH_LOGOUT)])) == 1
    mon._session_housekeeping(t0 + 4 * 25 + 400)
    activity = by_cat(pub, EventCategory.SSH_SESSION_ACTIVITY)
    assert len(activity) == 1 and activity[0].metadata["notify_discord"] is True
    summary = activity[0].metadata["ssh_activity"]
    assert summary["sessions"] == 4 and summary["status"] == "RECONNECTED" and summary["risk"] == "LOW"
    assert len(summary["durations"]) == 4
    print("Test B (4 reconnects: one announcement, three coalesced, then ONE SSH_SESSION_ACTIVITY summary with all durations) PASSED")

    mon, pub = make_monitor(policy="COOLDOWN")
    for i in range(100):
        base = t0 + i * 2
        mon._process_line(auth(port=3000 + i), event_time=base, pid=1000 + i)
        mon._process_line(LOGOUT.format(user="newusproud"), event_time=base + 1, pid=1000 + i)
    assert len(by_cat(pub, EventCategory.SSH_AUTH)) == 100 and len(by_cat(pub, EventCategory.SSH_LOGOUT)) == 100, \
        "all 100 raw sessions are retained"
    assert len(by_cat(pub, EventCategory.SSH_SESSION)) == 100
    mon._session_housekeeping(t0 + 100 * 2 + 400)
    speaking = notifying(pub)
    speaking = [e for e in speaking if e.category in (EventCategory.SSH_AUTH, EventCategory.SSH_LOGOUT, EventCategory.SSH_SESSION_ACTIVITY)]
    assert len(speaking) <= 3, f"100 reconnects -> a bounded number of notifications, got {len(speaking)}"
    assert by_cat(pub, EventCategory.SSH_SESSION_ACTIVITY)[0].metadata["ssh_activity"]["sessions"] == 100
    print(f"Test C (100 reconnects: 100 raw sessions retained, {len(speaking)} notifications, one activity summary of 100) PASSED")


def test_security_context_stays_visible():
    mon, pub = make_monitor(policy="STORE")
    t0 = time.time() - 100
    mon._process_line(auth(port=4001), event_time=t0 - 2000, pid=300)
    mon._process_line(LOGOUT.format(user="newusproud"), event_time=t0 - 1990, pid=300)
    for i in range(25):
        mon._process_line(FAILED.format(user=f"admin{i % 7}", ip="94.10.0.1", port=7000 + i), event_time=t0 + i * 0.2)
    mon._process_line(auth(ip="94.10.0.1", port=4002), event_time=t0 + 12, pid=301)
    hot = by_cat(pub, EventCategory.SSH_AUTH)[-1]
    assert "brute_force_correlation" in hot.metadata["ssh_security_flags"]
    assert hot.metadata["ssh_login_decision"] == "ALERT" and hot.metadata.get("notify_discord") is not False, \
        "brute force -> success is never suppressed, even for a key the user normally uses"
    mon._process_line(auth(ip="94.10.0.1", port=4003), event_time=t0 + 14, pid=302)
    again = by_cat(pub, EventCategory.SSH_AUTH)[-1]
    assert again.metadata["ssh_login_decision"] == "ALERT_REPEAT_COALESCED" and again.metadata["notify_discord"] is False, \
        "no extra plain SSH_AUTH after the escalation unless there is new evidence"
    print("Test D (known key logging in right after 25 failures from the same IP -> ALERT once, repeat coalesced, not stored-only) PASSED")

    mon, pub = make_monitor(policy="STORE")
    t1 = time.time() - 50
    mon._process_line(auth(fp="SHA256:unknown", port=5001), event_time=t1, pid=400)
    mon._success_metadata = lambda sport, kt, fp, sev, user, ip=None: {**mon._base_metadata(sport), **known_meta(fp, user, identity_status="UNKNOWN_KEY", key_user_mismatch=None)}
    mon._process_line(auth(fp="SHA256:other", port=5002, ip="203.0.113.7"), event_time=t1 + 1, pid=401)
    unknown = by_cat(pub, EventCategory.SSH_AUTH)[-1]
    assert unknown.metadata["ssh_login_decision"] == "ALERT" and "unknown_or_revoked_key" in unknown.metadata["ssh_security_flags"]
    assert unknown.metadata.get("notify_discord") is not False
    print("Test E (unknown key -> ALERT with the flag) PASSED")

    mon, pub = make_monitor(policy="STORE")
    mon._success_metadata = lambda sport, kt, fp, sev, user, ip=None: {**mon._base_metadata(sport), **known_meta(fp, user, key_user_mismatch=True)}
    mon._process_line(auth(port=5101), event_time=t1, pid=410)
    assert "key_user_mismatch" in by_cat(pub, EventCategory.SSH_AUTH)[0].metadata["ssh_security_flags"]
    mon2, pub2 = make_monitor(policy="STORE")
    mon2._process_line(ACCEPTED_PW.format(user="newusproud", ip="114.10.100.143", port=5201), event_time=t1, pid=411)
    mon2._process_line(ACCEPTED_PW.format(user="newusproud", ip="114.10.100.143", port=5202), event_time=t1 + 500, pid=412)
    assert all(e.metadata["ssh_login_decision"] == "ALERT" for e in by_cat(pub2, EventCategory.SSH_AUTH)), \
        "password logins are never 'known-normal' and never silently stored"
    print("Test E2 (key/user mismatch and password logins keep alerting -- the STORE policy only covers verified key logins) PASSED")

    mon, pub = make_monitor(policy="STORE")
    mon._process_line(auth(user="deploy", port=6001), event_time=t1, pid=420)
    assert "untrusted_user" in by_cat(pub, EventCategory.SSH_AUTH)[0].metadata["ssh_security_flags"]
    print("Test E3 (a user outside trusted_linux_users is always security relevant) PASSED")


def test_no_blind_merge():
    mon, pub = make_monitor(policy="COOLDOWN")
    t0 = time.time() - 100
    mon._process_line(auth(user="newusproud", port=8001), event_time=t0, pid=500)
    mon._success_metadata = lambda sport, kt, fp, sev, user, ip=None: {**mon._base_metadata(sport), **known_meta(fp, user, trusted_linux_user=True)}
    mon.config.trusted_linux_users
    mon._trusted_linux_users.add("otheruser")
    mon._process_line(auth(user="otheruser", port=8002), event_time=t0 + 1, pid=501)
    a, b = by_cat(pub, EventCategory.SSH_AUTH)
    assert a.metadata["ssh_session_id"] != b.metadata["ssh_session_id"]
    assert a.metadata["ssh_login_decision"] == "ALERT" and b.metadata["ssh_login_decision"] == "ALERT", \
        "Test H: same source IP, different users -> two identities, both announced (never merged by IP)"
    print("Test H (same IP, different users: not merged) PASSED")

    mon, pub = make_monitor(policy="COOLDOWN")
    mon._process_line(auth(ip="114.10.100.143", port=8101), event_time=t0, pid=510)
    mon._process_line(auth(ip="198.51.100.9", port=8102), event_time=t0 + 1, pid=511)
    a, b = by_cat(pub, EventCategory.SSH_AUTH)
    assert a.metadata["ssh_login_decision"] == "ALERT" and b.metadata["ssh_login_decision"] == "ALERT" and b.metadata["ssh_login_kind"] != KIND_RECONNECT
    print("Test I (same user, different source IP: a new identity, announced, never a reconnect) PASSED")

    mon, pub = make_monitor(policy="COOLDOWN")
    mon._process_line(auth(fp="SHA256:keyOne", port=8201), event_time=t0, pid=520)
    mon._process_line(LOGOUT.format(user="newusproud"), event_time=t0 + 5, pid=520)
    mon._process_line(auth(fp="SHA256:keyTwo", port=8202), event_time=t0 + 20, pid=521)
    one, two = by_cat(pub, EventCategory.SSH_AUTH)
    assert two.metadata["ssh_login_decision"] == "ALERT" and "new_authentication_identity" in two.metadata["ssh_security_flags"]
    assert two.metadata["ssh_login_kind"] != KIND_RECONNECT
    print("Test J (same user + IP, different key fingerprint: new authentication identity, alerted, not merged) PASSED")


def test_state_ports_and_late_events(tmpdir=None):
    tmp = tempfile.mkdtemp()
    state = os.path.join(tmp, "s.json")
    mon, pub = make_monitor(state_path=state, policy="STORE")
    t0 = time.time() - 60
    mon._process_line(auth(port=9001), event_time=t0, pid=600, cursor="c1", source="journal")
    mon._save_state(force=True)
    mon2, pub2 = make_monitor(state_path=state, policy="STORE")
    mon2._load_state()
    mon2._process_line(LOGOUT.format(user="newusproud"), event_time=t0 + 30, pid=600, cursor="c2", source="journal")
    rec = by_cat(pub2, EventCategory.SSH_SESSION)
    assert len(rec) == 1 and rec[0].metadata["ssh_session"]["status"] == STATUS_LOGGED_OUT
    assert abs(rec[0].metadata["ssh_session"]["duration"] - 30) < 1e-6
    assert by_cat(pub2, EventCategory.SSH_LOGOUT)[0].metadata["notify_discord"] is False
    print("Test F (RTSA restart mid-session: the pre-restart login is found again, the logout closes it, nothing re-announced) PASSED")

    mon3, pub3 = make_monitor(policy="STORE")
    mon3._process_line(LOGOUT.format(user="newusproud"), event_time=t0 + 20, pid=610)
    orphan = by_cat(pub3, EventCategory.SSH_LOGOUT)[0]
    assert orphan.metadata["ssh_logout_orphan"] and orphan.metadata["notify_discord"] is False
    mon3._process_line(auth(port=9101), event_time=t0, pid=610)
    late = by_cat(pub3, EventCategory.SSH_SESSION)
    assert len(late) == 1 and late[0].metadata["ssh_session"]["logout_time"] == t0 + 20
    print("Test G2 (LOGOUT before a delayed AUTH: stored as an orphan, then attached; one logical session results) PASSED")

    mon4, pub4 = make_monitor(policy="STORE")
    mon4._process_line(auth(port=56128), event_time=t0, pid=620)
    ev = by_cat(pub4, EventCategory.SSH_AUTH)[0]
    assert ev.metadata["source_port"] == 56128 and ev.metadata["ssh_port"] == 23109, "source port and SSH port are never confused"
    d = DiscordWebhookDispatcher(EventBus(), DiscordConfig(alert_channel_id=1))
    payload = d._build_payload(ev)
    fields = {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}
    assert fields["Source Port"] == "56128" and "23109" in fields["SSH Port"] and fields["Source Port"] != fields["SSH Port"]
    print("Test K (Source Port 56128 and SSH Port 23109 stay separate in metadata and in the Discord embed) PASSED")


async def test_discord_formats_and_escalation():
    mon, pub = make_monitor(policy="COOLDOWN")
    t0 = time.time() - 600
    for i in range(2):
        mon._process_line(auth(port=9300 + i), event_time=t0 + i * 20, pid=700 + i)
        mon._process_line(LOGOUT.format(user="newusproud"), event_time=t0 + i * 20 + 10, pid=700 + i)
    mon._session_housekeeping(time.time())
    activity = by_cat(pub, EventCategory.SSH_SESSION_ACTIVITY)[0]
    d = DiscordWebhookDispatcher(EventBus(), DiscordConfig(alert_channel_id=1))
    fields = {f["name"]: f["value"] for f in d._build_payload(activity)["embeds"][0]["fields"]}
    for required in ("User", "Source", "SSH Port", "Authentication", "Key", "Sessions", "Window", "Durations", "Status", "Risk", "Reason"):
        assert required in fields, (required, sorted(fields))
    assert fields["Status"] == "RECONNECTED" and fields["Sessions"] == "2"
    session = by_cat(pub, EventCategory.SSH_SESSION)[0]
    sfields = {f["name"]: f["value"] for f in d._build_payload(session)["embeds"][0]["fields"]}
    for required in ("User", "Source", "SSH Port", "Method", "Key", "Login", "Logout", "Duration", "Status", "Event Timing", "Security Context"):
        assert required in sfields, (required, sorted(sfields))
    print("Test L (SSH_SESSION_ACTIVITY and SSH_SESSION Discord formats carry the specified fields) PASSED")

    sent = []

    class Bot:
        def is_ready(self):
            return True

    async def send(payload, **kw):
        sent.append(payload)
        return ("OK", 1, len(sent))

    d._bot, d._send_via_bot = Bot(), send
    for ev in pub:
        await d._on_event(ev)
    categories = [p["embeds"][0]["fields"][1]["value"] for p in sent]
    assert categories.count("SSH_LOGOUT") == 0 and categories.count("SSH_AUTH") == 1 and categories.count("SSH_SESSION_ACTIVITY") == 1, categories
    print("Test M (through the dispatcher: 2 sessions -> 1 SSH_AUTH announcement + 1 SSH_SESSION_ACTIVITY, 0 logouts) PASSED")


def test_no_subprocess_per_event():
    calls = {"n": 0}
    originals = (subprocess.run, subprocess.Popen, subprocess.check_output)

    def counter(*a, **k):
        calls["n"] += 1
        raise AssertionError("no subprocess per SSH event")

    subprocess.run = subprocess.Popen = subprocess.check_output = counter
    try:
        mon, pub = make_monitor(policy="COOLDOWN")
        t0 = time.time() - 900
        for i in range(200):
            mon._process_line(auth(port=10000 + i), event_time=t0 + i, pid=2000 + i)
            mon._process_line(LOGOUT.format(user="newusproud"), event_time=t0 + i + 0.5, pid=2000 + i)
    finally:
        subprocess.run, subprocess.Popen, subprocess.check_output = originals
    assert calls["n"] == 0 and len(by_cat(pub, EventCategory.SSH_AUTH)) == 200
    print("Test N (200 logins + logouts: no ps/ss/who/sshd -T/journalctl subprocess per event) PASSED")


async def main():
    test_tracker_identity_and_correlation()
    test_normal_lifecycle_and_logout_policy()
    test_reconnect_coalescing_and_bounds()
    test_security_context_stays_visible()
    test_no_blind_merge()
    test_state_ports_and_late_events()
    await test_discord_formats_and_escalation()
    test_no_subprocess_per_event()
    print("\nALL SSH SESSION CORRELATION / ANTI-SPAM TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
