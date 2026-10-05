import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.analyzer as analyzer_module
from config.manager import DiscordConfig, SSHMonitorConfig
from core.analyzer import StatefulAnalyzer
from core.datatypes import BaseEvent, EventCategory, SSHEvent, Severity
from core.event_bus import EventBus
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.ssh_monitor import SSHMonitor


class _FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _make_monitor(**overrides) -> SSHMonitor:
    cfg = SSHMonitorConfig(enabled=True, geoip_lookup=False, **overrides)
    mon = SSHMonitor(EventBus(), cfg)
    return mon


def _make_analyzer(clock: _FakeClock, **overrides) -> StatefulAnalyzer:
    kwargs = dict(
        ssh_brute_force_threshold=5, ssh_brute_force_window_seconds=60,
        ssh_credential_stuffing_threshold=8, ssh_credential_stuffing_window_seconds=1800,
        ssh_credential_stuffing_min_distinct_ips=3, ssh_red_zone_cooldown_seconds=300.0,
    )
    kwargs.update(overrides)
    analyzer = StatefulAnalyzer(EventBus(), **kwargs)
    analyzer_module.time = clock
    return analyzer


def _failed_event(username: str, ip: str, *, status: str, method=None, ts: float) -> SSHEvent:
    return SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.MEDIUM,
        message=f"SSH login GAGAL untuk '{username}' dari {ip}", raw="", username=username,
        source_ip=ip, auth_method=method, success=False, timestamp=ts,
        metadata={"username_status": status},
    )


def _success_event(username: str, ip: str, *, method="password", ts: float) -> SSHEvent:
    return SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.LOW,
        message=f"SSH login diterima untuk '{username}' dari {ip}", raw="", username=username,
        source_ip=ip, auth_method=method, success=True, timestamp=ts,
        metadata={"hostname": "srv1", "server_name": "srv1"},
    )


async def main() -> None:

    mon1 = _make_monitor()
    published = []
    mon1.publish = lambda ev: published.append(ev)
    mon1._process_line("Invalid user cs from 94.177.195.107 port 36477")
    assert len(published) == 1
    ev = published[0]
    assert ev.username == "cs" and ev.source_ip == "94.177.195.107"
    assert ev.metadata["username_status"] == "INVALID_USER"
    print("Scenario 1 (Invalid user line -> username=cs, INVALID_USER) PASSED")

    mon2 = _make_monitor()
    published = []
    mon2.publish = lambda ev: published.append(ev)
    mon2._process_line("Failed password for root from 94.177.195.107 port 36477")
    assert len(published) == 1
    ev = published[0]
    assert ev.username == "root" and ev.auth_method == "password"
    assert ev.metadata["username_status"] == "EXISTING_USER", (
        "sshd only omits the 'invalid user' prefix for real Linux usernames -- this must be classified "
        "EXISTING_USER, never invented as such without log support"
    )
    print("Scenario 2 (Failed password for root, no 'invalid user' prefix -> EXISTING_USER) PASSED")

    mon3 = _make_monitor()
    published = []
    mon3.publish = lambda ev: published.append(ev)
    mon3._process_line("Failed publickey for deploy from 94.177.195.107 port 36477")
    assert len(published) == 1
    ev = published[0]
    assert ev.username == "deploy" and ev.auth_method == "publickey"
    assert ev.metadata["username_status"] == "EXISTING_USER"
    print("Scenario 3 (Failed publickey -> username parsed, method=publickey) PASSED")

    mon3b = _make_monitor()
    published = []
    mon3b.publish = lambda ev: published.append(ev)
    mon3b._process_line("Failed password for invalid user oracle from 94.177.195.107 port 36477")
    assert len(published) == 1
    assert published[0].metadata["username_status"] == "INVALID_USER", (
        "'Failed password for invalid user X' must still be classified INVALID_USER"
    )
    print("Scenario 3b (Failed password for invalid user X -> INVALID_USER) PASSED")

    mon3c = _make_monitor()
    published = []
    mon3c.publish = lambda ev: published.append(ev)
    mon3c._process_line("error: maximum authentication attempts exceeded for root from 94.177.195.107 port 36477")
    assert len(published) == 1
    assert published[0].username == "root" and published[0].metadata["username_status"] == "EXISTING_USER"
    print("Scenario 3c (maximum authentication attempts exceeded -- parsed as failed attempt) PASSED")

    mon16 = _make_monitor()
    published = []
    mon16.publish = lambda ev: published.append(ev)
    for garbage in ("", "not an ssh line at all", "Failed password for", "###garbled@@@ 12345"):
        mon16._process_line(garbage)
    assert published == [], "malformed/garbage lines must never crash or produce phantom events"
    print("Scenario 16 (malformed SSH log lines -- parser does not crash, no phantom events) PASSED")


    mon4 = _make_monitor()
    published = []
    mon4.publish = lambda ev: published.append(ev)
    mon4._process_line("Accepted password for root from 94.177.195.107 port 36477 ssh2")
    assert len(published) == 1
    ev = published[0]
    assert ev.category == EventCategory.SSH_AUTH and ev.success is True
    assert ev.username == "root" and ev.auth_method == "password"
    print("Scenario 4 (Accepted password -> SSH_AUTH success=True) PASSED")

    mon5 = _make_monitor()
    published = []
    mon5.publish = lambda ev: published.append(ev)
    mon5._process_line("Accepted publickey for deploy from 94.177.195.107 port 36477 ssh2: RSA SHA256:abc")
    assert len(published) == 1
    ev = published[0]
    assert ev.success is True and ev.auth_method == "publickey" and ev.username == "deploy"
    print("Scenario 5 (Accepted publickey -> SSH_AUTH success=True) PASSED")

    mon5b = _make_monitor()
    published = []
    mon5b.publish = lambda ev: published.append(ev)
    mon5b._process_line("Accepted keyboard-interactive/pam for admin from 94.177.195.107 port 36477 ssh2")
    assert len(published) == 1
    assert published[0].auth_method == "keyboard-interactive/pam"
    print("Scenario 5b (Accepted keyboard-interactive/pam parsed as a single auth method token) PASSED")


    clock = _FakeClock()
    an = _make_analyzer(clock)
    ip = "94.177.195.107"
    await an._on_event(_failed_event("cs", ip, status="INVALID_USER", ts=clock.now))
    clock.advance(1)
    await an._on_event(_failed_event("root", ip, status="EXISTING_USER", ts=clock.now))
    clock.advance(1)
    await an._on_event(_failed_event("root", ip, status="EXISTING_USER", ts=clock.now))
    detail = an._details["ssh_brute_force"][ip]
    assert detail.username_counts == {"cs": 1, "root": 2}
    assert detail.username_status == {"cs": "INVALID_USER", "root": "EXISTING_USER"}
    assert detail.total_attempts == 3
    print("Scenario 6+7 (multiple usernames aggregated, repeated username counted correctly) PASSED")


    clock = _FakeClock()
    an = _make_analyzer(clock)
    bus_events = []
    await an.bus.subscribe("test-sink", lambda e: bus_events.append(e) or asyncio.sleep(0), categories=list(EventCategory))
    ip = "203.0.113.5"
    attempts = [("cs", "INVALID_USER"), ("root", "EXISTING_USER"), ("admin", "INVALID_USER"),
                ("root", "EXISTING_USER"), ("ubuntu", "EXISTING_USER")]
    for username, status in attempts:
        await an._on_event(_failed_event(username, ip, status=status, ts=clock.now))
        clock.advance(1)
    brute_force_alerts = [e for e in bus_events if e.category == EventCategory.BRUTE_FORCE]
    assert len(brute_force_alerts) == 1, f"expected exactly one BRUTE_FORCE alert at threshold, got {len(brute_force_alerts)}"
    alert = brute_force_alerts[0]
    assert alert.severity == Severity.HIGH
    assert alert.metadata["source_ip"] == ip
    assert alert.metadata["username_counts"] == {"cs": 1, "root": 2, "admin": 1, "ubuntu": 1}
    assert alert.metadata["username_status"]["cs"] == "INVALID_USER"
    assert alert.metadata["username_status"]["root"] == "EXISTING_USER"
    assert alert.metadata["unique_usernames"] == 4
    assert alert.metadata["total_attempts"] == 5
    await an.bus.unsubscribe("test-sink")
    print("Scenario 8 (brute force threshold reached -> HIGH BRUTE_FORCE alert with per-username breakdown) PASSED")


    clock = _FakeClock()
    an = _make_analyzer(clock)
    bus_events = []
    await an.bus.subscribe("test-sink", lambda e: bus_events.append(e) or asyncio.sleep(0), categories=list(EventCategory))
    ip = "198.51.100.9"
    await an._on_event(_failed_event("root", ip, status="EXISTING_USER", ts=clock.now))
    clock.advance(2)
    await an._on_event(_success_event("root", ip, ts=clock.now))
    red_zone = [e for e in bus_events if e.category == EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE]
    assert red_zone == [], "a single mistyped-password-then-success must never become RED ZONE"
    await an.bus.unsubscribe("test-sink")
    print("Scenario 9 (single failed login + success -> NOT RED ZONE, normal mistyped-password case) PASSED")


    clock = _FakeClock()
    an = _make_analyzer(clock)
    bus_events = []
    await an.bus.subscribe("test-sink", lambda e: bus_events.append(e) or asyncio.sleep(0), categories=list(EventCategory))
    ip = "94.177.195.107"
    for username, status in [("cs", "INVALID_USER"), ("root", "EXISTING_USER"), ("admin", "INVALID_USER"),
                              ("root", "EXISTING_USER"), ("ubuntu", "EXISTING_USER")]:
        await an._on_event(_failed_event(username, ip, status=status, ts=clock.now))
        clock.advance(1)
    clock.advance(2)
    await an._on_event(_success_event("root", ip, ts=clock.now))
    red_zone = [e for e in bus_events if e.category == EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE]
    assert len(red_zone) == 1
    rz = red_zone[0]
    assert rz.severity == Severity.CRITICAL
    assert rz.metadata["source_ip"] == ip
    assert rz.metadata["username"] == "root"
    assert rz.metadata["brute_force_attempts"] >= 5
    print("Scenario 10 (brute force + same-IP successful login -> CRITICAL RED ZONE) PASSED")


    assert red_zone[0].metadata["same_username_as_target"] is True
    await an.bus.unsubscribe("test-sink")
    print("Scenario 11 (brute force targeted root, success as root -> SAME USERNAME correlation) PASSED")

    clock = _FakeClock()
    an = _make_analyzer(clock)
    bus_events = []
    await an.bus.subscribe("test-sink", lambda e: bus_events.append(e) or asyncio.sleep(0), categories=list(EventCategory))
    ip = "94.177.195.108"
    for username, status in [("root", "EXISTING_USER")] * 5:
        await an._on_event(_failed_event(username, ip, status=status, ts=clock.now))
        clock.advance(1)
    clock.advance(2)
    await an._on_event(_success_event("deploy", ip, ts=clock.now))
    red_zone2 = [e for e in bus_events if e.category == EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE]
    assert len(red_zone2) == 1
    assert red_zone2[0].metadata["same_username_as_target"] is False
    await an.bus.unsubscribe("test-sink")
    print("Scenario 12 (brute force targeted root, success as deploy -> DIFFERENT USERNAME correlation) PASSED")


    clock = _FakeClock()
    an = _make_analyzer(clock)
    bus_events = []
    await an.bus.subscribe("test-sink", lambda e: bus_events.append(e) or asyncio.sleep(0), categories=list(EventCategory))
    attacker_ip = "94.177.195.107"
    innocent_ip = "10.0.0.5"
    for username, status in [("root", "EXISTING_USER")] * 5:
        await an._on_event(_failed_event(username, attacker_ip, status=status, ts=clock.now))
        clock.advance(1)
    await an._on_event(_success_event("deploy", innocent_ip, ts=clock.now))
    red_zone3 = [e for e in bus_events if e.category == EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE]
    assert red_zone3 == [], "a successful login from an IP with no brute-force activity must never become RED ZONE"
    await an.bus.unsubscribe("test-sink")
    print("Scenario 13 (successful login from unrelated IP -> no brute-force-success correlation) PASSED")


    clock = _FakeClock()
    an = _make_analyzer(clock, ssh_red_zone_cooldown_seconds=300.0)
    bus_events = []
    await an.bus.subscribe("test-sink", lambda e: bus_events.append(e) or asyncio.sleep(0), categories=list(EventCategory))
    ip = "94.177.195.107"
    for username, status in [("root", "EXISTING_USER")] * 5:
        await an._on_event(_failed_event(username, ip, status=status, ts=clock.now))
        clock.advance(1)
    clock.advance(2)
    await an._on_event(_success_event("root", ip, ts=clock.now))
    clock.advance(5)
    await an._on_event(_success_event("root", ip, ts=clock.now))
    red_zone4 = [e for e in bus_events if e.category == EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE]
    assert len(red_zone4) == 1, "repeated successful logins within the cooldown window must not spam a second RED ZONE alert"
    await an.bus.unsubscribe("test-sink")
    print("Scenario 14 (repeated successful logins within cooldown -> deduplicated to one RED ZONE alert) PASSED")


    clock = _FakeClock()
    an = _make_analyzer(clock)
    ip = "203.0.113.99"
    for i in range(2000):
        await an._on_event(_failed_event(f"user{i}", ip, status="INVALID_USER", ts=clock.now))
    detail = an._details["ssh_brute_force"][ip]
    assert len(detail.username_counts) <= 50, f"username_counts must stay bounded, got {len(detail.username_counts)}"
    assert detail.truncated is True
    assert detail.total_attempts == 2000, "total attempt count must remain accurate even when the breakdown is capped"
    print("Scenario 15 (2000 distinct usernames from one IP -> bounded per-username tracking, accurate total) PASSED")


    analyzer_source = open("core/analyzer.py").read()
    for marker in ("subprocess.run(", "subprocess.Popen(", "create_subprocess", "os.system(", "socket.getaddrinfo", "requests.get"):
        assert marker not in analyzer_source, f"analyzer.py must never spawn subprocesses/external calls per event: found {marker}"
    print("Scenario 17 (core/analyzer.py contains no subprocess spawn or external network call) PASSED")


    dispatcher = DiscordWebhookDispatcher(
        EventBus(), DiscordConfig(enabled=True, alert_channel_id=555000), detection_only=False,
    )

    bf_alert = BaseEvent(
        source_module="analyzer", category=EventCategory.BRUTE_FORCE, severity=Severity.HIGH,
        message="Correlated rule 'ssh_brute_force' triggered", raw="Invalid user cs from 94.177.195.107 port 36477",
        metadata={
            "source_ip": "94.177.195.107", "observed_count": 27, "window_seconds": 60,
            "unique_usernames": 4, "first_seen": 1_000_000.0, "last_seen": 1_000_030.0,
            "username_counts": {"root": 8, "cs": 12, "admin": 5, "ubuntu": 2},
            "username_status": {"root": "EXISTING_USER", "cs": "INVALID_USER", "admin": "INVALID_USER", "ubuntu": "EXISTING_USER"},
            "auth_methods": ["password"],
        },
    )
    bf_payload = dispatcher._build_payload(bf_alert)
    bf_fields = {f["name"]: f["value"] for f in bf_payload["embeds"][0]["fields"]}
    assert bf_fields["Unique Usernames"] == "4"
    assert "cs" in bf_fields["Targeted Users"] and "INVALID USER" in bf_fields["Targeted Users"]
    assert "root" in bf_fields["Targeted Users"] and "EXISTING USER" in bf_fields["Targeted Users"]
    assert "Belum ada successful login" in bf_fields["Status"]
    bf_button_labels = [b["label"] for row in bf_payload["components"] for b in row["components"]]
    assert any("Ban IP" in label for label in bf_button_labels)
    print("Scenario 18 (BRUTE_FORCE embed shows targeted-user breakdown + ban-eligible buttons) PASSED")

    rz_alert = BaseEvent(
        source_module="analyzer", category=EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE, severity=Severity.CRITICAL,
        message="RED ZONE", raw="Accepted password for root from 94.177.195.107 port 36477 ssh2",
        metadata={
            "source_ip": "94.177.195.107", "username": "root", "auth_method": "password",
            "brute_force_attempts": 27, "brute_force_threshold": 5, "brute_force_window_seconds": 60,
            "same_username_as_target": True, "successful_login_at": 1_000_060.0,
            "first_seen": 1_000_000.0, "last_seen": 1_000_030.0,
            "seconds_between_first_attempt_and_success": 60.0,
            "username_counts": {"root": 8, "cs": 12, "admin": 5, "ubuntu": 2},
            "username_status": {"root": "EXISTING_USER", "cs": "INVALID_USER", "admin": "INVALID_USER", "ubuntu": "EXISTING_USER"},
        },
    )
    rz_payload = dispatcher._build_payload(rz_alert)
    assert rz_payload["embeds"][0]["title"] == "RTSA ALERT — SSH LOGIN AFTER BRUTE FORCE (RED ZONE)"
    rz_fields = {f["name"]: f["value"] for f in rz_payload["embeds"][0]["fields"]}
    assert rz_fields["Username"] == "root"
    assert rz_fields["Login"] == "SUCCESSFUL"
    assert "SAME USERNAME" in rz_fields["Correlation"]
    assert "cs" in rz_fields["Previous Attempts"]
    assert rz_fields["Time Between"] == "1m 0s"
    rz_button_labels = [b["label"] for row in rz_payload["components"] for b in row["components"]]
    assert any("Ban IP" in label for label in rz_button_labels), "RED ZONE must still require explicit operator ban action via the button"
    print("Scenario 19 (RED ZONE embed shows correlation/timeline fields + manual-ban button, no auto-ban) PASSED")

    print("\nALL SSH BRUTE-FORCE RED-ZONE CORRELATION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
