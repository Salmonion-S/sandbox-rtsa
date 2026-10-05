import asyncio
import os
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import ConfigManager, DiscordConfig, OutboundBackpressureConfig, SSHMonitorConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import DiscordWebhookDispatcher, _LOAD_OVERLOADED
from modules.ssh_monitor import SSHMonitor

_CONFIG_DIR = os.path.join(_REPO_ROOT, "config")
_SERVER1_PROFILE = os.path.join(_CONFIG_DIR, "discord-server1.yaml")
_SERVER2_PROFILE = os.path.join(_CONFIG_DIR, "discord-server2.yaml")


class _ReadyBot:
    def is_ready(self) -> bool:
        return True


def _make_dispatcher(**outbound_overrides) -> DiscordWebhookDispatcher:
    outbound = OutboundBackpressureConfig(**outbound_overrides)
    config = DiscordConfig(enabled=True, alert_channel_id=555000, outbound=outbound)
    dispatcher = DiscordWebhookDispatcher(EventBus(), config)
    dispatcher._bot = _ReadyBot()
    return dispatcher


def _wire_sent_collector(dispatcher):
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append((category, channel_id))
        return "OK", channel_id, 1

    dispatcher._send_via_bot = fake_send
    return sent


def _real_login_event(ssh_config: SSHMonitorConfig, username: str, ip: str = "10.0.0.5"):
    mon = SSHMonitor(EventBus(), ssh_config)
    published = []
    mon.publish = lambda ev: published.append(ev)
    mon._process_line(f"Accepted publickey for {username} from {ip} port 40001 ssh2: RSA SHA256:abc")
    assert len(published) == 1, "SSHMonitor must publish exactly one SSH_AUTH event for one Accepted line"
    return published[0]


async def test_1_successful_login_trusted_user_one_notification() -> None:
    ssh_cfg = SSHMonitorConfig(enabled=True, geoip_lookup=False, trusted_linux_users=["newusproud"], alert_on_login_logout=False)
    event = _real_login_event(ssh_cfg, "newusproud")
    assert event.success is True and event.category == EventCategory.SSH_AUTH

    dispatcher = _make_dispatcher()
    sent = _wire_sent_collector(dispatcher)
    await dispatcher._on_event(event)
    assert len(sent) == 1, f"trusted user 'newusproud' successful login must still produce exactly 1 realtime notification, got {sent}"
    print("Test 1 (successful SSH login, trusted user -> exactly 1 Discord notification) PASSED")


async def test_2_successful_login_untrusted_user_one_notification() -> None:
    ssh_cfg = SSHMonitorConfig(enabled=True, geoip_lookup=False, trusted_linux_users=[], alert_on_login_logout=False)
    event = _real_login_event(ssh_cfg, "randomvisitor")
    assert event.success is True

    dispatcher = _make_dispatcher()
    sent = _wire_sent_collector(dispatcher)
    await dispatcher._on_event(event)
    assert len(sent) == 1, f"untrusted user successful login must produce exactly 1 realtime notification, got {sent}"
    print("Test 2 (successful SSH login, untrusted user -> exactly 1 Discord notification) PASSED")


async def test_3_logout_one_notification() -> None:
    dispatcher = _make_dispatcher()
    sent = _wire_sent_collector(dispatcher)
    logout = BaseEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_LOGOUT, severity=Severity.INFO,
        message="SSH session ditutup untuk 'newusproud'", raw="", metadata={},
    )
    await dispatcher._on_event(logout)
    assert len(sent) == 1
    print("Test 3 (SSH logout -> exactly 1 Discord notification) PASSED")


async def test_4_trusted_user_does_not_suppress_ssh_auth() -> None:
    ssh_cfg_trusted = SSHMonitorConfig(enabled=True, geoip_lookup=False, trusted_linux_users=["newusproud"], alert_on_login_logout=False)
    ssh_cfg_untrusted = SSHMonitorConfig(enabled=True, geoip_lookup=False, trusted_linux_users=[], alert_on_login_logout=False)
    trusted_event = _real_login_event(ssh_cfg_trusted, "newusproud")
    untrusted_event = _real_login_event(ssh_cfg_untrusted, "newusproud")

    dispatcher = _make_dispatcher()
    sent = _wire_sent_collector(dispatcher)
    await dispatcher._on_event(trusted_event)
    await dispatcher._on_event(untrusted_event)
    assert len(sent) == 2, (
        f"whether or not 'newusproud' is in trusted_linux_users must never change whether the "
        f"successful SSH_AUTH notification is sent -- only its severity/enrichment path -- got {sent}"
    )
    print("Test 4 (trusted_linux_users membership never suppresses SSH_AUTH delivery, only severity) PASSED")


async def test_5_alert_on_login_logout_false_does_not_remove_ssh_auth() -> None:
    ssh_cfg = SSHMonitorConfig(enabled=True, geoip_lookup=False, trusted_linux_users=["svcacct"], alert_on_login_logout=False)
    event = _real_login_event(ssh_cfg, "svcacct")
    assert event.severity == Severity.INFO, (
        "with alert_on_login_logout=false and a trusted user, ssh_monitor.py assigns severity=INFO -- "
        "this is exactly the case that must still bypass the outbound severity floor"
    )
    dispatcher = _make_dispatcher()
    sent = _wire_sent_collector(dispatcher)
    await dispatcher._on_event(event)
    assert len(sent) == 1, "alert_on_login_logout=false must never cause a successful SSH_AUTH to be dropped"
    assert dispatcher._total_below_floor == 0
    print("Test 5 (alert_on_login_logout=false does not remove successful SSH_AUTH realtime delivery) PASSED")


def test_6_ignored_users_explicit_still_suppressed() -> None:
    ssh_cfg = SSHMonitorConfig(enabled=True, geoip_lookup=False, ignored_users=["backup-agent"])
    mon = SSHMonitor(EventBus(), ssh_cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)
    mon._process_line("Accepted publickey for backup-agent from 10.0.0.9 port 40000 ssh2: RSA SHA256:xyz")
    assert published == [], "a user in ignored_users (explicit whitelist) must never publish an SSH_AUTH event"
    mon._process_line("Accepted publickey for someoneelse from 10.0.0.9 port 40002 ssh2: RSA SHA256:xyz")
    assert len(published) == 1, "a non-whitelisted user must still publish normally"
    print("Test 6 (explicit ignored_users still suppresses at publish time, unrelated to trusted_linux_users) PASSED")


def test_7_duplicate_ssh_log_line_one_notification() -> None:
    ssh_cfg = SSHMonitorConfig(enabled=True, geoip_lookup=False)
    mon = SSHMonitor(EventBus(), ssh_cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)
    line = "Accepted publickey for deploy from 10.0.0.5 port 51000 ssh2: RSA SHA256:abc123"
    mon._process_line(line)
    mon._process_line(line)
    assert len(published) == 1, f"an identical raw SSH log line processed twice must publish exactly once, got {len(published)}"
    print("Test 7 (duplicate SSH log line -> exactly 1 notification) PASSED")


async def test_8_brute_force_remains_aggregated() -> None:
    dispatcher = _make_dispatcher(aggregation_window_seconds=999.0, aggregation_min_count=3, critical_aggregation_min_count=3)

    class _UnavailableBot:
        def is_ready(self):
            return False

    dispatcher._bot = _UnavailableBot()
    for i in range(3):
        ev = BaseEvent(
            source_module="analyzer", category=EventCategory.BRUTE_FORCE, severity=Severity.HIGH,
            message=f"brute force {i}", raw="", metadata={},
        )
        await dispatcher._on_event(ev)
    assert dispatcher._total_aggregated > 0, "BRUTE_FORCE must remain eligible for aggregation"
    assert len(dispatcher._pending_heap) == 1
    print("Test 8 (BRUTE_FORCE remains aggregated) PASSED")


async def test_9_ssh_credential_stuffing_remains_aggregated() -> None:
    dispatcher = _make_dispatcher(aggregation_window_seconds=999.0, aggregation_min_count=3, critical_aggregation_min_count=3)

    class _UnavailableBot:
        def is_ready(self):
            return False

    dispatcher._bot = _UnavailableBot()
    for i in range(3):
        ev = BaseEvent(
            source_module="analyzer", category=EventCategory.SSH_CREDENTIAL_STUFFING, severity=Severity.HIGH,
            message=f"credential stuffing {i}", raw="", metadata={},
        )
        await dispatcher._on_event(ev)
    assert dispatcher._total_aggregated > 0, "SSH_CREDENTIAL_STUFFING must remain eligible for aggregation"
    assert len(dispatcher._pending_heap) == 1
    print("Test 9 (SSH_CREDENTIAL_STUFFING remains aggregated) PASSED")


async def test_10_ssh_auth_bypasses_severity_floor() -> None:
    dispatcher = _make_dispatcher()
    sent = _wire_sent_collector(dispatcher)
    ssh_cfg = SSHMonitorConfig(enabled=True, geoip_lookup=False, trusted_linux_users=["deploy"], alert_on_login_logout=False)
    event = _real_login_event(ssh_cfg, "deploy")
    assert event.severity in (Severity.INFO, Severity.LOW)
    await dispatcher._on_event(event)
    assert len(sent) == 1
    assert dispatcher._total_below_floor == 0
    print("Test 10 (SSH_AUTH bypasses the outbound severity floor) PASSED")


async def test_11_ssh_logout_bypasses_severity_floor() -> None:
    dispatcher = _make_dispatcher()
    sent = _wire_sent_collector(dispatcher)
    logout = BaseEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_LOGOUT, severity=Severity.INFO,
        message="logout", raw="", metadata={},
    )
    await dispatcher._on_event(logout)
    assert len(sent) == 1
    assert dispatcher._total_below_floor == 0
    print("Test 11 (SSH_LOGOUT bypasses the outbound severity floor) PASSED")


async def test_12_ssh_auth_bypasses_load_shedding() -> None:
    dispatcher = _make_dispatcher()
    sent = _wire_sent_collector(dispatcher)
    dispatcher._load_shed_state = _LOAD_OVERLOADED
    ssh_cfg = SSHMonitorConfig(enabled=True, geoip_lookup=False)
    event = _real_login_event(ssh_cfg, "deploy")
    await dispatcher._on_event(event)
    assert len(sent) == 1, "SSH_AUTH (successful) must bypass load shedding even under OVERLOADED"
    assert dispatcher._total_shed == 0
    print("Test 12 (SSH_AUTH bypasses load shedding under OVERLOADED) PASSED")


async def test_13_ssh_logout_bypasses_load_shedding() -> None:
    dispatcher = _make_dispatcher()
    sent = _wire_sent_collector(dispatcher)
    dispatcher._load_shed_state = _LOAD_OVERLOADED
    logout = BaseEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_LOGOUT, severity=Severity.INFO,
        message="logout", raw="", metadata={},
    )
    await dispatcher._on_event(logout)
    assert len(sent) == 1, "SSH_LOGOUT must bypass load shedding even under OVERLOADED"
    assert dispatcher._total_shed == 0
    print("Test 13 (SSH_LOGOUT bypasses load shedding under OVERLOADED) PASSED")


def test_14_correct_server1_channel() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(f'discord:\n  enabled: false\n  channel_config_file: "{_SERVER1_PROFILE}"\n')
        cm = ConfigManager(cfg_path)
    assert cm.config.discord.category_channels.get("SSH_AUTH") == 1529383105679589396
    assert cm.config.discord.category_channels.get("SSH_LOGOUT") == 1529383105679589396
    print("Test 14 (Server1 SSH_AUTH/SSH_LOGOUT route to the configured Server1 SSH channel) PASSED")


def test_15_correct_server2_channel() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                'discord:\n  enabled: false\n  channel_config_file: "{}"\n'.format(_SERVER2_PROFILE)
            )
        cm = ConfigManager(cfg_path)
    assert cm.config.discord.category_channels.get("SSH_AUTH") == 1527175793761980498
    assert cm.config.discord.category_channels.get("SSH_LOGOUT") == 1527175793761980498
    print("Test 15 (Server2 SSH_AUTH/SSH_LOGOUT route to the configured Server2 SSH channel) PASSED")


async def main() -> None:
    await test_1_successful_login_trusted_user_one_notification()
    await test_2_successful_login_untrusted_user_one_notification()
    await test_3_logout_one_notification()
    await test_4_trusted_user_does_not_suppress_ssh_auth()
    await test_5_alert_on_login_logout_false_does_not_remove_ssh_auth()
    test_6_ignored_users_explicit_still_suppressed()
    test_7_duplicate_ssh_log_line_one_notification()
    await test_8_brute_force_remains_aggregated()
    await test_9_ssh_credential_stuffing_remains_aggregated()
    await test_10_ssh_auth_bypasses_severity_floor()
    await test_11_ssh_logout_bypasses_severity_floor()
    await test_12_ssh_auth_bypasses_load_shedding()
    await test_13_ssh_logout_bypasses_load_shedding()
    test_14_correct_server1_channel()
    test_15_correct_server2_channel()
    print("\nALL SSH TRUSTED-USER / REALTIME AUDIT TESTS PASSED (15/15)")


asyncio.run(asyncio.wait_for(main(), timeout=60))
