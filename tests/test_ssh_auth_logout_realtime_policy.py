import asyncio
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import ConfigManager, DiscordConfig, OutboundBackpressureConfig, SSHMonitorConfig
from core.datatypes import BaseEvent, EventCategory, SSHEvent, Severity
from core.event_bus import EventBus
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.ssh_monitor import SSHMonitor

_CONFIG_DIR = os.path.join(_REPO_ROOT, "config")
_SERVER1_PROFILE = os.path.join(_CONFIG_DIR, "discord-server1.yaml")
_SERVER2_PROFILE = os.path.join(_CONFIG_DIR, "discord-server2.yaml")


class _UnavailableBot:
    def is_ready(self) -> bool:
        return False


class _ReadyBot:
    def is_ready(self) -> bool:
        return True


def _make_dispatcher(**outbound_overrides) -> DiscordWebhookDispatcher:
    outbound = OutboundBackpressureConfig(**outbound_overrides)
    config = DiscordConfig(enabled=True, alert_channel_id=555000, outbound=outbound)
    return DiscordWebhookDispatcher(EventBus(), config)


def _login_event(user: str = "deploy", ip: str = "10.0.0.5") -> SSHEvent:
    return SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_AUTH,
        severity=Severity.INFO, message=f"SSH login diterima untuk '{user}' dari {ip} lewat publickey",
        raw="", username=user, source_ip=ip, auth_method="publickey", success=True,
        metadata={"hostname": "srv1", "server_name": "srv1"},
    )


def _logout_event(user: str = "deploy", ip: str = "10.0.0.5") -> BaseEvent:
    return BaseEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_LOGOUT,
        severity=Severity.INFO, message=f"SSH session ditutup untuk '{user}'",
        raw="", metadata={"session_duration": "5m", "hostname": "srv1", "server_name": "srv1"},
    )


def _failed_login_event(ip: str) -> SSHEvent:
    return SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_AUTH,
        severity=Severity.INFO, message=f"SSH login GAGAL dari {ip}",
        raw="", username="root", source_ip=ip, auth_method="password", success=False,
        metadata={},
    )


def _brute_force_event(i: int) -> BaseEvent:
    return BaseEvent(
        source_module="analyzer", category=EventCategory.BRUTE_FORCE, severity=Severity.HIGH,
        message=f"brute force attempt {i}", raw="", metadata={},
    )


async def test_1_successful_login_exactly_one_realtime_notification() -> None:
    dispatcher = _make_dispatcher()
    dispatcher._bot = _ReadyBot()
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append(category)
        return "OK", channel_id, 1

    dispatcher._send_via_bot = fake_send
    await dispatcher._on_event(_login_event())
    assert sent == ["SSH_AUTH"], f"expected exactly one realtime SSH_AUTH notification, got {sent}"
    assert dispatcher._total_below_floor == 0
    print("Test 1 (successful SSH login -> exactly 1 realtime Discord notification) PASSED")


async def test_2_logout_exactly_one_realtime_notification() -> None:
    dispatcher = _make_dispatcher()
    dispatcher._bot = _ReadyBot()
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append(category)
        return "OK", channel_id, 1

    dispatcher._send_via_bot = fake_send
    await dispatcher._on_event(_logout_event())
    assert sent == ["SSH_LOGOUT"], f"expected exactly one realtime SSH_LOGOUT notification, got {sent}"
    assert dispatcher._total_below_floor == 0, (
        "SSH_LOGOUT (severity=INFO by default) must never be silently dropped below the outbound "
        "severity floor -- this is the exact regression this fix addresses"
    )
    print("Test 2 (SSH logout -> exactly 1 realtime Discord notification) PASSED")


async def test_3_100_failed_logins_not_100_realtime_notifications() -> None:
    dispatcher = _make_dispatcher()
    dispatcher._bot = _ReadyBot()
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append(category)
        return "OK", channel_id, 1

    dispatcher._send_via_bot = fake_send
    for i in range(100):
        await dispatcher._on_event(_failed_login_event(f"203.0.113.{i % 250}"))
    assert len(sent) < 100, (
        f"100 low-signal failed-login attempts (severity=INFO, the ssh_monitor default when "
        f"alert_on_login_failure=False) must not produce 100 realtime Discord notifications, got {len(sent)}"
    )
    print(f"Test 3 (100 failed SSH login attempts -> {len(sent)} realtime notifications, not 100) PASSED")


async def test_4_brute_force_aggregates_per_policy() -> None:
    dispatcher = _make_dispatcher(
        aggregation_window_seconds=999.0, aggregation_min_count=3, critical_aggregation_min_count=3,
    )
    dispatcher._bot = _UnavailableBot()
    for i in range(3):
        await dispatcher._on_event(_brute_force_event(i))
    assert dispatcher._total_aggregated > 0, "BRUTE_FORCE events must still be eligible for aggregation"
    assert len(dispatcher._pending_heap) == 1, "3 matching BRUTE_FORCE alerts must collapse into 1 summary"
    print("Test 4 (BRUTE_FORCE aggregates per policy) PASSED")


async def test_5_ssh_auth_never_aggregated() -> None:
    dispatcher = _make_dispatcher(aggregation_window_seconds=999.0, aggregation_min_count=2)
    dispatcher._bot = _UnavailableBot()
    for i in range(5):
        await dispatcher._on_event(_login_event(user=f"user{i}", ip=f"10.0.0.{i}"))
    assert dispatcher._total_aggregated == 0, "SSH_AUTH must never be merged into an aggregate summary message"
    assert len(dispatcher._pending_heap) == 5, (
        f"each of the 5 individual SSH_AUTH logins must remain a separate pending alert, "
        f"got {len(dispatcher._pending_heap)}"
    )
    print("Test 5 (SSH_AUTH never enters aggregation, 5 logins stay 5 separate pending alerts) PASSED")


async def test_6_ssh_logout_never_aggregated() -> None:
    dispatcher = _make_dispatcher(aggregation_window_seconds=999.0, aggregation_min_count=2)
    dispatcher._bot = _UnavailableBot()
    for i in range(5):
        await dispatcher._on_event(_logout_event(user=f"user{i}", ip=f"10.0.0.{i}"))
    assert dispatcher._total_aggregated == 0, "SSH_LOGOUT must never be merged into an aggregate summary message"
    assert len(dispatcher._pending_heap) == 5
    print("Test 6 (SSH_LOGOUT never enters aggregation, 5 logouts stay 5 separate pending alerts) PASSED")


def test_7_duplicate_log_line_no_duplicate_notification() -> None:
    bus = EventBus()
    mon = SSHMonitor(bus, SSHMonitorConfig(enabled=True, geoip_lookup=False))
    published = []
    mon.publish = lambda ev: published.append(ev)

    line = "Accepted publickey for deploy from 10.0.0.5 port 51000 ssh2: RSA SHA256:abc123"
    mon._process_line(line)
    mon._process_line(line)
    assert len(published) == 1, f"an identical raw log line processed twice must publish exactly once, got {len(published)}"
    assert mon._duplicate_lines_suppressed_total == 1

    different_line = "Accepted publickey for deploy from 10.0.0.5 port 51999 ssh2: RSA SHA256:abc123"
    mon._process_line(different_line)
    assert len(published) == 2, "a genuinely distinct login (different source port) must still be published"
    print("Test 7 (duplicate log line -> no duplicate notification, distinct lines still publish) PASSED")


def test_8_whitelisted_ssh_event_follows_existing_semantics() -> None:
    bus = EventBus()
    mon = SSHMonitor(bus, SSHMonitorConfig(enabled=True, geoip_lookup=False, ignored_users=["backup-agent"]))
    published = []
    mon.publish = lambda ev: published.append(ev)

    mon._process_line("Accepted publickey for backup-agent from 10.0.0.9 port 40000 ssh2: RSA SHA256:xyz")
    assert published == [], "a user in ignored_users (whitelist) must never publish an SSH_AUTH event at all"

    mon._process_line("Accepted publickey for deploy from 10.0.0.9 port 40001 ssh2: RSA SHA256:xyz")
    assert len(published) == 1, "a non-whitelisted user must still publish normally"
    print("Test 8 (whitelisted/ignored SSH user follows existing suppression semantics) PASSED")


def test_9_server1_uses_server1_ssh_channel() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(f'discord:\n  enabled: false\n  channel_config_file: "{_SERVER1_PROFILE}"\n')
        cm = ConfigManager(cfg_path)
    assert cm.config.discord.category_channels.get("SSH_AUTH") == 1529383105679589396
    assert cm.config.discord.category_channels.get("SSH_LOGOUT") == 1529383105679589396
    print("Test 9 (Server1 SSH_AUTH/SSH_LOGOUT route to Server1's own SSH channel) PASSED")


def test_10_server2_uses_server2_ssh_channel() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                'discord:\n  enabled: false\n  channel_config_file: "{}"\n'.format(_SERVER2_PROFILE)
            )
        cm = ConfigManager(cfg_path)
    assert cm.config.discord.category_channels.get("SSH_AUTH") == 1527175793761980498
    assert cm.config.discord.category_channels.get("SSH_LOGOUT") == 1527175793761980498
    assert cm.config.discord.category_channels.get("SSH_AUTH") != 1529383105679589396, (
        "Server2's SSH channel must be distinct from Server1's, never hardcoded/shared by accident"
    )
    print("Test 10 (Server2 SSH_AUTH/SSH_LOGOUT route to Server2's own, distinct SSH channel) PASSED")


async def test_11_other_outbound_reductions_still_work() -> None:
    dispatcher = _make_dispatcher()
    dispatcher.config = DiscordConfig(
        enabled=True, alert_channel_id=555000, outbound=OutboundBackpressureConfig(),
    )
    from config.manager import NotificationPolicyConfig
    import dataclasses
    dispatcher.config = dataclasses.replace(
        dispatcher.config,
        notification_policy=NotificationPolicyConfig(
            enabled=True, internal_only_categories=["WEBSITE_DOWN", "pm2_monitor:SERVICE_DOWN"],
        ),
    )
    dispatcher._bot = _ReadyBot()
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append(category)
        return "OK", channel_id, 1

    dispatcher._send_via_bot = fake_send
    website_down = BaseEvent(
        source_module="website_monitor", category=EventCategory.WEBSITE_DOWN,
        severity=Severity.HIGH, message="down", raw="", metadata={},
    )
    await dispatcher._on_event(website_down)
    assert sent == [], "WEBSITE_DOWN must remain internal_only-suppressed -- SSH realtime fix must not weaken it"
    assert dispatcher._total_policy_suppressed == 1

    pm2_down = BaseEvent(
        source_module="pm2_monitor", category=EventCategory.SERVICE_DOWN,
        severity=Severity.HIGH, message="down", raw="", metadata={},
    )
    await dispatcher._on_event(pm2_down)
    assert sent == [], "pm2_monitor:SERVICE_DOWN must remain internal_only-suppressed"
    assert dispatcher._total_policy_suppressed == 2
    print("Test 11 (other outbound reductions -- WEBSITE_DOWN/PM2 internal_only -- still work unaffected) PASSED")


async def main() -> None:
    await test_1_successful_login_exactly_one_realtime_notification()
    await test_2_logout_exactly_one_realtime_notification()
    await test_3_100_failed_logins_not_100_realtime_notifications()
    await test_4_brute_force_aggregates_per_policy()
    await test_5_ssh_auth_never_aggregated()
    await test_6_ssh_logout_never_aggregated()
    test_7_duplicate_log_line_no_duplicate_notification()
    test_8_whitelisted_ssh_event_follows_existing_semantics()
    test_9_server1_uses_server1_ssh_channel()
    test_10_server2_uses_server2_ssh_channel()
    await test_11_other_outbound_reductions_still_work()
    print("\nALL SSH AUTH/LOGOUT REALTIME NOTIFICATION POLICY TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
