import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, SSHEvent, Severity
from core.event_bus import EventBus
from discord_integration.bot import _ssh_auth_incident_blocks_kick
from discord_integration.webhook import DiscordWebhookDispatcher, _ssh_mitigation_eligible


class _ReadyBot:
    def is_ready(self) -> bool:
        return True


def _make_dispatcher(detection_only: bool = False, **outbound_overrides) -> DiscordWebhookDispatcher:
    outbound = OutboundBackpressureConfig(**outbound_overrides)
    config = DiscordConfig(enabled=True, alert_channel_id=555000, outbound=outbound)
    return DiscordWebhookDispatcher(EventBus(), config, detection_only=detection_only)


def _trusted_login_event(user: str = "deploy", ip: str = "10.0.0.5", pid: int = 4242) -> SSHEvent:
    return SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_AUTH,
        severity=Severity.LOW, message=f"SSH login diterima untuk '{user}' dari {ip} lewat publickey",
        raw=f"Accepted publickey for {user} from {ip} port 51000 ssh2",
        username=user, source_ip=ip, auth_method="publickey", success=True, pid=pid,
        metadata={
            "hostname": "srv1", "server_name": "srv1",
            "pid": pid, "pid_create_time": 12345.0,
            "risk_reason": "Login SSH berhasil melalui jalur administrasi resmi (SSH).",
            "recommendation": "Tidak diperlukan tindakan.",
            "trusted_linux_user": True,
        },
    )


def _untrusted_login_event(user: str = "www-data", ip: str = "203.0.113.9", pid: int = 5150) -> SSHEvent:
    return SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_AUTH,
        severity=Severity.CRITICAL, message=f"SSH login diterima untuk '{user}' dari {ip} lewat password",
        raw=f"Accepted password for {user} from {ip} port 51001 ssh2",
        username=user, source_ip=ip, auth_method="password", success=True, pid=pid,
        metadata={
            "hostname": "srv1", "server_name": "srv1",
            "pid": pid, "pid_create_time": 54321.0,
            "risk_reason": (
                f"Login SSH berhasil sebagai Linux user '{user}' yang TIDAK ada di daftar "
                f"trusted_linux_users -- pada server dengan banyak user per-tenant CloudPanel, ini sangat mencurigakan."
            ),
            "recommendation": "Verifikasi SEGERA apakah ini benar-benar dilakukan admin.",
            "trusted_linux_user": False,
        },
    )


def _logout_event(user: str = "deploy") -> BaseEvent:
    return BaseEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_LOGOUT,
        severity=Severity.INFO, message=f"SSH session ditutup untuk '{user}'",
        raw="", metadata={"session_duration": "5m", "hostname": "srv1", "server_name": "srv1"},
    )


def _brute_force_event() -> BaseEvent:
    return BaseEvent(
        source_module="analyzer", category=EventCategory.BRUTE_FORCE, severity=Severity.HIGH,
        message="brute force threshold tercapai", raw="",
        metadata={"source_ip": "198.51.100.4"}, host=None,
    )


def _credential_stuffing_event() -> BaseEvent:
    return BaseEvent(
        source_module="analyzer", category=EventCategory.SSH_CREDENTIAL_STUFFING, severity=Severity.HIGH,
        message="credential stuffing threshold tercapai", raw="",
        metadata={"source_ip": "198.51.100.5"},
    )


def _button_custom_ids(payload) -> list:
    ids = []
    for row in payload.get("components", []):
        for comp in row.get("components", []):
            ids.append(comp["custom_id"])
    return ids


async def test_1_trusted_successful_login_no_mitigation() -> None:
    dispatcher = _make_dispatcher()
    dispatcher._bot = _ReadyBot()
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append((category, payload))
        return "OK", channel_id, 1

    dispatcher._send_via_bot = fake_send
    await dispatcher._on_event(_trusted_login_event())

    assert len(sent) == 1, f"expected exactly one realtime SSH_AUTH notification, got {len(sent)}"
    category, payload = sent[0]
    assert category == "SSH_AUTH"
    custom_ids = _button_custom_ids(payload)
    assert not any(cid.startswith("rtsa_action:kickssh:") for cid in custom_ids), (
        f"successful trusted SSH_AUTH must never offer a Kick button: {custom_ids}"
    )
    assert not any(cid.startswith("rtsa_action:ban:") for cid in custom_ids), (
        f"successful trusted SSH_AUTH must never offer a Ban button: {custom_ids}"
    )
    assert any(cid.startswith("rtsa_action:ignore:") for cid in custom_ids)
    assert any(cid.startswith("rtsa_action:timeline:") for cid in custom_ids)
    print("Test 1 (trusted publickey SSH_AUTH success -- exactly 1 realtime notification, zero kick, zero ban) PASSED")


async def test_2_untrusted_successful_login_still_no_kick() -> None:
    dispatcher = _make_dispatcher()
    dispatcher._bot = _ReadyBot()
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append((category, payload))
        return "OK", channel_id, 1

    dispatcher._send_via_bot = fake_send
    await dispatcher._on_event(_untrusted_login_event())

    assert len(sent) == 1
    _, payload = sent[0]
    custom_ids = _button_custom_ids(payload)
    assert not any(cid.startswith("rtsa_action:kickssh:") for cid in custom_ids), (
        f"a successful (non-attack) SSH_AUTH login must never offer a Kick button, even for an "
        f"unrecognized/untrusted user -- success alone is not attack evidence: {custom_ids}"
    )
    assert not any(cid.startswith("rtsa_action:ban:") for cid in custom_ids)
    print("Test 2 (successful non-attack SSH_AUTH -- no kick regardless of trust classification) PASSED")


async def test_3_brute_force_mitigation_unchanged() -> None:
    dispatcher = _make_dispatcher()
    dispatcher._bot = _ReadyBot()
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append((category, payload))
        return "OK", channel_id, 1

    dispatcher._send_via_bot = fake_send
    await dispatcher._on_event(_brute_force_event())

    assert len(sent) == 1
    _, payload = sent[0]
    custom_ids = _button_custom_ids(payload)
    assert any(cid.startswith("rtsa_action:ban:") for cid in custom_ids), (
        f"BRUTE_FORCE must remain mitigation-eligible (Ban button present) -- policy must not regress: {custom_ids}"
    )
    assert _ssh_mitigation_eligible(_brute_force_event()) is True
    print("Test 3 (BRUTE_FORCE threshold reached -- mitigation behavior unchanged, Ban button present) PASSED")


async def test_4_credential_stuffing_policy_unchanged() -> None:
    dispatcher = _make_dispatcher()
    dispatcher._bot = _ReadyBot()
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append((category, payload))
        return "OK", channel_id, 1

    dispatcher._send_via_bot = fake_send
    await dispatcher._on_event(_credential_stuffing_event())

    assert len(sent) == 1
    _, payload = sent[0]
    custom_ids = _button_custom_ids(payload)
    assert not any(cid.startswith("rtsa_action:kickssh:") for cid in custom_ids), (
        f"SSH_CREDENTIAL_STUFFING must never offer an SSH-session Kick button (that action only "
        f"ever existed for successful-login incidents): {custom_ids}"
    )
    print("Test 4 (SSH_CREDENTIAL_STUFFING threshold reached -- pre-existing mitigation policy preserved) PASSED")


async def test_5_low_severity_never_becomes_kick_failed() -> None:
    dispatcher = _make_dispatcher()
    dispatcher._bot = _ReadyBot()
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append((category, payload))
        return "OK", channel_id, 1

    dispatcher._send_via_bot = fake_send
    event = _trusted_login_event()
    assert event.severity == Severity.LOW
    await dispatcher._on_event(event)

    _, payload = sent[0]
    assert payload["embeds"][0]["title"] == f"RTSA Alert — {EventCategory.SSH_AUTH.value}"
    custom_ids = _button_custom_ids(payload)
    assert not any(cid.startswith("rtsa_action:kickssh:") for cid in custom_ids), (
        "a LOW-severity successful SSH_AUTH must never carry a Kick button that could later be "
        "finalized as 'Kick Failed'"
    )
    print("Test 5 (SSH_AUTH severity LOW -- never carries a path to 'Kick Failed') PASSED")


async def test_6_trusted_user_realtime_still_delivered() -> None:
    dispatcher = _make_dispatcher()
    dispatcher._bot = _ReadyBot()
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append(category)
        return "OK", channel_id, 1

    dispatcher._send_via_bot = fake_send
    await dispatcher._on_event(_trusted_login_event())
    assert sent == ["SSH_AUTH"], f"trusted-user successful SSH login must still be delivered realtime: {sent}"
    assert dispatcher._total_below_floor == 0
    print("Test 6 (trusted user SSH_AUTH -- realtime Discord notification still sent per existing policy) PASSED")


def test_7_mitigation_eligibility_predicate() -> None:
    assert _ssh_mitigation_eligible(_trusted_login_event()) is False
    assert _ssh_mitigation_eligible(_untrusted_login_event()) is False
    assert _ssh_mitigation_eligible(_logout_event()) is False
    assert _ssh_mitigation_eligible(_brute_force_event()) is True
    print("Test 7 (mitigation_eligible: SSH_AUTH/SSH_LOGOUT=false, BRUTE_FORCE=true) PASSED")


def test_8_no_hardcoded_kick_failed_string_outside_bot_button_handler() -> None:
    import inspect
    import discord_integration.webhook as webhook_module
    webhook_source = inspect.getsource(webhook_module)
    assert "Kick Failed" not in webhook_source, (
        "webhook.py (event -> Discord payload formatting) must never itself decide 'Kick Failed' -- "
        "that string may only ever be produced as a manual button-click *result* label in bot.py"
    )
    print("Test 8 ('Kick Failed' string does not originate from the event formatter, only from bot.py's button result) PASSED")


def test_9_stale_kickssh_button_refused_by_handler_guard() -> None:
    assert _ssh_auth_incident_blocks_kick({"category": "SSH_AUTH"}) is True
    assert _ssh_auth_incident_blocks_kick({"category": "PERSISTENCE_NEW_PORT"}) is False
    assert _ssh_auth_incident_blocks_kick({}) is False
    print(
        "Test 9 (bot.py kickssh handler guard: even a stale pre-fix button click on an SSH_AUTH "
        "incident is refused before _kick_ssh_session ever runs) PASSED"
    )


async def main() -> None:
    await test_1_trusted_successful_login_no_mitigation()
    await test_2_untrusted_successful_login_still_no_kick()
    await test_3_brute_force_mitigation_unchanged()
    await test_4_credential_stuffing_policy_unchanged()
    await test_5_low_severity_never_becomes_kick_failed()
    await test_6_trusted_user_realtime_still_delivered()
    test_7_mitigation_eligibility_predicate()
    test_8_no_hardcoded_kick_failed_string_outside_bot_button_handler()
    test_9_stale_kickssh_button_refused_by_handler_guard()
    print("\nALL SSH_AUTH KICK FALSE-MITIGATION FIX TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
