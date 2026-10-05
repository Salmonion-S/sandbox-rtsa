import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, NotificationPolicyConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import _SEND_OK, DiscordWebhookDispatcher


class _FakeBot:
    def is_ready(self) -> bool:
        return True


def _make_dispatcher(internal_only_categories):
    config = DiscordConfig(
        category_channels={
            "WEBSITE_DOWN": 1111111111111111111,
            "pm2_monitor:SERVICE_DOWN": 2222222222222222222,
            "SERVICE_DOWN": 3333333333333333333,
        },
        alert_channel_id=999999999999999999,
        notification_policy=NotificationPolicyConfig(
            enabled=True, internal_only_categories=internal_only_categories,
        ),
        outbound=OutboundBackpressureConfig(dedup_window_seconds=0.0),
    )
    dispatcher = DiscordWebhookDispatcher(EventBus(), config)
    dispatcher._bot = _FakeBot()
    return dispatcher


async def main() -> None:
    policy = ["WEBSITE_DOWN", "WEBSITE_RECOVERED", "pm2_monitor:SERVICE_DOWN", "pm2_monitor:SERVICE_RECOVERED"]
    dispatcher = _make_dispatcher(policy)
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append((source_module, category))
        return _SEND_OK, channel_id, 1
    dispatcher._send_via_bot = fake_send

    website_down = BaseEvent(
        source_module="website_monitor", category=EventCategory.WEBSITE_DOWN, severity=Severity.HIGH,
        message="example.com is down", raw="", metadata={"domain": "example.com"},
    )
    await dispatcher._on_event(website_down)
    assert not sent, f"WEBSITE_DOWN is policy-listed internal_only -- must produce zero Discord sends, got {sent}"
    print("Scenario 1 (WEBSITE_DOWN under notification_policy -- zero Discord HTTP calls) PASSED")

    pm2_down = BaseEvent(
        source_module="pm2_monitor", category=EventCategory.SERVICE_DOWN, severity=Severity.HIGH,
        message="app crashed", raw="", metadata={"user": "clientuser", "process": "app"},
    )
    await dispatcher._on_event(pm2_down)
    assert not sent, f"pm2_monitor:SERVICE_DOWN is policy-listed internal_only -- must produce zero sends, got {sent}"
    print("Scenario 2 (pm2_monitor:SERVICE_DOWN qualified policy key -- zero Discord HTTP calls) PASSED")

    service_avail_down = BaseEvent(
        source_module="service_availability_monitor", category=EventCategory.SERVICE_DOWN, severity=Severity.HIGH,
        message="nginx is down", raw="", metadata={"service": "nginx"},
    )
    await dispatcher._on_event(service_avail_down)
    assert sent and sent[-1] == ("service_availability_monitor", "SERVICE_DOWN"), (
        f"the SAME unqualified category SERVICE_DOWN from a DIFFERENT module (service_availability_monitor, "
        f"not pm2_monitor) must NOT be silently suppressed by a policy entry scoped to 'pm2_monitor:SERVICE_DOWN' "
        f"-- module-qualified policy keys must not leak across modules sharing a category name, got {sent}"
    )
    print(
        "Scenario 3 (service_availability_monitor's own SERVICE_DOWN is NOT suppressed by the "
        "pm2-scoped policy entry -- qualified keys correctly stay module-specific) PASSED"
    )

    sent.clear()
    escalated = BaseEvent(
        source_module="website_monitor", category=EventCategory.WEBSITE_DOWN, severity=Severity.CRITICAL,
        message="example.com down, correlated with active attack", raw="",
        metadata={"domain": "example.com", "notify_discord": True},
    )
    await dispatcher._on_event(escalated)
    assert sent, (
        "an event whose category is policy-listed internal_only but which explicitly sets "
        "notify_discord=True (a per-event evidence-based override) must still be delivered -- "
        "the category-level default must be overridable, not an absolute block"
    )
    print("Scenario 4 (explicit notify_discord=True on an internal_only-policy category still delivers) PASSED")

    sent.clear()
    dispatcher_disabled = _make_dispatcher([])
    dispatcher_disabled._send_via_bot = fake_send
    dispatcher_disabled._bot = _FakeBot()
    await dispatcher_disabled._on_event(website_down)
    assert sent, "an empty internal_only_categories list must not suppress anything -- policy is opt-in per category"
    print("Scenario 5 (empty internal_only_categories -- fully backward compatible, nothing suppressed) PASSED")

    sent.clear()
    config_policy_disabled = DiscordConfig(
        category_channels={"WEBSITE_DOWN": 1111111111111111111},
        alert_channel_id=999999999999999999,
        notification_policy=NotificationPolicyConfig(enabled=False, internal_only_categories=["WEBSITE_DOWN"]),
        outbound=OutboundBackpressureConfig(dedup_window_seconds=0.0),
    )
    dispatcher_policy_off = DiscordWebhookDispatcher(EventBus(), config_policy_disabled)
    dispatcher_policy_off._bot = _FakeBot()
    dispatcher_policy_off._send_via_bot = fake_send
    await dispatcher_policy_off._on_event(website_down)
    assert sent, "notification_policy.enabled=false must fully disable the policy layer, even with categories listed"
    print("Scenario 6 (notification_policy.enabled=false -- policy layer fully disabled, the 'turn off' switch) PASSED")

    sent.clear()
    dispatcher_audit = _make_dispatcher(["AUDIT_NETWORK"])
    dispatcher_audit._send_via_bot = fake_send
    audit_network = BaseEvent(
        source_module="audit_monitor", category=EventCategory.AUDIT_NETWORK, severity=Severity.MEDIUM,
        message="user ran netstat -tulpn", raw="", metadata={"binary": "netstat"},
    )
    await dispatcher_audit._on_event(audit_network)
    assert not sent, (
        f"AUDIT_NETWORK is a routine, non-privileged command category listed internal_only -- "
        f"must produce zero Discord sends, got {sent}"
    )
    print("Scenario 7 (routine AUDIT_NETWORK under notification_policy -- zero Discord HTTP calls) PASSED")

    sent.clear()
    audit_privesc = BaseEvent(
        source_module="audit_monitor", category=EventCategory.AUDIT_PRIVESC, severity=Severity.HIGH,
        message="user ran sudo -i", raw="", metadata={"binary": "sudo"},
    )
    await dispatcher_audit._on_event(audit_privesc)
    assert sent, (
        f"AUDIT_PRIVESC is not policy-listed internal_only and must still reach Discord "
        f"even when the same dispatcher also suppresses AUDIT_NETWORK, got {sent}"
    )
    print("Scenario 8 (AUDIT_PRIVESC not suppressed by the unrelated AUDIT_NETWORK policy entry) PASSED")

    print("\nALL NOTIFICATION POLICY TESTS PASSED")


asyncio.run(main())
