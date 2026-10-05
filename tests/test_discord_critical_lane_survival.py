import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import (
    _LOAD_DEGRADED, _LOAD_OVERLOADED, DiscordWebhookDispatcher,
)


def _make_dispatcher(**outbound_overrides) -> DiscordWebhookDispatcher:
    outbound = OutboundBackpressureConfig(**outbound_overrides)
    config = DiscordConfig(outbound=outbound)
    return DiscordWebhookDispatcher(EventBus(), config)


def _event(category, severity, **metadata) -> BaseEvent:
    return BaseEvent(
        source_module="test_module", category=category, severity=severity,
        message="test", raw="", metadata=metadata,
    )


async def main() -> None:
    reserved_capacity_cases = [
        (EventCategory.WEB_ATTACK_RCE, Severity.HIGH, "confirmed RCE"),
        (EventCategory.PERSISTENCE_NEW_PORT, Severity.MEDIUM, "malicious persistence (new port)"),
        (EventCategory.PERSISTENCE_SSH_KEY, Severity.MEDIUM, "malicious persistence (SSH key)"),
        (EventCategory.FILE_INTEGRITY_CHANGE, Severity.LOW, "critical FIM (even at LOW severity)"),
        (EventCategory.BAN_BYPASS_DETECTED, Severity.HIGH, "BAN_BYPASS_DETECTED"),
    ]

    for category, severity, label in reserved_capacity_cases:
        dispatcher = _make_dispatcher(aggregation_min_count=999)
        dispatcher._load_shed_state = _LOAD_OVERLOADED
        before = len(dispatcher._pending_heap)
        await dispatcher._on_event(_event(category, severity, case=label))
        assert len(dispatcher._pending_heap) == before + 1, (
            f"'{label}' must survive OVERLOADED load-shedding (reserved critical capacity) -- "
            f"it must still be queued for delivery, not shed"
        )
        assert dispatcher._total_shed == 0
    print(
        "Scenario 1 (confirmed RCE, malicious persistence, critical FIM, and BAN_BYPASS_DETECTED "
        "all survive OVERLOADED bulk-queue saturation, per the mandated critical-lane test) PASSED"
    )

    dispatcher2 = _make_dispatcher(
        aggregation_min_count=999, load_shed_degraded_queue_size=2, load_shed_overloaded_queue_size=50,
    )
    for i in range(2):
        await dispatcher2._on_event(_event(EventCategory.WEBSITE_DOWN, Severity.HIGH, seed=i))
    assert dispatcher2._load_shed_state == _LOAD_DEGRADED, (
        f"expected DEGRADED at depth>=2, got {dispatcher2._load_shed_state}"
    )
    for category, severity, label in reserved_capacity_cases:
        before = len(dispatcher2._pending_heap)
        await dispatcher2._on_event(_event(category, severity, case=label))
        assert len(dispatcher2._pending_heap) == before + 1, (
            f"'{label}' must also survive the lighter DEGRADED load-shed floor"
        )
    assert dispatcher2._total_shed == 0
    print("Scenario 2 (same reserved-capacity categories also survive a genuinely-triggered DEGRADED state) PASSED")

    dispatcher3 = _make_dispatcher(aggregation_min_count=999)
    dispatcher3._load_shed_state = _LOAD_OVERLOADED
    before = len(dispatcher3._pending_heap)
    await dispatcher3._on_event(_event(EventCategory.WEB_ATTACK_SCAN, Severity.LOW, case="bulk scan"))
    assert len(dispatcher3._pending_heap) == before, (
        "bulk scan traffic (WEB_ATTACK_SCAN) must still be shed under OVERLOADED -- reserved "
        "capacity is for a narrow, low-volume, high-value category set, not for the bulk "
        "attack-traffic categories load shedding exists to control"
    )
    assert dispatcher3._total_shed == 1
    print(
        "Scenario 3 (bulk WEB_ATTACK_SCAN traffic is still correctly shed under OVERLOADED -- "
        "reserved capacity does not defeat load shedding's purpose) PASSED"
    )

    dispatcher4 = _make_dispatcher(aggregation_min_count=999)
    dispatcher4._load_shed_state = _LOAD_OVERLOADED
    before = len(dispatcher4._pending_heap)
    await dispatcher4._on_event(_event(EventCategory.CORRELATED_THREAT, Severity.HIGH, case="correlated threat"))
    assert len(dispatcher4._pending_heap) == before, (
        "CORRELATED_THREAT is not in the narrow reserved-capacity set and must remain shed-able "
        "under OVERLOADED, matching the pre-existing w26 Test 4 contract"
    )
    print("Scenario 4 (CORRELATED_THREAT stays subject to load shedding, unchanged from before) PASSED")

    print("\nALL DISCORD CRITICAL-LANE SURVIVAL TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
