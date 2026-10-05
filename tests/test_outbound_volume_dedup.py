import asyncio
import logging
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

logging.getLogger("rtsa.discord.webhook").setLevel(logging.ERROR)

from config.manager import DiscordConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import _MAX_PENDING_QUEUE_SIZE, DiscordWebhookDispatcher


async def main() -> None:
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    for i in range(1000):
        event = BaseEvent(
            source_module="process_anomaly_detector", category=EventCategory.PROCESS_ANOMALY,
            severity=Severity.MEDIUM, message=f"anomaly #{i}", raw="",
            metadata={"project": "siteA", "correlation_id": "corr-fixed"},
        )
        await dispatcher._on_event(event)
    assert len(dispatcher._pending_heap) == 1, (
        f"1000 duplicate-identity events must collapse to exactly one queued alert, got "
        f"{len(dispatcher._pending_heap)}"
    )
    assert dispatcher._total_deduped == 999, dispatcher._total_deduped
    assert dispatcher._total_dropped_overflow == 0
    print("Scenario 1 (1000 duplicate-identity events: exactly one queued, 999 deduped, no overflow) PASSED")

    dispatcher2 = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    severities = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    for i in range(1000):
        event = BaseEvent(
            source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY,
            severity=severities[i % len(severities)], message=f"mixed #{i}", raw="",
            metadata={"correlation_id": f"corr-{i}"},
        )
        await dispatcher2._on_event(event)
    assert len(dispatcher2._pending_heap) <= _MAX_PENDING_QUEUE_SIZE, (
        f"the pending queue must never exceed its configured bound even under 1000 distinct "
        f"events: {len(dispatcher2._pending_heap)} > {_MAX_PENDING_QUEUE_SIZE}"
    )
    assert (
        dispatcher2._total_dropped_overflow > 0 or dispatcher2._total_shed > 0
        or dispatcher2._total_aggregated > 0
    ), (
        "1000 distinct events under sustained pressure must be bounded somehow -- via burst "
        "aggregation (now including HIGH/CRITICAL), overflow dropping, and/or load-shedding -- "
        "never unbounded queue growth"
    )
    represented = (
        sum(alert.aggregated_count for _, _, alert in dispatcher2._pending_heap)
        + dispatcher2._total_dropped_overflow + dispatcher2._total_deduped + dispatcher2._total_shed
    )
    assert represented == 1000, (
        f"every event must be accounted for somewhere -- queued (incl. folded into an aggregate "
        f"summary), deduped, shed, or overflow-dropped -- never silently lost: {represented}"
    )
    print(
        "Scenario 2 (1000 mixed-severity/distinct-identity events: queue stays bounded, "
        "load-shed/overflow/aggregation bounds it, no event silently lost) PASSED"
    )

    dispatcher3 = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    for i in range(1000):
        event = BaseEvent(
            source_module="process_anomaly_detector", category=EventCategory.PROCESS_ANOMALY,
            severity=Severity.LOW, message=f"identity #{i}", raw="",
            metadata={"correlation_id": f"corr-unique-{i}"},
        )
        await dispatcher3._on_event(event)
    assert len(dispatcher3._outbound_identity_state) <= 2000, (
        f"the dedup identity cache must stay bounded even after 1000 unique identities: "
        f"{len(dispatcher3._outbound_identity_state)}"
    )
    print("Scenario 3 (1000 unique identities: dedup identity cache stays bounded, no unbounded state growth) PASSED")

    print("\nALL OUTBOUND VOLUME / DEDUP STRESS TESTS PASSED")


asyncio.run(main())
