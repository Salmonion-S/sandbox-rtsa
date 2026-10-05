import asyncio
import heapq
import os
import random
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import (
    _MAX_PENDING_QUEUE_SIZE, _PENDING_ALERT_MAX_AGE_SECONDS, _SEND_OK, _SEND_PERMANENT,
    _SEND_RETRYABLE, DiscordWebhookDispatcher, _PendingAlert,
)


class _UnavailableBot:
    def is_ready(self) -> bool:
        return False


class _ReadyBot:
    def is_ready(self) -> bool:
        return True


def _make_dispatcher(**outbound_overrides) -> DiscordWebhookDispatcher:
    outbound = OutboundBackpressureConfig(**outbound_overrides)
    config = DiscordConfig(alert_channel_id=555000, outbound=outbound)
    return DiscordWebhookDispatcher(EventBus(), config)


def _event(i: int, category=EventCategory.WEB_ATTACK_SCAN, severity=Severity.LOW) -> BaseEvent:
    return BaseEvent(
        source_module="bench", category=category, severity=severity,
        message=f"e{i}", raw="", metadata={},
    )


def _push_manual_alert(dispatcher, aggregated_count, severity=Severity.LOW, age_seconds=0.0):
    dispatcher._pending_sequence += 1
    alert = _PendingAlert(
        payload={"embeds": [{}]}, event_id=f"manual-{dispatcher._pending_sequence}", category="TEST",
        source_module="manual", severity=severity,
        enqueued_monotonic=time.monotonic() - age_seconds,
        channel_id=555000, aggregated_count=aggregated_count, enqueued_wall=time.time(),
    )
    priority_rank = -[Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL].index(severity)
    heapq.heappush(dispatcher._pending_heap, (priority_rank, dispatcher._pending_sequence, alert))
    return alert


async def main() -> None:
    dispatcher = _make_dispatcher(
        dedup_window_seconds=0.0, aggregation_window_seconds=999.0, aggregation_min_count=3,
    )
    dispatcher._bot = _UnavailableBot()
    for i in range(3):
        await dispatcher._on_event(_event(i))
    assert dispatcher._total_aggregated > 0, "3 matching events must have triggered aggregation"
    assert len(dispatcher._pending_heap) == 1, "3 matched entries must collapse into 1 summary entry"
    _, _, summary = dispatcher._pending_heap[0]
    assert summary.aggregated_count == 3

    async def fake_send_ok(*args, **kwargs):
        return (_SEND_OK, 555000, 999)

    dispatcher._send_via_bot = fake_send_ok
    dispatcher._bot = _ReadyBot()
    await dispatcher._flush_pending_once()
    assert dispatcher._total_sent == 3, (
        f"sending one merged summary entry must count as 3 original events sent, not 1, got "
        f"{dispatcher._total_sent}"
    )
    assert len(dispatcher._pending_heap) == 0
    print(
        "Scenario 1 (3 events merged into 1 pending entry, then sent -- total_sent counts "
        "aggregated_count=3, not 1) PASSED"
    )

    dispatcher2 = _make_dispatcher()
    merged = _push_manual_alert(dispatcher2, aggregated_count=7, severity=Severity.LOW)
    dispatcher2._drop_lowest_priority_pending()
    assert dispatcher2._total_dropped_overflow == 7, (
        f"dropping one overflow entry that represents 7 original events must count as 7, not 1, "
        f"got {dispatcher2._total_dropped_overflow}"
    )
    print(
        "Scenario 2 (overflow-dropping a merged entry with aggregated_count=7 counts as 7 "
        "dropped events, not 1) PASSED"
    )

    dispatcher3 = _make_dispatcher()
    dispatcher3._bot = _ReadyBot()
    _push_manual_alert(
        dispatcher3, aggregated_count=4, severity=Severity.LOW,
        age_seconds=_PENDING_ALERT_MAX_AGE_SECONDS + 10.0,
    )
    await dispatcher3._flush_pending_once()
    assert dispatcher3._total_dropped_stale == 4, (
        f"age-expiring a merged entry with aggregated_count=4 must count as 4 dropped events, "
        f"not 1, got {dispatcher3._total_dropped_stale}"
    )
    print(
        "Scenario 3 (age-based stale-drop of a merged entry with aggregated_count=4 counts as "
        "4 dropped events, not 1) PASSED"
    )

    dispatcher4 = _make_dispatcher()
    dispatcher4._bot = _ReadyBot()
    _push_manual_alert(dispatcher4, aggregated_count=6, severity=Severity.LOW)

    async def fake_send_permanent(*args, **kwargs):
        return (_SEND_PERMANENT, None, None)

    dispatcher4._send_via_bot = fake_send_permanent
    await dispatcher4._flush_pending_once()
    assert dispatcher4._total_dropped_permanent == 6, (
        f"a permanently-failed merged entry with aggregated_count=6 must count as 6 dropped "
        f"events, not 1, got {dispatcher4._total_dropped_permanent}"
    )
    print(
        "Scenario 4 (permanent send failure on a merged entry with aggregated_count=6 counts "
        "as 6 dropped events, not 1) PASSED"
    )

    dispatcher4b = _make_dispatcher(circuit_breaker_failure_threshold=100, max_retry_attempts=5)
    dispatcher4b._bot = _ReadyBot()
    _push_manual_alert(dispatcher4b, aggregated_count=9, severity=Severity.LOW)

    async def fake_send_retryable(*args, **kwargs):
        return (_SEND_RETRYABLE, None, None)

    dispatcher4b._send_via_bot = fake_send_retryable
    for _ in range(5):
        await dispatcher4b._flush_pending_once()
    assert dispatcher4b._total_dropped_max_retries == 9, (
        f"a merged entry with aggregated_count=9 that exhausts max_retry_attempts=5 must count "
        f"as 9 dropped events, not 1, got {dispatcher4b._total_dropped_max_retries}"
    )
    assert len(dispatcher4b._pending_heap) == 0, "the exhausted entry must be removed from the queue"
    print(
        "Scenario 4b (an entry that exhausts max_retry_attempts is removed and counted as "
        "aggregated_count dropped events, not left retrying forever) PASSED"
    )

    dispatcher5 = _make_dispatcher(
        dedup_window_seconds=0.0, aggregation_window_seconds=999.0, aggregation_min_count=5,
    )
    dispatcher5._bot = _UnavailableBot()
    count = 600
    for i in range(count):
        await dispatcher5._on_event(_event(i))
    health5 = dispatcher5.get_outbound_health()
    events_still_queued = health5["pending_events_represented"]
    assert events_still_queued == count, (
        f"pending_events_represented must equal every event fed in (all merged, none sent/"
        f"dropped/shed), got {events_still_queued} for {count} input events"
    )
    assert health5["total_aggregated"] <= count, (
        f"total_aggregated must never exceed the number of input events (it must not double-"
        f"count the same event across repeated re-aggregation operations), got "
        f"{health5['total_aggregated']} for {count} input events"
    )
    print(
        f"Scenario 5 (600 events repeatedly re-aggregated -- total_aggregated stays bounded at "
        f"{health5['total_aggregated']} <= {count}, pending_events_represented is exact) PASSED"
    )

    random.seed(1337)
    _CATEGORY_MIX = [
        (EventCategory.FILE_INTEGRITY_CHANGE, "file_integrity_detector", 20),
        (EventCategory.WEB_ATTACK_SQLI, "nginx_monitor", 25),
        (EventCategory.PROCESS_ANOMALY, "process_anomaly_detector", 20),
        (EventCategory.PERSISTENCE_NEW_PORT, "host_persistence_detector", 15),
        (EventCategory.CORRELATED_THREAT, "threat_correlation_engine", 10),
        (EventCategory.SSH_AUTH, "ssh_monitor", 10),
    ]
    _SEVERITIES = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

    def _weighted_category():
        total = sum(w for _, _, w in _CATEGORY_MIX)
        r = random.uniform(0, total)
        upto = 0.0
        for category, module, weight in _CATEGORY_MIX:
            upto += weight
            if r <= upto:
                return category, module
        return _CATEGORY_MIX[-1][0], _CATEGORY_MIX[-1][1]

    def _make_mixed_event(i, identity_cardinality):
        category, module = _weighted_category()
        severity = random.choice(_SEVERITIES)
        identity_id = i % identity_cardinality
        metadata = {}
        if category == EventCategory.FILE_INTEGRITY_CHANGE:
            metadata = {"project": f"project-{identity_id % 15}", "domain": f"site{identity_id % 15}.example"}
        elif category == EventCategory.WEB_ATTACK_SQLI:
            metadata = {"source_ip": f"203.0.113.{identity_id % 40}"}
        elif category == EventCategory.PROCESS_ANOMALY:
            metadata = {"process_fingerprint": f"fp-{identity_id % 25}"}
        elif category == EventCategory.PERSISTENCE_NEW_PORT:
            metadata = {"affected_resource": f"port-{4000 + (identity_id % 10)}"}
        elif category == EventCategory.CORRELATED_THREAT:
            metadata = {"correlation_id": f"corr-{identity_id % 8}"}
        elif category == EventCategory.SSH_AUTH:
            metadata = {"source_ip": f"198.51.100.{identity_id % 20}"}
        return BaseEvent(
            source_module=module, category=category, severity=severity,
            message=f"synthetic event #{i}", raw="", metadata=metadata,
        )

    dispatcher6 = DiscordWebhookDispatcher(
        EventBus(), DiscordConfig(alert_channel_id=555000, outbound=OutboundBackpressureConfig(
            dedup_window_seconds=30.0, aggregation_window_seconds=5.0, aggregation_min_count=5,
            critical_aggregation_min_count=10, max_sends_per_second=1000.0, max_sends_burst=1000,
        )),
    )
    dispatcher6._bot = _UnavailableBot()
    total_events = 10_000
    for i in range(total_events):
        await dispatcher6._on_event(_make_mixed_event(i, 60))
    health6 = dispatcher6.get_outbound_health()
    accounted = (
        health6["total_sent"] + health6["total_deduped"] + health6["total_shed"]
        + health6["total_below_floor"] + health6["total_policy_suppressed"]
        + health6["total_dropped_overflow"] + health6["total_dropped_stale"]
        + health6["total_dropped_permanent"] + health6["total_dropped_max_retries"]
        + health6["pending_events_represented"]
    )
    assert accounted == total_events, (
        f"reproduction of the exact reported production failure mode (10,000 mixed events, "
        f"Discord unavailable) must account for exactly {total_events}, got {accounted}"
    )
    print(
        f"Scenario 6 (reproduction of the reported 10082/10000 mismatch scenario -- 10,000 "
        f"mixed events, Discord unavailable, now accounts for exactly {accounted}/{total_events}) PASSED"
    )

    print("\nALL DISCORD EXACT-ACCOUNTING REGRESSION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
