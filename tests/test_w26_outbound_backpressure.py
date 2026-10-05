import asyncio
import sys
import time

sys.path.insert(0, "/home/user/rtsa-2.5")

from config.manager import DiscordConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.self_health import (
    DEGRADED, NORMAL, OVERLOADED, SelfHealthMonitor, SelfHealthThresholds, get_self_health_monitor,
)
from discord_integration.webhook import (
    _SEND_OK, _SEND_PERMANENT, _SEND_RETRYABLE, DiscordWebhookDispatcher,
)


class _FakeBot:
    def is_ready(self) -> bool:
        return True


def _event(category, severity, **metadata) -> BaseEvent:
    return BaseEvent(
        source_module="test_module", category=category, severity=severity,
        message="test", raw="", metadata=metadata,
    )


def _make_dispatcher(**outbound_overrides) -> DiscordWebhookDispatcher:
    outbound = OutboundBackpressureConfig(**outbound_overrides)
    config = DiscordConfig(outbound=outbound)
    dispatcher = DiscordWebhookDispatcher(EventBus(), config)
    return dispatcher


async def main() -> None:
    dispatcher = _make_dispatcher(aggregation_min_count=999)
    for i in range(5):
        await dispatcher._on_event(_event(EventCategory.WEB_ATTACK_SCAN, Severity.LOW, project=f"p{i}"))
    await dispatcher._on_event(_event(EventCategory.REMOTE_ACCESS_BACKDOOR, Severity.CRITICAL, project="crit"))
    assert dispatcher._pending_heap, "pending heap should not be empty (no bot attached -- events always land in the pending heap)"
    top_rank, _, top_alert = dispatcher._pending_heap[0]
    assert top_alert.severity == Severity.CRITICAL, (
        f"the CRITICAL alert must be at the top of the heap regardless of arrival order, got {top_alert.severity}"
    )
    print("Test 1 (priority heap orders CRITICAL before LOW regardless of arrival order) PASSED")

    dispatcher = _make_dispatcher(aggregation_min_count=999)
    import discord_integration.webhook as webhook_mod
    original_max = webhook_mod._MAX_PENDING_QUEUE_SIZE
    webhook_mod._MAX_PENDING_QUEUE_SIZE = 3
    try:
        await dispatcher._on_event(_event(EventCategory.REMOTE_ACCESS_BACKDOOR, Severity.CRITICAL, project="keep-me"))
        await dispatcher._on_event(_event(EventCategory.WEB_ATTACK_SCAN, Severity.LOW, project="low1"))
        await dispatcher._on_event(_event(EventCategory.WEB_ATTACK_SCAN, Severity.LOW, project="low2"))
        await dispatcher._on_event(_event(EventCategory.WEB_ATTACK_SCAN, Severity.LOW, project="low3"))
        severities = [a.severity for _, _, a in dispatcher._pending_heap]
        assert Severity.CRITICAL in severities, "overflow must never evict the CRITICAL alert"
        assert len(dispatcher._pending_heap) == 3, f"queue should stay capped at 3, got {len(dispatcher._pending_heap)}"
        assert dispatcher._total_dropped_overflow == 1
    finally:
        webhook_mod._MAX_PENDING_QUEUE_SIZE = original_max
    print("Test 2 (overflow drops lowest-priority entry, never CRITICAL/HIGH) PASSED")

    dispatcher = _make_dispatcher(circuit_breaker_failure_threshold=3, backoff_base_seconds=0.05, backoff_jitter_seconds=0.0)
    for _ in range(3):
        dispatcher._record_send_failure()
    assert dispatcher._circuit_state == "OPEN", "circuit must trip OPEN after reaching the failure threshold"
    assert dispatcher._circuit_allows_attempt() is False, "circuit must block attempts during backoff cooldown"
    await asyncio.sleep(0.08)
    assert dispatcher._circuit_allows_attempt() is True, "circuit must allow exactly one probe after cooldown elapses"
    assert dispatcher._circuit_state == "HALF_OPEN"
    dispatcher._record_send_success()
    assert dispatcher._circuit_state == "CLOSED", "a successful probe must close the circuit and reset failure count"
    assert dispatcher._consecutive_failures == 0
    print("Test 3 (circuit breaker OPEN -> backoff -> HALF_OPEN probe -> CLOSED on success) PASSED")

    dispatcher = _make_dispatcher(circuit_breaker_failure_threshold=2, backoff_base_seconds=0.05, backoff_jitter_seconds=0.0)
    dispatcher._record_send_failure()
    dispatcher._record_send_failure()
    first_backoff = dispatcher._current_backoff_seconds
    await asyncio.sleep(first_backoff + 0.02)
    assert dispatcher._circuit_allows_attempt() is True
    dispatcher._record_send_failure()
    assert dispatcher._circuit_state == "OPEN"
    assert dispatcher._current_backoff_seconds > first_backoff, "backoff must increase (exponential) after a failed probe"
    print("Test 3b (failed HALF_OPEN probe reopens circuit with increased backoff) PASSED")

    dispatcher = _make_dispatcher(load_shed_degraded_queue_size=2, load_shed_overloaded_queue_size=4, aggregation_min_count=999)
    for i in range(2):
        await dispatcher._on_event(_event(EventCategory.WEBSITE_DOWN, Severity.HIGH, project=f"seed{i}"))
    assert dispatcher._load_shed_state == "DEGRADED", f"expected DEGRADED at depth>=2, got {dispatcher._load_shed_state}"
    before = len(dispatcher._pending_heap)
    await dispatcher._on_event(_event(EventCategory.WEBSITE_DOWN, Severity.MEDIUM, project="shed-me"))
    assert len(dispatcher._pending_heap) == before, "a MEDIUM event must be shed while DEGRADED (floor raised to HIGH)"
    assert dispatcher._total_shed == 1

    for i in range(3):
        await dispatcher._on_event(_event(EventCategory.WEBSITE_DOWN, Severity.HIGH, project=f"fill{i}"))
    assert dispatcher._load_shed_state == "OVERLOADED", f"expected OVERLOADED, got {dispatcher._load_shed_state}"
    before = len(dispatcher._pending_heap)
    await dispatcher._on_event(_event(EventCategory.CORRELATED_THREAT, Severity.HIGH, project="bypass-normally"))
    assert len(dispatcher._pending_heap) == before, (
        "OVERLOADED shedding must apply even to categories that normally bypass the severity floor"
    )
    print("Test 4 (load shedding raises floor at DEGRADED/OVERLOADED, applies even to bypass categories) PASSED")

    dispatcher = _make_dispatcher(aggregation_min_count=5, aggregation_window_seconds=60.0)
    for i in range(5):
        await dispatcher._on_event(_event(
            EventCategory.WEB_ATTACK_SCAN, Severity.LOW if i % 2 == 0 else Severity.MEDIUM, project=f"burst{i}",
        ))
    assert len(dispatcher._pending_heap) == 1, (
        f"5 similar LOW/MEDIUM alerts must collapse into exactly 1 summary, got {len(dispatcher._pending_heap)}"
    )
    _, _, summary = dispatcher._pending_heap[0]
    assert summary.aggregated_count == 5
    assert summary.severity == Severity.MEDIUM, "summary severity must be the HIGHEST among the collapsed alerts"
    embed_fields = {f["name"]: f["value"] for f in summary.payload["embeds"][0]["fields"]}
    assert embed_fields["Jumlah Digabung"] == "5"
    assert "First Seen" in embed_fields and "Last Seen" in embed_fields
    assert embed_fields["Highest Severity"] == "MEDIUM"
    assert dispatcher._total_aggregated == 5

    dispatcher2 = _make_dispatcher(aggregation_min_count=5, aggregation_window_seconds=60.0)
    for i in range(6):
        await dispatcher2._on_event(_event(EventCategory.WEBSITE_DOWN, Severity.CRITICAL, project=f"crit{i}"))
    assert len(dispatcher2._pending_heap) == 6, (
        "a modest CRITICAL burst (below the higher critical_aggregation_min_count threshold) must "
        "still be sent promptly and individually -- CRITICAL must never be delayed for a small burst"
    )

    dispatcher2c = _make_dispatcher(
        aggregation_min_count=5, critical_aggregation_min_count=10, aggregation_window_seconds=60.0,
    )
    for i in range(12):
        await dispatcher2c._on_event(_event(EventCategory.WEBSITE_DOWN, Severity.CRITICAL, project=f"crit{i}"))
    assert len(dispatcher2c._pending_heap) < 12, (
        "a genuinely large CRITICAL burst (past critical_aggregation_min_count) must still be "
        "bundled into a bounded summary -- CRITICAL is not exempt from aggregation, only given a "
        "higher bar so small/rare CRITICAL bursts are never delayed"
    )
    assert dispatcher2c._total_aggregated > 0
    print(
        "Test 5 (burst aggregation collapses LOW/MEDIUM eagerly; CRITICAL gets a higher bar so small "
        "bursts send promptly, but a genuinely large CRITICAL burst is still bounded, not 1:1 spam) PASSED"
    )

    dispatcher = _make_dispatcher(circuit_breaker_failure_threshold=2)
    dispatcher.set_bot(_FakeBot())

    async def _fake_permanent(*args, **kwargs):
        return _SEND_PERMANENT, None, None

    dispatcher._send_via_bot = _fake_permanent
    await dispatcher._on_event(_event(EventCategory.REMOTE_ACCESS_BACKDOOR, Severity.CRITICAL, project="perm"))
    assert len(dispatcher._pending_heap) == 0, "a PERMANENT failure must never be enqueued for retry"
    assert dispatcher._total_dropped_permanent == 1
    assert dispatcher._circuit_state == "CLOSED", "a PERMANENT (config) failure must never trip the circuit breaker"
    assert dispatcher._consecutive_failures == 0
    print("Test 6 (PERMANENT send failure is dropped, never retried, never trips circuit breaker) PASSED")

    dispatcher = _make_dispatcher(circuit_breaker_failure_threshold=5)
    dispatcher.set_bot(_FakeBot())

    async def _fake_retryable(*args, **kwargs):
        return _SEND_RETRYABLE, None, None

    dispatcher._send_via_bot = _fake_retryable
    await dispatcher._on_event(_event(EventCategory.REMOTE_ACCESS_BACKDOOR, Severity.CRITICAL, project="retry"))
    assert len(dispatcher._pending_heap) == 1, "a RETRYABLE failure must be enqueued for retry"
    assert dispatcher._consecutive_failures == 1
    print("Test 6b (RETRYABLE send failure is enqueued and counts toward circuit breaker) PASSED")

    dispatcher = _make_dispatcher(dedup_window_seconds=60.0, aggregation_min_count=999)
    await dispatcher._on_event(_event(EventCategory.FILE_INTEGRITY_CHANGE, Severity.MEDIUM, project="dedup-proj", domain="dedup.example"))
    await dispatcher._on_event(_event(EventCategory.FILE_INTEGRITY_CHANGE, Severity.MEDIUM, project="dedup-proj", domain="dedup.example"))
    assert len(dispatcher._pending_heap) == 1, "a repeat LOW alert with identical identity within the window must be deduped"
    assert dispatcher._total_deduped == 1

    dispatcher2 = _make_dispatcher(dedup_window_seconds=60.0, aggregation_min_count=999)
    await dispatcher2._on_event(_event(EventCategory.REMOTE_ACCESS_BACKDOOR, Severity.CRITICAL, project="dedup-proj", correlation_id="abc"))
    await dispatcher2._on_event(_event(EventCategory.REMOTE_ACCESS_BACKDOOR, Severity.CRITICAL, project="dedup-proj", correlation_id="abc"))
    assert len(dispatcher2._pending_heap) == 1, (
        "a repeat CRITICAL alert with identical identity within the dedup window must ALSO be "
        "deduped -- severity must never bypass identity-based dedup, only a genuinely different "
        "identity may bypass it"
    )
    assert dispatcher2._total_deduped == 1

    dispatcher2b = _make_dispatcher(dedup_window_seconds=60.0, aggregation_min_count=999)
    await dispatcher2b._on_event(_event(EventCategory.REMOTE_ACCESS_BACKDOOR, Severity.CRITICAL, project="dedup-proj", correlation_id="abc"))
    await dispatcher2b._on_event(_event(EventCategory.REMOTE_ACCESS_BACKDOOR, Severity.CRITICAL, project="dedup-proj", correlation_id="xyz"))
    assert len(dispatcher2b._pending_heap) == 2, (
        "a NEW CRITICAL alert with a genuinely different identity must never be suppressed, "
        "even within the dedup window of a same-category alert"
    )

    dispatcher3 = _make_dispatcher(dedup_window_seconds=60.0, aggregation_min_count=999)
    await dispatcher3._on_event(_event(EventCategory.FILE_INTEGRITY_CHANGE, Severity.MEDIUM, project="a"))
    await dispatcher3._on_event(_event(EventCategory.FILE_INTEGRITY_CHANGE, Severity.MEDIUM, project="b"))
    assert len(dispatcher3._pending_heap) == 2, "events with no shared identity fields must never be collapsed together"
    print(
        "Test 7 (outbound dedup collapses identical-identity repeats regardless of severity -- "
        "including HIGH/CRITICAL -- while a different identity, or unrelated events, are never "
        "suppressed) PASSED"
    )

    dispatcher = _make_dispatcher()
    health = dispatcher.get_outbound_health()
    for key in (
        "circuit_state", "load_shed_state", "pending_queue_depth", "consecutive_failures",
        "current_backoff_seconds", "total_sent", "total_failed", "total_shed", "total_aggregated",
        "total_dropped_overflow", "total_dropped_stale", "total_dropped_permanent", "total_deduped",
    ):
        assert key in health, f"get_outbound_health() missing expected key: {key}"
    print("Test 8 (get_outbound_health exposes full self-health metric shape) PASSED")

    dispatcher = _make_dispatcher()
    silent_event = _event(EventCategory.WEBSITE_DOWN, Severity.HIGH, notify_discord=False)
    await dispatcher._on_event(silent_event)
    assert len(dispatcher._pending_heap) == 0
    print("Test 9 (notify_discord=False still fully suppressed after heap migration) PASSED")

    monitor = SelfHealthMonitor(SelfHealthThresholds(
        degraded_cpu_percent=101, overloaded_cpu_percent=102, emergency_cpu_percent=103,
        degraded_memory_percent=101, overloaded_memory_percent=102, emergency_memory_percent=103,
        degraded_load_average_ratio=1000.0, overloaded_load_average_ratio=1001.0, emergency_load_average_ratio=1002.0,
        degraded_process_rss_mb=1e9, overloaded_process_rss_mb=2e9, emergency_process_rss_mb=3e9,
        degraded_swap_percent=101, overloaded_swap_percent=102,
    ))
    assert monitor.evaluate() == NORMAL, "with nothing attached and healthy CPU/mem, state must be NORMAL"

    class _StubDispatcher:
        def get_outbound_health(self):
            return {"load_shed_state": "DEGRADED", "circuit_state": "CLOSED"}

    monitor.attach_dispatcher(_StubDispatcher())
    assert monitor.evaluate() == DEGRADED, "DEGRADED outbound load-shed state must escalate self-health to DEGRADED"

    class _StubDispatcherOverloaded:
        def get_outbound_health(self):
            return {"load_shed_state": "OVERLOADED", "circuit_state": "OPEN"}

    monitor.attach_dispatcher(_StubDispatcherOverloaded())
    assert monitor.evaluate() == OVERLOADED, "OVERLOADED outbound load-shed state must escalate self-health to OVERLOADED"
    status = monitor.get_status()
    assert status["state"] == OVERLOADED
    assert status["reasons"], "get_status() must explain WHY the state escalated"
    print("Test 10 (RTSA_SELF_HEALTH escalates from outbound circuit/load-shed signals, with reasons) PASSED")

    monitor2 = SelfHealthMonitor(SelfHealthThresholds(
        degraded_cpu_percent=101, overloaded_cpu_percent=102, emergency_cpu_percent=103,
        degraded_memory_percent=101, overloaded_memory_percent=102, emergency_memory_percent=103,
        degraded_load_average_ratio=1000.0, overloaded_load_average_ratio=1001.0, emergency_load_average_ratio=1002.0,
        degraded_process_rss_mb=1e9, overloaded_process_rss_mb=2e9, emergency_process_rss_mb=3e9,
        degraded_swap_percent=101, overloaded_swap_percent=102,
        degraded_handler_latency_ms=100.0, overloaded_handler_latency_ms=5000.0,
    ))

    class _StubBus:
        subscriber_stats = {"slow_detector": {"avg_handler_latency_ms": 250.0}}

    monitor2.attach_bus(_StubBus())
    assert monitor2.evaluate() == DEGRADED, "high average handler latency on any subscriber must escalate self-health"
    print("Test 11 (RTSA_SELF_HEALTH escalates from event-bus subscriber latency) PASSED")

    a = get_self_health_monitor()
    b = get_self_health_monitor()
    assert a is b, "get_self_health_monitor() must return a stable process-wide singleton"
    print("Test 12 (get_self_health_monitor singleton stable across calls) PASSED")

    print("\nALL W26 OUTBOUND BACKPRESSURE + SELF-HEALTH TESTS PASSED")


asyncio.run(main())
