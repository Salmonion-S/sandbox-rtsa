import asyncio
import os
import random
import sys
import tracemalloc

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import _MAX_PENDING_QUEUE_SIZE, DiscordWebhookDispatcher


class _UnavailableBot:
    def is_ready(self) -> bool:
        return False


def _mixed_event(i: int, identity_cardinality: int) -> BaseEvent:
    categories = [
        EventCategory.WEB_ATTACK_SQLI, EventCategory.FILE_INTEGRITY_CHANGE,
        EventCategory.PROCESS_ANOMALY, EventCategory.SSH_AUTH,
    ]
    category = categories[i % len(categories)]
    severity = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL][i % 4]
    identity_id = i % identity_cardinality
    return BaseEvent(
        source_module="bench", category=category, severity=severity,
        message=f"e{i}", raw="", metadata={"source_ip": f"203.0.113.{identity_id % 250}"},
    )


async def _run_volume(count: int, identity_cardinality: int = 60):
    random.seed(7)
    dispatcher = DiscordWebhookDispatcher(
        EventBus(), DiscordConfig(alert_channel_id=555000, outbound=OutboundBackpressureConfig(
            dedup_window_seconds=30.0, aggregation_window_seconds=5.0, aggregation_min_count=5,
            critical_aggregation_min_count=10,
        )),
    )
    dispatcher._bot = _UnavailableBot()
    for i in range(count):
        await dispatcher._on_event(_mixed_event(i, identity_cardinality))
    return dispatcher


async def main() -> None:
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    health = dispatcher.get_outbound_health()
    required_named_metrics = [
        "discord_circuit_state", "discord_retry_queue", "discord_retry_dropped",
        "discord_retry_coalesced", "discord_retry_expired", "discord_send_failures",
    ]
    for name in required_named_metrics:
        assert name in health, f"get_outbound_health() must expose '{name}'"
    print("Scenario 1 (all 6 required named Discord failure-lifecycle metrics are exposed) PASSED")

    assert dispatcher.config.outbound.max_retry_attempts > 0
    custom = DiscordWebhookDispatcher(
        EventBus(), DiscordConfig(outbound=OutboundBackpressureConfig(max_retry_attempts=7)),
    )
    assert custom.config.outbound.max_retry_attempts == 7
    print("Scenario 2 (max_retry_attempts is a real, configurable knob) PASSED")

    tracemalloc.start()
    d10k = await _run_volume(10_000)
    _, peak_10k = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    tracemalloc.start()
    d50k = await _run_volume(50_000)
    _, peak_50k = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    h10k = d10k.get_outbound_health()
    h50k = d50k.get_outbound_health()
    assert h10k["pending_queue_depth"] <= _MAX_PENDING_QUEUE_SIZE
    assert h50k["pending_queue_depth"] <= _MAX_PENDING_QUEUE_SIZE
    assert h10k["dedup_cache_size"] <= 2000
    assert h50k["dedup_cache_size"] <= 2000
    growth_ratio = peak_50k / max(peak_10k, 1)
    assert growth_ratio < 3.0, (
        f"5x the input volume (10k -> 50k, simulating a sustained Discord-unavailable high-"
        f"traffic window) must not produce anywhere near 5x the peak traced memory -- growth "
        f"must stay bounded by the fixed-size queue/cache caps, not scale with input: "
        f"peak_10k={peak_10k} peak_50k={peak_50k} ratio={growth_ratio:.2f}"
    )
    print(
        f"Scenario 3 (10k -> 50k events with Discord unavailable: pending_queue_depth and "
        f"dedup_cache_size both stay capped, peak memory grows {growth_ratio:.2f}x not ~5x) PASSED"
    )

    print("\nALL DISCORD FAILURE-LIFECYCLE BOUND TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
