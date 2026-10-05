import asyncio
import sys
import time

sys.path.insert(0, "/home/user/rtsa-2.5")

from config.manager import DiscordConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import _SEND_OK, DiscordWebhookDispatcher, _SendRateLimiter


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
    return DiscordWebhookDispatcher(EventBus(), config)


async def main() -> None:
    limiter = _SendRateLimiter(rate_per_second=10.0, burst=2)
    timestamps = []
    for _ in range(4):
        await limiter.acquire()
        timestamps.append(time.monotonic())
    assert timestamps[1] - timestamps[0] < 0.05, "calls within burst capacity must be immediate"
    assert timestamps[2] - timestamps[1] >= 0.08, "call beyond burst capacity must be paced by ~1/rate"
    assert timestamps[3] - timestamps[2] >= 0.08, "pacing must hold for every call beyond capacity, not just the first"
    print("Test 1 (token bucket: burst free, overflow paced at ~1/rate) PASSED")

    dispatcher = _make_dispatcher(max_sends_per_second=10.0, max_sends_burst=2, aggregation_min_count=999)
    dispatcher.set_bot(_FakeBot())
    send_times = []

    async def _fake_send(*args, **kwargs):
        send_times.append(time.monotonic())
        return _SEND_OK, None, None

    dispatcher._send_via_bot = _fake_send
    start = time.monotonic()
    for i in range(5):
        await dispatcher._on_event(_event(EventCategory.WEB_ATTACK_SCAN, Severity.HIGH, project=f"p{i}"))
    elapsed = time.monotonic() - start
    assert len(send_times) == 5, "every event must still eventually be sent -- pacing delays, never drops"
    assert elapsed >= 0.25, (
        f"a burst beyond the token bucket's burst capacity must be spread out over time "
        f"instead of firing near-simultaneously, elapsed={elapsed:.3f}s"
    )
    print("Test 2 (_on_event direct-send burst is paced by the shared rate limiter) PASSED")

    dispatcher = _make_dispatcher(max_sends_per_second=10.0, max_sends_burst=1, aggregation_min_count=999)
    for i in range(4):
        await dispatcher._on_event(_event(EventCategory.WEB_ATTACK_SCAN, Severity.HIGH, project=f"q{i}"))
    assert len(dispatcher._pending_heap) == 4, "no bot attached yet -- all 4 must land in the pending heap"

    dispatcher.set_bot(_FakeBot())
    drain_times = []

    async def _fake_send_drain(*args, **kwargs):
        drain_times.append(time.monotonic())
        return _SEND_OK, None, None

    dispatcher._send_via_bot = _fake_send_drain
    start = time.monotonic()
    await dispatcher._flush_pending_once()
    elapsed = time.monotonic() - start
    assert len(drain_times) == 4, "flush must still drain the entire backlog, just paced"
    assert elapsed >= 0.25, (
        f"draining a backlog beyond burst capacity in one flush pass must be paced, not fired "
        f"back-to-back, elapsed={elapsed:.3f}s"
    )
    print("Test 3 (_flush_pending_once queue-drain burst is paced by the SAME shared rate limiter) PASSED")

    dispatcher = _make_dispatcher()
    assert dispatcher.config.outbound.max_sends_per_second == 4.0
    assert dispatcher.config.outbound.max_sends_burst == 4
    dispatcher.set_bot(_FakeBot())
    dispatcher._send_via_bot = _fake_send
    start = time.monotonic()
    await dispatcher._on_event(_event(EventCategory.WEB_ATTACK_SCAN, Severity.HIGH, project="solo"))
    elapsed = time.monotonic() - start
    assert elapsed < 0.05, "a single alert against a fresh/full token bucket must never be delayed"
    print("Test 4 (default rate-limit config never delays an isolated, non-bursty alert) PASSED")

    print("\nAll Discord send-rate-limiter tests PASSED")


if __name__ == "__main__":
    asyncio.run(main())
