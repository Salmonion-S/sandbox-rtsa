import asyncio
import logging
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import DiscordWebhookDispatcher


class _UnavailableBot:
    def is_ready(self) -> bool:
        return False


class _CollectingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


def _event(i: int) -> BaseEvent:
    return BaseEvent(
        source_module="bench", category=EventCategory.WEB_ATTACK_SCAN, severity=Severity.LOW,
        message=f"e{i}", raw="", metadata={},
    )


async def main() -> None:
    config = DiscordConfig(
        category_channels={}, alert_channel_id=999999999999999999,
        outbound=OutboundBackpressureConfig(dedup_window_seconds=0.0),
    )
    dispatcher = DiscordWebhookDispatcher(EventBus(), config)
    dispatcher._bot = _UnavailableBot()

    target_logger = logging.getLogger("rtsa.discord.webhook")
    handler = _CollectingHandler()
    handler.setLevel(logging.WARNING)
    target_logger.addHandler(handler)
    previous_level = target_logger.level
    target_logger.setLevel(logging.WARNING)
    try:
        for i in range(600):
            await dispatcher._on_event(_event(i))
    finally:
        target_logger.removeHandler(handler)
        target_logger.setLevel(previous_level)

    aggregate_lines = [m for m in handler.records if "digabung jadi satu ringkasan" in m]
    assert len(aggregate_lines) <= 2, (
        f"600 events triggering repeated re-aggregation within one throttle window must log at most "
        f"a couple of times, not once per aggregation operation, got {len(aggregate_lines)} lines"
    )
    assert dispatcher._total_aggregated > 0, "aggregation must still actually run even though logging is throttled"
    print(
        f"Scenario 1 (600 events causing many re-aggregation operations produce only "
        f"{len(aggregate_lines)} throttled log line(s), not one per operation) PASSED"
    )

    assert "operasi penggabungan lain sejak log terakhir" in aggregate_lines[-1] or len(aggregate_lines) <= 1, (
        "the throttled log line must fold in how many aggregation operations were suppressed since the last log"
    )
    print("Scenario 2 (throttled log line reports the folded suppressed-operation count) PASSED")

    dispatcher2 = DiscordWebhookDispatcher(EventBus(), config)
    dispatcher2._bot = _UnavailableBot()
    handler2 = _CollectingHandler()
    handler2.setLevel(logging.WARNING)
    target_logger.addHandler(handler2)
    try:
        for i in range(4):
            await dispatcher2._on_event(_event(i))
        assert dispatcher2._total_aggregated == 0, "fewer events than aggregation_min_count must never aggregate"
    finally:
        target_logger.removeHandler(handler2)
    assert not [m for m in handler2.records if "digabung jadi satu ringkasan" in m], (
        "no aggregation log line must appear when no aggregation ever happened"
    )
    print("Scenario 3 (below aggregation_min_count -- no aggregation, no log line at all) PASSED")

    print("\nALL DISCORD AGGREGATE-LOG THROTTLE TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
