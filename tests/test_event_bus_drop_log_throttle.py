import asyncio
import logging
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus


class _CountingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _event(i):
    return BaseEvent(
        source_module="bench", category=EventCategory.WEB_ATTACK_SCAN, severity=Severity.LOW,
        message=f"e{i}", raw="", metadata={},
    )


async def main() -> None:
    bus = EventBus()

    async def slow_handler(event):
        await asyncio.sleep(10)

    await bus.subscribe("slow_sub", slow_handler, max_queue_size=10)

    handler = _CountingHandler()
    handler.setLevel(logging.WARNING)
    logger = logging.getLogger("rtsa.core.event_bus")
    logger.addHandler(handler)
    try:
        for i in range(2000):
            bus.publish_nowait(_event(i))
    finally:
        logger.removeHandler(handler)

    drop_warnings = [r for r in handler.records if "penuh" in r.getMessage()]
    assert bus.stats["dropped"] > 1900, (
        f"a sustained full queue must still drop (and count) essentially every offered event "
        f"past the cap, got dropped={bus.stats['dropped']}"
    )
    assert len(drop_warnings) < 10, (
        f"logging one warning line PER dropped event during a sustained overload is itself "
        f"unbounded I/O proportional to attack volume -- the drop-log line must be rate-limited "
        f"to roughly one per second per subscriber, not one per drop. Offered ~1990 drops in a "
        f"single burst (all within well under 1s), got {len(drop_warnings)} log lines"
    )
    print(
        f"Scenario 1 (2000 events into a 10-slot full queue: {bus.stats['dropped']} events "
        f"dropped and counted, but only {len(drop_warnings)} warning log line(s) emitted -- "
        f"drop accounting is not itself an unbounded-I/O amplifier under sustained overload) PASSED"
    )

    await bus.shutdown()
    print("\nALL EVENT BUS DROP-LOG THROTTLE TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
