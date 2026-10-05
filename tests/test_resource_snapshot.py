import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.event_bus import EventBus
from core.resource_snapshot import build_resource_snapshot

_EXPECTED_FIELDS = {
    "load_state", "cpu_percent", "rss_mb", "tasks", "queue_depth", "queue_saturation",
    "events_ingress", "events_processed", "events_coalesced", "events_dropped",
    "critical_events", "subprocess_active", "subprocess_timeouts", "pm2_queries",
    "pm2_skipped", "fim_jobs", "fim_deferred", "db_queue", "db_latency_ms",
    "discord_queued", "discord_sent", "discord_suppressed",
}


class _FakePm2Monitor:
    _pm2_queries_total = 42
    _pm2_skipped_no_daemon_total = 7


class _FakeFimDetector:
    _fim_hash_deferred_total = 3


class _FakeDbWorker:
    stats = {"queue_size": 12, "avg_flush_time_ms": 4.5, "written": 100, "dropped": 0}


class _FakeDispatcher:
    def get_outbound_health(self):
        return {
            "pending_queue_depth": 5, "total_sent": 20, "total_policy_suppressed": 8,
            "total_shed": 1, "total_below_floor": 2, "total_deduped": 3,
        }


async def main() -> None:
    bare = build_resource_snapshot()
    assert set(bare.keys()) >= _EXPECTED_FIELDS, (
        f"build_resource_snapshot() must expose every field named in the spec even with no "
        f"optional objects attached, missing: {_EXPECTED_FIELDS - set(bare.keys())}"
    )
    assert bare["load_state"] in ("NORMAL", "DEGRADED", "OVERLOADED", "EMERGENCY")
    print("Scenario 1 (snapshot exposes the full required field set even with nothing attached) PASSED")

    bus = EventBus()

    async def handler(event):
        return None

    await bus.subscribe("test_sub", handler)
    snap = build_resource_snapshot(bus=bus)
    assert "events_ingress" in snap and snap["events_ingress"] == 0
    await bus.shutdown()
    print("Scenario 2 (EventBus-derived fields populate cleanly from a real bus) PASSED")

    snap2 = build_resource_snapshot(
        pm2_monitor=_FakePm2Monitor(), fim_detector=_FakeFimDetector(),
        db_worker=_FakeDbWorker(), dispatcher=_FakeDispatcher(),
    )
    assert snap2["pm2_queries"] == 42
    assert snap2["pm2_skipped"] == 7
    assert snap2["fim_deferred"] == 3
    assert snap2["db_queue"] == 12
    assert snap2["db_latency_ms"] == 4.5
    assert snap2["discord_queued"] == 5
    assert snap2["discord_sent"] == 20
    assert snap2["discord_suppressed"] == 8 + 1 + 2 + 3
    print("Scenario 3 (per-module counters flow through correctly when the objects are attached) PASSED")

    for value in snap2.values():
        if isinstance(value, str):
            assert value in ("NORMAL", "DEGRADED", "OVERLOADED", "EMERGENCY"), (
                f"no snapshot field may carry an attacker-controlled string value (IP/path/domain/UA) "
                f"-- every string field must be a fixed, small-cardinality label, got {value!r}"
            )
    print("Scenario 4 (no snapshot field carries an attacker-controlled string label) PASSED")

    print("\nALL RESOURCE SNAPSHOT TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
