import asyncio
import os
import random
import sys
import time
import tracemalloc

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import _MAX_PENDING_QUEUE_SIZE, DiscordWebhookDispatcher


class FakeMessage:
    _next_id = 1

    def __init__(self, channel):
        FakeMessage._next_id += 1
        self.id = FakeMessage._next_id
        self.channel = channel

    async def edit(self, content=None, embeds=None, view=None):
        pass


class FakeChannel:
    id = 555000

    def __init__(self):
        self.send_count = 0
        self.messages = {}

    async def send(self, content=None, embeds=None, view=None):
        self.send_count += 1
        m = FakeMessage(self)
        self.messages[m.id] = m
        return m

    async def fetch_message(self, message_id):
        return self.messages[message_id]


class FakeBot:
    def __init__(self, channel):
        self._channel = channel

    def is_ready(self):
        return True

    def get_channel(self, cid):
        return self._channel


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


def _make_event(i: int, identity_cardinality: int) -> BaseEvent:
    category, module = _weighted_category()
    severity = random.choice(_SEVERITIES)
    identity_id = i % identity_cardinality
    metadata = {}
    if category == EventCategory.FILE_INTEGRITY_CHANGE:
        metadata = {"project": f"project-{identity_id % 15}", "domain": f"site{identity_id % 15}.example"}
    elif category in (EventCategory.WEB_ATTACK_SQLI,):
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


async def main() -> None:
    random.seed(1337)
    channel = FakeChannel()
    dispatcher = DiscordWebhookDispatcher(
        EventBus(), DiscordConfig(alert_channel_id=555000, outbound=OutboundBackpressureConfig(
            dedup_window_seconds=30.0, aggregation_window_seconds=5.0, aggregation_min_count=5,
            critical_aggregation_min_count=10, max_sends_per_second=1000.0, max_sends_burst=1000,
        )),
    )
    dispatcher.set_bot(FakeBot(channel))

    total_events = 10_000
    identity_cardinality = 60

    tracemalloc.start()
    mem_before, _ = tracemalloc.get_traced_memory()

    start = time.monotonic()
    for i in range(total_events):
        ev = _make_event(i, identity_cardinality)
        await dispatcher._on_event(ev)
    elapsed = time.monotonic() - start

    mem_after, mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    health = dispatcher.get_outbound_health()
    notifications_sent = channel.send_count
    events_sent = health["total_sent"]
    notifications_suppressed = health["total_deduped"] + health["total_shed"]
    notifications_below_floor = health["total_below_floor"]
    notifications_merged = health["total_aggregated"]
    queue_depth = health["pending_queue_depth"]
    events_still_queued = health["pending_events_represented"]
    events_dropped = (
        health["total_dropped_overflow"] + health["total_dropped_stale"]
        + health["total_dropped_permanent"] + health["total_dropped_max_retries"]
    )
    events_policy_suppressed = health["total_policy_suppressed"]

    print("=" * 70)
    print("RTSA OUTBOUND LOAD BENCHMARK -- 10,000 SYNTHETIC EVENTS")
    print("=" * 70)
    print(f"events_received:          {total_events}")
    print(f"identity_cardinality:     {identity_cardinality}")
    print(f"notifications_sent (API calls): {notifications_sent}")
    print(f"events_sent (aggregated_count-aware): {events_sent}")
    print(f"notifications_suppressed: {notifications_suppressed} (dedup={health['total_deduped']}, shed={health['total_shed']})")
    print(f"notifications_below_floor: {notifications_below_floor} (routine low-severity noise, filtered pre-dedup)")
    print(f"events_policy_suppressed: {events_policy_suppressed}")
    print(f"events_dropped:           {events_dropped} (overflow={health['total_dropped_overflow']}, stale={health['total_dropped_stale']}, permanent={health['total_dropped_permanent']}, max_retries={health['total_dropped_max_retries']})")
    print(f"notifications_merged (diagnostic, NOT a partition term): {notifications_merged} (folded-in events, cumulative)")
    print(f"pending_queue_depth:      {queue_depth} (bound={_MAX_PENDING_QUEUE_SIZE})")
    print(f"events_still_queued:      {events_still_queued} (aggregated_count-aware, the true partition term)")
    print(f"processing_latency_total: {elapsed:.3f}s")
    print(f"processing_latency_avg:   {(elapsed / total_events) * 1000:.4f}ms/event")
    print(f"memory_traced_before:     {mem_before / 1024:.1f} KiB")
    print(f"memory_traced_after:      {mem_after / 1024:.1f} KiB")
    print(f"memory_traced_peak:       {mem_peak / 1024:.1f} KiB")
    print(f"memory_delta:             {(mem_after - mem_before) / 1024:.1f} KiB")
    print(f"dedup_cache_size:         {health['dedup_cache_size']}")
    accounted = (
        events_sent + notifications_suppressed + notifications_below_floor
        + events_policy_suppressed + events_dropped + events_still_queued
    )
    print(f"accounted_for (sent+suppressed+below_floor+policy_suppressed+dropped+still_queued): {accounted} / {total_events}")
    print("=" * 70)
    assert accounted == total_events, (
        f"every event must have exactly one final accounting state -- sent, suppressed, filtered "
        f"below floor, policy-suppressed, dropped, or still queued -- never silently unaccounted "
        f"and never double-counted through the diagnostic-only 'merged' metric: "
        f"{accounted} != {total_events}"
    )

    assert notifications_sent < total_events * 0.05, (
        f"notification count must be dramatically smaller than event count: "
        f"{notifications_sent} sent for {total_events} events "
        f"({notifications_sent / total_events * 100:.1f}%, expected < 5%)"
    )
    assert queue_depth <= _MAX_PENDING_QUEUE_SIZE, (
        f"pending queue must never exceed its configured bound: {queue_depth} > {_MAX_PENDING_QUEUE_SIZE}"
    )
    assert health["dedup_cache_size"] <= 2000, (
        f"dedup/edit-state cache must stay bounded under sustained load: {health['dedup_cache_size']}"
    )
    assert elapsed < 30.0, f"10,000 events must process in bounded time, took {elapsed:.1f}s"
    print(f"\nRESULT: {total_events} events -> {notifications_sent} notifications "
          f"({notifications_sent / total_events * 100:.2f}% of event volume) -- target achieved (< 5%)")
    print("\nLOAD BENCHMARK PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
