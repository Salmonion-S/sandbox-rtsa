import asyncio
import os
import random
import resource
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.pipeline_metrics import get_core_metrics
from discord_integration.webhook import _MAX_PENDING_QUEUE_SIZE, _SEND_OK, DiscordWebhookDispatcher


def rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def build_events(seed: int = 7):
    rng = random.Random(seed)
    events = []
    projects = ["alpha", "beta", "gamma", "delta"]
    for i in range(400):
        project = projects[i % 4]
        path = f"/home/{project}/htdocs/app/file{i % 25}.php"
        severity = Severity.LOW if i % 40 else Severity.HIGH
        events.append(BaseEvent(
            source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE, severity=severity,
            message=f"File berubah: {path}", raw="",
            metadata={"project": project, "domain": f"{project}.example", "path": path, "rule": "FIM_CHANGE"},
        ))
    for i in range(300):
        source = f"203.0.113.{i % 5 + 1}"
        action = "NEW" if i < 5 else ("UPDATE" if i % 60 == 0 else "SILENT")
        events.append(BaseEvent(
            source_module="nginx_monitor", category=EventCategory.WEB_ATTACK_SCAN,
            severity=Severity.MEDIUM if i < 200 else Severity.HIGH,
            message=f"Aktivitas scan dari {source}", raw="",
            metadata={"incident_id": f"scan-{source}", "incident_action": action, "source_ip": source,
                      "domain": "site.example", "evidence_delta": {"requests": 50}},
        ))
    for i in range(150):
        user = f"user{i % 10}"
        events.append(BaseEvent(
            source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.LOW,
            message=f"SSH login diterima untuk '{user}'", raw="",
            metadata={"source_ip": "198.51.100.20", "project": user, "rule": "known_key_login"},
        ))
    for i in range(100):
        events.append(BaseEvent(
            source_module="outbound_anomaly_detector", category=EventCategory.OUTBOUND_ANOMALY, severity=Severity.MEDIUM,
            message="Koneksi keluar tidak dikenal", raw="",
            metadata={"project": projects[i % 4], "affected_resource": f"192.0.2.{i % 4}:443", "rule": "OUTBOUND_UNKNOWN"},
        ))
    for i in range(50):
        new = i in (10, 25, 40)
        events.append(BaseEvent(
            source_module="host_persistence_detector", category=EventCategory.PERSISTENCE_NEW_PORT,
            severity=Severity.CRITICAL if new else Severity.MEDIUM,
            message=f"Port baru {31337 + i if new else 23109}", raw="",
            metadata={"affected_resource": f"0.0.0.0:{31337 + i if new else 23109}", "project": "host",
                      "rule": "PERSISTENCE_NEW_PORT"},
        ))
    rng.shuffle(events)
    return events


async def main() -> None:
    metrics = get_core_metrics()
    metrics.reset()
    config = DiscordConfig(alert_channel_id=555000, outbound=OutboundBackpressureConfig(
        max_sends_per_second=1000.0, max_sends_burst=1000,
    ))
    bus = EventBus()
    dispatcher = DiscordWebhookDispatcher(bus, config)
    sent, edits = [], []

    class Bot:
        def is_ready(self):
            return True

    async def send(payload, **kw):
        sent.append(payload)
        return (_SEND_OK, 555000, 5000 + len(sent))

    async def edit(channel_id, message_id, payload, **kw):
        edits.append(payload)
        return _SEND_OK

    dispatcher._bot = Bot()
    dispatcher._send_via_bot = send
    dispatcher._edit_via_bot = edit
    await dispatcher.start()

    await asyncio.sleep(1.0)
    idle_cpu_start, idle_wall = time.process_time(), time.monotonic()
    await asyncio.sleep(1.0)
    baseline_cpu = (time.process_time() - idle_cpu_start) / (time.monotonic() - idle_wall)
    baseline_rss = rss_mb()
    tasks_before = len(asyncio.all_tasks())
    subs_before = len(bus.subscriber_stats)

    events = build_events()
    assert len(events) == 1000
    criticals = [e for e in events if e.severity == Severity.CRITICAL]
    cpu_start, wall_start = time.process_time(), time.monotonic()
    peak_depth = 0
    for event in events:
        bus.publish_nowait(event)
        peak_depth = max(peak_depth, max(s["queue_size"] for s in bus.subscriber_stats.values()))
    sub = next(iter(bus._subscriptions.values()))
    await asyncio.wait_for(sub.queue.join(), timeout=60)
    await dispatcher._flush_pending_once()
    burst_cpu = time.process_time() - cpu_start
    burst_wall = time.monotonic() - wall_start
    peak_rss = rss_mb()
    snap = metrics.snapshot()
    latency = snap["latency"]["core_processing_latency"]
    counters = snap["counters"]
    tasks_after = len(asyncio.all_tasks())
    stats = dispatcher._gate.stats()
    stats_bus = list(bus.subscriber_stats.values())[0]

    messages = len(sent) + len(edits)
    print("== 1,000 mixed events (FIM 400 / NGINX 300 / SSH 150 / OUTBOUND 100 / PERSISTENCE 50) ==")
    print(f"CPU        baseline idle {baseline_cpu * 100:.2f}% of one core   burst {burst_cpu:.2f}s CPU over {burst_wall:.2f}s wall "
          f"({burst_cpu / max(burst_wall, 1e-9) * 100:.0f}% of one core)")
    print(f"RAM        baseline {baseline_rss:.1f} MB   peak {peak_rss:.1f} MB   growth {peak_rss - baseline_rss:.1f} MB")
    print(f"Latency    core_processing_latency avg {latency['sum'] / max(latency['count'], 1) * 1000:.1f} ms  max {latency['max'] * 1000:.1f} ms"
          f"   bus queue wait avg {stats_bus['avg_queue_wait_ms']} ms max {stats_bus['max_queue_wait_ms']} ms")
    print(f"Discord    {len(sent)} new messages + {len(edits)} edited updates for 1000 events "
          f"({messages / 10.0:.1f}% of event volume)")
    print(f"Queue      peak depth {peak_depth}  dropped {stats_bus['dropped']}  pending retry {len(dispatcher._pending_heap)}")
    print(f"Gate       incidents tracked {stats['incidents_tracked']}  open {stats['incidents_open']}  "
          f"received {counters['core_events_received']}  dedup {counters['core_events_deduplicated']}  "
          f"suppressed {counters['core_events_suppressed']}  created {counters['core_incidents_created']}  "
          f"updated {counters['core_incidents_updated']}  escalated {counters['core_incidents_escalated']}")

    assert counters["core_events_received"] == 1000
    assert stats_bus["dropped"] == 0, "1000 events never overflow the bounded queue"
    assert peak_depth <= stats_bus["queue_maxsize"]
    assert len(dispatcher._pending_heap) <= _MAX_PENDING_QUEUE_SIZE
    assert stats["incidents_tracked"] <= 200, "no incident explosion"
    assert len(sent) <= 100, f"no Discord storm: {len(sent)} new messages for 1000 events"
    assert len(sent) + len(edits) < 150
    critical_blob = " ".join(str(p) for p in sent)
    assert len(criticals) == 3
    for event in criticals:
        port = event.metadata["affected_resource"].rsplit(":", 1)[1]
        assert f"Port baru {port}" in critical_blob, f"genuinely new critical port {port} must be delivered"
    baseline_port_messages = [p for p in sent if "0.0.0.0:23109" in str(p)]
    assert len(baseline_port_messages) <= 1, "sshd on its own port is one baseline notification, never repeated"
    assert tasks_after == tasks_before, f"no scheduler/task multiplication: {tasks_before} -> {tasks_after}"
    assert len(bus.subscriber_stats) == subs_before == 1, "no duplicate subscriptions"
    assert peak_rss - baseline_rss < 60.0, "RAM under queue pressure stays bounded"
    assert burst_cpu < 6.0, f"CPU burst bounded: {burst_cpu:.2f}s"
    await dispatcher.stop()
    await bus.shutdown()
    assert not [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()
                and "rtsa-" in (t.get_name() or "")], "clean shutdown leaves no orphaned RTSA workers"
    print("\nCORE STRESS TEST (1,000 mixed events) PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=170))
