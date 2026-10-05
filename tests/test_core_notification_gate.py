import asyncio
import json
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import (
    CoreConfig, CoreDedupConfig, CoreEventQueueConfig, CoreNotificationsConfig, DiscordConfig,
    OutboundBackpressureConfig,
)
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.instance_lock import InstanceAlreadyRunning, SingleInstanceLock
from core.notification_gate import (
    ACTION_ESCALATE, ACTION_SEND, ACTION_SUPPRESS, ACTION_UPDATE, LIFECYCLE_NEW, LIFECYCLE_REOPENED,
    NotificationGate, event_fingerprint, PersistedIncident,
)
from core.pipeline_metrics import PipelineMetrics, get_core_metrics, CORE_COUNTERS, CORE_GAUGES, CORE_LATENCIES
from discord_integration.webhook import (
    _MAX_PENDING_QUEUE_SIZE, _SEND_OK, _SEND_RETRYABLE, DiscordWebhookDispatcher,
)


def ev(category=EventCategory.WEB_ATTACK_SCAN, severity=Severity.MEDIUM, module="nginx_monitor", message="scan",
       **meta):
    return BaseEvent(source_module=module, category=category, severity=severity, message=message, raw="", metadata=meta)


def make_gate(now=None, **notifications):
    clock = {"t": 1000.0}
    core = CoreConfig(
        dedup=CoreDedupConfig(default_window_seconds=30.0, window_by_category={}),
        notifications=CoreNotificationsConfig(**notifications),
    )
    gate = NotificationGate(core, clock=lambda: clock["t"], metrics=PipelineMetrics(CORE_COUNTERS, CORE_GAUGES, CORE_LATENCIES))
    return gate, clock


def identity(e):
    return f"{e.category.value}|{e.source_module}|project={e.metadata.get('project')}|domain={e.metadata.get('domain')}"


def dispatcher_with_bot(core=None, **outbound):
    config = DiscordConfig(alert_channel_id=555000, outbound=OutboundBackpressureConfig(**{
        "aggregation_min_count": 9999, "critical_aggregation_min_count": 9999, **outbound}))
    d = DiscordWebhookDispatcher(EventBus(), config, core_config=core)
    sent, edits = [], []

    class Bot:
        def is_ready(self):
            return True

    async def send(payload, **kw):
        sent.append(payload)
        return (_SEND_OK, 555000, 1000 + len(sent))

    async def edit(channel_id, message_id, payload, **kw):
        edits.append(payload)
        return _SEND_OK

    d._bot = Bot()
    d._send_via_bot = send
    d._edit_via_bot = edit
    return d, sent, edits


async def test_dedup_idempotency_fingerprint():
    gate, clock = make_gate()
    a = ev(project="p1", domain="d1")
    first = gate.decide(a, identity(a))
    assert first.action == ACTION_SEND and first.lifecycle == LIFECYCLE_NEW
    assert gate.decide(a, identity(a)).reason == "duplicate_event_id", "same event delivered twice is idempotent"
    for _ in range(100):
        clock["t"] += 0.1
        d = gate.decide(ev(project="p1", domain="d1"), identity(a))
        assert d.action == ACTION_SUPPRESS and d.reason == "duplicate"
    assert gate.sent_total == 1 and gate.suppressed_total == 101
    print("Test 1 (same event_id twice -> idempotent; 100 identical events -> 1 send, 100 duplicates suppressed) PASSED")

    x = ev(message="Anomali pada 2026-08-19 12:00:01.123 pid=4 ts=1787140801")
    y = ev(message="Anomali pada 2026-08-19 12:07:44.900 pid=4 ts=1787141264")
    assert event_fingerprint(x) == event_fingerprint(y), "high-precision timestamps never change the fingerprint"
    assert event_fingerprint(x) != event_fingerprint(ev(message="Anomali pada X pid=5"))
    assert event_fingerprint(ev(seed=1)) != event_fingerprint(ev(seed=2)), "different evidence is a different event"
    assert event_fingerprint(ev(seed=1, observed_at=5.0)) == event_fingerprint(ev(seed=1, observed_at=9.0))
    print("Test 2 (deterministic fingerprint: timestamps/observation times excluded, evidence included) PASSED")

    gate, clock = make_gate()
    one = ev(module="nginx_monitor", project="p1", domain="d1")
    two = ev(module="injection_detector", project="p1", domain="d1")
    assert gate.decide(one, identity(one)).action == ACTION_SEND
    clock["t"] += 1
    dup = gate.decide(two, identity(two))
    assert dup.action == ACTION_SUPPRESS and dup.reason == "duplicate_detector"
    other = ev(module="injection_detector", project="p2", domain="d2")
    assert gate.decide(other, identity(other)).action == ACTION_SEND, "different project is independent evidence"
    print("Test 3 (two detectors reporting the same thing -> one notification; other project unaffected) PASSED")


async def test_escalation_update_and_limits():
    gate, clock = make_gate(max_per_incident_updates=3)
    low = ev(severity=Severity.LOW, project="p", domain="d")
    assert gate.decide(low, identity(low)).action == ACTION_SEND
    clock["t"] += 2
    high = ev(severity=Severity.HIGH, project="p", domain="d")
    d = gate.decide(high, identity(high))
    assert d.action == ACTION_ESCALATE and d.previous_severity == "LOW" and d.lifecycle == "ESCALATED"
    clock["t"] += 2
    again = ev(severity=Severity.HIGH, project="p", domain="d")
    assert gate.decide(again, identity(again)).action == ACTION_SUPPRESS, "HIGH -> HIGH identical never repeats"
    clock["t"] += 2
    crit = ev(severity=Severity.CRITICAL, project="p", domain="d")
    assert gate.decide(crit, identity(crit)).action == ACTION_ESCALATE, "new critical evidence -> one escalation"
    clock["t"] += 2
    crit2 = ev(severity=Severity.CRITICAL, project="p", domain="d")
    assert gate.decide(crit2, identity(crit2)).action == ACTION_SUPPRESS
    print("Test 4 (LOW -> HIGH -> CRITICAL = initial + two escalations; identical repeats suppressed) PASSED")

    gate, clock = make_gate(max_per_incident_updates=2)
    first = ev(project="p", domain="d")
    assert gate.decide(first, identity(first)).action == ACTION_SEND
    actions = []
    for _ in range(6):
        clock["t"] += 40.0
        e = ev(project="p", domain="d")
        actions.append(gate.decide(e, identity(e)).action)
    assert actions.count(ACTION_UPDATE) == 2 and actions.count(ACTION_SUPPRESS) == 4, actions
    print("Test 5 (a recurring identical event is bounded: 1 notification + 2 updates, the rest suppressed) PASSED")

    gate, clock = make_gate(max_per_incident_updates=2)
    a = ev(project="p", domain="d", incident_id="inc-1", incident_action="NEW")
    assert gate.decide(a, identity(a)).action == ACTION_SEND
    seen = []
    for i in range(5):
        clock["t"] += 1.0
        e = ev(project="p", domain="d", incident_id="inc-1", incident_action="UPDATE", evidence_delta={"requests": 87})
        seen.append(gate.decide(e, identity(e)).action)
    assert seen == [ACTION_UPDATE, ACTION_UPDATE, ACTION_SUPPRESS, ACTION_SUPPRESS, ACTION_SUPPRESS], seen
    print("Test 6 (detector-owned incident deltas bypass the dedup window but are bounded per incident) PASSED")

    gate, clock = make_gate(max_per_minute=3, max_critical_per_minute=2)
    for i in range(3):
        e = ev(project=f"p{i}", domain="d")
        d = gate.decide(e, identity(e))
        assert d.action == ACTION_SEND
        gate.record_send()
    blocked = ev(project="pX", domain="d", category=EventCategory.NGINX_RATE_ANOMALY)
    d = gate.decide(blocked, identity(blocked))
    assert d.action == ACTION_SUPPRESS and d.reason == "rate_limit"
    crit = ev(project="pC", domain="d", severity=Severity.CRITICAL, category=EventCategory.WEB_ATTACK_SUCCESS)
    assert gate.decide(crit, identity(crit)).action == ACTION_SEND, "a NEW critical incident uses its own budget"
    crit_dup = ev(project="pC", domain="d", severity=Severity.CRITICAL, category=EventCategory.WEB_ATTACK_SUCCESS)
    assert gate.decide(crit_dup, identity(crit_dup)).action == ACTION_SUPPRESS, "critical is still deduplicated"
    summary = gate.take_suppression_summary()
    assert summary == {"NGINX_RATE_ANOMALY": 1}, summary
    assert gate.take_suppression_summary() == {}
    clock["t"] += 61.0
    later = ev(project="pX", domain="d", category=EventCategory.NGINX_RATE_ANOMALY)
    assert gate.decide(later, identity(later)).action == ACTION_SEND, "the window rolls; nothing is blocked forever"
    print("Test 7 (per-minute cap: suppressed + counted + summarised, critical budget separate, cap rolls off) PASSED")


async def test_lifecycle_reopen_and_separation():
    gate, clock = make_gate(incident_quiet_seconds=60.0, incident_close_seconds=300.0, reopen_window_seconds=300.0)
    a = ev(project="p", domain="d")
    assert gate.decide(a, identity(a)).lifecycle == LIFECYCLE_NEW
    clock["t"] += 400.0
    assert gate.sweep() == 1 and gate.open_incidents() == 0
    b = ev(project="p", domain="d")
    d = gate.decide(b, identity(b))
    assert d.reopened and d.lifecycle in (LIFECYCLE_REOPENED, "REOPENED") and d.action in (ACTION_SEND, ACTION_UPDATE), d
    clock["t"] += 2000.0
    c = ev(project="p", domain="d")
    assert gate.decide(c, identity(c)).lifecycle == LIFECYCLE_NEW, "after the reopen window a NEW incident starts"
    print("Test 8 (incident CLOSED by the sweep, REOPENED inside the reopen window, NEW after it) PASSED")

    gate, clock = make_gate()
    for project in ("alpha", "beta", "gamma"):
        e = ev(project=project, domain=f"{project}.example")
        assert gate.decide(e, identity(e)).action == ACTION_SEND
    other = ev(category=EventCategory.FILE_INTEGRITY_CHANGE, project="alpha", domain="alpha.example")
    assert gate.decide(other, identity(other)).action == ACTION_SEND
    print("Test 9 (different projects / different evidence kinds never suppress each other) PASSED")


async def test_restart_persistence():
    gate, clock = make_gate()
    a = ev(project="p", domain="d")
    assert gate.decide(a, identity(a)).action == ACTION_SEND
    exported = {k: v.__dict__ for k, v in gate.export_state().items()}
    gate2, clock2 = make_gate()
    clock2["t"] = 55.0
    assert gate2.import_state(exported) == 1
    b = ev(project="p", domain="d")
    assert gate2.decide(b, identity(b)).action == ACTION_SUPPRESS, "a restarted process does not re-notify the same incident"
    stale = {"x": PersistedIncident(first_seen_wall=1.0, last_event_wall=2.0, last_sent_wall=2.0, peak_rank=2, sent_count=1, updates_sent=0)}
    assert gate2.import_state(stale) == 0, "state older than the close+reopen horizon is ignored"

    tmp = tempfile.mkdtemp()
    core = CoreConfig(notifications=CoreNotificationsConfig(state_path=os.path.join(tmp, "gate.json")))
    d1, sent1, _ = dispatcher_with_bot(core=core)
    await d1._on_event(ev(project="p", domain="d"))
    assert len(sent1) == 1
    await d1._save_gate_state(force=True)
    assert os.path.exists(core.notifications.state_path)
    d2, sent2, _ = dispatcher_with_bot(core=core)
    await d2._load_gate_state()
    await d2._on_event(ev(project="p", domain="d"))
    assert sent2 == [], "process restart: the already-notified incident is not sent again"
    print("Test 10 (restart: incident state survives via the state store -> no duplicate notification; stale state ignored) PASSED")


async def test_dispatcher_behaviour():
    d, sent, edits = dispatcher_with_bot()
    for _ in range(100):
        await d._on_event(ev(project="p", domain="d"))
    assert len(sent) == 1 and d._total_deduped == 99
    print("Test 11 (100 identical events -> 1 Discord message, 99 deduplicated, none silently lost) PASSED")

    d, sent, edits = dispatcher_with_bot()
    await d._on_event(ev(severity=Severity.MEDIUM, project="p", domain="d", incident_id="inc-7", incident_action="NEW"))
    await d._on_event(ev(severity=Severity.MEDIUM, project="p", domain="d", incident_id="inc-7",
                         incident_action="UPDATE", evidence_delta={"requests": 87}))
    assert len(sent) == 1 and len(edits) == 1, "an UPDATE edits the existing message"
    blob = json.dumps(edits[0])
    assert "+87 requests" in blob and "Incident UPDATE" in blob and "inc-7" in blob, blob[:500]
    await d._on_event(ev(severity=Severity.HIGH, project="p", domain="d", incident_id="inc-7", incident_action="ESCALATE"))
    assert len(sent) == 2, "a severity escalation is a NEW message so the operator is notified again"
    assert "MEDIUM -> HIGH" in json.dumps(sent[1]).replace("\\\\", "")
    await d._on_event(ev(severity=Severity.HIGH, project="p", domain="d", incident_id="inc-7", incident_action="SILENT"))
    assert len(sent) == 2
    print("Test 12 (incident contract: NEW, UPDATE as an edited delta, ESCALATE as a new message, SILENT stays silent) PASSED")

    core = CoreConfig(notifications=CoreNotificationsConfig(max_per_minute=4))
    d, sent, edits = dispatcher_with_bot(core=core, max_sends_per_second=1000.0, max_sends_burst=1000)
    for i in range(20):
        await d._on_event(ev(project=f"project-{i}", domain=f"d{i}", category=EventCategory.OUTBOUND_ANOMALY))
    assert len(sent) == 4, f"the per-minute cap holds delivery to 4 messages, got {len(sent)}"
    assert d._total_gate_limited == 16
    await d._on_event(ev(severity=Severity.CRITICAL, project="hot", domain="d", category=EventCategory.WEB_ATTACK_SUCCESS))
    assert len(sent) == 5 and "Notifikasi Ditahan" in json.dumps(sent[-1]), "critical passes and reports what was held back"
    print("Test 13 (rate limit: 20 events -> 4 messages, 16 counted as held back, next message says so) PASSED")

    d, sent, edits = dispatcher_with_bot()
    evil = ev(project="p", domain="d", message="@everyone <@123> <@&9> **x**\n" + "A" * 5000)
    await d._on_event(evil)
    blob = json.dumps(sent[0])
    assert "<@123>" not in blob and "<@&9>" not in blob and "@everyone" not in blob.replace("@\\u200beveryone", "")
    assert all(len(f["value"]) <= 1024 for f in sent[0]["embeds"][0]["fields"])
    print("Test 14 (message safety: mentions neutralised, oversized text bounded) PASSED")


async def test_retry_and_failure_bounds():
    d, sent, edits = dispatcher_with_bot()
    attempts = {"n": 0}

    async def flaky(payload, **kw):
        attempts["n"] += 1
        if attempts["n"] <= 2:
            return (_SEND_RETRYABLE, None, None)
        sent.append(payload)
        return (_SEND_OK, 555000, 77)

    d._send_via_bot = flaky
    await d._on_event(ev(project="p", domain="d"))
    assert sent == [] and len(d._pending_heap) == 1
    for _ in range(3):
        d._next_attempt_at = 0.0
        await d._flush_pending_once()
    assert len(sent) == 1 and len(d._pending_heap) == 0, "retried until delivered, then delivered exactly once"
    await d._on_event(ev(project="p", domain="d"))
    assert len(sent) == 1, "the retried alert is not sent again as a new event"
    print("Test 15 (retryable failure: queued, retried, delivered exactly once, not duplicated) PASSED")

    d, sent, edits = dispatcher_with_bot(circuit_breaker_failure_threshold=3, backoff_base_seconds=0.01,
                                         backoff_max_seconds=0.05, backoff_jitter_seconds=0.0)

    async def always_fail(payload, **kw):
        return (_SEND_RETRYABLE, None, None)

    d._send_via_bot = always_fail
    started = time.process_time()
    for i in range(3000):
        await d._on_event(ev(project=f"p{i}", domain="d", category=EventCategory.OUTBOUND_ANOMALY,
                             severity=Severity.HIGH if i % 7 == 0 else Severity.MEDIUM))
    for _ in range(30):
        await d._flush_pending_once()
    cpu = time.process_time() - started
    assert len(d._pending_heap) <= _MAX_PENDING_QUEUE_SIZE, "the retry queue is bounded, never infinite"
    assert d._total_failed < 400, f"bounded retries, no storm: {d._total_failed}"
    assert cpu < 12.0, f"no CPU storm while Discord is unavailable: {cpu:.2f}s"
    print(f"Test 16 (Discord unavailable: 3000 events -> bounded queue ({len(d._pending_heap)}), {d._total_failed} failed attempts, {cpu:.2f}s CPU) PASSED")

    d1, _, _ = dispatcher_with_bot()
    await d1.start()
    assert len(d1.bus.subscriber_stats) == 1
    try:
        await d1.start()
    except ValueError:
        pass
    assert len(d1.bus.subscriber_stats) == 1, "a second start() never doubles the subscription"
    await d1.stop()
    assert len(d1.bus.subscriber_stats) == 0
    await d1.start()
    assert len(d1.bus.subscriber_stats) == 1
    await d1.stop()
    print("Test 17 (start/stop/start: exactly one subscription, no doubled handlers, clean shutdown) PASSED")


async def test_queue_overflow_priority():
    bus = EventBus(reserve_ratio=0.2)
    release = asyncio.Event()
    got = []

    async def slow(event):
        await release.wait()
        got.append(event)

    sub = await bus.subscribe("slow", slow, max_queue_size=50)
    for i in range(500):
        bus.publish_nowait(ev(severity=Severity.LOW, category=EventCategory.WEB_ATTACK_SCAN, message=f"low {i}"))
    depth_after_flood = sub.queue.qsize()
    assert depth_after_flood <= sub.soft_limit < 50 or depth_after_flood <= 50
    for i in range(5):
        bus.publish_nowait(ev(severity=Severity.CRITICAL, category=EventCategory.WEB_ATTACK_SUCCESS, message=f"crit {i}"))
    assert sub.queue.qsize() <= 50, "the declared bound is hard"
    stats = sub.stats
    assert stats["dropped_low_value"] > 400 and stats["dropped_reserved_full"] == 0, stats
    release.set()
    await asyncio.sleep(0.3)
    crit_delivered = [e for e in got if e.severity == Severity.CRITICAL]
    assert len(crit_delivered) == 5, "critical events survive a low-value flood"
    assert get_core_metrics().snapshot()["counters"]["core_queue_dropped"] >= 400
    await bus.shutdown()
    print("Test 18 (queue overflow: low-value flood dropped + counted, all 5 critical events preserved, hard bound kept) PASSED")


async def test_feedback_single_instance_metrics_cpu():
    from database.sqlite_pool import SQLiteWriteWorker
    worker = SQLiteWriteWorker(os.path.join(tempfile.mkdtemp(), "t.db"), queue_max_size=100)
    for _ in range(3):
        worker.enqueue_adaptive_feedback(
            incident_id="inc-1", correlation_id=None, kind="Web attack", scope_key="site", project="p", server="s",
            verdict="FALSE_POSITIVE", action=None, source="button", requested_by="op1",
        )
    worker.enqueue_adaptive_feedback(
        incident_id="inc-1", correlation_id=None, kind="Web attack", scope_key="site", project="p", server="s",
        verdict="TRUE_POSITIVE", action=None, source="button", requested_by="op1",
    )
    assert worker._queue.qsize() == 2 and worker.feedback_duplicates_skipped == 2
    print("Test 19 (adaptive feedback: a repeated click is one training record; a different verdict is another) PASSED")

    tmp = tempfile.mkdtemp()
    first = SingleInstanceLock(os.path.join(tmp, "rtsa.lock"))
    second = SingleInstanceLock(os.path.join(tmp, "rtsa.lock"))
    first.acquire()
    try:
        second.acquire()
        raise AssertionError("a second RTSA instance must fail fast")
    except InstanceAlreadyRunning:
        pass
    first.release()
    second.acquire()
    second.release()
    print("Test 20 (single instance: the second process fails fast, then succeeds once the first releases) PASSED")

    from core.metrics_exporter import MetricsExporter
    text = MetricsExporter.__new__(MetricsExporter)
    snapshot = get_core_metrics().snapshot()
    for name in ("core_events_received", "core_events_deduplicated", "core_events_coalesced", "core_events_suppressed",
                 "core_incidents_created", "core_incidents_updated", "core_incidents_escalated", "core_incidents_closed",
                 "core_incidents_reopened", "core_notifications_sent", "core_notifications_suppressed",
                 "core_notification_failures", "core_queue_dropped", "core_duplicate_events",
                 "core_duplicate_detector_events"):
        assert name in snapshot["counters"], name
    for name in ("core_incidents_open", "core_queue_depth"):
        assert name in snapshot["gauges"], name
    assert "core_processing_latency" in snapshot["latency"]
    print("Test 21 (all required core_* metrics registered in the existing exporter registry) PASSED")

    from core import self_health
    from modules.nginx_monitor import NginxMonitor
    from config.manager import NginxMonitorConfig, WebProbeConfig
    monitor = NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True, web_probe=WebProbeConfig(enrichment_enabled=True)))
    health = self_health.get_self_health_monitor()
    original = health._state
    health._state = self_health.OVERLOADED
    try:
        monitor._schedule_source_enrichment("8.8.8.8")
        assert not monitor._enrichment_tasks, "external enrichment is the first thing paused under host pressure"
    finally:
        health._state = original
    print("Test 22 (high CPU: low-priority external IP enrichment paused; detection/ingestion code paths untouched) PASSED")


async def main():
    await test_dedup_idempotency_fingerprint()
    await test_escalation_update_and_limits()
    await test_lifecycle_reopen_and_separation()
    await test_restart_persistence()
    await test_dispatcher_behaviour()
    await test_retry_and_failure_bounds()
    await test_queue_overflow_priority()
    await test_feedback_single_instance_metrics_cpu()
    print("\nALL CORE NOTIFICATION GATE TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=170))
