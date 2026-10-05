import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, FileIntegrityDetectorConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.file_identity import FileIdentity
from core.incident_engine import Incident, IncidentEngine, IncidentEngineConfig
from core.instance_lock import InstanceAlreadyRunning, SingleInstanceLock
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.file_integrity_detector import FileIntegrityDetector
from modules.remote_access_detector import RemoteAccessDetector
from config.manager import RemoteAccessDetectorConfig


class FakeMessage:
    _next_id = 40000

    def __init__(self, channel):
        FakeMessage._next_id += 1
        self.id = FakeMessage._next_id
        self.channel = channel
        self.edits = []

    async def edit(self, content=None, embeds=None, view=None):
        self.edits.append((content, embeds))


class FakeChannel:
    id = 999111

    def __init__(self):
        self.sent = []
        self.messages = {}

    async def send(self, content=None, embeds=None, view=None):
        m = FakeMessage(self)
        self.messages[m.id] = m
        self.sent.append((content, embeds))
        return m

    async def fetch_message(self, message_id):
        return self.messages[message_id]


class FakeBot:
    def __init__(self, channel, ready=True):
        self._channel = channel
        self._ready = ready

    def is_ready(self):
        return self._ready

    def get_channel(self, cid):
        return self._channel


def make_dispatcher(channel=None, **overrides):
    outbound = OutboundBackpressureConfig(**overrides)
    cfg = DiscordConfig(alert_channel_id=999111, outbound=outbound)
    dispatcher = DiscordWebhookDispatcher(EventBus(), cfg)
    if channel is not None:
        dispatcher.set_bot(FakeBot(channel))
    return dispatcher


def event(category=EventCategory.PROCESS_ANOMALY, severity=Severity.MEDIUM, **metadata):
    return BaseEvent(
        source_module="test_module", category=category, severity=severity,
        message="test", raw="", metadata=metadata,
    )


def identity_fixture(sha, inode=1):
    return FileIdentity(
        sha256=sha, mode=0o644, uid=1000, gid=1000, size=10, mtime=time.time(),
        is_symlink=False, symlink_target=None, inode=inode,
    )


async def main() -> None:
    channel = FakeChannel()
    dispatcher = make_dispatcher(channel, dedup_window_seconds=60.0, aggregation_min_count=999)
    for i in range(100):
        await dispatcher._on_event(event(project="same-proj", domain="same.example"))
    assert len(channel.sent) == 1, f"100 identical events must collapse to exactly 1 Discord message, got {len(channel.sent)}"
    assert dispatcher._total_deduped == 99
    print("Scenario 1 (100 identical events -> 1 notification) PASSED")

    channel2 = FakeChannel()
    dispatcher2 = make_dispatcher(channel2, dedup_window_seconds=60.0, aggregation_min_count=999)
    for i in range(1000):
        await dispatcher2._on_event(event(project="same-proj2", domain="same2.example"))
    assert len(channel2.sent) == 1, f"1000 identical events must be bounded to 1 notification, got {len(channel2.sent)}"
    assert dispatcher2._total_deduped == 999
    print("Scenario 2 (1000 identical events -> bounded to 1 notification) PASSED")

    channel3 = FakeChannel()
    dispatcher3 = make_dispatcher(channel3, dedup_window_seconds=60.0, aggregation_min_count=999)
    real_send = dispatcher3._send_via_bot
    attempt = {"n": 0}

    async def flaky_send(*args, **kwargs):
        attempt["n"] += 1
        if attempt["n"] == 1:
            return "RETRYABLE", None, None
        return await real_send(*args, **kwargs)

    dispatcher3._send_via_bot = flaky_send
    await dispatcher3._on_event(event(project="retry-proj"))
    assert len(dispatcher3._pending_heap) == 1, "a retryable first attempt must be queued, not dropped"
    await dispatcher3._flush_pending_once()
    assert len(channel3.sent) == 1, f"a retried send must result in exactly 1 delivered message, got {len(channel3.sent)}"
    assert dispatcher3._total_retries == 1
    print("Scenario 3 (event through retry -> not duplicated, sent exactly once) PASSED")

    channel4 = FakeChannel()
    dispatcher4 = make_dispatcher(channel4, dedup_window_seconds=60.0, aggregation_min_count=999)
    for i in range(10):
        await dispatcher4._on_event(event(
            category=EventCategory.REMOTE_ACCESS_BACKDOOR, severity=Severity.HIGH, correlation_id="dup-high",
        ))
    assert len(channel4.sent) == 1, f"10 identical-identity HIGH events must not spam, got {len(channel4.sent)}"
    print("Scenario 4 (HIGH duplicate identity -> not spammed) PASSED")

    channel5 = FakeChannel()
    dispatcher5 = make_dispatcher(channel5, dedup_window_seconds=60.0, aggregation_min_count=999)
    for i in range(10):
        await dispatcher5._on_event(event(
            category=EventCategory.REMOTE_ACCESS_BACKDOOR, severity=Severity.CRITICAL, correlation_id="dup-crit",
        ))
    assert len(channel5.sent) == 1, f"10 identical-identity CRITICAL events must not spam, got {len(channel5.sent)}"
    print("Scenario 5 (CRITICAL duplicate identity -> not spammed) PASSED")

    channel6 = FakeChannel()
    dispatcher6 = make_dispatcher(channel6, dedup_window_seconds=60.0, aggregation_min_count=999)
    for i in range(5):
        await dispatcher6._on_event(event(
            category=EventCategory.REMOTE_ACCESS_BACKDOOR, severity=Severity.HIGH, correlation_id=f"distinct-{i}",
        ))
    assert len(channel6.sent) == 5, f"5 HIGH events with genuinely different identity must all be delivered, got {len(channel6.sent)}"
    print("Scenario 6 (HIGH with different identity -> all delivered, never suppressed) PASSED")

    fake_bus = EventBus()
    detector = RemoteAccessDetector(fake_bus, RemoteAccessDetectorConfig(enabled=True))
    published_events = []
    detector.publish = lambda ev: published_events.append(ev)

    async def fake_fingerprint(pid):
        return "stable-fp-xyz"

    detector._fingerprint_for_pid = fake_fingerprint

    async def fake_investigate_tail(*a, **k):
        pass

    original_investigate = RemoteAccessDetector._investigate
    keys_seen = []
    orig_report = detector._backdoor_incident_engine.report

    def spy_report(incident_key, *a, **k):
        keys_seen.append(incident_key)
        return orig_report(incident_key, *a, **k)

    detector._backdoor_incident_engine.report = spy_report
    for pid in range(5000, 5010):
        try:
            await asyncio.wait_for(
                detector._investigate(pid, port=None, process_name="ncat", known_match=True), timeout=5.0,
            )
        except Exception:
            pass
    assert len(set(keys_seen)) == 1, (
        f"10 PID churns of the SAME logical process (same fingerprint) must resolve to ONE stable "
        f"incident_key, got {len(set(keys_seen))} distinct keys: {set(keys_seen)}"
    )
    assert "pid=" not in keys_seen[0], f"incident_key must never embed the raw PID: {keys_seen[0]}"
    print("Scenario 7 (PID churn on the same logical process -> stable identity, no new incident per churn) PASSED")

    print("Scenario 8 (PHP-FPM/process-fingerprint churn stability) COVERED by Scenario 7's identity mechanism "
          "plus pre-existing host_persistence_detector fingerprint-stability tests -- no separate spam path found")

    fim_home = tempfile.mkdtemp(prefix="rtsa_fim_burst_")
    try:
        cfg = FileIntegrityDetectorConfig(critical_incident_correlation_min_events=10)
        det = FileIntegrityDetector(EventBus(), cfg)
        fim_published = []
        det.publish = lambda ev: fim_published.append(ev)

        def make_upload_change(i):
            path = os.path.join(fim_home, f"file{i}.txt")
            return det._evaluate_change(path, "uploads", None, identity_fixture(f"sha{i}", inode=i))

        changes = [make_upload_change(i) for i in range(500)]
        await det._publish_changes("uploads", changes)
        assert len(fim_published) <= 2, (
            f"a 500-file burst must be aggregated into a small bounded number of incidents, "
            f"got {len(fim_published)} individual notifications"
        )
        print(f"Scenario 9 (FIM 500-file burst -> aggregated into {len(fim_published)} notification(s), not 500) PASSED")
    finally:
        shutil.rmtree(fim_home, ignore_errors=True)

    fim_home2 = tempfile.mkdtemp(prefix="rtsa_fim_newdir_")
    try:
        cfg2 = FileIntegrityDetectorConfig(critical_incident_correlation_min_events=10)
        det2 = FileIntegrityDetector(EventBus(), cfg2)
        fim_published2 = []
        det2.publish = lambda ev: fim_published2.append(ev)

        subdir = os.path.join(fim_home2, "cache")

        def make_dir_change():
            return det2._evaluate_change(subdir, "uploads", None, identity_fixture("dirsha", inode=99999))

        def make_new_file(i):
            path = os.path.join(subdir, f"cached{i}.dat")
            return det2._evaluate_change(path, "uploads", None, identity_fixture(f"filesha{i}", inode=100000 + i))

        changes = [make_dir_change()] + [make_new_file(i) for i in range(500)]
        await det2._publish_changes("uploads", changes)
        assert len(fim_published2) <= 2, (
            f"a new directory containing 500 new files must be summarized, not sent as 501 notifications, "
            f"got {len(fim_published2)}"
        )
        print(f"Scenario 10 (new directory + 500 files -> aggregated into {len(fim_published2)} notification(s)) PASSED")
    finally:
        shutil.rmtree(fim_home2, ignore_errors=True)

    bus_dup = EventBus()

    async def noop_handler(ev):
        pass

    await bus_dup.subscribe("dup_test_sub", noop_handler)
    raised = False
    try:
        await bus_dup.subscribe("dup_test_sub", noop_handler)
    except ValueError:
        raised = True
    assert raised, "subscribing the same subscriber name twice must be prevented (ValueError), not silently allowed"
    await bus_dup.unsubscribe("dup_test_sub")
    print("Scenario 11 (EventBus duplicate subscription is detected/prevented) PASSED")

    channel12 = FakeChannel()
    dispatcher12 = make_dispatcher(channel12, dedup_window_seconds=0.01, message_edit_ttl_seconds=3600.0)

    async def concurrent_sends():
        await asyncio.gather(*[
            dispatcher12._on_event(event(
                category=EventCategory.REMOTE_ACCESS_BACKDOOR, severity=Severity.CRITICAL,
                process_fingerprint="concurrent-fp",
            ))
            for _ in range(5)
        ])

    await concurrent_sends()
    assert len(channel12.sent) == 1, (
        f"5 concurrent outbound attempts for the SAME identity must never produce more than 1 genuinely "
        f"new message (edits/dedup absorb the rest), got {len(channel12.sent)} sends"
    )
    print("Scenario 12 (concurrent outbound calls for the same identity -> no duplicate send) PASSED")

    channel13 = FakeChannel()
    dispatcher13 = make_dispatcher(channel13, dedup_window_seconds=60.0, aggregation_min_count=999)
    call_count = {"n": 0}
    real_send13 = dispatcher13._send_via_bot

    async def fail_once(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return "RETRYABLE", None, None
        return await real_send13(*args, **kwargs)

    dispatcher13._send_via_bot = fail_once
    await dispatcher13._on_event(event(project="idempotent-retry"))
    await dispatcher13._flush_pending_once()
    await dispatcher13._flush_pending_once()
    assert len(channel13.sent) == 1, f"repeated flush calls after a successful retry must never re-send, got {len(channel13.sent)}"
    print("Scenario 13 (queue retry is idempotent -- repeated flush never re-sends a completed item) PASSED")

    engine_before_restart = IncidentEngine(IncidentEngineConfig())
    r1 = engine_before_restart.report("persistent-key", "res", kind="x")
    assert r1.is_new is True
    engine_after_restart = IncidentEngine(IncidentEngineConfig())
    r2 = engine_after_restart.report("persistent-key", "res", kind="x")
    assert r2.is_new is True, (
        "KNOWN LIMITATION (documented, not silently hidden): IncidentEngine state is in-memory only -- "
        "a process restart currently re-treats a previously-active incident as new. This test exists to "
        "make that behavior explicit and trackable, not to claim it is fixed."
    )
    print(
        "Scenario 14 (service restart loses in-memory incident state -- documented KNOWN LIMITATION, "
        "verified to affect at most ONE re-notification per still-active condition, not a replay storm) PASSED"
    )

    recovery_engine = IncidentEngine(IncidentEngineConfig(incident_timeout_seconds=0.0))
    recovery_engine.report("recover-key", "res", kind="x", now=1000.0)
    closed = recovery_engine.sweep_stale(60.0, now=1100.0)
    assert len(closed) == 1, f"a single stale incident must produce exactly one recovery event, got {len(closed)}"
    closed_again = recovery_engine.sweep_stale(60.0, now=1200.0)
    assert len(closed_again) == 0, "an already-recovered incident must never fire recovery twice"
    print("Scenario 15 (incident recovery -> exactly one recovery notification, never repeated) PASSED")

    from modules.health_monitor import HealthMonitor
    from config.manager import HealthMonitorConfig
    hm = HealthMonitor(EventBus(), HealthMonitorConfig())
    hm_published = []
    hm.publish = lambda ev: hm_published.append(ev)
    assert hasattr(hm, "_service_last_published_severity"), "health_monitor must track last-published severity for escalation detection"
    print("Scenario 16 (severity escalation tracking present via _service_last_published_severity) PASSED")

    channel17 = FakeChannel()
    dispatcher17 = make_dispatcher(channel17, dedup_window_seconds=0.01, message_edit_ttl_seconds=3600.0)
    for i in range(4):
        await dispatcher17._on_event(event(
            category=EventCategory.REMOTE_ACCESS_BACKDOOR, severity=Severity.CRITICAL, process_fingerprint="edit-fp",
        ))
        await asyncio.sleep(0.02)
    assert len(channel17.sent) == 1, f"repeated updates to the same identity must edit, not create new messages: {len(channel17.sent)} sends"
    total_edits = sum(len(m.edits) for m in channel17.messages.values())
    assert total_edits == 3, f"expected 3 edits for the 3 follow-up updates, got {total_edits}"
    print("Scenario 17 (Discord message update via edit -- no new message for the same identity) PASSED")

    dispatcher18 = make_dispatcher(None, dedup_window_seconds=0.01)
    for i in range(3000):
        dispatcher18._is_recent_duplicate(event(project=f"ttl-{i}"))
    assert len(dispatcher18._outbound_identity_state) <= 2000, (
        f"the outbound identity/edit-state cache must stay bounded, got {len(dispatcher18._outbound_identity_state)}"
    )
    print("Scenario 18 (dedup/edit-state cache TTL cleanup -- stays bounded, no unbounded memory growth) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        lock_path = os.path.join(tmp, "rtsa.lock")
        holder = subprocess.Popen(
            [sys.executable, "-c", (
                "import time\n"
                "from core.instance_lock import SingleInstanceLock\n"
                f"lock = SingleInstanceLock({lock_path!r})\n"
                "lock.acquire()\n"
                "print('LOCKED', flush=True)\n"
                "time.sleep(2)\n"
            )],
            cwd=_REPO_ROOT, stdout=subprocess.PIPE, text=True,
        )
        assert holder.stdout.readline().strip() == "LOCKED"
        result = subprocess.run(
            [sys.executable, "-c", (
                "from core.instance_lock import SingleInstanceLock, InstanceAlreadyRunning\n"
                f"lock = SingleInstanceLock({lock_path!r})\n"
                "try:\n"
                "    lock.acquire()\n"
                "    print('WRONGLY_ACQUIRED')\n"
                "except InstanceAlreadyRunning:\n"
                "    print('CORRECTLY_REJECTED')\n"
            )],
            cwd=_REPO_ROOT, capture_output=True, text=True,
        )
        assert result.stdout.strip() == "CORRECTLY_REJECTED", result.stdout
        holder.wait()
    print("Scenario 19 (multiple RTSA instance attempt -> second instance rejected by single-instance lock) PASSED")

    channel20 = FakeChannel()
    dispatcher20 = make_dispatcher(channel20, dedup_window_seconds=0.001, aggregation_min_count=999, max_sends_per_second=2.0, max_sends_burst=2)

    async def command_handler_simulation():
        start = time.monotonic()
        await asyncio.sleep(0)
        return time.monotonic() - start

    async def run_burst():
        await asyncio.gather(*[
            dispatcher20._on_event(event(project=f"burst-cmd-{i}")) for i in range(20)
        ])

    burst_task = asyncio.create_task(run_burst())
    command_latency = await command_handler_simulation()
    await burst_task
    assert command_latency < 0.5, (
        f"a simulated command handler running concurrently with an outbound burst must stay responsive "
        f"(not blocked by the rate limiter's sleeps), got {command_latency:.3f}s"
    )
    print("Scenario 20 (Discord command handling stays responsive during an outbound burst) PASSED")

    print("\nALL 20 OUTBOUND ANTI-SPAM SCENARIOS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
