import asyncio
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, SSHEventTimingConfig, SSHMonitorConfig
from core.analyzer import StatefulAnalyzer
from core.datatypes import BaseEvent, EventCategory, Severity, SSHEvent
from core.event_bus import EventBus, current_queue_wait_ms
from core.pipeline_metrics import get_ssh_metrics
from core.ssh_timing import (
    DELAYED, DUPLICATE, REALTIME, REPLAYED, STALE, UNKNOWN, assess_timing, explain_event_timing, format_delay,
    journal_realtime_to_epoch, notification_allowed_by_timing, parse_log_line_timestamp,
)
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.ssh_monitor import SSHMonitor, parse_journal_json_line

ACCEPTED = "Accepted publickey for {user} from {ip} port {port} ssh2"
LOGOUT = "pam_unix(sshd:session): session closed for user {user}"


def make_monitor(state_path="", **kw):
    cfg = SSHMonitorConfig(
        enabled=True, geoip_lookup=False, state_path=state_path, trusted_linux_users=["newusproud"],
        use_sshd_t=False, **kw,
    )
    mon = SSHMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def raw(pub):
    return [e for e in pub if e.category not in (EventCategory.SSH_SESSION, EventCategory.SSH_SESSION_ACTIVITY)]


def accepted(user="newusproud", ip="114.10.100.143", port=56128):
    return ACCEPTED.format(user=user, ip=ip, port=port)


def test_timing_model():
    cfg = SSHEventTimingConfig()
    now = 1_800_000_000.0
    assert assess_timing(now - 0.5, now, cfg).status == REALTIME
    assert assess_timing(now - 30, now, cfg).status == DELAYED
    late = assess_timing(now - 120, now, cfg)
    assert late.status == DELAYED and late.late
    assert assess_timing(now - 301, now, cfg).status == STALE
    assert assess_timing(now - 5, now, cfg, replayed=True).status == REPLAYED
    assert assess_timing(now - 5, now, cfg, duplicate=True).status == DUPLICATE
    unknown = assess_timing(None, now, cfg)
    assert unknown.status == UNKNOWN and unknown.delay_seconds is None, "observed time is never used as event time"
    ahead = assess_timing(now + 60, now, cfg)
    assert ahead.clock_skew and ahead.delay_seconds == 0.0
    custom = SSHEventTimingConfig(realtime_max_delay_seconds=2, delayed_max_delay_seconds=5, stale_after_seconds=10)
    assert assess_timing(now - 3, now, custom).status == DELAYED and assess_timing(now - 11, now, custom).status == STALE
    assert format_delay(1.234) == "1.2s" and format_delay(333) == "5m 33s" and format_delay(7440) == "2h 4m"
    assert format_delay(None) == "UNKNOWN"
    print("Test 0a (REALTIME/DELAYED/late/STALE/REPLAYED/DUPLICATE/UNKNOWN classification, configurable thresholds, honest UNKNOWN) PASSED")

    ok, _ = notification_allowed_by_timing(assess_timing(now - 100, now, cfg), security_relevant=False, critical=False)
    assert not ok, "a late, normal event is stored, not notified"
    ok, reason = notification_allowed_by_timing(assess_timing(now - 100, now, cfg), security_relevant=True, critical=False)
    assert ok and "Delayed Security Event" in reason
    ok, _ = notification_allowed_by_timing(assess_timing(now - 9000, now, cfg), security_relevant=True, critical=False)
    assert not ok, "stale needs critical evidence, not just relevance"
    ok, _ = notification_allowed_by_timing(assess_timing(now - 9000, now, cfg), security_relevant=True, critical=True)
    assert ok
    print("Test 0b (delayed notification policy: normal -> store, relevant late -> labelled, stale -> only critical) PASSED")

    micros = "1787140801123456"
    assert abs(journal_realtime_to_epoch(micros) - 1787140801.123456) < 1e-6
    parsed = parse_journal_json_line(json.dumps({
        "MESSAGE": "hello", "__REALTIME_TIMESTAMP": micros, "__CURSOR": "s=abc;i=1", "_PID": "4321",
    }))
    assert parsed == {"message": "hello", "event_time": journal_realtime_to_epoch(micros), "cursor": "s=abc;i=1", "pid": 4321}
    assert parse_journal_json_line("plain text line") is None and parse_journal_json_line("{not json") is None
    assert parse_journal_json_line(json.dumps({"MESSAGE": [104, 105]}))["message"] == "hi"
    iso, rest = parse_log_line_timestamp("2026-08-19T21:34:12.123456+07:00 host sshd[1]: x")
    assert iso == datetime(2026, 8, 19, 14, 34, 12, 123456, tzinfo=timezone.utc).timestamp() and rest.startswith("host")
    z, _ = parse_log_line_timestamp("2026-08-19T21:34:12Z sshd[1]: x")
    assert z == datetime(2026, 8, 19, 21, 34, 12, tzinfo=timezone.utc).timestamp()
    jan1 = datetime(2027, 1, 1, 0, 30, 0).timestamp()
    dec31, _ = parse_log_line_timestamp("Dec 31 23:59:58 host sshd[1]: x", now_epoch=jan1)
    assert datetime.fromtimestamp(dec31).year == 2026, "Dec 31 read on Jan 1 is last year"
    assert parse_log_line_timestamp("no timestamp here")[0] is None
    print("Test 0c (journal microseconds, JSON message forms, ISO with offsets/Z, syslog year rollover, no invented time) PASSED")


async def test_realtime_and_delayed():
    get_ssh_metrics().reset()
    mon, pub = make_monitor()
    now = time.time()
    mon._process_line(accepted(), event_time=now - 0.4, pid=100)
    mon._process_line(LOGOUT.format(user="newusproud"), event_time=now - 0.1, pid=100)
    pub = raw(pub)
    assert [e.category for e in pub] == [EventCategory.SSH_AUTH, EventCategory.SSH_LOGOUT]
    assert all(e.metadata["event_timing_status"] == REALTIME for e in pub)
    assert abs(pub[0].timestamp - (now - 0.4)) < 1e-6, "event.timestamp IS the source event time"
    assert pub[0].metadata["observed_time"] >= pub[0].metadata["event_time"]
    print("Test 1 (realtime AUTH + LOGOUT: REALTIME, timestamp = source event time, observed kept separate) PASSED")

    mon, pub = make_monitor()
    old = time.time() - 333
    mon._process_line(accepted(port=40001), event_time=old, pid=7, source="journal")
    mon._process_line(LOGOUT.format(user="newusproud"), event_time=old + 20, pid=7, source="journal")
    login, logout = raw(pub)
    assert login.metadata["event_timing_status"] == STALE and abs(login.metadata["event_delay_seconds"] - 333) < 2
    assert login.metadata["notify_discord"] is False, "a trusted user's old, normal login is stored, not announced"
    assert logout.metadata["notify_discord"] is False
    assert "SUPPRESSED" in login.metadata["ssh_notification_decision"]
    assert abs(login.timestamp - old) < 1e-6 and abs(logout.timestamp - (old + 20)) < 1e-6
    print("Test 2a (5-minute-old normal login+logout: STALE, event time preserved, stored -- never a 'new' Discord alert) PASSED")

    mon, pub = make_monitor()
    mon._process_line(accepted(user="intruder", ip="203.0.113.50"), event_time=time.time() - 400, pid=8)
    ev = pub[0]
    assert ev.metadata.get("notify_discord") is not False and ev.metadata["delayed_security_event"] is True
    assert "Delayed Security Event" in ev.message and "terlambat" in ev.message
    assert ev.severity == Severity.CRITICAL
    print("Test 2b (old login by an UNTRUSTED user is still notified, labelled Delayed Security Event) PASSED")


async def test_restart_and_overlap():
    tmp = tempfile.mkdtemp()
    state = os.path.join(tmp, "ssh_state.json")
    mon, pub = make_monitor(state_path=state)
    t0 = time.time() - 900
    mon._process_line(accepted(port=1111), event_time=t0, pid=11, cursor="s=1;i=1", source="journal")
    mon._process_line(LOGOUT.format(user="newusproud"), event_time=t0 + 60, pid=11, cursor="s=1;i=2", source="journal")
    assert len(raw(pub)) == 2 and mon._reader_state.journal_cursor == "s=1;i=2"
    mon._save_state(force=True)
    assert os.path.exists(state)

    mon2, pub2 = make_monitor(state_path=state)
    mon2._load_state()
    assert mon2._reader_state.journal_cursor == "s=1;i=2" and len(mon2._ledger) == 2
    assert "--after-cursor=s=1;i=2" in mon2._journal_command(), "the reader resumes from the saved cursor"
    mon2._process_line(accepted(port=1111), event_time=t0, pid=11, cursor="s=1;i=1", source="journal")
    mon2._process_line(LOGOUT.format(user="newusproud"), event_time=t0 + 60, pid=11, cursor="s=1;i=2", source="journal")
    assert pub2 == [], "RTSA restart: already-processed SSH_AUTH / SSH_LOGOUT are not re-published or re-notified"
    mon2._process_line(accepted(port=2222), event_time=time.time() - 1, pid=12, cursor="s=1;i=3", source="journal")
    assert len(raw(pub2)) == 1 and raw(pub2)[0].metadata["event_timing_status"] == REALTIME
    print("Test 3 (restart: cursor + ledger survive, replayed lines produce nothing, a genuinely new login still does) PASSED")

    mon3, pub3 = make_monitor()
    now = time.time()
    for _ in range(3):
        mon3._process_line(accepted(port=3333), event_time=now - 2, pid=13, cursor="s=2;i=9", source="journal")
    assert len(raw(pub3)) == 1 and mon3._duplicate_lines_suppressed_total == 2
    assert get_ssh_metrics().snapshot()["counters"]["ssh_events_duplicate_total"] >= 2
    same_second = [accepted(port=4000 + i) for i in range(5)]
    for i, line in enumerate(same_second):
        mon3._process_line(line, event_time=now - 1, pid=20 + i)
    assert len(raw(pub3)) == 6, "five DIFFERENT events inside the same second are all kept"
    print("Test 4 (poll overlap: the same journal entry three times = one logical event; same-second distinct events kept) PASSED")

    mon4, pub4 = make_monitor()
    top = time.time() - 10
    mon4._process_line(accepted(port=5001), event_time=top, pid=30, cursor="c1")
    mon4._process_line(accepted(port=5002), event_time=top - 600, pid=31, cursor="c2")
    pub4 = raw(pub4)
    assert pub4[1].metadata["event_timing_status"] == REPLAYED, "an entry far behind what was already read is a replay"
    assert pub4[1].metadata["notify_discord"] is False
    print("Test 5a (an entry 10 minutes behind the newest one already read = REPLAYED, state only, no notification) PASSED")

    mon5, pub5 = make_monitor()
    mon5._process_line("some unrelated sshd noise", event_time=time.time())
    mon5._process_line("", event_time=time.time())
    assert pub5 == []
    orig = mon5._process_line_inner

    def boom(line):
        raise RuntimeError("poison")

    mon5._process_line_inner = boom
    mon5._process_line(accepted(), event_time=time.time(), cursor="c9")
    assert mon5._line_errors_total == 1 and mon5._reader_state.journal_cursor == "c9", \
        "a poison line is counted and skipped; the cursor moves on instead of wedging the reader"
    mon5._process_line_inner = orig
    print("Test 5b (poison line: isolated, counted, cursor advances -- no infinite restart loop) PASSED")


async def test_reader_commands():
    mon, _ = make_monitor()
    cmd = mon._journal_command()
    assert "-o" in cmd and "json" in cmd and "-n" in cmd and "0" in cmd, "no saved cursor: start at the tail, never replay history"
    assert not any(part.startswith("--after-cursor") for part in cmd)
    mon._reader_state.journal_cursor = "s=x"
    cmd = mon._journal_command()
    assert "--after-cursor=s=x" in cmd and "-n" not in cmd
    legacy, _ = make_monitor(journal_output_json=False)
    assert "cat" in legacy._journal_command()
    print("Test 6a (journalctl command: JSON output keeps time+cursor; cursor resume vs tail start; legacy cat still available) PASSED")

    class FakeStdout:
        def __init__(self, lines):
            self.lines = list(lines)

        async def readline(self):
            return self.lines.pop(0) if self.lines else b""

    class FakeProc:
        def __init__(self, lines):
            self.stdout = FakeStdout(lines)

        def kill(self):
            pass

    mon, pub = make_monitor()
    entries = [
        json.dumps({"MESSAGE": accepted(port=7001), "__REALTIME_TIMESTAMP": str(int((time.time() - 1) * 1e6)),
                    "__CURSOR": "s=1;i=1", "_PID": "50"}).encode() + b"\n",
        b"plain non-json line\n",
        json.dumps({"MESSAGE": LOGOUT.format(user="newusproud"), "__REALTIME_TIMESTAMP": str(int(time.time() * 1e6)),
                    "__CURSOR": "s=1;i=2", "_PID": "50"}).encode() + b"\n",
    ]
    calls = {"n": 0}

    async def fake_exec(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeProc(entries)
        raise asyncio.CancelledError()

    async def fake_sleep(seconds):
        return None

    original_exec, original_sleep = asyncio.create_subprocess_exec, asyncio.sleep
    asyncio.create_subprocess_exec, asyncio.sleep = fake_exec, fake_sleep
    try:
        try:
            await mon._stream_journald()
        except asyncio.CancelledError:
            pass
    finally:
        asyncio.create_subprocess_exec, asyncio.sleep = original_exec, original_sleep
    pub = raw(pub)
    assert [e.category for e in pub] == [EventCategory.SSH_AUTH, EventCategory.SSH_LOGOUT]
    assert pub[0].metadata["ssh_source_pid"] == 50 and pub[0].metadata["event_timing_status"] == REALTIME
    assert mon._reader_state.journal_cursor == "s=1;i=2"
    print("Test 6b (journald stream: JSON entries carry time/pid/cursor, plain lines still work, cursor advances after processing) PASSED")

    mon, _ = make_monitor()
    mon._reader_state.journal_cursor = "s=stale"
    seen_cmds = []

    async def fake_exec2(*args, **kwargs):
        seen_cmds.append(list(args))
        if len(seen_cmds) >= 4:
            raise asyncio.CancelledError()
        return FakeProc([])

    asyncio.create_subprocess_exec, asyncio.sleep = fake_exec2, fake_sleep
    try:
        try:
            await mon._stream_journald()
        except asyncio.CancelledError:
            pass
    finally:
        asyncio.create_subprocess_exec, asyncio.sleep = original_exec, original_sleep
    assert any("--after-cursor=s=stale" in c for c in seen_cmds[:2])
    assert mon._reader_state.journal_cursor is None and "-n" in seen_cmds[-1], \
        "a cursor journalctl keeps rejecting is dropped and the reader falls back to the tail (no replay, no busy loop)"
    print("Test 6c (invalid saved cursor: dropped after repeated rejection, tail start, no replay) PASSED")


async def test_auth_log_reader_offsets_and_rotation():
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "auth.log")
    state = os.path.join(tmp, "state.json")
    stamp = lambda offset: datetime.fromtimestamp(time.time() - offset).strftime("%b %e %H:%M:%S")
    with open(path, "w") as fh:
        fh.write(f"{stamp(400)} host sshd[9]: {accepted(port=8001)}\n")
    mon, pub = make_monitor(state_path=state, auth_log_path=path, use_journald=False)
    task = asyncio.create_task(mon._tail_auth_log())
    await asyncio.sleep(0.8)
    assert pub == [], "a first start never replays what is already in the file"
    with open(path, "a") as fh:
        fh.write(f"{stamp(300)} host sshd[9]: {accepted(port=8002)}\n")
    await asyncio.sleep(1.2)
    assert len(pub) == 1 and pub[0].metadata["event_timing_status"] in (STALE, DELAYED)
    assert abs(pub[0].timestamp - (time.time() - 300)) < 5, "the line's own timestamp is the event time"
    assert pub[0].metadata["ssh_source_pid"] == 9
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    mon._save_state(force=True)

    with open(path, "a") as fh:
        fh.write(f"{stamp(200)} host sshd[9]: {accepted(port=8003)}\n")
    mon2, pub2 = make_monitor(state_path=state, auth_log_path=path, use_journald=False)
    mon2._load_state()
    task = asyncio.create_task(mon2._tail_auth_log())
    await asyncio.sleep(1.2)
    assert [e.metadata.get("source_port") for e in pub2] == [8003], \
        "restart resumes at the saved offset: only the line written while RTSA was down, nothing twice"
    os.rename(path, path + ".1")
    with open(path, "w") as fh:
        fh.write(f"{stamp(1)} host sshd[9]: {accepted(port=8004)}\n")
    await asyncio.sleep(1.5)
    assert [e.metadata.get("source_port") for e in pub2] == [8003, 8004]
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    print("Test 7 (auth.log: own timestamps, persisted inode+offset resume, rotation without duplicates) PASSED")


async def test_queue_delay_and_dispatcher_display():
    get_ssh_metrics().reset()
    bus = EventBus()
    seen = []

    async def slow(event):
        await asyncio.sleep(0)
        seen.append(current_queue_wait_ms.get())

    sub = await bus.subscribe("probe", slow)
    gate = asyncio.Event()

    async def blocker(event):
        await gate.wait()

    await bus.subscribe("blocker", blocker)
    ev = SSHEvent(source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.LOW, message="x",
                  raw="", username="u", source_ip="1.1.1.1", auth_method="publickey", success=True, metadata={})
    bus.publish_nowait(ev)
    await asyncio.sleep(0.6)
    assert seen and seen[0] < 300
    stats = sub.stats
    assert "oldest_age_seconds" in stats and "max_queue_wait_ms" in stats
    blocked = bus.subscriber_stats["blocker"]
    assert blocked["queue_size"] == 0 or blocked["oldest_age_seconds"] >= 0
    gate.set()
    await bus.shutdown()

    bus2 = EventBus()
    order = []
    gate2 = asyncio.Event()

    async def held(event):
        if not order:
            order.append("first")
            await gate2.wait()
        else:
            order.append(current_queue_wait_ms.get())

    await bus2.subscribe("held", held)
    bus2.publish_nowait(ev)
    await asyncio.sleep(0.05)
    bus2.publish_nowait(SSHEvent(source_module="ssh_monitor", category=EventCategory.SSH_LOGOUT, severity=Severity.INFO,
                                 message="y", raw="", metadata={}))
    await asyncio.sleep(0.8)
    behind = bus2.subscriber_stats["held"]
    assert behind["oldest_age_seconds"] >= 0.7, f"queue backlog is visible before it drains: {behind}"
    gate2.set()
    await asyncio.sleep(0.2)
    assert order[1] >= 700, f"the delayed event knows how long it waited: {order}"
    await bus2.shutdown()
    print("Test 8 (queue delay is measurable: oldest entry age while backed up, wait time delivered to the handler) PASSED")

    d = DiscordWebhookDispatcher(EventBus(), DiscordConfig(alert_channel_id=1))
    sent = []

    class Bot:
        def is_ready(self):
            return True

    async def send(payload, **kw):
        sent.append(payload)
        return ("OK", 1, 2)

    d._bot, d._send_via_bot = Bot(), send
    mon, pub = make_monitor()
    mon._process_line(accepted(user="intruder", ip="203.0.113.60"), event_time=time.time() - 333, pid=60)
    await d._on_event(pub[0])
    assert len(sent) == 1
    payload = sent[0]
    embed = payload["embeds"][0]
    names = {f["name"]: f["value"] for f in embed["fields"]}
    for required in ("Event Time", "RTSA Observed", "Processed", "Notified", "Event Delay", "Event Status"):
        assert required in names, (required, sorted(names))
    assert names["Event Status"] == "STALE" and names["Event Delay"].startswith("5m 3")
    assert embed["title"].startswith("⏱ Delayed Security Event"), embed["title"]
    stamped = d._stamp_notified_time(payload)
    stamped_names = {f["name"]: f["value"] for f in stamped["embeds"][0]["fields"]}
    assert "{{" not in stamped_names["Notified"] and "WIB" in stamped_names["Notified"]
    print("Test 9 (Discord shows Event Time / Observed / Processed / Notified / Delay / Status; title says Delayed Security Event) PASSED")

    mon, pub = make_monitor()
    mon._process_line(accepted(port=9101), event_time=time.time() - 0.3, pid=61)
    fresh = d._build_payload(pub[0])
    d2names = [f["name"] for f in d._apply_gate_context(fresh, pub[0], d._gate_decision(pub[0]))["embeds"][0]["fields"]]
    assert "Event Time" in d2names and "Event Delay" in d2names and "RTSA Observed" not in d2names, \
        "realtime alerts stay compact"
    text = explain_event_timing("SSH_AUTH", pub[0].metadata, pub[0].timestamp)
    assert "Event Status: REALTIME" in text and "Notification: SENT" in text
    stale_text = explain_event_timing(
        "SSH_AUTH", {**pub[0].metadata, "event_timing_status": "REPLAYED", "ssh_notification_decision": "SUPPRESSED: replay",
                     "ssh_notification_reason": "replay"}, pub[0].timestamp)
    assert "Replay: YES" in stale_text and "Notification: SUPPRESSED" in stale_text
    print("Test 10 (realtime alerts stay compact; /explain answers 'why notified now': status, replay, duplicate, decision) PASSED")


async def test_analyzer_event_time():
    class CaptureBus:
        def __init__(self):
            self.alerts = []

        async def publish(self, event):
            self.alerts.append(event)

    def failure(ts, ip="94.10.0.1", user="root"):
        return SSHEvent(source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.INFO,
                        message="fail", raw="", username=user, source_ip=ip, auth_method="password", success=False,
                        timestamp=ts, metadata={"username_status": "EXISTING_USER"})

    def success(ts, ip="94.10.0.1", user="newusproud", **meta):
        return SSHEvent(source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.LOW,
                        message="ok", raw="", username=user, source_ip=ip, auth_method="publickey", success=True,
                        timestamp=ts, metadata=meta)

    bus = CaptureBus()
    an = StatefulAnalyzer(bus, ssh_brute_force_threshold=5, ssh_brute_force_window_seconds=60)
    base = time.time() - 600
    for i in range(25):
        await an._on_event(failure(base + i * 0.4, user=f"u{i % 5}"))
    trigger = success(base + 12, event_timing_status="STALE", event_time=base + 12, observed_time=time.time(),
                      event_delay_seconds=588.0, event_late=True)
    await an._on_event(trigger)
    red = [a for a in bus.alerts if a.category == EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE]
    assert len(red) == 1 and red[0].severity == Severity.CRITICAL, \
        "brute force -> success is still a security escalation when everything is observed 10 minutes late"
    assert red[0].metadata["successful_login_at"] == base + 12
    assert red[0].metadata["event_timing_status"] == "STALE" and red[0].metadata["delayed_security_event"] is True
    print("Test 11 (25 failures + success observed 10 minutes late -> RED ZONE escalation on event time, labelled delayed) PASSED")

    bus = CaptureBus()
    an = StatefulAnalyzer(bus, ssh_brute_force_threshold=3, ssh_brute_force_window_seconds=60)
    t0 = time.time() - 5
    for i in range(3):
        await an._on_event(failure(t0 + 30 + i))
    await an._on_event(success(t0 + 0))
    assert not [a for a in bus.alerts if a.category == EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE], \
        "out of order: failures that happened AFTER the login are not its precursor"
    await an._on_event(success(t0 + 40, ip="94.10.0.1"))
    assert [a for a in bus.alerts if a.category == EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE], \
        "the login that really followed the failures is correlated regardless of processing order"
    print("Test 12 (out-of-order events correlate by event time, not by processing order) PASSED")


async def main():
    test_timing_model()
    await test_realtime_and_delayed()
    await test_restart_and_overlap()
    await test_reader_commands()
    await test_auth_log_reader_offsets_and_rotation()
    await test_queue_delay_and_dispatcher_display()
    await test_analyzer_event_time()
    print("\nALL SSH EVENT TIMING / REPLAY TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
