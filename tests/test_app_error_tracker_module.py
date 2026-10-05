from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _app_error_fakes import Clock, config, counters
from config.manager import (
    AppErrorBudgetConfig, AppErrorCollectionConfig, AppErrorLogSourceConfig, AppErrorResourceConfig, AppErrorStorageConfig, AppErrorStormConfig,
    DiscordConfig, OutboundBackpressureConfig,
)
from core import app_error_engine as eng
from core.datatypes import BaseEvent, EventCategory, Severity, SSHEvent
from core.event_bus import EventBus
from core.pipeline_metrics import get_app_error_metrics
from core.pm2_snapshot_cache import get_pm2_snapshot_cache
from database import app_error_store
from database.sqlite_pool import SQLiteWriteWorker
from discord_integration.webhook import DiscordWebhookDispatcher
from modules import application_error_tracker as tracker_module
from modules.application_error_tracker import ApplicationErrorTracker

SECRET = "hunter2hunter2"
FRESH = "2026-10-04T10:00:00Z"


BUSES = []


class Capture:
    def __init__(self, bus):
        self.bus = bus
        self.events = []
        BUSES.append(bus)

    async def start(self):
        await self.bus.subscribe("capture", self._on, categories=None)

    async def _on(self, event):
        self.events.append(event)

    def of(self, category, record=None):
        return [e for e in self.events if e.category == category and (record is None or e.metadata.get("record") == record)]


def err_block(message="Cannot read properties of undefined (reading 'id')", etype="TypeError", frame="getUser (/home/u/htdocs/disdik.example.com/src/users.js:42:17)", stamp=None):
    head = f"{stamp or time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())}Z: " if stamp != "" else ""
    return f"{head}{etype}: {message}\n    at {frame}\n    at next (/home/u/htdocs/disdik.example.com/node_modules/express/lib/router/route.js:137:13)\n"


async def make_tracker(tmp, *, db_worker=None, clock=None, **sections):
    sections.setdefault("storage", AppErrorStorageConfig(state_path=os.path.join(tmp, "state.json")))
    sections.setdefault("collection", AppErrorCollectionConfig(poll_interval_seconds=1.0))
    bus = EventBus()
    capture = Capture(bus)
    await capture.start()
    tracker = ApplicationErrorTracker(bus, config(**sections))
    clock = clock or Clock(time.time())
    tracker._clock = clock
    tracker.engine._clock = clock
    if db_worker is not None:
        tracker.attach_db_worker(db_worker)
    await tracker._subscribe()
    return tracker, bus, capture, clock


async def settle():
    await asyncio.sleep(0.15)


async def pump(tracker, clock, rounds=2):
    result = None
    for _ in range(rounds):
        result = await tracker.cycle()
        clock.advance(3)
    return result


def write(path, text, mode="a"):
    with open(path, mode, encoding="utf-8") as handle:
        handle.write(text)


async def test_1_incremental_tailing_cursors_rotation_and_bounds() -> None:
    tmp = tempfile.mkdtemp(prefix="rtsa-app-")
    log = os.path.join(tmp, "app.log")
    write(log, err_block("old error before RTSA started", "OldError"), "w")
    tracker, bus, capture, clock = await make_tracker(tmp, collection=AppErrorCollectionConfig(poll_interval_seconds=1.0, max_bytes_per_cycle=65536, max_bytes_per_file_per_cycle=16384))
    tracker.register_source(AppErrorLogSourceConfig(path=log, project="disdik", domain="disdik.example.com", service="api"))
    first = await tracker.cycle()
    assert first["produced"] == 0 and tracker.engine.incidents() == [], "a newly discovered log starts at its end: old content is never replayed"
    write(log, err_block("first", "TypeError")[:40])
    await tracker.cycle()
    assert tracker.engine.incidents() == [], "a partial line is carried over, not parsed"
    write(log, err_block("first", "TypeError")[40:])
    write(log, err_block("first", "TypeError"))
    await pump(tracker, clock)
    incident = tracker.engine.incidents()[0]
    assert incident.occurrence_count == 2 and incident.project == "disdik" and incident.domain == "disdik.example.com" and incident.error_type == "TypeError"
    before = get_app_error_metrics().snapshot()["counters"]["application_log_bytes_read_total"]
    await tracker.cycle()
    assert get_app_error_metrics().snapshot()["counters"]["application_log_bytes_read_total"] == before, "nothing is re-read when nothing changed"
    os.rename(log, log + ".1")
    write(log, err_block("after rotation", "RangeError"), "w")
    await pump(tracker, clock)
    assert {i.error_type for i in tracker.engine.incidents()} == {"TypeError", "RangeError"}, "rotation: the new file is read from its start"
    write(log, "truncated\n", "w")
    await tracker.cycle()
    write(log, err_block("after truncate", "SyntaxError"))
    await pump(tracker, clock)
    assert "SyntaxError" in {i.error_type for i in tracker.engine.incidents()}
    big = os.path.join(tmp, "big.log")
    tracker.register_source(AppErrorLogSourceConfig(path=big, project="big", domain="big.example.com"))
    write(big, "", "w")
    await tracker.cycle()
    write(big, "".join(f"noise line {i}\n" for i in range(5000)))
    reads = []
    for _ in range(3):
        start = get_app_error_metrics().snapshot()["counters"]["application_log_bytes_read_total"]
        await tracker.cycle()
        reads.append(get_app_error_metrics().snapshot()["counters"]["application_log_bytes_read_total"] - start)
    assert all(r <= 16384 for r in reads), reads
    assert os.path.getsize(big) > 16384 * 3, "the test file is larger than what was read in three cycles"
    await tracker._save_state_for_test() if hasattr(tracker, "_save_state_for_test") else tracker._save_state()
    restarted, bus2, capture2, clock2 = await make_tracker(tmp, collection=AppErrorCollectionConfig(poll_interval_seconds=1.0))
    restarted._load_state()
    assert os.path.realpath(log) in {os.path.realpath(p) for p in restarted._sources}
    await restarted.cycle()
    assert restarted.engine.incidents() == [], "after a restart the saved cursor resumes: no replay storm"
    write(log, err_block("after restart", "EvalError"))
    await pump(restarted, clock2)
    assert [i.error_type for i in restarted.engine.incidents()] == ["EvalError"]
    many = ApplicationErrorTracker(EventBus(), config(collection=AppErrorCollectionConfig(max_files=3)))
    for i in range(10):
        if len(many._sources) < 3:
            many.register_source(AppErrorLogSourceConfig(path=os.path.join(tmp, f"n{i}.log"), project=f"n{i}"))
    assert len(many._sources) == 3
    shutil.rmtree(tmp, ignore_errors=True)
    print("Test 1 (tailing: new logs start at the end, partial lines carried, no re-read, rotation and truncation handled, per-file byte budget, cursors survive a restart, file count bounded) PASSED")


async def test_2_pm2_discovery_uses_only_safe_logs_of_the_owning_user() -> None:
    tmp = tempfile.mkdtemp(prefix="rtsa-app-pm2-")
    home = os.path.join(tmp, "home", "alice")
    project = os.path.join(home, "htdocs", "disdik.example.com")
    os.makedirs(os.path.join(home, "logs"))
    os.makedirs(project)
    err = os.path.join(home, "logs", "api-error.log")
    out = os.path.join(home, "logs", "api-out.log")
    write(err, "", "w")
    write(out, "", "w")
    secret = os.path.join(tmp, "shadow-like")
    write(secret, f"root:{SECRET}:19000\n", "w")
    link = os.path.join(home, "logs", "evil.log")
    os.symlink(secret, link)
    other = os.path.join(tmp, "elsewhere.log")
    write(other, "", "w")
    me = os.getuid()
    real_getpwnam = tracker_module.pwd.getpwnam

    def fake_getpwnam(name):
        if name == "alice":
            return SimpleNamespace(pw_dir=home, pw_uid=me)
        if name == "mallory":
            return SimpleNamespace(pw_dir=home, pw_uid=me + 12345)
        raise KeyError(name)

    tracker_module.pwd.getpwnam = fake_getpwnam
    try:
        assert tracker_module.safe_user_log_path(err, "alice") == os.path.realpath(err)
        assert tracker_module.safe_user_log_path(link, "alice") is None, "a symlink to a file outside the home is refused"
        assert tracker_module.safe_user_log_path(other, "alice") is None, "a log outside the user's home is refused"
        assert tracker_module.safe_user_log_path(err, "mallory") is None, "a file the user does not own is refused"
        assert tracker_module.safe_user_log_path(err, "nobody-here") is None and tracker_module.safe_user_log_path("relative.log", "alice") is None
        cache = get_pm2_snapshot_cache()
        cache.reset_for_tests()
        processes = []
        for index, path in enumerate((err, link, other)):
            processes.append({"name": "api", "pid": 4000 + index, "pm_id": index, "pm2_env": {
                "status": "online", "pm_cwd": project, "pm_err_log_path": path, "pm_out_log_path": out, "restart_time": 2, "instances": 1,
                "env": {"DATABASE_URL": f"postgres://u:{SECRET}@h/db"},
            }})
        cache.store("alice", processes)
        tracker, bus, capture, clock = await make_tracker(tmp)
        tracker._refresh_pm2_sources(clock.t)
        paths = set(tracker._sources)
        assert paths == {os.path.realpath(err)}, paths
        src = tracker._sources[os.path.realpath(err)]
        assert src.project == "alice" and src.domain == "" and src.pm2_app == "api" and src.linux_user == "alice", "outside /home/<user>/htdocs/<domain> the project is the Linux user"
        assert tracker_module.project_from_cwd("/home/alice/htdocs/disdik.example.com/app", "alice", "api") == ("disdik.example.com", "disdik.example.com")
        assert tracker_module.project_from_cwd("/srv/app", "", "api") == ("api", "")
        assert out not in paths, "PM2 stdout logs are not read"
        assert SECRET not in json.dumps({p: s.__dict__ for p, s in tracker._sources.items()}, default=str)
        await tracker.cycle()
        write(err, err_block("db down", "Error", "q (/home/alice/htdocs/disdik.example.com/db.js:1:1)").replace("Error: db down", "Error: connect ECONNREFUSED 10.0.0.5:5432"))
        write(err, err_block("db down", "Error").replace("Error: db down", "Error: connect ECONNREFUSED 10.0.0.5:5432"))
        clock.advance(5)
        await pump(tracker, clock)
        assert tracker.engine.incidents()[0].error_class == "DATABASE"
        cache.store("alice", [dict(processes[0], pm2_env=dict(processes[0]["pm2_env"], restart_time=5))])
        tracker._refresh_pm2_sources(clock.t)
        minutes = tracker.engine._servers[tracker.server].minutes
        assert sum(m.restarts for m in minutes) == 3, "a PM2 restart-count increase becomes a restart signal"
        cache.reset_for_tests()
    finally:
        tracker_module.pwd.getpwnam = real_getpwnam
        shutil.rmtree(tmp, ignore_errors=True)
    print("Test 2 (PM2 error logs are discovered from the existing snapshot cache but only when they are regular files in the owning user's home; symlinks, foreign paths and other owners are refused; stdout and environments are never read) PASSED")


async def test_3_end_to_end_notification_and_sampled_raw_evidence() -> None:
    tmp = tempfile.mkdtemp(prefix="rtsa-app-e2e-")
    log = os.path.join(tmp, "app.log")
    write(log, "", "w")
    tracker, bus, capture, clock = await make_tracker(tmp)
    tracker.register_source(AppErrorLogSourceConfig(path=log, project="disdik", domain="disdik.example.com", service="api", environment="production"))
    await tracker.cycle()
    for _ in range(40):
        write(log, err_block(f"Cannot read properties of undefined (reading 'id') token={SECRET}"))
    clock.advance(1)
    await pump(tracker, clock)
    await settle()
    notices = capture.of(EventCategory.APPLICATION_ERROR, "NOTIFICATION")
    assert len(notices) == 1 and notices[0].metadata["notification_kind"] == "INITIAL" and notices[0].metadata["notify_discord"] is True
    incident = notices[0].metadata["incident"]
    assert incident["project"] == "disdik" and incident["occurrence_count"] >= 39 and incident["service"] == "api" and incident["environment"] == "production"
    assert SECRET not in json.dumps(notices[0].metadata, default=str) and SECRET not in notices[0].message
    samples = capture.of(EventCategory.APPLICATION_ERROR, "SAMPLE")
    assert 1 <= len(samples) <= tracker.cfg.storage.sample_max_per_incident and all(s.metadata["notify_discord"] is False for s in samples)
    assert SECRET not in json.dumps([s.metadata for s in samples], default=str)
    sample = samples[0].metadata
    for key in ("event_id", "event_time", "observed_at", "processed_at", "server", "hostname", "server_identity", "project", "domain", "environment", "service", "error_type",
                "error_message", "stack_trace", "source", "source_log", "fingerprint", "timing_status", "occurrence_count"):
        assert key in sample, key
    assert sample["source"] == "STRUCTURED_LOG" and sample["event_time"] is not None and sample["processed_at"] >= sample["observed_at"]
    assert tracker.engine.incidents()[0].occurrence_count == 40, "the last block of a batch is parsed on the next cycle: nothing is lost"
    for _ in range(300):
        write(log, err_block("again"))
        clock.advance(3)
        await tracker.cycle()
    await settle()
    assert len(capture.of(EventCategory.APPLICATION_ERROR, "SAMPLE")) <= tracker.cfg.storage.sample_max_per_incident * 2, "raw samples are bounded per incident"
    assert len(capture.of(EventCategory.APPLICATION_ERROR, "NOTIFICATION")) <= 3
    health = await tracker.health()
    assert health["sources"] == 1 and health["engine"]["incidents_tracked"] >= 1 and health["queue_depth"] == 0
    shutil.rmtree(tmp, ignore_errors=True)
    print("Test 3 (log lines -> normalized events -> one incident -> one INITIAL notification with project/domain/service/environment; secrets redacted; raw samples stored raw-only (notify_discord=False) and bounded) PASSED")


async def test_4_nginx_5xx_pm2_and_deployment_context() -> None:
    tmp = tempfile.mkdtemp(prefix="rtsa-app-ctx-")
    log = os.path.join(tmp, "app.log")
    write(log, "", "w")
    tracker, bus, capture, clock = await make_tracker(tmp)
    tracker.register_source(AppErrorLogSourceConfig(path=log, project="disdik", domain="disdik.example.com", service="api"))
    await tracker.cycle()
    now = clock.t
    tracker.handle_context_event(BaseEvent(source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE, severity=Severity.MEDIUM, message="x", raw="",
                                           metadata={"path": "/home/u/htdocs/disdik.example.com/dist/app.js", "change_type": "modified", "domain": "disdik.example.com"}, timestamp=now - 90))
    tracker.handle_context_event(BaseEvent(source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE, severity=Severity.MEDIUM, message="x", raw="",
                                           metadata={"path": "/home/o/htdocs/other.example.com/x.js", "change_type": "modified", "domain": "other.example.com"}, timestamp=now - 80))
    tracker.handle_context_event(BaseEvent(source_module="nginx_monitor", category=EventCategory.NGINX_ERROR_SPIKE, severity=Severity.HIGH, message="x", raw="",
                                           metadata={"status_counts": {"404": 900, "444": 5000, "500": 3, "502": 40}, "domain_counts": {"disdik.example.com": 44}}, timestamp=now - 30))
    tracker.handle_context_event(BaseEvent(source_module="health_monitor", category=EventCategory.HEALTH_STATUS, severity=Severity.HIGH, message="x", raw="",
                                           metadata={"resource": "CPU", "value": 97.0, "state": "HIGH"}, timestamp=now - 20))
    tracker.handle_context_event(BaseEvent(source_module="health_monitor", category=EventCategory.HEALTH_STATUS, severity=Severity.INFO, message="x", raw="",
                                           metadata={"resource": "Disk", "value": 40.0, "state": "NORMAL"}, timestamp=now - 20))
    minutes = tracker.engine._servers[tracker.server].minutes
    assert sum(m.http5xx for m in minutes) == 43, "404/444 are never counted as backend failures; 500+502 are"
    for _ in range(3):
        write(log, err_block("upstream failed", "Error"))
    clock.advance(1)
    await pump(tracker, clock)
    await settle()
    notice = capture.of(EventCategory.APPLICATION_ERROR, "NOTIFICATION")[0].metadata["incident"]
    types = {r["type"] for r in notice["correlation"]["refs"]}
    assert {"FIM_CHANGE", "NGINX_ERROR_SPIKE", "CPU_HIGH"} <= types and "DISK_PRESSURE" not in types, types
    refs = notice["correlation"]["refs"]
    assert all("other.example.com" not in json.dumps(r) for r in refs), "another project's change is not correlated"
    assert notice["correlation"]["possible_contributing_change"]["type"] == "FIM_CHANGE" and "not a proven root cause" in notice["correlation"]["note"]
    inc = tracker.engine.incidents()[0]
    clock.advance(200)
    tracker.handle_context_event(BaseEvent(source_module="pm2_monitor", category=EventCategory.SERVICE_DOWN, severity=Severity.HIGH, message="x", raw="",
                                           metadata={"process_name": "api", "status": "errored", "linux_user": "u", "domains": ["disdik.example.com"]}, timestamp=clock.t))
    assert sum(m.crashes for m in tracker.engine._servers[tracker.server].minutes) == 1
    clock.advance(110)
    tracker.engine.tick(clock.t)
    assert inc.state in eng.ACTIVE_STATES, "a PM2 crash keeps the project from being declared recovered although the log went quiet 310 s ago"
    clock.advance(200)
    tracker.engine.tick(clock.t)
    assert inc.state == eng.ST_RECOVERING
    tracker.handle_context_event(BaseEvent(source_module="x", category=EventCategory.SSH_AUTH, severity=Severity.INFO, message="x", raw="", metadata={"user": "alice"}, timestamp=clock.t))
    assert not any(c["type"] == "SSH_ACTION" and clock.t - c["at"] < 1 for c in tracker.engine._context), "failed or non-success SSH events are not actions"
    shutil.rmtree(tmp, ignore_errors=True)
    print("Test 4 (Nginx 404/444 never count as backend outage, 5xx do; same-project FIM/CPU/5xx context correlates, another project's change does not; PM2 crash blocks recovery) PASSED")


class FakeMessage:
    _next = 70000

    def __init__(self, channel=None):
        FakeMessage._next += 1
        self.id = FakeMessage._next
        self.channel = channel

    async def edit(self, content=None, embeds=None, view=None):
        return None


class FakeChannel:
    id = 999111

    def __init__(self):
        self.sent = []

    async def send(self, content=None, embeds=None, view=None):
        self.sent.append((content, embeds))
        return FakeMessage(self)

    async def fetch_message(self, message_id):
        return FakeMessage(self)


class FakeBot:
    def __init__(self, channel, ready=True):
        self.channel = channel
        self.ready = ready

    def is_ready(self):
        return self.ready

    def get_channel(self, cid):
        return self.channel


def make_dispatcher(channel, ready=True, **overrides):
    outbound = OutboundBackpressureConfig(**overrides)
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig(alert_channel_id=999111, outbound=outbound))
    dispatcher.set_bot(FakeBot(channel, ready))
    return dispatcher


def embed_dict(embed):
    return embed.to_dict() if hasattr(embed, "to_dict") else embed


def sent_embeds(channel):
    return [embed_dict(embeds[0]) for _content, embeds in channel.sent]


def titles(channel):
    return [e["title"] for e in sent_embeds(channel)]


def field_map(embed):
    return {f["name"]: f["value"] for f in embed["fields"]}


async def test_5_discord_payloads_and_a_storm_plus_a_security_alert() -> None:
    tmp = tempfile.mkdtemp(prefix="rtsa-app-discord-")
    tracker, bus, capture, clock = await make_tracker(tmp)
    channel = FakeChannel()
    dispatcher = make_dispatcher(channel, dedup_window_seconds=60.0)
    published = []
    tracker.publish = lambda event: published.append(event)
    for project in range(30):
        for _ in range(25):
            clock.advance(0.01)
            tracker.ingest_event(__import__("_app_error_fakes").make_event(clock, project=f"app{project:02d}", message=f"boom token={SECRET}", error_type="Error",
                                                                          error_class="UNHANDLED", frames=["    at run (/home/u/htdocs/app.example.com/run.js:1:1)"],
                                                                          stack_trace=f"Error: boom\n    at run (/a/b.js:1:1) password={SECRET}"))
        clock.advance(0.5)
    tracker._publish_notes(tracker.engine.tick(clock.t))
    notifications = [e for e in published if e.metadata.get("record") in ("NOTIFICATION", "DIGEST")]
    intrusion = SSHEvent(source_module="ssh_monitor", category=EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE, severity=Severity.CRITICAL, message="login after brute force from 203.0.113.9",
                         raw="", metadata={"source_ip": "203.0.113.9", "username": "root"}, username="root", source_ip="203.0.113.9", success=True)
    unknown_key = BaseEvent(source_module="ssh_monitor", category=EventCategory.SSH_KEY_CHANGE, severity=Severity.HIGH, message="unknown key added", raw="",
                            metadata={"path": "/root/.ssh/authorized_keys", "classification": "UNKNOWN_KEY_CHANGE"})
    for event in notifications + [intrusion, unknown_key]:
        await dispatcher._on_event(event)
    assert len(notifications) <= 6 and len([e for e in notifications if e.category == EventCategory.APPLICATION_ERROR_DIGEST]) == 1
    ts = titles(channel)
    assert any("SSH LOGIN AFTER BRUTE FORCE" in t for t in ts), "the security alert is delivered next to the application digest"
    assert any("SSH_KEY_CHANGE" in t for t in ts) and any(t == "RTSA Alert — APPLICATION_ERROR_DIGEST" for t in ts)
    app_messages = [t for t in ts if "APPLICATION_ERROR" in t]
    assert 1 <= len(app_messages) <= 6 and len(ts) == len(app_messages) + 2
    digest_embed = next(e for e in sent_embeds(channel) if e["title"].endswith("APPLICATION_ERROR_DIGEST"))
    fields = field_map(digest_embed)
    for name in ("Server", "Window", "Affected Projects", "New Incidents", "Critical", "High", "Medium", "Top Affected", "PM2 Crashes", "HTTP 5xx", "DB Errors", "Status"):
        assert name in fields, name
    assert fields["Affected Projects"] == "30" and fields["Window"] == "5 minutes" and fields["Status"] == "SERVER_APPLICATION_ERROR_STORM" and "•" in fields["Top Affected"]
    individual = next(e for e in sent_embeds(channel) if e["title"] == "RTSA Alert — APPLICATION_ERROR")
    ifields = field_map(individual)
    for name in ("Server", "Project", "Domain", "Error", "Severity", "State", "Occurrences", "Rate", "First Seen", "Last Seen", "Duration", "Fingerprint", "Stack (redacted, truncated)"):
        assert name in ifields, name
    blob = json.dumps(sent_embeds(channel), default=str)
    assert SECRET not in blob and all(len(f["value"]) <= 1024 for e in sent_embeds(channel) for f in e["fields"])
    assert tracker.engine.stats()["incidents_tracked"] == 30
    shutil.rmtree(tmp, ignore_errors=True)
    print("Test 5 (30 failing projects + an SSH brute-force intrusion + an unknown SSH key: <= 5 individual application alerts and 1 digest, the security alerts are delivered separately; payloads carry the required fields and no secret) PASSED")


async def test_6_discord_unavailable_is_bounded() -> None:
    tmp = tempfile.mkdtemp(prefix="rtsa-app-down-")
    tracker, bus, capture, clock = await make_tracker(tmp)
    channel = FakeChannel()
    dispatcher = make_dispatcher(channel, ready=False, dedup_window_seconds=60.0)
    published = []
    tracker.publish = lambda event: published.append(event)
    from _app_error_fakes import make_event
    for round_ in range(6):
        for project in range(25):
            clock.advance(0.01)
            tracker.ingest_event(make_event(clock, project=f"x{round_}-{project}", error_class="CRASH", error_type="ProcessCrash", message=f"crash {round_}"))
        clock.advance(400)
        tracker._publish_notes(tracker.engine.tick(clock.t))
    for event in [e for e in published if e.metadata.get("record") in ("NOTIFICATION", "DIGEST")]:
        await dispatcher._on_event(event)
    assert channel.sent == []
    depth = len(dispatcher._pending_heap)
    assert 0 < depth <= 40, f"the pending queue is bounded ({depth})"
    assert dispatcher.get_outbound_health()["pending_queue_depth"] == depth
    for _ in range(5):
        await dispatcher._flush_pending_once()
    assert len(dispatcher._pending_heap) <= depth and channel.sent == [], "while Discord is unavailable nothing is delivered and nothing grows"
    assert len(tracker.engine.incidents()) == 150, "collection and storage continue while Discord is down"
    shutil.rmtree(tmp, ignore_errors=True)
    print("Test 6 (Discord unavailable: the pending queue stays bounded, retries do not loop or grow, collection and incident storage continue) PASSED")


async def test_7_resource_pressure_never_amplifies_work() -> None:
    tmp = tempfile.mkdtemp(prefix="rtsa-app-pressure-")
    log = os.path.join(tmp, "app.log")
    write(log, "", "w")
    collection = AppErrorCollectionConfig(poll_interval_seconds=1.0, max_bytes_per_cycle=2_000_000, max_bytes_per_file_per_cycle=1_000_000, event_queue_max=25, batch_size=10)
    tracker, bus, capture, clock = await make_tracker(tmp, collection=collection)
    tracker.register_source(AppErrorLogSourceConfig(path=log, project="p", domain="p.example.com"))
    await tracker.cycle()
    observed = []
    original = tracker._collect_sync

    def spy(now, budget, per_file):
        observed.append((budget, per_file))
        return original(now, budget, per_file)

    tracker._collect_sync = spy
    write(log, "".join(err_block(f"variant number {i % 90} {'z' * (i % 90)}", f"Err{i % 90}Error") for i in range(3000)))
    await tracker.cycle(tracker_module._PRESSURE_NORMAL)
    await tracker.cycle(tracker_module._PRESSURE_SOFT)
    await tracker.cycle(tracker_module._PRESSURE_HARD)
    assert observed[1][0] == observed[0][0] // 2 and observed[2][0] == observed[0][0] // 4, observed
    assert tracker.engine.enrichment is False, "HARD pressure skips enrichment (correlation and sample storage)"
    assert tracker._poll_multiplier("HARD") == 4.0 and tracker._poll_multiplier("SOFT") == 2.0 and tracker._poll_multiplier("NORMAL") == 1.0
    assert len(tracker._queue) <= 25, "the event queue is bounded"
    assert counters(get_app_error_metrics())["application_event_dropped_total"] >= 0
    await tracker.cycle(tracker_module._PRESSURE_NORMAL)
    assert tracker.engine.enrichment is True, "normal behaviour returns when the pressure drops"
    tracker.set_pressure_provider(lambda: "HARD")
    assert tracker._pressure_provider() == "HARD"
    assert tracker_module.ApplicationErrorTracker._default_pressure(tracker) in ("NORMAL", "SOFT", "HARD")
    no_pressure, _, _, _ = await make_tracker(tmp, resources=AppErrorResourceConfig(pressure_aware=False))
    assert no_pressure._default_pressure() == "NORMAL"
    shutil.rmtree(tmp, ignore_errors=True)
    print("Test 7 (CPU pressure shrinks read budgets (1/2, 1/4), stretches the poll interval, drops enrichment, keeps the queue bounded and returns to normal by itself) PASSED")


async def test_8_restart_restores_incidents_budgets_and_cursors_without_replay() -> None:
    tmp = tempfile.mkdtemp(prefix="rtsa-app-restart-")
    db_path = os.path.join(tmp, "rtsa.db")
    worker = SQLiteWriteWorker(db_path, flush_interval_seconds=0.05)
    await worker.start()
    log = os.path.join(tmp, "app.log")
    write(log, "", "w")
    sections = dict(notifications=AppErrorBudgetConfig(individual_alerts=2, window_seconds=600.0, project_alerts=5, global_individual_alerts=5), storm=AppErrorStormConfig(enabled=False))
    tracker, bus, capture, clock = await make_tracker(tmp, db_worker=worker, **sections)
    for index in range(4):
        tracker.register_source(AppErrorLogSourceConfig(path=log + str(index), project=f"proj{index}", domain=f"proj{index}.example.com"))
        write(log + str(index), "", "w")
    await tracker.cycle()
    for index in range(4):
        for _ in range(5):
            write(log + str(index), err_block("db is down", "Error").replace("Error: db is down", "Error: connect ECONNREFUSED 10.0.0.5:5432"))
    clock.advance(1)
    await pump(tracker, clock)
    await settle()
    first_notices = capture.of(EventCategory.APPLICATION_ERROR, "NOTIFICATION")
    assert len(first_notices) == 2 and sum(1 for i in tracker.engine.incidents() if i.notification_state == eng.NS_BUDGET) == 2
    clock.advance(30)
    tracker.engine.tick(clock.t)
    tracker._publish_notes(tracker.engine.tick(clock.t))
    tracker._persist(force=True)
    tracker._save_state()
    await asyncio.sleep(0.4)
    rows = app_error_store.query_incidents(db_path)
    assert len(rows) == 4 and {r["project"] for r in rows} == {f"proj{i}" for i in range(4)}
    assert sorted(r["notification_state"] for r in rows).count("SENT") == 2
    detail = app_error_store.incident_detail(db_path, rows[0]["incident_id"])
    assert detail["occurrence_count"] == 5 and detail["fingerprint"] and "samples" in detail
    assert app_error_store.query_incidents(db_path, project="proj1")[0]["project"] == "proj1" and app_error_store.query_incidents(db_path, min_occurrences=99) == []
    await worker.stop()

    worker2 = SQLiteWriteWorker(db_path, flush_interval_seconds=0.05)
    await worker2.start()
    restarted, bus2, capture2, clock2 = await make_tracker(tmp, db_worker=worker2, clock=Clock(clock.t + 60), **sections)
    restarted._load_state()
    await restarted._restore_incidents(asyncio.get_running_loop())
    assert len(restarted.engine.incidents()) == 4
    restored = {i.project: i for i in restarted.engine.incidents()}
    assert sum(1 for i in restored.values() if i.notified_count == 1) == 2 and sum(1 for i in restored.values() if i.notified_count == 0) == 2
    for index in range(4):
        write(log + str(index), err_block("db is down", "Error").replace("Error: db is down", "Error: connect ECONNREFUSED 10.0.0.5:5432"))
    clock2.advance(5)
    await pump(restarted, clock2)
    await settle()
    assert capture2.of(EventCategory.APPLICATION_ERROR, "NOTIFICATION") == [], "restart: already-notified incidents are not re-announced and the restored budget still applies"
    assert all(i.occurrence_count >= 5 for i in restarted.engine.incidents())
    rows2 = app_error_store.recent_digests(db_path)
    assert isinstance(rows2, list)
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE app_error_incidents SET last_seen = ?", (time.time() - 200 * 86400,))
    conn.execute("INSERT INTO app_error_digests (server, generated_at, window_seconds, status, affected_projects, new_incidents, occurrences, data) VALUES ('s', ?, 300, 'X', 1, 1, 1, '{}')", (time.time() - 200 * 86400,))
    conn.commit()
    conn.close()
    worker2._retention_days = 90
    await asyncio.get_running_loop().run_in_executor(worker2._executor, worker2._prune_old_events)
    after = sqlite3.connect(db_path)
    assert after.execute("SELECT count(*) FROM app_error_incidents").fetchone()[0] == 0 and after.execute("SELECT count(*) FROM app_error_digests").fetchone()[0] == 0, "retention bounds table growth"
    after.close()
    await worker2.stop()
    shutil.rmtree(tmp, ignore_errors=True)
    print("Test 8 (restart: incidents, notification state and budgets restored from SQLite, log cursors resume, nothing is re-announced; rows are queryable per project and pruned by retention) PASSED")


async def test_9_module_lifecycle_on_the_real_event_bus() -> None:
    tmp = tempfile.mkdtemp(prefix="rtsa-app-life-")
    log = os.path.join(tmp, "app.log")
    write(log, "", "w")
    bus = EventBus()
    capture = Capture(bus)
    await capture.start()
    cfg = config(collection=AppErrorCollectionConfig(poll_interval_seconds=1.0, structured_logs=[AppErrorLogSourceConfig(path=log, project="live", domain="live.example.com")]),
                 storage=AppErrorStorageConfig(state_path=os.path.join(tmp, "state.json"), state_save_interval_seconds=5.0))
    tracker = ApplicationErrorTracker(bus, cfg)
    for source in cfg.collection.structured_logs:
        tracker.register_source(source)
    loop = asyncio.get_running_loop()
    tracker.start(loop)
    await asyncio.sleep(0.3)
    assert tracker.is_running
    for _ in range(4):
        write(log, err_block("live failure", "RuntimeError"))
    deadline = time.time() + 6
    while time.time() < deadline and not capture.of(EventCategory.APPLICATION_ERROR, "NOTIFICATION"):
        await asyncio.sleep(0.2)
    assert capture.of(EventCategory.APPLICATION_ERROR, "NOTIFICATION"), "the running module turns appended log lines into a notification event"
    await tracker.stop()
    assert not tracker.is_running and os.path.exists(os.path.join(tmp, "state.json")), "shutdown saves the cursor state"
    assert "application_error_tracker" not in bus._subscriptions, "the context subscription is removed on shutdown"
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert '"application_error_tracker": "application_error_tracker"' in open(os.path.join(root, "main.py")).read()
    assert tracker_module.ApplicationErrorTracker.enabled_by_default is False
    shutil.rmtree(tmp, ignore_errors=True)
    print("Test 9 (module lifecycle: starts on the real bus, turns log lines into notifications, saves state and unsubscribes on shutdown; registered in main; disabled by default) PASSED")


def test_10_metrics_are_registered_without_unbounded_labels() -> None:
    registry = get_app_error_metrics()
    expected_counters = {
        "application_errors_total", "application_error_fingerprints_total", "application_incidents_recovered_total", "application_error_storms_total",
        "application_notification_sent_total", "application_notification_suppressed_total", "application_notification_budget_exhausted_total", "application_digest_total",
        "application_event_dropped_total",
    }
    assert expected_counters <= set(registry.counter_help)
    assert {"application_incidents_open", "application_error_rate", "application_event_queue_depth"} <= set(registry.gauge_help)
    assert {"application_event_processing_latency"} <= set(registry.latency_help)
    names = list(registry.counter_help) + list(registry.gauge_help) + list(registry.latency_help)
    assert len(names) == len(set(names)) and all(n.startswith("application_") for n in names)
    from core.pipeline_metrics import get_lb_metrics
    assert not (set(names) & (set(get_lb_metrics().counter_help) | set(get_lb_metrics().gauge_help))), "no duplicate of an existing metric"
    from core import metrics_exporter
    assert "get_app_error_metrics" in open(metrics_exporter.__file__).read()
    print("Test 10 (application_* metrics are registered once in the existing exporter registries, label-free, none duplicates an existing metric) PASSED")


async def main() -> None:
    await test_1_incremental_tailing_cursors_rotation_and_bounds()
    await test_2_pm2_discovery_uses_only_safe_logs_of_the_owning_user()
    await test_3_end_to_end_notification_and_sampled_raw_evidence()
    await test_4_nginx_5xx_pm2_and_deployment_context()
    await test_5_discord_payloads_and_a_storm_plus_a_security_alert()
    await test_6_discord_unavailable_is_bounded()
    await test_7_resource_pressure_never_amplifies_work()
    await test_8_restart_restores_incidents_budgets_and_cursors_without_replay()
    await test_9_module_lifecycle_on_the_real_event_bus()
    test_10_metrics_are_registered_without_unbounded_labels()
    for bus in BUSES:
        await bus.shutdown()
    print("\nALL APPLICATION ERROR TRACKER MODULE TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
