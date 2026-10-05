from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _app_error_fakes import T0, Clock, config as app_config
from _investigation_fakes import NOW, AppFlow, EventDb, fail, live_session, login, logout, snapshot
from config.manager import (
    AppErrorCollectionConfig, AppErrorLogSourceConfig, AppErrorStorageConfig, ApplicationErrorTrackerConfig, DiscordConfig, InvestigationAppConfig, InvestigationConfig,
    InvestigationLimitsConfig, InvestigationSshConfig, ModulesConfig, NginxMonitorConfig, RTSAConfig, TrafficBaselineConfig, _build_dataclass, _validate_investigation,
)
from core import investigation_service as service_module
from core.app_error_model import hash_user_id
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.investigation_registry import InvestigationRegistry
from core.investigation_service import InvestigationService
from core.pipeline_metrics import (
    INVESTIGATION_COUNTERS, INVESTIGATION_GAUGES, INVESTIGATION_LATENCIES, PipelineMetrics, get_actor_metrics, get_app_error_metrics, get_core_metrics, get_investigation_metrics,
    get_lb_metrics, get_nginx_metrics, get_ssh_metrics,
)
from core.traffic_stats import TrafficHourlyRecorder
from database.sqlite_pool import SQLiteWriteWorker
from discord_integration.bot import RTSABot
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.application_error_tracker import ApplicationErrorTracker
from modules.nginx_monitor import NginxMonitor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLEANUP = []
BUSES = []


def fresh_metrics():
    return PipelineMetrics(INVESTIGATION_COUNTERS, INVESTIGATION_GAUGES, INVESTIGATION_LATENCIES)


def file_hash(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


async def seeded_flow():
    flow = await AppFlow().start()
    CLEANUP.append(flow)
    flow.engine.ingest(flow.event(project="shop", message="upstream timeout", count=120, users=90, domain="shop.example.com", route="/checkout", status=504))
    flow.engine.ingest(flow.event(project="blog", message="template error", count=30, domain="blog.example.com"))
    flow.clock.advance(20)
    await flow.persist()
    await flow.stop()
    return flow


def add_ssh_rows(db_path):
    conn = sqlite3.connect(db_path)
    db = EventDb.__new__(EventDb)
    db.conn, db._seq = conn, 0
    for n in range(6):
        fail(db, T0 - 400 + n, "203.0.113.9", "admin")
    login(db, T0 - 300, "deploy", "203.0.113.9", "sess-1", method="password")
    logout(db, T0 - 100, "sess-1", "deploy", "203.0.113.9", login_time=T0 - 300, duration=200.0)
    conn.commit()
    conn.close()


async def test_1_service_caches_coalesces_rejects_and_never_writes():
    flow = await seeded_flow()
    before = file_hash(flow.db_path)
    calls = []
    original = service_module.build_top_issues

    def counting(*args, **kwargs):
        calls.append(threading.current_thread().name)
        time.sleep(0.2)
        return original(*args, **kwargs)

    service_module.build_top_issues = counting
    try:
        metrics = fresh_metrics()
        service = InvestigationService(InvestigationConfig(), flow.db_path, registry=InvestigationRegistry(), clock=lambda: flow.clock.t + 10, metrics=metrics)
        results = await asyncio.gather(*(service.error_top(86400.0) for _ in range(5)))
        assert len(calls) == 1 and all(r["items"][0]["project"] == "shop" for r in results), "identical concurrent requests share one build"
        snap = metrics.snapshot()
        assert snap["counters"]["investigation_requests_total"] == 5 and snap["counters"]["investigation_coalesced_total"] == 4 and snap["counters"]["investigation_rows_read_total"] > 0
        assert calls[0] != threading.current_thread().name, "queries run off the event loop"
        again = await service.error_top(86400.0)
        assert again["cached"] is True and len(calls) == 1 and metrics.snapshot()["counters"]["investigation_cache_hits_total"] == 1
        uncached = InvestigationService(InvestigationConfig(limits=InvestigationLimitsConfig(cache_ttl_seconds=0.0)), flow.db_path, registry=InvestigationRegistry(), clock=lambda: flow.clock.t + 10, metrics=fresh_metrics())
        await uncached.error_top(86400.0)
        await uncached.error_top(86400.0)
        assert len(calls) == 3, "cache_ttl_seconds=0 disables caching"
        gate = threading.Event()

        def blocking(*args, **kwargs):
            gate.wait(5)
            return original(*args, **kwargs)

        service_module.build_top_issues = blocking
        service_module._ACQUIRE_TIMEOUT_SECONDS = 0.2
        busy_metrics = fresh_metrics()
        busy = InvestigationService(InvestigationConfig(limits=InvestigationLimitsConfig(max_concurrent=1)), flow.db_path, registry=InvestigationRegistry(), clock=lambda: flow.clock.t + 10, metrics=busy_metrics)
        first = asyncio.create_task(busy.error_top(3600.0))
        await asyncio.sleep(0.1)
        rejected = await busy.error_top(7200.0)
        assert rejected["kind"] == "BUSY" and busy_metrics.snapshot()["counters"]["investigation_rejected_total"] == 1
        gate.set()
        assert (await first)["items"], "the running request still completes"
        service_module.build_top_issues = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        failing = InvestigationService(InvestigationConfig(), flow.db_path, registry=InvestigationRegistry(), metrics=busy_metrics)
        try:
            await failing.error_top(900.0)
            raise AssertionError("expected failure")
        except RuntimeError:
            pass
        assert busy_metrics.snapshot()["counters"]["investigation_failures_total"] == 1 and not failing._inflight, "a failed build leaves no stuck in-flight entry"
    finally:
        service_module.build_top_issues = original
        service_module._ACQUIRE_TIMEOUT_SECONDS = 4.0
    assert file_hash(flow.db_path) == before, "no investigation call writes to the database"
    print("Test 1 (service: coalesced builds, short TTL cache, off-loop queries, busy rejection, failure cleanup, database never modified) PASSED")


async def test_2_ssh_snapshot_is_taken_on_the_loop_and_used():
    flow = await seeded_flow()
    add_ssh_rows(flow.db_path)
    registry = InvestigationRegistry()
    seen = []

    def provider():
        seen.append(threading.current_thread() is threading.main_thread())
        return snapshot([live_session("sess-live", "deploy", "198.51.100.7", 40404, auth_time=T0 - 50)], server="srv2", ssh_ports=[22])

    registry.register("ssh", provider)
    service = InvestigationService(InvestigationConfig(), flow.db_path, registry=registry, clock=lambda: T0 + 10, metrics=fresh_metrics(), passwd_provider=lambda: [{"name": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"}])
    report = await service.ssh_check(3600.0)
    assert seen == [True], "the live tracker snapshot is read on the event loop thread"
    assert report["active_sessions"]["items"][0]["session_id"] == "sess-live" and report["summary"]["suspicious_correlations"] == 1
    registry.unregister("ssh", provider)
    assert registry.snapshot("ssh") is None and registry.names() == []
    registry.register("ssh", lambda: (_ for _ in ()).throw(RuntimeError("provider failure")))
    assert registry.snapshot("ssh") == {"available": False, "error": "PROVIDER_FAILED"}, "a failing provider degrades to a data gap, never an exception"
    print("Test 2 (SSH live snapshot read on the loop, used for active sessions; provider failures degrade to an explicit gap) PASSED")


class FakeDb:
    def __init__(self, path):
        self.db_path = path


class FakeResponse:
    def __init__(self):
        self.sent = []

    async def send_message(self, content=None, **kwargs):
        self.sent.append((content, kwargs))


def make_bot(db_path, bus=None, svc_config=None):
    cfg = RTSAConfig(modules=ModulesConfig(), investigation=svc_config or InvestigationConfig())
    bot = RTSABot(DiscordConfig(enabled=True), cfg, bus or EventBus(), db_worker=FakeDb(db_path), supervisor=None)
    return bot


def embed_ok(embed):
    assert len(embed) <= 6000 and len(embed.fields) <= 25 and len(embed.title or "") <= 256 and len(embed.description or "") <= 4096
    assert all(len(f.name) <= 256 and len(f.value) <= 1024 for f in embed.fields)


async def test_3_bot_commands_are_read_only_ephemeral_and_discord_sized():
    flow = await seeded_flow()
    add_ssh_rows(flow.db_path)
    bus = EventBus()
    BUSES.append(bus)
    received = []

    async def on_event(event):
        received.append(event)

    await bus.subscribe("spy", on_event, categories=None)
    bot = make_bot(flow.db_path, bus)
    bot._investigation._clock = lambda: T0 + 30
    names = {c.name: c for c in bot.tree.get_commands()}
    assert {"sshcheck", "errortop", "errordetail", "errorimpact"} <= set(names)
    assert all(len(names[n].description) <= 100 for n in ("sshcheck", "errortop", "errordetail", "errorimpact"))
    before = file_hash(flow.db_path)
    for coro in (bot._sshcheck_command(""), bot._sshcheck_command("24h"), bot._sshcheck_command("7d"), bot._errortop_command("24h"), bot._errortop_command("7d"),
                 bot._errortop_command("30d"), bot._errorimpact_command("7d")):
        embeds, files = await coro
        assert 1 <= len(embeds) <= 10 and all(embed_ok(e) is None for e in embeds)
    ssh_embeds, _ = await bot._sshcheck_command("24h")
    text = " ".join(f"{f.name} {f.value}" for e in ssh_embeds for f in e.fields) + " ".join(e.title for e in ssh_embeds)
    assert "SSH SECURITY QUICK CHECK" in ssh_embeds[0].title and "CORRELATED_SUSPICIOUS_LOGIN" in text and "Assessment:" in text
    top_embeds, _ = await bot._errortop_command("24h")
    assert top_embeds[0].title == "RTSA — TOP PRODUCTION ISSUES" and "Window: 1d" in top_embeds[0].description
    display = json.loads(sqlite3.connect(flow.db_path).execute("SELECT data FROM app_error_incidents WHERE project='shop'").fetchone()[0])["display_id"]
    detail_embeds, detail_files = await bot._errordetail_command(display.lower())
    assert detail_files and detail_files[0].filename == f"production_issue_brief_{display}.md"
    brief = detail_files[0].fp.read().decode("utf-8")
    assert "# PRODUCTION ISSUE BRIEF" in brief and "does not edit repositories" in brief and all(embed_ok(e) is None for e in detail_embeds)
    for bad in ("", "APP-20000101-0000", "garbage!"):
        missing, files = await bot._errordetail_command(bad)
        assert not files and "Result" in " ".join(f.name for f in missing[0].fields)
    for text_window, expected in (("bad", "Invalid window"), ("45d", "too large"), ("0m", "at least 1 minute")):
        warn, _ = await bot._errortop_command(text_window)
        assert expected in warn[0].description, text_window
    await asyncio.sleep(0.1)
    assert received == [], "on-demand investigation commands publish nothing to the event bus, so no Discord alert can come from them"
    assert file_hash(flow.db_path) == before
    print("Test 3 (four commands registered; read-only, bus-silent, Discord-sized embeds, brief attached, invalid windows explained) PASSED")


async def test_4_unauthorized_users_and_disabled_layer_get_nothing():
    flow = await seeded_flow()
    bot = make_bot(flow.db_path)
    spy = []
    original = bot._investigation.ssh_check

    async def watched(*a, **k):
        spy.append(1)
        return await original(*a, **k)

    bot._investigation.ssh_check = watched
    for name in ("sshcheck", "errortop", "errorimpact", "errordetail"):
        command = bot.tree.get_command(name)
        interaction = SimpleNamespace(user=SimpleNamespace(id=1), response=FakeResponse(), followup=SimpleNamespace())
        args = ("APP-20260101-0001",) if name == "errordetail" else ()
        await command.callback(interaction, *args)
        assert interaction.response.sent and "izin" in interaction.response.sent[0][0] and interaction.response.sent[0][1]["ephemeral"] is True, name
    assert not spy, "an unauthorized caller never reaches the service"
    off = make_bot(flow.db_path, svc_config=InvestigationConfig(enabled=False))
    for coro in (off._sshcheck_command(""), off._errortop_command(""), off._errorimpact_command(""), off._errordetail_command("APP-20260101-0001")):
        embeds, files = await coro
        assert "dinonaktifkan" in embeds[0].description and not files
    print("Test 4 (non-members are denied before any query runs; investigation.enabled=false answers with a notice) PASSED")


async def test_5_tracker_collects_user_ids_with_a_persistent_salt_and_structured_logs():
    tmp = tempfile.mkdtemp(prefix="rtsa-app-users-")
    CLEANUP.append(SimpleNamespace(cleanup=lambda: shutil.rmtree(tmp, ignore_errors=True)))
    log = os.path.join(tmp, "app.jsonl")
    open(log, "w").close()
    state = os.path.join(tmp, "state.json")
    db = os.path.join(tmp, "rtsa.db")
    worker = SQLiteWriteWorker(db, flush_interval_seconds=0.05)
    await worker.start()

    def line(user, extra=None):
        err = {"type": "TypeError", "message": "Cannot read properties of undefined (reading 'profile')", "stack": "TypeError: x\n    at load (/app/src/profile.js:10:3)"}
        body = {"level": 50, "time": int(time.time() * 1000), "msg": "request failed", "err": err, "req": {"method": "GET", "url": "/api/profile/7", "user": {"id": user}}}
        body.update(extra or {})
        return json.dumps(body) + "\n"

    cfg = app_config(
        collection=AppErrorCollectionConfig(poll_interval_seconds=1.0, structured_logs=[AppErrorLogSourceConfig(path=log, project="portal", domain="portal.example.com", format="json")]),
        storage=AppErrorStorageConfig(state_path=state),
    )
    bus = EventBus()
    BUSES.append(bus)
    tracker = ApplicationErrorTracker(bus, cfg)
    clock = Clock(time.time())
    tracker._clock = clock
    tracker.engine._clock = clock
    tracker.attach_db_worker(worker)
    assert log in tracker._sources and tracker._sources[log].trusted, "structured_logs from the config are registered by the tracker itself"
    await tracker.setup()
    salt = tracker._user_salt
    assert len(salt) == 32 and json.load(open(state))["user_salt"] == salt.hex(), "the salt is created once and persisted immediately"
    await tracker.cycle()
    with open(log, "a") as handle:
        handle.write(line(42))
        handle.write(line(42))
        handle.write(line(1001))
        handle.write(line("mail-user@example.com"))
        handle.write(line(True))
        handle.write(line(None))
        handle.write(line(7, {"userId": "top-level-wins-after-first-field"}))
    for _ in range(3):
        await tracker.cycle()
        clock.advance(3)
    incident = tracker.engine.incidents()[0]
    assert incident.occurrence_count == 7 and incident.user_tagged == 5 and incident.user_sketch is not None and incident.user_sketch.count() == 4, "ids 42, 1001, the mail id and the top-level userId; bool/None carry no user"
    tracker._persist(force=True)
    await worker.stop()
    raw = open(db, "rb").read()
    assert b"mail-user@example.com" not in raw and salt not in raw and salt.hex().encode() not in raw
    row = json.loads(sqlite3.connect(db).execute("SELECT data FROM app_error_incidents").fetchone()[0])
    assert row["user_tagged"] == 5 and row["user_sketch"] and "hourly_deltas" not in row
    again = ApplicationErrorTracker(EventBus(), cfg)
    again._load_state()
    assert again._user_salt == salt and again._ensure_salt() is False, "a restart keeps the salt so earlier sketches stay valid"
    assert hash_user_id(salt, "42") == hash_user_id(again._user_salt, "42")
    off_cfg = app_config(
        collection=AppErrorCollectionConfig(poll_interval_seconds=1.0, capture_user_ids=False, structured_logs=[AppErrorLogSourceConfig(path=log, project="portal", format="json")]),
        storage=AppErrorStorageConfig(state_path=os.path.join(tmp, "state-off.json")),
    )
    disabled = ApplicationErrorTracker(EventBus(), off_cfg)
    await disabled.setup()
    assert disabled._user_salt == b"" and not os.path.exists(os.path.join(tmp, "state-off.json")), "no salt is created when user capture is off"
    info = tracker.investigation_info()
    assert info["available"] and info["capture_user_ids"] and info["structured_sources"] == 1
    from core.investigation_registry import get_investigation_registry
    assert get_investigation_registry().snapshot("app_errors")["structured_sources"] == 1
    await disabled.teardown()
    assert get_investigation_registry().snapshot("app_errors") is None, "an unregistered provider is removed only by its owner"
    await tracker.teardown()
    assert get_investigation_registry().snapshot("app_errors") is None
    print("Test 5 (tracker registers structured_logs itself, hashes user ids with a persisted salt, ignores non-id values, and stores no raw ids) PASSED")


async def test_6_traffic_recorder_and_nginx_hook():
    writes = []
    rec = TrafficHourlyRecorder(max_keys=2)
    worker = SimpleNamespace(enqueue_traffic_hourly=lambda rows: writes.append(rows) or True)
    rec.record("A.example.com", 7200.0, 10, 1, 2)
    rec.record("a.example.com", 7300.0, 5, 0, 1)
    rec.record("b.example.com", 7200.0, 4, 0, 0)
    rec.record("c.example.com", 7200.0, 99, 0, 0)
    rec.record("", 7200.0, 5, 0, 0)
    rec.record("b.example.com", 7200.0, 0, 0, 0)
    assert rec.pending() == 2 and rec.dropped_requests == 99 and rec.flush() == 0, "nothing is flushed before a worker exists"
    rec.attach_db_worker(worker)
    assert rec.flush() == 2 and rec.pending() == 0 and sorted(writes[0]) == [("a.example.com", 2, 15, 1, 3), ("b.example.com", 2, 4, 0, 0)]
    rec.attach_db_worker(SimpleNamespace(enqueue_traffic_hourly=lambda rows: False))
    rec.record("a.example.com", 7200.0, 1, 0, 0)
    assert rec.flush() == 0 and rec.pending() == 1, "a full write queue keeps the counts for the next flush"
    tb = TrafficBaselineConfig(window_seconds=1.0)
    monitor = NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True, traffic_baseline=tb))
    monitor.publish = lambda event: None

    async def no_context(domain):
        return "", {"domain": domain or "unknown"}

    monitor._cloudpanel_context = no_context
    captured = []
    monitor.attach_db_worker(SimpleNamespace(enqueue_traffic_hourly=lambda rows: captured.append(rows) or True))
    for status in [200] * 7 + [404, 404, 502]:
        monitor._track_traffic_baseline("shop.example.com", "/p", status, "198.51.100.1", is_suspicious=False)
    await monitor._sweep_traffic_windows()
    assert len(captured) == 1 and len(captured[0]) == 1
    domain, hour, requests, s4, s5 = captured[0][0]
    assert (domain, requests, s4, s5) == ("shop.example.com", 10, 2, 1) and abs(hour - time.time() // 3600) <= 1
    print("Test 6 (hourly traffic recorder is bounded and lossless on queue pressure; the nginx sweep records per-domain request, 4xx and 5xx totals) PASSED")


async def test_7_sqlite_schema_indexes_and_retention():
    tmp = tempfile.mkdtemp(prefix="rtsa-retention-")
    CLEANUP.append(SimpleNamespace(cleanup=lambda: shutil.rmtree(tmp, ignore_errors=True)))
    worker = SQLiteWriteWorker(os.path.join(tmp, "rtsa.db"), flush_interval_seconds=0.05, retention_days=30)
    await worker.start()
    row_old = {"incident_id": "old0000000000001", "server": "s", "project": "p", "fingerprint": "f", "state": "OPEN", "severity": "HIGH", "first_seen": 1.0, "last_seen": 2.0,
               "occurrence_count": 3, "hourly_deltas": {"0": [3, 0, 0, 0]}}
    worker.enqueue_app_error_incident(row_old)
    now_hour = int(time.time() // 3600)
    worker.enqueue_app_error_incident({**row_old, "incident_id": "new0000000000001", "last_seen": time.time(), "first_seen": time.time() - 5, "hourly_deltas": {str(now_hour): [2, 1, 0, 0]}})
    worker.enqueue_traffic_hourly([("old.example.com", 0, 5, 0, 0), ("new.example.com", now_hour, 5, 1, 1)])
    await asyncio.sleep(0.6)
    await asyncio.get_running_loop().run_in_executor(worker._executor, worker._prune_old_events)
    await worker.stop()
    conn = sqlite3.connect(os.path.join(tmp, "rtsa.db"))
    assert [r[0] for r in conn.execute("SELECT incident_id FROM app_error_hourly")] == ["new0000000000001"]
    assert [r[0] for r in conn.execute("SELECT domain FROM traffic_hourly")] == ["new.example.com"], "hourly tables follow the retention window"
    indexes = {r[1] for t in ("events", "app_error_incidents", "app_error_hourly", "traffic_hourly") for r in conn.execute(f"PRAGMA index_list({t})")}
    assert {"idx_events_category_ts", "idx_app_error_incidents_last_seen", "idx_app_error_incidents_first_seen", "idx_app_error_hourly_hour", "idx_traffic_hourly_hour"} <= indexes
    plan = " ".join(str(r) for r in conn.execute("EXPLAIN QUERY PLAN SELECT * FROM events WHERE category='SSH_AUTH' AND timestamp >= 1 AND timestamp <= 2"))
    assert "idx_events_category_ts" in plan, "category + time queries use the composite index"
    print("Test 7 (new tables and composite/time indexes exist, are used by the investigation queries, and are pruned by retention) PASSED")


def test_8_config_defaults_match_yaml_and_are_validated():
    for name in ("config.yaml", "config2.yaml"):
        raw = yaml.safe_load(open(os.path.join(ROOT, "config", name)))
        assert _build_dataclass(InvestigationConfig, raw["investigation"]) == InvestigationConfig(), name
        collection = _build_dataclass(AppErrorCollectionConfig, raw["modules"]["application_error_tracker"]["collection"])
        assert collection.user_id_fields == AppErrorCollectionConfig().user_id_fields and collection.capture_user_ids is True, name
        assert collection.structured_logs == [], "no production log path is invented"
        assert InvestigationConfig().ssh.known_legitimate_uid0 == [] and InvestigationConfig().app.project_criticality == {}, "no production value is invented"
    errors = []
    _validate_investigation(InvestigationConfig(), errors)
    assert errors == []
    bad = InvestigationConfig(
        limits=InvestigationLimitsConfig(query_time_budget_seconds=0.1, top_n=99, max_concurrent=0, cache_ttl_seconds=-1),
        ssh=InvestigationSshConfig(default_window_seconds=10.0, max_window_seconds=5.0, known_legitimate_uid0=["root", ""], brute_force_min_failures=0),
        app=InvestigationAppConfig(project_criticality={"x": "URGENT"}, high_user_impact=50, critical_user_impact=10),
    )
    errors = []
    _validate_investigation(bad, errors)
    joined = " ".join(errors)
    for token in ("query_time_budget_seconds", "top_n", "max_concurrent", "cache_ttl_seconds", "default_window_seconds", "known_legitimate_uid0", "brute_force_min_failures", "project_criticality", "high_user_impact"):
        assert token in joined, token
    from config.manager import _validate_application_error_tracker
    errors = []
    _validate_application_error_tracker(ApplicationErrorTrackerConfig(collection=AppErrorCollectionConfig(user_id_fields=["ok", " bad field"])), errors)
    assert any("user_id_fields" in e for e in errors)
    print("Test 8 (investigation and user_id_fields defaults equal both YAML files, invent no production value, and invalid settings are rejected) PASSED")


def test_9_metrics_are_registered_once_and_exported():
    registry = get_investigation_metrics()
    names = list(registry.counter_help) + list(registry.gauge_help) + list(registry.latency_help)
    assert len(names) == len(set(names)) and all(n.startswith("investigation_") for n in names)
    others = set()
    for other in (get_nginx_metrics(), get_core_metrics(), get_ssh_metrics(), get_lb_metrics(), get_actor_metrics(), get_app_error_metrics()):
        others |= set(other.counter_help) | set(other.gauge_help) | set(other.latency_help)
    assert not (set(names) & others)
    assert "get_investigation_metrics" in open(os.path.join(ROOT, "core", "metrics_exporter.py")).read()
    print("Test 9 (investigation_* metrics are unique, label-free and exported by the existing exporter) PASSED")


def build_note_event(category, meta, severity=Severity.HIGH):
    return BaseEvent(source_module="test", category=category, severity=severity, message="m", raw="", metadata=meta)


def test_10_alerts_point_to_the_investigation_commands():
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    incident = {"incident_id": "abcdef0123456789", "display_id": "APP-20261002-1234", "project": "shop", "domain": "shop.example.com", "error_type": "TypeError", "error_message": "x",
                "severity": "HIGH", "state": "OPEN", "occurrence_count": 5, "first_seen": T0, "last_seen": T0, "duration_seconds": 0, "fingerprint": "ff"}
    payload = dispatcher._build_payload(build_note_event(EventCategory.APPLICATION_ERROR, {"record": "NOTIFICATION", "notification_kind": "INITIAL", "incident": incident}))
    fields = {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}
    assert fields["Investigate"] == "/errordetail APP-20261002-1234"
    digest = {"server": "srv2", "window_seconds": 300, "affected_projects": 2, "new_incidents": 2, "severity_counts": {}, "top_affected": [{"project": "shop", "occurrences": 90, "severity": "HIGH", "display_id": "APP-20261002-1234"}],
              "status": "MULTIPLE_APPLICATION_INCIDENTS"}
    payload = dispatcher._build_payload(build_note_event(EventCategory.APPLICATION_ERROR_DIGEST, {"record": "DIGEST", "digest": digest}))
    fields = {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}
    assert "/errordetail APP-20261002-1234" in fields["Top Affected"] and "/errortop 24h" in fields["Investigate"]
    ssh = dispatcher._build_payload(build_note_event(EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE, {"username": "deploy", "source_ip": "203.0.113.9", "brute_force_attempts": 6}, Severity.CRITICAL))
    assert any(f["name"] == "Investigate" and "/sshcheck" in f["value"] for f in ssh["embeds"][0]["fields"])
    print("Test 10 (application alerts and digests name /errordetail <id> and /errortop; suspicious SSH alerts name /sshcheck) PASSED")


async def test_11_alerting_is_unchanged_and_not_amplified():
    flow = await AppFlow().start()
    CLEANUP.append(flow)
    notes = []
    for project in range(30):
        notes.extend(flow.engine.ingest(flow.event(project=f"p{project}", message=f"failure {project}x", count=40, users=10, domain=f"p{project}.example.com")).notifications)
    sent_before = len(notes)
    flow.clock.advance(30)
    notes_tick = flow.engine.tick(flow.clock.t)
    bus = EventBus()
    BUSES.append(bus)
    received = []

    async def on_event(event):
        received.append(event)

    await bus.subscribe("spy", on_event, categories=None)
    await flow.persist()
    await flow.stop()
    service = InvestigationService(InvestigationConfig(), flow.db_path, registry=InvestigationRegistry(), clock=lambda: flow.clock.t + 5, metrics=fresh_metrics())
    for _ in range(25):
        await service.error_top(86400.0)
        await service.error_impact(86400.0)
        await service.ssh_check(3600.0)
    await asyncio.sleep(0.1)
    assert received == [] and flow.engine.tick(flow.clock.t) == [], "repeated investigation never creates alerts or digests"
    assert sent_before <= flow.engine.cfg.notifications.individual_alerts + 1 and sent_before < 30 and notes_tick is not None
    print("Test 11 (the Task I anti-spam budget still caps alerts; repeated investigation commands add no notifications) PASSED")


async def test_12_ssh_monitor_and_key_monitor_snapshots():
    from core.ssh_key_baseline import KeyBaseline, KeyEntry, SourceEntry, UserEntry
    from core.ssh_key_monitor import SshKeyMonitor
    from core.ssh_key_registry import SshKeyRegistry

    tmp = tempfile.mkdtemp(prefix="rtsa-keysnap-")
    CLEANUP.append(SimpleNamespace(cleanup=lambda: shutil.rmtree(tmp, ignore_errors=True)))
    registry = SshKeyRegistry(os.path.join(tmp, "registry.json"))
    TRUSTED_FP = "SHA256:" + "A" * 43
    registry.register(TRUSTED_FP, "owner@example.com", "Owner", key_type="ssh-ed25519", expected_linux_users=["deploy"])
    monitor = SshKeyMonitor.__new__(SshKeyMonitor)
    monitor._lock = threading.RLock()
    monitor.registry = registry
    monitor.config = SimpleNamespace(new_key_window_seconds=604800.0)
    monitor.baseline = KeyBaseline(os.path.join(tmp, "baseline.json"), "srv2")
    monitor.baseline.initialized, monitor.baseline.created_at = True, NOW - 86400
    keys = {TRUSTED_FP: KeyEntry("ssh-ed25519", "owner@example.com", "", [], NOW - 80000, NOW), "SHA256:other": KeyEntry("ssh-rsa", "x", "", ["from"], NOW - 100, NOW)}
    source = SourceEntry("/home/deploy/.ssh/authorized_keys", "USER_HOME", True, False, "", 1001, 1001, "deploy", "deploy", 0o600, NOW - 80000, NOW, keys)
    monitor.baseline.users["deploy"] = UserEntry("deploy", 1001, "/home/deploy", {"authorized_keys_files": [".ssh/authorized_keys"]}, "d", NOW - 80000, NOW, {source.path: source})
    monitor.baseline.additions["deploy|SHA256:other"] = {"first_seen": NOW - 100, "source": source.path, "classification": "UNKNOWN_KEY_CHANGE", "verified": False, "logins": {}}
    monitor.health = lambda: {"initialized": True}
    snap = monitor.investigation_snapshot(max_keys=1)
    assert snap["truncated"] is True and snap["key_count"] == 1 and snap["users"]["deploy"]["home"] == "/home/deploy"
    full = monitor.investigation_snapshot()
    entry = full["users"]["deploy"]["sources"][source.path]["keys"]
    assert entry[TRUSTED_FP]["registry_status"] == "TRUSTED" and entry[TRUSTED_FP]["owner_email"] == "owner@example.com"
    assert True and entry["SHA256:other"]["registry_status"] == "NOT_REGISTERED"
    assert "deploy|SHA256:other" in full["additions"] and not any(isinstance(v, object) and hasattr(v, "__dict__") for v in full["users"].values())
    json.dumps(full)
    holder_ready, holder_release = threading.Event(), threading.Event()

    def hold_lock():
        with monitor._lock:
            holder_ready.set()
            holder_release.wait(5)

    thread = threading.Thread(target=hold_lock)
    thread.start()
    holder_ready.wait(5)
    started = time.monotonic()
    assert monitor.investigation_snapshot(lock_timeout=0.2) == {"busy": True} and time.monotonic() - started < 2.0, "a long reconcile cannot stall the report"
    holder_release.set()
    thread.join()
    assert monitor.investigation_snapshot()["users"], "the lock is released and the snapshot works again"
    print("Test 12 (key monitor snapshot is a bounded, JSON-safe copy with registry status and recent additions) PASSED")


async def test_13_real_ssh_monitor_events_feed_the_report():
    from _ssh_logout_fakes import FAILED, FP, IP, LOGIN_AT, LOGOUT_AT, USER, FrozenClock, accepted, closed, make_monitor, reset_metrics
    reset_metrics()
    tmp = tempfile.mkdtemp(prefix="rtsa-ssh-real-")
    CLEANUP.append(SimpleNamespace(cleanup=lambda: shutil.rmtree(tmp, ignore_errors=True)))
    worker = SQLiteWriteWorker(os.path.join(tmp, "rtsa.db"), flush_interval_seconds=0.05)
    await worker.start()
    sent = 0

    async def flush(events):
        nonlocal sent
        for event in events[sent:]:
            worker.enqueue_event(event)
        sent = len(events)
        await asyncio.sleep(0.4)

    accounts = [{"name": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"}]
    with FrozenClock(LOGIN_AT - 70) as clock:
        mon, pub = make_monitor(logout_policy="INFO")
        for n in range(6):
            clock.at(LOGIN_AT - 60 + n)
            mon._process_line(FAILED.format(user="admin", ip=IP, port=40000 + n), event_time=LOGIN_AT - 60 + n, pid=3000 + n)
        clock.at(LOGIN_AT + 1)
        mon._process_line(accepted(), event_time=LOGIN_AT, pid=4100)
        live = mon.investigation_snapshot()
        assert live["available"] and len(live["sessions"]) == 1 and json.dumps({k: v for k, v in live.items() if k != "keys_fn"})
        assert callable(live["keys_fn"]) and json.dumps(live["keys_fn"]()), "the key baseline is fetched lazily, off the event loop"
        await flush(pub)
        registry = InvestigationRegistry()
        registry.register("ssh", lambda: live)
        service = InvestigationService(InvestigationConfig(), os.path.join(tmp, "rtsa.db"), registry=registry, clock=lambda: LOGIN_AT + 30, metrics=fresh_metrics(), passwd_provider=lambda: accounts)
        during = await service.ssh_check(3600.0)
        active = during["active_sessions"]["items"][0]
        assert during["active_sessions"]["source"] == "LIVE_TRACKER" and active["user"] == USER and active["source_ip"] == IP and active["source_port"] == 21509
        assert active["ssh_port"] == 23109 and active["fingerprint"] == FP and active["key_owner"] == "owner@example.com" and active["sshd_pid"] == 4100 and active["session_id"]
        assert active["key_source"] == "/home/newusproud/.ssh/authorized_keys" and active["auth_method"] == "publickey"
        item = during["logins"]["items"][0]
        assert item["session_id"] == active["session_id"] and item["fingerprint"] == FP and item["status"] == "NO_LOGOUT_OBSERVED" and item["source_port"] == 21509
        assert during["failed"]["total"] == 6 and during["failed"]["unique_ips"] == 1 and during["failed"]["ssh_ports"] == [23109]
        assert during["summary"]["suspicious_correlations"] == 1, "the real failed-then-accepted sequence is correlated"
        clock.at(LOGOUT_AT + 1)
        mon._process_line(closed(), event_time=LOGOUT_AT, pid=4100)
        await flush(pub)
        registry.register("ssh", mon.investigation_snapshot)
        service_after = InvestigationService(InvestigationConfig(), os.path.join(tmp, "rtsa.db"), registry=registry, clock=lambda: LOGOUT_AT + 60, metrics=fresh_metrics(), passwd_provider=lambda: accounts)
        after = await service_after.ssh_check(3600.0)
    closed_item = after["logins"]["items"][0]
    assert closed_item["status"] == "LOGGED_OUT" and closed_item["logout_classification"] == "NORMAL_SESSION_END" and closed_item["duration"] == 754
    assert closed_item["logout_time"] == LOGOUT_AT and closed_item["login_time"] == LOGIN_AT and after["active_sessions"]["items"] == [], "a closed session leaves the live list"
    assert closed_item["session_id"] == active["session_id"], "login and logout are joined by the tracker's session id"
    await worker.stop()
    print("Test 13 (events produced by the real SSH monitor flow through SQLite into the report with the same session id, identity, duration and correlation) PASSED")


async def main() -> None:
    await test_1_service_caches_coalesces_rejects_and_never_writes()
    await test_2_ssh_snapshot_is_taken_on_the_loop_and_used()
    await test_3_bot_commands_are_read_only_ephemeral_and_discord_sized()
    await test_4_unauthorized_users_and_disabled_layer_get_nothing()
    await test_5_tracker_collects_user_ids_with_a_persistent_salt_and_structured_logs()
    await test_6_traffic_recorder_and_nginx_hook()
    await test_7_sqlite_schema_indexes_and_retention()
    test_8_config_defaults_match_yaml_and_are_validated()
    test_9_metrics_are_registered_once_and_exported()
    test_10_alerts_point_to_the_investigation_commands()
    await test_11_alerting_is_unchanged_and_not_amplified()
    await test_12_ssh_monitor_and_key_monitor_snapshots()
    await test_13_real_ssh_monitor_events_feed_the_report()
    for bus in BUSES:
        await bus.shutdown()
    for item in CLEANUP:
        item.cleanup()
    print("\nALL INVESTIGATION INTEGRATION TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
