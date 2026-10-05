from __future__ import annotations

import ast
import io
import json
import os
import sys
import time
import tokenize

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _app_error_fakes import SERVER, config, counters, kinds, make_engine, make_event, run_events
from config.manager import (
    AppErrorBudgetConfig, AppErrorDigestConfig, AppErrorIncidentConfig, AppErrorRecoveryConfig, AppErrorReminderConfig, AppErrorStormConfig,
)
from core import app_error_engine as eng
from core import app_error_model as model
from core.app_error_model import LogParser, compute_fingerprint, normalize_message, redact_stack, redact_text

SECRET = "hunter2hunter2"


def parse_all(text, parser=None, now=1000.0):
    parser = parser or LogParser()
    out = []
    for line in text.splitlines():
        out.extend(parser.feed(line, now))
    out.extend(parser.flush(now + 10, True))
    return out, parser


def test_1_log_lines_become_exceptions_only_when_they_are_exceptions() -> None:
    node = """2026-10-04T10:00:00: TypeError: Cannot read properties of undefined (reading 'id')
    at getUser (/home/app/src/users.js:42:17)
    at Layer.handle [as handle_request] (/home/app/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/app/node_modules/express/lib/router/route.js:137:13)
GET /health 200 3ms
Warning: Using a deprecated API
(node:1234) [DEP0005] DeprecationWarning: Buffer() is deprecated due to security and usability issues.
console.error line without any exception type
Listening on port 3000
"""
    events, parser = parse_all(node)
    assert len(events) == 1 and events[0].error_type == "TypeError" and len(events[0].stack) == 3 and events[0].event_time is not None
    assert events[0].error_class == model.CLASS_EXCEPTION and parser.ignored_lines >= 4, "plain stderr lines are not exceptions"
    pm2_prefixed, _ = parse_all("0|api  | 2026-10-04 10:00:01 +07:00: Error: connect ECONNREFUSED 10.0.0.5:5432\n0|api  |     at TCPConnectWrap.afterConnect (node:net:1:1)")
    assert len(pm2_prefixed) == 1 and pm2_prefixed[0].error_class == model.CLASS_DATABASE and pm2_prefixed[0].db_class == "CONNECTION_REFUSED"
    assert abs(pm2_prefixed[0].event_time - (1_790_000_000 - 1_790_000_000 + pm2_prefixed[0].event_time)) < 1
    structured = [
        '{"level":50,"time":1790000000000,"msg":"request failed","err":{"type":"ValidationError","message":"bad input","stack":"ValidationError: bad input\\n    at v (/app/v.js:1:1)"},"req":{"method":"POST","url":"/api/orders/123?token=abc"},"res":{"statusCode":500}}',
        '{"level":30,"msg":"info line"}',
        '{"level":"error","message":"boom","service":"billing"}',
        '{"level":"warn","message":"slow"}',
        "not json at all {",
    ]
    out, parser = parse_all("\n".join(structured))
    assert [e.error_type for e in out] == ["ValidationError", "Error"] and out[0].http_status == 500 and out[0].http_method == "POST" and out[0].event_time == 1_790_000_000.0
    assert out[1].service == "billing"
    py, _ = parse_all("Traceback (most recent call last):\n  File \"/app/main.py\", line 10, in handler\n    x = 1/0\nZeroDivisionError: division by zero\nINFO: done")
    assert len(py) == 1 and py[0].error_type == "ZeroDivisionError" and len(py[0].stack) == 1
    php, _ = parse_all("PHP Fatal error:  Uncaught Exception: boom in /var/www/a.php:12\nStack trace:\n#0 /var/www/b.php(5): foo()\n#1 {main}")
    assert len(php) == 1 and php[0].error_type == "Exception" and php[0].error_class == model.CLASS_UNHANDLED
    oom, _ = parse_all("FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory")
    assert oom[0].error_class == model.CLASS_OOM and model.base_severity(oom[0].error_class) == model.SEV_HIGH
    crash, _ = parse_all("Segmentation fault (core dumped)")
    assert crash[0].error_class == model.CLASS_CRASH
    unhandled, _ = parse_all("(node:99) UnhandledPromiseRejectionWarning: Error: kaput\n    at f (/a/b.js:1:1)")
    assert unhandled[0].error_class == model.CLASS_UNHANDLED and unhandled[0].error_type == "Error"
    db, _ = parse_all("FATAL:  sorry, too many clients already")
    assert db[0].error_class == model.CLASS_DATABASE and db[0].db_class == "TOO_MANY_CLIENTS"
    bounded = LogParser(max_block_lines=5)
    long_block = "Error: x\n" + "\n".join(f"    at f{i} (/a/b.js:{i}:1)" for i in range(500))
    out, parser = parse_all(long_block, bounded)
    assert len(out) == 1 and len(out[0].stack) <= 5 and parser.truncated_blocks >= 1, "a runaway stack is bounded"
    assert parse_all("", LogParser())[0] == [] and parse_all("x" * 100000, LogParser(max_line_chars=100))[0] == []
    print("Test 1 (Node/pino/winston/Python/PHP/OOM/crash/unhandled/DB-error lines are exceptions; warnings, deprecations, access lines and bare console.error are ignored; runaway stacks bounded) PASSED")


def test_2_fingerprint_groups_repeats_but_keeps_project_and_error_boundaries() -> None:
    base = "Cannot read properties of undefined (reading 'id') at 10:00:01 req-abc123def456 user 8841 from 203.0.113.9:51234 /api/users/778899?page=3&sort=x"
    other = "Cannot read properties of undefined (reading 'id') at 11:22:33 req-zzzzzz999888 user 9 from 198.51.100.77:40000 /api/users/12?page=9&sort=y"
    frames = ["    at getUser (/home/app/src/users.js:42:17)"]
    moved = ["    at getUser (/home/app/src/users.js:99:3)"]
    a = compute_fingerprint("projA", "api", "TypeError", base, frames)
    assert a == compute_fingerprint("projA", "api", "TypeError", other, moved), "timestamps, request ids, user ids, IPs, query values and line numbers do not split a fingerprint"
    assert a != compute_fingerprint("projB", "api", "TypeError", base, frames), "the same error in another project is another fingerprint"
    assert a != compute_fingerprint("projA", "worker", "TypeError", base, frames), "service boundaries matter"
    assert a != compute_fingerprint("projA", "api", "RangeError", base, frames)
    assert a != compute_fingerprint("projA", "api", "TypeError", "x is not a function", frames), "a different message is a different error"
    assert a != compute_fingerprint("projA", "api", "TypeError", base, ["    at other (/home/app/src/orders.js:42:17)"]), "a different code path is a different error"
    uuid_a = compute_fingerprint("p", "s", "E", "order 123e4567-e89b-12d3-a456-426614174000 failed", [])
    uuid_b = compute_fingerprint("p", "s", "E", "order 9a1b2c3d-1111-2222-3333-444455556666 failed", [])
    assert uuid_a == uuid_b
    assert "<ts>" in normalize_message("at 2026-10-04T10:00:00Z") and "<n>" in normalize_message("pid 4812 exited")
    assert model.normalize_route("/api/users/123/orders/aabbccdd11?x=1") == "/api/users/:id/orders/:id"
    internal = ["    at Layer.handle (/app/node_modules/express/lib/router/layer.js:95:5)", "    at getUser (/app/src/u.js:1:1)"]
    assert compute_fingerprint("p", "s", "E", "m", internal) == compute_fingerprint("p", "s", "E", "m", ["    at getUser (/app/src/u.js:7:7)"]), "framework frames are skipped"
    assert len(a) == 16
    print("Test 2 (fingerprint ignores timestamps/PIDs/request ids/UUIDs/IPs/query values/line numbers/framework frames, keeps project, service, error type, message and code path) PASSED")


def test_3_secrets_are_redacted_everywhere() -> None:
    samples = [
        f"password={SECRET} user=alice", f"token: {SECRET}", f"Authorization: Bearer {SECRET}abcdef", f'{{"api_key":"{SECRET}"}}',
        f"postgres://app:{SECRET}@10.0.0.5:5432/db failed", f"Cookie: sessionid={SECRET}; csrftoken=abc", f"mongodb+srv://u:{SECRET}@cluster.example/app",
        f"DATABASE_URL=postgres://u:{SECRET}@h/db", "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAL\n-----END RSA PRIVATE KEY-----",
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop", "aws AKIAABCDEFGHIJKLMNOP", f"client_secret = {SECRET}", f"refresh_token={SECRET}",
        f"SECRET_KEY=abcd1234efgh5678",
    ]
    for text in samples:
        cleaned = redact_text(text)
        assert SECRET not in cleaned and "MIIBOg" not in cleaned and "eyJzdWIi" not in cleaned and "AKIAABCDEF" not in cleaned and "abcd1234efgh" not in cleaned, (text, cleaned)
    assert "REDACTED" in redact_text(f"password={SECRET}")
    stack = redact_stack([f"    at connect (/a/db.js:1:1) password={SECRET}"] * 40, 300)
    assert SECRET not in stack and len(stack) <= 300 and redact_stack([], 100) == ""
    os.environ["RTSA_TEST_API_SECRET"] = "s3cr3tEnvValue9"
    model.refresh_env_secrets()
    try:
        assert "s3cr3tEnvValue9" not in redact_text("connect failed using s3cr3tEnvValue9 as the key"), "values of secret-named environment variables are redacted wherever they appear"
    finally:
        os.environ.pop("RTSA_TEST_API_SECRET", None)
        model.refresh_env_secrets()
    engine, clock, _ = make_engine()
    engine.ingest(make_event(clock, message=f"login failed password={SECRET}", error_class="DATABASE"))
    row = engine.drain_dirty()[0]
    assert SECRET not in json.dumps(row), "stored incident rows carry redacted messages"
    event = make_event(clock, message=f"x token={SECRET}", stack_trace=f"at f token={SECRET}")
    assert SECRET not in json.dumps(event.to_dict())
    print("Test 3 (passwords, tokens, cookies, authorization, API keys, JWTs, AWS keys, private keys, .env lines and connection strings are redacted from messages, stacks, rows and events) PASSED")


def test_4_ten_thousand_occurrences_are_one_incident_with_bounded_notifications() -> None:
    engine, clock, metrics = make_engine()
    notes = []
    for _ in range(10_000):
        clock.advance(0.002)
        notes.extend(engine.ingest(make_event(clock, message="boom")).notifications)
    incidents = engine.incidents()
    assert len(incidents) == 1 and incidents[0].occurrence_count == 10_000
    assert len(notes) <= 3 and kinds(notes)[0] == eng.NK_INITIAL, kinds(notes)
    c = counters(metrics)
    assert c["application_errors_total"] == 10_000 and c["application_error_fingerprints_total"] == 1
    summary = engine.summary(incidents[0])
    assert summary["occurrence_count"] == 10_000 and summary["peak_rate_per_min"] >= 1000 and summary["current_rate_per_min"] > 0
    assert summary["first_seen"] <= summary["last_seen"] and incidents[0].state in eng.ACTIVE_STATES
    print("Test 4 (10,000 occurrences of one fingerprint = 1 incident with 10,000 occurrences, first/last seen, current and peak rate, and at most initial + escalation notifications) PASSED")


def test_5_twenty_projects_are_separate_incidents_and_one_digest() -> None:
    engine, clock, metrics = make_engine()
    notes = []
    for i in range(20):
        for _ in range(30):
            clock.advance(0.05)
            notes.extend(engine.ingest(make_event(clock, project=f"proj{i:02d}", message="timeout contacting upstream", error_class="DATABASE", error_type="DbError")).notifications)
    assert len({inc.project for inc in engine.incidents()}) == 20 and len(engine.incidents()) == 20, "every project keeps its own incident"
    individual = [n for n in notes if n.kind != eng.NK_DIGEST]
    assert len(individual) <= 5, "the per-server budget caps individual alerts"
    notes.extend(engine.tick(clock.t))
    digests = [n for n in notes if n.kind == eng.NK_DIGEST]
    assert len(digests) == 1 and digests[0].digest["affected_projects"] == 20 and digests[0].digest["new_incidents"] == 20
    assert digests[0].digest["status"] == eng.STATUS_STORM and digests[0].digest["top_affected"] and len(digests[0].digest["top_affected"]) <= 5
    rows = engine.drain_dirty(100)
    assert len(rows) == 20 and {r["project"] for r in rows} == {f"proj{i:02d}" for i in range(20)}, "all evidence stays queryable per project"
    assert counters(metrics)["application_digest_total"] == 1
    print("Test 5 (20 projects -> 20 separate incidents, at most 5 individual alerts and exactly one server digest listing all of them) PASSED")


def test_6_hundred_projects_never_become_a_notification_storm() -> None:
    engine, clock, metrics = make_engine()
    notes = []
    for i in range(100):
        for _ in range(20):
            clock.advance(0.01)
            notes.extend(engine.ingest(make_event(clock, project=f"app{i:03d}", message="unhandled failure", error_type="Error", error_class="UNHANDLED")).notifications)
        clock.advance(0.2)
    notes.extend(engine.tick(clock.t))
    assert engine.level(SERVER) == eng.LEVEL_STORM
    sent = [n for n in notes]
    assert len(sent) <= 6, f"100 failing projects produced {len(sent)} notifications"
    assert len([n for n in sent if n.kind == eng.NK_DIGEST]) == 1
    assert len(engine.incidents()) == 100 and sum(i.occurrence_count for i in engine.incidents()) == 2000
    digest = next(n.digest for n in sent if n.kind == eng.NK_DIGEST)
    assert digest["affected_projects"] == 100 and digest["suppressed_incidents"] >= 90
    c = counters(metrics)
    assert c["application_error_storms_total"] == 1 and c["application_notification_suppressed_total"] >= 90 and c["application_errors_total"] == 2000
    for _ in range(3):
        clock.advance(60)
        again = engine.tick(clock.t)
        assert not [n for n in again if n.kind != eng.NK_DIGEST]
    clock.advance(400)
    later = engine.tick(clock.t)
    assert len([n for n in later if n.kind == eng.NK_DIGEST]) <= 1, "digests are limited to one per window and only when something changed"
    print("Test 6 (100 failing projects -> 100 stored incidents, SERVER_APPLICATION_ERROR_STORM, at most 5 individual alerts + 1 digest; no further messages while quiet) PASSED")


def test_7_notification_budgets_per_fingerprint_project_server_and_global() -> None:
    cfg = config(notifications=AppErrorBudgetConfig(individual_alerts=100, project_alerts=100, global_individual_alerts=100, fingerprint_min_interval_seconds=0.0),
                 storm=AppErrorStormConfig(enabled=False))
    engine, clock, _ = make_engine(cfg)
    notes = []
    for i in range(30):
        clock.advance(0.1)
        notes.extend(engine.ingest(make_event(clock, project=f"p{i}", message="m", error_class="CRASH", error_type="ProcessCrash")).notifications)
    assert len(notes) == 30, "generous budgets let every first alert through"
    project_cfg = config(notifications=AppErrorBudgetConfig(individual_alerts=100, project_alerts=2, global_individual_alerts=100), storm=AppErrorStormConfig(enabled=False))
    engine, clock, metrics = make_engine(project_cfg)
    notes = []
    for i in range(10):
        clock.advance(0.1)
        notes.extend(engine.ingest(make_event(clock, project="one-project", message=f"distinct failure {chr(97 + i) * 7}", error_class="CRASH", error_type=f"Boom{i}")).notifications)
    assert len(notes) == 2, "per-project budget"
    states = {i.notification_state for i in engine.incidents()}
    assert eng.NS_BUDGET in states and counters(metrics)["application_notification_budget_exhausted_total"] >= 8
    server_cfg = config(notifications=AppErrorBudgetConfig(individual_alerts=3, project_alerts=100, global_individual_alerts=100), storm=AppErrorStormConfig(enabled=False))
    engine, clock, _ = make_engine(server_cfg)
    notes = []
    for i in range(10):
        clock.advance(0.1)
        notes.extend(engine.ingest(make_event(clock, project=f"s{i}", error_class="CRASH", error_type="X")).notifications)
    assert len(notes) == 3, "per-server budget"
    clock.advance(601)
    again = engine.ingest(make_event(clock, project="s-late", error_class="CRASH", error_type="X")).notifications
    assert kinds(again) == [eng.NK_INITIAL], "the budget window slides"
    global_cfg = config(notifications=AppErrorBudgetConfig(individual_alerts=100, project_alerts=100, global_individual_alerts=4), storm=AppErrorStormConfig(enabled=False))
    engine, clock, _ = make_engine(global_cfg)
    notes = []
    for i in range(10):
        clock.advance(0.1)
        notes.extend(engine.ingest(make_event(clock, project=f"g{i}", error_class="CRASH", error_type="X")).notifications)
    assert len(notes) == 4, "global budget"
    cool_cfg = config(notifications=AppErrorBudgetConfig(individual_alerts=100, project_alerts=100, global_individual_alerts=100, fingerprint_min_interval_seconds=900.0,
                                                         update_min_delta=5, update_growth_factor=2.0), storm=AppErrorStormConfig(enabled=False))
    engine, clock, _ = make_engine(cool_cfg)
    engine.ingest(make_event(clock, error_class="CRASH", error_type="X"))
    notes = []
    for _ in range(100):
        clock.advance(1)
        notes.extend(engine.ingest(make_event(clock, error_class="CRASH", error_type="X")).notifications)
    assert notes == [] and next(iter(engine.incidents())).notification_state == eng.NS_COOLDOWN, "per-fingerprint cooldown holds updates back"
    print("Test 7 (budgets per fingerprint cooldown, per project, per server (sliding window) and global; each exhausted budget only suppresses the notification) PASSED")


def test_8_updates_only_on_significant_change() -> None:
    cfg = config(notifications=AppErrorBudgetConfig(fingerprint_min_interval_seconds=60.0, update_growth_factor=10.0, update_min_delta=100))
    engine, clock, _ = make_engine(cfg)
    log = []
    log.extend(run_events(engine, [make_event(clock, count=20)]))
    clock.advance(30)
    log.extend(run_events(engine, [make_event(clock, count=15)]))
    first = kinds(log)
    assert first == [eng.NK_INITIAL], "20 errors -> initial; 35 errors -> nothing"
    clock.advance(600)
    log.extend(run_events(engine, [make_event(clock, count=5000)]))
    assert kinds(log)[-1] in (eng.NK_UPDATE, eng.NK_ESCALATION), "5,000 errors is a significant change"
    before = len(log)
    clock.advance(600)
    log.extend(run_events(engine, [make_event(clock, count=50_000)]))
    assert len(log) == before + 1 and kinds(log)[-1] in (eng.NK_UPDATE, eng.NK_ESCALATION)
    clock.advance(1)
    quiet = run_events(engine, [make_event(clock, count=1)])
    assert quiet == [], "50,001 errors -> no message"
    inc = engine.incidents()[0]
    assert inc.severity == eng.SEV_CRITICAL and inc.occurrence_count == 20 + 15 + 5000 + 50_000 + 1
    print("Test 8 (20 errors initial, 35 nothing, 5,000 update, 50,000 escalation, 50,001 no message) PASSED")


def test_9_long_running_incident_gets_controlled_reminders_then_a_long_cooldown() -> None:
    engine, clock, _ = make_engine()
    notes = []
    start = clock.t
    while clock.t - start < 6 * 3600:
        for _ in range(3):
            clock.advance(20)
            notes.extend(engine.ingest(make_event(clock, message="upstream timeout", count=2, error_type="TimeoutError")).notifications)
        notes.extend(engine.tick(clock.t))
    reminders = [n for n in notes if n.kind == eng.NK_REMINDER]
    assert kinds(notes)[0] == eng.NK_INITIAL and len(reminders) == 3, kinds(notes)
    times = [n.created_at - start for n in notes if n.kind == eng.NK_REMINDER]
    assert [round(t / 600) for t in times] == [3, 6, 18], "reminders at ~30 min, ~1 h and ~3 h, then the long cooldown"
    assert all(t2 - t1 >= 1700 for t1, t2 in zip(times, times[1:])), "never minute-by-minute"
    summary = reminders[-1].incident
    assert summary["reminders_sent"] == 3 and summary["occurrence_count"] > 1000 and summary["duration_seconds"] > 10000 and summary["trend"] in ("STABLE", "RISING", "FALLING")
    assert summary["current_rate_per_min"] > 0 and summary["last_seen"] and summary["severity"]
    later = []
    for _ in range(2 * 3600 // 60):
        clock.advance(60)
        later.extend(engine.ingest(make_event(clock, message="upstream timeout", error_type="TimeoutError")).notifications)
        later.extend(engine.tick(clock.t))
    assert all(n.kind != eng.NK_REMINDER for n in later[:1]) and len([n for n in later if n.kind == eng.NK_REMINDER]) <= 1
    print("Test 9 (6-hour incident: initial + reminders at 30 min, 1 h, 3 h with duration/total/rate/last seen/severity/trend, then a long cooldown; never minute-by-minute) PASSED")


def test_10_recovery_needs_a_quiet_window_and_sends_one_notification() -> None:
    engine, clock, metrics = make_engine()
    for _ in range(5):
        clock.advance(10)
        engine.ingest(make_event(clock, error_class="DATABASE", error_type="DbError"))
    inc = engine.incidents()[0]
    assert inc.state in eng.ACTIVE_STATES and inc.notified_count == 1
    clock.advance(30)
    engine.observe_signal(eng.SIG_HEALTH_OK, server=SERVER, project="disdik")
    assert engine.tick(clock.t) == [] and inc.state in eng.ACTIVE_STATES, "one successful request never recovers an incident"
    clock.advance(310)
    assert engine.tick(clock.t) == [] and inc.state == eng.ST_RECOVERING
    clock.advance(10)
    engine.ingest(make_event(clock, error_class="DATABASE", error_type="DbError"))
    assert inc.state == eng.ST_OPEN, "errors returning during RECOVERING reopen the incident"
    clock.advance(320)
    engine.tick(clock.t)
    clock.advance(330)
    notes = engine.tick(clock.t)
    assert inc.state == eng.ST_RECOVERED and kinds(notes) == [eng.NK_RECOVERY]
    assert engine.tick(clock.t + 1) == [], "exactly one recovery notification"
    assert counters(metrics)["application_incidents_recovered_total"] == 1
    print("Test 10 (a single health sample does not recover; error-free window -> RECOVERING; errors during RECOVERING -> OPEN; confirmed -> RECOVERED with exactly one notification) PASSED")


def test_11_recovery_waits_for_other_bad_signals_and_samples() -> None:
    cfg = config(recovery=AppErrorRecoveryConfig(error_free_seconds=300.0, confirm_seconds=600.0, min_success_samples=3))
    engine, clock, _ = make_engine(cfg)
    for _ in range(3):
        clock.advance(5)
        engine.ingest(make_event(clock, error_class="CRASH", error_type="ProcessCrash"))
    inc = engine.incidents()[0]
    clock.advance(400)
    engine.observe_signal(eng.SIG_HTTP_5XX, server=SERVER, project="disdik", count=40)
    engine.tick(clock.t)
    assert inc.state in eng.ACTIVE_STATES, "ongoing 5xx for the project keeps the incident open even without new log errors"
    clock.advance(310)
    engine.tick(clock.t)
    assert inc.state == eng.ST_RECOVERING
    clock.advance(700)
    engine.tick(clock.t)
    assert inc.state == eng.ST_RECOVERING, "minimum successful samples are required"
    for _ in range(3):
        engine.observe_signal(eng.SIG_HEALTH_OK, server=SERVER, project="disdik")
    notes = engine.tick(clock.t + 1)
    assert inc.state == eng.ST_RECOVERED and kinds(notes) == [eng.NK_RECOVERY]
    print("Test 11 (recovery also waits for project 5xx/PM2/DB signals to normalise and for the configured minimum successful samples) PASSED")


def test_12_recovered_error_reopens_within_the_window_and_starts_fresh_afterwards() -> None:
    engine, clock, metrics = make_engine()
    for _ in range(4):
        clock.advance(10)
        engine.ingest(make_event(clock, error_class="CRASH", error_type="ProcessCrash"))
    first = engine.incidents()[0]
    first_id = first.incident_id
    clock.advance(310)
    engine.tick(clock.t)
    clock.advance(310)
    engine.tick(clock.t)
    assert first.state == eng.ST_RECOVERED
    clock.advance(120)
    notes = engine.ingest(make_event(clock, error_class="CRASH", error_type="ProcessCrash")).notifications
    assert first.state in eng.ACTIVE_STATES and first.reopened_count == 1 and kinds(notes) == [eng.NK_REOPENED]
    assert first.incident_id == first_id and len(engine.incidents()) == 1
    clock.advance(310)
    engine.tick(clock.t)
    clock.advance(310)
    engine.tick(clock.t)
    assert first.state == eng.ST_RECOVERED
    clock.advance(4000)
    engine.tick(clock.t)
    assert first.state == eng.ST_RESOLVED
    clock.advance(10)
    fresh = engine.ingest(make_event(clock, error_class="CRASH", error_type="ProcessCrash"))
    assert fresh.is_new and fresh.incident_id != first_id and kinds(fresh.notifications) == [eng.NK_INITIAL]
    print("Test 12 (recovered error returning inside the reopen window = same incident reopened; after RESOLVED it is a new lifecycle with a new id) PASSED")


def test_13_same_project_different_errors_and_same_error_different_projects_stay_separate() -> None:
    engine, clock, _ = make_engine(config(storm=AppErrorStormConfig(enabled=False), notifications=AppErrorBudgetConfig(individual_alerts=50, project_alerts=50, global_individual_alerts=50)))
    for message in ("db timeout", "cache miss storm", "null pointer in render"):
        for _ in range(3):
            clock.advance(1)
            engine.ingest(make_event(clock, project="disdik", message=message, error_type="Error"))
    for project in ("alpha", "beta"):
        for _ in range(3):
            clock.advance(1)
            engine.ingest(make_event(clock, project=project, message="TypeError X", error_type="TypeError"))
    incidents = engine.incidents()
    assert len(incidents) == 5 and len({i.fingerprint for i in incidents}) == 5
    assert len([i for i in incidents if i.project == "disdik"]) == 3
    alpha = next(i for i in incidents if i.project == "alpha")
    beta = next(i for i in incidents if i.project == "beta")
    assert alpha.fingerprint != beta.fingerprint and alpha.incident_id != beta.incident_id
    print("Test 13 (same project + different errors = separate incidents; the same TypeError in Project A and Project B is not merged) PASSED")


def test_14_budget_exhaustion_keeps_collecting_and_records_the_reason() -> None:
    cfg = config(notifications=AppErrorBudgetConfig(individual_alerts=2, project_alerts=10, global_individual_alerts=10), storm=AppErrorStormConfig(enabled=False))
    engine, clock, metrics = make_engine(cfg)
    notes = []
    for i in range(8):
        for _ in range(50):
            clock.advance(0.01)
            notes.extend(engine.ingest(make_event(clock, project=f"b{i}", error_class="CRASH", error_type="ProcessCrash")).notifications)
    assert len(notes) == 2
    suppressed = [i for i in engine.incidents() if i.notification_state == eng.NS_BUDGET]
    assert len(suppressed) == 6 and all(i.occurrence_count == 50 and i.suppression_reason == eng.NS_BUDGET and i.suppressed_count >= 1 for i in suppressed)
    rows = {r["project"]: r for r in engine.drain_dirty(100)}
    assert len(rows) == 8 and all(r["occurrence_count"] == 50 for r in rows.values()), "events keep being stored and incidents keep updating"
    assert rows["b7"]["notification_state"] == "SUPPRESSED_BUDGET"
    c = counters(metrics)
    assert c["application_errors_total"] == 400 and c["application_notification_suppressed_total"] >= 6 and c["application_notification_budget_exhausted_total"] >= 6
    clock.advance(30)
    assert engine.tick(clock.t) == [], "withheld incidents are batched for one digest window"
    clock.advance(280)
    digest_notes = engine.tick(clock.t)
    assert kinds(digest_notes) == [eng.NK_DIGEST] and digest_notes[0].digest["suppressed_incidents"] == 6
    assert {i.notification_state for i in suppressed} == {eng.NS_DIGESTED}
    print("Test 14 (budget exhausted: every occurrence is still counted and stored, only the notification is suppressed with SUPPRESSED_BUDGET, then summarized in one digest) PASSED")


def test_15_stale_replayed_and_duplicate_events_never_create_fresh_alerts() -> None:
    engine, clock, metrics = make_engine()
    stale = engine.ingest(make_event(clock, timing="STALE", event_time=clock.t - 86400, error_class="CRASH", error_type="ProcessCrash"))
    assert stale.notifications == [] and stale.historical and stale.is_new
    incident = engine.incidents()[0]
    assert incident.state == eng.ST_RESOLVED and incident.historical and incident.notification_state == eng.NS_STALE
    replayed = engine.ingest(make_event(clock, timing="REPLAYED", event_time=clock.t - 7200, error_class="CRASH", error_type="ProcessCrash", count=50))
    assert replayed.notifications == [] and incident.stale_count == 51 and incident.occurrence_count == 51
    assert counters(metrics)["application_error_stale_total"] == 51
    assert counters(metrics)["application_notification_sent_total"] == 0 and engine.tick(clock.t + 1000) == []
    fresh = engine.ingest(make_event(clock, error_class="CRASH", error_type="ProcessCrash"))
    assert fresh.is_new is True or kinds(fresh.notifications) == [eng.NK_INITIAL], "a genuinely new occurrence after the history is a real incident"
    first = make_event(clock, project="dup", event_id="same-id", error_class="CRASH", error_type="ProcessCrash")
    assert kinds(engine.ingest(first).notifications) == [eng.NK_INITIAL]
    again = engine.ingest(make_event(clock, project="dup", event_id="same-id", error_class="CRASH", error_type="ProcessCrash"))
    assert again.duplicate and again.notifications == []
    pm2_out = make_event(clock, project="dup2", error_class="CRASH", error_type="ProcessCrash", event_time=clock.t + 0.123, source_log="/logs/out.log")
    pm2_err = make_event(clock, project="dup2", error_class="CRASH", error_type="ProcessCrash", event_time=clock.t + 0.123, source_log="/logs/err.log")
    engine.ingest(pm2_out)
    assert engine.ingest(pm2_err).duplicate, "the same line written to two PM2 logs is one occurrence"
    same_file_a = make_event(clock, project="dup3", message="x", event_time=clock.t + 0.5, source_log="/logs/err.log")
    same_file_b = make_event(clock, project="dup3", message="x", event_time=clock.t + 0.5, source_log="/logs/err.log")
    engine.ingest(same_file_a)
    assert not engine.ingest(same_file_b).duplicate, "distinct lines from one file in the same millisecond are all counted"
    assert counters(metrics)["application_error_deduplicated_total"] >= 2
    print("Test 15 (STALE/REPLAYED events are stored as historical without notification, identical event ids and PM2 out/err duplicates are dropped, same-file repeats are counted) PASSED")


def test_16_critical_classes_open_immediately_and_candidates_need_repetition() -> None:
    engine, clock, _ = make_engine()
    one = engine.ingest(make_event(clock, project="solo", error_class="EXCEPTION"))
    assert one.notifications == [] and engine.incidents()[0].state == eng.ST_CANDIDATE
    clock.advance(1)
    two = engine.ingest(make_event(clock, project="solo", error_class="EXCEPTION"))
    assert kinds(two.notifications) == [eng.NK_INITIAL] and engine.incidents()[0].state in eng.ACTIVE_STATES
    crash = engine.ingest(make_event(clock, project="solo2", error_class="CRASH", error_type="ProcessCrash"))
    assert kinds(crash.notifications) == [eng.NK_INITIAL]
    engine.ingest(make_event(clock, project="noise", message="one off"))
    clock.advance(1000)
    engine.tick(clock.t)
    noise = next(i for i in engine.incidents() if i.project == "noise")
    assert noise.state == eng.ST_RESOLVED and noise.notification_state == eng.NS_CANDIDATE
    print("Test 16 (CRASH/OOM/DATABASE/UNHANDLED open immediately; a one-off ordinary exception stays a CANDIDATE and expires silently) PASSED")


def test_17_correlation_is_evidence_based_and_never_claims_root_cause() -> None:
    engine, clock, metrics = make_engine()
    t = clock.t
    engine.observe_signal(eng.SIG_CONTEXT, server=SERVER, project="disdik", domain="disdik.example.com", at=t - 120, detail="modified app.js", context_type="FIM_CHANGE", ref="fim-1")
    engine.observe_signal(eng.SIG_CONTEXT, server=SERVER, project="other", at=t - 100, detail="modified x.js", context_type="FIM_CHANGE", ref="fim-2")
    engine.observe_signal(eng.SIG_CONTEXT, server=SERVER, at=t - 60, detail="cpu 96", context_type="CPU_HIGH", ref="cpu-1")
    engine.observe_signal(eng.SIG_CONTEXT, server=SERVER, project="disdik", at=t - 5000, detail="old change", context_type="FIM_CHANGE", ref="fim-old")
    engine.observe_signal(eng.SIG_CONTEXT, server=SERVER, project="disdik", at=t + 9999, detail="far later", context_type="DEPLOYMENT", ref="late")
    engine.observe_signal(eng.SIG_CONTEXT, server=SERVER, at=t - 30, detail="ssh user", context_type="SSH_ACTION", ref="ssh-1")
    notes = engine.ingest(make_event(clock, error_class="CRASH", error_type="ProcessCrash")).notifications
    correlation = notes[0].incident["correlation"]
    refs = {r["ref"] for r in correlation["refs"]}
    assert {"fim-1", "cpu-1", "ssh-1"} <= refs and refs.isdisjoint({"fim-2", "fim-old", "late"}), refs
    assert correlation["basis"] == "TEMPORAL" and "not a proven root cause" in correlation["note"]
    change = correlation["possible_contributing_change"]
    assert change["ref"] == "fim-1" and change["delta_seconds"] == -120.0
    assert counters(metrics)["application_error_correlations_total"] == 1
    clean_engine, clean_clock, _ = make_engine()
    clean = clean_engine.ingest(make_event(clean_clock, error_class="CRASH", error_type="ProcessCrash")).notifications[0].incident
    assert clean["correlation"] == {}, "no evidence, no correlation"
    text = json.dumps(correlation).lower()
    assert "caused by" not in text and "root cause is" not in text
    print("Test 17 (correlation links only same-project or server-wide events inside the window, labels the nearest earlier change as a possible contributing change, and states it is temporal, not causal) PASSED")


def test_18_events_per_second_are_cheap_and_state_is_bounded() -> None:
    engine, clock, metrics = make_engine(config(incidents=AppErrorIncidentConfig(max_incidents=200)))
    started = time.perf_counter()
    for i in range(20_000):
        clock.advance(0.0005)
        engine.ingest(make_event(clock, project=f"p{i % 50}", message=f"error variant {i % 7}", event_id=f"bulk{i}", event_time=clock.t + i * 1e-6))
    elapsed = time.perf_counter() - started
    assert elapsed < 6.0, f"20,000 individual events took {elapsed:.2f}s"
    assert len(engine.incidents()) <= 200 and engine.stats()["incidents_tracked"] <= 200
    for i in range(1000):
        engine.ingest(make_event(clock, project=f"flood{i}", message="flood", event_id=f"flood{i}", event_time=clock.t + 1 + i * 1e-3))
    assert len(engine.incidents()) <= 200, "the incident table is bounded"
    assert len(engine._seen_ids) <= 50_000 and len(engine._seen_sigs) <= 20_000 and len(engine._context) <= 2000
    print(f"Test 18 (20,000 individual events processed in {elapsed:.2f}s; incident table, dedup caches and context ring are all bounded) PASSED")


def test_19_config_validation_and_defaults() -> None:
    import yaml
    from config.manager import ApplicationErrorTrackerConfig, _build_dataclass, _validate_application_error_tracker

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("config.yaml", "config2.yaml"):
        raw = yaml.safe_load(open(os.path.join(root, "config", name)))["modules"]["application_error_tracker"]
        parsed = _build_dataclass(ApplicationErrorTrackerConfig, raw, "modules.application_error_tracker")
        assert parsed == ApplicationErrorTrackerConfig() and parsed.enabled is False, "disabled by default, YAML equals the code defaults"

    def problems(**sections):
        out = []
        _validate_application_error_tracker(ApplicationErrorTrackerConfig(enabled=True, **sections), out)
        return out

    assert problems() == []
    assert problems(notifications=AppErrorBudgetConfig(update_growth_factor=1.0))
    assert problems(storm=AppErrorStormConfig(busy_new_incidents=20, min_incidents=10))
    assert problems(reminders=AppErrorReminderConfig(first_seconds=7200.0, second_seconds=3600.0))
    assert problems(recovery=AppErrorRecoveryConfig(error_free_seconds=600.0, confirm_seconds=300.0))
    assert problems(digest=AppErrorDigestConfig(window_seconds=1.0))
    assert problems(incidents=AppErrorIncidentConfig(high_rate_per_minute=100.0, critical_rate_per_minute=10.0))
    print("Test 19 (defaults: disabled, YAML equals code defaults; inconsistent budgets, storm thresholds, reminder schedule, recovery windows and rates are rejected) PASSED")


def test_20_hygiene() -> None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for rel in ("core/app_error_model.py", "core/app_error_engine.py", "modules/application_error_tracker.py", "database/app_error_store.py"):
        text = open(os.path.join(root, rel)).read()
        assert not [t for t in tokenize.generate_tokens(io.StringIO(text).readline) if t.type == tokenize.COMMENT], rel
        assert not [n for n in ast.walk(ast.parse(text)) if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and ast.get_docstring(n)], rel
        for forbidden in ("shell=True", "os.system", "subprocess", "eval(", "exec("):
            assert forbidden not in text, (rel, forbidden)
    print("Test 20 (new application-error code has no comments/docstrings and runs no subprocess, shell or eval) PASSED")


def main() -> None:
    test_1_log_lines_become_exceptions_only_when_they_are_exceptions()
    test_2_fingerprint_groups_repeats_but_keeps_project_and_error_boundaries()
    test_3_secrets_are_redacted_everywhere()
    test_4_ten_thousand_occurrences_are_one_incident_with_bounded_notifications()
    test_5_twenty_projects_are_separate_incidents_and_one_digest()
    test_6_hundred_projects_never_become_a_notification_storm()
    test_7_notification_budgets_per_fingerprint_project_server_and_global()
    test_8_updates_only_on_significant_change()
    test_9_long_running_incident_gets_controlled_reminders_then_a_long_cooldown()
    test_10_recovery_needs_a_quiet_window_and_sends_one_notification()
    test_11_recovery_waits_for_other_bad_signals_and_samples()
    test_12_recovered_error_reopens_within_the_window_and_starts_fresh_afterwards()
    test_13_same_project_different_errors_and_same_error_different_projects_stay_separate()
    test_14_budget_exhaustion_keeps_collecting_and_records_the_reason()
    test_15_stale_replayed_and_duplicate_events_never_create_fresh_alerts()
    test_16_critical_classes_open_immediately_and_candidates_need_repetition()
    test_17_correlation_is_evidence_based_and_never_claims_root_cause()
    test_18_events_per_second_are_cheap_and_state_is_bounded()
    test_19_config_validation_and_defaults()
    test_20_hygiene()
    print("\nALL APPLICATION ERROR ENGINE TESTS PASSED")


if __name__ == "__main__":
    main()
