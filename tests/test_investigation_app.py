from __future__ import annotations

import ast
import asyncio
import io
import json
import os
import re
import sqlite3
import sys
import time
import tokenize

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _app_error_fakes import SERVER, T0
from _investigation_fakes import SALT, AppFlow, run_detail, run_impact, run_top
from config.manager import InvestigationAppConfig, InvestigationConfig
from core import app_error_engine as eng
from core import investigation_format as fmt
from core.app_error_model import display_incident_id, hash_user_id
from core.hll import HyperLogLog
from database import app_error_store

FLOWS = []


async def new_flow(**kwargs) -> AppFlow:
    flow = await AppFlow(**kwargs).start()
    FLOWS.append(flow)
    return flow


def top_text(report):
    return fmt.sections_to_text("t", "h", fmt.top_sections(report))


def insert_events(db_path, rows):
    conn = sqlite3.connect(db_path)
    for index, (ts, category, severity, meta, message) in enumerate(rows):
        conn.execute(
            "INSERT INTO events (event_id, timestamp, source_module, category, severity, message, raw, host, metadata) VALUES (?,?,?,?,?,?,?,?,?)",
            (f"ctx{index}-{int(ts)}", ts, "test", category, severity, message, "", "h", json.dumps(meta)),
        )
    conn.commit()
    conn.close()


def only(report, project):
    return [i for i in report["items"] if i["project"] == project][0]


async def test_1_one_project_one_error():
    flow = await new_flow()
    flow.engine.ingest(flow.event(project="disdik", message="Cannot read properties of undefined", count=5, route="/api/items/42", status=500, domain="disdik.example.com"))
    flow.clock.advance(30)
    await flow.persist()
    await flow.stop()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    assert len(report["items"]) == 1 and report["total_incidents"] == 1 and report["projects"] == 1
    item = report["items"][0]
    assert re.fullmatch(r"APP-\d{8}-\d{4}", item["display_id"]) and item["project"] == "disdik" and item["error_type"] == "TypeError"
    assert item["occurrences"] == 5 and item["occurrence_basis"] == "HOURLY_BUCKETS" and item["status"] == "ACTIVE" and item["routes"][0][0] == "/api/items/:id"
    assert item["affected_users"] is None and item["error_rate"]["percent"] is None and item["http_5xx"] == 5
    text = top_text(report)
    assert "Affected Users: UNKNOWN / NOT AVAILABLE" in text and "Error Rate: UNKNOWN" in text and item["display_id"] in text and f"/errordetail {item['display_id']}" in text
    print("Test 1 (one project, one error: one ranked incident with display id, routes, status and an explicit UNKNOWN for users and error rate) PASSED")


async def test_2_ten_thousand_repeats_stay_one_incident():
    flow = await new_flow()
    for _ in range(10000):
        flow.engine.ingest(flow.event(project="disdik", message="Connection reset by peer", count=1, domain="disdik.example.com"))
    flow.clock.advance(20)
    await flow.persist()
    await flow.stop()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    assert report["total_incidents"] == 1 and report["items"][0]["occurrences"] == 10000 and report["items"][0]["occurrences_total"] == 10000
    conn = sqlite3.connect(flow.db_path)
    assert conn.execute("SELECT count(*) FROM app_error_incidents").fetchone()[0] == 1
    assert conn.execute("SELECT SUM(occurrences) FROM app_error_hourly").fetchone()[0] == 10000, "hourly deltas are added exactly once"
    conn.close()
    print("Test 2 (10,000 repeats: one incident, exact windowed occurrences, hourly buckets added once) PASSED")


async def test_3_multiple_projects_rank_by_impact_and_users_are_not_double_counted():
    flow = await new_flow()
    plan = [("alpha", 3000, 3000), ("bravo", 9000, 40), ("charlie", 50000, 0), ("delta", 10, 5), ("echo", 800, 800)]
    for project, occurrences, users in plan:
        flow.engine.ingest(flow.event(project=project, message=f"{project} failure", count=occurrences, users=min(users, occurrences), domain=f"{project}.example.com"))
    flow.engine.ingest(flow.event(project="alpha", error_type="RangeError", message="alpha second failure", count=3000, users=3000, user_base=1500, domain="alpha.example.com"))
    flow.clock.advance(30)
    await flow.persist()
    await flow.stop()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    order = [i["project"] for i in report["items"]]
    assert order[0] == "alpha" and order.index("echo") < order.index("bravo") < order.index("delta") and report["projects"] == 5
    assert only(report, "charlie")["affected_users"] is None
    impact = run_impact(flow.db_path, 86400.0, flow.clock.t)
    alpha = [p for p in impact["projects"] if p["project"] == "alpha"][0]
    assert alpha["incidents"] == 2 and 4200 <= alpha["affected_users"] <= 4800, "distinct users across one project's incidents are merged, not summed (union is 4,500)"
    assert impact["projects"][0]["project"] == "alpha" and impact["total_projects"] == 5
    text = fmt.sections_to_text("t", "h", fmt.impact_sections(impact))
    assert "#1 alpha" in text and "distinct (estimate)" in text and "UNKNOWN / NOT AVAILABLE" in text
    print("Test 3 (multiple projects ranked by impact; project users are the union of the incident sketches, never the sum) PASSED")


async def test_4_occurrence_volume_is_not_user_impact():
    flow = await new_flow()
    flow.engine.ingest(flow.event(project="loud", message="loud failure", count=10000, users=2, domain="loud.example.com"))
    flow.engine.ingest(flow.event(project="wide", message="wide failure", count=500, users=480, domain="wide.example.com"))
    flow.engine.ingest(flow.event(project="tiny", message="tiny failure", count=3, users=3, domain="tiny.example.com"))
    flow.engine.ingest(flow.event(project="noisy", message="noisy failure", count=5000, users=10, domain="noisy.example.com"))
    flow.engine.ingest(flow.event(project="broad", message="broad failure", count=600, users=580, domain="broad.example.com"))
    flow.clock.advance(30)
    await flow.persist()
    await flow.stop()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    order = [i["project"] for i in report["items"]]
    assert order.index("wide") < order.index("loud") and order.index("broad") < order.index("noisy"), "high user impact outranks high raw volume"
    assert order.index("noisy") < order.index("loud"), "10 users beat 2 users at similar volume"
    wide, loud = only(report, "wide"), only(report, "loud")
    assert wide["occurrences"] < loud["occurrences"] and wide["score"] > loud["score"] and wide["components"]["users"] > loud["components"]["users"]
    assert any("users affected" in r for r in wide["reasons"]) and wide["components"]["occurrences"] <= 10.0
    assert 440 <= wide["affected_users"] <= 520 and loud["affected_users"] == 2
    print("Test 4 (10,000 occurrences from 2 users rank below 500 occurrences from ~480 users; volume contributes at most 10 of 100 points) PASSED")


async def test_5_low_occurrences_high_users_and_no_fabricated_users():
    flow = await new_flow()
    flow.engine.ingest(flow.event(project="checkout", message="payment widget crash", count=40, users=38, domain="checkout.example.com"))
    flow.engine.ingest(flow.event(project="batch", message="nightly export failed", count=40, domain="batch.example.com"))
    flow.clock.advance(30)
    await flow.persist()
    await flow.stop()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    checkout, batch = only(report, "checkout"), only(report, "batch")
    assert checkout["affected_users"] and 35 <= checkout["affected_users"] <= 41 and batch["affected_users"] is None
    assert batch["components"]["users"] == 0.0 and any("affected users unknown" in r for r in batch["reasons"])
    assert checkout["score"] > batch["score"]
    text = top_text(report)
    assert text.count("UNKNOWN / NOT AVAILABLE") == 1, "only the incident without user identifiers reports unknown users"
    gaps = " ".join(report["data_gaps"])
    assert "AFFECTED_USERS_UNKNOWN" in gaps and "ERROR_RATE_UNKNOWN" in gaps
    detail = run_detail(flow.db_path, batch["display_id"], flow.clock.t + 10)
    assert detail["affected_users"] is None and "UNKNOWN / NOT AVAILABLE" in fmt.sections_to_text("t", "h", fmt.detail_sections(detail)) and "no user identifier" in detail["brief"]
    print("Test 5 (few occurrences but many users ranks first; missing user data is UNKNOWN / NOT AVAILABLE and never estimated) PASSED")


async def test_6_error_rate_comes_from_stored_traffic_only():
    flow = await new_flow()
    flow.engine.ingest(flow.event(project="shop", message="upstream timeout", count=300, users=250, domain="shop.example.com", status=504, route="/checkout"))
    flow.engine.ingest(flow.event(project="blog", message="template error", count=300, users=250, domain="blog.example.com"))
    flow.clock.advance(30)
    await flow.persist()
    hour = int(flow.clock.t // 3600)
    flow.worker.enqueue_traffic_hourly([("shop.example.com", hour, 20000, 400, 600), ("shop.example.com", hour - 1, 10000, 100, 200)])
    flow.worker.enqueue_traffic_hourly([("shop.example.com", hour, 1000, 0, 100)])
    await flow.settle(flow.worker.stats["written"] + 2)
    await flow.stop()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    shop, blog = only(report, "shop"), only(report, "blog")
    assert shop["error_rate"]["requests"] == 31000 and shop["error_rate"]["status_5xx"] == 900 and shop["error_rate"]["percent"] == round(100 * 900 / 31000, 2), "hourly upserts add up"
    assert blog["error_rate"]["percent"] is None and blog["error_rate"]["requests"] is None, "no stored traffic means UNKNOWN, not 0%"
    assert any("returned 5xx in the window" in r for r in shop["reasons"]) and shop["components"]["error_rate"] > 0 == blog["components"]["error_rate"]
    print("Test 6 (error rate is the stored nginx 5xx share per domain; hourly traffic upserts accumulate; absent traffic stays UNKNOWN) PASSED")


async def test_7_long_running_incident():
    flow = await new_flow()
    for hour in range(5):
        flow.engine.ingest(flow.event(project="portal", message="session store unavailable", count=60, users=40, user_base=hour * 10, domain="portal.example.com"))
        flow.clock.advance(3600)
        await flow.persist()
    flow.clock.advance(-3500)
    await flow.stop()
    short = run_top(flow.db_path, 3 * 3600.0, flow.clock.t)
    full = run_top(flow.db_path, 86400.0, flow.clock.t)
    item = full["items"][0]
    assert item["duration_seconds"] >= 4 * 3600 and any("long-running issue" in r for r in item["reasons"]) and item["components"]["duration"] >= 2.9
    assert item["occurrences"] == 300 and short["items"][0]["occurrences"] < 300 and short["items"][0]["occurrence_basis"] == "HOURLY_BUCKETS", "window sums come from hourly buckets"
    assert 72 <= item["affected_users"] <= 90 and item["first_seen_before_window"] is False and short["items"][0]["first_seen_before_window"] is True
    assert any("covers the whole incident" in r for r in short["items"][0]["reasons"]), "lifetime user counts are labelled when the incident predates the window"
    print("Test 7 (long-running incident: duration scored, windowed occurrences from hourly buckets, lifetime user scope disclosed) PASSED")


async def test_8_recovered_incident_ranks_below_an_active_twin():
    flow = await new_flow()
    flow.engine.ingest(flow.event(project="old", message="legacy failure", count=200, users=150, domain="old.example.com"))
    flow.clock.advance(400)
    flow.engine.tick(flow.clock.t)
    flow.clock.advance(700)
    flow.engine.tick(flow.clock.t)
    flow.engine.ingest(flow.event(project="live", message="legacy failure", count=200, users=150, domain="live.example.com"))
    flow.clock.advance(20)
    await flow.persist()
    await flow.stop()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    old, live = only(report, "old"), only(report, "live")
    assert old["status"] == "RECOVERED" and live["status"] == "ACTIVE" and live["score"] > old["score"] and any("already recovered" in r for r in old["reasons"])
    assert [i["project"] for i in report["items"]][0] == "live" and report["active_incidents"] == 1
    print("Test 8 (a recovered incident stays visible but ranks below an equally impactful active one) PASSED")


async def test_9_multiple_servers_are_separate_incidents_and_widen_impact():
    flow = await new_flow()
    first = flow.event(project="api", message="redis timeout", count=100, users=80, domain="api.example.com")
    second = flow.event(project="api", message="redis timeout", count=100, users=80, user_base=40, domain="api.example.com")
    second.server = "srv3"
    flow.engine.ingest(first)
    flow.engine.ingest(second)
    flow.clock.advance(20)
    await flow.persist()
    await flow.stop()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    assert {tuple(i["servers"]) for i in report["items"]} == {(SERVER,), ("srv3",)}
    conn = sqlite3.connect(flow.db_path)
    row = json.loads(conn.execute("SELECT data FROM app_error_incidents LIMIT 1").fetchone()[0])
    row["servers"] = ["srv2", "srv3"]
    conn.execute("UPDATE app_error_incidents SET data = ? WHERE incident_id = ?", (json.dumps(row), row["incident_id"]))
    conn.commit()
    conn.close()
    widened = run_top(flow.db_path, 86400.0, flow.clock.t)
    item = [i for i in widened["items"] if i["incident_id"] == row["incident_id"]][0]
    assert item["servers"] == ["srv2", "srv3"] and any("seen on 2 servers" in r for r in item["reasons"])
    assert "Servers: srv2, srv3" in fmt.sections_to_text("t", "h", fmt.detail_sections(run_detail(flow.db_path, item["display_id"], flow.clock.t + 5)))
    print("Test 9 (the same error on two servers is two incidents; an incident seen on several servers gains breadth and lists them) PASSED")


async def test_10_error_storm_is_bounded_and_ranked():
    flow = await new_flow()
    for project in range(40):
        for kind, wording in enumerate(("upstream timeout", "connection refused", "bad gateway")):
            flow.engine.ingest(flow.event(
                project=f"site{project:02d}", error_type="HTTPError", message=wording, count=50 + project, users=(project * 10 if kind == 0 else 0),
                domain=f"site{project:02d}.example.com", status=502, error_class="HTTP_5XX",
            ))
    flow.clock.advance(30)
    flow.engine.tick(flow.clock.t)
    await flow.persist()
    await flow.stop()
    started = time.monotonic()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    elapsed = time.monotonic() - started
    assert report["total_incidents"] == 120 and len(report["items"]) == 10 and report["projects"] == 40 and elapsed < 3.0
    assert report["store"]["queries"] <= 8 and report["items"][0]["project"] == "site39" and not report["truncated"]
    pages = fmt.paginate("h", fmt.top_sections(report))
    assert len(pages) <= 10 and all(len(page) <= 25 and all(len(b) <= 1024 for _t, b in page) for page in pages)
    impact = run_impact(flow.db_path, 86400.0, flow.clock.t)
    assert impact["total_projects"] == 40 and len(impact["projects"]) == 10
    print("Test 10 (error storm of 120 incidents across 40 projects: top 10 only, a handful of queries, Discord-sized pages) PASSED")


async def test_11_database_impact_outranks_a_plain_exception():
    flow = await new_flow()
    flow.engine.ingest(flow.event(project="dbapp", error_type="DatabaseError", message="too many connections", error_class="DATABASE", count=100, users=20, domain="dbapp.example.com"))
    flow.engine.ingest(flow.event(project="plain", error_type="TypeError", message="undefined is not a function", count=100, users=20, domain="plain.example.com"))
    flow.clock.advance(20)
    await flow.persist()
    await flow.stop()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    db_item, plain = only(report, "dbapp"), only(report, "plain")
    assert db_item["db_errors"] == 100 and plain["db_errors"] == 0 and db_item["score"] > plain["score"]
    assert any("database error occurrence" in r for r in db_item["reasons"]) and db_item["components"]["infrastructure"] == 4.0 + 0.0
    print("Test 11 (database errors add infrastructure impact and are named in the reasons) PASSED")


async def test_12_pm2_crash_and_oom():
    flow = await new_flow()
    flow.engine.ingest(flow.event(project="worker", error_type="OutOfMemoryError", message="heap out of memory", error_class="OOM", count=4, users=0, domain="worker.example.com", pm2_app="worker-1"))
    flow.engine.observe_signal(eng.SIG_PM2_CRASH, server=SERVER, project="worker", domain="worker.example.com", detail="worker-1 errored", context_type="PM2_DOWN")
    flow.clock.advance(20)
    await flow.persist()
    await flow.stop()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    item = only(report, "worker")
    assert item["crashes"] == 4 and item["pm2_apps"] == ["worker-1"] and any("crash/OOM" in r for r in item["reasons"]) and item["components"]["infrastructure"] >= 6.0
    assert item["priority"] in ("MEDIUM", "HIGH", "CRITICAL") and item["severity"] == "HIGH"
    print("Test 12 (PM2 crash/OOM: crash count, PM2 app and infrastructure points are visible in the ranking) PASSED")


async def test_13_fim_and_deployment_correlation_is_evidence_not_cause():
    flow = await new_flow()
    flow.engine.observe_signal(eng.SIG_CONTEXT, server=SERVER, project="disdik", domain="disdik.example.com", at=T0 - 120, detail="MODIFIED app.js", context_type="FIM_CHANGE", ref="fim1")
    flow.engine.ingest(flow.event(project="disdik", message="Cannot read properties of undefined", count=80, users=60, domain="disdik.example.com", route="/api/list", status=500,
                                  frames=["at handler (/app/src/list.js:10:5)"]))
    flow.clock.advance(60)
    await flow.persist()
    await flow.stop()
    row = json.loads(sqlite3.connect(flow.db_path).execute("SELECT data FROM app_error_incidents").fetchone()[0])
    assert row["correlation"].get("refs"), "the existing engine correlated the FIM change at open time"
    insert_events(flow.db_path, [
        (T0 - 120, "FILE_INTEGRITY_CHANGE", "HIGH", {"domain": "disdik.example.com", "path": "/home/u/htdocs/disdik.example.com/app.js", "change_type": "MODIFIED"}, "app.js modified"),
        (T0 - 100, "CLOUDPANEL_ENV_CHANGED", "MEDIUM", {"domain": "disdik.example.com"}, "env changed"),
        (T0 + 10, "LB_DB_CONNECTIVITY_FAILURE", "HIGH", {}, "db connectivity failure token=shouldnotappear"),
        (T0 + 30, "NGINX_ERROR_SPIKE", "HIGH", {"status_counts": {"502": 30}}, "nginx 5xx spike"),
        (T0 - 300, "SSH_AUTH", "LOW", {"success": True, "username": "deploy", "source_ip": "198.51.100.7"}, "ssh login"),
        (T0 - 290, "BRUTE_FORCE", "HIGH", {"source_ip": "203.0.113.9"}, "brute force"),
        (T0 + 5, "HEALTH_STATUS", "HIGH", {"state": "HIGH", "resource": "cpu", "value": 97}, "cpu high"),
        (T0 - 5000, "FILE_INTEGRITY_CHANGE", "HIGH", {"domain": "disdik.example.com", "path": "/x/old"}, "outside the lookback"),
    ])
    detail = run_detail(flow.db_path, row["display_id"], flow.clock.t + 10)
    kinds = {t["type"] for t in detail["timeline"]}
    assert {"FIM_CHANGE", "DEPLOYMENT", "DB_CONNECTIVITY_FAILURE", "NGINX_ERROR_SPIKE", "SSH_AUTH", "BRUTE_FORCE", "CPU_HIGH"} <= kinds, kinds
    assert not any(t["delta_seconds"] < -900 for t in detail["timeline"]), "events outside the correlation window are not listed"
    scopes = {t["type"]: t["scope"] for t in detail["timeline"]}
    assert scopes["FIM_CHANGE"] == "PROJECT" and scopes["SSH_AUTH"] == "SERVER" and detail["possible_contributing_change"]["type"] == "FIM_CHANGE"
    assert detail["deployment_correlation"] and all(d["deployment"] or d["type"] == "FIM_CHANGE" for d in detail["deployment_correlation"])
    brief = detail["brief"]
    for heading in ("# PRODUCTION ISSUE BRIEF", "## Issue", "## Impact", "## Relevant stack trace", "## Correlated infrastructure events", "## Recent FIM / deployment changes",
                    "## PM2 / Nginx / DB context", "## Known", "## Unknown", "## Investigation priority"):
        assert heading in brief, heading
    assert "does not edit repositories, deploy fixes or restart services" in brief and "root cause (RTSA reports correlation only" in brief
    assert "shouldnotappear" not in brief and "caused" not in brief.lower().replace("not proven causes", "").replace("never a proven cause", ""), "no causal claim is made"
    text = fmt.sections_to_text("t", "h", fmt.detail_sections(detail))
    assert "Temporal correlation only; not a proven cause." in text and "SSH_AUTH" in text
    print("Test 13 (FIM/deployment/DB/Nginx/CPU/SSH timeline is shown as temporal evidence with scopes; the brief never claims a cause) PASSED")


async def test_14_delayed_replayed_and_duplicate_events():
    flow = await new_flow()
    replayed = flow.event(project="history", message="old failure", count=30, users=12, domain="history.example.com", timing="REPLAYED", event_time=T0 - 3 * 3600)
    flow.engine.ingest(replayed)
    live = flow.event(project="current", message="current failure", count=30, users=12, domain="current.example.com")
    flow.engine.ingest(live)
    twin = flow.event(project="current", message="current failure", count=30, domain="current.example.com", event_id=live.event_id)
    outcome = flow.engine.ingest(twin)
    marked = flow.event(project="current", message="current failure", count=30, domain="current.example.com", timing="DUPLICATE")
    flow.engine.ingest(marked)
    assert outcome.duplicate
    flow.clock.advance(20)
    await flow.persist()
    await flow.stop()
    report = run_top(flow.db_path, 86400.0, flow.clock.t)
    history, current = only(report, "history"), only(report, "current")
    assert history["status"] == "HISTORICAL" and history["priority"] in ("LOW", "MEDIUM") and any("replayed/stale history" in r for r in history["reasons"])
    assert current["occurrences"] == 30 and current["status"] == "ACTIVE", "duplicate event ids and DUPLICATE timing never add occurrences"
    assert report["historical_incidents"] == 1 and report["items"][0]["project"] == "current"
    conn = sqlite3.connect(flow.db_path)
    hours = {r[0] for r in conn.execute("SELECT hour FROM app_error_hourly WHERE incident_id = ?", (history["incident_id"],))}
    assert hours == {int((T0 - 3 * 3600) // 3600)}, "replayed events are bucketed at their event time, not at the detection time"
    print("Test 14 (replayed events stay HISTORICAL at their event hour with capped priority; duplicate events add nothing) PASSED")


async def test_15_restart_keeps_users_hours_and_identity():
    first = await new_flow()
    first.engine.ingest(first.event(project="portal", message="queue stalled", count=100, users=50, domain="portal.example.com"))
    first.clock.advance(60)
    await first.persist()
    await first.stop()
    original = run_top(first.db_path, 86400.0, first.clock.t)["items"][0]
    second = await new_flow(db_dir=first.dir, clock=first.clock)
    rows = app_error_store.load_recent_incidents(second.db_path, first.clock.t - 86400, 100)
    assert second.engine.restore(rows) == 1
    restored = second.engine.incidents()[0]
    assert restored.user_sketch is not None and 48 <= restored.user_sketch.count() <= 52 and restored.user_tagged == 50 and not restored.pending_hourly
    second.engine.ingest(second.event(project="portal", message="queue stalled", count=60, users=50, user_base=30, domain="portal.example.com"))
    second.clock.advance(30)
    await second.persist()
    await second.stop()
    report = run_top(second.db_path, 86400.0, second.clock.t)
    item = report["items"][0]
    assert item["incident_id"] == original["incident_id"] and item["display_id"] == original["display_id"] and report["total_incidents"] == 1
    assert item["occurrences"] == 160 and item["occurrences_total"] == 160, "no double counting across the restart"
    assert 76 <= item["affected_users"] <= 84 and item["users_tagged_occurrences"] == 100
    conn = sqlite3.connect(second.db_path)
    assert conn.execute("SELECT SUM(occurrences) FROM app_error_hourly").fetchone()[0] == 160
    print("Test 15 (RTSA restart: incident identity, user sketch and hourly buckets continue; occurrences are never double counted) PASSED")


async def test_16_persistence_failure_requeues_hourly_deltas():
    flow = await new_flow()
    flow.engine.ingest(flow.event(project="retry", message="retry failure", count=40, users=5, domain="retry.example.com"))
    flow.clock.advance(5)
    rows = flow.engine.drain_dirty(100)
    assert rows[0]["hourly_deltas"] and flow.engine.dirty_count() == 0 and not flow.engine.incidents()[0].pending_hourly
    flow.engine.requeue(rows[0])
    assert flow.engine.dirty_count() == 1 and flow.engine.incidents()[0].pending_hourly, "a failed enqueue puts the incident and its hourly deltas back"
    again = flow.engine.drain_dirty(100)
    assert again[0]["hourly_deltas"] == rows[0]["hourly_deltas"]
    for row in again:
        assert flow.worker.enqueue_app_error_incident(row)
    await flow.settle(flow.worker.stats["written"] + 1)
    await flow.stop()
    conn = sqlite3.connect(flow.db_path)
    assert conn.execute("SELECT SUM(occurrences) FROM app_error_hourly").fetchone()[0] == 40
    assert "hourly_deltas" not in json.loads(conn.execute("SELECT data FROM app_error_incidents").fetchone()[0]), "transient deltas are not stored inside the incident row"
    print("Test 16 (a failed persistence attempt re-queues the incident with its hourly deltas; nothing is lost or counted twice) PASSED")


async def test_17_user_ids_are_hashed_and_never_stored():
    flow = await new_flow()
    ev = flow.event(project="privacy", message="profile load failed", count=10, domain="privacy.example.com")
    for name in ("alice@example.com", "bob@example.com", "alice@example.com"):
        ev.add_user_hash(hash_user_id(SALT, name))
    assert ev.user_tagged == 3
    flow.engine.ingest(ev)
    flow.clock.advance(5)
    await flow.persist()
    await flow.stop()
    raw = open(flow.db_path, "rb").read()
    assert b"alice@example.com" not in raw and b"bob@example.com" not in raw and SALT not in raw
    item = run_top(flow.db_path, 86400.0, flow.clock.t)["items"][0]
    assert item["affected_users"] == 2, "repeat users count once"
    assert "user_sketch" not in json.dumps(ev.to_dict()) and "user_hashes" not in ev.to_dict(), "sketches never leak into published event payloads"
    assert hash_user_id(SALT, "alice@example.com") != hash_user_id(b"another-install-salt", "alice@example.com")
    sketch = HyperLogLog()
    sketch.add_hashes(hash_user_id(SALT, f"u{i}") for i in range(12000))
    assert 11000 <= sketch.count() <= 13000 and HyperLogLog.from_b64(sketch.to_b64()).count() == sketch.count() and len(sketch.to_b64()) < 1500
    print("Test 17 (user identifiers are salted hashes inside a bounded sketch; raw ids and the salt never reach SQLite or event payloads) PASSED")


async def test_18_display_id_lookup_prefix_and_collisions():
    flow = await new_flow()
    for project in ("one", "two"):
        flow.engine.ingest(flow.event(project=project, message=f"{project} failure", count=10, users=3, domain=f"{project}.example.com"))
    flow.clock.advance(5)
    await flow.persist()
    await flow.stop()
    items = run_top(flow.db_path, 86400.0, flow.clock.t)["items"]
    one = only({"items": items}, "one")
    by_display = run_detail(flow.db_path, one["display_id"].lower(), flow.clock.t + 5)
    by_prefix = run_detail(flow.db_path, one["incident_id"][:8].upper(), flow.clock.t + 5)
    by_full = run_detail(flow.db_path, one["incident_id"], flow.clock.t + 5)
    assert by_display["found"] and by_prefix["found"] and by_full["found"] and by_display["incident_id"] == by_prefix["incident_id"] == one["incident_id"]
    for bad in ("", "nonsense id", "APP-20991231-0000", "APP-20269999-0001", "zzzzzzzz"):
        missing = run_detail(flow.db_path, bad, flow.clock.t + 5)
        assert missing["found"] is False and missing["message"], bad
    conn = sqlite3.connect(flow.db_path)
    row = json.loads(conn.execute("SELECT data FROM app_error_incidents WHERE incident_id = ?", (one["incident_id"],)).fetchone()[0])
    twin = dict(row)
    twin["incident_id"] = one["incident_id"][:8] + "ffffffff"
    twin["fingerprint"] = "twinfingerprint00"
    while display_incident_id(twin["incident_id"], twin["first_seen"]) != one["display_id"]:
        twin["incident_id"] = twin["incident_id"][:8] + format(int(twin["incident_id"][8:], 16) - 1, "08x")
    conn.execute(
        "INSERT INTO app_error_incidents (incident_id, server, project, domain, fingerprint, error_type, state, severity, first_seen, last_seen, occurrence_count, updated_at, data) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (twin["incident_id"], twin["server"], twin["project"], twin["domain"], twin["fingerprint"], twin["error_type"], twin["state"], twin["severity"], twin["first_seen"],
         twin["last_seen"], 1, time.time(), json.dumps(twin)),
    )
    conn.commit()
    conn.close()
    ambiguous = run_detail(flow.db_path, one["display_id"], flow.clock.t + 5)
    assert ambiguous["found"] is False and len(ambiguous["candidates"]) == 2 and "full 16 character id" in ambiguous["message"]
    print("Test 18 (lookup by APP-YYYYMMDD-NNNN, hex prefix or full id; unknown ids and display-id collisions are explained, never guessed) PASSED")


async def test_19_project_criticality_is_only_used_when_configured():
    flow = await new_flow()
    flow.engine.ingest(flow.event(project="plain", message="same failure", count=100, users=30, domain="plain.example.com"))
    flow.engine.ingest(flow.event(project="vital", message="same failure", count=100, users=30, domain="vital.example.com"))
    flow.clock.advance(5)
    await flow.persist()
    await flow.stop()
    default = run_top(flow.db_path, 86400.0, flow.clock.t)
    assert abs(only(default, "plain")["score"] - only(default, "vital")["score"]) < 0.01 and not any("criticality" in r for i in default["items"] for r in i["reasons"])
    cfg = InvestigationConfig(app=InvestigationAppConfig(project_criticality={"vital": "critical"}))
    tuned = run_top(flow.db_path, 86400.0, flow.clock.t, cfg=cfg)
    assert tuned["items"][0]["project"] == "vital" and any("explicitly configured as CRITICAL" in r for r in tuned["items"][0]["reasons"])
    print("Test 19 (project criticality affects ranking only when the operator configured it explicitly) PASSED")


async def test_20_stale_store_and_disabled_tracker_are_reported():
    flow = await new_flow()
    flow.engine.ingest(flow.event(project="portal", message="queue stalled", count=30, users=5, domain="portal.example.com"))
    flow.clock.advance(5)
    await flow.persist()
    await flow.stop()
    later = flow.clock.t + 7200
    report = run_top(flow.db_path, 86400.0, later, info={"available": False, "enabled": False, "capture_user_ids": True})
    gaps = " ".join(report["data_gaps"])
    assert "APPLICATION_ERROR_TRACKER_DISABLED" in gaps
    assert report["items"][0]["status"] == "ACTIVE_STATE_NOT_REFRESHED", "an OPEN state that was never refreshed is not shown as live"
    off = run_top(flow.db_path, 86400.0, flow.clock.t + 10, info={"available": True, "enabled": True, "capture_user_ids": False})
    assert "USER_IDS_NOT_CAPTURED" in " ".join(off["data_gaps"])
    missing = run_top("/nonexistent/rtsa.db", 86400.0, flow.clock.t, info=None)
    assert missing["items"] == [] and any("DATABASE_NOT_FOUND" in g for g in missing["data_gaps"])
    print("Test 20 (disabled tracker, uncaptured user ids, unrefreshed state and a missing database are explicit data gaps) PASSED")


def test_21_sources_are_hygienic_read_only_and_do_not_notify():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    read_only = ("core/investigation_app.py", "core/investigation_format.py", "core/investigation_service.py", "core/investigation_store.py")
    for rel in read_only + ("core/hll.py", "core/traffic_stats.py"):
        source = open(os.path.join(root, rel)).read()
        assert not [t for t in tokenize.generate_tokens(io.StringIO(source).readline) if t.type == tokenize.COMMENT], rel
        tree = ast.parse(source)
        assert not [n for n in ast.walk(tree) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)], f"{rel} has a docstring"
        assert "subprocess" not in source and "os.system" not in source, rel
        if rel in read_only:
            modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names] + [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
            assert not [m for m in modules if "discord" in m or "webhook" in m or "event_bus" in m], f"{rel} must not reach Discord or the event bus"
            attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            assert not (attrs & {"publish", "publish_nowait", "enqueue_event", "enqueue_app_error_incident", "enqueue_app_error_digest", "enqueue_traffic_hourly"}), rel
    main_source = open(os.path.join(root, "main.py")).read()
    assert '("tce", "application_error_tracker", "nginx_monitor")' in main_source, "the DB worker is attached to the tracker and to nginx traffic recording"
    print("Test 21 (no comments/docstrings, no event publishing, Discord or event-bus access, no subprocess; main attaches the DB worker to the tracker) PASSED")


async def main() -> None:
    await test_1_one_project_one_error()
    await test_2_ten_thousand_repeats_stay_one_incident()
    await test_3_multiple_projects_rank_by_impact_and_users_are_not_double_counted()
    await test_4_occurrence_volume_is_not_user_impact()
    await test_5_low_occurrences_high_users_and_no_fabricated_users()
    await test_6_error_rate_comes_from_stored_traffic_only()
    await test_7_long_running_incident()
    await test_8_recovered_incident_ranks_below_an_active_twin()
    await test_9_multiple_servers_are_separate_incidents_and_widen_impact()
    await test_10_error_storm_is_bounded_and_ranked()
    await test_11_database_impact_outranks_a_plain_exception()
    await test_12_pm2_crash_and_oom()
    await test_13_fim_and_deployment_correlation_is_evidence_not_cause()
    await test_14_delayed_replayed_and_duplicate_events()
    await test_15_restart_keeps_users_hours_and_identity()
    await test_16_persistence_failure_requeues_hourly_deltas()
    await test_17_user_ids_are_hashed_and_never_stored()
    await test_18_display_id_lookup_prefix_and_collisions()
    await test_19_project_criticality_is_only_used_when_configured()
    await test_20_stale_store_and_disabled_tracker_are_reported()
    test_21_sources_are_hygienic_read_only_and_do_not_notify()
    for flow in FLOWS:
        flow.cleanup()
    print("\nALL APPLICATION INVESTIGATION TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
