from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _lb_fakes import DOMAIN, Env, make_config, make_report, origin_ips
from config.manager import LbDomainConfig, LbPoolGateConfig, LoadBalancingConfig, _validate_load_balancing
from core import lb_pool_collect as pc
from core import lb_pool_gate as g
from core.lb_database import infer_db_mode
from core.lb_model import OpStatus
from core.lb_pool_gate import POOL_FAIL, POOL_PASS, POOL_UNKNOWN, POOL_WARN

NOW = 1_800_000_000.0
CFG = LbPoolGateConfig()
SECRET = "S3cr3tPassw0rd!"


def node(server_id, instances=4, pool=20, state=g.STATE_EFFECTIVE, background=0, healthy=True, current=None, basis=None):
    row = {
        "server_id": server_id, "background": background, "app_healthy": healthy, "current_connections": current,
        "pm2": {"instances": instances, "instance_basis": basis or f"PM2_RUNTIME(online={instances}, configured={instances})", "exec_mode": "cluster", "apps": [{"name": "disdik", "instances": instances}]} if instances else {},
        "pool": {"per_instance": pool, "state": state, "drivers": ["prisma"], "source": "test"} if pool else {},
    }
    return row


def samples(creates=1, closes=1, total=40, requests=500, waiting=0, idle_tx=0, count=12):
    return [
        {"t": NOW + 5 * i, "total": total + i % 3, "active": 5, "idle": 30, "idle_in_transaction": idle_tx, "creates": creates if i else 0,
         "closes": closes if i else 0, "requests": requests, "pool_waiting": waiting}
        for i in range(count)
    ]


def evidence(nodes, max_connections=300, errors=None, sample_rows=None, other=0, app_gate=None, postgres=None, **extra):
    pg = {"max_connections": max_connections, "superuser_reserved": 3, "current": 45, "by_role": {"app": 45}, "app_roles": ["app"], "collected_at": NOW - 30}
    pg.update(postgres or {})
    row = {
        "domain": DOMAIN, "nodes": nodes, "postgres": pg, "other_db_connections": other,
        "telemetry": {"samples": samples() if sample_rows is None else sample_rows, "errors": errors or {}},
        "app_gate": app_gate or {"both_origins_healthy": True, "db_primary_shared": True, "db_connectivity_ok": True, "readiness_separated": True},
        "health": {"separated": True, "readiness_uses_db": False},
    }
    row.update(extra)
    return row


def run(raw, cfg=CFG):
    return g.evaluate_evidence(raw, cfg, now=NOW)


def test_1_single_node_single_instance_and_multiple_instances() -> None:
    one = run(evidence([node("server1", instances=1, pool=10)]))
    assert one.theoretical_max == 10 and one.budget.application_budget == 300 - 13
    assert one.pool_safety == POOL_PASS and one.scenarios[0].key == "A" and not any(s.key.startswith(("B:", "D:")) for s in one.scenarios), "one node has no failover scenario"
    many = run(evidence([node("server1", instances=4, pool=20)]))
    assert many.theoretical_max == 80 and many.nodes[0].node_max == 80 and many.pool_safety == POOL_PASS
    print("Test 1 (one node: 1 PM2 instance x pool 10 = 10; 4 instances x pool 20 = 80; no failover scenario for a single node) PASSED")


def test_2_two_nodes_active_active_with_shared_postgres() -> None:
    result = run(evidence([node("server1", 4, 20), node("server2", 4, 20)]))
    assert result.theoretical_max == 160 and result.budget.reserved_total == 13 and result.budget.application_budget == 287
    assert result.headroom == 127 and result.pool_safety == POOL_PASS and result.readiness == g.READY and result.lifecycle == g.LC_READY
    keys = [s.key for s in result.scenarios]
    assert keys[0] == "A" and {"B:server1", "B:server2", "D:server1", "D:server2", "F", "G", "H"} <= set(keys)
    data = result.to_dict()
    assert data["active_active_readiness"] == g.READY and data["budget"]["application_budget"] == 287
    print("Test 2 (two nodes 4x20 each = 160 against budget 287 with shared PostgreSQL: PASS, READY, headroom 127, scenarios A/B/D/F/G/H) PASSED")


def test_3_pool_below_and_exceeding_the_safe_budget() -> None:
    below = run(evidence([node("server1", 2, 10), node("server2", 2, 10)], max_connections=100, sample_rows=samples(total=10)))
    assert below.budget.application_budget == 87 and below.theoretical_max == 40 and below.pool_safety == POOL_PASS
    over = run(evidence([node("server1", 1, 70), node("server2", 1, 70)], max_connections=100))
    assert over.theoretical_max == 140 and over.budget.application_budget == 87 and over.pool_safety == POOL_FAIL
    assert over.readiness == g.NOT_READY and over.lifecycle == g.LC_POOL_UNSAFE and over.scenarios[0].status == POOL_FAIL
    assert any(f["code"] == "POOL_OVER_BUDGET" for f in over.findings)
    assert over.suggested_pool_per_instance == (87 - 0) // (2 + 1)
    low = run(evidence([node("server1", 4, 20), node("server2", 4, 20)], max_connections=200))
    assert low.pool_safety == POOL_WARN and low.headroom == 27 and any(f["code"] == "POOL_LOW_HEADROOM" for f in low.findings)
    print("Test 3 (70+70 against max_connections=100 is FAIL/NOT_READY/POOL_UNSAFE; 2x10 per node PASS; thin headroom WARN; a pool that fits is suggested for a manual change) PASSED")


def test_4_unknown_inputs_are_unknown_not_zero() -> None:
    no_pool = run(evidence([node("server1", 4, 0), node("server2", 4, 20)]))
    assert no_pool.pool_safety == POOL_UNKNOWN and no_pool.theoretical_max is None and any("pool size" in u for u in no_pool.unknowns)
    assert no_pool.lifecycle == g.LC_POOL_AUDIT and no_pool.readiness == g.READINESS_UNKNOWN
    no_pm2 = run(evidence([node("server1", 0, 20), node("server2", 4, 20)]))
    assert no_pm2.pool_safety == POOL_UNKNOWN and any("PM2 instance count" in u for u in no_pm2.unknowns)
    no_max = run(evidence([node("server1"), node("server2")], postgres={"max_connections": None}))
    assert no_max.pool_safety == POOL_UNKNOWN and no_max.budget.application_budget is None and no_max.lifecycle == g.LC_DB_CAPACITY_AUDIT
    assert any(f["code"] == "PG_MAX_CONNECTIONS_UNKNOWN" for f in no_max.findings)
    unknown_part_over = run(evidence([node("server1", 1, 200), node("server2", 0, 0)], max_connections=100))
    assert unknown_part_over.pool_safety == POOL_FAIL, "the known part alone already exceeds the budget, so it is FAIL not UNKNOWN"
    none = run(evidence([]))
    assert none.pool_safety == POOL_UNKNOWN and none.lifecycle == g.LC_DISCOVERING
    bg = run(evidence([node("server1", background=None), node("server2", background=None)]))
    assert bg.pool_safety == POOL_WARN and any("background" in u for u in bg.unknowns), "unknown background connections are not assumed to be zero"
    other = run(evidence([node("server1"), node("server2")], other=None))
    assert other.pool_safety == POOL_WARN and other.budget.other_basis == "MEASURED_CURRENT", "measured other-role connections are counted"
    unknown_other = run(evidence([node("server1"), node("server2")], other=None, postgres={"by_role": {}, "app_roles": []}))
    assert unknown_other.budget.other_basis == "UNKNOWN" and unknown_other.pool_safety == POOL_WARN
    print("Test 4 (unknown pool / PM2 instances / max_connections / background / other-service usage -> UNKNOWN or WARN, never assumed zero; a known excess still FAILs) PASSED")


def test_5_reserved_budget_is_configurable_and_role_limits_cap_it() -> None:
    base = run(evidence([node("server1"), node("server2")], max_connections=200))
    assert (base.budget.reserved_system, base.budget.reserved_admin, base.budget.reserved_monitoring) == (3, 5, 5)
    bigger = LbPoolGateConfig(reserved_admin_connections=20, reserved_monitoring_connections=15)
    assert run(evidence([node("server1"), node("server2")], max_connections=200), bigger).budget.application_budget == 200 - 3 - 20 - 15 - 0
    other = run(evidence([node("server1"), node("server2")], max_connections=200, other=30))
    assert other.budget.application_budget == 200 - 13 - 30 and other.budget.other_basis == "DECLARED_AND_MEASURED" and other.budget.other_consumers == 30
    capped = run(evidence([node("server1"), node("server2")], max_connections=300, postgres={"role_connection_limit": 100}))
    assert capped.budget.application_budget == 100 and capped.budget.role_limit == 100 and any("role/database connection limit" in n for n in capped.budget.notes)
    pg16 = run(evidence([node("server1"), node("server2")], max_connections=200, postgres={"reserved_connections": 7}))
    assert pg16.budget.reserved_system == 10
    default_sys = run(evidence([node("server1"), node("server2")], postgres={"superuser_reserved": None}))
    assert default_sys.budget.reserved_system == CFG.default_superuser_reserved_connections and any("configured default" in n for n in default_sys.budget.notes)
    print("Test 5 (reserve = PostgreSQL superuser reserve + configurable admin/monitoring + other consumers; role/database connection limits cap the application budget) PASSED")


def test_6_failover_budgets_for_app_and_server_failure() -> None:
    result = run(evidence([node("server1", 4, 20), node("server2", 3, 20)], max_connections=300))
    by_key = {s.key: s for s in result.scenarios}
    assert by_key["A"].connections == 140
    assert by_key["B:server1"].connections == 60 and by_key["B:server2"].connections == 80
    assert by_key["D:server1"].connections == 60 + 80, "an unmeasured dead server's connections are assumed to linger at its pool maximum"
    measured = run(evidence([node("server1", 4, 20, current=30), node("server2", 3, 20)], max_connections=300))
    assert {s.key: s for s in measured.scenarios}["D:server1"].connections == 60 + 30
    assert any("linger" in n for n in by_key["D:server1"].notes)
    assert result.failover_max == 140
    tight = run(evidence([node("server1", 4, 20), node("server2", 4, 20)], max_connections=110))
    assert {s.key: s for s in tight.scenarios}["B:server1"].status == POOL_PASS and {s.key: s for s in tight.scenarios}["A"].status == POOL_FAIL
    util = run(evidence([node("server1", 2, 20), node("server2", 2, 20)], max_connections=300, sample_rows=samples(total=70)))
    b = {s.key: s for s in util.scenarios}["B:server1"]
    assert b.utilization is not None and b.utilization > 1.0 and b.status == POOL_WARN and any("pool waiting" in n for n in b.notes)
    spike = by_key["F"]
    assert spike.dimension == "pool" and any("capped by the pools" in n for n in spike.notes)
    restart = by_key["G"]
    assert restart.connections == 140 + 20 and any("overlaps" in n for n in restart.notes)
    print("Test 6 (A/B/D/F/G/H: surviving-node maxima, lingering connections of a dead server, failover pool utilization, spike capped by pools, PM2 reload overlap) PASSED")


def test_7_measured_pool_timeouts_exhaustion_and_churn() -> None:
    nodes = [node("server1"), node("server2")]
    timeouts = run(evidence(nodes, errors={"POOL_TIMEOUT": 12}))
    assert timeouts.pool_safety == POOL_FAIL and timeouts.telemetry.pool_timeouts == 12 and any(f["code"] == "POOL_TIMEOUTS_OBSERVED" for f in timeouts.findings)
    few = run(evidence(nodes, errors={"CONNECT_TIMEOUT": 3}))
    assert few.pool_safety == POOL_WARN and few.telemetry.pool_timeouts == 3
    exhaustion = run(evidence(nodes, errors={"TOO_MANY_CLIENTS": 2}))
    assert exhaustion.telemetry.exhaustion and exhaustion.pool_safety == POOL_FAIL and exhaustion.lifecycle == g.LC_POOL_UNSAFE
    peak = run(evidence(nodes, max_connections=50, sample_rows=samples(total=60)))
    assert peak.telemetry.exhaustion and peak.pool_safety == POOL_FAIL
    churn_fail = run(evidence(nodes, sample_rows=samples(creates=150, closes=150)))
    assert churn_fail.telemetry.churn == g.CHURN_FAIL and churn_fail.pool_safety == POOL_FAIL
    churn_warn = run(evidence(nodes, sample_rows=samples(creates=20, closes=20)))
    assert churn_warn.telemetry.churn == g.CHURN_WARN and churn_warn.pool_safety == POOL_WARN
    ok = run(evidence(nodes))
    assert ok.telemetry.churn == g.CHURN_OK and 0 < ok.telemetry.creates_per_second < CFG.churn_warn_creates_per_second and ok.pool_safety == POOL_PASS
    assert ok.telemetry.creates_per_100_requests is not None and ok.telemetry.requests_per_second == 100.0
    waiting = run(evidence(nodes, sample_rows=samples(waiting=4)))
    assert waiting.telemetry.pool_waiting_peak == 4 and waiting.pool_safety == POOL_WARN
    growth = run(evidence(nodes, sample_rows=[dict(r, idle_in_transaction=i * 2) for i, r in enumerate(samples())]))
    assert growth.telemetry.idle_in_transaction_growth and growth.pool_safety == POOL_WARN and any(f["code"] == "IDLE_IN_TRANSACTION_GROWTH" for f in growth.findings)
    unmeasured = run(evidence(nodes, sample_rows=[]))
    assert not unmeasured.telemetry.measured and unmeasured.pool_safety == POOL_WARN and any(f["code"] == "NO_MEASURED_TELEMETRY" for f in unmeasured.findings), "arithmetic alone never reaches PASS"
    assert unmeasured.lifecycle == g.LC_READY_FOR_TEST
    print("Test 7 (pool timeouts, too-many-clients exhaustion, peak above max_connections, churn FAIL/WARN/OK, pool waiting and idle-in-transaction growth are detected; no measurement caps the gate at WARN) PASSED")


def test_8_error_classification_activity_sampling_and_no_one_second_polling() -> None:
    cases = {
        "FATAL:  sorry, too many clients already": "TOO_MANY_CLIENTS",
        "FATAL: remaining connection slots are reserved for non-replication superuser connections": "RESERVED_SLOTS_ONLY",
        "Timed out fetching a new connection from the connection pool. (P2024)": "POOL_TIMEOUT",
        "KnexTimeoutError: Knex: Timeout acquiring a connection": "POOL_TIMEOUT",
        "Error: timeout exceeded when trying to connect": "CONNECT_TIMEOUT",
        "error: password authentication failed for user \"app\"": "AUTH_FAILURE",
        "read ECONNRESET": "CONNECTION_RESET",
        "Connection terminated unexpectedly": "CONNECTION_TERMINATED",
        "connect ECONNREFUSED 10.0.0.5:5432": "CONNECTION_REFUSED",
    }
    for line, code in cases.items():
        assert pc.classify_db_error(line) == code, line
    assert pc.classify_db_error("GET /health 200") is None
    counts = pc.count_db_errors(list(cases) * 3 + ["noise"] * 100)
    assert counts["TOO_MANY_CLIENTS"] == 3 and sum(counts.values()) == 27
    rows = [
        [["10", "100", "idle", "0"], ["11", "101", "active", "0"], ["12", "102", "idle in transaction", "1"]],
        [["10", "100", "idle", "0"], ["13", "103", "idle", "0"], ["14", "104", "idle", "0"]],
        [["13", "103", "idle", "0"], ["15", "105", "idle", "0"]],
    ]
    clock = {"t": 1000.0}
    slept = []
    served = iter(rows)

    def fake_runner(name):
        assert name == "activity"
        return next(served)

    def fake_sleep(seconds):
        slept.append(seconds)
        clock["t"] += seconds

    out = pc.sample_activity(fake_runner, 4.5, 0.1, clock=lambda: clock["t"], sleep=fake_sleep)
    assert slept and all(s >= 2.0 for s in slept), "sampling never polls faster than every 2 seconds"
    assert out[0].get("creates") is None and (out[1]["creates"], out[1]["closes"]) == (2, 2) and (out[2]["creates"], out[2]["closes"]) == (1, 2)
    assert out[0]["idle_in_transaction"] == 1 and out[0]["lock_waiting"] == 1
    analyzed = g.analyze_telemetry(out, {}, CFG, 100, 13)
    assert analyzed.creates_per_second is not None and analyzed.closes_per_second is not None
    long_run = pc.sample_activity(lambda n: [["1", "1", "idle", "0"]], 100000.0, 2.0, clock=lambda: clock["t"], sleep=fake_sleep)
    assert len(long_run) <= 300, "the sampler is bounded"
    print("Test 8 (error classes for Prisma/pg/knex/PostgreSQL messages; backend create/close derived from pid sets; samples >= 2 s apart and bounded) PASSED")


def test_9_pool_detection_traces_values_to_the_runtime() -> None:
    prisma = pc.detect_pool({"DATABASE_URL": f"postgresql://app:{SECRET}@10.0.0.5/db?connection_limit=15"}, {"pool": {}, "url_pool": 15}, ["@prisma/client"], {}, 4)
    assert (prisma.per_instance, prisma.state) == (15, g.STATE_EFFECTIVE) and SECRET not in json.dumps(prisma.to_dict())
    from_file = pc.detect_pool({"DATABASE_URL": "postgresql://a:b@h/db?connection_limit=15"}, {"pool": {}, "url_pool": None}, ["prisma"], {}, 4)
    assert (from_file.per_instance, from_file.state) == (15, g.STATE_CONFIGURED), "a value only in an env file is CONFIGURED, not EFFECTIVE"
    default = pc.detect_pool({"DATABASE_URL": "postgresql://a:b@h/db"}, {}, ["@prisma/client"], {}, 4)
    assert (default.per_instance, default.state) == (9, g.STATE_DRIVER_DEFAULT)
    unknown_cpu = pc.detect_pool({"DATABASE_URL": "postgresql://a:b@h/db"}, {}, ["@prisma/client"], {}, None)
    assert unknown_cpu.per_instance is None and unknown_cpu.state == g.STATE_UNKNOWN
    traced = pc.detect_pool({"DB_POOL_MAX": "25"}, {"pool": {"DB_POOL_MAX": "30"}, "url_pool": None}, ["pg"], {"src/db.js": "const pool = new Pool({ host: h, max: Number(process.env.DB_POOL_MAX) || 10 })"}, 4)
    assert (traced.per_instance, traced.state) == (30, g.STATE_EFFECTIVE) and "PM2 process environment" in traced.source
    env_only = pc.detect_pool({"DB_POOL_MAX": "25"}, {"pool": {}, "url_pool": None}, ["pg"], {"src/db.js": "new Pool({ max: parseInt(process.env.DB_POOL_MAX, 10) })"}, 4)
    assert (env_only.per_instance, env_only.state) == (25, g.STATE_CONFIGURED)
    literal = pc.detect_pool({}, {}, ["pg"], {"src/db.js": "new Pool({ max: Number(process.env.NOT_SET) || 12 })"}, 4)
    assert literal.per_instance == 12 and "not set" in literal.source
    seq = pc.detect_pool({}, {}, ["sequelize", "pg"], {"models/index.js": "new Sequelize(a, b, c, { pool: { max: 8, min: 0 } })"}, 4)
    assert (seq.per_instance, seq.state, seq.drivers) == (8, g.STATE_CONFIGURED, ["sequelize"]), "pg under Sequelize is the driver, not a second pool"
    typeorm = pc.detect_pool({}, {}, ["typeorm"], {"src/data-source.ts": "new DataSource({ type: 'postgres', extra: { max: 18 } })"}, 4)
    assert typeorm.per_instance == 18
    knex = pc.detect_pool({}, {}, ["knex"], {"knexfile.js": "module.exports = { client: 'pg', pool: { min: 2, max: 14 } }"}, 4)
    assert knex.per_instance == 14
    knex_default = pc.detect_pool({}, {}, ["knex"], {}, 4)
    assert (knex_default.per_instance, knex_default.state) == (10, g.STATE_DRIVER_DEFAULT)
    both = pc.detect_pool({}, {}, ["@prisma/client", "pg", "connect-pg-simple"], {}, 2)
    assert both.per_instance == 5 + 10 and "connect-pg-simple" in both.drivers and "counted at their defaults" in both.detail
    nothing = pc.detect_pool({}, {}, ["express"], {}, 4)
    assert nothing.per_instance is None and nothing.state == g.STATE_UNKNOWN
    assert pc.detect_drivers(["next", "prisma", "pg", "pg-pool", "lodash"]) == ["prisma", "pg"]
    print("Test 9 (pool size: Prisma URL EFFECTIVE vs CONFIGURED vs driver default, env references traced to the PM2 process environment, Sequelize/TypeORM/Knex/pg pools, auxiliary session-store pools, unknown stays UNKNOWN) PASSED")


def test_10_pm2_instance_discovery() -> None:
    root = "/home/disdik/htdocs/disdik.example.com"
    secret_url = f"postgresql://app:{SECRET}@10.0.0.5/db?connection_limit=7"
    processes = [
        {"name": "disdik", "pm2_env": {"status": "online", "pm_cwd": root, "instances": 4, "exec_mode": "cluster_mode", "restart_time": 2, "node_version": "20.11.0",
                                       "env": {"DATABASE_URL": secret_url, "DB_POOL_MAX": "12", "API_TOKEN": "tok_live_123"}}},
        {"name": "disdik", "pm2_env": {"status": "online", "pm_cwd": root, "instances": 4, "exec_mode": "cluster_mode"}},
        {"name": "disdik", "pm2_env": {"status": "stopped", "pm_cwd": root, "instances": 4, "exec_mode": "cluster_mode"}},
        {"name": "worker", "pm2_env": {"status": "online", "pm_cwd": root + "/worker", "instances": 1, "exec_mode": "fork_mode"}},
        {"name": "other", "pm2_env": {"status": "online", "pm_cwd": "/home/other/htdocs/x", "instances": 9}},
    ]
    summary = pc.summarize_pm2(processes, root, (), 8)
    assert summary["instances"] == 5 and summary["instance_basis"].startswith("PM2_RUNTIME(online=3") and summary["exec_mode"] == "mixed"
    assert {a["name"]: a["instances"] for a in summary["apps"]} == {"disdik": 4, "worker": 1}, "configured instances count even when fewer are online; foreign projects are ignored"
    assert summary["runtime"] == {"pool": {"DB_POOL_MAX": "12"}, "url_pool": 7}
    text = json.dumps(summary)
    assert SECRET not in text and "tok_live_123" not in text and "10.0.0.5" not in text, "PM2 environments are never copied"
    only = pc.summarize_pm2(processes, root, ["disdik"], 8)
    assert only["instances"] == 4 and only["exec_mode"] == "cluster"
    maxed = pc.summarize_pm2([{"name": "a", "pm2_env": {"status": "online", "pm_cwd": root, "instances": "max", "exec_mode": "cluster_mode"}}], root, (), 6)
    assert maxed["instances"] == 6
    assert pc.summarize_pm2(None, root)["instances"] is None and pc.summarize_pm2([], root)["found"] is False
    print("Test 10 (PM2 instance count from the live process list: online vs configured, 'max', per-app filter, foreign projects ignored, no environment values retained) PASSED")


def test_11_readiness_versus_liveness() -> None:
    separated = pc.classify_health_endpoints([{"path": "/health/live", "status": 200}, {"path": "/health/ready", "status": 200, "body_keys": ["status", "database"]}])
    assert separated["separated"] is True and separated["readiness_uses_db"] is True and separated["liveness_path"] == "/health/live"
    light = pc.classify_health_endpoints([{"path": "/livez", "status": 200}, {"path": "/readyz", "status": 200, "uses_database": False}])
    assert light["separated"] is True and light["readiness_uses_db"] is False
    single = pc.classify_health_endpoints([{"path": "/healthz", "status": 200}])
    assert single["separated"] is False and "cannot be told apart" in single["note"]
    none = pc.classify_health_endpoints([{"path": "/health/ready", "status": 503}])
    assert none["separated"] is None
    result = run(evidence([node("server1"), node("server2")], app_gate={"both_origins_healthy": True, "db_primary_shared": True, "db_connectivity_ok": True, "readiness_separated": False}))
    assert result.readiness == g.NOT_READY and any(f["code"] == "HEALTH_NOT_SEPARATED" for f in result.findings)
    heavy = run(evidence([node("server1"), node("server2")], health={"separated": True, "readiness_uses_db": True}))
    h = {s.key: s for s in heavy.scenarios}["H"]
    assert h.status == POOL_WARN and any("monitor_regions" in n for n in h.notes), "a DB-backed readiness check is flagged until the probe rate is known"
    bounded = run(evidence([node("server1"), node("server2")], health={"separated": True, "readiness_uses_db": True}), LbPoolGateConfig(monitor_regions=3))
    assert {s.key: s for s in bounded.scenarios}["H"].status == POOL_PASS
    print("Test 11 (liveness vs readiness: separate endpoints detected, a single endpoint is not enough for READY, DB-backed readiness is flagged for probe load) PASSED")


def test_12_failover_test_plan_blocks_database_server_shutdown() -> None:
    plan = g.plan_failover_tests(["server1", "server2"], "server1")
    by_id = {p["id"]: p for p in plan}
    assert by_id["A"]["status"] == g.PLANNED and by_id["C"]["status"] == g.PLANNED
    assert by_id["D:server1"]["status"] == g.BLOCKED_BY_DATABASE_TOPOLOGY and "sole PostgreSQL primary" in by_id["D:server1"]["reason"]
    assert by_id["D:server2"]["status"] == g.REQUIRES_APPROVAL
    unknown = g.plan_failover_tests(["server1", "server2"], None)
    assert all(p["status"] == g.BLOCKED_BY_DATABASE_TOPOLOGY for p in unknown if p["id"].startswith("D:"))
    assert g.plan_failover_tests(["server1"], "server1") == []
    healthy = run(evidence([node("server1"), node("server2")]))
    assert healthy.to_dict()["pgbouncer"]["applied"] is False
    print("Test 12 (Server1 hosts the sole PostgreSQL primary -> its full-server failure test is BLOCKED_BY_DATABASE_TOPOLOGY; application-only tests stay planned) PASSED")


def test_13_application_failures_degrade_the_lifecycle_and_recover() -> None:
    down2 = run(evidence([node("server1"), node("server2", healthy=False)], app_gate={"both_origins_healthy": False, "db_primary_shared": True, "db_connectivity_ok": True, "readiness_separated": True}))
    assert down2.lifecycle == g.LC_DEGRADED and down2.readiness == g.NOT_READY
    down1 = run(evidence([node("server1", healthy=False), node("server2")], app_gate={"both_origins_healthy": False, "db_primary_shared": True, "db_connectivity_ok": True, "readiness_separated": True}))
    assert down1.lifecycle == g.LC_DEGRADED and down1.readiness == g.NOT_READY
    recovered = run(evidence([node("server1"), node("server2")]))
    assert recovered.lifecycle == g.LC_READY and recovered.readiness == g.READY
    unreachable = run(evidence([node("server1"), node("server2")], app_gate={"both_origins_healthy": True, "db_primary_shared": True, "db_connectivity_ok": False, "readiness_separated": True}))
    assert unreachable.readiness == g.NOT_READY, "READY needs database connectivity from every node, not only healthy Cloudflare origins"
    cloudflare_only = run(evidence([node("server1"), node("server2")], app_gate={"both_origins_healthy": True}))
    assert cloudflare_only.readiness == g.READINESS_UNKNOWN and cloudflare_only.lifecycle == g.LC_VALIDATING
    topology = run(evidence([node("server1"), node("server2")], app_gate={"both_origins_healthy": True, "db_primary_shared": False, "db_connectivity_ok": True}))
    assert topology.readiness == g.NOT_READY
    testing = run(evidence([node("server1"), node("server2")], phase="testing"))
    recovering = run(evidence([node("server1"), node("server2")], phase="recovering"))
    assert testing.lifecycle == g.LC_TESTING and recovering.lifecycle == g.LC_RECOVERING
    stale = g.evaluate_evidence(evidence([node("server1"), node("server2")], postgres={"collected_at": NOW - 7200}), CFG, now=NOW)
    assert stale.pool_safety == POOL_WARN and any(f["code"] == "PG_EVIDENCE_STALE" for f in stale.findings)
    print("Test 13 (server1/server2 application failure -> DEGRADED/NOT_READY, recovery -> READY; Cloudflare health alone, DB unreachable or non-shared topology never READY; stale evidence caps at WARN) PASSED")


def test_14_pgbouncer_recommendation_is_evidence_based_and_never_applied() -> None:
    nodes = [node("server1"), node("server2")]
    fine = run(evidence(nodes))
    assert fine.pgbouncer["recommendation"] == g.PGB_NOT_NECESSARY and "measured creation rate" in " ".join(fine.pgbouncer["evidence"]) and fine.pgbouncer["applied"] is False
    unknown = run(evidence([node("server1", 4, 0), node("server2")], sample_rows=[]))
    assert unknown.pgbouncer["recommendation"] == g.PGB_NOT_EVALUATED
    arithmetic = run(evidence([node("server1", 1, 70), node("server2", 1, 70)], max_connections=100))
    assert arithmetic.pgbouncer["recommendation"] == g.PGB_REDUCE_POOL_FIRST and "lowering the pool" in " ".join(arithmetic.pgbouncer["evidence"])
    impossible = run(evidence([node("server1", 60, 5), node("server2", 60, 5)], max_connections=100))
    assert impossible.suggested_pool_per_instance == 0 and impossible.pgbouncer["recommendation"] == g.PGB_RECOMMENDED
    churn = run(evidence(nodes, sample_rows=samples(creates=150, closes=150)))
    assert churn.pgbouncer["recommendation"] == g.PGB_RECOMMENDED and "dedicated service" in churn.pgbouncer["placement"] and "single pool caps the total" in churn.pgbouncer["placement"]
    assert "RTSA never installs" in churn.pgbouncer["note"]
    session = run(evidence(nodes, sample_rows=samples(creates=150, closes=150), stack={"dependencies": ["pg-boss", "prisma"]}))
    assert "SESSION_POOLING_ONLY" in session.pgbouncer["mode_compatibility"] and any("pg-boss" in s for s in session.pgbouncer["session_pooling_required"])
    transaction = run(evidence(nodes, sample_rows=samples(creates=30, closes=30), stack={"dependencies": ["prisma"]}))
    assert transaction.pgbouncer["recommendation"] == g.PGB_CONSIDER and "pgbouncer=true" in " ".join(transaction.pgbouncer["transaction_pooling_notes"])
    print("Test 14 (PgBouncer: NOT_NECESSARY with measured evidence, REDUCE_POOL_FIRST when a smaller pool fits, RECOMMENDED on churn/impossible budget with placement and compatibility notes, never applied) PASSED")


def test_15_read_only_postgres_collection_never_exposes_credentials_or_writes() -> None:
    for name, sql in pc.PG_QUERIES.items():
        assert re.match(r"^\s*SELECT\b", sql), name
        assert not re.search(r"\b(INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|TRUNCATE|GRANT|REVOKE|COPY|VACUUM|SET|RESET|CALL|DO|pg_terminate_backend|pg_cancel_backend|pg_reload_conf)\b", sql, re.I), name
    captured = []

    class Proc:
        returncode = 0
        stderr = ""

        def __init__(self, out):
            self.stdout = out

    answers = {
        "max_connections": "200\x1f3\x1f0\x1f10.0.0.5\x1fon\x1fon\n",
        "count(*), count": "",
    }

    def fake_run(argv, **kwargs):
        captured.append((argv, kwargs))
        sql = argv[argv.index("-c") + 1]
        if "max_connections" in sql:
            return Proc("200\x1f3\x1f0\x1f10.0.0.5\x1fon\x1fon\n")
        if "GROUP BY 1" in sql and "state" in sql:
            return Proc("active\x1f6\nidle\x1f30\nidle in transaction\x1f2\n")
        if "usename" in sql:
            return Proc("app\x1f30\nmonitor\x1f8\n")
        if "client_addr" in sql:
            return Proc("10.0.0.11\x1f20\n10.0.0.12\x1f18\n")
        if "backend_start))" in sql:
            return Proc("3600.5\x1f12.25\x1f1\n")
        if "rolconnlimit" in sql:
            return Proc("120\x1f0\n")
        return Proc("")

    original = pc.subprocess.run
    pc.subprocess.run = fake_run
    try:
        os.environ["PGPASSWORD"] = SECRET
        runner = pc.psql_runner("/usr/bin/psql", {"PGHOST": "10.0.0.5"}, ["app"])
        facts = pc.collect_pg(runner, ["app"], now=NOW)
    finally:
        pc.subprocess.run = original
        os.environ.pop("PGPASSWORD", None)
    assert facts.max_connections == 200 and facts.superuser_reserved == 3 and facts.current == 38 and facts.idle_in_transaction == 2
    assert facts.by_role == {"app": 30, "monitor": 8} and facts.application_current == 30 and facts.other_current == 8
    assert facts.role_connection_limit == 120 and facts.read_only_verified is True and facts.longest_transaction_seconds == 12.25 and facts.lock_waits == 1
    for argv, kwargs in captured:
        assert SECRET not in " ".join(argv) and kwargs.get("shell") in (None, False) and isinstance(argv, list)
        assert "default_transaction_read_only=on" in kwargs["env"]["PGOPTIONS"] and "statement_timeout=5000" in kwargs["env"]["PGOPTIONS"]
        assert kwargs["timeout"] <= 10 and "-X" in argv
    assert SECRET not in json.dumps(facts.to_dict())
    flagged = run(evidence([node("server1"), node("server2")], postgres={"listen_addresses": "*"}))
    assert any(f["code"] == "PG_LISTENS_ON_ALL_ADDRESSES" for f in flagged.findings)
    private = run(evidence([node("server1"), node("server2")], postgres={"listen_addresses": "10.0.0.5,127.0.0.1"}))
    assert not any(f["code"] == "PG_LISTENS_ON_ALL_ADDRESSES" for f in private.findings)
    print("Test 15 (collection: fixed SELECT-only SQL, read-only transaction + statement timeout, argv without shell or password, results parsed to counts, public listen_addresses flagged but never changed) PASSED")


def test_16_credentials_are_redacted_everywhere() -> None:
    url = f"postgresql://app:{SECRET}@10.0.0.5:5432/db?connection_limit=9&sslmode=require"
    report = make_report("server1")
    report.pm2 = pc.summarize_pm2([{"name": "a", "pm2_env": {"status": "online", "pm_cwd": "/p", "instances": 2, "env": {"DATABASE_URL": url, "DB_POOL_MAX": "9"}}}], "/p", (), 4)
    report.pool = pc.detect_pool({"DATABASE_URL": url}, report.pm2["runtime"], ["@prisma/client"], {}, 4).to_dict()
    assert SECRET not in json.dumps(report.to_dict())
    raw = evidence([node("server1"), node("server2")])
    raw["postgres"]["source"] = f"read-only psql password={SECRET}"
    result = run(raw)
    dumped = json.dumps(result.to_dict()) + json.dumps(result.compact()) + "\n".join(g.render_text(result))
    assert SECRET not in dumped
    from core.lb_format import _pool_gate_lines
    assert SECRET not in "\n".join(_pool_gate_lines(result.compact(), NOW, {}))
    print("Test 16 (database URLs, PM2 environments and evidence sources never leak credentials into reports, results, compact state or Discord text) PASSED")


def test_17_no_automatic_database_change_replication_exposure_or_deployment() -> None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sources = {name: open(os.path.join(root, "core", name)).read() for name in ("lb_pool_gate.py", "lb_pool_collect.py")}
    forbidden = (
        "ALTER SYSTEM", "pg_reload_conf", "pg_ctl", "systemctl", "service postgresql", "SET max_connections", "set_config(",
        "CREATE PUBLICATION", "CREATE SUBSCRIPTION", "pglogical", "bdr.", "ufw ", "iptables", "nft ",
        "shell=True", "os.system", "pm2 restart", "pm2 reload", "pm2 scale", "pm2 start", "apt ", "pgbouncer.ini", "npm ",
    )
    for name, text in sources.items():
        for token in forbidden:
            assert token not in text, (name, token)
    assert "subprocess" not in sources["lb_pool_gate.py"], "the gate itself runs nothing"
    assert sources["lb_pool_collect.py"].count("subprocess.run(") == 1, "the only process the collector runs is the read-only psql"
    decision = infer_db_mode(None)
    assert decision.mode.value != "MULTI_PRIMARY"
    cfg = LbPoolGateConfig()
    assert cfg.enforcement == "block_on_fail"
    print("Test 17 (the new code cannot change max_connections, restart PostgreSQL/PM2, create replication, expose PostgreSQL, install PgBouncer or deploy anything) PASSED")


def pooled_report(server_id, instances=4, pool=20, **kwargs):
    report = make_report(server_id, **kwargs)
    report.pm2 = {"found": True, "instances": instances, "instance_basis": f"PM2_RUNTIME(online={instances}, configured={instances})", "exec_mode": "cluster", "apps": [{"name": "disdik", "instances": instances}], "runtime": {"pool": {}, "url_pool": pool}}
    report.pool = {"per_instance": pool, "state": g.STATE_EFFECTIVE, "drivers": ["prisma"], "source": "test", "detail": "", "components": []}
    report.health_endpoints = {"separated": True, "readiness_uses_db": False, "liveness_path": "/health/live", "readiness_path": "/health/ready"}
    report.stack = {"dependencies": ["prisma"], "drivers": ["prisma"]}
    return report


def make_env(instances=4, pool=20, max_connections=300, enforcement="block_on_fail", extra_domain=None, **report_kwargs):
    domain = LbDomainConfig(domain=DOMAIN, origins=["server1", "server2"], db_max_connections=max_connections, background_connections_per_node=0, other_db_connections=0, **(extra_domain or {}))
    cfg = make_config(2, domains=[domain], pool_gate=LbPoolGateConfig(enforcement=enforcement))
    env = Env(2, cfg=cfg)
    env.ports.local_report = pooled_report("server1", instances, pool, **report_kwargs)
    env.ports.reports["server2"].report = pooled_report("server2", instances, pool, **report_kwargs)
    return env


async def test_18_orchestrator_persists_the_gate_and_cekloadbalance_shows_it() -> None:
    env = make_env()
    result = await env.orch.genloadbalance(DOMAIN, origin_ips(2), operator="tester", apply=True, confirmed=True)
    assert result.status == OpStatus.SUCCESS, (result.message, result.plan.blocker_codes() if result.plan else None)
    gate = env.store.domain(DOMAIN).db["pool_gate"]
    assert gate["theoretical_max"] == 160 and gate["application_budget"] == 300 - 13 and gate["pool_safety"] == POOL_WARN
    assert [n["instances"] for n in gate["nodes"]] == [4, 4] and gate["lifecycle"] in (g.LC_READY_FOR_TEST, g.LC_VALIDATING)
    status = await env.monitor.status(DOMAIN, full=True)
    from core import lb_format
    title, kind, body, fields = lb_format.format_status(status, {})
    for token in ("APPLICATION", "DATABASE", "max_connections: 300", "application budget: 287", "theoretical active/active max: 160", "failover max", "CAPACITY", "GATE", "POOL_SAFETY: WARN", "ACTIVE_ACTIVE_READINESS", "PGBOUNCER"):
        assert token in body, token
    gauges = env.metrics.snapshot()["gauges"]
    assert gauges["lb_db_connections_max"] == 300 and gauges["lb_db_connections_theoretical_max"] == 160 and gauges["lb_pool_safety"] == 2.0
    assert env.metrics.snapshot()["counters"]["lb_pool_gate_evaluations_total"] >= 1
    assert env.cf.mutations().count("create_load_balancer") == 1
    db_result = await env.orch.dbgenbalance(DOMAIN, operator="tester")
    assert db_result.assessment.pool_gate is not None
    _, _, _, db_fields = lb_format.format_db(db_result)
    assert any(name == "Connection pool gate" and "POOL_SAFETY" in value for name, value, _ in db_fields)
    print("Test 18 (/genloadbalance and /dbgenbalance evaluate the gate from PM2/pool facts, persist it, publish lb_db_* metrics and /cekloadbalance shows APPLICATION/DATABASE/CAPACITY/GATE) PASSED")


async def test_19_unsafe_pool_blocks_active_active_without_touching_anything() -> None:
    env = make_env(instances=1, pool=70, max_connections=100)
    result = await env.orch.genloadbalance(DOMAIN, origin_ips(2), operator="tester", apply=True, confirmed=True)
    assert result.status == OpStatus.ABORTED and "POOL_UNSAFE" in result.plan.blocker_codes()
    assert env.cf.mutations() == [] and env.ports.prepare_calls == [], "nothing is created, enabled or prepared when the gate is FAIL"
    cats = env.categories()
    assert cats.count("LB_DB_POOL_UNSAFE") == 0, "a dry/aborted plan evaluates but only a persisted assessment alerts"
    db_result = await env.orch.dbgenbalance(DOMAIN, operator="tester")
    assert db_result.assessment.pool_gate.pool_safety == POOL_FAIL
    assert env.categories().count("LB_DB_POOL_UNSAFE") == 1 and env.cf.mutations() == []
    advisory = make_env(instances=1, pool=70, max_connections=100, enforcement="advisory")
    adv = await advisory.orch.genloadbalance(DOMAIN, origin_ips(2), operator="tester", apply=True, confirmed=True)
    assert "POOL_UNSAFE" not in (adv.plan.blocker_codes() if adv.plan else []), "advisory mode reports but never blocks"
    print("Test 19 (POOL_SAFETY=FAIL aborts /genloadbalance before any Cloudflare mutation or vhost preparation; advisory enforcement only reports) PASSED")


async def test_20_unknown_gate_follows_the_enforcement_policy_and_legacy_declarations_still_work() -> None:
    legacy_domain = LbDomainConfig(domain=DOMAIN, origins=["server1", "server2"], app_connection_pool=10, db_max_connections=1000)
    legacy = Env(2, cfg=make_config(2, domains=[legacy_domain]))
    result = await legacy.orch.genloadbalance(DOMAIN, origin_ips(2), operator="tester", apply=True, confirmed=True)
    assert result.status == OpStatus.SUCCESS, "reports without PM2/pool facts keep the previous behaviour"
    gate = legacy.store.domain(DOMAIN).db["pool_gate"]
    assert gate["pool_safety"] == POOL_WARN and gate["theoretical_max"] == 20, "a legacy per-origin pool total is used but never reaches PASS"
    strict_domain = LbDomainConfig(domain=DOMAIN, origins=["server1", "server2"], db_max_connections=300, pm2_instances={"server1": 2, "server2": 2})

    async def provide(domain):
        return {"postgres": {"max_connections": 300, "collected_at": NOW, "superuser_reserved": 3}}, "OK"

    for enforcement, expect_block in (("block_on_unknown", True), ("block_on_fail", False)):
        env = Env(2, cfg=make_config(2, domains=[strict_domain], pool_gate=LbPoolGateConfig(enforcement=enforcement, pg_evidence_max_age_seconds=10 ** 9)))
        env.ports.load_pool_evidence = provide
        outcome = await env.orch.genloadbalance(DOMAIN, origin_ips(2), operator="tester", apply=True, confirmed=True)
        codes = outcome.plan.blocker_codes() if outcome.plan else []
        assert ("POOL_UNSAFE" in codes) is expect_block, (enforcement, codes, outcome.status)
        if expect_block:
            assert outcome.status == OpStatus.ABORTED and env.cf.mutations() == []
            assert any("POOL_SAFETY=UNKNOWN" in b.message for b in outcome.plan.blockers if b.code == "POOL_UNSAFE")
        else:
            assert outcome.status == OpStatus.SUCCESS, "an UNKNOWN gate only warns under block_on_fail"
    print("Test 20 (legacy app_connection_pool declarations keep working as WARN; block_on_unknown turns an unproven gate into a blocker only when verified inputs exist) PASSED")


async def test_21_postgres_evidence_file_feeds_measured_capacity_and_alerts_once() -> None:
    env = make_env(instances=2, pool=10, max_connections=300)
    raw = evidence([node("server1"), node("server2")], max_connections=100, errors={"TOO_MANY_CLIENTS": 4})

    async def provide(domain):
        return {k: raw[k] for k in ("postgres", "telemetry", "other_db_connections")}, "OK"

    env.ports.load_pool_evidence = provide
    first = await env.orch.dbgenbalance(DOMAIN, operator="tester")
    assert first.assessment.pool_gate.pool_safety == POOL_FAIL and first.assessment.pool_gate.telemetry.exhaustion
    again = await env.orch.dbgenbalance(DOMAIN, operator="tester")
    assert again.assessment.pool_gate.pool_safety == POOL_FAIL
    assert env.categories().count("LB_DB_POOL_UNSAFE") == 1, "one deduplicated alert for a persisting condition"
    snap = env.metrics.snapshot()
    assert snap["counters"]["lb_pool_gate_fail_total"] == 1 and snap["counters"]["lb_pool_gate_evaluations_total"] == 1, "identical evidence is not counted twice"
    assert snap["gauges"]["lb_pool_safety"] == 3.0
    event = next(e for e in env.ports.events if e.category.value == "LB_DB_POOL_UNSAFE")
    assert "changes no database setting" in event.message and SECRET not in event.message
    healthy = {k: v for k, v in evidence([node("server1"), node("server2")], max_connections=300).items() if k in ("postgres", "telemetry", "other_db_connections")}

    async def provide_healthy(domain):
        return healthy, "OK"

    env.ports.load_pool_evidence = provide_healthy
    fixed = await env.orch.dbgenbalance(DOMAIN, operator="tester")
    assert fixed.assessment.pool_gate.pool_safety != POOL_FAIL and not env.monitor.alerts.is_open(f"lb_pool:{DOMAIN}")
    print("Test 21 (operator PostgreSQL evidence: exhaustion -> FAIL with one LB_DB_POOL_UNSAFE alert, identical evidence counted once, recovery resolves the alert) PASSED")


async def test_22_server2_database_connectivity_failure_and_app_failure_are_not_ready() -> None:
    env = make_env(instances=2, pool=10, max_connections=300)
    env.ports.reports["server2"].report = pooled_report("server2", 2, 10, db_level="TCP")
    result = await env.orch.dbgenbalance(DOMAIN, operator="tester")
    gate = result.assessment.pool_gate
    assert gate.readiness == g.NOT_READY and result.assessment.connectivity_ok == 1 and result.assessment.connectivity_total == 2
    unhealthy = make_env(instances=2, pool=10, max_connections=300)
    unhealthy.ports.reports["server2"].report.health_ok = False
    degraded = await unhealthy.orch.dbgenbalance(DOMAIN, operator="tester")
    assert degraded.assessment.pool_gate.lifecycle == g.LC_DEGRADED and degraded.assessment.pool_gate.readiness == g.NOT_READY
    print("Test 22 (Server2 -> PostgreSQL connectivity failure or an unhealthy application keeps the gate NOT_READY/DEGRADED) PASSED")


async def test_23_duplicate_cloudflare_pool_and_monitor_are_detected() -> None:
    env = make_env(instances=2, pool=10, max_connections=300)
    applied = await env.orch.genloadbalance(DOMAIN, origin_ips(2), operator="tester", apply=True, confirmed=True)
    assert applied.status == OpStatus.SUCCESS
    pool = copy.deepcopy(next(iter(env.cf.pools.values())))
    pool["id"] = "pool-duplicate"
    env.cf.pools["pool-duplicate"] = pool
    plan = await env.orch.genloadbalance(DOMAIN, origin_ips(2), operator="tester", apply=False)
    assert any("pools carry the tag" in c.message for c in plan.plan.conflicts), [c.message for c in plan.plan.conflicts]
    del env.cf.pools["pool-duplicate"]
    monitor = copy.deepcopy(next(iter(env.cf.monitors.values())))
    monitor["id"] = "mon-duplicate"
    env.cf.monitors["mon-duplicate"] = monitor
    plan = await env.orch.genloadbalance(DOMAIN, origin_ips(2), operator="tester", apply=False)
    assert any("monitors carry the tag" in c.message for c in plan.plan.conflicts)
    before = len(env.cf.mutations())
    blocked = await env.orch.genloadbalance(DOMAIN, origin_ips(2), operator="tester", apply=True, confirmed=True)
    assert blocked.status == OpStatus.ABORTED and len(env.cf.mutations()) == before, "duplicates are never created, merged or deleted automatically"
    print("Test 23 (duplicate RTSA-tagged Cloudflare pool or monitor aborts with a conflict; nothing is created, merged or deleted automatically) PASSED")


def test_24_configuration_defaults_yaml_and_validation() -> None:
    import yaml
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("config.yaml", "config2.yaml"):
        raw = yaml.safe_load(open(os.path.join(root, "config", name)))
        block = raw["load_balancing"]["pool_gate"]
        parsed = LbPoolGateConfig(**block)
        assert parsed == LbPoolGateConfig() and parsed.enforcement == "block_on_fail" and parsed.enabled
    def errors(**gate):
        out = []
        _validate_load_balancing(LoadBalancingConfig(pool_gate=LbPoolGateConfig(**gate)), out)
        return out
    assert errors() == []
    assert any("enforcement" in e for e in errors(enforcement="always"))
    assert any("warn_headroom_ratio" in e for e in errors(warn_headroom_ratio=1.5))
    assert any("churn" in e for e in errors(churn_warn_creates_per_second=10, churn_fail_creates_per_second=5))
    assert any("reserved_admin_connections" in e for e in errors(reserved_admin_connections=-2))
    assert any("pg_evidence_dir" in e for e in errors(pg_evidence_dir="relative"))
    bad = LoadBalancingConfig(domains=[LbDomainConfig(domain="a.example.com", pm2_instances={"server1": 0}, other_db_connections=-5)])
    problems = []
    _validate_load_balancing(bad, problems)
    assert any("pm2_instances" in e for e in problems) and any("other_db_connections" in e for e in problems)
    print("Test 24 (pool_gate defaults match both YAML profiles; invalid enforcement, ratios, churn thresholds, paths and PM2 declarations are rejected) PASSED")


def test_25_metrics_are_registered_once_and_exported() -> None:
    from core.pipeline_metrics import get_lb_metrics
    registry = get_lb_metrics()
    for name in ("lb_pool_gate_evaluations_total", "lb_pool_gate_fail_total", "lb_db_pool_timeouts_total", "lb_db_connection_errors_total", "lb_db_connection_churn_total"):
        assert name in registry.counter_help
    for name in ("lb_db_connections_current", "lb_db_connections_max", "lb_db_connections_reserved", "lb_db_connections_application_budget", "lb_db_connections_theoretical_max", "lb_db_connections_failover_max", "lb_db_pool_waiting", "lb_pool_safety", "lb_active_active_ready"):
        assert name in registry.gauge_help
    names = list(registry.counter_help) + list(registry.gauge_help) + list(registry.latency_help)
    assert len(names) == len(set(names)), "no duplicate metric names"
    print("Test 25 (pool-gate metrics are registered once in the existing LB registry and exported with the other lb_* metrics) PASSED")


def test_26_cli_analyze_sql_and_assemble() -> None:
    import tempfile
    directory = tempfile.mkdtemp(prefix="rtsa-pool-")
    path = os.path.join(directory, "evidence.json")
    json.dump(evidence([node("server1", 1, 70), node("server2", 1, 70)], max_connections=100), open(path, "w"))
    out = os.path.join(directory, "result.json")
    code = pc.main(["analyze", "--evidence", path, "--out", out])
    assert code == 5 and json.load(open(out))["pool_safety"] == POOL_FAIL
    pg_path, samples_path, errors_path, merged = (os.path.join(directory, n) for n in ("pg.json", "samples.json", "errors.json", "merged.json"))
    json.dump({"max_connections": 200}, open(pg_path, "w"))
    json.dump({"samples": samples()}, open(samples_path, "w"))
    json.dump({"errors": {"POOL_TIMEOUT": 1}}, open(errors_path, "w"))
    assert pc.main(["assemble", "--postgres", pg_path, "--samples", samples_path, "--errors", errors_path, "--other-db-connections", "4", "--out", merged]) == 0
    data = json.load(open(merged))
    assert data["postgres"]["max_connections"] == 200 and len(data["telemetry"]["samples"]) == 12 and data["other_db_connections"] == 4
    assert oct(os.stat(merged).st_mode & 0o777) == "0o600"
    log = os.path.join(directory, "app.log")
    open(log, "w").write("ok\nsorry, too many clients already\nP2024 Timed out fetching a new connection from the connection pool\n")
    errors_out = os.path.join(directory, "errors-out.json")
    assert pc.main(["count-errors", "--log", log, "--out", errors_out]) == 0
    assert json.load(open(errors_out))["errors"] == {"TOO_MANY_CLIENTS": 1, "POOL_TIMEOUT": 1}
    assert pc.main(["sql", "--name", "settings"]) == 0
    print("Test 26 (CLI: analyze returns a gate-specific exit code, assemble merges evidence into a 0600 file, count-errors and sql work offline) PASSED")


def test_27_validation_gate_requires_pool_safety_pass() -> None:
    from core import lb_validation as v
    for value, expected in (("PASS", v.PASS), ("FAIL", v.FAIL), ("WARN", v.INSUFFICIENT_DATA), ("UNKNOWN", v.INSUFFICIENT_DATA)):
        items = {i.item_id: i for i in v.evaluate_gate({"pool_gate": {"pool_safety": value, "reasons": ["why"]}}, v.Thresholds())}
        assert items["pool_safety"].status == expected, (value, items["pool_safety"].status)
    missing = {i.item_id: i for i in v.evaluate_gate({}, v.Thresholds())}
    assert missing["pool_safety"].status == v.INSUFFICIENT_DATA and "pool gate" in missing["pool_safety"].evidence
    result = run(evidence([node("server1", 1, 70), node("server2", 1, 70)], max_connections=100))
    items = {i.item_id: i for i in v.evaluate_gate({"pool_gate": result.to_dict()}, v.Thresholds())}
    assert items["pool_safety"].status == v.FAIL and "needs" in items["pool_safety"].evidence
    print("Test 27 (the DISDIK validation gate has a pool_safety item: only POOL_SAFETY=PASS passes, FAIL fails, WARN/UNKNOWN/missing stay INSUFFICIENT_DATA) PASSED")


def test_28_hygiene() -> None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("lb_pool_gate.py", "lb_pool_collect.py"):
        text = open(os.path.join(root, "core", name)).read()
        assert not re.search(r"(^|\s)#\s", text) and '"""' not in text, name
    print("Test 28 (new modules contain no comments or docstrings) PASSED")


def main() -> None:
    test_1_single_node_single_instance_and_multiple_instances()
    test_2_two_nodes_active_active_with_shared_postgres()
    test_3_pool_below_and_exceeding_the_safe_budget()
    test_4_unknown_inputs_are_unknown_not_zero()
    test_5_reserved_budget_is_configurable_and_role_limits_cap_it()
    test_6_failover_budgets_for_app_and_server_failure()
    test_7_measured_pool_timeouts_exhaustion_and_churn()
    test_8_error_classification_activity_sampling_and_no_one_second_polling()
    test_9_pool_detection_traces_values_to_the_runtime()
    test_10_pm2_instance_discovery()
    test_11_readiness_versus_liveness()
    test_12_failover_test_plan_blocks_database_server_shutdown()
    test_13_application_failures_degrade_the_lifecycle_and_recover()
    test_14_pgbouncer_recommendation_is_evidence_based_and_never_applied()
    test_15_read_only_postgres_collection_never_exposes_credentials_or_writes()
    test_16_credentials_are_redacted_everywhere()
    test_17_no_automatic_database_change_replication_exposure_or_deployment()
    asyncio.run(test_18_orchestrator_persists_the_gate_and_cekloadbalance_shows_it())
    asyncio.run(test_19_unsafe_pool_blocks_active_active_without_touching_anything())
    asyncio.run(test_20_unknown_gate_follows_the_enforcement_policy_and_legacy_declarations_still_work())
    asyncio.run(test_21_postgres_evidence_file_feeds_measured_capacity_and_alerts_once())
    asyncio.run(test_22_server2_database_connectivity_failure_and_app_failure_are_not_ready())
    asyncio.run(test_23_duplicate_cloudflare_pool_and_monitor_are_detected())
    test_24_configuration_defaults_yaml_and_validation()
    test_25_metrics_are_registered_once_and_exported()
    test_26_cli_analyze_sql_and_assemble()
    test_27_validation_gate_requires_pool_safety_pass()
    test_28_hygiene()
    print("\nALL LOAD BALANCER POOL GATE TESTS PASSED")


if __name__ == "__main__":
    main()
