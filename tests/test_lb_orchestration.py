from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _lb_fakes import DOMAIN, Env, SimulatedCrash, make_config, make_report, origin_ips
from config.manager import LbDomainConfig
from core.lb_model import OpStatus
from core.lb_origin import ReportLoad


def ip(n: int) -> str:
    return f"203.0.113.{10 + n}"


async def apply(env: Env, n: int = None, **kwargs):
    return await env.orch.genloadbalance(DOMAIN, origin_ips(n or env.n), operator="tester", apply=True, confirmed=True, **kwargs)


def pool_origins(env: Env):
    pool = next(iter(env.cf.pools.values()))
    return {o["name"]: o for o in pool["origins"]}


async def test_1_two_three_and_many_origins_healthy() -> None:
    for count in (2, 3, 6):
        env = Env(count)
        result = await apply(env)
        assert result.status == OpStatus.SUCCESS, (count, result.message, result.failed_step)
        assert (len(env.cf.monitors), len(env.cf.pools), len(env.cf.lbs)) == (1, 1, 1)
        origins = pool_origins(env)
        assert len(origins) == count and all(o["enabled"] for o in origins.values())
        status = result.final_status
        assert status.overall == "ACTIVE" and status.serving_count == count and status.healthy_count == count
        lb = next(iter(env.cf.lbs.values()))
        assert lb["enabled"] is True and lb["description"] == f"rtsa:{DOMAIN}:loadbalance"
        assert env.cf.mutations().count("create_load_balancer") == 1
        assert env.cf.call_counts.get("create_lb_pool") == 1 and env.cf.call_counts.get("create_lb_monitor") == 1
        calls = sum(env.cf.call_counts.values())
        assert calls <= 40, f"Cloudflare API calls must stay bounded, got {calls} for {count} origins"
        assert env.metrics.snapshot()["counters"]["lb_operations_success_total"] == 1
    print("Test 1 (2, 3 and 6 healthy origins -> exactly one monitor/pool/LB, all enabled and serving, bounded API calls) PASSED")


async def test_2_one_and_multiple_origins_down() -> None:
    env = Env(3)
    env.ports.down.add(ip(3))
    result = await apply(env)
    assert result.status == OpStatus.SUCCESS
    origins = pool_origins(env)
    assert origins["server3"]["enabled"] is False and origins["server1"]["enabled"] and origins["server2"]["enabled"]
    assert ip(3) not in env.cf.enabled_addresses_ever(), "an unreachable origin must never be enabled, not even transiently"
    assert result.final_status.overall == "DEGRADED"
    down = next(a for a in result.plan.origins if a.spec.origin_id == "server3")
    assert down.decision == "DISABLE" and "PORT_UNREACHABLE" in down.reasons

    env = Env(4)
    env.ports.down.update({ip(2), ip(4)})
    result = await apply(env)
    assert result.status == OpStatus.SUCCESS
    origins = pool_origins(env)
    assert [n for n, o in origins.items() if o["enabled"]] == ["server1", "server3"]
    assert result.final_status.overall == "DEGRADED" and result.final_status.serving_count == 2
    print("Test 2 (one and multiple origins down are added DISABLED, never enabled, LB stays on healthy origins) PASSED")


async def test_3_all_origins_down_no_mutation() -> None:
    env = Env(3)
    env.ports.down.update({ip(1), ip(2), ip(3)})
    result = await apply(env)
    assert result.status == OpStatus.ABORTED, result.status
    assert "MINIMUM_HEALTHY_ORIGINS" in result.plan.blocker_codes()
    assert env.cf.mutations() == [], "no Cloudflare mutation when every origin is down"
    assert env.store.domain(DOMAIN) is None
    assert env.metrics.snapshot()["counters"]["lb_operations_failed_total"] == 1
    cats = env.categories()
    assert cats.count("LB_ORIGIN_SETUP_FAILED") == 3
    print("Test 3 (all origins down -> ABORTED by minimum_healthy_origins, zero Cloudflare mutations, production path preserved) PASSED")


async def test_4_setup_failure_disables_origin_and_dedups_alert() -> None:
    env = Env(3)
    env.ports.reports["server2"] = ReportLoad("OK", make_report("server2", blockers=["NGINX_VHOST_MISSING"], vhost_state="MISSING"))
    result = await apply(env)
    assert result.status == OpStatus.SUCCESS
    assert pool_origins(env)["server2"]["enabled"] is False
    assert env.categories().count("LB_ORIGIN_SETUP_FAILED") == 1
    again = await apply(env)
    assert again.status == OpStatus.NOOP
    assert env.categories().count("LB_ORIGIN_SETUP_FAILED") == 1, "the same setup failure is not re-announced on every run"
    assert env.metrics.snapshot()["counters"]["lb_notifications_suppressed"] >= 1
    print("Test 4 (Server2 setup failure -> Server2 DISABLED, LB safe on the others, one alert then suppressed) PASSED")


async def test_5_cloudflare_failure_rolls_back_only_this_operation() -> None:
    steps = {
        "create_lb_monitor": (True, 0, 0, 0),
        "create_lb_pool": (True, 0, 0, 0),
        "update_lb_pool": (False, 0, 0, 0),
        "create_load_balancer": (False, 0, 0, 0),
    }
    for method in ("create_lb_monitor", "create_lb_pool", "update_lb_pool", "create_load_balancer"):
        env = Env(3)
        env.cf.fail_methods[method] = "injected 500"
        result = await apply(env)
        assert result.status in (OpStatus.FAILED, OpStatus.ROLLED_BACK), (method, result.status)
        assert result.rollback_result in ("NOT NEEDED", "COMPLETE"), (method, result.rollback_result)
        assert (len(env.cf.monitors), len(env.cf.pools), len(env.cf.lbs)) == (0, 0, 0), (method, "everything created by the operation is removed")
        assert result.status != OpStatus.SUCCESS
        assert env.metrics.snapshot()["counters"]["lb_operations_failed_total"] == 1
    env = Env(3)
    env.cf.fail_methods["update_load_balancer"] = "injected 500"
    result = await apply(env)
    assert result.status == OpStatus.ROLLED_BACK and result.rollback_result == "COMPLETE", (result.status, result.rollback_result)
    assert (len(env.cf.monitors), len(env.cf.pools), len(env.cf.lbs)) == (0, 0, 0)
    assert env.metrics.snapshot()["counters"]["lb_rollbacks_total"] == 1
    env = Env(3)
    env.cf.fail_methods["list_lb_pools"] = "injected outage"
    result = await apply(env)
    assert result.status == OpStatus.PRECHECK_FAILED and env.cf.mutations() == []
    print("Test 5 (Cloudflare API failure at every step -> STOP and roll back only what this operation created; read failure -> PRECHECK FAILED) PASSED")


async def test_6_existing_dns_conflict_aborts() -> None:
    env = Env(3)
    env.cf.dns.append({"id": "dns-1", "name": DOMAIN, "type": "A", "content": "198.51.100.7", "proxied": True})
    result = await apply(env)
    assert result.status == OpStatus.ABORTED and "DNS_CONFLICT" in result.plan.blocker_codes()
    assert env.cf.mutations() == [] and len(env.cf.dns) == 1
    assert "198.51.100.7" in " ".join(f.message for f in result.plan.conflicts)
    dry = await env.orch.genloadbalance(DOMAIN, origin_ips(3), operator="t", apply=False)
    assert dry.status == OpStatus.DRY_RUN and dry.plan.verdict == "BLOCKED" and dry.plan.conflicts
    print("Test 6 (existing DNS record -> PLAN/ABORT with the exact record, never overwritten or deleted) PASSED")


async def test_7_existing_lb_reuse_and_idempotency() -> None:
    env = Env(3)
    first = await apply(env)
    assert first.status == OpStatus.SUCCESS
    snapshot = json.dumps([env.cf.monitors, env.cf.pools, env.cf.lbs], sort_keys=True)
    before = len(env.cf.mutations())
    second = await apply(env)
    assert second.status == OpStatus.NOOP and "nothing changed" in second.message
    assert len(env.cf.mutations()) == before, "the second identical run performs no Cloudflare mutation"
    assert json.dumps([env.cf.monitors, env.cf.pools, env.cf.lbs], sort_keys=True) == snapshot
    assert second.final_status.overall == "ACTIVE"

    env4 = Env(4, state_dir=env.dir, cloudflare=env.cf)
    env4.ports.reports["server4"] = ReportLoad("OK", make_report("server4"))
    third = await env4.orch.genloadbalance(DOMAIN, origin_ips(4), operator="t", apply=True, confirmed=True)
    assert third.status == OpStatus.SUCCESS
    assert (len(env.cf.monitors), len(env.cf.pools), len(env.cf.lbs)) == (1, 1, 1), "adding an origin reuses monitor, pool and LB"
    assert len(pool_origins(env)) == 4 and pool_origins(env)["server4"]["enabled"]
    created = [m for m in env.cf.mutations() if m.startswith("create_")]
    assert created.count("create_load_balancer") == 1 and created.count("create_lb_pool") == 1

    foreign = Env(3)
    foreign.cf.lbs["lb-x"] = {"id": "lb-x", "name": DOMAIN, "description": "someone else", "default_pools": ["p"], "enabled": True}
    blocked = await apply(foreign)
    assert blocked.status == OpStatus.ABORTED and "FOREIGN_RESOURCE_CONFLICT" in blocked.plan.blocker_codes()
    assert foreign.cf.mutations() == [] and foreign.cf.lbs["lb-x"]["description"] == "someone else"
    print("Test 7 (re-run -> verified NOOP with zero mutations; added origin reuses monitor/pool/LB; foreign LB is never touched) PASSED")


async def test_8_duplicate_command_single_flight() -> None:
    env = Env(3)
    first, second = await asyncio.gather(apply(env), apply(env))
    statuses = sorted(r.status.value for r in (first, second))
    assert statuses == ["BUSY", "SUCCESS"], statuses
    assert (len(env.cf.monitors), len(env.cf.pools), len(env.cf.lbs)) == (1, 1, 1)
    busy = first if first.status == OpStatus.BUSY else second
    assert busy.holder
    other = await env.orch.addloadbalance(DOMAIN, operator="t")
    assert other.status in (OpStatus.DRY_RUN, OpStatus.ABORTED)
    print("Test 8 (duplicate concurrent /genloadbalance -> one SUCCESS and one BUSY, never duplicate resources; per-domain lock) PASSED")


async def test_9_db_unreachable_and_version_mismatch() -> None:
    env = Env(3)
    report = make_report("server2", db_level="NONE", blockers=["DB_UNREACHABLE"])
    env.ports.reports["server2"] = ReportLoad("OK", report)
    result = await apply(env)
    assert result.status == OpStatus.SUCCESS
    assert pool_origins(env)["server2"]["enabled"] is False
    assert "LB_DB_CONNECTIVITY_FAILURE" in env.categories()
    assert ip(2) not in env.cf.enabled_addresses_ever()
    assert result.final_status.serving_count == 2

    env = Env(3)
    env.ports.reports["server3"] = ReportLoad("OK", make_report("server3", app_version="2.4.0+def", schema_version="41:old"))
    result = await apply(env)
    assert result.status == OpStatus.SUCCESS
    mismatch = next(a for a in result.plan.origins if a.spec.origin_id == "server3")
    assert "VERSION_MISMATCH" in mismatch.reasons and mismatch.decision == "DISABLE"
    assert pool_origins(env)["server3"]["enabled"] is False
    status = await env.monitor.status(DOMAIN, force=True, full=True)
    by_id = {o.origin_id: o for o in status.origins}
    assert by_id["server3"].label == "DISABLED" and by_id["server1"].label == "SERVING"

    env = Env(2)
    env.ports.reports["server2"] = ReportLoad("OK", make_report("server2", app_version="2.4.0+def", schema_version="41:old"))
    result = await apply(env)
    assert result.status == OpStatus.SUCCESS, "with a tie the local orchestrator origin is the reference; the other is disabled"
    assert pool_origins(env)["server1"]["enabled"] and not pool_origins(env)["server2"]["enabled"]
    print("Test 9 (DB unreachable -> origin NOT SERVING + alert; version/schema mismatch -> VERSION_MISMATCH, never enabled) PASSED")


async def test_10_database_architecture_blocks() -> None:
    env = Env(3)
    env.ports.reports["server2"] = ReportLoad("OK", make_report("server2", db_mode="LOCAL_PER_ORIGIN"))
    result = await apply(env)
    assert result.status == OpStatus.ABORTED and "DB_LOCAL_PER_ORIGIN" in result.plan.blocker_codes()
    assert env.cf.mutations() == []

    env = Env(3)
    env.ports.reports["server3"] = ReportLoad("OK", make_report("server3", db_host="other-db.internal"))
    result = await apply(env)
    assert result.status == OpStatus.ABORTED and "DB_TARGET_MISMATCH" in result.plan.blocker_codes()

    env = Env(3)
    env.ports.reports["server3"] = ReportLoad("OK", make_report("server3", db_mode="UNKNOWN"))
    result = await apply(env)
    assert result.status == OpStatus.ABORTED and "DB_MODE_UNKNOWN" in result.plan.blocker_codes()

    env = Env(2, cfg=make_config(2, domains=[LbDomainConfig(domain=DOMAIN, db_mode="MULTI_PRIMARY")]))
    env.ports.local_report = make_report("server1", db_mode="MULTI_PRIMARY")
    env.ports.reports["server2"] = ReportLoad("OK", make_report("server2", db_mode="MULTI_PRIMARY"))
    dry = await env.orch.genloadbalance(DOMAIN, origin_ips(2), operator="t", apply=False)
    assert any(w.code == "DB_MODE_WARNING" for w in dry.plan.warnings), "MULTI_PRIMARY is accepted only as an explicit declaration, with a warning"
    assert all(not c.detail.lower().startswith("create database") for c in dry.plan.changes)
    print("Test 10 (LOCAL_PER_ORIGIN / different DB targets / unknown mode block multi-origin activation; MULTI_PRIMARY only as explicit declaration) PASSED")


async def test_11_shared_state_requirement() -> None:
    upload = [{"kind": "uploads", "evidence": "user-writable upload directories hold files on this origin: uploads", "confidence": "HIGH", "blocking": True}]
    env = Env(3)
    env.ports.reports["server2"] = ReportLoad("OK", make_report("server2", stateful=upload))
    result = await apply(env)
    assert result.status == OpStatus.ABORTED and "SHARED_STATE_REQUIRED" in result.plan.blocker_codes()
    assert env.cf.mutations() == []
    messages = " ".join(f.message for f in result.plan.blockers)
    assert "session affinity is not enabled automatically" in messages
    lb_bodies = [b for m, b in env.cf.history if m == "create_load_balancer"]
    assert not lb_bodies

    cfg = make_config(3, domains=[LbDomainConfig(domain=DOMAIN, shared_state={"uploads": "shared"})])
    env = Env(3, cfg=cfg)
    env.ports.reports["server2"] = ReportLoad("OK", make_report("server2", stateful=upload))
    result = await apply(env)
    assert result.status == OpStatus.SUCCESS
    lb = next(iter(env.cf.lbs.values()))
    assert lb["session_affinity"] == "none", "session affinity is never switched on as a universal fix"
    print("Test 11 (local uploads/sessions -> SHARED_STATE_REQUIRED blocks multi-origin; explicit declaration clears it; no automatic affinity) PASSED")


async def test_12_crash_during_operation_is_recoverable() -> None:
    env = Env(3)
    env.cf.crash_after["create_load_balancer"] = 0
    try:
        await apply(env)
        raise AssertionError("the simulated crash must propagate")
    except SimulatedCrash:
        pass
    assert len(env.cf.monitors) == 1 and len(env.cf.pools) == 1 and len(env.cf.lbs) == 0
    assert env.ctx.locks.holder(DOMAIN) is None, "the lock is released even when the process dies mid-operation"
    env.cf.crash_after.clear()
    env.cf.call_counts.clear()
    restarted = env.rebuild()
    recovered = restarted.orch.recover_on_start()
    assert len(recovered) == 1 and recovered[0].status == "INTERRUPTED"
    status = await restarted.monitor.status(DOMAIN, force=True, full=True)
    assert status.interrupted_operation == recovered[0].operation_id
    result = await restarted.orch.genloadbalance(DOMAIN, origin_ips(3), operator="t", apply=True, confirmed=True)
    assert result.status == OpStatus.SUCCESS, (result.status, result.message)
    assert (len(env.cf.monitors), len(env.cf.pools), len(env.cf.lbs)) == (1, 1, 1), "re-running after a crash reuses the partial resources"
    assert restarted.store.interrupted_for(DOMAIN) is None
    print("Test 12 (RTSA crash mid-operation -> state marked INTERRUPTED, lock released, idempotent re-run completes with no duplicates) PASSED")


async def test_13_rollback_failure_is_reported_honestly() -> None:
    env = Env(3)
    env.cf.fail_methods["update_load_balancer"] = "injected activate failure"
    env.cf.fail_methods["delete_load_balancer"] = "injected delete failure"
    result = await apply(env)
    assert result.status == OpStatus.ROLLBACK_INCOMPLETE, result.status
    assert result.rollback_result.startswith("INCOMPLETE")
    assert "LB_ROLLBACK_FAILED" in env.categories()
    event = next(e for e in env.ports.events if e.category.value == "LB_ROLLBACK_FAILED")
    assert event.severity.value == "CRITICAL" and "ROLLBACK_INCOMPLETE" in event.message
    assert len(env.cf.lbs) == 1, "the LB that could not be deleted is reported, not silently forgotten"
    lb = next(iter(env.cf.lbs.values()))
    assert lb["enabled"] is False, "the LB that failed to delete was created disabled and never served traffic"
    assert result.status != OpStatus.SUCCESS
    print("Test 13 (rollback failure -> ROLLBACK_INCOMPLETE + CRITICAL LB_ROLLBACK_FAILED, success is never claimed) PASSED")


async def test_14_dry_run_is_read_only() -> None:
    env = Env(3)
    result = await env.orch.genloadbalance(DOMAIN, origin_ips(3), operator="t", apply=False)
    assert result.status == OpStatus.DRY_RUN and result.plan.verdict == "READY"
    assert env.cf.mutations() == [] and env.store.domain(DOMAIN) is None
    from core.lb_format import format_plan

    title, kind, description, fields = format_plan(result.plan, dry_run=True)
    names = [f[0] for f in fields]
    for required in ("Current state", "Cloudflare changes", "Origin changes", "DATABASE changes", "NGINX changes", "Risk", "Rollback plan"):
        assert required in names, (required, names)
    assert "No change was made" in description
    assert result.plan.planned["enabled_origins"] == ["server1", "server2", "server3"]
    print("Test 14 (dry run shows current/planned state, Cloudflare/origin/DB/NGINX changes, conflicts, risk and rollback plan with zero mutation) PASSED")


async def test_15_confirmation_and_plan_drift() -> None:
    env = Env(3)
    result = await env.orch.genloadbalance(DOMAIN, origin_ips(3), operator="t", apply=True, confirmed=False)
    assert result.status == OpStatus.ABORTED and "confirmation" in result.message
    assert env.cf.mutations() == []
    preview = await env.orch.plan(DOMAIN, origin_ips(3), operator="t")
    env.ports.down.add(ip(3))
    stale = await env.orch.genloadbalance(DOMAIN, origin_ips(3), operator="t", apply=True, confirmed=True, preview_fingerprint=preview.fingerprint)
    assert stale.status == OpStatus.ABORTED and "changed since the preview" in stale.message
    assert env.cf.mutations() == []
    env.ports.allowed = False
    blocked = await apply(env)
    assert blocked.status == OpStatus.ABORTED and "detection-only" in blocked.message and env.cf.mutations() == []
    print("Test 15 (apply needs explicit confirmation; a state change after the preview aborts; detection-only mode blocks mutation) PASSED")


async def test_16_identity_and_authorization_gates() -> None:
    env = Env(3, server_id="server2")
    result = await apply(env)
    assert result.status == OpStatus.ABORTED and "NOT_ORCHESTRATOR" in result.plan.blocker_codes()
    assert env.cf.mutations() == [] and env.cf.calls == []
    env = Env(3, server_id="")
    result = await apply(env)
    assert result.status == OpStatus.ABORTED and "NOT_ORCHESTRATOR" in result.plan.blocker_codes()
    env = Env(3, cfg=make_config(3, enabled=False))
    result = await apply(env)
    assert result.status == OpStatus.ABORTED and "LOAD_BALANCING_DISABLED" in result.plan.blocker_codes()
    env = Env(3, cloudflare=None)
    result = await apply(env)
    assert result.status == OpStatus.PRECHECK_FAILED and "CLOUDFLARE_UNAVAILABLE" in result.plan.blocker_codes()
    assert "manual DNS" in result.plan.blockers[0].message
    print("Test 16 (only the configured orchestrator identity may orchestrate; disabled config and missing credentials -> PRECHECK FAILED, no manual DNS fallback) PASSED")


async def test_17_ssrf_and_inventory_authorization() -> None:
    env = Env(3)
    attempts = ["127.0.0.1", "localhost", "169.254.169.254", "10.9.9.9", "198.51.100.99", "http://evil.example", "::1", "0.0.0.0", "203.0.113.11:8080"]
    for target in attempts:
        result = await env.orch.genloadbalance(DOMAIN, target, operator="t", apply=False)
        assert result.plan.verdict == "BLOCKED", target
        codes = result.plan.blocker_codes()
        assert any(c in codes for c in ("FORBIDDEN_TARGET", "ORIGIN_NOT_AUTHORIZED", "INVALID_ADDRESS")), (target, codes)
    assert env.ports.tcp_calls == 0 and env.ports.http_calls == 0, "rejected targets are never probed"
    assert env.cf.calls == [], "rejected input does not even reach Cloudflare"
    mixed = await env.orch.genloadbalance(DOMAIN, "203.0.113.11 169.254.169.254", operator="t", apply=False)
    assert mixed.plan.verdict == "BLOCKED" and env.ports.tcp_calls == 0
    print("Test 17 (127.0.0.1/localhost/metadata/unknown private/unknown public/URLs rejected before any probe; origins must be in the authorized inventory) PASSED")


async def test_18_prune_and_drain() -> None:
    env = Env(3)
    await apply(env)
    kept = Env(3, state_dir=env.dir, cloudflare=env.cf)
    plan = await kept.orch.plan(DOMAIN, f"{ip(1)} {ip(2)}", operator="t")
    assert plan.kept == ["server3"] and plan.drain == [], "without --prune an omitted origin is kept"
    pruned = await kept.orch.genloadbalance(DOMAIN, f"{ip(1)} {ip(2)}", operator="t", apply=True, confirmed=True, prune=True)
    assert pruned.status == OpStatus.SUCCESS, (pruned.status, pruned.message)
    assert sorted(pool_origins(env)) == ["server1", "server2"]
    sequence = [h for h in env.cf.history if h[0] == "update_lb_pool"]
    drain_bodies = [b for _, b in sequence if any(o["name"] == "server3" and not o["enabled"] for o in b.get("origins", []))]
    assert drain_bodies, "the origin is DRAINING (disabled) before it is removed"
    assert any(s >= 5.0 for s in kept.ports.sleeps), "drain waits for stabilisation"

    guarded = Env(3, state_dir=env.dir + "-g", min_healthy=2)
    await apply(guarded)
    guarded.cf.unhealthy_addresses.add(ip(2))
    result = await guarded.orch.genloadbalance(DOMAIN, f"{ip(1)} {ip(2)}", operator="t", apply=True, confirmed=True, prune=True)
    assert result.status in (OpStatus.ROLLED_BACK, OpStatus.ABORTED, OpStatus.FAILED), result.status
    assert "server3" in pool_origins(guarded), "a failed drain restores the original pool"
    print("Test 18 (omitted origins are kept unless --prune; prune drains (disable, wait, verify, remove); failed drain restores the pool) PASSED")


async def test_19_data_plane_failure_rolls_back_cutover() -> None:
    env = Env(3)
    env.ports.public_ok = False
    result = await apply(env)
    assert result.status == OpStatus.ROLLED_BACK and result.failed_step == "verify"
    assert (len(env.cf.monitors), len(env.cf.pools), len(env.cf.lbs)) == (0, 0, 0)

    env = Env(3)
    assert (await apply(env)).status == OpStatus.SUCCESS
    before_lb = json.dumps(next(iter(env.cf.lbs.values())), sort_keys=True)
    env.ports.public_ok = False
    env.ports.reports["server4"] = ReportLoad("OK", make_report("server4"))
    env4 = Env(4, state_dir=env.dir, cloudflare=env.cf)
    env4.ports = env.ports
    env4.ctx.ports = env.ports
    env4.ports.reports["server4"] = ReportLoad("OK", make_report("server4"))
    failed = await env4.orch.genloadbalance(DOMAIN, origin_ips(4), operator="t", apply=True, confirmed=True)
    assert failed.status == OpStatus.ROLLED_BACK
    assert json.dumps(next(iter(env.cf.lbs.values())), sort_keys=True) == before_lb
    assert len(pool_origins(env)) == 3, "the origin list is restored to the snapshot"
    print("Test 19 (data-plane verification failure -> rollback of exactly this operation; pre-existing LB/pool restored from the snapshot) PASSED")


async def test_20_cloudflare_health_failure_disables_origin_again() -> None:
    env = Env(3)
    env.cf.unhealthy_addresses.add(ip(3))
    result = await apply(env)
    assert result.status == OpStatus.SUCCESS
    assert pool_origins(env)["server3"]["enabled"] is False
    assert any(f.code == "CLOUDFLARE_HEALTH_FAILED" for a in result.plan.origins for f in a.findings)
    assert result.final_status.overall == "DEGRADED"
    env = Env(2, min_healthy=2)
    env.cf.unhealthy_addresses.add(ip(2))
    result = await apply(env)
    assert result.status == OpStatus.ROLLED_BACK, "fewer healthy origins than the minimum after enabling -> everything is rolled back"
    assert (len(env.cf.pools), len(env.cf.lbs)) == (0, 0)
    print("Test 20 (origin healthy for RTSA but unhealthy in Cloudflare is disabled again; below the minimum everything is rolled back) PASSED")


async def test_21_origin_quality_gates() -> None:
    cases = {
        "TLS_INVALID": lambda e: e.ports.tls_untrusted.add(ip(2)),
        "HEALTH_ENDPOINT_LEAK": lambda e: e.ports.http_leak.__setitem__(ip(2), "credential"),
        "HOST_HEADER_FAILED": lambda e: e.ports.http_status.__setitem__(ip(2), 421),
        "HEALTH_ENDPOINT_NOT_FOUND": lambda e: e.ports.http_status.__setitem__(ip(2), 404),
        "HEALTH_ENDPOINT_UNHEALTHY": lambda e: e.ports.http_status.__setitem__(ip(2), 503),
    }
    for code, mutate in cases.items():
        env = Env(3)
        mutate(env)
        result = await apply(env)
        assert result.status == OpStatus.SUCCESS, (code, result.status)
        origin = next(a for a in result.plan.origins if a.spec.origin_id == "server2")
        assert code in origin.reasons, (code, origin.reasons)
        assert pool_origins(env)["server2"]["enabled"] is False and ip(2) not in env.cf.enabled_addresses_ever()
    env = Env(3)
    env.ports.reports["server2"] = ReportLoad("OK", make_report("server2", scheme="http", port=80))
    result = await apply(env)
    assert any("ORIGIN_PARAMETER_MISMATCH" == f.code for f in result.plan.blockers), "origins must agree on one scheme/port/health path"
    print("Test 21 (TLS invalid / health leak / Host header / missing or failing health endpoint / mixed endpoints -> origin disabled or plan blocked) PASSED")


async def test_22_monitor_and_pool_settings() -> None:
    cfg = make_config(3, domains=[LbDomainConfig(domain=DOMAIN, health_path="/status")])
    env = Env(3, cfg=cfg)
    result = await apply(env)
    assert result.status == OpStatus.SUCCESS
    monitor = next(iter(env.cf.monitors.values()))
    assert monitor["path"] == "/status", "the health path comes from project configuration, not a hardcoded default"
    assert monitor["header"] == {"Host": [DOMAIN]} and monitor["type"] == "https" and monitor["method"] == "GET"
    assert monitor["allow_insecure"] is False, "certificate validation stays on by default"
    assert monitor["interval"] >= 30 and monitor["consecutive_down"] >= 2 and monitor["consecutive_up"] >= 1 and monitor["timeout"] <= 10
    assert monitor["description"] == f"rtsa:{DOMAIN}:monitor" and monitor["port"] == 443
    pool = next(iter(env.cf.pools.values()))
    assert pool["description"] == f"rtsa:{DOMAIN}:pool" and pool["name"] == "rtsa-example-com-pool"
    assert pool["minimum_origins"] == 1 and pool["origin_steering"] == {"policy": "random"}
    assert all(o["header"] == {"Host": [DOMAIN]} for o in pool["origins"]), "the domain Host header is used, not the origin IP"
    lb = next(iter(env.cf.lbs.values()))
    assert lb["steering_policy"] == "off" and lb["proxied"] is True
    status = result.final_status
    assert status.steering == "off" and status.origin_steering == "random"

    env = Env(3)
    env.ports.reports["server2"] = ReportLoad("OK", make_report("server2", health_path=""))
    env.ports.reports["server3"] = ReportLoad("OK", make_report("server3", health_path=""))
    env.ports.local_report = make_report("server1", health_path="")
    result = await apply(env)
    assert result.status == OpStatus.ABORTED and "ORIGIN_ENDPOINT_UNKNOWN" in {f.code for a in result.plan.origins for f in a.findings}
    print("Test 22 (monitor: configured path, Host header, HTTPS verified, non-aggressive thresholds; pool/LB tagging and steering reported as configured) PASSED")


async def test_23_no_secret_reaches_state_or_audit() -> None:
    secret = "cf-token-0123456789abcdef0123456789abcdef01234567"
    env = Env(3)
    env.cf.fail_methods["create_lb_pool"] = f"Authorization: Bearer {secret} password=hunter2hunter2"
    result = await apply(env)
    assert result.status in (OpStatus.FAILED, OpStatus.ROLLED_BACK)
    blob = open(env.store.path, encoding="utf-8").read() + json.dumps(env.ports.audits, default=str)
    blob += " ".join(e.message for e in env.ports.events) + result.message + (result.rollback_result or "")
    assert secret not in blob and "hunter2" not in blob, "secrets must never be persisted, audited or alerted"
    print("Test 23 (API error text with bearer token/password is scrubbed from state, audit log, alerts and results) PASSED")


async def test_24_audit_record_contents() -> None:
    env = Env(3)
    result = await apply(env)
    entry = env.store.last_audit()
    for key in ("operation_id", "operator", "server", "domain", "old_state", "planned_state", "actual_changes", "cloudflare_ids", "origin_changes",
                "db_changes", "rollback_result", "final_status", "timestamp"):
        assert key in entry, key
    assert entry["operator"] == "tester" and entry["server"] == "server1" and entry["domain"] == DOMAIN and entry["final_status"] == "SUCCESS"
    assert entry["cloudflare_ids"]["monitor"] and entry["cloudflare_ids"]["pool"] and entry["cloudflare_ids"]["load_balancer"]
    assert env.ports.audits and env.ports.audits[-1]["status"] == "SUCCESS"
    reload_state = env.rebuild().store
    reload_state.load()
    assert reload_state.domain(DOMAIN).lb_id == next(iter(env.cf.lbs))
    assert sorted(reload_state.domain(DOMAIN).origins) == ["server1", "server2", "server3"]
    print("Test 24 (every mutation is audited with operation id, operator, server, domain, states, Cloudflare IDs and final status; state persists) PASSED")


async def test_25_bounded_origin_count() -> None:
    env = Env(20)
    result = await env.orch.genloadbalance(DOMAIN, origin_ips(20), operator="t", apply=False)
    assert result.plan.verdict == "BLOCKED" and any(f.code == "TOO_MANY_ORIGINS" or "TOO_MANY_ORIGINS" in f.message for f in result.plan.blockers)
    assert env.ports.tcp_calls == 0
    print("Test 25 (origins beyond max_origins are rejected before probing) PASSED")


async def test_26_db_connection_budget_limits_origins() -> None:
    cfg = make_config(4, domains=[LbDomainConfig(domain=DOMAIN, app_connection_pool=100, db_max_connections=300, db_current_connections=0)])
    env = Env(4, cfg=cfg)
    result = await apply(env)
    assert result.status == OpStatus.SUCCESS
    enabled = [n for n, o in pool_origins(env).items() if o["enabled"]]
    assert len(enabled) == 2, f"3 x 100 connections exceed 80% of 300; only 2 origins fit, got {enabled}"
    capped = [a for a in result.plan.origins if "DB_CAPACITY_RISK" in a.reasons]
    assert len(capped) == 2 and all(a.decision == "DISABLE" for a in capped)
    assert result.final_status.overall == "DEGRADED"
    roomy = Env(4, cfg=make_config(4, domains=[LbDomainConfig(domain=DOMAIN, app_connection_pool=50, db_max_connections=1000)]))
    ok = await apply(roomy)
    assert ok.status == OpStatus.SUCCESS and all(o["enabled"] for o in pool_origins(roomy).values())
    assert ok.plan.db.budget.status == "OK" and "4 origins x 50 pool = 200" in ok.plan.db.budget.detail
    print("Test 26 (origins x pool vs max_connections: extra origins stay DISABLED with DB_CAPACITY_RISK; roomy budget enables all) PASSED")


async def test_27_malformed_remote_endpoint_is_never_probed() -> None:
    env = Env(3)
    env.ports.reports["server2"] = ReportLoad("OK", make_report("server2", health_path="/a b;rm -rf", scheme="https"))
    env.ports.reports["server3"] = ReportLoad("OK", make_report("server3", scheme="ftp", port=70000))
    before = env.ports.http_calls
    result = await env.orch.genloadbalance(DOMAIN, origin_ips(3), operator="t", apply=False)
    by_id = {a.spec.origin_id: a for a in result.plan.origins}
    assert "ORIGIN_ENDPOINT_INVALID" in by_id["server2"].reasons and by_id["server2"].http is None
    assert "ORIGIN_ENDPOINT_INVALID" in by_id["server3"].reasons and by_id["server3"].http is None
    assert env.ports.http_calls - before == 1, "only the well-formed origin was probed"
    assert any(f.code == "ORIGIN_PARAMETER_MISMATCH" for f in result.plan.blockers) or by_id["server1"].decision == "ENABLE"
    print("Test 27 (a signed report with a malformed scheme/port/health path is rejected before any probe) PASSED")


async def main() -> None:
    for test in (
        test_1_two_three_and_many_origins_healthy, test_2_one_and_multiple_origins_down, test_3_all_origins_down_no_mutation,
        test_4_setup_failure_disables_origin_and_dedups_alert, test_5_cloudflare_failure_rolls_back_only_this_operation,
        test_6_existing_dns_conflict_aborts, test_7_existing_lb_reuse_and_idempotency, test_8_duplicate_command_single_flight,
        test_9_db_unreachable_and_version_mismatch, test_10_database_architecture_blocks, test_11_shared_state_requirement,
        test_12_crash_during_operation_is_recoverable, test_13_rollback_failure_is_reported_honestly, test_14_dry_run_is_read_only,
        test_15_confirmation_and_plan_drift, test_16_identity_and_authorization_gates, test_17_ssrf_and_inventory_authorization,
        test_18_prune_and_drain, test_19_data_plane_failure_rolls_back_cutover, test_20_cloudflare_health_failure_disables_origin_again,
        test_21_origin_quality_gates, test_22_monitor_and_pool_settings, test_23_no_secret_reaches_state_or_audit,
        test_24_audit_record_contents, test_25_bounded_origin_count, test_26_db_connection_budget_limits_origins,
        test_27_malformed_remote_endpoint_is_never_probed,
    ):
        await test()
    print("\nALL LOAD BALANCER ORCHESTRATION TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
