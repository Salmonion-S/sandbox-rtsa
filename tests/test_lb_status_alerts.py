from __future__ import annotations

import asyncio
import json
import os
import sys
from unittest import mock

_TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _TESTS)
os.chdir(os.path.dirname(_TESTS))

from _lb_fakes import DOMAIN, Env, make_report, origin_ips
from core.lb_format import format_status
from core.lb_model import OpStatus
from core.lb_origin import ReportLoad
from core.pipeline_metrics import get_lb_metrics

NAMES = {"server1": "Server1", "server2": "Server2", "server3": "Server3", "server4": "Server4"}


def ip(n: int) -> str:
    return f"203.0.113.{10 + n}"


async def deploy(n: int = 3, **kwargs) -> Env:
    env = Env(n, **kwargs)
    result = await env.orch.genloadbalance(DOMAIN, origin_ips(n), operator="t", apply=True, confirmed=True)
    assert result.status == OpStatus.SUCCESS, (result.status, result.message)
    env.ports.events.clear()
    return env


def text_of(status) -> str:
    return format_status(status, NAMES)[2]


async def test_1_cek_output_distinguishes_configured_healthy_serving() -> None:
    env = Env(4)
    env.ports.reports["server4"] = ReportLoad("OK", make_report("server4", blockers=["NGINX_VHOST_MISSING"]))
    assert (await env.orch.genloadbalance(DOMAIN, origin_ips(4), operator="t", apply=True, confirmed=True)).status == OpStatus.SUCCESS
    env.cf.unhealthy_addresses.add(ip(3))
    status = await env.monitor.status(DOMAIN, force=True, full=True)
    out = text_of(status)
    assert "Server1 203.0.113.11 -> HEALTHY / SERVING" in out
    assert "Server2 203.0.113.12 -> HEALTHY / SERVING" in out
    assert "Server3 203.0.113.13 -> UNHEALTHY / NOT SERVING" in out
    assert "Server4 203.0.113.14 -> UNKNOWN / DISABLED" in out
    for expected in ("Domain: example.com", "Overall: DEGRADED", "Cloudflare: CONNECTED", "LB ID: lb-", "Pool: rtsa-example-com-pool", "Monitor: mon-",
                     "Steering: off (origin steering: random)", "Origins: 4", "Healthy: 2", "Serving: 2", "Disabled: 1", "203.0.113.11:443", "HTTP 200", "RTT 42ms",
                     "LOAD BALANCE: SERVING", "LOAD BALANCE: NOT SERVING", "LOAD BALANCE: DISABLED", "Reason: UPSTREAM_TIMEOUT",
                     "Reason: health check unavailable", "DB:", "PRIMARY_SHARED", "Connectivity: 4/4", "Config Drift: NONE", "Last Verified:", "RTSA — LOAD BALANCE STATUS"):
        assert expected in out or expected in format_status(status, NAMES)[0], expected
    assert "CONFIGURED: yes | HEALTHY: yes | SERVING: yes | TRAFFIC_OBSERVED: NOT_VERIFIABLE" in out
    assert "CONFIGURED: yes | HEALTHY: no | SERVING: no" in out
    assert "TRAFFIC_DISTRIBUTION: NOT_VERIFIABLE" in out
    assert "%" not in out, "no percentages are ever invented"
    assert "round" not in out.lower(), "never claims round-robin"
    title, kind, description, fields = format_status(status, NAMES)
    assert kind == "warning" and len(description) < 4096
    print("Test 1 (/cekloadbalance: per-server HEALTHY/UNHEALTHY/UNKNOWN + SERVING/NOT SERVING/DISABLED, RTT, HTTP code, reason, steering as configured, no invented traffic share) PASSED")


async def test_2_traffic_distribution_only_when_measurable() -> None:
    env = await deploy(3)
    status = await env.monitor.status(DOMAIN, force=True, full=True)
    assert status.traffic_distribution == "NOT_VERIFIABLE" and status.traffic_share == {}
    env.ports.traffic = {"server1": 300, "server2": 100}
    status = await env.monitor.status(DOMAIN, force=True, full=True)
    assert status.traffic_distribution == "NOT_VERIFIABLE", "server3 is serving but has no counter: distribution is not claimed"
    by_id = {o.origin_id: o.traffic_observed for o in status.origins}
    assert by_id == {"server1": "OBSERVED", "server2": "OBSERVED", "server3": "NOT_VERIFIABLE"}
    env.ports.traffic = {"server1": 300, "server2": 100, "server3": 0}
    status = await env.monitor.status(DOMAIN, force=True, full=True)
    assert status.traffic_distribution == "MEASURED" and status.traffic_share == {"server1": 75.0, "server2": 25.0, "server3": 0.0}
    assert status.origins[2].traffic_observed == "NONE", "healthy and serving is not the same as traffic observed"
    assert "TRAFFIC_DISTRIBUTION: Server1 75.0%, Server2 25.0%, Server3 0.0%" in text_of(status)
    print("Test 2 (TRAFFIC_DISTRIBUTION is NOT_VERIFIABLE unless every serving origin has a counter; healthy/serving never implies traffic observed) PASSED")


async def test_3_overall_status_layers() -> None:
    env = await deploy(3)
    ok = await env.monitor.status(DOMAIN, force=True, full=True)
    assert ok.overall == "ACTIVE" and ok.control_plane["ok"] and ok.data_plane["ok"]
    env.ports.public_ok = False
    degraded = await env.monitor.status(DOMAIN, force=True, full=True)
    assert degraded.overall == "DEGRADED" and not degraded.data_plane["ok"] and degraded.serving_count == 3, "one failing layer -> DEGRADED"
    assert "HTTPS request through the public hostname failed" in " ".join(degraded.reasons)
    env.ports.public_ok = True
    env.ports.dns_answers = []
    dns = await env.monitor.status(DOMAIN, force=True, full=True)
    assert dns.overall == "DEGRADED" and "DNS does not resolve the hostname" in dns.reasons
    env.ports.dns_answers = ["104.16.0.1"]
    env.cf.unhealthy_addresses.update({ip(1), ip(2)})
    one_left = await env.monitor.status(DOMAIN, force=True, full=True)
    assert one_left.overall == "DEGRADED" and one_left.serving_count == 1
    env.cf.unhealthy_addresses.add(ip(3))
    env.ports.public_ok = False
    dead = await env.monitor.status(DOMAIN, force=True, full=True)
    assert dead.overall == "FAILED" and dead.serving_count == 0 and "LB_UNAVAILABLE" in " ".join(dead.reasons)
    env.cf.unhealthy_addresses.clear()
    env.ports.public_ok = True
    next(iter(env.cf.lbs.values()))["enabled"] = False
    disabled = await env.monitor.status(DOMAIN, force=True, full=True)
    assert disabled.overall == "FAILED" and "load balancer is disabled in Cloudflare" in disabled.reasons
    next(iter(env.cf.lbs.values()))["enabled"] = True
    env.cf.unreachable_health = True
    unknown = await env.monitor.status(DOMAIN, force=True, full=True)
    assert unknown.overall == "DEGRADED" and all(o.health == "UNKNOWN" for o in unknown.origins), "no health data means UNKNOWN, never HEALTHY"
    assert not any(o.serving for o in unknown.origins)
    env.cf.unreachable_health = False
    env.cf.fail_methods["list_lb_monitors"] = "api down"
    unreachable = await env.monitor.status(DOMAIN, force=True, full=True)
    assert unreachable.cloudflare == "UNREACHABLE" and unreachable.overall == "DEGRADED" and "control plane unverifiable" in " ".join(unreachable.reasons)
    env.ports.public_ok = False
    dead2 = await env.monitor.status(DOMAIN, force=True, full=True)
    assert dead2.overall == "FAILED"
    none = Env(3, cloudflare=None)
    status = await none.monitor.status(DOMAIN, force=True, full=True)
    assert status.overall == "NOT_CONFIGURED" and status.cloudflare == "NOT_CONFIGURED"
    unmanaged = Env(3)
    assert (await unmanaged.monitor.status("other.example.com", force=True, full=True)).overall == "NOT_CONFIGURED"
    print("Test 3 (control plane + data plane layered status: any failing layer -> DEGRADED; nothing serving -> FAILED; unknown health is never HEALTHY) PASSED")


async def test_4_status_is_cached_and_bounded() -> None:
    env = await deploy(3)
    env.ports.mono += env.cfg.status_cache_ttl_seconds + 1
    env.cf.calls.clear()
    first = await env.monitor.status(DOMAIN, full=True)
    first_calls = len(env.cf.calls)
    assert first_calls > 0
    second = await env.monitor.status(DOMAIN, full=True)
    assert second is first and len(env.cf.calls) == first_calls, "a second /cekloadbalance inside the TTL costs no API call"
    env.ports.mono += env.cfg.status_cache_ttl_seconds + 1
    await env.monitor.status(DOMAIN, full=True)
    assert len(env.cf.calls) > first_calls
    env.cf.calls.clear()

    async def slow_dns(domain, timeout):
        await asyncio.sleep(0.02)
        return ["104.16.0.1"]

    env.ports.resolve_dns = slow_dns
    results = await asyncio.gather(*(env.monitor.status(DOMAIN, force=True, full=True) for _ in range(8)))
    assert all(r is results[0] for r in results), "concurrent requests share one in-flight computation (single flight)"
    full_calls = len(env.cf.calls)
    env.cf.calls.clear()
    light = await env.monitor.status(DOMAIN, force=True, full=False)
    assert len(env.cf.calls) <= 4 < full_calls, "the periodic poll uses a light snapshot (LB + pool + health)"
    assert {m for m, _ in env.cf.calls} <= {"get_load_balancer", "get_lb_pool", "get_lb_pool_health"}
    assert light.overall == "ACTIVE" and not light.full_check
    print("Test 4 (TTL cache, single-flight and light polling keep Cloudflare API calls bounded) PASSED")


async def test_5_drift_detection_without_auto_repair() -> None:
    mutations = {
        "origin removed": lambda cf: cf.pools[next(iter(cf.pools))].__setitem__("origins", [o for o in cf.pools[next(iter(cf.pools))]["origins"] if o["name"] != "server3"]),
        "IP changed": lambda cf: cf.pools[next(iter(cf.pools))]["origins"][0].__setitem__("address", "198.51.100.77"),
        "monitor changed": lambda cf: cf.monitors[next(iter(cf.monitors))].__setitem__("interval", 5),
        "LB changed": lambda cf: cf.lbs[next(iter(cf.lbs))].__setitem__("steering_policy", "random"),
        "pool changed": lambda cf: cf.pools[next(iter(cf.pools))].__setitem__("minimum_origins", 5),
        "origin enabled flag": lambda cf: cf.pools[next(iter(cf.pools))]["origins"][1].__setitem__("enabled", False),
        "DNS changed": lambda cf: cf.dns.append({"id": "d", "name": DOMAIN, "type": "A", "content": "198.51.100.9", "proxied": True}),
        "extra origin": lambda cf: cf.pools[next(iter(cf.pools))]["origins"].append({"name": "rogue", "address": "198.51.100.66", "enabled": True, "weight": 1, "header": {"Host": [DOMAIN]}}),
        "health endpoint changed": lambda cf: cf.monitors[next(iter(cf.monitors))].__setitem__("path", "/other"),
    }
    expected_kind = {
        "origin removed": "ORIGIN_REMOVED", "IP changed": "IP_CHANGED", "monitor changed": "MONITOR_CHANGED", "LB changed": "LB_CHANGED",
        "pool changed": "POOL_CHANGED", "origin enabled flag": "POOL_CHANGED", "DNS changed": "DNS_CHANGED", "extra origin": "ORIGIN_ADDED",
        "health endpoint changed": "HEALTH_ENDPOINT_CHANGED",
    }
    for label, mutate in mutations.items():
        env = await deploy(3)
        before_mutations = len(env.cf.mutations())
        mutate(env.cf)
        status = await env.monitor.status(DOMAIN, force=True, full=True)
        kinds = {d.kind for d in status.drift}
        assert expected_kind[label] in kinds, (label, kinds)
        assert status.overall == "DEGRADED", label
        assert "Config Drift: CONFIG_DRIFT" in text_of(status)
        assert len(env.cf.mutations()) == before_mutations, "drift is reported, never auto-repaired"
    env = await deploy(3)
    env.store.domain(DOMAIN).db["fingerprint"] = "aaaa"
    env.store.domain(DOMAIN).db["observed_fingerprint"] = "bbbb"
    status = await env.monitor.status(DOMAIN, force=True, full=True)
    assert "DB_HOST_CHANGED" in {d.kind for d in status.drift}
    print("Test 5 (drift: origin removed/added, IP, monitor, pool, LB, DNS, health endpoint, DB host -> CONFIG_DRIFT; Cloudflare is never auto-overwritten) PASSED")


async def test_6_drift_repair_is_an_explicit_reapply() -> None:
    env = await deploy(3)
    pool = next(iter(env.cf.pools.values()))
    pool["origins"] = [o for o in pool["origins"] if o["name"] != "server3"]
    env.cf.monitors[next(iter(env.cf.monitors))]["path"] = "/other"
    drifted = await env.monitor.status(DOMAIN, force=True, full=True)
    assert drifted.drift
    plan = await env.orch.plan(DOMAIN, origin_ips(3), operator="t")
    updates = {(c.resource, c.action) for c in plan.changes}
    assert ("monitor", "UPDATE") in updates and ("pool", "UPDATE") in updates, "the plan shows exactly how to repair the drift"
    repaired = await env.orch.genloadbalance(DOMAIN, origin_ips(3), operator="t", apply=True, confirmed=True)
    assert repaired.status == OpStatus.SUCCESS
    status = await env.monitor.status(DOMAIN, force=True, full=True)
    assert status.overall == "ACTIVE" and not status.drift
    assert (len(env.cf.monitors), len(env.cf.pools), len(env.cf.lbs)) == (1, 1, 1)
    print("Test 6 (drift repair is an explicit confirmed re-run whose plan shows the exact diff; no duplicates; status returns to ACTIVE) PASSED")


async def test_7_alert_lifecycle_dedup_escalation_recovery() -> None:
    env = await deploy(3)
    env.cf.unhealthy_addresses.add(ip(3))
    for _ in range(6):
        await env.monitor.poll_once()
    down = [e for e in env.ports.events if e.category.value == "LB_ORIGIN_DOWN"]
    assert len(down) == 1, "Server3 DOWN -> one alert; repeated polls are suppressed"
    assert down[0].severity.value == "HIGH" and down[0].metadata["domain"] == DOMAIN and down[0].metadata["origin_id"] == "server3"
    assert "UPSTREAM_TIMEOUT" in down[0].message
    assert any(e.category.value == "LB_POOL_DEGRADED" for e in env.ports.events)
    assert sum(1 for e in env.ports.events if e.category.value == "LB_POOL_DEGRADED") == 1
    assert env.metrics.snapshot()["counters"]["lb_notifications_suppressed"] >= 5
    base = env.metrics.snapshot()["counters"]["lb_notifications_sent"]
    now = {"t": 10_000_000.0}
    with mock.patch("core.incident_engine.time.time", lambda: now["t"]):
        env.monitor.incidents._incidents[f"lb_origin_down:{DOMAIN}:server3"].first_detected_at = now["t"] - 2000.0
        await env.monitor.poll_once()
    reminders = [e for e in env.ports.events if e.category.value == "LB_ORIGIN_DOWN" and e.metadata.get("reminder")]
    assert len(reminders) == 1 and reminders[0].metadata["reminder_index"] == 1, "a meaningful escalation update is published once"
    assert env.metrics.snapshot()["counters"]["lb_notifications_sent"] > base
    env.cf.unhealthy_addresses.clear()
    await env.monitor.poll_once()
    recovered = [e for e in env.ports.events if e.category.value == "LB_ORIGIN_RECOVERED"]
    assert len(recovered) == 1 and recovered[0].severity.value == "INFO" and "RECOVERED" in recovered[0].message
    for _ in range(3):
        await env.monitor.poll_once()
    assert len([e for e in env.ports.events if e.category.value == "LB_ORIGIN_RECOVERED"]) == 1, "recovery is announced once"
    env.cf.unhealthy_addresses.add(ip(3))
    await env.monitor.poll_once()
    assert len([e for e in env.ports.events if e.category.value == "LB_ORIGIN_DOWN" and not e.metadata.get("reminder")]) == 2, "a new outage is a new incident"
    print("Test 7 (Server3 DOWN -> one alert, repeated polls suppressed, one escalation update, recovery announced once, new outage is a new incident) PASSED")


async def test_8_pool_unavailable_and_other_alert_types() -> None:
    env = await deploy(3)
    env.cf.unhealthy_addresses.update({ip(1), ip(2), ip(3)})
    await env.monitor.poll_once()
    pool = [e for e in env.ports.events if e.category.value == "LB_POOL_DEGRADED"]
    assert len(pool) == 1 and pool[0].severity.value == "CRITICAL" and "LB_UNAVAILABLE" in pool[0].message
    downs = [e for e in env.ports.events if e.category.value == "LB_ORIGIN_DOWN"]
    assert len(downs) == 3 and all(e.severity.value == "CRITICAL" for e in downs)
    env.cf.unhealthy_addresses.clear()
    await env.monitor.poll_once()
    env.ports.events.clear()
    env.cf.monitors[next(iter(env.cf.monitors))]["path"] = "/changed"
    env.monitor.invalidate(DOMAIN)
    env.ports.mono += env.cfg.drift_check_interval_seconds + 1
    for _ in range(3):
        env.ports.mono += env.cfg.status_cache_ttl_seconds + 1
        await env.monitor.poll_once()
    drift = [e for e in env.ports.events if e.category.value == "LB_CONFIG_DRIFT"]
    assert len(drift) == 1 and drift[0].severity.value == "MEDIUM" and "does not overwrite drift automatically" in drift[0].message
    assert env.metrics.snapshot()["counters"]["lb_config_drift_total"] == 1
    env.monitor.report_db_failure(DOMAIN, "server2", "no greeting")
    env.monitor.report_db_failure(DOMAIN, "server2", "no greeting")
    assert [e.category.value for e in env.ports.events].count("LB_DB_CONNECTIVITY_FAILURE") == 1
    assert env.metrics.snapshot()["counters"]["lb_db_connectivity_failures_total"] == 2
    env.monitor.report_setup_failure(DOMAIN, "server2", ["NGINX_VHOST_MISSING"])
    env.monitor.report_setup_failure(DOMAIN, "server2", ["NGINX_VHOST_MISSING"])
    assert [e.category.value for e in env.ports.events].count("LB_ORIGIN_SETUP_FAILED") == 1
    blob = " ".join(e.message + json.dumps(e.metadata, default=str) for e in env.ports.events)
    assert "Bearer" not in blob and "password" not in blob.lower()
    print("Test 8 (pool unavailable is CRITICAL LB_POOL_DEGRADED; drift, DB connectivity and setup failures raise one deduplicated alert each) PASSED")


async def test_9_polling_is_bounded() -> None:
    env = await deploy(3)
    env.cf.calls.clear()
    processed = await env.monitor.poll_once()
    assert processed == 1
    assert len(env.cf.calls) <= 5, f"one poll of one domain should cost a handful of API calls, got {len(env.cf.calls)}"
    disabled = Env(3, cfg=__import__("_lb_fakes").make_config(3, enabled=False))
    assert await disabled.monitor.poll_once() == 0 and disabled.cf.calls == []
    nocf = Env(3, cloudflare=None)
    assert await nocf.monitor.poll_once() == 0
    locked = await deploy(3)
    locked.ctx.locks.try_acquire(DOMAIN, "op-x", "genloadbalance")
    locked.cf.calls.clear()
    assert await locked.monitor.poll_once() == 0 and locked.cf.calls == [], "the poller never races a running operation"
    print("Test 9 (a poll costs a handful of API calls; disabled/credential-less/locked domains are skipped) PASSED")


async def test_10_metrics_exposed_through_the_existing_exporter() -> None:
    from core.event_bus import EventBus
    from core.metrics_exporter import MetricsExporter

    class FakeDb:
        stats = {"written": 0, "dropped": 0, "queue_size": 0}

    class FakeSupervisor:
        stats = {}

    registry = get_lb_metrics()
    registry.reset()
    env = Env(3, metrics=registry)
    env.ports.down.add(ip(3))
    result = await env.orch.genloadbalance(DOMAIN, origin_ips(3), operator="t", apply=True, confirmed=True)
    assert result.status == OpStatus.SUCCESS
    await env.monitor.status(DOMAIN, force=True, full=True)
    rendered = MetricsExporter(EventBus(), FakeDb(), FakeSupervisor())._render()
    for name in (
        "rtsa_lb_operations_total", "rtsa_lb_operations_success_total", "rtsa_lb_operations_failed_total", "rtsa_lb_rollbacks_total",
        "rtsa_lb_origins_total", "rtsa_lb_origins_healthy", "rtsa_lb_origins_unhealthy", "rtsa_lb_origins_serving",
        "rtsa_lb_health_check_latency_seconds", "rtsa_lb_cloudflare_api_latency_seconds", "rtsa_lb_config_drift_total",
        "rtsa_lb_db_connectivity_failures_total", "rtsa_lb_notifications_sent", "rtsa_lb_notifications_suppressed",
    ):
        assert name in rendered, name
    assert "rtsa_lb_operations_total 1" in rendered and "rtsa_lb_operations_success_total 1" in rendered
    assert "rtsa_lb_origins_total 3" in rendered and "rtsa_lb_origins_serving 2" in rendered and "rtsa_lb_origins_healthy 2" in rendered
    assert 'rtsa_lb_cloudflare_api_latency_seconds{stat="count"}' in rendered
    assert rendered.count("# TYPE rtsa_lb_operations_total") == 1, "one exporter, one registry: no second exporter is created"
    assert 'domain=' not in "\n".join(line for line in rendered.splitlines() if line.startswith("rtsa_lb_")), "no unbounded label cardinality"
    registry.reset()
    print("Test 10 (all required lb_* metrics are exposed through the existing Prometheus exporter with bounded label cardinality) PASSED")


async def test_11_dbgenbalance_report() -> None:
    env = await deploy(3)
    result = await env.orch.dbgenbalance(DOMAIN, operator="alice")
    assert result.status == OpStatus.SUCCESS
    db = result.assessment
    assert db.mode == "PRIMARY_SHARED" and db.connectivity_ok == 3 and db.connectivity_total == 3 and db.safe_for_multi_origin
    assert db.verification_level == "PROTOCOL" and db.budget.status == "NOT_VERIFIED"
    assert env.cf.mutations().count("create_load_balancer") == 1 and not any(m.startswith("delete_") for m in env.cf.mutations())
    assert env.store.last_audit()["kind"] == "dbgenbalance" and env.store.last_audit()["db_changes"] == ["none (RTSA never changes databases)"]
    from core.lb_format import format_db

    title, kind, description, fields = format_db(result)
    names = [f[0] for f in fields]
    assert kind == "success" and "Safe for multi-origin" in names and "Per origin" in names
    assert any("DB connectivity is not DB load balancing" in v for _, v, _ in fields)

    env.ports.reports["server2"] = ReportLoad("OK", make_report("server2", db_mode="LOCAL_PER_ORIGIN"))
    blocked = await env.orch.dbgenbalance(DOMAIN, operator="alice")
    assert blocked.assessment.mode == "LOCAL_PER_ORIGIN" and not blocked.assessment.safe_for_multi_origin
    assert any(f.code == "DB_LOCAL_PER_ORIGIN" for f in blocked.assessment.findings)
    declared = await env.orch.dbgenbalance(DOMAIN, operator="alice", declared_mode="MULTI_PRIMARY")
    assert declared.assessment.mode == "MULTI_PRIMARY" and any(f.code == "DB_MODE_WARNING" for f in declared.assessment.findings)
    assert (await env.orch.dbgenbalance(DOMAIN, operator="alice", declared_mode="BOGUS")).assessment.mode == "UNKNOWN"
    env.ports.reports["server2"] = ReportLoad("OK", make_report("server2", db_level="NONE", blockers=["DB_UNREACHABLE"]))
    env.ports.events.clear()
    unreachable = await env.orch.dbgenbalance(DOMAIN, operator="alice")
    assert unreachable.assessment.connectivity_ok == 2 and "LB_DB_CONNECTIVITY_FAILURE" in env.categories()
    env.ports.reports.pop("server3")
    missing = await env.orch.dbgenbalance(DOMAIN, operator="alice")
    assert any(f.code == "ORIGIN_REPORT_MISSING" for f in missing.assessment.findings)
    print("Test 11 (/dbgenbalance: mode, connectivity n/m, verification level, budget, versions; LOCAL_PER_ORIGIN blocks; MULTI_PRIMARY only declared; DB never changed) PASSED")


async def test_12_disabled_feature_and_mention_safety() -> None:
    disabled = Env(3, cfg=__import__("_lb_fakes").make_config(3, enabled=False))
    status = await disabled.monitor.status(DOMAIN, force=True, full=True)
    assert status.overall == "NOT_CONFIGURED" and disabled.cf.calls == [], "a disabled feature never touches Cloudflare, not even for /cekloadbalance"
    assert "load_balancing.enabled is false" in " ".join(status.reasons)
    env = await deploy(3)
    env.cf.unhealthy_addresses.add(ip(3))
    status = await env.monitor.status(DOMAIN, force=True, full=True)
    status.origins[2].reason = "@everyone <@&123456789> <@42> <#99> look"
    status.reasons.append("@here ping")
    rendered = format_status(status, NAMES)[2]
    for raw in ("@everyone", "<@&123456789>", "<@42>", "<#99>", "@here"):
        assert raw not in rendered, f"{raw} must not survive in Discord output"
    assert "@\u200beveryone" in rendered and "<\u200b@\u200b&123456789>" in rendered
    print("Test 12 (a disabled feature never calls Cloudflare; Discord mentions in report-derived text are neutralised) PASSED")


async def main() -> None:
    for test in (
        test_1_cek_output_distinguishes_configured_healthy_serving, test_2_traffic_distribution_only_when_measurable,
        test_3_overall_status_layers, test_4_status_is_cached_and_bounded, test_5_drift_detection_without_auto_repair,
        test_6_drift_repair_is_an_explicit_reapply, test_7_alert_lifecycle_dedup_escalation_recovery,
        test_8_pool_unavailable_and_other_alert_types, test_9_polling_is_bounded, test_10_metrics_exposed_through_the_existing_exporter,
        test_11_dbgenbalance_report, test_12_disabled_feature_and_mention_safety,
    ):
        await test()
    print("\nALL LOAD BALANCER STATUS/ALERT TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
