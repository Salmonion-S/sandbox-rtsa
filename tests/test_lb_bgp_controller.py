import asyncio
import os
import sys
import tempfile
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _lb_bgp_fakes import (
    DOMAIN, PREFIX, VIP, FakeClock, FakeObserver, FakeRouter, Node, make_cfg, run_ticks,
)
from core.lb_bgp_controller import DESIRED_DISABLED, DESIRED_DRAINED, DESIRED_ENABLED
from core.lb_bgp_model import HealthLayer, ServiceState
from core.lb_bgp_state import BgpStateStore


def build(nodes=3, tmp=None, hold=9.0, bfd=None, **cfg_over):
    tmp = tmp or tempfile.mkdtemp()
    clock = FakeClock()
    router = FakeRouter(clock, hold_seconds=hold, bfd_seconds=bfd)
    cfg = make_cfg(tmp, nodes=nodes, **cfg_over)
    members = [Node(cfg, n, clock, router, tmp) for n in cfg.services[0].nodes]
    return clock, router, cfg, members, tmp


async def start_all(members, enable=True):
    for m in members:
        await m.controller.start()
        if enable:
            await m.controller.request_enable("test")


async def stabilise(members, seconds=40.0):
    await run_ticks(members, seconds)


async def test_1_boot_requires_proven_stability_before_advertising():
    clock, router, cfg, members, _ = build(nodes=1)
    node = members[0]
    await start_all(members)
    assert node.controller.fsm.state == ServiceState.HEALTH_CHECKING and node.speaker.announce_calls == 0
    await node.controller.tick()
    assert node.speaker.announce_calls == 0, "a host that just came up is never advertised on the first healthy probe"
    clock.advance(2.0)
    await node.controller.tick()
    clock.advance(2.0)
    await node.controller.tick()
    assert node.speaker.announce_calls == 0, "3 healthy probes but the minimum healthy duration (6s) has not passed"
    assert node.controller.readiness.value == "APPLICATION_READY"
    clock.advance(4.0)
    await node.controller.tick()
    assert node.controller.fsm.state == ServiceState.ACTIVE and node.speaker.announce_calls == 1
    assert node.controller.readiness.value == "HEALTH_STABLE"
    path = [t["target"] for t in node.controller.snapshot().history]
    assert path[:6] == ["VALIDATING", "PLANNED", "PREPARED", "HEALTH_CHECKING", "READY", "ADVERTISING"], path
    assert node.categories() == ["LB_NODE_READY", "LB_ROUTE_ADVERTISED"]
    assert router.paths() == ["node1"]
    print("Test 1 (boot: discovery -> health -> READY -> ADVERTISING -> ACTIVE only after stability; never advertised on boot) PASSED")


async def test_2_single_failed_probe_never_withdraws():
    clock, router, cfg, members, _ = build(nodes=1)
    node = members[0]
    await start_all(members)
    await stabilise(members)
    assert node.controller.fsm.state == ServiceState.ACTIVE
    node.ports.set(HealthLayer.APPLICATION, False)
    await run_ticks(members, 4.0)
    node.ports.set(HealthLayer.APPLICATION, True)
    await run_ticks(members, 20.0)
    assert node.speaker.withdraw_calls == 0 and node.controller.fsm.state == ServiceState.ACTIVE
    assert node.categories() == ["LB_NODE_READY", "LB_ROUTE_ADVERTISED"], "two failed probes below the threshold raise nothing"
    assert node.metrics.snapshot()["counters"]["lb_bgp_probe_failures_total"] >= 2
    print("Test 2 (a failing probe below the consecutive-failure threshold never withdraws and never alerts) PASSED")


async def test_3_application_failure_withdraws_with_measured_convergence():
    clock, router, cfg, members, _ = build(nodes=3)
    await start_all(members)
    await stabilise(members)
    assert all(m.controller.fsm.state == ServiceState.ACTIVE for m in members)
    assert router.paths() == ["node1", "node2", "node3"]
    victim = members[2]
    victim.speaker.visibility_delay = 0.5
    victim.ports.set(HealthLayer.APPLICATION, False)
    started = clock.t
    await run_ticks(members, 12.0)
    assert victim.controller.fsm.state == ServiceState.WITHDRAWN and victim.speaker.withdraw_calls == 1
    assert router.paths() == ["node1", "node2"]
    assert victim.controller.withdraw_reason == "UNHEALTHY"
    last = victim.controller.last_convergence
    assert last.failure_detected_at is not None and last.health_failed_at is not None
    assert abs(last.health_failed_at - last.failure_detected_at - 4.0) < 1e-6, "3 probes 2s apart: failure confirmed 4s after the first"
    assert last.route_withdraw_started_at >= last.health_failed_at
    assert abs(last.bgp_withdraw_observed_at - last.route_withdraw_started_at - 0.5) < 1e-6, \
        "the withdraw is only declared converged when the speaker no longer advertises it (measured, 0.5s)"
    assert last.ecmp_path_removed_at is None and last.traffic_recovery_observed_at is None, "nothing is invented"
    latencies = last.latencies()
    assert latencies["ecmp_convergence_latency"] is None and latencies["service_recovery_latency"] is None
    cats = victim.categories()
    assert cats.count("LB_NODE_UNHEALTHY") == 1 and cats.count("LB_ROUTE_WITHDRAWN") == 1
    event = next(e for e in victim.ports.events if e.category.value == "LB_NODE_UNHEALTHY")
    text = event.message
    assert "Domain : example.com" in text and "VIP    : 203.0.113.10" in text and "Node   : node3" in text
    assert "State  : NOT_SERVING" in text and "application" in text and "route withdrawn" in text
    assert all(m.controller.fsm.state == ServiceState.ACTIVE for m in members[:2]), "healthy nodes keep serving"
    print("Test 3 (3 nodes, application dies on one: withdrawn after 3 probes, measured timestamps, others keep serving) PASSED")


async def test_4_each_layer_gates_the_route():
    for layer in (HealthLayer.NGINX, HealthLayer.VIP_LISTENER, HealthLayer.NETWORK, HealthLayer.APPLICATION):
        clock, router, cfg, members, _ = build(nodes=2)
        await start_all(members)
        await stabilise(members)
        members[1].ports.set(layer, False)
        await run_ticks(members, 10.0)
        assert members[1].controller.fsm.state == ServiceState.WITHDRAWN, layer
        assert router.paths() == ["node1"], layer
        assert members[1].controller.snapshot().healthy is False
    print("Test 4 (nginx / VIP listener / network / application failure each withdraw the route while the host stays up) PASSED")


async def test_5_database_and_backend_policy_is_configurable():
    for policy, expect in (("required", "WITHDRAWN"), ("optional", "DEGRADED"), ("ignored", "ACTIVE")):
        base = make_cfg(tempfile.mkdtemp(), nodes=1)
        cfg = replace(base, health=replace(base.health, database=policy))
        clock = FakeClock()
        router = FakeRouter(clock)
        tmp = tempfile.mkdtemp()
        node = Node(cfg, cfg.services[0].nodes[0], clock, router, tmp)
        await node.controller.start()
        await node.controller.request_enable("test")
        await run_ticks([node], 40.0)
        assert node.controller.fsm.state == ServiceState.ACTIVE
        node.ports.set(HealthLayer.DATABASE, False)
        await run_ticks([node], 14.0)
        assert node.controller.fsm.state.value == expect, (policy, node.controller.fsm.state)
        if policy == "optional":
            assert node.speaker.withdraw_calls == 0 and node.controller.snapshot().healthy is True
    print("Test 5 (a database outage withdraws only when the policy says the app cannot serve; optional = DEGRADED, ignored = ignored) PASSED")


async def test_6_recovery_is_controlled():
    clock, router, cfg, members, _ = build(nodes=2)
    await start_all(members)
    await stabilise(members)
    node = members[1]
    node.ports.set(HealthLayer.NGINX, False)
    await run_ticks(members, 10.0)
    assert node.controller.fsm.state == ServiceState.WITHDRAWN and router.paths() == ["node1"]
    node.ports.set(HealthLayer.NGINX, True)
    withdrawn_at = node.controller.hyst.last_withdraw_at
    await node.controller.tick()
    assert node.speaker.announce_calls == 1, "no immediate re-advertisement"
    clock.advance(2.0)
    await node.controller.tick()
    clock.advance(2.0)
    await node.controller.tick()
    assert node.speaker.announce_calls == 1 and node.controller.fsm.state != ServiceState.ACTIVE
    await run_ticks(members, 14.0)
    assert node.controller.fsm.state == ServiceState.ACTIVE and node.speaker.announce_calls == 2
    assert node.controller.hyst.last_advertise_at - withdrawn_at >= cfg.health.cooldown_seconds
    assert router.paths() == ["node1", "node2"]
    cats = node.categories()
    assert cats.count("LB_NODE_RECOVERED") == 1 and cats.count("LB_ROUTE_ADVERTISED") == 2
    assert "ECMP" in next(e for e in node.ports.events if e.category.value == "LB_NODE_RECOVERED").message
    print("Test 6 (recovery: confirmation + minimum healthy duration + cooldown before the route comes back, one recovery alert) PASSED")


async def test_7_route_flap_is_suppressed():
    clock, router, cfg, members, _ = build(nodes=2, health=replace(make_cfg(tempfile.mkdtemp()).health, max_transitions_per_window=4, cooldown_seconds=4.0, min_healthy_seconds=2.0, up_threshold=2))
    await start_all(members)
    await stabilise(members)
    node = members[1]
    for _ in range(8):
        node.ports.set(HealthLayer.APPLICATION, False)
        await run_ticks(members, 8.0)
        node.ports.set(HealthLayer.APPLICATION, True)
        await run_ticks(members, 14.0)
    announces = node.speaker.announce_calls
    assert node.controller.hyst.flap_events >= 1, "a flapping node is held down"
    assert announces <= 6, f"advertisements are bounded by the flap window, got {announces}"
    assert node.metrics.snapshot()["counters"]["lb_bgp_flap_suppressions_total"] >= 1
    assert node.controller.fsm.state != ServiceState.ACTIVE or node.controller.hyst.flap_until <= clock.t
    print("Test 7 (route flap: bounded transitions per window, then a hold-down; no endless advertise/withdraw loop) PASSED")


async def test_8_bgp_session_down_removes_serving_and_alerts_once():
    clock, router, cfg, members, _ = build(nodes=2)
    await start_all(members)
    await stabilise(members)
    node = members[0]
    node.speaker.session_up = False
    router.routes["node1"]["session"] = False
    await run_ticks(members, 30.0)
    assert node.controller.fsm.state == ServiceState.ADVERTISING and not node.controller.snapshot().serving
    assert node.speaker.withdraw_calls == 0, "a dead session removes the route by itself; RTSA does not fight it"
    assert node.categories().count("LB_BGP_DOWN") == 1, "one alert for a standing condition, not one per poll"
    assert router.paths() == ["node2"]
    node.speaker.session_up = True
    router.routes["node1"]["session"] = True
    await run_ticks(members, 10.0)
    assert node.controller.fsm.state == ServiceState.ACTIVE
    assert node.categories().count("LB_BGP_ESTABLISHED") == 1
    print("Test 8 (BGP session down: node no longer SERVING, route disappears by itself, exactly one BGP_DOWN/ESTABLISHED pair) PASSED")


async def test_9_withdraw_failure_is_loud_and_retried():
    clock, router, cfg, members, _ = build(nodes=2)
    await start_all(members)
    await stabilise(members)
    node = members[1]
    node.speaker.fail_withdraw = True
    node.ports.set(HealthLayer.APPLICATION, False)
    await run_ticks(members, 14.0)
    assert node.controller.fsm.state != ServiceState.WITHDRAWN and node.speaker.withdraw_calls >= 2, "retried every cycle"
    event = next(e for e in node.ports.events if e.category.value == "LB_NODE_UNHEALTHY")
    assert event.severity.value == "CRITICAL" and "withdraw FAILED" in event.message and "route NOT withdrawn" in event.message
    node.speaker.fail_withdraw = False
    await run_ticks(members, 6.0)
    assert node.controller.fsm.state == ServiceState.WITHDRAWN and router.paths() == ["node1"]
    print("Test 9 (a failed BGP withdraw is a CRITICAL alert, retried every cycle, and success is never claimed early) PASSED")


async def test_10_announce_failure_never_serves():
    clock, router, cfg, members, _ = build(nodes=1)
    node = members[0]
    node.speaker.fail_announce = True
    await start_all(members)
    await run_ticks(members, 20.0)
    assert node.controller.fsm.state == ServiceState.FAILED and not node.controller.snapshot().serving
    assert "LB_ORIGIN_SETUP_FAILED" in node.categories() and router.paths() == []
    node.speaker.fail_announce = False
    await run_ticks(members, 120.0)
    assert node.controller.fsm.state == ServiceState.ACTIVE, node.controller.fsm.state
    print("Test 10 (announce failure -> FAILED, not serving, LB_ORIGIN_SETUP_FAILED; retries and recovers by itself) PASSED")


async def test_11_drain_keeps_services_running_and_waits_for_connections():
    clock, router, cfg, members, _ = build(nodes=3)
    await start_all(members)
    await stabilise(members)
    node = members[2]
    node.ports.connections = 7
    ok, text = await node.controller.request_drain("operator")
    assert ok and "nginx/PM2 stay running" in text
    await run_ticks(members, 4.0)
    assert node.controller.fsm.state == ServiceState.DRAINING and router.paths() == ["node1", "node2"]
    assert node.speaker.withdraw_calls == 1
    await run_ticks(members, 30.0)
    assert node.controller.fsm.state == ServiceState.DRAINING, "existing connections are still open"
    node.ports.connections = 0
    await run_ticks(members, 14.0)
    assert node.controller.fsm.state == ServiceState.WITHDRAWN and node.controller.withdraw_reason == "DRAINED"
    assert node.controller.snapshot().healthy is not None
    assert node.ports.layer_state[HealthLayer.APPLICATION] is True and node.ports.layer_state[HealthLayer.NGINX] is True
    assert not any(a["kind"] in ("nginx_stop", "pm2_stop") for a in node.ports.audits)
    assert "LB_NODE_UNHEALTHY" not in node.categories(), "a drain is maintenance, not an incident"
    await node.controller.request_resume("operator")
    await run_ticks(members, 40.0)
    assert node.controller.fsm.state == ServiceState.ACTIVE and router.paths() == ["node1", "node2", "node3"]
    print("Test 11 (drain: route withdrawn first, wait for connections, NOT_SERVING; nginx/PM2 untouched; resume re-qualifies) PASSED")


async def test_12_drain_times_out_instead_of_waiting_forever():
    clock, router, cfg, members, _ = build(nodes=2)
    await start_all(members)
    await stabilise(members)
    node = members[1]
    node.ports.connections = 50
    await node.controller.request_drain("operator")
    await run_ticks(members, 80.0)
    assert node.controller.fsm.state == ServiceState.WITHDRAWN and node.controller.withdraw_reason == "DRAINED"
    print("Test 12 (a drain with stuck connections ends at max_wait_seconds, bounded) PASSED")


async def test_13_shadow_mode_never_touches_bgp():
    clock, router, cfg, members, _ = build(nodes=2, apply_enabled=False)
    await start_all(members)
    await stabilise(members)
    for m in members:
        assert m.speaker.announce_calls == 0 and m.speaker.withdraw_calls == 0
        assert m.controller.shadow and m.controller.fsm.state == ServiceState.READY
        assert m.controller.shadow_decision == "WOULD_ADVERTISE" and not m.controller.snapshot().serving
    node = members[0]
    node.speaker.originate = True
    node.ports.set(HealthLayer.APPLICATION, False)
    await run_ticks(members, 12.0)
    assert node.speaker.withdraw_calls == 0, "shadow mode does not withdraw"
    event = next(e for e in node.ports.events if e.category.value == "LB_NODE_UNHEALTHY")
    assert event.severity.value == "CRITICAL" and "shadow mode" in event.message and "NOT withdrawn" in event.message
    only_audit = [a for a in node.ports.audits if a["kind"].startswith("bgp_announce") or a["kind"].startswith("bgp_withdraw")]
    assert only_audit == []
    node2 = members[1]
    node2.ports.allow_mutations = False
    assert node2.controller.shadow, "detection-only mode forces shadow behaviour"
    print("Test 13 (apply_enabled=false / detection-only: decisions are computed and shown, BGP is never changed, mis-advertising alerts) PASSED")


async def test_14_restart_keeps_operator_intent_and_cooldown():
    tmp = tempfile.mkdtemp()
    clock, router, cfg, members, _ = build(nodes=2, tmp=tmp)
    await start_all(members)
    await stabilise(members)
    node = members[1]
    await node.controller.request_drain("operator")
    await run_ticks(members, 40.0)
    assert node.controller.fsm.state == ServiceState.WITHDRAWN
    again = Node(cfg, cfg.services[0].nodes[1], clock, router, tmp, store=BgpStateStore(node.store._path, clock=clock.now))
    again.ports.layer_state = dict(node.ports.layer_state)
    await again.controller.start()
    await run_ticks([again], 40.0)
    assert again.controller.desired == DESIRED_DRAINED and again.speaker.announce_calls == 0, "a restart never undoes a drain"
    assert again.controller.hyst.last_withdraw_at is not None
    await again.controller.request_resume("operator")
    assert again.controller.desired == DESIRED_ENABLED
    print("Test 14 (restart: drain intent and withdraw cooldown are restored from the persisted state, no surprise advertisement) PASSED")


async def test_15_stale_advertisement_of_an_unhealthy_node_is_withdrawn():
    tmp = tempfile.mkdtemp()
    clock, router, cfg, members, _ = build(nodes=1, tmp=tmp)
    node = members[0]
    node.speaker.originate = True
    router.set_advertised("node1", True)
    node.ports.set(HealthLayer.APPLICATION, False)
    await start_all(members)
    await run_ticks(members, 12.0)
    assert node.speaker.withdraw_calls >= 1 and not node.speaker.originate, "RTSA restarted into an advertised-but-unhealthy node"
    print("Test 15 (RTSA restarts while the route is still advertised and the node is unhealthy -> withdrawn, not trusted blindly) PASSED")


async def test_16_external_removal_is_detected_and_repaired():
    clock, router, cfg, members, _ = build(nodes=1)
    node = members[0]
    await start_all(members)
    await stabilise(members)
    assert node.controller.fsm.state == ServiceState.ACTIVE
    node.speaker.originate = False
    router.set_advertised("node1", False)
    await run_ticks(members, 8.0)
    assert node.speaker.announce_calls == 2 and node.controller.fsm.state == ServiceState.ACTIVE
    assert "LB_CONFIG_DRIFT" in node.categories()
    print("Test 16 (the route disappears outside RTSA: drift alert once and a re-announce) PASSED")


async def test_17_no_alert_per_poll():
    clock, router, cfg, members, _ = build(nodes=2)
    await start_all(members)
    await stabilise(members)
    node = members[1]
    node.ports.set(HealthLayer.APPLICATION, False)
    await run_ticks(members, 400.0)
    assert node.categories().count("LB_NODE_UNHEALTHY") == 1 and node.categories().count("LB_ROUTE_WITHDRAWN") == 1
    assert node.speaker.withdraw_calls == 1
    print("Test 17 (200 polls of a standing outage -> one UNHEALTHY and one WITHDRAWN notification, one withdraw) PASSED")


async def test_18_probe_errors_are_unknown_not_failures():
    clock, router, cfg, members, _ = build(nodes=2)
    await start_all(members)
    await stabilise(members)
    node = members[1]
    node.ports.probe_error = True
    await run_ticks(members, 40.0)
    assert node.speaker.withdraw_calls == 0 and node.controller.fsm.state == ServiceState.ACTIVE
    assert node.controller.verdict.state == "UNKNOWN"
    print("Test 18 (a broken probe is UNKNOWN, not a failure: the route is neither withdrawn nor wrongly proven healthy) PASSED")


async def test_19_n_node_active_active_join_leave_and_hard_failure():
    for count in (2, 3, 4, 8):
        clock, router, cfg, members, _ = build(nodes=count)
        await start_all(members)
        await stabilise(members, 60.0)
        assert [m.controller.fsm.state for m in members] == [ServiceState.ACTIVE] * count
        assert router.paths() == [f"node{i + 1}" for i in range(count)], count
        counts = router.distribute(4000)
        assert all(v > 0 for v in counts.values()) and len(counts) == count
        await members[-1].controller.request_drain("operator")
        await run_ticks(members, 30.0)
        assert len(router.paths()) == count - 1, "node leave"
        await members[-1].controller.request_resume("operator")
        await run_ticks(members, 40.0)
        assert len(router.paths()) == count, "node join / return"
    clock, router, cfg, members, _ = build(nodes=4, hold=9.0)
    await start_all(members)
    await stabilise(members)
    router.kill("node4")
    died = clock.t
    detected = None
    for _ in range(40):
        clock.advance(0.5)
        if "node4" not in router.paths() and detected is None:
            detected = clock.t - died
    assert detected is not None and 8.9 <= detected <= 9.6, f"a silent death takes the hold timer ({detected}s) -- never 'instant'"
    assert len(router.paths()) == 3
    clock2 = FakeClock()
    router2 = FakeRouter(clock2, hold_seconds=9.0, bfd_seconds=0.9)
    cfg2 = make_cfg(tempfile.mkdtemp(), nodes=2)
    router2.register("node1")
    router2.set_advertised("node1", True)
    router2.kill("node1")
    clock2.advance(1.0)
    assert router2.paths() == [], "with BFD the same silent death converges in ~1s"
    print("Test 19 (2/3/4/8 nodes active-active, node leave/join, silent death costs the hold timer, BFD changes only that) PASSED")


async def test_20_ecmp_observer_reports_installed_paths():
    clock, router, cfg, members, _ = build(nodes=3)
    await start_all(members)
    await stabilise(members)
    obs = await FakeObserver(router).observe(PREFIX)
    assert obs.active == 3 and obs.bgp_paths == 3
    members[0].ports.set(HealthLayer.APPLICATION, False)
    await run_ticks(members, 12.0)
    assert (await FakeObserver(router).observe(PREFIX)).active == 2
    flows = router.distribute(9999)
    assert sum(flows.values()) == 9999 and set(flows) == {"node2", "node3"}
    print("Test 20 (ECMP observation: next-hops installed, never an invented 33/33/33 share; only active paths receive flows) PASSED")


async def test_21_node_report_is_written_and_signed():
    from core.lb_bgp_state import load_node_report

    clock, router, cfg, members, tmp = build(nodes=1)
    node = members[0]
    await start_all(members)
    await stabilise(members)
    loaded = load_node_report(cfg.node_reports_dir, DOMAIN, "node1", key=node.ports.key, max_age_seconds=300.0, now=clock.t)
    assert loaded.usable and loaded.report.state == "ACTIVE" and loaded.report.mode == "apply" and loaded.report.healthy is True
    assert loaded.report.vip == VIP and loaded.report.originated is True
    assert load_node_report(cfg.node_reports_dir, DOMAIN, "node1", key=b"x" * 32, max_age_seconds=300.0, now=clock.t).status == "NODE_REPORT_INVALID"
    assert load_node_report(cfg.node_reports_dir, DOMAIN, "node1", key=node.ports.key, max_age_seconds=300.0, now=clock.t + 4000).status == "NODE_REPORT_STALE"
    assert load_node_report(cfg.node_reports_dir, DOMAIN, "node9", key=node.ports.key, max_age_seconds=300.0, now=clock.t).status == "NODE_REPORT_MISSING"
    print("Test 21 (signed node report: state/health/route proof verifies; wrong key, stale and missing reports are rejected) PASSED")


async def test_22_adoption_and_default_off():
    tmp = tempfile.mkdtemp()
    clock, router, cfg, members, _ = build(nodes=1, tmp=tmp)
    node = members[0]
    await node.controller.start()
    await run_ticks(members, 60.0)
    assert node.controller.desired == DESIRED_DISABLED and node.speaker.announce_calls == 0 and not node.controller.snapshot().serving
    assert node.controller.snapshot().healthy is True and node.controller.readiness.value == "HEALTH_STABLE", "health is visible even when not enabled"
    assert router.paths() == [], "a node that was never enabled never advertises, however healthy"
    clock2, router2, cfg2, members2, _ = build(nodes=1)
    legacy = members2[0]
    legacy.speaker.originate = True
    router2.set_advertised("node1", True)
    await legacy.controller.start()
    await run_ticks(members2, 40.0)
    assert legacy.controller.desired == DESIRED_ENABLED and legacy.controller.fsm.state == ServiceState.ACTIVE
    assert any(a["kind"] == "bgp_adopt" for a in legacy.ports.audits)
    assert legacy.speaker.withdraw_calls == 0, "an existing advertisement of a healthy node is adopted, not torn down"
    print("Test 22 (never-enabled nodes stay off however healthy; an existing advertisement is adopted under health gating) PASSED")


async def test_23_speaker_restart_loses_the_route_and_is_re_announced():
    clock, router, cfg, members, _ = build(nodes=2)
    await start_all(members)
    await stabilise(members)
    node = members[1]
    assert node.controller.fsm.state == ServiceState.ACTIVE and node.speaker.announce_calls == 1
    node.speaker.unreachable = True
    node.speaker.originate = False
    router.set_advertised("node2", False)
    await run_ticks(members, 12.0)
    assert node.speaker.announce_calls == 1
    assert node.controller.fsm.state == ServiceState.ADVERTISING and not node.controller.fsm.serving
    assert node.speaker.withdraw_calls == 0
    node.speaker.unreachable = False
    await run_ticks(members, 12.0)
    assert node.speaker.announce_calls == 2, node.speaker.announce_calls
    assert node.controller.fsm.state == ServiceState.ACTIVE and node.controller.fsm.serving
    assert node.categories().count("LB_CONFIG_DRIFT") == 1
    assert router.paths() == ["node1", "node2"]
    print("Test 23 (the BGP daemon restarts without the route: never stuck, re-announced once it answers, drift alerted once) PASSED")


async def main():
    await test_1_boot_requires_proven_stability_before_advertising()
    await test_2_single_failed_probe_never_withdraws()
    await test_3_application_failure_withdraws_with_measured_convergence()
    await test_4_each_layer_gates_the_route()
    await test_5_database_and_backend_policy_is_configurable()
    await test_6_recovery_is_controlled()
    await test_7_route_flap_is_suppressed()
    await test_8_bgp_session_down_removes_serving_and_alerts_once()
    await test_9_withdraw_failure_is_loud_and_retried()
    await test_10_announce_failure_never_serves()
    await test_11_drain_keeps_services_running_and_waits_for_connections()
    await test_12_drain_times_out_instead_of_waiting_forever()
    await test_13_shadow_mode_never_touches_bgp()
    await test_14_restart_keeps_operator_intent_and_cooldown()
    await test_15_stale_advertisement_of_an_unhealthy_node_is_withdrawn()
    await test_16_external_removal_is_detected_and_repaired()
    await test_17_no_alert_per_poll()
    await test_18_probe_errors_are_unknown_not_failures()
    await test_19_n_node_active_active_join_leave_and_hard_failure()
    await test_20_ecmp_observer_reports_installed_paths()
    await test_21_node_report_is_written_and_signed()
    await test_22_adoption_and_default_off()
    await test_23_speaker_restart_loses_the_route_and_is_re_announced()
    print("\nALL BGP/ECMP NODE CONTROLLER TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
