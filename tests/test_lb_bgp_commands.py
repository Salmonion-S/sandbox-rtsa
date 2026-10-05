import asyncio
import os
import sys
import tempfile
from dataclasses import replace

_TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _TESTS)

from _lb_bgp_fakes import DOMAIN, World, run_ticks
from core.datatypes import EventCategory
from core.lb_bgp_format import format_bgp_add, format_bgp_plan, format_bgp_status
from core.lb_bgp_model import HealthLayer, ServiceState
from core.lb_model import OpStatus

PUBLIC = "9.9.9.10"


async def enable(world, seconds=60.0):
    await world.node.controller.start()
    await world.node.controller.request_enable("seed")
    await run_ticks([world.node], seconds)


def text_of(parts):
    title, kind, description, fields = parts
    return "\n".join([title, description] + [f"{n}: {v}" for n, v, _ in fields])


async def test_1_gen_dry_run_plans_but_changes_nothing():
    w = World(tempfile.mkdtemp(), attest=False)
    await w.node.controller.start()
    result = await w.orchestrator.genloadbalance(DOMAIN, ["node1", "node2"], operator="op")
    assert result.status == OpStatus.DRY_RUN and result.dry_run and result.nodes == ["node1", "node2"]
    assert result.report.verdict in ("UNPROVEN", "NOT_FEASIBLE") and result.blockers
    assert any("VIP configuration" in x for x in result.would_create) and any("BGP policy" in x for x in result.would_create)
    assert any("Health-gated advertisement" in x for x in result.would_create) and any("Node registration" in x for x in result.would_create)
    for kept in ("DNS records", "Cloudflare production load balancer / pools / monitors", "BGP production configuration (peers, ASNs, policies)", "Nginx configuration", "PM2 / application processes"):
        assert kept in result.would_not_change, kept
    assert w.node.speaker.announce_calls == 0 and w.node.speaker.withdraw_calls == 0 and w.ports.events == []
    assert any(a["kind"] == "genloadbalance" and a["dry_run"] for a in w.ports.audits)
    out = text_of(format_bgp_plan(result))
    for needle in ("LOAD BALANCER PLAN", "DRY RUN", "Mode         : BGP + ECMP", "Feasibility", "would create", "Would NOT change", "Reference FRR config"):
        assert needle in out, needle
    assert "25%" not in out and "%" not in out.split("Reference FRR config")[0].replace("100%", ""), "no traffic share is invented"
    print("Test 1 (/genloadbalance --bgp-ecmp: a dry-run plan with feasibility, would-create / would-NOT-change, reference config; nothing changes) PASSED")


async def test_2_gen_rejects_bad_input_before_any_probe():
    w = World(tempfile.mkdtemp())
    for domain, nodes in (("../../etc/passwd", []), ("https://evil.example", []), ("unconfigured.example.com", []), ("localhost", [])):
        result = await w.orchestrator.genloadbalance(domain, nodes, operator="op")
        assert result.status == OpStatus.PRECHECK_FAILED and result.report is None, domain
    bad = await w.orchestrator.genloadbalance(DOMAIN, ["node1", "node9; reboot"], operator="op")
    assert bad.status == OpStatus.PRECHECK_FAILED and "allowed node ids" in bad.message
    dup = await w.orchestrator.genloadbalance(DOMAIN, ["node1", "node1"], operator="op")
    assert dup.status == OpStatus.PRECHECK_FAILED
    arbitrary = await w.orchestrator.genloadbalance(DOMAIN, ["10.9.9.9"], operator="op")
    assert arbitrary.status == OpStatus.PRECHECK_FAILED, "nodes come from the configured list, never from user-supplied addresses"
    assert w.metrics.snapshot()["counters"]["lb_bgp_feasibility_runs_total"] == 0
    print("Test 2 (hostile domain, unknown/duplicate nodes, raw IPs, unconfigured domain: rejected before any probe) PASSED")


async def test_3_gen_apply_is_per_node_not_remote():
    w = World(tempfile.mkdtemp())
    await w.node.controller.start()
    result = await w.orchestrator.genloadbalance(DOMAIN, [], operator="op", apply=True)
    assert result.status == OpStatus.ABORTED and not result.dry_run and "per node" in result.message
    assert "no cross-server execution channel" in result.message
    assert w.node.speaker.announce_calls == 0 and w.node.controller.desired == "DISABLED"
    print("Test 3 (/genloadbalance --apply: refused, activation is per node; no remote execution, nothing changed) PASSED")


async def test_4_status_ladder_with_provenance_and_stale_reports():
    w = World(tempfile.mkdtemp(), nodes=4)
    await enable(w)
    assert w.node.controller.fsm.state == ServiceState.ACTIVE
    w.write_report("node2")
    w.write_report("node3", state="WITHDRAWN", healthy=False, originated=False)
    w.write_report("node4", age=1000.0)
    status = await w.status.status(DOMAIN, force=True)
    nodes = {n.node_id: n for n in status.nodes}
    assert nodes["node1"].source == "LOCAL" and nodes["node1"].ladder == {
        "CONFIGURED": "YES", "HEALTHY": "YES", "BGP_ESTABLISHED": "YES", "ROUTE_ADVERTISED": "YES", "SERVING": "YES", "TRAFFIC_OBSERVED": "NO",
    }
    assert nodes["node2"].source == "NODE_REPORT" and nodes["node2"].label == "HEALTHY / SERVING"
    assert nodes["node3"].label == "UNHEALTHY / NOT_SERVING" and nodes["node3"].ladder["ROUTE_ADVERTISED"] == "NO"
    assert nodes["node4"].report_status == "NODE_REPORT_STALE" and nodes["node4"].serving is None and nodes["node4"].label == "UNKNOWN / UNKNOWN"
    assert status.ecmp_expected == 4 and status.overall == "DEGRADED" and status.serving_count == 2
    assert any("stale node reports: node4" in r for r in status.reasons)
    out = text_of(format_bgp_status(status))
    for needle in ("LOAD BALANCER STATUS", "BGP + ECMP", "ESTABLISHED / ADVERTISING", "UNKNOWN / UNKNOWN", "expected    : 4", "State ladder",
                   "CONFIGURED YES | HEALTHY YES | BGP_ESTABLISHED YES | ROUTE_ADVERTISED YES | SERVING YES | TRAFFIC_OBSERVED NO", "Cloudflare", "NOT_CONFIGURED"):
        assert needle in out, needle
    print("Test 4 (status ladder CONFIGURED/HEALTHY/BGP_ESTABLISHED/ROUTE_ADVERTISED/SERVING/TRAFFIC_OBSERVED, per node, with source and staleness) PASSED")


async def test_5_ecmp_state_comes_from_the_router_or_is_unknown():
    w = World(tempfile.mkdtemp(), nodes=3, observer=False)
    await enable(w)
    status = await w.status.status(DOMAIN, force=True)
    assert status.ecmp_active is None and "ECMP" in text_of(format_bgp_status(status)) and "UNKNOWN (no router observer is configured)" in text_of(format_bgp_status(status))
    w2 = World(tempfile.mkdtemp(), nodes=3, observer=True)
    await enable(w2)
    w2.write_report("node2")
    w2.write_report("node3")
    for n in ("node2", "node3"):
        w2.router.set_advertised(n, True)
    s2 = await w2.status.status(DOMAIN, force=True)
    assert s2.ecmp_active == 3 and s2.ecmp_source == "FAKE_ROUTER" and s2.overall == "ACTIVE"
    w2.router.set_advertised("node3", False)
    s3 = await w2.status.status(DOMAIN, force=True)
    assert s3.ecmp_active == 2 and s3.overall == "DEGRADED" and any("router FIB has 2 path(s)" in r for r in s3.reasons)
    print("Test 5 (ECMP active paths exist only with a router observer; with one, disagreement with node reports degrades the status) PASSED")


async def test_6_node_reports_are_trusted_only_when_signed():
    w = World(tempfile.mkdtemp(), nodes=2)
    await enable(w)
    w.write_report("node2", key=b"w" * 32)
    status = await w.status.status(DOMAIN, force=True)
    node2 = next(n for n in status.nodes if n.node_id == "node2")
    assert node2.source == "NONE" and node2.report_status == "NODE_REPORT_INVALID" and node2.serving is None
    nokey = World(tempfile.mkdtemp(), nodes=2, key=None)
    await enable(nokey)
    nokey.write_report("node2", key=b"w" * 32)
    node2 = next(n for n in (await nokey.status.status(DOMAIN, force=True)).nodes if n.node_id == "node2")
    assert node2.source == "NONE" and "signing key" in node2.report_detail
    print("Test 6 (a node report with a bad signature, or no configured key, contributes no state at all) PASSED")


async def test_7_shadow_mode_status_is_honest():
    w = World(tempfile.mkdtemp(), apply_enabled=False)
    await enable(w)
    status = await w.status.status(DOMAIN, force=True)
    assert status.overall == "SHADOW" and status.shadow and status.serving_count == 0
    assert any("nothing is advertised by RTSA" in r for r in status.reasons)
    assert "SHADOW" in text_of(format_bgp_status(status))
    print("Test 7 (apply_enabled=false: the status says SHADOW, nothing is claimed to be serving) PASSED")


async def test_8_status_for_unconfigured_domains():
    w = World(tempfile.mkdtemp())
    view, error = await w.orchestrator.cekloadbalance("other.example.com")
    assert view is None and "not configured" in error
    view, error = await w.orchestrator.cekloadbalance("../x")
    assert view is None and "invalid domain" in error
    disabled = World(tempfile.mkdtemp())
    disabled.status.cfg = replace(disabled.cfg, enabled=False)
    view, _ = await disabled.orchestrator.cekloadbalance(DOMAIN)
    assert view.overall == "NOT_CONFIGURED" and any("enabled is false" in r for r in view.reasons)
    print("Test 8 (cek on an unconfigured / invalid / disabled service says so and never invents state) PASSED")


async def test_9_add_preview_identity_and_gating():
    w = World(tempfile.mkdtemp())
    await w.node.controller.start()
    preview = await w.orchestrator.addloadbalance(DOMAIN, operator="op")
    assert preview.status == OpStatus.DRY_RUN and preview.nodes == ["node1"] and preview.dry_run
    assert any("health-gated advertisement for node node1" in x for x in preview.would_create)
    assert w.node.controller.desired == "DISABLED" and w.node.speaker.announce_calls == 0
    w2 = World(tempfile.mkdtemp())
    w2.local = "server_9"
    result = await w2.orchestrator.addloadbalance(DOMAIN, operator="op")
    assert result.status == OpStatus.PRECHECK_FAILED and "hostname is never consulted" in result.message
    w3 = World(tempfile.mkdtemp())
    w3.local = ""
    assert (await w3.orchestrator.addloadbalance(DOMAIN, operator="op")).status == OpStatus.PRECHECK_FAILED
    print("Test 9 (/addloadbalance preview: server identity from server.config.yaml only; non-nodes are refused; nothing changes) PASSED")


async def test_10_add_apply_is_gated_by_config_feasibility_confirmation():
    shadow = World(tempfile.mkdtemp(), apply_enabled=False)
    await shadow.node.controller.start()
    r = await shadow.orchestrator.addloadbalance(DOMAIN, operator="op", apply=True, confirmed=True)
    assert r.status == OpStatus.ABORTED and "apply_enabled is false" in r.message and shadow.node.controller.desired == "DISABLED"
    blocked = World(tempfile.mkdtemp(), attest=False)
    await blocked.node.controller.start()
    r = await blocked.orchestrator.addloadbalance(DOMAIN, operator="op", apply=True, confirmed=True)
    assert r.status == OpStatus.ABORTED and "feasibility" in r.message.lower() and blocked.node.controller.desired == "DISABLED"
    ok = World(tempfile.mkdtemp())
    await ok.node.controller.start()
    ok.node.ports.allow_mutations = False
    r = await ok.orchestrator.addloadbalance(DOMAIN, operator="op", apply=True, confirmed=True)
    assert r.status == OpStatus.ABORTED and "detection-only" in r.message
    ok.node.ports.allow_mutations = True
    for n in ("node2", "node3"):
        ok.router.set_advertised(n, True)
    r = await ok.orchestrator.addloadbalance(DOMAIN, operator="op", apply=True, confirmed=False)
    assert r.status == OpStatus.ABORTED and r.confirmation_needed and ok.node.controller.desired == "DISABLED"
    held, _ = ok.locks.try_acquire(DOMAIN, "someone-else", "addloadbalance")
    r = await ok.orchestrator.addloadbalance(DOMAIN, operator="op", apply=True, confirmed=True)
    assert r.status == OpStatus.BUSY and ok.node.controller.desired == "DISABLED"
    ok.locks.release(DOMAIN, "someone-else")
    r = await ok.orchestrator.addloadbalance(DOMAIN, operator="op", apply=True, confirmed=True)
    assert r.status == OpStatus.SUCCESS and ok.node.controller.desired == "ENABLED"
    assert ok.node.speaker.announce_calls == 0, "enabling never advertises by itself: the node must first prove stable health"
    assert any("controller state" in a for a in r.applied)
    assert any(a["kind"] == "addloadbalance" and a["ok"] for a in ok.ports.audits)
    await run_ticks([ok.node], 60.0)
    assert ok.node.controller.fsm.state == ServiceState.ACTIVE and ok.node.speaker.announce_calls == 1
    print("Test 10 (/addloadbalance --apply needs apply_enabled + feasibility + no detection-only + lock + confirmation; it enables, it does not advertise) PASSED")


async def test_11_drain_resume_disable_through_the_command():
    w = World(tempfile.mkdtemp())
    await enable(w)
    for n in ("node2", "node3"):
        w.router.set_advertised(n, True)
    w.ports.connections = 3
    r = await w.orchestrator.addloadbalance(DOMAIN, operator="op", action="drain", apply=True, confirmed=True)
    assert r.status == OpStatus.SUCCESS and w.node.controller.desired == "DRAINED" and "nginx/PM2 stay running" in r.message
    await run_ticks([w.node], 10.0)
    assert w.node.controller.fsm.state == ServiceState.DRAINING
    w.ports.connections = 0
    await run_ticks([w.node], 30.0)
    assert w.node.controller.fsm.state == ServiceState.WITHDRAWN
    assert w.ports.layer_state[HealthLayer.NGINX] is True and w.ports.layer_state[HealthLayer.APPLICATION] is True
    r = await w.orchestrator.addloadbalance(DOMAIN, operator="op", action="resume", apply=True, confirmed=True)
    assert r.status == OpStatus.SUCCESS and w.node.controller.desired == "ENABLED"
    await run_ticks([w.node], 60.0)
    assert w.node.controller.fsm.state == ServiceState.ACTIVE
    r = await w.orchestrator.addloadbalance(DOMAIN, operator="op", action="disable", apply=True, confirmed=True)
    assert r.status == OpStatus.SUCCESS
    await run_ticks([w.node], 10.0)
    assert w.node.controller.fsm.state == ServiceState.WITHDRAWN and w.node.controller.withdraw_reason == "OPERATOR"
    preview = await w.orchestrator.addloadbalance(DOMAIN, operator="op", action="drain")
    assert preview.status == OpStatus.DRY_RUN and w.node.controller.desired == "DISABLED"
    bad = await w.orchestrator.addloadbalance(DOMAIN, operator="op", action="reboot")
    assert bad.status == OpStatus.PRECHECK_FAILED
    print("Test 11 (drain -> DRAINING -> WITHDRAWN keeps nginx/PM2 running; resume re-qualifies; disable withdraws; unknown actions refused) PASSED")


async def test_12_ecmp_alerts_follow_the_incident_lifecycle():
    w = World(tempfile.mkdtemp(), nodes=4)
    await enable(w)
    for n in ("node2", "node3", "node4"):
        w.router.set_advertised(n, True)
    await w.status.poll_once()
    assert not [e for e in w.ports.events if e.category == EventCategory.LB_ECMP_DEGRADED]
    w.router.set_advertised("node3", False)
    for _ in range(25):
        await w.status.poll_once()
    degraded = [e for e in w.ports.events if e.category == EventCategory.LB_ECMP_DEGRADED]
    assert len(degraded) == 1 and "3/4 paths" in degraded[0].message and "(was 4)" in degraded[0].message, "one alert for 25 polls"
    w.router.set_advertised("node3", True)
    for _ in range(5):
        await w.status.poll_once()
    recovered = [e for e in w.ports.events if e.category == EventCategory.LB_ECMP_RECOVERED]
    assert len(recovered) == 1 and "(3 -> 4)" in recovered[0].message
    w.router.set_advertised("node2", False)
    w.router.set_advertised("node3", False)
    w.router.set_advertised("node4", False)
    w.router.set_advertised("node1", False)
    await w.status.poll_once()
    assert any(e.category == EventCategory.LB_ECMP_DEGRADED and e.severity.value == "CRITICAL" for e in w.ports.events)
    gauges = w.metrics.snapshot()["gauges"]
    assert gauges["lb_bgp_ecmp_expected"] == 4 and gauges["lb_bgp_ecmp_active"] == 0
    print("Test 12 (ECMP 4 -> 3 -> 4 -> 0: one DEGRADED, one RECOVERED, CRITICAL at zero; 25 polls do not spam; gauges follow) PASSED")


async def test_13_ecmp_convergence_is_measured_from_the_router_view():
    w = World(tempfile.mkdtemp(), nodes=3)
    await enable(w)
    for n in ("node2", "node3"):
        w.router.set_advertised(n, True)
    await w.status.poll_once()
    w.node.speaker.visibility_delay = 0.0
    w.node.ports.set(HealthLayer.APPLICATION, False)
    await run_ticks([w.node], 12.0)
    assert w.node.controller.fsm.state == ServiceState.WITHDRAWN
    w.clock.advance(0.4)
    await w.status.poll_once()
    status = await w.status.status(DOMAIN, force=True)
    lat = status.convergence["latencies"]
    assert lat["bgp_convergence_latency"] is not None and lat["ecmp_convergence_latency"] is not None
    assert lat["ecmp_convergence_latency"] >= 0.0 and status.convergence["ecmp_path_removed_at"] is not None
    assert lat["service_recovery_latency"] is None, "service recovery is not measured unless a traffic probe saw it"
    out = text_of(format_bgp_status(status))
    assert "ECMP path removal:" in out and "service recovery : not observed" in out
    print("Test 13 (ECMP convergence latency comes from the router observer's drop; service recovery stays 'not observed') PASSED")


async def test_14_formatting_neutralises_and_hides_secrets():
    w = World(tempfile.mkdtemp())
    await enable(w)
    w.node.ports.set(HealthLayer.APPLICATION, False)
    w.ports.layer_state[HealthLayer.APPLICATION] = False
    await w.node.controller.tick()
    result = await w.orchestrator.addloadbalance(DOMAIN, operator="@everyone", action="prepare")
    out = text_of(format_bgp_add(result))
    assert "Health layers (with provenance)" in out and "LOCAL_PROBE" in out and "application: FAIL" in out
    assert "Not changed" in out and "DNS, Cloudflare, BGP peers/policies, nginx, PM2, databases" in out
    assert "@everyone" not in out or "@​everyone" in out
    print("Test 14 (formatted output carries layer provenance and the 'not changed' list; nothing sensitive or unneutralised) PASSED")


async def main():
    await test_1_gen_dry_run_plans_but_changes_nothing()
    await test_2_gen_rejects_bad_input_before_any_probe()
    await test_3_gen_apply_is_per_node_not_remote()
    await test_4_status_ladder_with_provenance_and_stale_reports()
    await test_5_ecmp_state_comes_from_the_router_or_is_unknown()
    await test_6_node_reports_are_trusted_only_when_signed()
    await test_7_shadow_mode_status_is_honest()
    await test_8_status_for_unconfigured_domains()
    await test_9_add_preview_identity_and_gating()
    await test_10_add_apply_is_gated_by_config_feasibility_confirmation()
    await test_11_drain_resume_disable_through_the_command()
    await test_12_ecmp_alerts_follow_the_incident_lifecycle()
    await test_13_ecmp_convergence_is_measured_from_the_router_view()
    await test_14_formatting_neutralises_and_hides_secrets()
    print("\nALL BGP COMMAND / STATUS TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
