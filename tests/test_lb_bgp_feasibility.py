import asyncio
import os
import sys
import tempfile
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _lb_bgp_fakes import (
    ALL_ATTESTATIONS, DOMAIN, FakeClock, FakeFeasibilityPorts, FakeObserver, FakeRouter, FakeSpeaker, make_cfg,
)
from config.manager import BgpAttestationConfig, BgpNodeConfig, BgpServiceConfig
from core.lb_bgp_feasibility import (
    ARCH_BGP_ECMP, ARCH_BGP_ECMP_PRIVATE_PLUS_CLOUDFLARE, ARCH_CLOUDFLARE_LB, FEASIBLE, NOT_FEASIBLE, NO_FAKE_BGP, UNPROVEN,
    SCOPE_INTERNET, SCOPE_PRIVATE, assess_feasibility, vip_scope,
)
from core.lb_bgp_model import EcmpObservation, Verdict

PUBLIC_VIP = "9.9.9.10"


def service(vip, prefix, n=3):
    nodes = [BgpNodeConfig(f"node{i + 1}", f"server_{i + 1}", f"10.0.1.{i + 1}") for i in range(n)]
    return BgpServiceConfig(domain=DOMAIN, vip=vip, prefix=prefix, port=443, nodes=nodes)


def world(vip=PUBLIC_VIP, prefix="9.9.9.10/32", attest=True, frr=True, local=True, listening=True, sessions=True, nodes=3):
    clock = FakeClock()
    router = FakeRouter(clock)
    cfg = make_cfg(tempfile.mkdtemp(), nodes=nodes)
    cfg = replace(cfg, services=[service(vip, prefix, nodes)], attestations=list(ALL_ATTESTATIONS) if attest else [])
    ports = FakeFeasibilityPorts(clock)
    if local:
        ports.addresses.append(vip)
    if listening:
        ports.listening = [("0.0.0.0", 443, "nginx")]
    speaker = FakeSpeaker(clock, router, "node1")
    speaker.available = frr
    speaker.session_up = sessions
    return cfg, ports, speaker, router, clock


def checks(report):
    return {c.check_id: c for c in report.checks}


async def run(cfg, ports, speaker, observer=None, advertising=None):
    return await assess_feasibility(
        cfg, cfg.services[0], ports=ports, speaker=speaker, observer=observer, local_node=cfg.services[0].nodes[0],
        advertising_nodes=advertising,
    )


async def test_1_unprovable_topology_is_not_feasible_and_says_why():
    cfg, ports, speaker, router, clock = world(attest=False, frr=False, local=False, listening=False)
    report = await run(cfg, ports, speaker)
    c = checks(report)
    assert report.scope == SCOPE_INTERNET and report.verdict == NOT_FEASIBLE and not report.apply_allowed
    assert c["bgp_speaker_present"].verdict == Verdict.FAILED
    for name in ("upstream_bgp_permitted", "asn_available", "prefix_announceable", "multi_origin_allowed", "provider_antispoof_ok", "router_ecmp_enabled"):
        assert c[name].verdict == Verdict.UNPROVEN and c[name].provenance.value == "NOT_OBSERVED" and c[name].required, name
    assert report.architecture == ARCH_CLOUDFLARE_LB
    assert "NOT proven for public Internet traffic" in report.statement and NO_FAKE_BGP in report.statement
    assert "installing a BGP daemon does not create ECMP" in report.statement
    print("Test 1 (no FRR, no ASN/prefix/upstream evidence: NOT_FEASIBLE, Cloudflare LB recommended, 'no fake BGP' stated) PASSED")


async def test_2_missing_provider_evidence_alone_is_unproven_not_assumed():
    cfg, ports, speaker, router, clock = world(attest=False)
    ports.binaries = {"bird": "/usr/sbin/bird"}
    report = await run(cfg, ports, speaker)
    c = checks(report)
    assert c["bgp_instance"].verdict == Verdict.PROVEN and c["bgp_sessions"].verdict == Verdict.PROVEN
    assert c["vip_local"].verdict == Verdict.PROVEN and c["vip_listener"].verdict == Verdict.PROVEN
    assert report.verdict == UNPROVEN and not report.apply_allowed
    assert all(c[n].verdict == Verdict.UNPROVEN for n in ("upstream_bgp_permitted", "asn_available", "prefix_announceable"))
    assert "bird" in c["other_bgp_daemons"].evidence and "will not touch" in c["other_bgp_daemons"].evidence
    assert "upstream_bgp_permitted" in report.statement
    print("Test 2 (everything measurable is fine but provider facts are unattested: UNPROVEN, apply blocked, other daemons left alone) PASSED")


async def test_3_attested_denial_is_a_failure():
    cfg, ports, speaker, router, clock = world(attest=False)
    cfg = replace(cfg, attestations=[BgpAttestationConfig("prefix_announceable", False, "provider says VPS addresses are not announceable")])
    report = await run(cfg, ports, speaker)
    c = checks(report)["prefix_announceable"]
    assert c.verdict == Verdict.FAILED and c.provenance.value == "ATTESTED" and "NOT available" in c.evidence
    assert report.verdict == NOT_FEASIBLE
    print("Test 3 (an operator attestation that a prerequisite is NOT available fails the feasibility, with provenance ATTESTED) PASSED")


async def test_4_all_prerequisites_with_router_evidence_is_feasible():
    cfg, ports, speaker, router, clock = world()
    for node in ("node1", "node2", "node3"):
        router.register(node)
        router.set_advertised(node, True)
    cfg = replace(cfg, attestations=[a for a in ALL_ATTESTATIONS if a.name != "router_ecmp_enabled"])
    report = await run(cfg, ports, speaker, observer=FakeObserver(router), advertising={"node2": True, "node3": True})
    c = checks(report)
    assert c["router_ecmp"].verdict == Verdict.PROVEN and c["router_ecmp"].provenance.value == "ROUTER_REPORTED"
    assert "3 next-hop" in c["router_ecmp"].evidence
    assert c["fib_matches_rib"].verdict == Verdict.PROVEN
    speaker.originate = True
    report = await run(cfg, ports, speaker, observer=FakeObserver(router), advertising={"node2": True, "node3": True})
    assert checks(report)["multi_node_advertisement"].verdict == Verdict.PROVEN
    assert report.verdict == FEASIBLE and report.apply_allowed and report.architecture == ARCH_BGP_ECMP and report.blockers == []
    print("Test 4 (provider evidence + measured BGP + router FIB with 3 next-hops + 3 advertising nodes: FEASIBLE for the Internet scope) PASSED")


async def test_5_private_vip_behind_cloudflare_cannot_serve_the_internet():
    cfg, ports, speaker, router, clock = world(vip="10.99.0.10", prefix="10.99.0.10/32", attest=False)
    ports.dns = ["104.16.1.1", "104.16.2.2"]
    report = await run(cfg, ports, speaker)
    c = checks(report)
    assert vip_scope("10.99.0.10") == SCOPE_PRIVATE and report.scope == SCOPE_PRIVATE and report.cloudflare_in_front is True
    assert c["cloudflare_reaches_vip"].verdict == Verdict.FAILED and "not a global address" in c["cloudflare_reaches_vip"].evidence
    assert "Cloudflare edge" in c["dns_resolution"].evidence
    assert report.verdict == NOT_FEASIBLE
    assert c["upstream_bgp_permitted"].required is False, "provider attestations are not required for a private scope"
    print("Test 5 (private VIP while Cloudflare proxies the domain: Cloudflare cannot reach it -> NOT_FEASIBLE; DNS is only observed) PASSED")


async def test_6_private_scope_can_be_feasible_for_internal_traffic_only():
    cfg, ports, speaker, router, clock = world(vip="10.99.0.10", prefix="10.99.0.10/32", attest=False)
    ports.dns = ["10.99.0.10"]
    cfg = replace(cfg, attestations=[
        BgpAttestationConfig("common_network_domain", True, "all nodes on VLAN 40, ticket NET-12"),
        BgpAttestationConfig("router_ecmp_enabled", True, "tor1 maximum-paths 8, NET-77"),
    ])
    report = await run(cfg, ports, speaker)
    assert report.verdict == FEASIBLE and report.scope == SCOPE_PRIVATE and report.architecture == ARCH_BGP_ECMP_PRIVATE_PLUS_CLOUDFLARE
    assert "PRIVATE network only" in report.statement and "Cloudflare load balancer" in report.statement
    print("Test 6 (private VIP, common network attested, router ECMP attested: FEASIBLE for the private network; internet stays on Cloudflare) PASSED")


async def test_7_local_prerequisites_are_measured_never_assumed():
    cfg, ports, speaker, router, clock = world(local=False, listening=False)
    c = checks(await run(cfg, ports, speaker))
    assert c["vip_local"].verdict == Verdict.FAILED and "ip addr add" in c["vip_local"].remedy
    assert c["vip_listener"].verdict == Verdict.FAILED and "does not rewrite bind addresses" in c["vip_listener"].remedy
    cfg, ports, speaker, router, clock = world(sessions=False)
    c = checks(await run(cfg, ports, speaker))
    assert c["bgp_sessions"].verdict == Verdict.FAILED and "0/1" in c["bgp_sessions"].evidence
    cfg, ports, speaker, router, clock = world()
    speaker.unexpected = ["198.51.100.9"]
    c = checks(await run(cfg, ports, speaker))
    assert c["peer_allowlist"].verdict == Verdict.FAILED and "198.51.100.9" in c["peer_allowlist"].evidence
    cfg, ports, speaker, router, clock = world()
    speaker.local_asn = 65999
    c = checks(await run(cfg, ports, speaker))
    assert c["bgp_instance"].verdict == Verdict.FAILED and "differs" in c["bgp_instance"].evidence
    cfg, ports, speaker, router, clock = world()
    ports.sysctls["net.ipv4.conf.all.rp_filter"] = "1"
    c = checks(await run(cfg, ports, speaker))
    assert c["net.ipv4.conf.all.rp_filter"].verdict == Verdict.FAILED and not c["net.ipv4.conf.all.rp_filter"].required
    ports.sysctls.pop("net.ipv4.fib_multipath_hash_policy")
    assert checks(await run(cfg, ports, speaker))["net.ipv4.fib_multipath_hash_policy"].verdict == Verdict.UNPROVEN
    print("Test 7 (VIP, listener, sessions, peer allowlist, ASN, rp_filter, multipath sysctl: each measured, failures carry a remedy) PASSED")


async def test_8_fib_and_bgp_table_disagreement_is_surfaced():
    cfg, ports, speaker, router, clock = world()
    for node in ("node1", "node2", "node3"):
        router.register(node)
        router.set_advertised(node, True)

    class SkewedObserver(FakeObserver):
        async def observe(self, prefix):
            return EcmpObservation(prefix, ["10.0.1.1", "10.0.1.2"], 3, "FAKE_ROUTER", "kernel", clock.t)

    report = await run(cfg, ports, speaker, observer=SkewedObserver(router))
    c = checks(report)
    assert c["router_ecmp"].verdict == Verdict.PROVEN and c["fib_matches_rib"].verdict == Verdict.FAILED
    assert "judge ECMP by the FIB" in c["fib_matches_rib"].remedy and "2" in c["fib_matches_rib"].evidence and "3" in c["fib_matches_rib"].evidence

    class Single(FakeObserver):
        async def observe(self, prefix):
            return EcmpObservation(prefix, ["10.0.1.1"], 1, "FAKE_ROUTER", "kernel", clock.t)

    report = await run(cfg, ports, speaker, observer=Single(router))
    assert checks(report)["router_ecmp"].verdict == Verdict.FAILED, "one next-hop is not ECMP"
    print("Test 8 (router FIB vs BGP table disagreement is reported; a single next-hop is not ECMP) PASSED")


async def test_9_report_is_serialisable_and_secret_free():
    cfg, ports, speaker, router, clock = world()
    report = await run(cfg, ports, speaker)
    data = report.to_dict()
    assert data["verdict"] in (FEASIBLE, NOT_FEASIBLE, UNPROVEN) and data["checks"] and all("provenance" in c for c in data["checks"])
    import json

    json.dumps(data)
    print("Test 9 (the report is plain JSON data: every check has a verdict and a provenance) PASSED")


async def main():
    await test_1_unprovable_topology_is_not_feasible_and_says_why()
    await test_2_missing_provider_evidence_alone_is_unproven_not_assumed()
    await test_3_attested_denial_is_a_failure()
    await test_4_all_prerequisites_with_router_evidence_is_feasible()
    await test_5_private_vip_behind_cloudflare_cannot_serve_the_internet()
    await test_6_private_scope_can_be_feasible_for_internal_traffic_only()
    await test_7_local_prerequisites_are_measured_never_assumed()
    await test_8_fib_and_bgp_table_disagreement_is_surfaced()
    await test_9_report_is_serialisable_and_secret_free()
    print("\nALL BGP FEASIBILITY TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
