import os
import sys
import tempfile
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _lb_bgp_fakes import PEER_ADDRESS, PREFIX, make_cfg
import config.manager as cm
from config.manager import BgpAttestationConfig, BgpNodeConfig, BgpPeerConfig, LoadBalancingConfig
from core import lb_bgp_validate as lbv
from core.lb_bgp_health import Hysteresis, evaluate_layers
from core.lb_bgp_model import (
    ALLOWED_TRANSITIONS, Convergence, HealthLayer, IllegalTransition, LayerResult, Provenance, ServiceFsm, ServiceState,
)
from core.lb_bgp_orchestrator import parse_bgp_arguments, render_reference_config, wants_bgp_mode


def lb(bgp):
    return replace(LoadBalancingConfig(), bgp_ecmp=bgp)


def errors_for(bgp):
    out = []
    cm._validate_load_balancing(lb(bgp), out)
    return out


def valid(**over):
    return make_cfg(tempfile.mkdtemp(), nodes=2, **over)


def only_error(bgp, needle):
    errors = errors_for(bgp)
    assert any(needle in e for e in errors), (needle, errors)


def test_1_shipped_profiles_and_defaults_are_safe():
    assert errors_for(LoadBalancingConfig().bgp_ecmp) == []
    assert LoadBalancingConfig().bgp_ecmp.enabled is False and LoadBalancingConfig().bgp_ecmp.apply_enabled is False
    os.environ["RTSA_DISCORD_BOT_TOKEN"] = "MTE1Nzk2.G7vQ2k.Zq8rT2vK9mLp4WnB7yHdE5uXcA1sF3gJ0oP"
    os.environ["RTSA_CLOUDFLARE_API_TOKEN"] = "Zq8rT2vK9mLp4WnB7yHdE5uXcA1sF3gJ0oPiR6tY"
    for name in ("config/config.yaml", "config/config2.yaml"):
        cfg = cm.ConfigManager(os.path.abspath(name)).config.load_balancing.bgp_ecmp
        assert not cfg.enabled and not cfg.apply_enabled and not cfg.manage_vip and cfg.services == [] and cfg.peers == []
        assert cfg.router_observer.type == "none" and cfg.health.down_threshold >= 2 and cfg.policy.accept_inbound_routes is False
        assert not any(a.value for a in cfg.attestations), "the repository invents no provider facts"
    print("Test 1 (shipped profiles: bgp_ecmp disabled, shadow-only, no invented VIP/ASN/peers/attestations) PASSED")


def test_2_valid_configuration_has_no_errors():
    cfg = valid()
    assert errors_for(cfg) == [], errors_for(cfg)
    full = replace(
        cfg, manage_vip=True,
        attestations=[BgpAttestationConfig("router_ecmp_enabled", True, "ticket NET-1234: maximum-paths 8 on tor1")],
        peers=[BgpPeerConfig("rtr", PEER_ADDRESS, 65000, "ipv4", "RTSA_BGP_PEER_SECRET")],
    )
    assert errors_for(full) == []
    print("Test 2 (a complete valid bgp_ecmp configuration passes validation) PASSED")


def test_3_malformed_configuration_is_rejected():
    base = valid()
    svc = base.services[0]

    def with_service(**over):
        return replace(base, services=[replace(svc, **over)])

    only_error(with_service(vip="127.0.0.1", prefix="127.0.0.1/32"), "loopback")
    only_error(with_service(vip="169.254.169.254", prefix="169.254.169.254/32"), "link-local")
    only_error(with_service(vip="224.0.0.1", prefix="224.0.0.1/32"), "multicast")
    only_error(with_service(vip="0.0.0.0", prefix="0.0.0.0/32"), "unspecified")
    only_error(with_service(vip="2001:db8::1"), "not an ipv4 address")
    only_error(with_service(vip="203.0.113.10; reboot"), "not a valid IP address")
    only_error(with_service(prefix="203.0.0.0/16"), "too broad")
    only_error(with_service(prefix="0.0.0.0/0"), "too broad")
    only_error(with_service(prefix="203.0.113.11/32"), "does not contain the VIP")
    only_error(with_service(prefix="203.0.113.10/24"), "host bits")
    only_error(with_service(prefix="not-a-prefix"), "valid CIDR")
    only_error(with_service(domain="not a domain"), "domain tidak valid")
    only_error(with_service(port=0), "port")
    only_error(with_service(scheme="ftp"), "scheme")
    only_error(with_service(health_path="/x?y=1"), "health_path")
    only_error(with_service(minimum_ready_nodes=9), "minimum_ready_nodes")
    only_error(with_service(address_family="ipv5"), "address_family")
    only_error(with_service(nodes=[BgpNodeConfig("n1", "host1", "10.0.1.1")]), "server_identity")
    only_error(with_service(nodes=[BgpNodeConfig("n1", "server_1", "10.0.1.999")]), "address")
    only_error(with_service(nodes=[BgpNodeConfig("n1", "server_1", "10.0.1.1"), BgpNodeConfig("n1", "server_2", "10.0.1.2")]), "duplikat")
    only_error(with_service(nodes=[BgpNodeConfig("n1", "server_1", "10.0.1.1"), BgpNodeConfig("n2", "server_1", "10.0.1.2")]), "dipakai dua node")
    only_error(with_service(nodes=[BgpNodeConfig("n1", "server_1", "10.0.1.1"), BgpNodeConfig("n2", "server_2", "10.0.1.1")]), "dipakai dua node")
    only_error(replace(base, services=[svc, replace(svc, domain="b.example.com", prefix="203.0.113.0/24")]), "prefix berbeda")
    only_error(replace(base, services=[svc, svc]), "duplikat")
    only_error(replace(base, speaker=replace(base.speaker, local_asn=0), enabled=True), "local_asn wajib")
    for asn in (23456, 65535, 4294967295, -5, 4294967296):
        only_error(replace(base, speaker=replace(base.speaker, local_asn=asn)), "local_asn")
    only_error(replace(base, peers=[BgpPeerConfig("p", "10.0.0.1; reboot", 65000)]), "address")
    only_error(replace(base, peers=[BgpPeerConfig("p", "127.0.0.1", 65000)]), "loopback")
    only_error(replace(base, peers=[BgpPeerConfig("p", "10.0.0.1", 0)]), "asn")
    only_error(replace(base, peers=[BgpPeerConfig("p", "10.0.0.1", 65000), BgpPeerConfig("q", "10.0.0.1", 65000)]), "duplikat")
    only_error(replace(base, peers=[BgpPeerConfig("p", "10.0.0.1", 65000, "ipv4", "hunter2 is the password")]), "NAMA environment variable")
    only_error(replace(base, peers=[BgpPeerConfig("p; id", "10.0.0.1", 65000)]), "peer_id")
    only_error(replace(base, speaker=replace(base.speaker, vtysh_path="vtysh -c reboot")), "vtysh_path")
    only_error(replace(base, speaker=replace(base.speaker, vtysh_pathspace="../x")), "vtysh_pathspace")
    only_error(replace(base, speaker=replace(base.speaker, vty_socket_dir="relative/dir")), "vty_socket_dir")
    only_error(replace(base, speaker=replace(base.speaker, vtysh_pathspace="a", vty_socket_dir="/x")), "tidak boleh dipakai bersamaan")
    only_error(replace(base, speaker=replace(base.speaker, type="bird")), "speaker.type")
    only_error(replace(base, speaker=replace(base.speaker, command_timeout_seconds=0.1)), "command_timeout")
    only_error(replace(base, speaker=replace(base.speaker, state_cache_seconds=0.2)), "state_cache_seconds")
    only_error(replace(base, timers=replace(base.timers, hold_seconds=4)), "hold_seconds")
    only_error(replace(base, bfd=replace(base.bfd, multiplier=0)), "bfd")
    only_error(replace(base, policy=replace(base.policy, max_prefix=0)), "max_prefix")
    only_error(replace(base, policy=replace(base.policy, communities=["65000:abc"])), "communities")
    only_error(replace(base, policy=replace(base.policy, next_hop="evil")), "next_hop")
    only_error(replace(base, health=replace(base.health, down_threshold=1)), "satu probe gagal")
    only_error(replace(base, health=replace(base.health, probe_interval_seconds=0.1)), "probe_interval")
    only_error(replace(base, health=replace(base.health, nginx="maybe")), "nginx")
    only_error(replace(base, health=replace(base.health, database="required")), "database_targets")
    only_error(replace(base, health=replace(base.health, backend="required")), "backend_targets")
    only_error(replace(base, health=replace(base.health, backend_targets=["db; rm"])), "host:port")
    only_error(replace(base, health=replace(base.health, max_transitions_per_window=1)), "max_transitions_per_window")
    only_error(replace(base, drain=replace(base.drain, wait_seconds=100, max_wait_seconds=10)), "drain")
    only_error(replace(base, router_observer=replace(base.router_observer, type="ssh_root")), "router_observer.type")
    only_error(replace(base, state_path="relative.json"), "path absolut")
    only_error(replace(base, node_report_interval_seconds=1.0), "node_report_interval")
    only_error(replace(base, attestations=[BgpAttestationConfig("magic", True, "x")]), "tidak dikenal")
    only_error(replace(base, attestations=[BgpAttestationConfig("asn_available", True, "")]), "wajib menyertakan evidence")
    only_error(replace(base, attestations=[BgpAttestationConfig("asn_available", False, ""), BgpAttestationConfig("asn_available", False, "")]), "duplikat")
    only_error(replace(base, enabled=False, apply_enabled=True), "apply_enabled")
    only_error(replace(base, enabled=True, peers=[]), "peers wajib")
    only_error(replace(base, enabled=True, services=[]), "services wajib")
    print("Test 3 (malformed VIP/prefix/ASN/peer/node/timer/policy/health/attestation/secret configs are each rejected) PASSED")


def test_4_validators():
    ip, problem = lbv.parse_address("203.0.113.10", "ipv4")
    assert ip is not None and not problem
    for bad, family in (("10.0.0.1/24", "ipv4"), ("fe80::1", "ipv6"), ("::1", "ipv6"), ("224.0.0.9", "ipv4"), ("", "ipv4"), ("1.2.3.4%eth0", "ipv4"), ("::ffff:127.0.0.1", "ipv6")):
        assert lbv.parse_address(bad, family)[0] is None, bad
    assert lbv.parse_prefix("203.0.113.10/32", ip, "ipv4")[0] is not None
    v6, _ = lbv.parse_address("2001:db8::10", "ipv6")
    assert lbv.parse_prefix("2001:db8::10/128", v6, "ipv6")[0] is not None and lbv.parse_prefix("2001:db8::/32", v6, "ipv6")[0] is None
    assert lbv.asn_error(65001) == "" and lbv.is_private_asn(65001) and not lbv.is_private_asn(13335)
    assert lbv.asn_error(True) and lbv.asn_error("65001") and lbv.asn_error(0)
    assert lbv.vty_socket_error("/var/run/frr") == "" and lbv.vty_socket_error("/a/../b") and lbv.pathspace_error("ok-1") == ""
    assert lbv.NODE_ID_RE.match("node1") and not lbv.NODE_ID_RE.match("Node 1") and lbv.SERVER_IDENTITY_RE.match("server_2")
    print("Test 4 (address/prefix/ASN/path validators: private is allowed, loopback/link-local/multicast/overbroad are not) PASSED")


def test_5_state_machine_is_explicit():
    assert set(ALLOWED_TRANSITIONS) == set(ServiceState) and len(ServiceState) == 13
    fsm = ServiceFsm()
    for target in (ServiceState.VALIDATING, ServiceState.PLANNED, ServiceState.PREPARED, ServiceState.HEALTH_CHECKING,
                   ServiceState.READY, ServiceState.ADVERTISING, ServiceState.ACTIVE, ServiceState.DRAINING, ServiceState.WITHDRAWN):
        assert fsm.move(target, "step", 1.0)
    for illegal in (ServiceState.ACTIVE, ServiceState.ADVERTISING, ServiceState.DEGRADED, ServiceState.PLANNED):
        try:
            fsm.move(illegal, "nope", 2.0)
            raise AssertionError(illegal)
        except IllegalTransition:
            pass
    assert not fsm.move(ServiceState.WITHDRAWN, "same", 3.0)
    assert fsm.force(ServiceState.FAILED, "crash", 4.0) and fsm.state == ServiceState.FAILED
    for i in range(200):
        fsm.force(ServiceState.DISCOVERING if i % 2 == 0 else ServiceState.FAILED, "loop", float(i))
    assert len(fsm.history) <= 50
    only_serving = [s for s in ServiceState if ServiceFsm(s).serving]
    assert only_serving == [ServiceState.ACTIVE, ServiceState.DEGRADED]
    print("Test 5 (13-state lifecycle: only declared transitions, illegal ones raise, history bounded, serving != enabled) PASSED")


def layers(**ok):
    return {
        layer: LayerResult(layer, ok.get(layer.value, True), Provenance.LOCAL_PROBE, "" if ok.get(layer.value, True) else "bad", 1.0)
        for layer in HealthLayer
    }


def test_6_layered_health_keeps_provenance_and_policy():
    health = valid().health
    verdict = evaluate_layers(health, layers())
    assert verdict.ready is True and verdict.state == "READY"
    assert all(r.provenance == Provenance.LOCAL_PROBE for r in verdict.results.values())
    assert evaluate_layers(health, layers(application=False)).ready is False
    assert evaluate_layers(health, layers(application=False)).failed_layers == ["application"]
    assert evaluate_layers(health, layers(application=None)).ready is None and evaluate_layers(health, layers(application=None)).state == "UNKNOWN"
    optional = evaluate_layers(health, layers(database=False))
    assert optional.ready is True and optional.warnings == ["database (optional) check failed"]
    ignored = evaluate_layers(replace(health, database="ignored"), layers(database=False))
    assert ignored.ready is True and ignored.warnings == []
    drained = evaluate_layers(health, layers(), draining=True)
    assert drained.ready is False and drained.draining and drained.failed_layers == [] and "draining" in drained.reason()
    planes = {r.layer.value: r.plane.value for r in verdict.results.values()}
    assert planes["vip_listener"] == "B_NETWORK" and planes["application"] == "C_APPLICATION", "layers keep their plane"
    print("Test 6 (layered health keeps plane + provenance per layer; required/optional/ignored; unknown is not failure; drain is not failure) PASSED")


def test_7_hysteresis_rules():
    health = replace(valid().health, down_threshold=3, up_threshold=3, min_healthy_seconds=10.0, cooldown_seconds=20.0, max_transitions_per_window=3, transition_window_seconds=100.0, flap_hold_seconds=50.0)
    h = Hysteresis(health)
    good, bad, unknown = evaluate_layers(health, layers()), evaluate_layers(health, layers(application=False)), evaluate_layers(health, layers(application=None))
    for t in (0.0, 1.0):
        h.observe(bad, t)
    assert not h.failed()
    h.observe(unknown, 2.0)
    assert not h.failed() and h.consecutive_fail == 2, "unknown neither fails nor heals"
    h.observe(bad, 3.0)
    assert h.failed() and h.first_failure_at == 0.0
    for t in (4.0, 5.0, 6.0):
        h.observe(good, t)
    assert h.consecutive_ok == 3 and h.first_failure_at is None and not h.stable(6.0) and h.may_advertise(6.0)[1].startswith("minimum healthy")
    assert h.stable(16.0) and h.may_advertise(16.0) == (True, "")
    h.note_withdraw(16.0)
    assert not h.may_advertise(30.0)[0] and "cooldown" in h.may_advertise(30.0)[1]
    assert h.may_advertise(40.0)[0]
    h.note_advertise(40.0)
    h.note_withdraw(41.0)
    h.note_advertise(42.0)
    h.note_withdraw(43.0)
    assert h.flap_suppressed(44.0) and "flap" in h.may_advertise(60.0)[1] and h.flap_events == 1
    assert not h.flap_suppressed(100.0)
    print("Test 7 (hysteresis: consecutive failures, recovery confirmation, minimum healthy duration, cooldown, flap hold-down) PASSED")


def test_8_convergence_never_invents_numbers():
    c = Convergence(event="UNHEALTHY", failure_detected_at=10.0, health_failed_at=14.0, route_withdraw_started_at=14.2, bgp_withdraw_observed_at=14.9)
    lat = c.latencies()
    assert lat["health_detection_latency"] == 4.0 and lat["bgp_convergence_latency"] == 0.7
    assert lat["ecmp_convergence_latency"] is None and lat["service_recovery_latency"] is None
    assert c.slowest() == 4.0 and Convergence().slowest() is None and Convergence().latencies()["bgp_convergence_latency"] is None
    assert Convergence.from_dict(c.to_dict()).latencies() == lat and Convergence.from_dict({"junk": 1, "event": "x"}).event == "x"
    print("Test 8 (convergence latencies come only from recorded timestamps; unobserved stages stay None) PASSED")


def test_9_arguments_and_mode_selection():
    assert parse_bgp_arguments("example.com --bgp-ecmp --dry-run", "node1 node2")[:2] == ("example.com", ["node1", "node2"])
    domain, nodes, flags, error = parse_bgp_arguments("example.com", "node1,node2 --apply")
    assert domain == "example.com" and nodes == ["node1", "node2"] and flags["apply"] and error is None
    for bad in ("--rm-rf example.com", "example.com --drain --resume", "", "a" * 5000, "example.com --bgp-ecmp --evil"):
        assert parse_bgp_arguments(bad)[3], bad
    assert wants_bgp_mode("example.com --bgp-ecmp") == "bgp_ecmp" and wants_bgp_mode("example.com --drain") == "bgp_ecmp"
    assert wants_bgp_mode("example.com --cloudflare") == "cloudflare" and wants_bgp_mode("example.com") is None
    assert wants_bgp_mode("example.com --bgp-ecmp --cloudflare") == "conflict"
    print("Test 9 (command argument parsing: BGP flags, hostile input, explicit mode selection and conflicts) PASSED")


def test_10_reference_config_is_safe_to_show():
    cfg = replace(
        valid(), bfd=replace(valid().bfd, enabled=True),
        peers=[BgpPeerConfig("rtr", PEER_ADDRESS, 65000, "ipv4", "RTSA_BGP_PEER_SECRET")],
        speaker=replace(valid().speaker, local_asn=65001),
    )
    os.environ["RTSA_BGP_PEER_SECRET"] = "TopSecretValue!"
    lines = render_reference_config(cfg, cfg.services[0], cfg.services[0].nodes[0])
    text = "\n".join(lines)
    assert "TopSecretValue!" not in text and "RTSA_BGP_PEER_SECRET" in text and "never printed" in text
    assert f"permit {PREFIX}" in text and "maximum-prefix" in text and "RTSA_DENY_ALL in" in text and "bfd" in text
    assert not any(line.strip().startswith("network ") for line in lines), "RTSA owns the network statement; it is never in the static config"
    assert not any(token in text for token in ("0.0.0.0/0", "redistribute"))
    print("Test 10 (the reference FRR config exports only the VIP prefix, denies inbound routes, and never prints a secret) PASSED")


def main():
    test_1_shipped_profiles_and_defaults_are_safe()
    test_2_valid_configuration_has_no_errors()
    test_3_malformed_configuration_is_rejected()
    test_4_validators()
    test_5_state_machine_is_explicit()
    test_6_layered_health_keeps_provenance_and_policy()
    test_7_hysteresis_rules()
    test_8_convergence_never_invents_numbers()
    test_9_arguments_and_mode_selection()
    test_10_reference_config_is_safe_to_show()
    print("\nALL BGP CONFIG / MODEL TESTS PASSED")


if __name__ == "__main__":
    main()
