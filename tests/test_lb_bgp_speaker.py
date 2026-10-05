import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _lb_bgp_fakes import PEER_ADDRESS, PREFIX
from _lb_bgp_frr_fake import FakeFrr
from config.manager import BgpPeerConfig, BgpRouterObserverConfig, BgpSpeakerConfig
from core.lb_bgp_speaker import (
    FrrRouterObserver, FrrVtyshSpeaker, NullRouterObserver, SubprocessRunner, redact_config_text,
)

import core.lb_bgp_speaker as speaker_module

REAL_RESOLVE = speaker_module.resolve_binary
speaker_module.resolve_binary = lambda path, which=None: path if path and " " not in path and "\x00" not in path else None

PEERS = [BgpPeerConfig("rtr", PEER_ADDRESS, 65000)]


def speaker(fake, **over):
    cfg = BgpSpeakerConfig(vtysh_path="/usr/bin/vtysh", local_asn=65001, state_cache_seconds=1.0, **over)
    return FrrVtyshSpeaker(cfg, PEERS, fake, which=lambda name: "/usr/bin/" + name)


async def test_1_announce_and_withdraw_use_fixed_vtysh_templates():
    if True:
        fake = FakeFrr()
        spk = speaker(fake)
        result = await spk.announce(PREFIX)
        assert result.ok and result.changed and PREFIX in fake.originated
        assert await spk.originated(PREFIX) is True and await spk.advertised_peers(PREFIX) == [PEER_ADDRESS]
        last = [c for c in fake.calls if "configure terminal" in c][-1]
        assert last[0] == "/usr/bin/vtysh" and last.count("-c") == 4, "one argv list, never a shell string"
        assert last[1:] == ["-c", "configure terminal", "-c", "router bgp 65001", "-c", "address-family ipv4 unicast", "-c", f"network {PREFIX}"]
        again = await spk.announce(PREFIX)
        assert again.ok and fake.originated == [PREFIX], "announce is idempotent"
        gone = await spk.withdraw(PREFIX)
        assert gone.ok and gone.changed and fake.originated == []
        assert await spk.originated(PREFIX) is False and await spk.advertised_peers(PREFIX) == []
        second = await spk.withdraw(PREFIX)
        assert second.ok and not second.changed and second.detail == "already withdrawn", "withdraw is idempotent"
    print("Test 1 (announce/withdraw: one fixed vtysh argv, idempotent both ways, verified through the BGP table) PASSED")


async def test_2_hostile_prefixes_never_reach_vtysh():
    if True:
        fake = FakeFrr()
        spk = speaker(fake)
        hostile = [
            "203.0.113.10/32; reload", "203.0.113.10/32\nrouter bgp 1", "$(reboot)", "../../etc/passwd", "0.0.0.0/0", "203.0.0.0/8",
            "203.0.113.10/33", "", " ", "a" * 500, "203.0.113.10/32 && id", "::/0", "2001:db8::/32",
            "203.0.113.11/24",
        ]
        for text in hostile:
            fake.calls.clear()
            result = await spk.announce(text)
            assert not result.ok and not any(c for c in fake.calls if "network" in " ".join(c)), repr(text)
            assert not (await spk.withdraw(text)).ok, repr(text)
        assert fake.originated == []
    print("Test 2 (hostile / too-broad / malformed prefixes are refused before any vtysh call) PASSED")


async def test_3_wrong_asn_unexpected_peer_and_missing_bgp_are_refused():
    if True:
        wrong = FakeFrr(asn=65999)
        refused = await speaker(wrong).announce(PREFIX)
        assert not refused.ok and "differs" in refused.detail and wrong.originated == []
        none = FakeFrr(asn=None)
        refused = await speaker(none).announce(PREFIX)
        assert not refused.ok and "never creates a BGP instance" in refused.detail or "not running" in refused.detail
        assert none.asn is None, "RTSA must never create `router bgp`"
        rogue = FakeFrr()
        rogue.unexpected = {"198.51.100.99": "Established"}
        refused = await speaker(rogue).announce(PREFIX)
        assert not refused.ok and "unexpected BGP peers" in refused.detail and rogue.originated == []
        snap = await speaker(rogue).peers(force=True)
        assert snap.unexpected == ["198.51.100.99"] and list(snap.peers) == ["rtr"], "an unauthorized peer is reported, never adopted"
        down = FakeFrr()
        down.daemon_up = False
        refused = await speaker(down).announce(PREFIX)
        assert not refused.ok and not down.originated
        cap = await speaker(down).capability()
        assert cap.available and not cap.daemon_reachable
    print("Test 3 (wrong ASN, no BGP instance, unauthorized peer, daemons down: nothing is announced and nothing is created) PASSED")


async def test_4_timeouts_garbage_and_missing_binary():
    if True:
        slow = FakeFrr()
        slow.timeout = True
        assert (await speaker(slow).announce(PREFIX)).ok is False
        assert await speaker(slow).originated(PREFIX) is None
        garbage = FakeFrr()
        garbage.garbage = True
        assert await speaker(garbage).originated(PREFIX) is None and (await speaker(garbage).peers(force=True)).ok is False
        speaker_module.resolve_binary = lambda path, which=None: None
        missing = speaker(FakeFrr())
        cap = await missing.capability()
        assert cap.available is False and "not found" in cap.detail
        assert (await missing.announce(PREFIX)).ok is False
        speaker_module.resolve_binary = lambda path, which=None: path if path and " " not in path and "\x00" not in path else None
    assert REAL_RESOLVE("vtysh; reboot") is None and REAL_RESOLVE("/etc/passwd") is None and REAL_RESOLVE("") is None
    assert REAL_RESOLVE("a b") is None and REAL_RESOLVE("v\x00") is None
    print("Test 4 (timeouts, non-JSON output, missing binary: unknown / refused, never assumed; binary path cannot carry arguments) PASSED")


async def test_5_secrets_never_leave_the_speaker():
    if True:
        fake = FakeFrr()
        spk = speaker(fake)
        digest = await spk.running_config_digest()
        assert digest and "SuperSecret123" not in digest
        text = redact_config_text(fake.running_config)
        assert "SuperSecret123" not in text and "[REDACTED]" in text and "remote-as 65000" in text
        refused = await speaker(FakeFrr(asn=65999)).announce(PREFIX)
        assert "SuperSecret123" not in str(refused.to_dict())
    print("Test 5 (BGP authentication secrets are redacted from every digest/log/result) PASSED")


async def test_6_state_is_cached_not_polled():
    if True:
        fake = FakeFrr()
        spk = speaker(fake)
        for _ in range(20):
            await spk.peers()
        assert len(fake.calls) == 1, "peer state is cached for state_cache_seconds, never polled per call"
        await spk.peers(force=True)
        assert len(fake.calls) == 2
    print("Test 6 (20 status reads inside the cache window -> one vtysh command; no per-second BGP polling) PASSED")


async def test_6b_back_to_back_prefix_reads_are_coalesced():
    fake = FakeFrr()
    fake.originated = [PREFIX]
    spk = speaker(fake)
    await spk.originated(PREFIX)
    await spk.advertised_peers(PREFIX)
    assert len([c for c in fake.calls if any("unicast 203.0.113.10/32 json" in part for part in c)]) == 1, "originated + advertised_peers share one vtysh call"
    await spk.announce(PREFIX)
    await spk.originated(PREFIX)
    assert len([c for c in fake.calls if any("unicast 203.0.113.10/32 json" in part for part in c)]) == 2, "a change invalidates the cached entry"
    print("Test 6b (originated + advertised_peers in one refresh cost a single vtysh call; our own change invalidates it) PASSED")


async def test_7_router_observer_reads_the_fib_not_just_the_bgp_table():
    fake = FakeFrr()
    fake.ip_routes = [{"dst": "203.0.113.10", "protocol": "bgp", "flags": [], "nexthops": [
        {"gateway": "10.10.1.2", "dev": "a", "flags": []}, {"gateway": "10.10.2.2", "dev": "b", "flags": []},
        {"gateway": "10.10.3.2", "dev": "c", "flags": ["dead", "linkdown"]},
    ]}]
    if True:
        obs = FrrRouterObserver(BgpRouterObserverConfig(type="frr_vtysh", ip_path="/sbin/ip", vtysh_path="/usr/bin/vtysh"), fake)
        out = await obs.observe(PREFIX)
        assert out.nexthops == ["10.10.1.2", "10.10.2.2"] and out.active == 2 and out.fib_source == "kernel", "dead next-hops do not count"
        fake.originated = [PREFIX]
        fake.ip_routes = []
        assert (await FrrRouterObserver(BgpRouterObserverConfig(type="frr_vtysh", ip_path="/sbin/ip", vtysh_path="/usr/bin/vtysh"), fake).observe(PREFIX)).active == 0
        bad = await FrrRouterObserver(BgpRouterObserverConfig(type="frr_vtysh", ip_path="/sbin/ip"), fake).observe("not-a-prefix")
        assert bad.error and bad.active == 0
    null = await NullRouterObserver().observe(PREFIX)
    assert null.source == "NOT_OBSERVED" and null.error
    print("Test 7 (router observer: kernel FIB next-hops, dead ones excluded; without an observer the answer is NOT_OBSERVED, never a guess) PASSED")


async def test_8_subprocess_runner_is_bounded_and_shell_free():
    runner = SubprocessRunner()
    ok = await runner.run(["/bin/echo", "hello; id"], 5.0, 1000)
    assert ok.ok and ok.stdout.strip() == "hello; id", "no shell: metacharacters stay literal"
    big = await runner.run(["/usr/bin/head", "-c", "100000", "/dev/zero"], 5.0, 100)
    assert big.truncated and len(big.stdout) <= 100
    slow = await runner.run(["/bin/sleep", "5"], 0.3, 100)
    assert slow.timed_out and slow.rc is None
    missing = await runner.run(["/nonexistent/binary"], 1.0, 100)
    assert missing.missing and not missing.ok
    env = await runner.run(["/usr/bin/env"], 5.0, 4000)
    assert "HOME" not in env.stdout and "RTSA_" not in env.stdout and "PATH=" in env.stdout, "minimal environment, no secrets"
    print("Test 8 (command runner: no shell, bounded output, hard timeout, minimal environment) PASSED")


async def main():
    await test_1_announce_and_withdraw_use_fixed_vtysh_templates()
    await test_2_hostile_prefixes_never_reach_vtysh()
    await test_3_wrong_asn_unexpected_peer_and_missing_bgp_are_refused()
    await test_4_timeouts_garbage_and_missing_binary()
    await test_5_secrets_never_leave_the_speaker()
    await test_6_state_is_cached_not_polled()
    await test_6b_back_to_back_prefix_reads_are_coalesced()
    await test_7_router_observer_reads_the_fib_not_just_the_bgp_table()
    await test_8_subprocess_runner_is_bounded_and_shell_free()
    print("\nALL BGP SPEAKER TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
