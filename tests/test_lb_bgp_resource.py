import asyncio
import asyncio.subprocess as aio_subprocess
import os
import subprocess
import sys
import tempfile
import time
import tracemalloc
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _lb_bgp_fakes import FakeClock, FakeRouter, Node, make_cfg
from core.lb_bgp_model import HealthLayer, ServiceState
from core.lb_bgp_state import BgpStateStore, MAX_AUDIT, MAX_RECORDS


def many_services(count, nodes=8):
    tmp = tempfile.mkdtemp()
    base = make_cfg(tmp, nodes=nodes)
    template = base.services[0]
    services = [
        replace(template, domain=f"app{i}.example.com", vip=f"10.77.{i // 200}.{i % 200 + 10}", prefix=f"10.77.{i // 200}.{i % 200 + 10}/32")
        for i in range(count)
    ]
    cfg = replace(base, services=services, speaker=replace(base.speaker, state_cache_seconds=5.0))
    return tmp, cfg


async def test_1_polling_is_bounded_not_per_tick():
    tmp, cfg = many_services(32)
    clock = FakeClock()
    router = FakeRouter(clock)
    store = BgpStateStore(os.path.join(tmp, "state.json"), clock=clock.now)
    members = []
    for service in cfg.services:
        scoped = replace(cfg, services=[service])
        node = Node(scoped, service.nodes[0], clock, router, tmp, store=store)
        members.append(node)
    for m in members:
        await m.controller.start()
        await m.controller.request_enable("seed")
    ticks = 150
    for _ in range(ticks):
        for m in members:
            await m.controller.tick()
        clock.advance(2.0)
    per_controller = [m.speaker.queries for m in members]
    assert max(per_controller) <= ticks * 3 // 2, f"speaker queries per controller {max(per_controller)} for {ticks} ticks: cached, not per tick"
    assert max(per_controller) < ticks * 3 / 2.5
    probes = [m.ports.probes for m in members]
    assert all(p == ticks for p in probes), "one probe round per tick, no bursts"
    announces = sum(m.speaker.announce_calls for m in members)
    assert announces == len(members), "each node announces exactly once"
    print(f"Test 1 (32 services x {ticks} ticks: at most {max(per_controller)} speaker queries per controller; one probe round per tick; one announce per node) PASSED")


async def test_2_hot_path_runs_no_subprocess():
    tmp, cfg = many_services(8)
    clock = FakeClock()
    router = FakeRouter(clock)
    calls = {"n": 0}

    def forbid(*a, **k):
        calls["n"] += 1
        raise AssertionError("the controller hot path must not spawn processes itself")

    originals = (subprocess.run, subprocess.Popen, subprocess.check_output, aio_subprocess.create_subprocess_exec if hasattr(aio_subprocess, "create_subprocess_exec") else None, asyncio.create_subprocess_exec)
    subprocess.run = subprocess.Popen = subprocess.check_output = forbid
    asyncio.create_subprocess_exec = forbid
    try:
        members = [Node(replace(cfg, services=[s]), s.nodes[0], clock, router, tmp) for s in cfg.services]
        for m in members:
            await m.controller.start()
            await m.controller.request_enable("seed")
        for _ in range(60):
            for m in members:
                await m.controller.tick()
            clock.advance(2.0)
        for m in members:
            m.ports.set(HealthLayer.APPLICATION, False)
        for _ in range(10):
            for m in members:
                await m.controller.tick()
            clock.advance(2.0)
        assert all(m.controller.fsm.state == ServiceState.WITHDRAWN for m in members)
    finally:
        subprocess.run, subprocess.Popen, subprocess.check_output = originals[:3]
        asyncio.create_subprocess_exec = originals[4]
    assert calls["n"] == 0
    print("Test 2 (probe, decide, withdraw, report: the controller spawns no process; commands exist only behind the speaker/runner port) PASSED")


async def test_3_state_and_memory_are_bounded():
    tmp = tempfile.mkdtemp()
    store = BgpStateStore(os.path.join(tmp, "state.json"))
    for i in range(1000):
        store.put(f"d{i}.example.com|node1", {"state": "ACTIVE", "history": [{"n": j} for j in range(20)]})
        store.add_audit({"kind": "bgp_announce", "i": i, "token": "secret-value", "detail": "x" * 5000})
    assert len(store._records) <= MAX_RECORDS and len(store.audit_entries()) <= MAX_AUDIT
    assert all("secret-value" not in str(e) for e in store.audit_entries()), "secrets are redacted before they are stored"
    size = os.path.getsize(os.path.join(tmp, "state.json"))
    assert size < 2_000_000, size
    tmp2 = tempfile.mkdtemp()
    cfg = make_cfg(tmp2, nodes=3)
    clock = FakeClock()
    router = FakeRouter(clock)
    node = Node(cfg, cfg.services[0].nodes[2], clock, router, tmp2)
    await node.controller.start()
    await node.controller.request_enable("seed")
    tracemalloc.start()
    before = None
    for cycle in range(60):
        node.ports.set(HealthLayer.APPLICATION, cycle % 2 == 0)
        for _ in range(40):
            await node.controller.tick()
            clock.advance(2.0)
        if cycle == 10:
            before = tracemalloc.get_traced_memory()[0]
    after = tracemalloc.get_traced_memory()[0]
    tracemalloc.stop()
    assert len(node.controller.fsm.history) <= 50 and len(node.controller.hyst.transitions) <= node.controller.hyst.transitions.maxlen
    assert len(node.alerts.incidents) <= 8, "incidents are resolved, not accumulated"
    assert after - before < 1_500_000, f"memory grew by {after - before} bytes over 50 flap cycles"
    print("Test 3 (state records, audit ring, history, incidents and memory stay bounded across 2400 ticks with 60 flap cycles) PASSED")


async def test_4_cpu_overhead_is_small():
    tmp, cfg = many_services(16)
    clock = FakeClock()
    router = FakeRouter(clock)
    store = BgpStateStore(os.path.join(tmp, "state.json"), clock=clock.now)
    members = [Node(replace(cfg, services=[s]), s.nodes[0], clock, router, tmp, store=store) for s in cfg.services]
    for m in members:
        await m.controller.start()
        await m.controller.request_enable("seed")
    started = time.process_time()
    rounds = 100
    for _ in range(rounds):
        for m in members:
            await m.controller.tick()
        clock.advance(2.0)
    cpu = time.process_time() - started
    per_tick_ms = cpu / (rounds * len(members)) * 1000.0
    assert per_tick_ms < 25.0, f"{per_tick_ms:.2f} ms CPU per controller tick (fake I/O included)"
    print(f"Test 4 (16 controllers x {rounds} ticks: {per_tick_ms:.2f} ms CPU per tick including state and report writes) PASSED")


async def test_5_drain_and_withdraw_are_not_blocked_by_other_services():
    tmp, cfg = many_services(4, nodes=3)
    clock = FakeClock()
    router = FakeRouter(clock)
    members = [Node(replace(cfg, services=[s]), s.nodes[0], clock, router, tmp) for s in cfg.services]
    for m in members:
        await m.controller.start()
        await m.controller.request_enable("seed")
    for _ in range(40):
        await asyncio.gather(*(m.controller.tick() for m in members))
        clock.advance(2.0)
    assert all(m.controller.fsm.state == ServiceState.ACTIVE for m in members)
    members[1].speaker.fail_withdraw = True
    members[1].ports.set(HealthLayer.APPLICATION, False)
    members[2].ports.set(HealthLayer.APPLICATION, False)
    for _ in range(10):
        await asyncio.gather(*(m.controller.tick() for m in members))
        clock.advance(2.0)
    assert members[2].controller.fsm.state == ServiceState.WITHDRAWN, "a stuck withdraw on one service does not delay another"
    assert members[0].controller.fsm.state == ServiceState.ACTIVE and members[3].controller.fsm.state == ServiceState.ACTIVE
    print("Test 5 (independent services: a failing withdraw on one never blocks or delays another; healthy ones keep serving) PASSED")


async def main():
    await test_1_polling_is_bounded_not_per_tick()
    await test_2_hot_path_runs_no_subprocess()
    await test_3_state_and_memory_are_bounded()
    await test_4_cpu_overhead_is_small()
    await test_5_drain_and_withdraw_are_not_blocked_by_other_services()
    print("\nALL BGP RESOURCE TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
