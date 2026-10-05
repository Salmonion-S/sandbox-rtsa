from __future__ import annotations

import asyncio
import os
import random
import subprocess
import sys
import time
import tracemalloc
from unittest import mock

_TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _TESTS)
os.chdir(os.path.dirname(_TESTS))

from _lb_fakes import ZONE_ID, Env, FakeCloudflare, make_config
from config.manager import LbDomainConfig, LoadBalancingConfig
from core.lb_model import OpStatus

DOMAINS = [f"app{i:02d}.example.com" for i in range(24)]
ORIGINS = 8


class MeteredCloudflare:
    def __init__(self, inner: FakeCloudflare, delay: float = 0.0004) -> None:
        self.inner = inner
        self.delay = delay
        self.inflight = 0
        self.peak = 0
        self.total = 0
        self.peak_tasks = 0

    def __getattr__(self, name):
        attr = getattr(self.inner, name)
        if not asyncio.iscoroutinefunction(attr):
            return attr

        async def wrapper(*args, **kwargs):
            self.inflight += 1
            self.total += 1
            self.peak = max(self.peak, self.inflight)
            self.peak_tasks = max(self.peak_tasks, len(asyncio.all_tasks()))
            try:
                await asyncio.sleep(self.delay)
                return await attr(*args, **kwargs)
            finally:
                self.inflight -= 1

        return wrapper


def stress_config(domains=DOMAINS, origins: int = ORIGINS, **overrides) -> LoadBalancingConfig:
    cfg = make_config(origins, domains=[LbDomainConfig(domain=d, origins=[f"server{i}" for i in range(1, origins + 1)]) for d in domains], **overrides)
    return cfg


def origin_args(n: int = ORIGINS) -> str:
    return " ".join(f"203.0.113.{10 + i}" for i in range(1, n + 1))


def build(origins: int = ORIGINS, domains=DOMAINS, **overrides):
    inner = FakeCloudflare()
    metered = MeteredCloudflare(inner)
    env = Env(origins, cfg=stress_config(domains, origins, **overrides), cloudflare=metered)
    env.ports.dns_answers = ["104.16.0.1"]
    return env, metered, inner


async def test_1_many_domains_concurrently_bounded() -> None:
    env, metered, inner = build(api_concurrency=4, probe_concurrency=4)
    baseline_tasks = len(asyncio.all_tasks())
    started = time.process_time()
    results = await asyncio.gather(*(env.orch.genloadbalance(d, origin_args(), operator="stress", apply=True, confirmed=True) for d in DOMAINS))
    cpu = time.process_time() - started
    assert all(r.status == OpStatus.SUCCESS for r in results), [(r.domain, r.status, r.message) for r in results if r.status != OpStatus.SUCCESS][:3]
    assert (len(inner.monitors), len(inner.pools), len(inner.lbs)) == (len(DOMAINS), len(DOMAINS), len(DOMAINS)), "exactly one monitor, pool and LB per domain"
    assert metered.peak <= 4, f"Cloudflare API concurrency must stay bounded, peak {metered.peak}"
    per_domain = metered.total / len(DOMAINS)
    assert per_domain <= 45, f"API calls per domain must be bounded, got {per_domain:.1f}"
    assert metered.peak_tasks <= len(DOMAINS) * (ORIGINS + 6) + baseline_tasks, f"task fan-out must be bounded, peak {metered.peak_tasks}"
    assert len(asyncio.all_tasks()) == baseline_tasks, "no leaked background tasks after the operations finish"
    assert len(env.ctx.locks) == 0, "every per-domain lock is released"
    assert len(env.store.operations()) <= 60 and len(env.store._audit) <= 300
    assert cpu < 25.0, f"CPU time for {len(DOMAINS)} concurrent operations must stay modest, got {cpu:.1f}s"
    print(f"Test 1 ({len(DOMAINS)} domains x {ORIGINS} origins applied concurrently: peak API concurrency {metered.peak} <= 4, {per_domain:.1f} calls/domain, no leaked tasks or locks, cpu {cpu:.1f}s) PASSED")


async def test_2_polling_cycles_do_not_leak_or_spike() -> None:
    domains = DOMAINS[:12]
    env, metered, inner = build(domains=domains, api_concurrency=4)
    await asyncio.gather(*(env.orch.genloadbalance(d, origin_args(), operator="stress", apply=True, confirmed=True) for d in domains))
    env.ports.events.clear()
    for _ in range(5):
        env.ports.mono += 200
        await env.monitor.poll_once()
    calls_before = metered.total
    cycles = 30
    started = time.process_time()
    for _ in range(cycles):
        env.ports.mono += 200
        env.ports.clock += 200
        processed = await env.monitor.poll_once()
        assert processed == len(domains)
    cpu = time.process_time() - started
    per_cycle_calls = (metered.total - calls_before) / cycles
    tracemalloc.start()
    baseline_mem = tracemalloc.get_traced_memory()[0]
    for _ in range(30):
        env.ports.mono += 200
        env.ports.clock += 200
        await env.monitor.poll_once()
    grown = tracemalloc.get_traced_memory()[0] - baseline_mem
    tracemalloc.stop()
    assert per_cycle_calls <= len(domains) * 6, f"a polling cycle costs a handful of API calls per domain, got {per_cycle_calls:.0f}"
    assert metered.peak <= 4
    assert grown < 3_000_000, f"memory must not grow with polling cycles, grew {grown} bytes"
    assert cpu / cycles < 0.5, f"one polling cycle of {len(domains)} domains must not spike CPU, got {cpu / cycles:.3f}s"
    assert len(env.monitor._cache) <= max(64, env.cfg.max_domains * 2) and len(env.monitor._status_by_domain) == len(domains)
    assert len(env.monitor.incidents) == 0, "healthy polling opens no incidents"
    assert env.ports.events == [], "healthy polling publishes no notifications"
    print(f"Test 2 ({cycles} polling cycles over {len(domains)} domains: {per_cycle_calls:.0f} API calls/cycle, memory growth {grown // 1024} KiB, {cpu / cycles * 1000:.0f} ms CPU/cycle, no events) PASSED")


async def test_3_flapping_origins_are_deduplicated() -> None:
    env, metered, inner = build(api_concurrency=4)
    await asyncio.gather(*(env.orch.genloadbalance(d, origin_args(), operator="stress", apply=True, confirmed=True) for d in DOMAINS[:6]))
    env.ports.events.clear()
    start_counters = dict(env.metrics.snapshot()["counters"])
    rng = random.Random(7)
    addresses = [f"203.0.113.{10 + i}" for i in range(1, ORIGINS + 1)]
    flaps = 0
    state = set()
    cycles = 120
    for _ in range(cycles):
        env.ports.mono += 130
        want = set()
        for address in addresses:
            went_down = address in state and rng.random() >= 0.2
            fails = address not in state and rng.random() < 0.05
            if went_down or fails:
                want.add(address)
        want = want if len(want) < ORIGINS else set()
        flaps += len(want ^ state)
        state = want
        inner.unhealthy_addresses = set(want)
        await env.monitor.poll_once()
    snapshot = env.metrics.snapshot()["counters"]
    sent = snapshot["lb_notifications_sent"] - start_counters["lb_notifications_sent"]
    suppressed = snapshot["lb_notifications_suppressed"] - start_counters["lb_notifications_suppressed"]
    downs = sum(1 for e in env.ports.events if e.category.value == "LB_ORIGIN_DOWN" and not e.metadata.get("reminder"))
    recoveries = sum(1 for e in env.ports.events if e.category.value == "LB_ORIGIN_RECOVERED")
    assert sent == len(env.ports.events) and downs <= flaps * 6, "at most one DOWN alert per origin outage per domain (6 domains share each address)"
    assert suppressed > sent, "repeated polls of the same outage are suppressed far more often than they notify"
    assert recoveries <= downs + 6
    assert len(env.monitor.incidents) <= 6 * ORIGINS + 12, "open incidents are bounded by domains x origins"
    inner.unhealthy_addresses = set()
    for _ in range(3):
        env.ports.mono += 130
        await env.monitor.poll_once()
    assert len(env.monitor.incidents) == 0, "every incident closes once the origins recover"
    print(f"Test 3 ({flaps} origin flaps over {cycles} cycles -> {downs} DOWN + {recoveries} RECOVERED alerts, {suppressed} repeats suppressed, no stuck incidents) PASSED")


async def test_4_status_cache_is_bounded_for_arbitrary_domains() -> None:
    env, metered, inner = build()
    inner.zones = {"example.com": {"id": ZONE_ID, "name": "example.com"}}
    await env.orch.genloadbalance(DOMAINS[0], origin_args(), operator="stress", apply=True, confirmed=True)
    for i in range(400):
        env.ports.mono += 1
        status = await env.monitor.status(f"random{i}.other-zone.test", force=True, full=True)
        assert status.overall == "NOT_CONFIGURED"
    assert len(env.monitor._cache) <= 64 and len(env.monitor._status_by_domain) <= 2, "operator-supplied domains cannot grow the caches"
    assert len(env.monitor._last_full) <= 64 and len(env.monitor._drift_open) <= 64
    assert env.monitor.managed_domains() == [DOMAINS[0]] + [d for d in env.cfg.domains and [x.domain for x in env.cfg.domains] if d != DOMAINS[0]]
    print("Test 4 (400 arbitrary domain lookups -> caches stay bounded, unknown zones report NOT_CONFIGURED) PASSED")


async def test_5_no_remote_or_shell_execution() -> None:
    env, metered, inner = build()
    calls = {"n": 0}

    def tripwire(*args, **kwargs):
        calls["n"] += 1
        raise AssertionError("the load balancer orchestration must never execute shell or remote commands")

    async def async_tripwire(*args, **kwargs):
        tripwire()

    with mock.patch.object(asyncio, "create_subprocess_exec", async_tripwire), mock.patch.object(asyncio, "create_subprocess_shell", async_tripwire), \
            mock.patch.object(subprocess, "Popen", tripwire), mock.patch.object(subprocess, "run", tripwire), mock.patch.object(os, "system", tripwire):
        for domain in DOMAINS[:4]:
            result = await env.orch.genloadbalance(domain, origin_args(), operator="stress", apply=True, confirmed=True)
            assert result.status == OpStatus.SUCCESS
            await env.orch.dbgenbalance(domain, operator="stress")
            await env.orch.addloadbalance(domain, operator="stress")
            await env.monitor.status(domain, force=True, full=True)
        await env.monitor.poll_once()
    assert calls["n"] == 0
    print("Test 5 (apply, /addloadbalance, /dbgenbalance, status and polling execute zero shell/remote commands; remote orchestration is signed data, not execution) PASSED")


async def test_6_state_persistence_stays_small_and_fast() -> None:
    env, metered, inner = build()
    started = time.perf_counter()
    for i in range(100):
        domain = DOMAINS[i % len(DOMAINS)]
        await env.orch.genloadbalance(domain, origin_args(), operator="stress", apply=False)
    elapsed = time.perf_counter() - started
    assert len(env.store.operations()) == 60 and len(env.store._audit) <= 300, "operation journal and audit trail are rings"
    size = os.path.getsize(env.store.path)
    assert size < 2_000_000, f"state file must stay small, {size} bytes"
    assert elapsed / 100 < 0.5, f"a dry run costs {elapsed / 100 * 1000:.0f} ms"
    assert env.store.save_failures == 0
    print(f"Test 6 (100 dry runs -> bounded journal/audit rings, state file {size // 1024} KiB, {elapsed / 100 * 1000:.0f} ms per dry run) PASSED")


async def test_7_probe_concurrency_is_global() -> None:
    env, metered, inner = build(origins=16, domains=DOMAINS[:8], probe_concurrency=3)
    peak = {"now": 0, "max": 0}
    original = env.ports.tcp_probe

    async def counting(address, port, timeout):
        peak["now"] += 1
        peak["max"] = max(peak["max"], peak["now"])
        try:
            await asyncio.sleep(0.002)
            return await original(address, port, timeout)
        finally:
            peak["now"] -= 1

    env.ports.tcp_probe = counting
    plans = await asyncio.gather(*(env.orch.plan(d, origin_args(16), operator="stress") for d in DOMAINS[:8]))
    assert all(p.verdict == "READY" for p in plans)
    assert peak["max"] <= 3, f"origin probes are bounded globally, peak {peak['max']}"
    print(f"Test 7 (8 concurrent plans x 16 origins: peak simultaneous origin probes {peak['max']} <= probe_concurrency 3) PASSED")


async def main() -> None:
    for test in (
        test_1_many_domains_concurrently_bounded, test_2_polling_cycles_do_not_leak_or_spike, test_3_flapping_origins_are_deduplicated,
        test_4_status_cache_is_bounded_for_arbitrary_domains, test_5_no_remote_or_shell_execution, test_6_state_persistence_stays_small_and_fast,
        test_7_probe_concurrency_is_global,
    ):
        await test()
    print("\nALL LOAD BALANCER RESOURCE/STRESS TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
