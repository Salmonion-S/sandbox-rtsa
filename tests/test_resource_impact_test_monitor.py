import asyncio
import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import (
    ResourceImpactAlertsConfig, ResourceImpactBaselineConfig, ResourceImpactSamplingConfig,
    ResourceImpactTestConfig, ResourceImpactTriggerConfig,
)
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from modules.resource_impact_test import (
    _CLASS_LOW, _MAX_SECOND_BUCKETS, ResourceImpactTestMonitor,
)


def _make_monitor(**overrides) -> ResourceImpactTestMonitor:
    trigger_overrides = overrides.pop("trigger", {})
    sampling_overrides = overrides.pop("sampling", {})
    baseline_overrides = overrides.pop("baseline", {})
    alerts_overrides = overrides.pop("alerts", {})
    overrides.setdefault("enabled", True)
    cfg = ResourceImpactTestConfig(
        trigger=ResourceImpactTriggerConfig(**trigger_overrides),
        sampling=ResourceImpactSamplingConfig(**sampling_overrides),
        baseline=ResourceImpactBaselineConfig(**baseline_overrides),
        alerts=ResourceImpactAlertsConfig(**alerts_overrides),
        **overrides,
    )
    mon = ResourceImpactTestMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def _scan_event() -> BaseEvent:
    return BaseEvent(
        source_module="nginx_monitor", category=EventCategory.WEB_ATTACK_SCAN,
        severity=Severity.LOW, message="scan", raw="",
    )


def _fake_snapshot(**values):
    base = {
        "cpu_percent": 3.0, "rss_mb": 180.0, "tasks": 32, "subprocess_active": 2,
        "queue_depth": 4, "server_load1": 2.1, "mem_available_mb": 5000.0,
    }
    base.update(values)
    return base


async def test_1_disabled_zero_overhead() -> None:
    from main import _MODULE_CONFIG_ATTR
    assert _MODULE_CONFIG_ATTR.get("resource_impact_test") == "resource_impact_test", (
        "resource_impact_test must be registered in the module-config-attr gate so main.py's "
        "loader can skip instantiation entirely when disabled"
    )

    cfg = ResourceImpactTestConfig(enabled=False)
    assert hasattr(cfg, "enabled") and cfg.enabled is False, (
        "the exact same 'has .enabled and not .enabled -> skip' gate every other module uses "
        "must apply here -- so the module is never even instantiated when disabled"
    )

    mon, published = _make_monitor(enabled=False)
    bus = mon.bus
    subs_before = dict(bus._subscriptions)
    await mon.setup()
    assert bus._subscriptions == subs_before, "disabled module must not create any EventBus subscription"
    await mon.run()
    assert published == [], "disabled module must never publish any Discord traffic"
    assert mon._state == "IDLE"
    print("Test 1 (disabled: zero subscription, zero task, zero Discord traffic) PASSED")


async def test_2_baseline_calculation() -> None:
    mon, published = _make_monitor(baseline={"samples": 5, "max_age_seconds": 300.0})
    mon._snapshot = lambda: _fake_snapshot(cpu_percent=3.0, rss_mb=180.0, tasks=32)
    for _ in range(5):
        await mon._tick_idle(time.monotonic())
    baseline = mon._baseline
    assert baseline is not None
    assert baseline.cpu_percent == 3.0
    assert baseline.rss_mb == 180.0
    assert baseline.tasks == 32
    assert baseline.sample_count == 5
    assert baseline.stale is False
    print("Test 2 (baseline correctly calculated from stable metrics, median-based) PASSED")

    mon2, _ = _make_monitor(baseline={"samples": 3, "max_age_seconds": 0.01})
    mon2._snapshot = lambda: _fake_snapshot()
    await mon2._tick_idle(time.monotonic())
    await asyncio.sleep(0.05)
    mon2._recompute_baseline()
    assert mon2._baseline.stale is True, "a baseline older than max_age_seconds must be marked stale"
    print("Test 2b (an aged-out baseline is correctly marked stale) PASSED")


async def test_3_scan_trigger_starts_exactly_one_window() -> None:
    mon, published = _make_monitor(
        trigger={"min_events_per_second": 5.0, "activation_window_seconds": 1.0, "max_test_duration_seconds": 60.0},
    )
    mon._snapshot = lambda: _fake_snapshot()
    for _ in range(3):
        await mon._tick_idle(time.monotonic())

    for _ in range(20):
        await mon._on_trigger_event(_scan_event())
    await mon._tick_idle(time.monotonic())

    assert mon._state == "ACTIVE", f"expected ACTIVE after rate exceeds threshold, got {mon._state}"
    assert len([e for e in published if e.metadata.get("phase") == "START"]) == 1
    print("Test 3 (scan rate above threshold starts exactly one test window) PASSED")


async def test_4_duplicate_trigger_still_one_window() -> None:
    mon, published = _make_monitor(
        trigger={"min_events_per_second": 5.0, "activation_window_seconds": 1.0, "max_test_duration_seconds": 60.0},
    )
    mon._snapshot = lambda: _fake_snapshot()
    await mon._tick_idle(time.monotonic())

    for _ in range(5000):
        await mon._on_trigger_event(_scan_event())
    for _ in range(10):
        if mon._state == "IDLE":
            await mon._tick_idle(time.monotonic())
        elif mon._state == "ACTIVE":
            await mon._tick_active(time.monotonic())
        elif mon._state == "RECOVERY":
            await mon._tick_recovery(time.monotonic())

    starts = [e for e in published if e.metadata.get("phase") == "START"]
    assert len(starts) == 1, (
        f"thousands of matching trigger events within one burst must start exactly one test "
        f"window, not one per event, got {len(starts)}"
    )
    print("Test 4 (thousands of matching events during one burst -- still exactly one window) PASSED")


async def test_5_peak_captured() -> None:
    mon, published = _make_monitor(
        trigger={"min_events_per_second": 5.0, "activation_window_seconds": 1.0, "max_test_duration_seconds": 60.0},
    )
    values = iter([
        _fake_snapshot(cpu_percent=3.0, rss_mb=180.0, tasks=32),
        _fake_snapshot(cpu_percent=3.0, rss_mb=180.0, tasks=32),
        _fake_snapshot(cpu_percent=3.0, rss_mb=180.0, tasks=32),
    ])
    mon._snapshot = lambda: next(values, _fake_snapshot(cpu_percent=3.0, rss_mb=180.0, tasks=32))
    for _ in range(3):
        await mon._tick_idle(time.monotonic())

    for _ in range(20):
        await mon._on_trigger_event(_scan_event())
    mon._snapshot = lambda: _fake_snapshot(cpu_percent=9.0, rss_mb=190.0, tasks=36)
    await mon._tick_idle(time.monotonic())
    assert mon._state == "ACTIVE"

    mon._snapshot = lambda: _fake_snapshot(cpu_percent=25.0, rss_mb=210.0, tasks=40)
    for _ in range(20):
        await mon._on_trigger_event(_scan_event())
    await mon._tick_active(time.monotonic())

    mon._snapshot = lambda: _fake_snapshot(cpu_percent=12.0, rss_mb=200.0, tasks=38)
    for _ in range(20):
        await mon._on_trigger_event(_scan_event())
    await mon._tick_active(time.monotonic())

    assert mon._peak is not None
    assert mon._peak.cpu_percent == 25.0, f"peak CPU must be the max observed, got {mon._peak.cpu_percent}"
    assert mon._peak.rss_mb == 210.0, f"peak RSS must be the max observed, got {mon._peak.rss_mb}"
    assert mon._peak.tasks == 40, f"peak tasks must be the max observed, got {mon._peak.tasks}"
    print("Test 5 (peak tracker correctly captures the maximum resource values observed) PASSED")


async def test_6_recovery_detected_once() -> None:
    mon, published = _make_monitor(
        trigger={
            "min_events_per_second": 5.0, "activation_window_seconds": 1.0,
            "max_test_duration_seconds": 30.0, "recovery_quiet_seconds": 0.3,
        },
        sampling={"active_interval_seconds": 0.05, "recovery_interval_seconds": 0.05},
    )
    mon._snapshot = lambda: _fake_snapshot()
    for _ in range(3):
        await mon._tick_idle(time.monotonic())

    for _ in range(20):
        await mon._on_trigger_event(_scan_event())
    await mon._tick_idle(time.monotonic())
    assert mon._state == "ACTIVE"

    await asyncio.sleep(2.2)
    await mon._tick_active(time.monotonic())
    assert mon._state == "RECOVERY", f"expected RECOVERY once scan rate drops, got {mon._state}"

    for _ in range(30):
        await asyncio.sleep(0.05)
        await mon._tick_recovery(time.monotonic())
        if mon._state == "IDLE":
            break

    assert mon._state == "IDLE", "recovery must eventually complete and return to IDLE"
    recoveries = [e for e in published if e.metadata.get("phase") == "RECOVERY"]
    assert len(recoveries) == 1, f"expected exactly one RECOVERY alert, got {len(recoveries)}"
    assert len(mon.recent_summaries()) == 1
    print("Test 6 (recovery is detected exactly once, ending the window and returning to IDLE) PASSED")


async def test_7_discord_unavailable_no_unbounded_backlog() -> None:
    from config.manager import DiscordConfig, OutboundBackpressureConfig
    from discord_integration.webhook import DiscordWebhookDispatcher, _MAX_PENDING_QUEUE_SIZE

    class _UnavailableBot:
        def is_ready(self) -> bool:
            return False

    bus = EventBus()
    dispatcher = DiscordWebhookDispatcher(
        bus, DiscordConfig(outbound=OutboundBackpressureConfig(dedup_window_seconds=0.0)),
    )
    dispatcher._bot = _UnavailableBot()
    await bus.subscribe("discord_stub", dispatcher._on_event, categories=None)

    mon, _ = _make_monitor(
        trigger={"min_events_per_second": 5.0, "activation_window_seconds": 1.0, "max_test_duration_seconds": 1.0},
        alerts={"send_start": True, "send_peak": True, "send_recovery": True, "cooldown_seconds": 0.0},
    )
    mon.bus = bus
    mon.publish = lambda ev: bus.publish_nowait(ev)
    mon._snapshot = lambda: _fake_snapshot()

    for _ in range(3):
        await mon._tick_idle(time.monotonic())

    for cycle in range(5):
        for _ in range(20):
            await mon._on_trigger_event(_scan_event())
        await mon._tick_idle(time.monotonic())
        if mon._state == "ACTIVE":
            await mon._tick_active(time.monotonic())
        await asyncio.sleep(1.3)
        if mon._state == "ACTIVE":
            await mon._tick_active(time.monotonic())
        for _ in range(15):
            if mon._state == "RECOVERY":
                await mon._tick_recovery(time.monotonic())
            await asyncio.sleep(0.05)
        mon._cooldown_until = 0.0

    await asyncio.sleep(0.1)
    health = dispatcher.get_outbound_health()
    assert health["pending_queue_depth"] <= _MAX_PENDING_QUEUE_SIZE, (
        f"repeated resource-impact-test alert cycles with Discord unavailable must never exceed "
        f"the dispatcher's existing bounded queue: {health['pending_queue_depth']} > {_MAX_PENDING_QUEUE_SIZE}"
    )
    print(
        "Test 7 (Discord unavailable across many alert cycles -- pending queue stays within the "
        "existing bounded cap, no feature-specific unbounded backlog) PASSED"
    )


async def test_8_50k_events_bounded() -> None:
    mon, _ = _make_monitor(
        trigger={"min_events_per_second": 999999.0, "activation_window_seconds": 5.0},
    )
    for i in range(50_000):
        await mon._on_trigger_event(_scan_event())
    assert len(mon._second_buckets) <= _MAX_SECOND_BUCKETS, (
        f"50,000 trigger events must never grow the per-second bucket deque past its hard cap "
        f"of {_MAX_SECOND_BUCKETS}, got {len(mon._second_buckets)}"
    )
    print(
        f"Test 8 (50,000 trigger events -- per-second bucket deque stays bounded at "
        f"{len(mon._second_buckets)} <= {_MAX_SECOND_BUCKETS}) PASSED"
    )


async def test_9_attack_cardinality_no_unbounded_memory() -> None:
    mon, _ = _make_monitor(
        trigger={"min_events_per_second": 5.0, "activation_window_seconds": 1.0, "max_test_duration_seconds": 60.0},
    )
    mon._snapshot = lambda: _fake_snapshot()
    for _ in range(3):
        await mon._tick_idle(time.monotonic())
    for i in range(20):
        await mon._on_trigger_event(_scan_event())
    await mon._tick_idle(time.monotonic())
    assert mon._state == "ACTIVE"

    for i in range(10_000):
        ev = BaseEvent(
            source_module="nginx_monitor", category=EventCategory.WEB_ATTACK_SCAN, severity=Severity.LOW,
            message="scan", raw="",
            metadata={"source_ip": f"203.0.{i % 250}.{i % 250}", "path": f"/unique-path-{i}"},
        )
        await mon._on_trigger_event(ev)

    assert len(mon._second_buckets) <= _MAX_SECOND_BUCKETS
    assert len(mon._window["category_counts"]) <= len(mon._trigger_categories), (
        "category_counts must only ever have as many keys as configured trigger categories, "
        "regardless of attacker-controlled IP/path cardinality in event metadata"
    )
    print(
        "Test 9 (10,000 events with unique attacker-controlled IPs/paths in metadata -- no "
        "per-key structure grows, memory stays bounded) PASSED"
    )


async def test_10_critical_event_does_not_interfere() -> None:
    bus = EventBus()
    mon, _ = _make_monitor(
        trigger={"min_events_per_second": 5.0, "activation_window_seconds": 1.0, "max_test_duration_seconds": 60.0},
    )
    mon.bus = bus
    await mon.setup()

    received = []

    async def other_subscriber(event: BaseEvent) -> None:
        received.append(event)

    await bus.subscribe("other_consumer", other_subscriber, categories=None)

    mon._snapshot = lambda: _fake_snapshot()
    for _ in range(3):
        await mon._tick_idle(time.monotonic())
    for _ in range(20):
        await bus.publish(_scan_event())
    await mon._tick_idle(time.monotonic())
    assert mon._state == "ACTIVE"

    critical_before = bus.stats.get("critical_published", 0)
    critical_event = BaseEvent(
        source_module="remote_access_detector", category=EventCategory.BAN_BYPASS_DETECTED,
        severity=Severity.CRITICAL, message="critical during test window", raw="",
    )
    await bus.publish(critical_event)
    await asyncio.sleep(0.05)

    assert critical_event in received, (
        "a critical security event published during an active resource-impact-test window must "
        "still reach every other subscriber completely unaffected -- the module only ever "
        "subscribes read-only to its own trigger categories, never intercepting or filtering "
        "anything else"
    )
    assert bus.stats.get("critical_published", 0) == critical_before + 1

    await mon._tick_active(time.monotonic())
    window_critical_count = bus.stats.get("critical_published", 0) - mon._window["critical_at_start"]
    assert window_critical_count == 1, (
        f"the module may OBSERVE the critical-event count via the existing bus.stats counter "
        f"for its own summary, but must never consume/block the event itself; expected 1 "
        f"critical event counted within the window, got {window_critical_count}"
    )
    await mon.teardown()
    print(
        "Test 10 (a critical event during an active test window reaches all other subscribers "
        "unaffected; the module only observes the count, never interferes) PASSED"
    )


async def main() -> None:
    await test_1_disabled_zero_overhead()
    await test_2_baseline_calculation()
    await test_3_scan_trigger_starts_exactly_one_window()
    await test_4_duplicate_trigger_still_one_window()
    await test_5_peak_captured()
    await test_6_recovery_detected_once()
    await test_7_discord_unavailable_no_unbounded_backlog()
    await test_8_50k_events_bounded()
    await test_9_attack_cardinality_no_unbounded_memory()
    await test_10_critical_event_does_not_interfere()
    print("\nALL RESOURCE IMPACT TEST MONITOR REGRESSION TESTS PASSED")


assert _CLASS_LOW == "LOW_IMPACT"
asyncio.run(asyncio.wait_for(main(), timeout=60))
