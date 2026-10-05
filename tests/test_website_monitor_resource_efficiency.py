import asyncio
import inspect
import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import modules.website_monitor as website_monitor_module
from config.manager import WebsiteMonitorConfig
from core.cloudpanel_resolver import CloudPanelAsset
from core.datatypes import EventCategory, HealthEvent, Severity
from core.event_bus import EventBus
from core.self_health import DEGRADED, EMERGENCY, NORMAL, OVERLOADED, get_self_health_monitor
from core.website_check import WebsiteCheckResult
from modules.website_monitor import WebsiteMonitor


def _ok_result(domain: str) -> WebsiteCheckResult:
    return WebsiteCheckResult(domain=domain, scheme="https", condition="ok", status_code=200, provider="origin")


def _down_result(domain: str) -> WebsiteCheckResult:
    return WebsiteCheckResult(domain=domain, scheme="https", condition="timeout", provider="network")


def _make_monitor(**overrides) -> WebsiteMonitor:
    cfg = WebsiteMonitorConfig(enabled=True, incident_mode=True, **overrides)
    return WebsiteMonitor(EventBus(), cfg)


def _set_domains(wm: WebsiteMonitor, domains) -> None:
    wm._domains = list(domains)
    wm._last_discovery_monotonic = time.monotonic()


def _reset_self_health() -> None:
    monitor = get_self_health_monitor()
    monitor._state = NORMAL
    monitor._external_metrics.clear()


async def test_a_enabled_monitoring_runs() -> None:
    wm = _make_monitor(down_confirmation_checks=1)
    _set_domains(wm, ["a.example.com"])

    async def fake_check(session, domain, *, timeout_seconds, follow_redirects):
        return _ok_result(domain)

    original = website_monitor_module.check_website
    website_monitor_module.check_website = fake_check
    try:
        await wm._poll_once()
    finally:
        website_monitor_module.check_website = original
    assert wm._checks_completed_total == 1
    print("Test A (Website Monitor enabled -- monitoring runs, check completes) PASSED")


async def test_b_bounded_concurrency_100_domains() -> None:
    _reset_self_health()
    wm = _make_monitor(max_concurrent_checks=8, down_confirmation_checks=1)
    _set_domains(wm, [f"domain{i}.example.com" for i in range(100)])

    active = 0
    peak = 0

    async def fake_check(session, domain, *, timeout_seconds, follow_redirects):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return _ok_result(domain)

    original = website_monitor_module.check_website
    website_monitor_module.check_website = fake_check
    try:
        await wm._poll_once()
    finally:
        website_monitor_module.check_website = original

    assert peak <= 8, f"concurrency must never exceed max_concurrent_checks=8, observed peak={peak}"
    assert wm._checks_completed_total == 100
    print(f"Test B (100 domains, max_concurrent_checks=8 -- peak concurrency={peak}, bounded) PASSED")


async def test_c_only_one_active_cycle() -> None:
    _reset_self_health()
    wm = _make_monitor(max_concurrent_checks=4, down_confirmation_checks=1)
    _set_domains(wm, [f"slow{i}.example.com" for i in range(10)])

    release_event = asyncio.Event()

    async def slow_check(session, domain, *, timeout_seconds, follow_redirects):
        await release_event.wait()
        return _ok_result(domain)

    original = website_monitor_module.check_website
    website_monitor_module.check_website = slow_check
    try:
        cycle1 = asyncio.create_task(wm._poll_once())
        await asyncio.sleep(0.05)
        assert wm._scan_in_progress is True

        await wm._poll_once()
        assert wm._checks_skipped_overlap_total == 1, (
            "a second _poll_once() call while the first is in flight must be skipped, not run twice"
        )
        assert wm._checks_completed_total == 0, "the skipped cycle must not perform any checks"

        release_event.set()
        await cycle1
    finally:
        website_monitor_module.check_website = original

    assert wm._checks_completed_total == 10
    print("Test C (a second poll trigger while a cycle is active is skipped -- only one active cycle) PASSED")


async def test_d_slow_website_no_overlapping_cycles() -> None:
    _reset_self_health()
    wm = _make_monitor(max_concurrent_checks=2, down_confirmation_checks=1)
    _set_domains(wm, ["slow.example.com"])

    call_count = 0

    async def slow_check(session, domain, *, timeout_seconds, follow_redirects):
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.05)
        return _ok_result(domain)

    original = website_monitor_module.check_website
    website_monitor_module.check_website = slow_check
    try:
        cycle1 = asyncio.create_task(wm._poll_once())
        await asyncio.sleep(0.01)
        cycle2 = asyncio.create_task(wm._poll_once())
        cycle3 = asyncio.create_task(wm._poll_once())
        await asyncio.gather(cycle1, cycle2, cycle3)
    finally:
        website_monitor_module.check_website = original

    assert call_count == 1, f"only the first cycle must actually run a check, got {call_count} calls"
    assert wm._checks_skipped_overlap_total == 2
    print("Test D (slow website check -- concurrent poll attempts never create overlapping cycles) PASSED")


async def test_e_failed_website_confirmation_still_works() -> None:
    wm = _make_monitor(down_confirmation_checks=2, transient_retry_delay_seconds=0.0)
    _set_domains(wm, ["failing.example.com"])

    async def fake_check(session, domain, *, timeout_seconds, follow_redirects):
        return _down_result("failing.example.com")

    captured = []

    async def collector(event):
        captured.append(event)

    sub = await wm.bus.subscribe("e_collector", collector, categories=None)
    original = website_monitor_module.check_website
    website_monitor_module.check_website = fake_check
    try:
        await wm._poll_once()
        assert not any(e.category == EventCategory.WEBSITE_DOWN for e in captured), (
            "first failure must not confirm yet"
        )
        await wm._poll_once()
        await sub.queue.join()
    finally:
        website_monitor_module.check_website = original

    down_events = [e for e in captured if e.category == EventCategory.WEBSITE_DOWN]
    assert len(down_events) == 1
    await wm.bus.unsubscribe("e_collector")
    print("Test E (failed website -- confirmation still works via down_confirmation_checks) PASSED")


async def test_f_recovered_website_still_works() -> None:
    wm = _make_monitor(
        down_confirmation_checks=1, recovery_confirmation_checks=1, transient_retry_enabled=False,
    )
    _set_domains(wm, ["recovering.example.com"])

    outcomes = [_down_result("recovering.example.com"), _ok_result("recovering.example.com")]

    async def fake_check(session, domain, *, timeout_seconds, follow_redirects):
        return outcomes.pop(0)

    captured = []

    async def collector(event):
        captured.append(event)

    sub = await wm.bus.subscribe("f_collector", collector, categories=None)
    original = website_monitor_module.check_website
    website_monitor_module.check_website = fake_check
    try:
        await wm._poll_once()
        await wm._poll_once()
        await sub.queue.join()
    finally:
        website_monitor_module.check_website = original

    recovered = [e for e in captured if e.category == EventCategory.WEBSITE_RECOVERED]
    assert len(recovered) == 1
    await wm.bus.unsubscribe("f_collector")
    print("Test F (recovered website -- recovery detection still works) PASSED")


async def test_g_pm2_correlation_still_works() -> None:
    wm = _make_monitor(down_confirmation_checks=1)
    from core.datatypes import BaseEvent
    await wm._on_pm2_event(BaseEvent(
        source_module="pm2_monitor", category=EventCategory.SERVICE_DOWN, severity=Severity.HIGH,
        message="", raw="", metadata={"linux_user": "clp1", "process_name": "app"},
    ))
    assert wm._pm2_down_processes["clp1"] == {"app"}
    print("Test G (PM2 correlation -- SERVICE_DOWN still tracked) PASSED")


async def test_h_nginx_correlation_still_works() -> None:
    wm = _make_monitor(down_confirmation_checks=1)
    health_event = HealthEvent(
        source_module="health_monitor", category=EventCategory.HEALTH_STATUS,
        severity=Severity.INFO, message="", raw="", services={"nginx": False},
    )
    await wm._on_health_event(health_event)
    assert wm._nginx_locally_up is False
    print("Test H (NGINX local correlation -- health_monitor signal still tracked) PASSED")


async def test_i_one_incident_notification_not_per_check() -> None:
    wm = _make_monitor(down_confirmation_checks=1)
    domains = [f"sub{i}.proj1.example.com" for i in range(20)]
    _set_domains(wm, list(domains))

    shared_asset = CloudPanelAsset(
        domain="proj1.example.com", linux_user="proj1", project_root="/home/proj1",
        htdocs_path="/home/proj1/htdocs", nginx_vhost="proj1.conf", pm2_user="proj1",
        discovered_at=time.time(),
    )

    async def fake_resolve_domain(domain):
        return shared_asset

    captured = []

    async def collector(event):
        captured.append(event)

    sub = await wm.bus.subscribe("i_collector", collector, categories=None)
    original_resolve = website_monitor_module.cloudpanel_resolver.resolve_domain
    website_monitor_module.cloudpanel_resolver.resolve_domain = fake_resolve_domain
    try:
        for domain in domains:
            await wm._evaluate(domain, _down_result(domain))
        await sub.queue.join()
    finally:
        website_monitor_module.cloudpanel_resolver.resolve_domain = original_resolve

    down_events = [e for e in captured if e.category == EventCategory.WEBSITE_DOWN]
    assert len(down_events) == 1, (
        f"20 domains under the same project/root_cause must collapse into 1 incident notification, "
        f"got {len(down_events)}"
    )
    incident_key = wm._incident_key_for(domains[0], shared_asset, "NETWORK_TIMEOUT")
    incident = wm._incident_engine.get(incident_key)
    assert incident is not None
    assert len(incident.currently_active_resources) == 20, (
        "internal state must still track all 20 affected domains even though only 1 notification "
        "was ever sent"
    )
    await wm.bus.unsubscribe("i_collector")
    print("Test I (20 domains, same project + root cause -- exactly 1 Discord notification, not 20) PASSED")


async def test_j_reminders_still_work() -> None:
    wm = _make_monitor(
        down_confirmation_checks=1, reminder_enabled=True, reminder_interval_seconds=[0.01], maximum_reminders=2,
    )
    domain = "reminder.example.com"
    result = _down_result(domain)
    wm._states.setdefault(domain, website_monitor_module._WebsiteState())
    captured = []

    async def collector(event):
        captured.append(event)

    sub = await wm.bus.subscribe("j_collector", collector, categories=None)
    observation = wm._pm2_observation(None)
    root_cause = website_monitor_module.classify_root_cause(result, observation.down, None)
    wm._handle_incident_down(domain, result, None, "diagnosis", root_cause, observation, confirmed_check_count=1)
    await sub.queue.join()
    time.sleep(0.02)
    wm._handle_incident_down(domain, result, None, "diagnosis", root_cause, observation, confirmed_check_count=2)
    await sub.queue.join()

    down_events = [e for e in captured if e.category == EventCategory.WEBSITE_DOWN]
    assert len(down_events) == 2, f"expected initial + 1 reminder, got {len(down_events)}"
    assert down_events[1].metadata["is_reminder"] is True
    await wm.bus.unsubscribe("j_collector")
    print("Test J (reminders -- still fire per IncidentEngine reminder_interval_seconds policy) PASSED")


def test_k_website_monitor_never_spawns_main() -> None:
    source = inspect.getsource(website_monitor_module)
    forbidden = ["subprocess", "Popen", "os.exec", "os.fork", "multiprocessing", "main.py", "sys.executable"]
    for token in forbidden:
        assert token not in source, f"website_monitor.py must never spawn processes (found {token!r})"
    assert WebsiteMonitor.restart_policy == "always"
    print("Test K (website_monitor.py contains no process-spawn primitives; module-only restart) PASSED")


def test_l_effective_concurrency_tiers() -> None:
    wm = _make_monitor(
        max_concurrent_checks=8, degraded_max_concurrent_checks=3, critical_max_concurrent_checks=1,
    )
    monitor = get_self_health_monitor()
    try:
        monitor._state = NORMAL
        assert wm._effective_concurrency() == 8
        monitor._state = DEGRADED
        assert wm._effective_concurrency() == 3
        monitor._state = OVERLOADED
        assert wm._effective_concurrency() == 1
        monitor._state = EMERGENCY
        assert wm._effective_concurrency() == 1
    finally:
        monitor._state = NORMAL
    print("Test L (adaptive concurrency: NORMAL=8, DEGRADED=3, OVERLOADED/EMERGENCY=1) PASSED")


async def test_resource_benchmark() -> None:
    for n_domains in (100, 500, 1000):
        _reset_self_health()
        wm = _make_monitor(max_concurrent_checks=20, down_confirmation_checks=1)
        _set_domains(wm, [f"bench{i}.example.com" for i in range(n_domains)])

        async def fake_check(session, domain, *, timeout_seconds, follow_redirects):
            await asyncio.sleep(0.001)
            return _ok_result(domain)

        original = website_monitor_module.check_website
        website_monitor_module.check_website = fake_check
        tasks_before = len(asyncio.all_tasks())
        start = time.monotonic()
        try:
            await wm._poll_once()
        finally:
            website_monitor_module.check_website = original
        duration = time.monotonic() - start
        tasks_after = len(asyncio.all_tasks())

        assert wm._checks_completed_total == n_domains
        assert tasks_after - tasks_before <= 1, (
            f"no leaked asyncio tasks after a {n_domains}-domain cycle: before={tasks_before} after={tasks_after}"
        )
        print(
            f"Benchmark ({n_domains} domains): duration={duration:.2f}s tasks_leaked={tasks_after - tasks_before} "
            f"checks_completed={wm._checks_completed_total}"
        )
    print("Test (resource benchmark 100/500/1000 domains -- bounded, no task leakage) PASSED")


async def main() -> None:
    await test_a_enabled_monitoring_runs()
    await test_b_bounded_concurrency_100_domains()
    await test_c_only_one_active_cycle()
    await test_d_slow_website_no_overlapping_cycles()
    await test_e_failed_website_confirmation_still_works()
    await test_f_recovered_website_still_works()
    await test_g_pm2_correlation_still_works()
    await test_h_nginx_correlation_still_works()
    await test_i_one_incident_notification_not_per_check()
    await test_j_reminders_still_work()
    test_k_website_monitor_never_spawns_main()
    test_l_effective_concurrency_tiers()
    await test_resource_benchmark()
    print("\nALL WEBSITE MONITOR RESOURCE-EFFICIENCY TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
