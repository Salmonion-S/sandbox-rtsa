import asyncio
import os
import sys
from unittest import mock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, HealthMonitorConfig
from core.datatypes import EventCategory, HealthEvent, Severity
from core.event_bus import EventBus
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.health_monitor import (
    HealthMonitor, _SERVICE_STATUS_DOWN, _SERVICE_STATUS_NOT_INSTALLED, _SERVICE_STATUS_UP,
)


def _snapshot(services):
    return HealthEvent(
        source_module="health_monitor", category=EventCategory.HEALTH_STATUS,
        severity=Severity.INFO, message="", raw="",
        cpu_percent=10.0, mem_percent=10.0, disk_percent=10.0, services=services,
    )


async def main():
    bus = EventBus()
    hm = HealthMonitor(bus, HealthMonitorConfig())
    collected = []

    async def collector(event):
        collected.append(event)

    sub = await bus.subscribe("collector", collector, categories=None)

    hm._evaluate_service_health(_snapshot({"nginx": False}))
    await sub.queue.join()
    assert not any(e.severity == Severity.CRITICAL for e in collected), (
        "a single transient failed check must never fire a CRITICAL service-down alert -- "
        "this is exactly the reported false positive"
    )
    assert not any(e.severity == Severity.HIGH for e in collected), (
        "a single transient failed check must not even fire HIGH -- it is unconfirmed"
    )
    pending = [e for e in collected if e.severity == Severity.LOW]
    assert len(pending) == 1 and pending[0].metadata.get("consecutive_failures") == 1, (
        "the first failure should still be visible internally as LOW-severity telemetry "
        "for forensics/correlation, naturally below the Discord severity floor"
    )
    print("Test 1 (single transient failure never fires CRITICAL) PASSED")

    collected.clear()
    hm._evaluate_service_health(_snapshot({"nginx": True}))
    await sub.queue.join()
    assert not any("pulih" in e.message for e in collected), (
        "a failure that was never confirmed/alerted must not publish a RECOVERED event either -- "
        "nothing was ever announced as down"
    )
    print("Test 2 (recovery before confirmation is silent, no bogus RECOVERED) PASSED")

    collected.clear()
    for _ in range(4):
        hm._evaluate_service_health(_snapshot({"nginx": False}))
        await sub.queue.join()
    high_events = [e for e in collected if e.severity == Severity.HIGH]
    critical_events = [e for e in collected if e.severity == Severity.CRITICAL]
    assert len(high_events) == 1, f"HIGH must fire exactly once on confirmation, got {len(high_events)}"
    assert len(critical_events) == 1, f"CRITICAL must fire exactly once on escalation, got {len(critical_events)}"
    assert high_events[0].metadata.get("consecutive_failures") == 2
    assert critical_events[0].metadata.get("consecutive_failures") == 4
    print("Test 3 (persistent outage: HIGH then CRITICAL, each exactly once, no spam) PASSED")

    collected.clear()
    hm._evaluate_service_health(_snapshot({"nginx": True}))
    await sub.queue.join()
    recovered = [e for e in collected if "pulih" in e.message]
    assert len(recovered) == 1, "a real confirmed outage must publish exactly one RECOVERED event"
    assert recovered[0].metadata.get("first_failure_at") is not None
    assert recovered[0].metadata.get("recovered_at") is not None
    print("Test 5 (recovery after real outage publishes RECOVERED with evidence) PASSED")

    await bus.shutdown()

    bus2 = EventBus()
    hm_immediate = HealthMonitor(bus2, HealthMonitorConfig(service_down_confirm_checks=1))
    collected2 = []

    async def collector2(event):
        collected2.append(event)

    sub2 = await bus2.subscribe("collector2", collector2, categories=None)
    hm_immediate._evaluate_service_health(_snapshot({"nginx": False}))
    await sub2.queue.join()
    assert any(e.severity == Severity.HIGH for e in collected2), (
        "service_down_confirm_checks=1 must restore alert-on-first-failure for operators who want it"
    )
    await bus2.shutdown()
    print("Test 6 (service_down_confirm_checks=1 restores old immediate-alert behavior) PASSED")

    bus3 = EventBus()
    hm3 = HealthMonitor(bus3, HealthMonitorConfig())

    async def fake_unit_state_reloading(systemctl, unit):
        return ("loaded", "reloading")

    async def fake_port_open(ports):
        return True

    async def fake_http_ok(ports):
        return True

    hm3._systemctl_unit_state = fake_unit_state_reloading
    hm3._any_port_listening = fake_port_open
    hm3._local_http_reachable = fake_http_ok
    with mock.patch("modules.health_monitor.shutil.which", return_value="/usr/bin/systemctl"):
        status = await hm3._probe_service_status("nginx")
    assert status == _SERVICE_STATUS_UP, (
        f"a systemd state blip (e.g. mid-reload) with the port still listening must not be "
        f"classified as down, got {status}"
    )
    print("Test 7 (systemd blip + port still listening = UP, not down) PASSED")

    async def fake_unit_state_inactive(systemctl, unit):
        return ("loaded", "inactive")

    async def fake_port_closed(ports):
        return False

    async def fake_http_down(ports):
        return False

    hm3._systemctl_unit_state = fake_unit_state_inactive
    hm3._any_port_listening = fake_port_closed
    hm3._local_http_reachable = fake_http_down
    with mock.patch("modules.health_monitor.shutil.which", return_value="/usr/bin/systemctl"):
        status2 = await hm3._probe_service_status("nginx")
    assert status2 == _SERVICE_STATUS_DOWN, f"both signals failing must be down, got {status2}"
    print("Test 8 (systemd inactive + port closed = genuine DOWN) PASSED")

    async def fake_unit_state_active(systemctl, unit):
        return ("loaded", "active")

    hm3._systemctl_unit_state = fake_unit_state_active
    hm3._any_port_listening = fake_port_open
    hm3._local_http_reachable = fake_http_down
    with mock.patch("modules.health_monitor.shutil.which", return_value="/usr/bin/systemctl"):
        status3 = await hm3._probe_service_status("nginx")
    assert status3 == _SERVICE_STATUS_UP
    diagnosis = hm3._diagnose_service("nginx")
    assert "HTTP" in diagnosis and "application" in diagnosis, (
        f"systemd active + port open + HTTP failing must diagnose as an HTTP/application "
        f"issue, not a service outage: {diagnosis}"
    )
    print("Test 9 (systemd active + HTTP failing diagnoses as HTTP/app issue, stays UP) PASSED")
    await bus3.shutdown()

    bus4 = EventBus()
    hm4 = HealthMonitor(bus4, HealthMonitorConfig())

    async def fake_pm2_empty():
        return None

    hm4._pm2_active = fake_pm2_empty
    with mock.patch("modules.health_monitor.shutil.which", return_value="/usr/bin/pm2"):
        status_empty = await hm4._probe_service_status("pm2")
    assert status_empty == _SERVICE_STATUS_NOT_INSTALLED, (
        f"pm2 installed but with zero registered apps must be treated as unused "
        f"(NOT_INSTALLED), not alerted on: {status_empty}"
    )
    print("Test 10 (pm2 with zero registered apps = NOT_INSTALLED, not CRITICAL) PASSED")

    async def fake_pm2_down():
        return False

    hm4._pm2_active = fake_pm2_down
    with mock.patch("modules.health_monitor.shutil.which", return_value="/usr/bin/pm2"):
        status_down = await hm4._probe_service_status("pm2")
    assert status_down == _SERVICE_STATUS_DOWN, (
        f"pm2 with apps registered but none online is a genuine failure: {status_down}"
    )
    print("Test 11 (pm2 with apps registered but none online = genuine DOWN) PASSED")
    await bus4.shutdown()

    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    pending_event = HealthEvent(
        source_module="health_monitor", category=EventCategory.HEALTH_STATUS,
        severity=Severity.LOW, message="Service check gagal 1x: nginx", raw="",
        metadata={"service": "nginx", "consecutive_failures": 1},
    )
    await dispatcher._on_event(pending_event)
    assert len(dispatcher._pending_heap) == 0, (
        "an unconfirmed (LOW-severity) service-check-failed event must never reach Discord -- "
        "it is below the default MEDIUM severity floor and HEALTH_STATUS bypasses nothing"
    )
    print("Test 12 (unconfirmed LOW-severity telemetry never reaches Discord) PASSED")

    print("\nALL HEALTH MONITOR CONSECUTIVE-FAILURE TESTS PASSED")


asyncio.run(main())
