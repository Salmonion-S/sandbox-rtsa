import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import WebsiteMonitorConfig
from core.datatypes import EventCategory, HealthEvent, Severity
from core.event_bus import EventBus
from core.website_check import WebsiteCheckResult
from modules.website_monitor import WebsiteMonitor, classify_root_cause


async def main():
    bus = EventBus()

    wm = WebsiteMonitor(bus, WebsiteMonitorConfig(enabled=True, incident_mode=True))
    collected = []

    async def collector(event):
        collected.append(event)

    sub = await bus.subscribe("collector", collector, categories=None)
    timeout_result = WebsiteCheckResult(
        domain="example.com", scheme="https", condition="timeout", provider="network",
    )
    await wm._evaluate("example.com", timeout_result)
    await sub.queue.join()
    down_events = [e for e in collected if e.category == EventCategory.WEBSITE_DOWN]
    assert len(down_events) == 0, f"a single transient timeout must not fire WEBSITE_DOWN: {down_events}"
    print("Test 1 (single transient timeout: no WEBSITE_DOWN) PASSED")

    ok_result = WebsiteCheckResult(
        domain="example.com", scheme="https", condition="ok", status_code=200, provider="origin",
    )
    await wm._evaluate("example.com", ok_result)
    await sub.queue.join()
    recovered_events = [e for e in collected if e.category == EventCategory.WEBSITE_RECOVERED]
    assert len(recovered_events) == 0, (
        f"a never-confirmed failure must not publish RECOVERED either: {recovered_events}"
    )
    print("Test 2 (recovery before confirmation: silent, no bogus RECOVERED) PASSED")

    collected.clear()
    await wm._evaluate("example.com", timeout_result)
    await wm._evaluate("example.com", timeout_result)
    await sub.queue.join()
    down_events2 = [e for e in collected if e.category == EventCategory.WEBSITE_DOWN]
    assert len(down_events2) == 1, f"2 consecutive failures must confirm and publish once: {down_events2}"
    assert down_events2[0].metadata["root_cause"] == "NETWORK_TIMEOUT"
    print("Test 3 (2 consecutive failures confirm WEBSITE_DOWN, root_cause=NETWORK_TIMEOUT) PASSED")

    wm_immediate = WebsiteMonitor(bus, WebsiteMonitorConfig(
        enabled=True, incident_mode=True, down_confirmation_checks=1,
    ))
    collected_immediate = []

    async def collector_immediate(event):
        collected_immediate.append(event)

    sub_immediate = await bus.subscribe("collector_immediate", collector_immediate, categories=None)
    await wm_immediate._evaluate("immediate.com", timeout_result)
    await sub_immediate.queue.join()
    assert any(e.category == EventCategory.WEBSITE_DOWN for e in collected_immediate), (
        "down_confirmation_checks=1 must restore alert-on-first-failure for operators who want it"
    )
    print("Test 4 (down_confirmation_checks=1 restores old immediate-alert behavior) PASSED")

    wm3 = WebsiteMonitor(bus, WebsiteMonitorConfig(enabled=True, incident_mode=True))
    collected3 = []

    async def collector3(event):
        collected3.append(event)

    sub3 = await bus.subscribe("collector3", collector3, categories=None)
    health_event = HealthEvent(
        source_module="health_monitor", category=EventCategory.HEALTH_STATUS,
        severity=Severity.INFO, message="", raw="", services={"nginx": True},
    )
    await wm3._on_health_event(health_event)
    assert wm3._nginx_locally_up is True
    refused_result = WebsiteCheckResult(
        domain="local-evidence.com", scheme="https", condition="connection_refused", provider="network",
    )
    await wm3._evaluate("local-evidence.com", refused_result)
    await wm3._evaluate("local-evidence.com", refused_result)
    await sub3.queue.join()
    down_events3 = [e for e in collected3 if e.category == EventCategory.WEBSITE_DOWN]
    assert len(down_events3) == 1
    assert down_events3[0].metadata["root_cause"] == "REMOTE_PROBE_FAILURE", down_events3[0].metadata["root_cause"]
    print("Test 5 (nginx locally UP + remote connection_refused -> REMOTE_PROBE_FAILURE) PASSED")

    wm4 = WebsiteMonitor(bus, WebsiteMonitorConfig(enabled=True, incident_mode=True))
    collected4 = []

    async def collector4(event):
        collected4.append(event)

    sub4 = await bus.subscribe("collector4", collector4, categories=None)
    await wm4._evaluate("no-local-evidence.com", refused_result)
    await wm4._evaluate("no-local-evidence.com", refused_result)
    await sub4.queue.join()
    down_events4 = [e for e in collected4 if e.category == EventCategory.WEBSITE_DOWN]
    assert len(down_events4) == 1
    assert down_events4[0].metadata["root_cause"] == "NGINX_DOWN", down_events4[0].metadata["root_cause"]
    print("Test 6 (no local evidence available -> falls back to NGINX_DOWN, never fabricated) PASSED")

    await bus.shutdown()

    dns_result = WebsiteCheckResult(domain="ghost.com", scheme="https", condition="dns_failure", provider="network")
    assert classify_root_cause(dns_result, None, None) == "DNS_FAILURE"
    private_result = WebsiteCheckResult(
        domain="rebind.com", scheme="https", condition="blocked_private_target", provider="network",
    )
    assert classify_root_cause(private_result, None, None) == "BLOCKED_PRIVATE_TARGET"
    tls_result = WebsiteCheckResult(domain="badcert.com", scheme="https", condition="tls_failure", provider="network")
    assert classify_root_cause(tls_result, None, None) == "SSL_INVALID"
    timeout_only = WebsiteCheckResult(domain="slow.com", scheme="https", condition="timeout", provider="network")
    assert classify_root_cause(timeout_only, None, None) == "NETWORK_TIMEOUT"
    assert classify_root_cause(timeout_only, None, True) != "SSL_INVALID", (
        "a bare timeout must never be labeled SSL_INVALID regardless of any other signal"
    )
    print("Test 7 (DNS_FAILURE/BLOCKED_PRIVATE_TARGET accurate; SSL_INVALID never applied to timeouts) PASSED")

    print("\nALL WEBSITE MONITOR CONFIRMATION/ROOT-CAUSE TESTS PASSED")


asyncio.run(main())
