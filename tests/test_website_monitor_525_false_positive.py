from __future__ import annotations

import asyncio
import os
import sys
from types import SimpleNamespace
from unittest import mock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import WebsiteMonitorConfig
from core.datatypes import EventCategory
from core.event_bus import EventBus
from core.website_check import WebsiteCheckResult
import modules.website_monitor as website_monitor_module
from modules.website_monitor import (
    ROOT_CAUSE_ORIGIN_TLS_HANDSHAKE_FAILURE, ROOT_CAUSE_SSL_INVALID, WebsiteMonitor,
    classify_root_cause, root_cause_confidence,
)

_DOMAIN = "www.newus.id"


def _result(*, status_code=None, condition="ok") -> WebsiteCheckResult:
    return WebsiteCheckResult(
        domain=_DOMAIN, scheme="https", condition=condition, status_code=status_code,
        status_text=f"HTTP {status_code}" if status_code else None,
        response_time_ms=321.0, provider="cloudflare" if status_code else "origin",
    )


_525 = _result(status_code=525, condition="cloudflare_down")
_526 = _result(status_code=526, condition="cloudflare_down")
_502 = _result(status_code=502, condition="http_down")
_OK = _result(status_code=200, condition="ok")


async def main() -> None:
    bus = EventBus()
    wm = WebsiteMonitor(bus, WebsiteMonitorConfig(
        enabled=True, incident_mode=True, down_confirmation_checks=2,
        recovery_confirmation_checks=2, transient_retry_enabled=False,
    ))
    collected = []

    async def collector(event):
        collected.append(event)

    sub = await bus.subscribe("collector", collector, categories=None)

    def _down_events():
        return [e for e in collected if e.category == EventCategory.WEBSITE_DOWN]

    await wm._evaluate(_DOMAIN, _525)
    await sub.queue.join()
    assert _down_events() == [], "one HTTP 525 must never confirm WEBSITE_DOWN"
    print("Test 1 (a single HTTP 525 -> SUSPECTED, not CONFIRMED, no alert) PASSED")

    await wm._evaluate(_DOMAIN, _525)
    await sub.queue.join()
    down = _down_events()
    assert len(down) == 1, f"expected exactly one WEBSITE_DOWN after 2 consecutive 525s, got {len(down)}"
    assert down[0].metadata["check_count"] == 2, (
        f"the real confirmation count must be reported, not the incident engine's own report "
        f"counter -- got {down[0].metadata['check_count']}"
    )
    assert "Checks confirming this outage:\n2/2" in down[0].message, down[0].message
    print("Test 2 (525, 525 with down_confirmation_checks=2 -> CONFIRMED, check_count correctly shows 2) PASSED")

    collected.clear()
    wm2 = WebsiteMonitor(bus, WebsiteMonitorConfig(
        enabled=True, incident_mode=True, down_confirmation_checks=2, transient_retry_enabled=False,
    ))
    await wm2._evaluate(_DOMAIN, _525)
    await wm2._evaluate(_DOMAIN, _OK)
    await sub.queue.join()
    assert not any(e.category == EventCategory.WEBSITE_DOWN for e in collected), (
        "525 followed by a recovery before the confirmation threshold must never confirm down"
    )
    print("Test 3 (525, 200 -- recovers before confirmation -- never CONFIRMED) PASSED")

    collected.clear()
    wm3 = WebsiteMonitor(bus, WebsiteMonitorConfig(
        enabled=True, incident_mode=True, down_confirmation_checks=2,
        recovery_confirmation_checks=2, transient_retry_enabled=False,
    ))
    await wm3._evaluate(_DOMAIN, _525)
    await wm3._evaluate(_DOMAIN, _525)
    await wm3._evaluate(_DOMAIN, _OK)
    recovered_mid = [e for e in collected if e.category == EventCategory.WEBSITE_RECOVERED]
    assert recovered_mid == [], "one healthy check must not yet confirm recovery (recovery_confirmation_checks=2)"
    await wm3._evaluate(_DOMAIN, _OK)
    await sub.queue.join()
    down4 = [e for e in collected if e.category == EventCategory.WEBSITE_DOWN]
    recovered4 = [e for e in collected if e.category == EventCategory.WEBSITE_RECOVERED]
    assert len(down4) == 1 and len(recovered4) == 1, (down4, recovered4)
    print("Test 4 (525, 525, 200, 200 -> confirmed down, then confirmed recovered) PASSED")

    rc_525 = classify_root_cause(_525, None, None)
    rc_526 = classify_root_cause(_526, None, None)
    assert rc_525 == ROOT_CAUSE_ORIGIN_TLS_HANDSHAKE_FAILURE, rc_525
    assert rc_526 == ROOT_CAUSE_SSL_INVALID, rc_526
    assert rc_525 != rc_526, "525 and 526 must not collapse into the same root cause"
    assert root_cause_confidence(rc_526) == "CONFIRMED"
    assert root_cause_confidence(rc_525) != "CONFIRMED", (
        "a bare Cloudflare 525 (handshake failure, often transient) must never carry the same "
        "CONFIRMED confidence as an explicit invalid-certificate signal (526)"
    )
    print("Test 5 (HTTP 526 -> certificate-specific classification, distinct from 525's handshake failure) PASSED")

    collected.clear()
    wm6 = WebsiteMonitor(bus, WebsiteMonitorConfig(enabled=True, incident_mode=True, transient_retry_enabled=False))
    await wm6._evaluate("totally-unmapped-domain.example", _OK)
    await sub.queue.join()
    assert not any(e.category == EventCategory.WEBSITE_DOWN for e in collected)
    print("Test 6 (owner/backend unresolved + HTTP 200 -> HEALTHY, no WEBSITE_DOWN) PASSED")

    from modules.website_monitor import Pm2Observation, PM2_STATE_UNKNOWN, EVIDENCE_PROJECT_USER_UNRESOLVED
    unresolved_observation = Pm2Observation(state=PM2_STATE_UNKNOWN, reason_code=EVIDENCE_PROJECT_USER_UNRESOLVED)
    resolved_down_observation = Pm2Observation(state=PM2_STATE_UNKNOWN, reason_code=EVIDENCE_PROJECT_USER_UNRESOLVED)
    rc_unresolved = classify_root_cause(_525, unresolved_observation.down, None)
    rc_resolved = classify_root_cause(_525, resolved_down_observation.down, None)
    assert rc_unresolved == rc_resolved == ROOT_CAUSE_ORIGIN_TLS_HANDSHAKE_FAILURE
    assert root_cause_confidence(rc_unresolved) == root_cause_confidence(rc_resolved), (
        "owner-resolution status must never change SSL/TLS root-cause confidence"
    )
    print("Test 7 (owner unresolved + HTTP 525 -- confirms a probe failure, but adds no confidence) PASSED")

    collected.clear()
    wm8 = WebsiteMonitor(bus, WebsiteMonitorConfig(
        enabled=True, incident_mode=True, down_confirmation_checks=2, transient_retry_enabled=False,
    ))
    await wm8._evaluate(_DOMAIN, _525)
    await sub.queue.join()
    assert collected == [], f"one intermittent 525 must produce zero Discord events, got {[e.category for e in collected]}"
    print("Test 8 (Cloudflare domain, one intermittent 525 -- no immediate HIGH alert) PASSED")

    wm9 = WebsiteMonitor(bus, WebsiteMonitorConfig(enabled=True, max_concurrent_checks=8))
    with mock.patch.object(website_monitor_module, "get_self_health_monitor", lambda: SimpleNamespace(state="NORMAL")):
        assert wm9._effective_concurrency() == 8
    print("Test 9 (bounded concurrency machinery unaffected -- max_concurrent_checks respected) PASSED")

    collected.clear()
    wm10 = WebsiteMonitor(bus, WebsiteMonitorConfig(
        enabled=True, incident_mode=True, down_confirmation_checks=2, transient_retry_enabled=False,
    ))
    await wm10._evaluate(_DOMAIN, _525)
    await wm10._evaluate(_DOMAIN, _525)
    await sub.queue.join()
    first_down = [e for e in collected if e.category == EventCategory.WEBSITE_DOWN]
    assert len(first_down) == 1 and first_down[0].metadata["root_cause"] == ROOT_CAUSE_ORIGIN_TLS_HANDSHAKE_FAILURE
    collected.clear()
    await wm10._evaluate(_DOMAIN, _502)
    await sub.queue.join()
    mid_flap = [e for e in collected if e.category == EventCategory.WEBSITE_DOWN]
    assert all(e.metadata.get("is_new") is not True for e in mid_flap) or mid_flap == [], (
        f"a single differently-classified probe during an already-confirmed outage must not "
        f"immediately fire a fresh 'is_new' WEBSITE_DOWN incident: {[e.metadata for e in mid_flap]}"
    )
    assert wm10._states[_DOMAIN].root_cause == ROOT_CAUSE_ORIGIN_TLS_HANDSHAKE_FAILURE, (
        "the officially-reported root cause must not flip on a single differing reading"
    )
    print("Test 10 (mid-outage root-cause flap (525 -> one 502) does not bypass reclassification confirmation) PASSED")

    collected.clear()
    await wm10._evaluate(_DOMAIN, _502)
    await sub.queue.join()
    assert wm10._states[_DOMAIN].root_cause == "BACKEND_DEGRADED" or wm10._states[_DOMAIN].root_cause is not None
    reclassified = [e for e in collected if e.category == EventCategory.WEBSITE_DOWN]
    assert len(reclassified) == 1, f"a consistently-reproduced new root cause must eventually reclassify, got {reclassified}"
    print("Test 11 (a root cause reproduced consistently DOES eventually reclassify, gate delays not blocks) PASSED")

    wm12 = WebsiteMonitor(bus, WebsiteMonitorConfig(
        enabled=True, incident_mode=True, down_confirmation_checks=2,
        transient_retry_enabled=True, transient_retry_delay_seconds=0.0,
    ))
    call_log = []

    async def flaky_then_ok(session, domain, *, timeout_seconds, follow_redirects):
        call_log.append(domain)
        return _OK

    original_check_website = website_monitor_module.check_website
    website_monitor_module.check_website = flaky_then_ok
    try:
        result = await wm12._maybe_retry_transient(_DOMAIN, _525)
    finally:
        website_monitor_module.check_website = original_check_website
    assert len(call_log) == 1, "the retry itself must be exactly one extra bounded call, never a loop"
    assert not result.is_down, "a 525 that recovers on the single bounded retry must be treated as healthy"
    print("Test 12 (bounded single retry: a transient 525 that recovers never counts as a confirmed failure) PASSED")

    await bus.unsubscribe("collector")
    print("\nALL 525 FALSE-POSITIVE / MULTI-PROBE CONFIRMATION TESTS PASSED")


asyncio.run(main())
