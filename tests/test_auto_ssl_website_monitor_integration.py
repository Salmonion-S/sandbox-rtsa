from __future__ import annotations

import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import WebsiteMonitorConfig
from core.datatypes import EventCategory
from core.event_bus import EventBus
from core.website_check import WebsiteCheckResult
import modules.website_monitor as website_monitor_module
from modules.website_monitor import WebsiteMonitor

DOMAIN = "shop.example.com"
OTHER = "other.example.com"


def _result(domain: str = DOMAIN, *, status_code=None, condition="ok") -> WebsiteCheckResult:
    return WebsiteCheckResult(
        domain=domain, scheme="https", condition=condition, status_code=status_code,
        status_text=f"HTTP {status_code}" if status_code else None, response_time_ms=100.0,
        provider="cloudflare" if condition == "cloudflare_down" else "origin",
    )


_526 = _result(status_code=526, condition="cloudflare_down")
_OK = _result(status_code=200)
_502 = _result(status_code=502, condition="http_down")

NOTE = {
    "method": "certbot", "issuer": "Let's Encrypt (R3)", "new_expiry": "2026-12-01 00:00 UTC (89d left)",
    "verification": "PASS (nginx active, origin TLS, certificate validity, domain coverage)",
    "duration_seconds": 42.0, "previous_failure": "SSL_INVALID (HTTP 526)", "incident_id": "x@1",
}


def make_monitor(bus: EventBus, **overrides) -> WebsiteMonitor:
    cfg = WebsiteMonitorConfig(
        enabled=True, incident_mode=True, down_confirmation_checks=2, recovery_confirmation_checks=2,
        transient_retry_enabled=False, **overrides,
    )
    return WebsiteMonitor(bus, cfg)


async def main() -> None:
    bus = EventBus()
    collected = []

    async def collector(event):
        collected.append(event)

    sub = await bus.subscribe("collector", collector, categories=None)

    def of(category):
        return [e for e in collected if e.category == category]

    wm = make_monitor(bus)
    await wm._evaluate(DOMAIN, _526)
    await wm._evaluate(DOMAIN, _526)
    await sub.queue.join()
    assert len(of(EventCategory.WEBSITE_DOWN)) == 1
    down = of(EventCategory.WEBSITE_DOWN)[0]
    assert down.metadata["first_detected_at"] and down.metadata["incident_key"] and down.metadata["down_confirmation_checks"] == 2
    wm.register_recovery_note(DOMAIN, NOTE)
    await wm._evaluate(DOMAIN, _OK)
    await sub.queue.join()
    assert of(EventCategory.WEBSITE_RECOVERED) == [], "one healthy probe must not confirm recovery"
    await wm._evaluate(DOMAIN, _OK)
    await sub.queue.join()
    recovered = of(EventCategory.WEBSITE_RECOVERED)
    assert len(recovered) == 1, "exactly one WEBSITE_RECOVERED from the existing lifecycle"
    text = recovered[0].message
    for expected in (
        f"Auto SSL Repair ({DOMAIN}):", "Previous Failure: SSL_INVALID (HTTP 526)", "Repair Method: certbot",
        "Certificate Issuer: Let's Encrypt (R3)", "New Expiry: 2026-12-01 00:00 UTC (89d left)",
        "Verification: PASS", "Repair Duration: 42",
    ):
        assert expected in text, f"missing {expected!r} in:\n{text}"
    assert recovered[0].metadata["auto_ssl_repair"][DOMAIN]["method"] == "certbot"
    assert wm._recovery_notes == {}, "a consumed note must not linger"
    print("Test 1 (repair note rides on the existing WEBSITE_RECOVERED after the normal recovery confirmation) PASSED")

    collected.clear()
    wm = make_monitor(bus)
    await wm._evaluate(DOMAIN, _526)
    await wm._evaluate(DOMAIN, _526)
    await wm._evaluate(DOMAIN, _OK)
    await wm._evaluate(DOMAIN, _OK)
    await sub.queue.join()
    recovered = of(EventCategory.WEBSITE_RECOVERED)
    assert len(recovered) == 1 and "Auto SSL Repair" not in recovered[0].message
    assert "auto_ssl_repair" not in recovered[0].metadata
    print("Test 2 (recovery without a repair note is byte-for-byte the normal recovery notification) PASSED")

    collected.clear()
    wm = make_monitor(bus)
    wm._session = object()
    await wm._evaluate(DOMAIN, _526)
    await wm._evaluate(DOMAIN, _526)
    await sub.queue.join()
    collected.clear()
    probes = [_OK, _OK, _OK]
    calls = []

    async def fake_check(session, domain, **kwargs):
        calls.append(domain)
        return probes[min(len(calls) - 1, len(probes) - 1)]

    original = website_monitor_module.check_website
    website_monitor_module.check_website = fake_check
    try:
        wm.register_recovery_note(DOMAIN, NOTE)
        outcome = await wm.recheck_domain(DOMAIN, interval_seconds=0.0)
    finally:
        website_monitor_module.check_website = original
    await sub.queue.join()
    assert outcome.healthy is True and outcome.last_probe_ok is True
    assert len(calls) == 2, f"recheck stops as soon as recovery is confirmed (recovery_confirmation_checks=2), got {len(calls)}"
    recovered = of(EventCategory.WEBSITE_RECOVERED)
    assert len(recovered) == 1 and "Auto SSL Repair" in recovered[0].message
    assert wm._states[DOMAIN].last_status == "up"
    print("Test 3 (recheck_domain feeds real probes into _evaluate; lifecycle emits WEBSITE_RECOVERED; stops early) PASSED")

    collected.clear()
    wm = make_monitor(bus)
    wm._session = object()
    await wm._evaluate(DOMAIN, _526)
    await wm._evaluate(DOMAIN, _526)
    await sub.queue.join()
    collected.clear()
    calls.clear()
    probes = [_502]
    website_monitor_module.check_website = fake_check
    try:
        outcome = await wm.recheck_domain(DOMAIN, interval_seconds=0.0)
    finally:
        website_monitor_module.check_website = original
    await sub.queue.join()
    assert outcome.healthy is False and outcome.last_probe_ok is False and outcome.status_code == 502
    assert len(calls) == wm.config.recovery_confirmation_checks + 2, "recheck is bounded, never an open-ended loop"
    assert of(EventCategory.WEBSITE_RECOVERED) == [], "a still-down site must never be reported recovered"
    reclassified = of(EventCategory.WEBSITE_DOWN)
    assert len(reclassified) == 1 and reclassified[0].metadata["root_cause"] != "SSL_INVALID", (
        "the only WEBSITE_DOWN a re-check may produce is the EXISTING reclassification gate announcing that "
        "the outage now has a different (confirmed) root cause -- never a duplicate SSL alert"
    )
    assert wm._states[DOMAIN].last_status == "down"
    print("Test 4 (still down -> bounded probes, healthy=False, no false recovery) PASSED")

    collected.clear()
    wm = make_monitor(bus)
    wm._session = object()
    await wm._evaluate(DOMAIN, _526)
    await wm._evaluate(DOMAIN, _526)
    await sub.queue.join()
    collected.clear()
    calls.clear()
    probes = [_OK, _502, _OK, _OK, _OK]
    website_monitor_module.check_website = fake_check
    try:
        outcome = await wm.recheck_domain(DOMAIN, interval_seconds=0.0)
    finally:
        website_monitor_module.check_website = original
    await sub.queue.join()
    assert outcome.healthy is True and len(calls) == 4, calls
    assert len(of(EventCategory.WEBSITE_RECOVERED)) == 1
    print("Test 5 (flapping probes reset the recovery counter; recovery only after consecutive healthy probes) PASSED")

    wm = make_monitor(bus)
    wm._session = object()
    wm._rechecking.add(DOMAIN)
    blocked = await wm.recheck_domain(DOMAIN, interval_seconds=0.0)
    assert blocked.healthy is False and blocked.condition == "recheck_unavailable"
    wm._rechecking.clear()
    wm._session = None
    assert (await wm.recheck_domain(DOMAIN)).condition == "recheck_unavailable"
    print("Test 6 (concurrent recheck of the same domain / no session -> refused, never double-probed) PASSED")

    wm = make_monitor(bus)
    for index in range(website_monitor_module._MAX_RECOVERY_NOTES + 25):
        wm.register_recovery_note(f"d{index}.example.com", {"method": "certbot"})
    assert len(wm._recovery_notes) <= website_monitor_module._MAX_RECOVERY_NOTES
    wm.register_recovery_note(DOMAIN, NOTE)
    wm.register_recovery_note(DOMAIN, None)
    assert DOMAIN not in wm._recovery_notes
    wm.register_recovery_note(OTHER, NOTE)
    stamp, note = wm._recovery_notes[OTHER]
    wm._recovery_notes[OTHER] = (stamp - website_monitor_module._RECOVERY_NOTE_TTL_SECONDS - 5, note)
    assert wm._consume_recovery_notes([OTHER]) == [], "a stale note must never be attached to a later, unrelated recovery"
    print("Test 7 (recovery notes are bounded, clearable and expire) PASSED")

    collected.clear()
    wm = make_monitor(bus)
    wm.register_recovery_note(OTHER, NOTE)
    await wm._evaluate(DOMAIN, _526)
    await wm._evaluate(DOMAIN, _526)
    await wm._evaluate(DOMAIN, _OK)
    await wm._evaluate(DOMAIN, _OK)
    await sub.queue.join()
    recovered = of(EventCategory.WEBSITE_RECOVERED)
    assert len(recovered) == 1 and "Auto SSL Repair" not in recovered[0].message
    assert OTHER in wm._recovery_notes
    print("Test 8 (a note for another domain is neither consumed nor shown) PASSED")

    wm = make_monitor(bus)
    await wm._evaluate(DOMAIN, _526)
    ctx = wm.get_diagnostic_context(DOMAIN)
    assert ctx["last_result"] is _526 and ctx["conf_directory"] == wm.config.conf_directory
    assert ctx["pm2_state"] in ("UNKNOWN", "CONFIRMED_UP", "CONFIRMED_DOWN")
    print("Test 9 (diagnostic context reuses the monitor's own last probe / PM2 / nginx observations) PASSED")

    await bus.unsubscribe("collector")
    print("\nALL AUTO SSL x WEBSITE MONITOR INTEGRATION TESTS PASSED")


asyncio.run(main())
