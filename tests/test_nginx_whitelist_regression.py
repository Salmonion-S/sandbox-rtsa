import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, NginxMonitorConfig
from core.datatypes import EventCategory, Severity, WebAttackEvent
from core.event_bus import EventBus
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.nginx_monitor import NginxMonitor, _LogSource

WHITELISTED_IP = "203.0.113.50"
ATTACKER_IP = "198.51.100.7"
SQLI_PATH = "/index.php?id=1 union select 1,2,3--"


async def main():
    bus = EventBus()
    mon = NginxMonitor(bus, NginxMonitorConfig(whitelisted_ips=[]))

    assert not mon._is_ip_whitelisted(WHITELISTED_IP), (
        "sanity check: this IP must start out NOT whitelisted"
    )
    mon.reload_config(NginxMonitorConfig(whitelisted_ips=[WHITELISTED_IP]))
    assert mon._is_ip_whitelisted(WHITELISTED_IP), (
        "after reload_config() with the IP newly added to whitelisted_ips, "
        "_is_ip_whitelisted() must return True WITHOUT a process restart -- "
        "this is exactly the /rtsareload bug"
    )
    mon.reload_config(NginxMonitorConfig(whitelisted_ips=[]))
    assert not mon._is_ip_whitelisted(WHITELISTED_IP), (
        "reload_config() must also be able to REMOVE a whitelist entry, not just add one"
    )
    print("Test 1 (reload_config rebuilds _whitelisted_networks from the new config) PASSED")

    mon2 = NginxMonitor(bus, NginxMonitorConfig(whitelisted_ips=[WHITELISTED_IP]))
    collected = []

    async def collector(event):
        collected.append(event)

    sub = await bus.subscribe("collector", collector, categories=None)
    source = _LogSource(log_file="/var/log/nginx/test-access.log", line_number=1, raw_line="raw")

    is_whitelisted = mon2._is_ip_whitelisted(WHITELISTED_IP)
    assert is_whitelisted
    await mon2._check_web_attack_signature(
        WHITELISTED_IP, SQLI_PATH, "GET", "sqlmap/1.0", 404, "example.com", source,
        is_whitelisted=is_whitelisted,
    )
    is_whitelisted_attacker = mon2._is_ip_whitelisted(ATTACKER_IP)
    assert not is_whitelisted_attacker
    await mon2._check_web_attack_signature(
        ATTACKER_IP, SQLI_PATH, "GET", "sqlmap/1.0", 404, "example.com", source,
        is_whitelisted=is_whitelisted_attacker,
    )
    await sub.queue.join()
    await bus.shutdown()

    sqli_events = [e for e in collected if e.category == EventCategory.WEB_ATTACK_SQLI]
    assert len(sqli_events) == 2, (
        f"BOTH the whitelisted and non-whitelisted attacker must produce a raw WEB_ATTACK_SQLI "
        f"event on the bus -- whitelisting must never make an attack invisible to the "
        f"detection/forensic pipeline: got {len(sqli_events)}"
    )
    whitelisted_event = next(e for e in sqli_events if e.source_ip == WHITELISTED_IP)
    attacker_event = next(e for e in sqli_events if e.source_ip == ATTACKER_IP)
    assert whitelisted_event.metadata.get("notify_discord") is False, (
        "the event from the whitelisted IP must be marked notify_discord=False -- "
        "detected+recorded, but Discord delivery suppressed"
    )
    assert attacker_event.metadata.get("classification") == "ATTEMPT", (
        "sanity check: a 404-status signature match with no verification evidence must "
        "classify as ATTEMPT -- this is what should be driving the suppression below, "
        "not whitelist status (the attacker IP is confirmed non-whitelisted above)"
    )
    assert attacker_event.metadata.get("notify_discord") is False, (
        "an ATTEMPT-tier signature match from a NON-whitelisted IP is now notify_discord=False "
        "by default (web_attack_attempt_outbound_enabled=False) -- a bare match is never "
        "outbound-worthy on its own. This is a deliberate behavior change from the original "
        "PRIORITAS 2/3/4 fix (written before outcome classification existed, when it expected "
        "notify_discord=True here); the whitelist forensic-visibility guarantee itself is "
        "untouched -- the event is still published to the bus with full detection metadata, "
        "only outbound delivery is gated."
    )
    print("Test 2 (malicious payload from whitelisted IP: still detected+recorded, only Discord suppressed) PASSED")

    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    await dispatcher._on_event(whitelisted_event)
    assert len(dispatcher._pending_heap) == 0, (
        "a notify_discord=False event must never reach the Discord send/queue path, "
        "regardless of its category or severity"
    )
    confirmed_attack_event = WebAttackEvent(
        source_module="nginx_monitor",
        category=EventCategory.WEB_ATTACK_SQLI,
        severity=Severity.HIGH,
        message="Web attack signature cocok dengan bukti sukses terverifikasi",
        raw="",
        source_ip=ATTACKER_IP, confidence=0.9,
        metadata={"notify_discord": True, "classification": "CONFIRMED_SUCCESS"},
    )
    await dispatcher._on_event(confirmed_attack_event)
    assert len(dispatcher._pending_heap) == 1, (
        "a normal (notify_discord=True) WEB_ATTACK_SQLI event must still be queued for delivery"
    )
    print("Test 3 (DiscordWebhookDispatcher actually suppresses notify_discord=False events) PASSED")

    recovered_event = WebAttackEvent(
        source_module="nginx_monitor",
        category=EventCategory.NGINX_ATTACK_RECOVERED,
        severity=Severity.INFO,
        message="Aktivitas serangan dari 198.51.100.7 sudah berhenti",
        raw="",
        source_ip=ATTACKER_IP, matched_signature="WEB_ATTACK_SQLI",
        metadata={"notify_discord": True},
    )
    payload = dispatcher._build_payload(recovered_event)
    fields = payload["embeds"][0].get("fields", [])
    confidence_fields = [f for f in fields if f["name"] == "Tingkat Keyakinan Deteksi"]
    assert not confidence_fields, (
        f"NGINX_ATTACK_RECOVERED must NOT show a Confidence field at all (no fabricated 0.00): "
        f"{confidence_fields}"
    )
    print("Test 4 (NGINX_ATTACK_RECOVERED omits the fake confidence=0.00 field entirely) PASSED")

    real_attack_event = WebAttackEvent(
        source_module="nginx_monitor",
        category=EventCategory.WEB_ATTACK_SQLI,
        severity=Severity.HIGH,
        message="Web attack signature cocok",
        raw="",
        source_ip=ATTACKER_IP, confidence=0.85,
        metadata={"notify_discord": True},
    )
    payload = dispatcher._build_payload(real_attack_event)
    fields = payload["embeds"][0].get("fields", [])
    confidence_fields = [f for f in fields if f["name"] == "Tingkat Keyakinan Deteksi"]
    assert len(confidence_fields) == 1 and confidence_fields[0]["value"] == "0.85", (
        f"a genuine WEB_ATTACK_SQLI detection with a real confidence must still render it: {confidence_fields}"
    )
    print("Test 5 (a genuine detection event with a real confidence still renders it -- no regression) PASSED")

    print("\nALL NGINX WHITELIST REGRESSION TESTS PASSED")


asyncio.run(main())
