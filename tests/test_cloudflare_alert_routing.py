import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, OutboundBackpressureConfig
from core.datatypes import BaseEvent, EventCategory, NginxEvent, Severity, WebAttackEvent
from core.event_bus import EventBus
from discord_integration.webhook import (
    _SEND_OK, _SEND_PERMANENT, _SEND_RETRYABLE, DiscordWebhookDispatcher,
)

CLOUDFLARE_CHANNEL = 1538602043349143612
DEFAULT_CHANNEL = 1529424988644442315
WEB_ATTACK_SCAN_CHANNEL = 1527176072079081643


class _FakeBot:
    def __init__(self, ready: bool = True) -> None:
        self._ready = ready

    def is_ready(self) -> bool:
        return self._ready


def _make_dispatcher(*, cloudflare_channel: int = CLOUDFLARE_CHANNEL, **outbound_overrides) -> DiscordWebhookDispatcher:
    outbound_kwargs = {"dedup_window_seconds": 0.0, "message_edit_ttl_seconds": 3600.0}
    outbound_kwargs.update(outbound_overrides)
    outbound = OutboundBackpressureConfig(**outbound_kwargs)
    config = DiscordConfig(
        cloudflare_scan_channel_id=cloudflare_channel,
        category_channels={"NGINX_RATE_ANOMALY": DEFAULT_CHANNEL, "WEB_ATTACK_SCAN": WEB_ATTACK_SCAN_CHANNEL},
        alert_channel_id=999999999999999999,
        outbound=outbound,
    )
    dispatcher = DiscordWebhookDispatcher(EventBus(), config)
    dispatcher._bot = _FakeBot()
    return dispatcher


def _scan_burst_event(domain: str = "victim.example.com", **extra_metadata) -> NginxEvent:
    return NginxEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY,
        severity=Severity.HIGH, message="Aktivitas scanning tinggi terdeteksi", raw="",
        domain=domain,
        metadata={
            "domain": domain, "detector": "scan_burst_recommendation",
            "scan_count": 2000, "scan_window_seconds": 60.0, "scan_count_threshold": 10,
            "recommendation": "Consider enabling Cloudflare Under Attack Mode manually.",
            "cloudflare_action_recommended": True,
            **extra_metadata,
        },
    )


def _scan_burst_low_confidence_event(domain: str = "lowconf.example.com", **extra_metadata) -> NginxEvent:
    return NginxEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY,
        severity=Severity.MEDIUM, message="Aktivitas scanning mencurigakan terdeteksi", raw="",
        domain=domain,
        metadata={
            "domain": domain, "detector": "scan_burst_recommendation",
            "scan_count": 15, "scan_window_seconds": 60.0, "scan_count_threshold": 10,
            "recommendation": (
                "Suspicious scanning activity detected. Review source IPs and request "
                "patterns before enabling Cloudflare Under Attack Mode."
            ),
            "cloudflare_action_recommended": False,
            **extra_metadata,
        },
    )


def _generic_rate_anomaly_event(ip: str = "203.0.113.9", domain: str = "other.example.com", **extra_metadata) -> NginxEvent:
    return NginxEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY,
        severity=Severity.MEDIUM, message="Response rate-limit/forbidden 429", raw="",
        source_ip=ip, domain=domain,
        metadata={"domain": domain, "check_count": 3, "incident_key": f"rate:{ip}", **extra_metadata},
    )


def _web_attack_scan_event(domain: str = "victim2.example.com", ip: str = "198.51.100.7") -> WebAttackEvent:
    return WebAttackEvent(
        source_module="nginx_monitor", category=EventCategory.WEB_ATTACK_SCAN,
        severity=Severity.HIGH, message="scan signature match", raw="",
        source_ip=ip, domain=domain, metadata={"domain": domain, "request_count": 50},
    )


async def main() -> None:
    dispatcher = _make_dispatcher()
    captured = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        captured.append(channel_id)
        return _SEND_OK, channel_id, 1
    dispatcher._send_via_bot = fake_send

    await dispatcher._on_event(_scan_burst_event(domain="cf1.example.com"))
    assert captured[-1] == CLOUDFLARE_CHANNEL, f"expected cloudflare channel, got {captured[-1]}"
    print("Test 1 (NGINX_RATE_ANOMALY + scan-burst signature classification -> Cloudflare destination only) PASSED")

    dispatcher = _make_dispatcher()
    captured = []
    dispatcher._send_via_bot = fake_send
    await dispatcher._on_event(_generic_rate_anomaly_event(domain="cf2.example.com"))
    assert captured[-1] == DEFAULT_CHANNEL, f"expected default channel for unclassified rate anomaly, got {captured[-1]}"
    print("Test 2 (NGINX_RATE_ANOMALY without attack classification -> stays default destination) PASSED")

    dispatcher = _make_dispatcher(aggregation_min_count=999999, dedup_window_seconds=30.0)
    sent_count = {"n": 0}

    async def counting_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        sent_count["n"] += 1
        return _SEND_OK, channel_id, 1
    dispatcher._send_via_bot = counting_send
    for _ in range(2000):
        await dispatcher._on_event(_scan_burst_event(domain="cf3.example.com"))
    assert sent_count["n"] == 1, f"2000 identical scan-burst events must collapse to 1 Discord send, got {sent_count['n']}"
    assert dispatcher._total_deduped == 1999, f"expected 1999 deduped events, got {dispatcher._total_deduped}"
    print("Test 3 (2000 repeated matching requests -> bounded to 1 Discord notification via dedup) PASSED")

    dispatcher = _make_dispatcher()
    captured = []
    dispatcher._send_via_bot = fake_send
    edited = []

    async def fake_edit(channel_id, message_id, payload, category=None):
        edited.append(channel_id)
        return _SEND_OK
    dispatcher._edit_via_bot = fake_edit

    await dispatcher._on_event(_scan_burst_event(domain="cf4.example.com"))
    assert captured[-1] == CLOUDFLARE_CHANNEL
    for state in dispatcher._outbound_identity_state.values():
        state.last_sent_monotonic -= 3600.0
    await dispatcher._on_event(_scan_burst_event(domain="cf4.example.com", scan_count=2500, is_reminder=True))
    assert edited and edited[-1] == CLOUDFLARE_CHANNEL, f"UPDATE/reminder must stay on the same Cloudflare channel, got {edited}"
    print("Test 4 (Initial NEW routed to Cloudflare -> UPDATE/REMINDER stays on Cloudflare via message edit) PASSED")

    from discord_integration.webhook import _is_cloudflare_scan_signal
    recovered_event = NginxEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_ATTACK_RECOVERED,
        severity=Severity.INFO, message="recovered", raw="",
        metadata={
            "domain": "cf4.example.com", "detector": "scan_burst_recommendation",
            "cloudflare_action_recommended": True,
        },
    )
    assert _is_cloudflare_scan_signal(recovered_event) is True, (
        "a RECOVERED event carrying the same originating classification metadata must resolve to the "
        "same Cloudflare destination as its NEW/UPDATE siblings"
    )
    print("Test 5 (RECOVERED event carrying the same classification resolves to the same Cloudflare destination) PASSED")

    dispatcher = _make_dispatcher()
    captured = []
    dispatcher._send_via_bot = fake_send
    dispatcher._edit_via_bot = fake_edit
    edited = []
    await dispatcher._on_event(_scan_burst_event(domain="cf6.example.com"))
    for state in dispatcher._outbound_identity_state.values():
        state.last_sent_monotonic -= 3600.0
    await dispatcher._on_event(_scan_burst_event(domain="cf6.example.com", scan_count=2200, is_reminder=True))
    assert all(c == CLOUDFLARE_CHANNEL for c in captured), captured
    assert all(c == CLOUDFLARE_CHANNEL for c in edited), edited
    print("Test 6 (reminder incident stays on Cloudflare channel, never appears on default channel) PASSED")

    dispatcher = _make_dispatcher(dedup_window_seconds=30.0)
    captured = []
    dispatcher._send_via_bot = fake_send
    await dispatcher._on_event(_scan_burst_event(domain="cf7.example.com"))
    await dispatcher._on_event(_scan_burst_event(domain="cf7.example.com"))
    assert len(captured) == 1, f"identical incident must not produce a duplicate send in either channel, got {len(captured)} sends"
    print("Test 7 (dedup: identical incident never produces a duplicate send in default or Cloudflare) PASSED")

    dispatcher = _make_dispatcher(dedup_window_seconds=30.0)
    captured = []
    dispatcher._send_via_bot = fake_send
    await dispatcher._on_event(_scan_burst_event(domain="cf8a.example.com"))
    await dispatcher._on_event(_scan_burst_event(domain="cf8b.example.com"))
    assert len(captured) == 2, f"a genuinely different incident identity must still be delivered, got {len(captured)} sends"
    assert all(c == CLOUDFLARE_CHANNEL for c in captured)
    print("Test 8 (different incident identity is still delivered, not swallowed by dedup) PASSED")

    dispatcher = _make_dispatcher()

    async def failing_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        return _SEND_RETRYABLE, None, None
    dispatcher._send_via_bot = failing_send
    await dispatcher._on_event(_scan_burst_event(domain="cf9.example.com"))
    health = dispatcher.get_outbound_health()
    assert health["failed_by_destination"].get("cloudflare", 0) == 1, health["failed_by_destination"]
    assert len(dispatcher._pending_heap) == 1, "a retryable Cloudflare-destined failure must still be queued for retry (bounded)"
    assert dispatcher._circuit_state in ("CLOSED", "OPEN", "HALF_OPEN")
    print("Test 9 (Cloudflare destination failure increments failed_by_destination metrics, bounded retry, no crash) PASSED")

    dispatcher_no_cf = _make_dispatcher(cloudflare_channel=0)
    captured = []
    dispatcher_no_cf._send_via_bot = fake_send
    await dispatcher_no_cf._on_event(_scan_burst_event(domain="cf10.example.com"))
    assert captured[-1] == DEFAULT_CHANNEL, (
        f"with cloudflare_scan_channel_id unset, routing must fall back to existing category_channels "
        f"behaviour exactly as before this feature existed, got {captured[-1]}"
    )
    captured = []
    await dispatcher_no_cf._on_event(_web_attack_scan_event())
    assert captured[-1] == WEB_ATTACK_SCAN_CHANNEL
    print("Test 10 (config without cloudflare_scan_channel_id is fully backward compatible with old routing) PASSED")

    dispatcher = _make_dispatcher()
    captured = []
    dispatcher._send_via_bot = fake_send
    for i in range(20):
        await dispatcher._on_event(_scan_burst_event(domain=f"metrics-domain-{i}.example.com"))
        await dispatcher._on_event(_generic_rate_anomaly_event(domain=f"metrics-generic-{i}.example.com", ip=f"10.0.0.{i}"))
    health = dispatcher.get_outbound_health()
    destination_labels = set(health["sent_by_destination"].keys())
    assert destination_labels <= {"default", "cloudflare"}, (
        f"destination metric labels must stay within the bounded {{default, cloudflare}} set, "
        f"never per-domain, got {destination_labels}"
    )
    assert len(destination_labels) <= 2
    print("Test 11 (destination metrics use a bounded label set, never high-cardinality per-domain labels) PASSED")

    print("Test 12 (existing Discord anti-spam suite regression) DEFERRED to full suite run -- see tests/test_outbound_antispam_20_scenarios.py, tests/test_w26_outbound_backpressure.py")
    print("Test 13 (existing Nginx tests regression) DEFERRED to full suite run -- see tests/test_nginx_*.py")

    from discord_integration.webhook import _is_cloudflare_scan_signal as classify
    new_event = _scan_burst_event(domain="cf14.example.com")
    recovered_event2 = NginxEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_ATTACK_RECOVERED,
        severity=Severity.INFO, message="recovered", raw="",
        metadata={
            "domain": "cf14.example.com", "detector": "scan_burst_recommendation",
            "cloudflare_action_recommended": True,
        },
    )
    assert classify(new_event) == classify(recovered_event2) is True, (
        "the destination classification must be identical (deterministic) between the NEW event and its "
        "RECOVERED sibling carrying the same originating classification metadata -- channel must never change"
    )
    print("Test 14 (incident routing persistence: channel classification identical between NEW and RECOVERED) PASSED")

    dispatcher = _make_dispatcher()
    captured = []
    dispatcher._send_via_bot = fake_send
    await dispatcher._on_event(_scan_burst_low_confidence_event(domain="lowconf1.example.com"))
    assert captured[-1] == DEFAULT_CHANNEL, (
        f"a scan-burst alert without cloudflare_action_recommended=True (e.g. raw count over "
        f"threshold but no sequential enumeration or distributed-scan evidence) must stay on the "
        f"default channel, never the Cloudflare channel, got {captured[-1]}"
    )
    print(
        "Test 15 (low/medium-confidence scan-burst alert -- request count alone -- stays on the "
        "default channel, not Cloudflare) PASSED"
    )

    print("\nALL CLOUDFLARE ALERT ROUTING TESTS PASSED")


asyncio.run(main())
