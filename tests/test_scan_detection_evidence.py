import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import tempfile

from config.manager import ConfigManager, DiscordConfig, NginxMonitorConfig, OutboundBackpressureConfig, ScanBurstRecommendationConfig
from core.datatypes import EventCategory, NginxEvent, Severity, WebAttackEvent
from core.event_bus import EventBus
from discord_integration.webhook import _SEND_OK, DiscordWebhookDispatcher
from modules.nginx_monitor import NginxMonitor

DOMAIN = "simpangbabat.simpuskes.com"
LOG_FILE = "/var/log/nginx/simpangbabat.simpuskes.com.access.log"

_CONFIG_DIR = os.path.join(_REPO_ROOT, "config")
_SERVER1_PROFILE = os.path.join(_CONFIG_DIR, "discord-server1.yaml")
_SERVER2_PROFILE = os.path.join(_CONFIG_DIR, "discord-server2.yaml")


def make_monitor(**sb_overrides):
    defaults = dict(
        enabled=True, scan_window_seconds=60.0, scan_count_threshold=10,
        cooldown_seconds=1800.0, max_tracked_vhosts=500,
        minimum_unique_paths_for_enumeration=3, minimum_unique_ips_for_distributed=5,
        dominant_source_ratio=0.6, minimum_confidence_for_cloudflare_recommendation="HIGH",
    )
    defaults.update(sb_overrides)
    sb = ScanBurstRecommendationConfig(**defaults)
    cfg = NginxMonitorConfig(enabled=True, scan_burst_recommendation=sb)
    mon = NginxMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_cloudpanel_context(domain):
        return "", {"domain": domain or "unknown"}

    mon._cloudpanel_context = fake_cloudpanel_context
    return mon, published


def access_line(method, path, *, status=200, ip="203.0.113.7", ua="Mozilla/5.0", host=DOMAIN):
    return f'{ip} - - [01/Jan/2026:00:00:00 +0000] "{method} {path} HTTP/1.1" {status} 100 "-" "{ua}" "{host}"'


def scan_events(published):
    return [e for e in published if e.category == EventCategory.NGINX_RATE_ANOMALY]


async def main() -> None:
    line_no = {"n": 0}

    def nxt() -> int:
        line_no["n"] += 1
        return line_no["n"]

    mon, pub = make_monitor()
    for _ in range(10):
        await mon._process_access_line(
            access_line("GET", "/about-us", status=200), LOG_FILE, nxt(), domain=DOMAIN,
        )
    assert not scan_events(pub), f"10 benign requests must never produce a scan-rate alert: {scan_events(pub)}"
    print("Test 1 (10 benign requests never produce a NGINX_RATE_ANOMALY scan alert) PASSED")

    mon, pub = make_monitor()
    for _ in range(10):
        await mon._process_access_line(
            access_line("GET", "/.env", status=404, ip="203.0.113.20"), LOG_FILE, nxt(), domain=DOMAIN,
        )
    events = scan_events(pub)
    assert len(events) == 1
    assert events[0].metadata["confidence_label"] not in ("HIGH", "CRITICAL"), (
        f"10 signature-matching requests all against the SAME path must not automatically reach "
        f"HIGH: {events[0].metadata}"
    )
    print("Test 2 (broad signature match repeated against the same single path -- not automatically HIGH) PASSED")

    mon, pub = make_monitor(scan_count_threshold=5)
    lines = [
        access_line("GET", p, status=404, ip="203.0.113.30")
        for p in ("/.env", "/.git/config", "/wp-login.php", "/.aws/credentials")
    ]
    fixed_line_numbers = [nxt() for _ in lines]
    for _ in range(500):
        for line, ln in zip(lines, fixed_line_numbers):
            await mon._process_access_line(line, LOG_FILE, ln, domain=DOMAIN)
    state = mon._scan_burst_windows.get(DOMAIN)
    assert len(state.events) == 4, (
        f"2000 duplicate-processing attempts of only 4 distinct physical log lines must collapse "
        f"to exactly 4 tracked observations, got {len(state.events)}"
    )
    print("Test 3 (2000 duplicate-processing attempts of the same log lines -- dedup correct, no doubling) PASSED")

    mon, pub = make_monitor(scan_count_threshold=2000, minimum_unique_paths_for_enumeration=3)
    paths = ("/.env", "/.git/config", "/wp-login.php", "/.aws/credentials", "/phpmyadmin")
    for i in range(2000):
        await mon._process_access_line(
            access_line("GET", paths[i % len(paths)], status=404, ip="203.0.113.40"),
            LOG_FILE, nxt(), domain=DOMAIN,
        )
    events = scan_events(pub)
    assert len(events) == 1
    assert events[0].metadata["scan_count"] == 2000
    assert events[0].metadata["confidence_label"] in ("HIGH", "CRITICAL")
    print("Test 4 (2000 unique sequential scan requests from one source, real enumeration evidence -- reaches HIGH) PASSED")

    mon, pub = make_monitor(minimum_unique_ips_for_distributed=5, scan_count_threshold=15)
    paths = ("/.env", "/.git/config", "/wp-login.php")
    for i in range(15):
        await mon._process_access_line(
            access_line("GET", paths[i % len(paths)], status=404, ip=f"198.51.100.{i}"),
            LOG_FILE, nxt(), domain=DOMAIN,
        )
    events = scan_events(pub)
    assert len(events) == 1
    assert events[0].metadata["distributed_scanning"] is True
    assert events[0].metadata["sequential_enumeration"] is False
    assert events[0].metadata["unique_ips"] == 15
    print("Test 5 (distributed suspicious scanning across many sources -- classification matches distributed evidence) PASSED")

    mon, pub = make_monitor()
    for i in range(10):
        await mon._track_scan_burst(
            DOMAIN, True, ip="", path="/.env", method="GET", status=404, ua="",
            category="WEB_ATTACK_SCAN", log_file=LOG_FILE, line_number=nxt(),
        )
    events = scan_events(pub)
    assert len(events) == 1
    assert events[0].metadata["confidence_label"] == "LOW"
    assert events[0].metadata["cloudflare_action_recommended"] is False
    print("Test 6 (source IP unavailable -- N/A -- never immediately produces a HIGH Cloudflare recommendation) PASSED")

    mon, pub = make_monitor()
    for path in ("/.env", "/.git/config", "/wp-login.php", "/.aws/credentials", "/config.php.bak",
                 "/.env", "/.git/config", "/wp-login.php", "/.aws/credentials", "/config.php.bak"):
        await mon._process_access_line(
            access_line("GET", path, status=404, ip="203.0.113.99"), LOG_FILE, nxt(), domain=DOMAIN,
        )
    events = scan_events(pub)
    assert len(events) == 1
    assert events[0].metadata["confidence_label"] in ("HIGH", "CRITICAL")
    assert events[0].metadata["top_source_ip"] == "203.0.113.99"
    print("Test 7 (real source IP + strong sequential enumeration -- reaches HIGH) PASSED")

    mon, pub = make_monitor()
    for path in ("/.env", "/.git/config", "/wp-login.php") * 4:
        await mon._process_access_line(
            access_line("GET", path, status=404, ip="203.0.113.55"), LOG_FILE, nxt(), domain=DOMAIN,
        )
    events = scan_events(pub)
    assert len(events) == 1
    ev = events[0]
    assert ev.message.count("Rekomendasi") == 0, (
        f"the recommendation sentence must not be baked into the message body: {ev.message!r}"
    )
    assert isinstance(ev.metadata.get("recommendation"), str) and ev.metadata["recommendation"]
    print("Test 8 (Cloudflare/scan recommendation appears exactly once -- in metadata['recommendation'] only) PASSED")

    config = DiscordConfig(
        category_channels={"NGINX_RATE_ANOMALY": 1111111111111111111},
        alert_channel_id=999999999999999999,
        outbound=OutboundBackpressureConfig(dedup_window_seconds=0.0),
    )
    dispatcher = DiscordWebhookDispatcher(EventBus(), config)
    payload = dispatcher._build_payload(ev)
    embed = payload["embeds"][0]
    recommendation_fields = [f for f in embed["fields"] if f["name"] in ("Recommendation", "Rekomendasi")]
    assert len(recommendation_fields) == 1, (
        f"exactly one Recommendation field must be present in the Discord payload, "
        f"got {len(recommendation_fields)}: {recommendation_fields}"
    )
    assert "Rekomendasi" not in embed["description"], (
        f"the embed description (built from event.message) must not also bake in the recommendation "
        f"text shown separately in the Recommendation field: {embed['description']!r}"
    )
    field_names = [f["name"] for f in embed["fields"]]
    for logical_field in ("Domain", "Modul Sumber", "Kategori", "Tingkat Keparahan"):
        assert field_names.count(logical_field) <= 1, (
            f"field '{logical_field}' must appear at most once in the payload, "
            f"found {field_names.count(logical_field)} times: {field_names}"
        )
    print("Test 9 (Recommendation/Domain/Module-source/Category/Severity each appear at most once in the Discord payload) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                'discord:\n  enabled: false\n  channel_config_file: "{}"\n'.format(_SERVER2_PROFILE)
            )
        cm2 = ConfigManager(cfg_path)
    dispatcher2 = DiscordWebhookDispatcher(EventBus(), cm2.config.discord)
    captured = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        captured.append(channel_id)
        return _SEND_OK, channel_id, 1
    dispatcher2._send_via_bot = fake_send

    class _FakeBot:
        def is_ready(self):
            return True
    dispatcher2._bot = _FakeBot()

    normal_scan_event = WebAttackEvent(
        source_module="nginx_monitor", category=EventCategory.WEB_ATTACK_SCAN,
        severity=Severity.MEDIUM, message="scan signature match", raw="",
        source_ip="203.0.113.61", domain="server2-example.com",
        metadata={"domain": "server2-example.com", "request_count": 3},
    )
    await dispatcher2._on_event(normal_scan_event)
    assert captured and captured[-1] == 1527176072079081643, (
        f"a normal WEB_ATTACK_SCAN event on the real Server2 profile must route to Server2's "
        f"dedicated scan channel 1527176072079081643, got {captured}"
    )
    print("Test 10 (normal WEB_ATTACK_SCAN on the real Server2 profile -> 1527176072079081643) PASSED")

    captured.clear()
    cloudflare_scan_event = NginxEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY,
        severity=Severity.HIGH, message="Aktivitas scanning mencurigakan", raw="",
        domain="server2-example.com",
        metadata={
            "domain": "server2-example.com", "detector": "scan_burst_recommendation",
            "scan_count": 40, "scan_window_seconds": 60.0, "scan_count_threshold": 10,
            "confidence_label": "HIGH", "cloudflare_action_recommended": True,
            "recommendation": "Consider enabling Cloudflare Under Attack Mode manually.",
        },
    )
    await dispatcher2._on_event(cloudflare_scan_event)
    assert captured and captured[-1] == 1538602043349143612, (
        f"a HIGH-confidence Cloudflare-action scan-burst recommendation on the real Server2 "
        f"profile must route to 1538602043349143612, got {captured}"
    )
    print("Test 11 (high-confidence Cloudflare-action recommendation on the real Server2 profile -> 1538602043349143612) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(f'discord:\n  enabled: false\n  channel_config_file: "{_SERVER1_PROFILE}"\n')
        cm1 = ConfigManager(cfg_path)
    dispatcher1 = DiscordWebhookDispatcher(EventBus(), cm1.config.discord)
    captured1 = []
    dispatcher1._send_via_bot = fake_send
    dispatcher1._bot = _FakeBot()

    normal_scan_event_s1 = WebAttackEvent(
        source_module="nginx_monitor", category=EventCategory.WEB_ATTACK_SCAN,
        severity=Severity.MEDIUM, message="scan signature match", raw="",
        source_ip="203.0.113.62", domain="server1-example.com",
        metadata={"domain": "server1-example.com", "request_count": 3},
    )

    async def fake_send1(payload, event_id=None, category=None, source_module=None, channel_id=None):
        captured1.append(channel_id)
        return _SEND_OK, channel_id, 1
    dispatcher1._send_via_bot = fake_send1
    await dispatcher1._on_event(normal_scan_event_s1)
    assert captured1 and captured1[-1] == 1529424482383695972, (
        f"WEB_ATTACK_SCAN on the real Server1 profile must route to Server1's own shared "
        f"web-attack channel 1529424482383695972 (never Server2's dedicated scan channel), got {captured1}"
    )
    assert cm1.config.discord.cloudflare_scan_channel_id == 0
    print(
        "Test 12 (Server1 profile routing stays on Server1's own channels -- shared web-attack "
        "channel, no Cloudflare channel) PASSED"
    )

    print("\nALL SCAN-DETECTION EVIDENCE / FALSE-POSITIVE REGRESSION TESTS PASSED")


asyncio.run(main())
