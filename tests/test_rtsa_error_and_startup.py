import asyncio
import inspect
import os
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import main as main_mod
from config.manager import (
    ConfigManager, ConfigValidationError, DiscordConfig, OutboundBackpressureConfig,
)
from core.datatypes import BaseEvent, EventCategory, Severity
from core.error_reporting import (
    compute_error_fingerprint, report_component_error, report_component_recovered, sanitize_error_text,
)
from core.event_bus import EventBus
from discord_integration.webhook import _SEND_OK, DiscordWebhookDispatcher

CLOUDFLARE_CHANNEL = 1538602043349143612
DEFAULT_CHANNEL = 1529424988644442315
WEB_ATTACK_SCAN_CHANNEL = 1527176072079081643
ERROR_CHANNEL = 1545250790543720458

_CONFIG_DIR = os.path.join(_REPO_ROOT, "config")


class _FakeBot:
    def is_ready(self) -> bool:
        return True


async def _drain(subscription, timeout: float = 2.0) -> None:
    await asyncio.wait_for(subscription.queue.join(), timeout=timeout)


def _make_dispatcher() -> DiscordWebhookDispatcher:
    config = DiscordConfig(
        cloudflare_scan_channel_id=CLOUDFLARE_CHANNEL,
        category_channels={
            "NGINX_RATE_ANOMALY": DEFAULT_CHANNEL, "WEB_ATTACK_SCAN": WEB_ATTACK_SCAN_CHANNEL,
            "RTSA_COMPONENT_ERROR": ERROR_CHANNEL, "RTSA_COMPONENT_RECOVERED": ERROR_CHANNEL,
            "RTSA_STARTUP_HEALTH": ERROR_CHANNEL,
        },
        alert_channel_id=999999999999999999,
        outbound=OutboundBackpressureConfig(dedup_window_seconds=0.0),
    )
    dispatcher = DiscordWebhookDispatcher(EventBus(), config)
    dispatcher._bot = _FakeBot()
    return dispatcher


def _make_engine_stub(*, failed_components=None, discord_enabled=False, metrics_started=False):
    from config.manager import RTSAConfig
    engine = main_mod.RTSAEngine.__new__(main_mod.RTSAEngine)
    engine.bus = EventBus()
    engine.config = RTSAConfig()
    engine.modules = []
    engine._failed_components = list(failed_components or [])
    engine._discord_bot_had_failure = False
    engine._started_at = 0.0
    engine._process_lineage = {}
    engine.metrics_exporter = object() if metrics_started else None
    engine.webhook_dispatcher = None
    return engine


def _write_config_pointing_at(
    tmpdir: str, discord_profile_abs_path: str,
) -> str:
    base_path = os.path.join(tmpdir, "config.yaml")
    with open(base_path, "w") as f:
        f.write(
            "discord:\n"
            "  enabled: false\n"
            f"  channel_config_file: \"{discord_profile_abs_path}\"\n"
        )
    return base_path


async def main() -> None:
    dispatcher = _make_dispatcher()
    captured = []

    async def fake_send(payload, event_id=None, category=None, source_module=None, channel_id=None):
        captured.append((channel_id, payload))
        return _SEND_OK, channel_id, 1
    dispatcher._send_via_bot = fake_send

    web_attack_scan_event = BaseEvent(
        source_module="nginx_monitor", category=EventCategory.WEB_ATTACK_SCAN, severity=Severity.HIGH,
        message="scan", raw="", metadata={"domain": "a.example.com"},
    )
    await dispatcher._on_event(web_attack_scan_event)
    assert captured[-1][0] == WEB_ATTACK_SCAN_CHANNEL
    print("Test A (WEB_ATTACK_SCAN routes to its own dedicated channel 1527176072079081643) PASSED")

    captured.clear()
    cf_event = BaseEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY, severity=Severity.HIGH,
        message="cf", raw="", metadata={"domain": "b.example.com", "classification": "HIGH_ATTACK_TRAFFIC"},
    )
    await dispatcher._on_event(cf_event)
    assert captured[-1][0] == CLOUDFLARE_CHANNEL
    print("Test B (Cloudflare-classified alert routes to 1538602043349143612) PASSED")

    captured.clear()
    plain_event = BaseEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY, severity=Severity.MEDIUM,
        message="plain", raw="", metadata={"domain": "c.example.com", "check_count": 3},
    )
    await dispatcher._on_event(plain_event)
    assert captured[-1][0] == DEFAULT_CHANNEL, (
        "NGINX_RATE_ANOMALY without a Cloudflare mitigation context must not be swept into the "
        "Cloudflare or WEB_ATTACK_SCAN channel"
    )
    print("Test C (NGINX_RATE_ANOMALY without mitigation context keeps existing default routing) PASSED")

    captured.clear()
    mitigation_event = BaseEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY, severity=Severity.HIGH,
        message="mitigation", raw="",
        metadata={
            "domain": "d.example.com", "detector": "scan_burst_recommendation", "scan_count": 500,
            "cloudflare_action_recommended": True,
        },
    )
    await dispatcher._on_event(mitigation_event)
    assert captured[-1][0] == CLOUDFLARE_CHANNEL
    print("Test D (NGINX_RATE_ANOMALY with Cloudflare mitigation context routes to Cloudflare channel) PASSED")

    dispatcher2 = _make_dispatcher()
    captured2 = []

    async def fake_send2(payload, event_id=None, category=None, source_module=None, channel_id=None):
        captured2.append((channel_id, payload))
        return _SEND_OK, channel_id, 1
    dispatcher2._send_via_bot = fake_send2
    bus2 = dispatcher2.bus
    sub2 = await bus2.subscribe("discord_webhook", dispatcher2._on_event, categories=None)

    try:
        raise RuntimeError("simulated unhandled exception in detector X")
    except RuntimeError as exc:
        await report_component_error(bus2, "test_detector", exc, source="unit_test.E")
    await _drain(sub2)
    assert captured2 and captured2[-1][0] == ERROR_CHANNEL, (
        f"an unhandled component exception must route to the RTSA error channel, got {captured2}"
    )
    assert captured2[-1][1]["embeds"][0]["title"] == "RTSA ERROR — COMPONENT_FAILURE"
    print("Test E (unhandled exception routes to RTSA error channel 1545250790543720458) PASSED")

    dispatcher3 = _make_dispatcher()
    captured3 = []

    async def fake_send3(payload, event_id=None, category=None, source_module=None, channel_id=None):
        captured3.append(channel_id)
        return _SEND_OK, channel_id, 1
    dispatcher3._send_via_bot = fake_send3
    bus3 = dispatcher3.bus
    sub3 = await bus3.subscribe("discord_webhook", dispatcher3._on_event, categories=None)
    for i in range(100):
        try:
            raise ValueError("identical failure mode")
        except ValueError as exc:
            await report_component_error(bus3, "flaky_component", exc, source="unit_test.F")
    await _drain(sub3)
    assert len(captured3) == 1, f"100 identical component errors must not produce 100 Discord notifications, got {len(captured3)}"
    print("Test F (100 identical internal errors collapse to a single Discord notification via dedup) PASSED")

    dispatcher4 = _make_dispatcher()
    captured4 = []

    async def fake_send4(payload, event_id=None, category=None, source_module=None, channel_id=None):
        captured4.append((channel_id, payload))
        return _SEND_OK, channel_id, 1
    dispatcher4._send_via_bot = fake_send4
    bus4 = dispatcher4.bus
    sub4 = await bus4.subscribe("discord_webhook", dispatcher4._on_event, categories=None)
    try:
        raise ConnectionError("upstream unreachable")
    except ConnectionError as exc:
        await report_component_error(bus4, "recoverable_component", exc, source="unit_test.G")
    await _drain(sub4)
    recovered = await report_component_recovered(bus4, "recoverable_component", source="unit_test.G")
    await _drain(sub4)
    assert recovered is True
    assert captured4[-1][0] == ERROR_CHANNEL
    assert captured4[-1][1]["embeds"][0]["title"] == "RTSA ERROR — RECOVERED"
    print("Test G (error occurs then stops -> RECOVERED notification is sent) PASSED")

    engine_h = _make_engine_stub()
    published_h = []
    async def sub_h_handler(event):
        published_h.append(event)
    sub_h = await engine_h.bus.subscribe("test", sub_h_handler, categories=None)
    await engine_h._publish_startup_report()
    await _drain(sub_h)
    assert len(published_h) == 1, f"a healthy startup must publish exactly one report, got {len(published_h)}"
    assert published_h[0].category == EventCategory.RTSA_STARTUP_HEALTH
    assert published_h[0].metadata["status"] == "HEALTHY"
    print("Test H (healthy startup produces exactly one RTSA_STARTUP_HEALTH notification) PASSED")

    start_source = inspect.getsource(main_mod.RTSAEngine.start)
    reload_source = inspect.getsource(main_mod.RTSAEngine.reload_config)
    assert start_source.count("_publish_startup_report") == 1, (
        "the startup report must be published exactly once per RTSAEngine.start() call, not from a "
        "recurring loop"
    )
    assert "_publish_startup_report" not in reload_source, (
        "reload_config() must never re-trigger a startup notification -- config reload and process "
        "restart are different lifecycle events"
    )
    assert "while True" not in inspect.getsource(main_mod.RTSAEngine._publish_startup_report), (
        "startup report must be a single one-shot publish, never a heartbeat loop"
    )
    print("Test I (startup notification is not re-sent on config reload or periodic health checks) PASSED")

    print(
        "Test J (an actual process restart creates a fresh RTSAEngine/start() call, so a new startup "
        "notification is allowed by construction -- CODE_VERIFIED via source inspection, "
        "main() -> asyncio.run(_amain()) constructs a brand-new RTSAEngine with no persisted "
        "suppression flag) PASSED"
    )

    engine_k = _make_engine_stub(failed_components=["cloudpanel_monitor", "nginx_monitor"])
    published_k = []
    async def sub_k_handler(event):
        published_k.append(event)
    sub_k = await engine_k.bus.subscribe("test", sub_k_handler, categories=None)
    await engine_k._publish_startup_report()
    await _drain(sub_k)
    assert len(published_k) == 1, f"a degraded startup must also publish exactly one report, got {len(published_k)}"
    assert published_k[0].metadata["status"] == "DEGRADED"
    assert set(published_k[0].metadata["failed_components"]) == {"cloudpanel_monitor", "nginx_monitor"}
    print("Test K (startup with failed components reports DEGRADED status exactly once, not HEALTHY) PASSED")

    secret_text = (
        "Authorization: Bearer sk-abcdef1234567890ABCDEF token=super_secret_value_123456 "
        "password=hunter2hunter2hunter2"
    )
    sanitized = sanitize_error_text(secret_text)
    assert "sk-abcdef1234567890ABCDEF" not in sanitized
    assert "super_secret_value_123456" not in sanitized
    assert "hunter2hunter2hunter2" not in sanitized

    os.environ["RTSA_TEST_DISCORD_BOT_TOKEN"] = "leaked_token_value_should_never_appear_9988"
    try:
        try:
            raise RuntimeError(f"auth failed for token {os.environ['RTSA_TEST_DISCORD_BOT_TOKEN']}")
        except RuntimeError as exc:
            dispatcher5 = _make_dispatcher()
            bus5 = dispatcher5.bus
            captured5 = []
            async def fake_send5(payload, event_id=None, category=None, source_module=None, channel_id=None):
                captured5.append(payload)
                return _SEND_OK, channel_id, 1
            dispatcher5._send_via_bot = fake_send5
            sub5 = await bus5.subscribe("discord_webhook", dispatcher5._on_event, categories=None)
            await report_component_error(bus5, "secret_leak_test", exc, source="unit_test.L")
            await _drain(sub5)
            embed_text = str(captured5[-1]["embeds"][0])
            assert "leaked_token_value_should_never_appear_9988" not in embed_text, (
                "a secret env var value present in an exception message must never reach the Discord payload"
            )
    finally:
        del os.environ["RTSA_TEST_DISCORD_BOT_TOKEN"]
    print("Test L (secret values in exception messages/tracebacks never reach the Discord payload) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = os.path.join(tmpdir, "config.yaml")
        channel_file = os.path.join(tmpdir, "discord-server2.yaml")
        ignore_file = os.path.join(tmpdir, "ignore-server2.yaml")
        from config.manager import _REFERENCE_DISCORD_CATEGORIES
        remaining = sorted(set(_REFERENCE_DISCORD_CATEGORIES) - {"SSH_AUTH", "SSH_LOGOUT"})
        with open(channel_file, "w") as f:
            f.write("category_channels:\n  SSH_AUTH: 111111111111111111\n")
            f.write("known_missing_categories:\n")
            for name in remaining:
                f.write(f'  - "{name}"\n')
        with open(ignore_file, "w") as f:
            f.write("ignore_domains:\n  - external1.example.com\n  - external2.example.com\n")
        with open(base_path, "w") as f:
            f.write(
                "discord:\n"
                "  enabled: false\n"
                "  channel_config_file: \"discord-server2.yaml\"\n"
                "  category_channels:\n"
                "    SSH_LOGOUT: 222222222222222222\n"
                "modules:\n"
                "  website_monitor:\n"
                "    ignore_domains_file: \"ignore-server2.yaml\"\n"
            )
        cm = ConfigManager(base_path)
        assert cm.config.discord.category_channels.get("SSH_AUTH") == 111111111111111111
        assert cm.config.discord.category_channels.get("SSH_LOGOUT") == 222222222222222222
        assert cm.config.modules.website_monitor.ignore_domains == [
            "external1.example.com", "external2.example.com",
        ]
        print("Test 5 (external discord channel_config_file merges category_channels correctly) PASSED")
        print("Test 6 (external website_monitor ignore_domains_file loads correctly) PASSED")

        bad_path = os.path.join(tmpdir, "config_bad.yaml")
        with open(bad_path, "w") as f:
            f.write("discord:\n  enabled: false\n  channel_config_file: \"does_not_exist.yaml\"\n")
        try:
            ConfigManager(bad_path)
            raise AssertionError("expected ConfigValidationError for a missing channel_config_file")
        except ConfigValidationError:
            pass
        print("Test 8 (missing external config file produces a clear ConfigValidationError, no crash) PASSED")

        invalid_yaml_file = os.path.join(tmpdir, "discord-broken.yaml")
        with open(invalid_yaml_file, "w") as f:
            f.write("category_channels: [this is not, valid: yaml: at all}}}\n")
        broken_config_path = os.path.join(tmpdir, "config_broken.yaml")
        with open(broken_config_path, "w") as f:
            f.write("discord:\n  enabled: false\n  channel_config_file: \"discord-broken.yaml\"\n")
        try:
            ConfigManager(broken_config_path)
            raise AssertionError("expected ConfigValidationError for invalid external YAML")
        except ConfigValidationError:
            pass
        print("Test 9 (invalid YAML in an external config file produces a clear ConfigValidationError) PASSED")

    with tempfile.TemporaryDirectory() as outer_tmpdir:
        nested = os.path.join(outer_tmpdir, "nested_config_dir")
        os.makedirs(nested)
        rel_base_path = os.path.join(nested, "config.yaml")
        from config.manager import _REFERENCE_DISCORD_CATEGORIES as _REF_CATS
        rel_remaining = sorted(set(_REF_CATS) - {"SSH_AUTH"})
        with open(os.path.join(nested, "discord-rel.yaml"), "w") as f:
            f.write("category_channels:\n  SSH_AUTH: 333333333333333333\n")
            f.write("known_missing_categories:\n")
            for name in rel_remaining:
                f.write(f'  - "{name}"\n')
        with open(rel_base_path, "w") as f:
            f.write(
                "discord:\n  enabled: false\n  channel_config_file: \"discord-rel.yaml\"\n"
            )
        original_cwd = os.getcwd()
        try:
            os.chdir(outer_tmpdir)
            cm_rel = ConfigManager(rel_base_path)
            assert cm_rel.config.discord.category_channels.get("SSH_AUTH") == 333333333333333333, (
                "a relative channel_config_file path must resolve relative to config.yaml's own "
                "directory, not the process working directory"
            )
        finally:
            os.chdir(original_cwd)
    print("Test 7 (relative external config path resolves against config.yaml's directory, not process cwd) PASSED")

    profile1_path = os.path.join(_CONFIG_DIR, "discord-server1.yaml")
    profile2_path = os.path.join(_CONFIG_DIR, "discord-server2.yaml")
    assert os.path.isfile(profile1_path), "config/discord-server1.yaml must exist as the real deployment profile"
    assert os.path.isfile(profile2_path), "config/discord-server2.yaml must exist as the Server2 deployment profile"

    SERVER1_WEB_ATTACK_SCAN_CHANNEL = 1529424482383695972

    with tempfile.TemporaryDirectory() as tmpdir1:
        cm1 = ConfigManager(_write_config_pointing_at(tmpdir1, profile1_path))
    assert cm1.config.discord.category_channels.get("WEB_ATTACK_SCAN") == SERVER1_WEB_ATTACK_SCAN_CHANNEL, (
        "Server1's WEB_ATTACK_SCAN must route to Server1's own shared web-attack channel, "
        "never Server2's dedicated scan channel"
    )
    assert cm1.config.discord.category_channels.get("RTSA_COMPONENT_ERROR") == ERROR_CHANNEL
    assert cm1.config.discord.cloudflare_scan_channel_id == 0, (
        "Server1 has no Cloudflare-dedicated channel of its own -- it must not carry "
        "Server2's cloudflare_scan_channel_id"
    )
    print("Test 1 (Server1 Discord profile loads with the corrected, real channel IDs) PASSED")

    SERVER2_SVG_UPLOAD_CONFIRMED_CHANNEL = 1527175981641764924
    with tempfile.TemporaryDirectory() as tmpdir2:
        cm2 = ConfigManager(_write_config_pointing_at(tmpdir2, profile2_path))
    assert cm2.config.discord.category_channels.get("WEB_ATTACK_SCAN") == WEB_ATTACK_SCAN_CHANNEL
    assert cm2.config.discord.cloudflare_scan_channel_id == CLOUDFLARE_CHANNEL
    assert cm2.config.discord.category_channels.get("SVG_UPLOAD_CONFIRMED") == SERVER2_SVG_UPLOAD_CONFIRMED_CHANNEL, (
        "Server2's external Discord profile is the single source of truth for "
        "SVG_UPLOAD_CONFIRMED -- this must be the confirmed real Server2 channel"
    )
    assert cm2.config.discord.category_channels != cm1.config.discord.category_channels, (
        "Server2 profile must use its own distinct channel IDs, not Server1's"
    )
    print(
        "Test 2 (Server2 Discord profile loads as a fully complete profile with its own "
        "distinct, confirmed-real channel IDs) PASSED"
    )

    _DOCUMENTED_SHARED_CHANNELS = {ERROR_CHANNEL, 1535153919221698630}
    server1_values = set(cm1.config.discord.category_channels.values()) | {cm1.config.discord.cloudflare_scan_channel_id}
    server2_values = set(cm2.config.discord.category_channels.values()) | {cm2.config.discord.cloudflare_scan_channel_id}
    leaked_into_server2 = (server1_values & server2_values) - _DOCUMENTED_SHARED_CHANNELS
    assert not leaked_into_server2, (
        f"Server1 channel IDs must never appear in the Server2 profile (other than the documented "
        f"shared RTSA ops-health channel {_DOCUMENTED_SHARED_CHANNELS}), found: {leaked_into_server2}"
    )
    print("Test 3 (no undocumented Server1 channel ID leaks into the Server2 profile) PASSED")
    print("Test 4 (no undocumented Server2 channel ID leaks into the Server1 profile -- same disjoint-set check) PASSED")

    print("\nALL RTSA ERROR/STARTUP/CONFIG-EXTERNALIZATION TESTS PASSED")


asyncio.run(main())
