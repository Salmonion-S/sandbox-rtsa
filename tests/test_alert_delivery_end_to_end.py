import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import contextlib

import yaml

import core.incident_engine as incident_engine_module
import core.scheduler as scheduler_module
import modules.website_monitor as website_monitor_module
from config.manager import DiscordConfig, NotificationPolicyConfig, WebsiteMonitorConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.website_check import WebsiteCheckResult, _classify_status as classify_status
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.website_monitor import WebsiteMonitor

_SERVER1_PROFILE = "config/discord-server1.yaml"
_SERVER2_PROFILE = "config/discord-server2.yaml"
_PRODUCTION_CONFIG = "config/config.yaml"


def load_profile_channels(path):
    with open(path) as f:
        loaded = yaml.safe_load(f) or {}
    return loaded.get("category_channels") or {}


def load_production_internal_only():
    with open(_PRODUCTION_CONFIG) as f:
        loaded = yaml.safe_load(f) or {}
    policy = ((loaded.get("discord") or {}).get("notification_policy") or {})
    return list(policy.get("internal_only_categories") or [])


class FakeReadyBot:
    def is_ready(self):
        return True


class _StopScheduler(Exception):
    pass


class FakeClock:

    def __init__(self, start=1_700_000_000.0):
        self._start = start
        self.now = start

    def time(self):
        return self.now

    def set(self, elapsed_seconds):
        self.now = self._start + elapsed_seconds

    @contextlib.contextmanager
    def installed(self):
        original = incident_engine_module.time
        incident_engine_module.time = self
        try:
            yield self
        finally:
            incident_engine_module.time = original


class MockTransport:

    def __init__(self, dispatcher):
        self.sends = []
        self.edits = []
        self._dispatcher = dispatcher

        async def _capture(payload, event_id=None, category=None, source_module=None, channel_id=None):
            resolved = channel_id if channel_id is not None else dispatcher._resolve_channel_id(
                category, source_module,
            )
            self.sends.append({
                "payload": payload, "event_id": event_id, "category": category,
                "source_module": source_module, "channel_id": resolved,
            })
            return "OK", resolved, 900000 + len(self.sends)

        async def _capture_edit(channel_id, message_id, payload, category=None):
            self.edits.append({
                "payload": payload, "category": category,
                "channel_id": channel_id, "message_id": message_id,
            })
            return "OK"

        dispatcher._send_via_bot = _capture
        dispatcher._edit_via_bot = _capture_edit

    def categories(self):
        return [s["category"] for s in self.sends]

    def channels_for(self, category):
        return [s["channel_id"] for s in self.sends if s["category"] == category]

    def edit_categories(self):
        return [e["category"] for e in self.edits]

    def deliveries(self):
        return len(self.sends) + len(self.edits)

    def clear(self):
        self.sends.clear()
        self.edits.clear()


async def build_stack(
    *, internal_only, profile_path=_SERVER1_PROFILE, dedup_window_seconds=0.0,
    sends_per_second=None,
):
    bus = EventBus()
    discord_cfg = DiscordConfig(
        enabled=True,
        alert_channel_id=999000999000999000,
        category_channels=load_profile_channels(profile_path),
        notification_policy=NotificationPolicyConfig(
            enabled=True, internal_only_categories=list(internal_only),
        ),
    )
    object.__setattr__(discord_cfg.outbound, "dedup_window_seconds", dedup_window_seconds)
    object.__setattr__(discord_cfg.outbound, "aggregation_min_count", 10_000)
    if sends_per_second is not None:
        object.__setattr__(discord_cfg.outbound, "max_sends_per_second", sends_per_second)
        object.__setattr__(discord_cfg.outbound, "max_sends_burst", int(sends_per_second))
    dispatcher = DiscordWebhookDispatcher(bus, discord_cfg)
    dispatcher._bot = FakeReadyBot()
    transport = MockTransport(dispatcher)
    await dispatcher.start()
    return bus, dispatcher, transport


async def drain(bus, dispatcher, settle_seconds=0.35):
    deadline = asyncio.get_running_loop().time() + settle_seconds
    while asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.01)


def make_website_monitor(**overrides):
    overrides.setdefault("enabled", True)
    overrides.setdefault("auto_discover", False)
    monitor = WebsiteMonitor(EventBus(), WebsiteMonitorConfig(**overrides))
    monitor._nginx_locally_up = None
    return monitor


DOWN = WebsiteCheckResult(
    "shop.example.com", "https", "connection_refused", provider="network", error_detail="refused",
)
UP = WebsiteCheckResult(
    "shop.example.com", "https", "ok", status_code=200, provider="network", response_time_ms=12.0,
)


async def main() -> None:
    server1 = load_profile_channels(_SERVER1_PROFILE)
    server2 = load_profile_channels(_SERVER2_PROFILE)
    for name, channels in (("server1", server1), ("server2", server2)):
        assert "WEBSITE_DOWN" in channels, f"{name} profile is missing a WEBSITE_DOWN channel"
        assert "WEBSITE_RECOVERED" in channels, f"{name} profile is missing a WEBSITE_RECOVERED channel"
        assert isinstance(channels["WEBSITE_DOWN"], int) and channels["WEBSITE_DOWN"] > 0
    print(
        f"Test 1 (both Discord profiles map WEBSITE_DOWN/WEBSITE_RECOVERED to real channels: "
        f"server1={server1['WEBSITE_DOWN']} server2={server2['WEBSITE_DOWN']}) PASSED"
    )

    shipped_internal_only = load_production_internal_only()
    assert "WEBSITE_DOWN" not in shipped_internal_only, (
        "REGRESSION GUARD: WEBSITE_DOWN must never be listed in "
        "discord.notification_policy.internal_only_categories -- that flag makes webhook.py drop the "
        "event before channel resolution, which is exactly why website outage alerts stopped "
        f"reaching Discord. Current value: {shipped_internal_only}"
    )
    assert "WEBSITE_RECOVERED" not in shipped_internal_only, (
        f"REGRESSION GUARD: WEBSITE_RECOVERED must not be internal-only either. "
        f"Current value: {shipped_internal_only}"
    )
    print(
        f"Test 2 [ROOT CAUSE GUARD] (shipped config no longer marks website categories internal-only; "
        f"remaining intentional entries: {shipped_internal_only}) PASSED"
    )

    bus, dispatcher, transport = await build_stack(internal_only=["WEBSITE_DOWN", "WEBSITE_RECOVERED"])
    monitor = make_website_monitor(down_confirmation_checks=2, recovery_confirmation_checks=2)
    monitor.publish = lambda event: bus.publish_nowait(event)
    await monitor._evaluate("shop.example.com", DOWN)
    await monitor._evaluate("shop.example.com", DOWN)
    await drain(bus, dispatcher)
    assert transport.sends == [], (
        "reproduction of the reported production symptom: with the categories marked internal-only "
        "the confirmed outage produces no Discord send at all"
    )
    assert dispatcher._total_policy_suppressed >= 1, (
        f"the drop must be attributable to the notification policy counter, got "
        f"{dispatcher._total_policy_suppressed}"
    )
    print(
        f"Test 3 [ROOT CAUSE PROOF] (with WEBSITE_DOWN marked internal-only the full real pipeline "
        f"produces ZERO Discord sends and increments _total_policy_suppressed to "
        f"{dispatcher._total_policy_suppressed} -- the exact reported symptom, reproduced) PASSED"
    )
    await dispatcher.stop()

    bus, dispatcher, transport = await build_stack(internal_only=shipped_internal_only)
    monitor = make_website_monitor(down_confirmation_checks=2, recovery_confirmation_checks=2)
    monitor.publish = lambda event: bus.publish_nowait(event)

    await monitor._evaluate("shop.example.com", DOWN)
    await drain(bus, dispatcher)
    assert transport.sends == [], "the first unconfirmed failure must not notify"

    await monitor._evaluate("shop.example.com", DOWN)
    await drain(bus, dispatcher)
    down_sends = [s for s in transport.sends if s["category"] == "WEBSITE_DOWN"]
    assert len(down_sends) == 1, f"expected exactly one WEBSITE_DOWN send, got {transport.categories()}"
    assert down_sends[0]["channel_id"] == server1["WEBSITE_DOWN"], (
        f"WEBSITE_DOWN must resolve to the configured channel {server1['WEBSITE_DOWN']}, "
        f"got {down_sends[0]['channel_id']}"
    )
    assert down_sends[0]["payload"], "the real formatter must have produced a payload"
    print(
        f"Test 4 [PRIMARY REGRESSION TEST] (simulated outage -> real WebsiteMonitor -> real "
        f"IncidentEngine -> real EventBus -> real routing -> exactly ONE mock Discord send on "
        f"channel {down_sends[0]['channel_id']}) PASSED"
    )

    for _ in range(5):
        await monitor._evaluate("shop.example.com", DOWN)
    await drain(bus, dispatcher)
    down_sends = [s for s in transport.sends if s["category"] == "WEBSITE_DOWN"]
    assert len(down_sends) == 1, (
        f"5 further identical failing polls must not produce additional initial alerts, got "
        f"{len(down_sends)}"
    )
    print("Test 5 (5 further identical down polls produce zero additional sends -- dedup holds through the real dispatcher) PASSED")

    await monitor._evaluate("shop.example.com", UP)
    await drain(bus, dispatcher)
    assert [s for s in transport.sends if s["category"] == "WEBSITE_RECOVERED"] == [], (
        "recovery must be confirmed before notifying"
    )
    await monitor._evaluate("shop.example.com", UP)
    await drain(bus, dispatcher)
    recovered = [s for s in transport.sends if s["category"] == "WEBSITE_RECOVERED"]
    assert len(recovered) == 1, f"expected exactly one WEBSITE_RECOVERED send, got {transport.categories()}"
    assert recovered[0]["channel_id"] == server1["WEBSITE_RECOVERED"]
    print(
        f"Test 6 (confirmed recovery -> exactly ONE WEBSITE_RECOVERED send on channel "
        f"{recovered[0]['channel_id']}) PASSED"
    )
    await dispatcher.stop()

    bus, dispatcher, transport = await build_stack(
        internal_only=shipped_internal_only, profile_path=_SERVER2_PROFILE,
    )
    monitor = make_website_monitor(down_confirmation_checks=1, recovery_confirmation_checks=1)
    monitor.publish = lambda event: bus.publish_nowait(event)
    await monitor._evaluate("shop.example.com", DOWN)
    await drain(bus, dispatcher)
    down_sends = [s for s in transport.sends if s["category"] == "WEBSITE_DOWN"]
    assert len(down_sends) == 1 and down_sends[0]["channel_id"] == server2["WEBSITE_DOWN"], (
        f"the Server2 profile must resolve WEBSITE_DOWN to {server2['WEBSITE_DOWN']}, got {down_sends}"
    )
    print(
        f"Test 7 (the same pipeline under the Server2 profile delivers WEBSITE_DOWN to the Server2 "
        f"channel {server2['WEBSITE_DOWN']}) PASSED"
    )
    await dispatcher.stop()

    bus, dispatcher, transport = await build_stack(internal_only=shipped_internal_only)
    flapping = make_website_monitor(down_confirmation_checks=1, recovery_confirmation_checks=1)
    flapping.publish = lambda event: bus.publish_nowait(event)
    for result in (DOWN, UP, DOWN, UP):
        await flapping._evaluate("flap.example.com", result)
        await drain(bus, dispatcher)
    down_new = len([s for s in transport.sends if s["category"] == "WEBSITE_DOWN"])
    up_new = len([s for s in transport.sends if s["category"] == "WEBSITE_RECOVERED"])
    down_edits = len([e for e in transport.edits if e["category"] == "WEBSITE_DOWN"])
    up_edits = len([e for e in transport.edits if e["category"] == "WEBSITE_RECOVERED"])
    assert down_new + down_edits == 2 and up_new + up_edits == 2, (
        f"a DOWN/UP/DOWN/UP flap with confirmation=1 must produce four paired transitions in total, "
        f"got down={down_new}+{down_edits}edit recovered={up_new}+{up_edits}edit"
    )
    assert down_new == 1 and up_new == 1, (
        f"the repeat of each transition must reuse the existing Discord message via edit rather than "
        f"posting a second one (outbound.message_edit_enabled is True in production), got "
        f"down_new={down_new} up_new={up_new}"
    )
    assert down_edits == 1 and up_edits == 1, (
        f"the repeat of each transition must be delivered as an edit, got "
        f"down_edits={down_edits} up_edits={up_edits}"
    )
    print(
        f"Test 8 (DOWN/UP/DOWN/UP flap -> {down_new} new down + {down_edits} down edit, {up_new} new "
        f"recovery + {up_edits} recovery edit: every transition is delivered, repeats reuse the "
        f"existing message instead of creating a storm) PASSED"
    )
    await dispatcher.stop()

    bus, dispatcher, transport = await build_stack(
        internal_only=shipped_internal_only, sends_per_second=200.0,
    )
    matrix = [
        ("WEBSITE_DOWN", EventCategory.WEBSITE_DOWN, Severity.HIGH, "website_monitor"),
        ("WEBSITE_RECOVERED", EventCategory.WEBSITE_RECOVERED, Severity.INFO, "website_monitor"),
        ("CLOUDPANEL_PROJECT_CREATED", EventCategory.CLOUDPANEL_PROJECT_CREATED, Severity.MEDIUM, "cloudpanel_monitor"),
        ("CLOUDPANEL_PROJECT_DELETED", EventCategory.CLOUDPANEL_PROJECT_DELETED, Severity.HIGH, "cloudpanel_monitor"),
        ("SYSTEMD_SECURITY", EventCategory.SYSTEMD_SECURITY, Severity.HIGH, "systemd_monitor"),
        ("SYSTEMD_PROCESS_MISMATCH", EventCategory.SYSTEMD_PROCESS_MISMATCH, Severity.HIGH, "systemd_monitor"),
        ("SERVICE_DOWN", EventCategory.SERVICE_DOWN, Severity.HIGH, "service_availability_monitor"),
        ("SERVICE_RECOVERED", EventCategory.SERVICE_RECOVERED, Severity.INFO, "service_availability_monitor"),
        ("HEALTH_STATUS", EventCategory.HEALTH_STATUS, Severity.HIGH, "health_monitor"),
        ("FILE_INTEGRITY_CHANGE", EventCategory.FILE_INTEGRITY_CHANGE, Severity.HIGH, "file_integrity_detector"),
        ("BRUTE_FORCE", EventCategory.BRUTE_FORCE, Severity.HIGH, "ssh_monitor"),
        ("WEB_ATTACK_SCAN", EventCategory.WEB_ATTACK_SCAN, Severity.HIGH, "nginx_monitor"),
        ("WEB_ATTACK_SUCCESS", EventCategory.WEB_ATTACK_SUCCESS, Severity.CRITICAL, "nginx_monitor"),
        ("RTSA_COMPONENT_ERROR", EventCategory.RTSA_COMPONENT_ERROR, Severity.HIGH, "supervisor"),
        ("RTSA_COMPONENT_RECOVERED", EventCategory.RTSA_COMPONENT_RECOVERED, Severity.INFO, "supervisor"),
    ]
    unrouted = []
    delivered = []
    for label, category, severity, source in matrix:
        transport.clear()
        bus.publish_nowait(BaseEvent(
            source_module=source, category=category, severity=severity,
            message=f"{label} matrix probe", raw="", metadata={},
        ))
        await drain(bus, dispatcher)
        sends = [s for s in transport.sends if s["category"] == category.value]
        if not sends:
            unrouted.append(label)
        else:
            channel = sends[0]["channel_id"]
            assert channel, f"{label} resolved to a falsy channel id"
            delivered.append((label, channel))
    assert not unrouted, f"these categories produced no Discord send at all: {unrouted}"
    print(f"Test 9 [ALERT ROUTING MATRIX] (all {len(delivered)} required categories resolved to a channel and reached the mock transport) PASSED")
    for label, channel in delivered:
        print(f"    {label:<28} -> channel {channel}")
    await dispatcher.stop()

    bus, dispatcher, transport = await build_stack(internal_only=shipped_internal_only)
    bus.publish_nowait(BaseEvent(
        source_module="pm2_monitor", category=EventCategory.SERVICE_DOWN, severity=Severity.HIGH,
        message="pm2 process down", raw="", metadata={},
    ))
    await drain(bus, dispatcher)
    assert transport.sends == [], (
        "the intentional pm2_monitor:SERVICE_DOWN internal-only entry must still suppress, proving "
        "the fix removed only the website categories and did not disable the policy mechanism"
    )
    assert dispatcher._total_policy_suppressed >= 1
    print("Test 10 (the intentional pm2_monitor:SERVICE_DOWN suppression still works -- the policy mechanism itself was not disabled) PASSED")
    await dispatcher.stop()

    import shutil
    import tempfile

    os.environ.setdefault("RTSA_DISCORD_BOT_TOKEN", "test_fixture_token_never_a_real_credential_0123456789abcdef")
    os.environ.setdefault("RTSA_CLOUDFLARE_API_TOKEN", "test_fixture_cf_token_never_real_fedcba9876543210")
    from config.manager import ConfigManager

    with tempfile.TemporaryDirectory(prefix="rtsa_real_config_") as tmp:
        for name in os.listdir("config"):
            if name.endswith(".yaml"):
                shutil.copy(os.path.join("config", name), os.path.join(tmp, name))
        cfg_path = os.path.join(tmp, "config.yaml")
        with open(cfg_path) as f:
            raw = yaml.safe_load(f)
        raw["database"]["path"] = os.path.join(tmp, "data", "rtsa.db")
        raw["logging"]["directory"] = os.path.join(tmp, "logs")
        with open(cfg_path, "w") as f:
            yaml.safe_dump(raw, f)

        real = ConfigManager(cfg_path).config
        assert real.modules.website_monitor.enabled is True, "website_monitor must stay enabled"
        assert "WEBSITE_DOWN" not in real.discord.notification_policy.internal_only_categories
        resolved = real.discord.category_channels
        assert resolved.get("WEBSITE_DOWN"), "the real config pipeline must resolve a WEBSITE_DOWN channel"
        assert resolved.get("WEBSITE_RECOVERED"), "the real config pipeline must resolve a WEBSITE_RECOVERED channel"
        assert resolved.get("SYSTEMD_SECURITY"), (
            "systemd categories must still be injected by the service-profile merge"
        )
        assert real.discord.alert_channel_id, (
            "an alert_channel_id fallback must exist so a category with no explicit mapping "
            "(for example SERVICE_DOWN) still resolves to a real channel instead of being dropped"
        )
        print(
            f"Test 11 [FULL CONFIG VALIDATION] (the real ConfigManager loads the shipped config end to "
            f"end: website_monitor enabled, {len(resolved)} categories routed, "
            f"WEBSITE_DOWN->{resolved['WEBSITE_DOWN']}, SYSTEMD_SECURITY->{resolved['SYSTEMD_SECURITY']} "
            f"via the service-profile merge, unmapped categories fall back to "
            f"{real.discord.alert_channel_id}) PASSED"
        )

    bus, dispatcher, transport = await build_stack(internal_only=shipped_internal_only)
    clock = FakeClock()
    reminder_monitor = make_website_monitor(
        down_confirmation_checks=1, recovery_confirmation_checks=1,
        reminder_interval_seconds=[1800.0, 3600.0, 7200.0, 21600.0], maximum_reminders=4,
    )
    reminder_monitor.publish = lambda event: bus.publish_nowait(event)
    with clock.installed():
        await reminder_monitor._evaluate("long.example.com", DOWN)
        await drain(bus, dispatcher)
        initial = transport.deliveries()
        assert initial == 1, f"the first confirmed outage must produce exactly one delivery, got {initial}"

        for elapsed in (60.0, 600.0, 1799.0):
            clock.set(elapsed)
            await reminder_monitor._evaluate("long.example.com", DOWN)
        await drain(bus, dispatcher)
        assert transport.deliveries() == 1, (
            f"polls before the first reminder interval must not notify again, got "
            f"{transport.deliveries()} deliveries"
        )

        reminder_deliveries = []
        for elapsed in (1800.0, 3600.0, 7200.0, 21600.0):
            clock.set(elapsed)
            await reminder_monitor._evaluate("long.example.com", DOWN)
            await drain(bus, dispatcher)
            reminder_deliveries.append(transport.deliveries())
        assert reminder_deliveries == [2, 3, 4, 5], (
            f"each of the four configured reminder intervals must produce exactly one further "
            f"delivery, got cumulative {reminder_deliveries}"
        )

        for elapsed in (43200.0, 64800.0, 80000.0):
            clock.set(elapsed)
            await reminder_monitor._evaluate("long.example.com", DOWN)
            await drain(bus, dispatcher)
        assert transport.deliveries() == 5, (
            f"maximum_reminders=4 must hard-cap the incident at 1 initial + 4 reminders, got "
            f"{transport.deliveries()} deliveries"
        )

        clock.set(82000.0)
        await reminder_monitor._evaluate("long.example.com", UP)
        await drain(bus, dispatcher)
        recovered = [c for c in transport.categories() + transport.edit_categories()
                     if c == "WEBSITE_RECOVERED"]
        assert len(recovered) == 1, (
            f"a sustained outage must end with exactly one recovery notification, got {len(recovered)}"
        )
    print(
        f"Test 12 [REMINDER BOUNDING] (a 22-hour outage under a controlled clock produces 1 initial "
        f"alert + exactly 4 reminders at 1800/3600/7200/21600s, then nothing however long it stays "
        f"down, then exactly 1 recovery -- {transport.deliveries()} deliveries total, not one per poll) "
        f"PASSED"
    )
    await dispatcher.stop()

    ignored = make_website_monitor(
        auto_discover=False, domains=["kept.example.com", "skip.example.com"],
        ignore_domains=["skip.example.com"],
    )
    await ignored._maybe_refresh_discovery()
    assert ignored._domains == ["kept.example.com"], (
        f"ignore_domains must remove the domain from the manual list, got {ignored._domains}"
    )
    print(
        f"Test 13 (ignore_domains removes skip.example.com from the manual domain list, leaving "
        f"{ignored._domains}) PASSED"
    )

    manual = make_website_monitor(
        auto_discover=False, domains=["a.example.com", "b.example.com", "localhost", "10.0.0.5"],
    )
    await manual._maybe_refresh_discovery()
    assert manual._domains == ["a.example.com", "b.example.com"], (
        f"auto_discover=False must monitor exactly the configured public domains and drop "
        f"private/local entries, got {manual._domains}"
    )
    print(
        f"Test 14 (auto_discover=False monitors the manual list {manual._domains} and drops the "
        f"non-public localhost/10.0.0.5 entries) PASSED"
    )

    async def cloudpanel_ok():
        return ["cp-one.example.com", "cp-two.example.com"]

    async def cloudpanel_empty():
        return []

    async def cloudpanel_raises():
        raise RuntimeError("simulated CloudPanel discovery failure")

    def nginx_ok(_directory):
        return {"nginx-one.example.com": {"access_log": "/var/log/nginx/x.log"}}

    def nginx_raises(_directory):
        raise RuntimeError("simulated nginx sweep failure")

    matrix_cases = [
        ("cloudpanel ok + nginx ok", cloudpanel_ok, nginx_ok, [], {"cp-one.example.com", "cp-two.example.com", "nginx-one.example.com"}),
        ("cloudpanel raises, nginx ok", cloudpanel_raises, nginx_ok, [], {"nginx-one.example.com"}),
        ("cloudpanel ok, nginx raises", cloudpanel_ok, nginx_raises, [], {"cp-one.example.com", "cp-two.example.com"}),
        ("both sources fail, manual survives", cloudpanel_raises, nginx_raises, ["manual.example.com"], {"manual.example.com"}),
        ("cloudpanel empty, nginx ok", cloudpanel_empty, nginx_ok, [], {"nginx-one.example.com"}),
        ("ignore list applied after merge", cloudpanel_ok, nginx_ok, [], {"cp-two.example.com", "nginx-one.example.com"}),
    ]
    original_discover = website_monitor_module.cloudpanel_resolver.discover_all_domains
    original_vhosts = website_monitor_module.discover_nginx_vhosts
    original_looks = website_monitor_module.cloudpanel_resolver.looks_like_cloudpanel_vhost
    website_monitor_module.cloudpanel_resolver.looks_like_cloudpanel_vhost = lambda _log: False
    try:
        for label, cp_fn, nginx_fn, manual_domains, expected in matrix_cases:
            ignore = ["cp-one.example.com"] if label.startswith("ignore list") else []
            website_monitor_module.cloudpanel_resolver.discover_all_domains = cp_fn
            website_monitor_module.discover_nginx_vhosts = nginx_fn
            probe = make_website_monitor(
                auto_discover=True, domains=list(manual_domains), ignore_domains=ignore,
            )
            discovered = set(await probe._discover_domains())
            assert discovered == expected, (
                f"discovery matrix case '{label}' must yield {sorted(expected)}, got {sorted(discovered)}"
            )
            if label != "both sources fail, manual survives":
                assert discovered, f"case '{label}' must not zero out monitoring"
    finally:
        website_monitor_module.cloudpanel_resolver.discover_all_domains = original_discover
        website_monitor_module.discover_nginx_vhosts = original_vhosts
        website_monitor_module.cloudpanel_resolver.looks_like_cloudpanel_vhost = original_looks
    print(
        f"Test 15 [DISCOVERY MATRIX] ({len(matrix_cases)} source combinations: one discovery source "
        f"raising never zeroes out monitoring, the surviving source and the manual list still "
        f"produce domains, and ignore_domains is applied after the merge) PASSED"
    )

    guard = make_website_monitor(auto_discover=False, domains=["boom.example.com"])

    async def exploding_check(_domain):
        raise RuntimeError("simulated per-domain check crash")

    guard._check_one_domain = exploding_check
    crashed = False
    try:
        await guard._poll_once()
    except RuntimeError:
        crashed = True
    assert guard._scan_in_progress is False, (
        "_scan_in_progress must be cleared in the finally block even when a cycle raises, otherwise "
        "the single-flight guard latches on and website monitoring silently stops forever"
    )
    reentered = make_website_monitor(auto_discover=False, domains=["x.example.com"])
    reentered._scan_in_progress = True
    checked = []
    reentered._check_one_domain = lambda domain: checked.append(domain)
    await reentered._poll_once()
    assert checked == [] and reentered._checks_skipped_overlap_total == 1, (
        f"a cycle starting while another is in flight must be skipped and counted, got "
        f"checked={checked} skipped={reentered._checks_skipped_overlap_total}"
    )
    print(
        f"Test 16 [SINGLE FLIGHT] (an overlapping cycle is skipped and counted, and a cycle that "
        f"raises mid-flight still clears _scan_in_progress -- crash_propagated={crashed}, so the "
        f"guard cannot latch on and stop monitoring) PASSED"
    )

    offsets = []
    original_sleep = asyncio.sleep

    async def record_sleep(delay, *args, **kwargs):
        offsets.append(delay)
        raise _StopScheduler()

    scheduler_module.asyncio.sleep = record_sleep
    try:
        offset_monitor = make_website_monitor(auto_discover=False, poll_interval_seconds=420.0)
        try:
            await offset_monitor.run()
        except _StopScheduler:
            pass
    finally:
        scheduler_module.asyncio.sleep = original_sleep
    assert offsets and offsets[0] == website_monitor_module._STARTUP_OFFSET_SECONDS > 0, (
        f"the website scanner must wait its startup offset before the first cycle so every scanner "
        f"does not fire at once on boot, got first sleep {offsets[:1]} vs offset "
        f"{website_monitor_module._STARTUP_OFFSET_SECONDS}"
    )
    print(
        f"Test 17 [STARTUP OFFSET] (run() defers the first poll by "
        f"{website_monitor_module._STARTUP_OFFSET_SECONDS}s instead of scanning immediately on boot) "
        f"PASSED"
    )

    status_matrix = [
        (200, "ok", False), (301, "ok", False), (404, "ok", False),
        (500, "http_down", True), (502, "http_down", True), (503, "http_down", True),
        (504, "http_down", True), (521, "cloudflare_down", True), (522, "cloudflare_down", True),
        (523, "cloudflare_down", True), (524, "cloudflare_down", True),
    ]
    for status, expected_condition, expected_down in status_matrix:
        classified = classify_status("m.example.com", "https", status, 5.0)
        assert classified.condition == expected_condition, (
            f"HTTP {status} must classify as {expected_condition}, got {classified.condition}"
        )
        assert classified.is_down is expected_down, (
            f"HTTP {status} must have is_down={expected_down}, got {classified.is_down}"
        )

    bus, dispatcher, transport = await build_stack(
        internal_only=shipped_internal_only, sends_per_second=200.0,
    )
    for status, _expected_condition, expected_down in status_matrix:
        domain = f"s{status}.example.com"
        status_monitor = make_website_monitor(
            down_confirmation_checks=1, recovery_confirmation_checks=1,
        )
        status_monitor.publish = lambda event: bus.publish_nowait(event)
        await status_monitor._evaluate(domain, classify_status(domain, "https", status, 5.0))
        await drain(bus, dispatcher)
    down_sends = [s for s in transport.sends if s["category"] == "WEBSITE_DOWN"]
    expected_down_count = len([1 for _s, _c, d in status_matrix if d])
    assert len(down_sends) == expected_down_count, (
        f"each distinct down status must produce its own WEBSITE_DOWN alert, expected "
        f"{expected_down_count} got {len(down_sends)}"
    )
    assert all(s["channel_id"] == server1["WEBSITE_DOWN"] for s in down_sends), (
        f"every down-status alert must route to the website channel {server1['WEBSITE_DOWN']}"
    )
    print(
        f"Test 18 [HTTP STATUS MATRIX] (200/301/404 are up and alert-free; "
        f"500/502/503/504 classify as http_down and 521/522/523/524 as cloudflare_down, and all "
        f"{expected_down_count} down statuses reach channel {server1['WEBSITE_DOWN']}) PASSED"
    )
    await dispatcher.stop()

    print("\nALL ALERT DELIVERY END-TO-END TESTS PASSED")


asyncio.run(main())
