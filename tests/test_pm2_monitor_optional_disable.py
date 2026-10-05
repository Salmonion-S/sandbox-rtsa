import asyncio
import os
import sys
import time
import tokenize

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.cloudpanel_resolver as cloudpanel_resolver
from config.manager import Pm2MonitorConfig, WebsiteMonitorConfig
from core.cloudpanel_resolver import CloudPanelAsset
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.website_check import WebsiteCheckResult, diagnose
from modules.pm2_monitor import Pm2Monitor
from modules.website_monitor import WebsiteMonitor, classify_root_cause


def test_1_pm2_monitor_config_gate_matches_main() -> None:
    from main import _MODULE_CONFIG_ATTR

    assert _MODULE_CONFIG_ATTR.get("pm2_monitor") == "pm2_monitor", (
        "main.py must map the 'pm2_monitor' discovered module name to the "
        "Pm2MonitorConfig attribute on ModulesConfig -- this is the mapping _load_modules() "
        "uses to decide whether to construct Pm2Monitor at all"
    )

    disabled_cfg = Pm2MonitorConfig(enabled=False)
    enabled_cfg = Pm2MonitorConfig(enabled=True)
    assert hasattr(disabled_cfg, "enabled") and not disabled_cfg.enabled, (
        "the exact gate condition main.py._load_modules() checks "
        "(hasattr(module_config, 'enabled') and not module_config.enabled) must evaluate True "
        "for a disabled pm2_monitor config -- this is what skips instantiating Pm2Monitor entirely"
    )
    assert not (hasattr(enabled_cfg, "enabled") and not enabled_cfg.enabled), (
        "the same gate must evaluate False for an enabled config, so Pm2Monitor is constructed "
        "normally when enabled=true (the current production default)"
    )
    print("Test 1 (pm2_monitor.enabled=false matches main.py's exact module-skip gate) PASSED")


async def test_2_disabled_pm2_monitor_creates_zero_work() -> None:
    subprocess_calls = {"n": 0}
    original_create = asyncio.create_subprocess_exec

    async def counting(*args, **kwargs):
        subprocess_calls["n"] += 1
        raise AssertionError("asyncio.create_subprocess_exec must never be called while pm2_monitor is disabled")

    asyncio.create_subprocess_exec = counting
    try:
        mon = Pm2Monitor(EventBus(), Pm2MonitorConfig(enabled=False))
        await mon.setup()
        await mon.run()
        assert subprocess_calls["n"] == 0
        assert mon._pm2_queries_total == 0
        assert mon._pm2_scan_cycles_total == 0
    finally:
        asyncio.create_subprocess_exec = original_create
    print("Test 2 (Pm2Monitor.run()/setup() with enabled=false: zero subprocess, zero scan cycles) PASSED")


def test_3_website_monitor_source_has_no_direct_pm2_invocation() -> None:
    with open("modules/website_monitor.py", "rb") as f:
        source = f.read()
    forbidden = [b"create_subprocess_exec", b"pm2 jlist", b"pwd.getpwnam"]
    for token in forbidden:
        assert token not in source, (
            f"website_monitor.py must never directly invoke PM2/subprocess primitives "
            f"(found forbidden token: {token!r}) -- its only relationship with PM2 is passive "
            f"EventBus correlation with events pm2_monitor itself publishes"
        )
    print("Test 3 (website_monitor.py contains no direct pm2/jlist/subprocess invocation) PASSED")


def test_4_classify_root_cause_never_fabricates_pm2_down() -> None:
    result_502 = WebsiteCheckResult(domain="app.example", scheme="https", condition="http_down", status_code=502)
    assert classify_root_cause(result_502, None, None) == "HTTP_FAILURE_UNCLASSIFIED", (
        "a 502 with pm2_down=None (PM2 monitor disabled or simply never reported) must degrade "
        "to an explicit uncertainty verdict -- never PM2_DOWN, and never a confident backend "
        "failure claim either, because 'RTSA has no PM2 evidence' is not evidence of anything"
    )
    assert classify_root_cause(result_502, False, None) == "BACKEND_DEGRADED", (
        "a 502 with pm2_down=False (PM2 monitor active and confirms the process is online) "
        "must be BACKEND_DEGRADED -- the app is misbehaving while running, it is not down"
    )
    assert classify_root_cause(result_502, True, None) == "PM2_DOWN", (
        "a 502 with pm2_down=True (PM2 monitor explicitly reported this process stopped) "
        "is the only case that may be labeled PM2_DOWN"
    )
    print("Test 4 (classify_root_cause: PM2_DOWN only ever fires on an explicit True signal) PASSED")


def test_5_diagnose_text_reflects_unknown_vs_confirmed() -> None:
    result_502 = WebsiteCheckResult(domain="app.example", scheme="https", condition="http_down", status_code=502)
    unknown_text = diagnose(result_502, pm2_down=None)
    assert "could not" in unknown_text.lower(), (
        f"pm2_down=None must state plainly that RTSA could not determine/verify the backend "
        f"state, got: {unknown_text!r}"
    )
    assert "stopped" not in unknown_text.lower() and "online" not in unknown_text.lower()

    stopped_text = diagnose(result_502, pm2_down=True)
    assert "stopped" in stopped_text.lower() or "offline" in stopped_text.lower()

    online_text = diagnose(result_502, pm2_down=False)
    assert "online" in online_text.lower()
    print("Test 5 (diagnose() text distinguishes unknown/stopped/online PM2 status, never fabricates) PASSED")


async def test_6_website_monitor_pm2_down_status_stays_unknown_when_pm2_silent() -> None:
    bus = EventBus()
    wm = WebsiteMonitor(bus, WebsiteMonitorConfig(enabled=True))
    asset = CloudPanelAsset(
        domain="silent-pm2.example", linux_user="newus001", project_root="/home/newus001",
        htdocs_path="/home/newus001/htdocs/silent-pm2.example", nginx_vhost=None,
        pm2_user="newus001", discovered_at=time.time(),
    )
    observation = wm._pm2_observation(asset)
    assert observation.down is None and observation.state == "UNKNOWN", (
        "with pm2_monitor disabled (or simply never having reported anything for this user), "
        "the PM2 observation must stay UNKNOWN, never DOWN or a fabricated OK"
    )
    assert observation.reason_code == "DOMAIN_PROCESS_MAPPING_UNKNOWN", (
        "the reason PM2 state is unknown must be recorded as an explicit evidence code, so the "
        "alert can say why rather than implying a diagnosis"
    )
    unmapped = wm._pm2_observation(None)
    assert unmapped.state == "UNKNOWN" and unmapped.reason_code == "PROJECT_USER_UNRESOLVED", (
        "a domain with no CloudPanel project must be distinguishable from a mapped project whose "
        "PM2 state simply was never reported"
    )
    print("Test 6 (WebsiteMonitor._pm2_observation stays UNKNOWN with an explicit reason code when PM2 monitor is silent) PASSED")


async def test_7_end_to_end_502_with_pm2_disabled_never_fabricates_down() -> None:
    original_resolve = cloudpanel_resolver.resolve_domain
    asset = CloudPanelAsset(
        domain="pm2off.example", linux_user="newus002", project_root="/home/newus002",
        htdocs_path="/home/newus002/htdocs/pm2off.example", nginx_vhost=None,
        pm2_user="newus002", discovered_at=time.time(),
    )

    async def fake_resolve(domain):
        return asset if domain == "pm2off.example" else None

    cloudpanel_resolver.resolve_domain = fake_resolve
    try:
        bus = EventBus()
        wm = WebsiteMonitor(bus, WebsiteMonitorConfig(enabled=True, incident_mode=True, conf_directory="/nonexistent/rtsa-test/sites-enabled"))
        collected = []

        async def collector(event):
            collected.append(event)

        sub = await bus.subscribe("collector", collector, categories=None)
        result_502 = WebsiteCheckResult(domain="pm2off.example", scheme="https", condition="http_down", status_code=502)
        await wm._evaluate("pm2off.example", result_502)
        await wm._evaluate("pm2off.example", result_502)
        await sub.queue.join()
        down_events = [e for e in collected if e.category == EventCategory.WEBSITE_DOWN]
        assert len(down_events) == 1
        assert down_events[0].metadata["root_cause"] == "HTTP_FAILURE_UNCLASSIFIED", (
            f"with PM2 monitor never having published anything for this user, a confirmed 502 must "
            f"be classified as an explicit uncertainty, not PM2_DOWN and not a confident backend "
            f"failure -- got {down_events[0].metadata['root_cause']!r}"
        )
        assert down_events[0].metadata["root_cause_confidence"] == "LOW", (
            "an unclassified HTTP failure must carry LOW root-cause confidence so the alert "
            "cannot read as a confident diagnosis"
        )
        assert down_events[0].metadata["pm2_state"] == "UNKNOWN", (
            "PM2 state must be reported as UNKNOWN rather than folded into the root cause"
        )
        await bus.shutdown()
    finally:
        cloudpanel_resolver.resolve_domain = original_resolve
    print(
        "Test 7 (end-to-end: confirmed 502 with PM2 monitor silent -> WEBSITE_DOWN root_cause="
        "HTTP_FAILURE_UNCLASSIFIED at LOW confidence with pm2_state=UNKNOWN, never PM2_DOWN "
        "and never a confident backend failure) PASSED"
    )


async def test_8_website_monitor_still_detects_down_and_recovery_with_pm2_disabled() -> None:
    bus = EventBus()
    wm = WebsiteMonitor(bus, WebsiteMonitorConfig(enabled=True, incident_mode=True))
    collected = []

    async def collector(event):
        collected.append(event)

    sub = await bus.subscribe("collector", collector, categories=None)
    timeout_result = WebsiteCheckResult(domain="stillworks.example", scheme="https", condition="timeout", provider="network")
    await wm._evaluate("stillworks.example", timeout_result)
    await wm._evaluate("stillworks.example", timeout_result)
    await sub.queue.join()
    down_events = [e for e in collected if e.category == EventCategory.WEBSITE_DOWN]
    assert len(down_events) == 1, "WEBSITE_DOWN detection must work identically regardless of pm2_monitor's enabled state"

    ok_result = WebsiteCheckResult(domain="stillworks.example", scheme="https", condition="ok", status_code=200, provider="origin")
    await wm._evaluate("stillworks.example", ok_result)
    await wm._evaluate("stillworks.example", ok_result)
    await sub.queue.join()
    recovered_events = [e for e in collected if e.category == EventCategory.WEBSITE_RECOVERED]
    assert len(recovered_events) == 1, "WEBSITE_RECOVERED detection must also work identically with pm2_monitor disabled"
    await bus.shutdown()
    print("Test 8 (WEBSITE_DOWN/WEBSITE_RECOVERED lifecycle fully functional with PM2 monitor never involved) PASSED")


async def test_9_on_pm2_event_only_reacts_to_real_pm2_monitor_source() -> None:
    bus = EventBus()
    wm = WebsiteMonitor(bus, WebsiteMonitorConfig(enabled=True))
    spoofed = BaseEvent(
        source_module="some_other_module", category=EventCategory.SERVICE_DOWN, severity=Severity.HIGH,
        message="fake", raw="", metadata={"linux_user": "newus003", "process_name": "app"},
    )
    await wm._on_pm2_event(spoofed)
    assert "newus003" not in wm._pm2_down_processes, (
        "a SERVICE_DOWN event from any source other than 'pm2_monitor' must never populate "
        "_pm2_down_processes -- only the real pm2_monitor module's own events count as evidence"
    )
    real_event = BaseEvent(
        source_module="pm2_monitor", category=EventCategory.SERVICE_DOWN, severity=Severity.HIGH,
        message="real", raw="", metadata={"linux_user": "newus003", "process_name": "app"},
    )
    await wm._on_pm2_event(real_event)
    assert "app" in wm._pm2_down_processes["newus003"]
    print("Test 9 (_on_pm2_event only trusts events genuinely published by pm2_monitor) PASSED")


def test_10_pm2_monitor_source_has_no_zero_comment_regression() -> None:
    with open("modules/pm2_monitor.py", "rb") as f:
        toks = list(tokenize.tokenize(f.readline))
    comments = [t for t in toks if t.type == tokenize.COMMENT]
    assert len(comments) == 0
    print("Test 10 (modules/pm2_monitor.py remains comment-free) PASSED")


async def main() -> None:
    test_1_pm2_monitor_config_gate_matches_main()
    await test_2_disabled_pm2_monitor_creates_zero_work()
    test_3_website_monitor_source_has_no_direct_pm2_invocation()
    test_4_classify_root_cause_never_fabricates_pm2_down()
    test_5_diagnose_text_reflects_unknown_vs_confirmed()
    await test_6_website_monitor_pm2_down_status_stays_unknown_when_pm2_silent()
    await test_7_end_to_end_502_with_pm2_disabled_never_fabricates_down()
    await test_8_website_monitor_still_detects_down_and_recovery_with_pm2_disabled()
    await test_9_on_pm2_event_only_reacts_to_real_pm2_monitor_source()
    test_10_pm2_monitor_source_has_no_zero_comment_regression()
    print("\nALL PM2-MONITOR-OPTIONAL-DISABLE TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
