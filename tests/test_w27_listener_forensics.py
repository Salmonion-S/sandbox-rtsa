import asyncio
import os
import sys
import time
from unittest import mock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, RemoteAccessDetectorConfig, TceConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.process_correlation import _Correlation
from discord_integration.webhook import DiscordWebhookDispatcher
import modules.remote_access_detector as rad_mod
from modules.remote_access_detector import (
    RemoteAccessDetector, build_score_breakdown, classify_bind_scope, classify_chrome_trust,
    classify_event_taxonomy, format_endpoint, sanitize_cmdline,
)
from modules.process_anomaly_detector import ProcessSnapshot, TrustMatchDetail
from modules.threat_correlation_engine import (
    CorrelationCandidateEvent, _extract_listener_forensics, classify_event, group_classified_events,
    score_group,
)


async def main():
    assert classify_bind_scope("127.0.0.1") == ("LOOPBACK_ONLY", "LOCAL_ONLY")
    assert classify_bind_scope("::1") == ("LOOPBACK_ONLY", "LOCAL_ONLY")
    assert classify_bind_scope("0.0.0.0") == ("ALL_INTERFACES", "INTERNET_EXPOSED")
    assert classify_bind_scope("::") == ("ALL_INTERFACES", "INTERNET_EXPOSED")
    assert classify_bind_scope("10.0.0.5") == ("PRIVATE_NETWORK", "LAN_ACCESSIBLE")
    assert classify_bind_scope("8.8.8.8") == ("PUBLIC_ADDRESS", "INTERNET_EXPOSED")
    assert classify_bind_scope(None) == ("UNKNOWN", "UNKNOWN")
    assert format_endpoint("0.0.0.0", 29143) == "0.0.0.0:29143"
    assert format_endpoint("::1", 29143) == "[::1]:29143"
    print("Test 1 (bind/exposure classification: loopback < private < public/all-interfaces) PASSED")

    assert "hunter2" not in sanitize_cmdline("app --password=hunter2 --port 8080")
    assert "[REDACTED]" in sanitize_cmdline("app --api-key=sk-abc123 --verbose")
    assert "[REDACTED]" in sanitize_cmdline("app --token abc.def.ghi")
    assert sanitize_cmdline(None) is None
    assert sanitize_cmdline("node index.js") == "node index.js"
    print("Test 2 (secret redaction: password/api-key/token args never leak) PASSED")

    assert classify_chrome_trust("node", None) is None, "non-chrome executables get no classification"
    assert classify_chrome_trust("chrome", None) == "UNKNOWN_CHROME"
    puppeteer_match = TrustMatchDetail(
        profile_name="puppeteer_playwright_headless_browser", basename_match=True, path_match=True,
        matched_path_substring=".cache/puppeteer/", parent_match=True, uid_match=True,
    )
    assert classify_chrome_trust("chrome", puppeteer_match) == "TRUSTED_PUPPETEER"
    playwright_match = TrustMatchDetail(
        profile_name="puppeteer_playwright_headless_browser", basename_match=True, path_match=True,
        matched_path_substring=".cache/ms-playwright/", parent_match=True, uid_match=True,
    )
    assert classify_chrome_trust("chrome", playwright_match) == "TRUSTED_PLAYWRIGHT"
    print("Test 3 (Chrome trust classification: full profile match required, never basename-alone) PASSED")

    total, breakdown = build_score_breakdown(["unmanaged", "system_uid", "internet_exposed"])
    assert total == 20 + 15 + 15
    assert len(breakdown) == 3
    assert all("label" in item and "points" in item and "signal" in item for item in breakdown)
    print("Test 4 (itemized, traceable score breakdown) PASSED")

    assert classify_event_taxonomy(
        known_match=True, trust_classification=None, severity=Severity.CRITICAL, evidence=[],
    ) == "CONFIRMED_THREAT"
    assert classify_event_taxonomy(
        known_match=False, trust_classification="TRUSTED_PUPPETEER", severity=Severity.INFO, evidence=[],
    ) == "TRUSTED_AUTOMATION"
    assert classify_event_taxonomy(
        known_match=False, trust_classification=None, severity=Severity.MEDIUM, evidence=[],
    ) == "UNKNOWN"
    assert classify_event_taxonomy(
        known_match=False, trust_classification=None, severity=Severity.INFO, evidence=["managed_listener"],
    ) == "EXPECTED_APPLICATION"
    print("Test 5 (event classification taxonomy: UNKNOWN never auto-promotes) PASSED")

    bus = EventBus()
    events = []

    async def collector(e):
        events.append(e)

    sub = await bus.subscribe("c", collector, categories=None)
    rad = RemoteAccessDetector(bus, RemoteAccessDetectorConfig(legitimacy_score_threshold=60))

    def fake_read_snapshot(pid):
        if pid == 613841:
            return ProcessSnapshot(
                pid=613841, ppid=613700, uid=1005, gid=1005,
                exe="/home/simpuskes-api/.cache/puppeteer/chrome/linux-1/chrome-linux/chrome",
                cwd="/home/simpuskes-api/htdocs/api-simpuskes.com",
                cmdline="/path/chrome --remote-debugging-port=29143 --password=hunter2secret",
                username="simpuskes-api", start_time=time.time() - 30, project=None,
                network_active=True, start_time_ticks=1,
            )
        if pid == 613700:
            return ProcessSnapshot(
                pid=613700, ppid=1, uid=1005, gid=1005, exe="/usr/bin/node",
                cwd="/home/simpuskes-api/htdocs/api-simpuskes.com", cmdline="node index.js",
                username="simpuskes-api", start_time=time.time() - 500, project=None,
                network_active=False, start_time_ticks=1,
            )
        return None

    async def fake_correlate_pid(pid, username, ppid, *, port=None, conf_directory=None, resolve_cloudpanel=True):
        return _Correlation(
            pm2_app_name="simpuskes-api", pm2_status="online",
            cloudpanel_domain="api-simpuskes.com", cloudpanel_htdocs_path="/home/simpuskes-api/htdocs/api-simpuskes.com",
        )

    rad_mod.read_process_snapshot = fake_read_snapshot
    rad_mod.correlate_pid = fake_correlate_pid
    try:
        await rad._investigate(613841, port=29143, process_name="chrome", bind_ip="0.0.0.0")
        await sub.queue.join()
        assert len(events) == 1
        m = events[0].metadata
        assert "hunter2secret" not in (m.get("command_line") or ""), "SECRET LEAKED in command_line"
        assert "hunter2secret" not in (events[0].raw or ""), "SECRET LEAKED in raw"
        assert m.get("process_classification") == "TRUSTED_PUPPETEER"
        assert m.get("classification") == "TRUSTED_AUTOMATION"
        assert m.get("bind_classification") == "ALL_INTERFACES"
        assert m.get("exposure") == "INTERNET_EXPOSED"
        assert m.get("ownership_chain") == [
            "Port 29143", "chrome PID 613841", "node PID 613700", "PM2 app: simpuskes-api",
            "api-simpuskes.com",
        ]
        assert m.get("timeline"), "timeline must be populated with real timestamps"
        assert all(e.get("timestamp") for e in m["timeline"]), "no fabricated/missing timestamps"
        assert m.get("uid") == 1005
        assert m.get("parent_uid") == 1005
        print("Test 6 (end-to-end _investigate(): no secret leakage, correct trust/exposure/chain) PASSED")
    finally:
        pass

    from modules.remote_access_detector import ListenerBaselineEntry
    rad2 = RemoteAccessDetector(bus, RemoteAccessDetectorConfig(legitimacy_score_threshold=60))
    rad2._baseline_is_initial = False
    rad2._baseline[29143] = ListenerBaselineEntry(
        port=29143, process_fingerprint="fp-original-legit-process", first_seen=100.0, last_seen=100.0,
    )
    events2 = []

    async def collector2(e):
        events2.append(e)

    sub2 = await bus.subscribe("c2", collector2, categories=None)

    async def fake_fingerprint_changed(pid):
        return "fp-DIFFERENT-suspicious-process"

    rad2._fingerprint_for_pid = fake_fingerprint_changed

    def fake_scan_listeners():
        return [(29143, "suspicious_binary", 99999, "0.0.0.0")]

    def fake_scan_processes():
        return []

    rad2._scan_listeners = fake_scan_listeners
    rad2._scan_processes = fake_scan_processes
    investigated = []

    async def fake_investigate_bounded(pid, *, port, process_name, bind_ip=None, known_match=False,
                                         known_port_label=None, identity_changed=False, previous_fingerprint=None):
        investigated.append((pid, port, identity_changed, previous_fingerprint))

    rad2._investigate_bounded = fake_investigate_bounded

    async def fake_save_baseline_locked():
        return None

    rad2._save_baseline_locked = fake_save_baseline_locked

    await rad2._poll_once()
    assert len(investigated) == 1, f"a genuine identity change on an already-baselined port must trigger investigation: {investigated}"
    assert investigated[0][2] is True, "identity_changed flag must be True"
    assert investigated[0][3] == "fp-original-legit-process", "previous_fingerprint must be preserved"
    assert rad2._baseline[29143].process_fingerprint == "fp-DIFFERENT-suspicious-process", (
        "baseline must be updated to the new fingerprint after detecting the change"
    )
    print("Test 7 (SAME port, DIFFERENT process identity -- now detected, was previously invisible) PASSED")

    rad3 = RemoteAccessDetector(bus, RemoteAccessDetectorConfig())
    rad3._baseline_is_initial = False
    rad3._baseline[29143] = ListenerBaselineEntry(
        port=29143, process_fingerprint="fp-stable", first_seen=100.0, last_seen=100.0,
    )

    async def fake_fingerprint_same(pid):
        return "fp-stable"

    rad3._fingerprint_for_pid = fake_fingerprint_same
    rad3._scan_listeners = fake_scan_listeners
    rad3._scan_processes = fake_scan_processes
    investigated3 = []
    rad3._investigate_bounded = fake_investigate_bounded
    rad3._save_baseline_locked = fake_save_baseline_locked
    await rad3._poll_once()
    assert len(investigated) == 1, "unrelated -- sanity check on the shared 'investigated' list from Test 7"
    print("Test 8 (stable, unchanged port: no re-investigation, no noise) PASSED")

    await bus.shutdown()

    tce_config = TceConfig()
    listener = CorrelationCandidateEvent(
        event_id="rad-1", timestamp=1.0, category="REMOTE_ACCESS_BACKDOOR", severity="HIGH",
        message="Listener tidak dikelola", source_module="remote_access_detector",
        user="attacker", pid=613841, executable="/tmp/.x/backdoor", process_fingerprint="fp-1",
        port=29143,
        raw_metadata={
            "bind_address": "0.0.0.0", "local_endpoint": "0.0.0.0:29143", "exposure": "INTERNET_EXPOSED",
            "bind_classification": "ALL_INTERFACES", "classification": "SUSPICIOUS",
            "evidence": ["unmanaged", "internet_exposed"], "score": 35,
            "score_breakdown": [{"signal": "unmanaged", "label": "Unmanaged", "points": 20}],
            "recommendation": "Investigate.",
        },
    )
    webshell = CorrelationCandidateEvent(
        event_id="wsh-1", timestamp=2.0, category="FILE_INTEGRITY_CHANGE", severity="CRITICAL",
        message="shell.php created", source_module="webshell_detector", user="attacker",
    )
    classified = [classify_event(e, tce_config) for e in (listener, webshell)]
    result = score_group(group_classified_events(classified)[0], tce_config)
    forensics = _extract_listener_forensics(result)
    assert forensics is not None
    assert forensics["exposure"] == "INTERNET_EXPOSED"
    assert forensics["listener_classification"] == "SUSPICIOUS"
    assert forensics["listener_score"] == 35
    assert forensics["listener_recommendation"] == "Investigate."
    assert "classification" not in forensics, "must be renamed to listener_classification, not left bare"
    assert "score" not in forensics, "must be renamed to listener_score, not left bare"

    webshell_only_group = [
        classify_event(e, tce_config) for e in (
            webshell,
            CorrelationCandidateEvent(
                event_id="wsh-2", timestamp=3.0, category="FILE_INTEGRITY_CHANGE", severity="CRITICAL",
                message="backdoor.php created", source_module="webshell_detector", user="attacker",
            ),
        )
    ]
    result2 = score_group(group_classified_events(webshell_only_group)[0], tce_config)
    assert _extract_listener_forensics(result2) is None, "must never fabricate listener forensics for a non-listener group"
    print("Test 9 (TCE raw_metadata pass-through; never fabricated for non-listener groups) PASSED")

    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    meta = {
        "label": result.tier, "confidence": result.total, "correlation_id": "corr-1",
        "project": None, "user": "attacker", "process": listener.executable,
        "process_fingerprint": listener.process_fingerprint, "port": 29143, "pid": 613841,
    }
    meta.update(forensics)
    event = BaseEvent(
        source_module="tce", category=EventCategory.CORRELATED_THREAT, severity=Severity.HIGH,
        message=result.tier, raw="", metadata=meta,
    )
    payload = dispatcher._build_payload(event)
    field_names = {f["name"] for f in payload["embeds"][0]["fields"]}
    required = {
        "Target", "Exposure", "Process", "Executable", "Listener Score Breakdown", "Recommendation",
    }
    missing = required - field_names
    assert not missing, f"CORRELATED_THREAT is missing required forensic fields: {missing}"
    all_values = " ".join(str(f["value"]) for f in payload["embeds"][0]["fields"])
    assert all_values != "Remote Access Backdoor (+40)"
    print("Test 10 (CORRELATED_THREAT Discord payload has full forensic context, not a bare evidence line) PASSED")

    trusted_listener = CorrelationCandidateEvent(
        event_id="rad-2", timestamp=1.0, category="REMOTE_ACCESS_BACKDOOR", severity="INFO",
        message="Listener terverifikasi", source_module="remote_access_detector",
        user="deploy", pid=4242, executable="/usr/bin/chrome",
        raw_metadata={
            "process_classification": "TRUSTED_PUPPETEER", "classification": "TRUSTED_AUTOMATION",
            "exposure": "LOCAL_ONLY", "bind_classification": "LOOPBACK_ONLY",
        },
    )
    trusted_listener_2 = CorrelationCandidateEvent(
        event_id="rad-3", timestamp=2.0, category="REMOTE_ACCESS_BACKDOOR", severity="INFO",
        message="Listener terverifikasi lagi", source_module="remote_access_detector",
        user="deploy", pid=4243, executable="/usr/bin/chrome",
    )
    classified_trusted = [classify_event(e, tce_config) for e in (trusted_listener, trusted_listener_2)]
    result_trusted = score_group(group_classified_events(classified_trusted)[0], tce_config)
    assert result_trusted.total == 0
    assert result_trusted.total < tce_config.min_publish_confidence
    forensics_trusted = _extract_listener_forensics(result_trusted)
    assert forensics_trusted["listener_classification"] == "TRUSTED_AUTOMATION"
    print("Test 11 (trusted Chrome/Puppeteer listener still never crosses publish threshold) PASSED")

    print("\nALL W27 LISTENER FORENSICS TESTS PASSED")


asyncio.run(main())
