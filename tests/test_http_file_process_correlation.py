import asyncio
import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, RemoteAccessDetectorConfig, TceConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.process_correlation import _Correlation
from discord_integration.webhook import DiscordWebhookDispatcher
import modules.remote_access_detector as rad_mod
from modules.remote_access_detector import RemoteAccessDetector
from modules.process_anomaly_detector import ProcessSnapshot
from modules.threat_correlation_engine import (
    ClassifiedEvent, CorrelationCandidateEvent, GroupResult, build_event_chain,
    classify_event, group_classified_events, score_group,
)


async def main():
    tce_config = TceConfig()

    http_event = CorrelationCandidateEvent(
        event_id="http-1", timestamp=1000.0, category="WEB_ATTACK_RCE", severity="HIGH",
        message="SQLi/RCE attempt", source_module="nginx_monitor",
        webroot="/home/victim/htdocs/example.com", source_ip="203.0.113.9",
    )
    file_event = CorrelationCandidateEvent(
        event_id="file-1", timestamp=1001.0, category="FILE_INTEGRITY_CHANGE", severity="CRITICAL",
        message="shell.php created", source_module="webshell_detector",
        webroot="/home/victim/htdocs/example.com", path="/home/victim/htdocs/example.com/public/shell.php",
    )
    process_event = CorrelationCandidateEvent(
        event_id="proc-1", timestamp=1002.0, category="PROCESS_ANOMALY", severity="CRITICAL",
        message="/tmp/.x spawned", source_module="process_anomaly_detector",
        webroot="/home/victim/htdocs/example.com", pid=9999, discord_eligible=True,
        rules=["SHELL_SPAWN_NETWORK_TOOL"],
    )
    classified = [classify_event(e, tce_config) for e in (http_event, file_event, process_event)]
    groups = group_classified_events(classified)
    assert len(groups) == 1, f"all 3 events share the same webroot key -- must form a single group: {groups}"
    group = groups[0]
    kinds = {c.kind for c in group}
    assert kinds == {"Web attack (unconfirmed)", "Webshell Signature", "Reverse Shell"}, kinds

    result = score_group(group, tce_config)
    chain = build_event_chain(result)
    assert len(chain) == 3, chain
    assert [c["hop"] for c in chain] == ["HTTP_REQUEST", "FILE_CHANGED", "PROCESS_CREATED"], chain
    assert [c["event_id"] for c in chain] == ["http-1", "file-1", "proc-1"], (
        "chain must reference the ORIGINAL raw event_ids -- nothing is fabricated or deleted"
    )
    print("Scenario 16 (HTTP request -> file change -> new process: one group, ordered event chain) PASSED")

    file_event_2 = CorrelationCandidateEvent(
        event_id="file-2", timestamp=5.0, category="FILE_INTEGRITY_CHANGE", severity="MEDIUM",
        message="config.js modified", source_module="file_integrity_detector",
        webroot="/home/other/htdocs/other.com",
    )
    file_event_3 = CorrelationCandidateEvent(
        event_id="file-3", timestamp=6.0, category="FILE_INTEGRITY_CHANGE", severity="MEDIUM",
        message="README modified", source_module="file_integrity_detector",
        webroot="/home/other/htdocs/other.com",
    )
    classified2 = [classify_event(e, tce_config) for e in (file_event_2, file_event_3)]
    result2 = score_group(classified2, tce_config)
    assert build_event_chain(result2) == [], "a single-stage cluster is not an HTTP->FILE->PROCESS chain"
    print("Scenario 16b (same-stage cluster, no HTTP/process hop -- event_chain stays empty) PASSED")

    real_read_snapshot = rad_mod.read_process_snapshot
    real_correlate_pid = rad_mod.correlate_pid
    try:
        def fake_read_snapshot(pid):
            if pid == 31337:
                return ProcessSnapshot(
                    pid=31337, ppid=500, uid=1000, gid=1000,
                    exe="/home/newus/.local/bin/backdoor", cwd="/home/newus/project",
                    cmdline="/home/newus/.local/bin/backdoor --listen 10723",
                    username="newus", start_time=time.time(), project=None, network_active=True,
                    start_time_ticks=313370,
                )
            if pid == 500:
                return ProcessSnapshot(
                    pid=500, ppid=1, uid=1000, gid=1000, exe="/usr/bin/node", cwd="/home/newus/project",
                    cmdline="node index.js", username="newus", start_time=time.time() - 100,
                    project=None, network_active=False, start_time_ticks=5000,
                )
            return None

        async def fake_correlate_pid(pid, username, ppid, *, port=None, conf_directory=None, resolve_cloudpanel=True):
            return _Correlation()

        rad_mod.read_process_snapshot = fake_read_snapshot
        rad_mod.correlate_pid = fake_correlate_pid

        bus = EventBus()
        events = []

        async def collector(e):
            events.append(e)

        sub = await bus.subscribe("c", collector, categories=None)
        rad = RemoteAccessDetector(bus, RemoteAccessDetectorConfig(legitimacy_score_threshold=60))
        await rad._investigate(31337, port=10723, process_name="backdoor")
        await sub.queue.join()
        assert len(events) == 1
        meta = events[0].metadata
        assert meta["pid"] == 31337
        assert meta["port"] == 10723
        assert meta["linux_user"] == "newus"
        assert meta["parent_user"] == "newus"
        assert meta["parent_executable"] == "/usr/bin/node"
        assert meta["command_line"] == "/home/newus/.local/bin/backdoor --listen 10723"
        assert meta["process_fingerprint"], "listener process must get a computed fingerprint"
        assert "deployment_status" in meta
        print("Scenario 17 (new listener -- enriched with parent/user/fingerprint/command context) PASSED")
    finally:
        rad_mod.read_process_snapshot = real_read_snapshot
        rad_mod.correlate_pid = real_correlate_pid

    assert meta["linux_user"] == "newus"
    assert meta["executable"] == "/home/newus/.local/bin/backdoor"
    assert meta["cwd"] == "/home/newus/project"
    assert meta["parent_process"] == "node"
    print("Scenario 19-22 (REMOTE_ACCESS_BACKDOOR carries user/executable/cwd/parent context) PASSED")

    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    sparse_event = BaseEvent(
        source_module="process_anomaly_detector", category=EventCategory.PROCESS_ANOMALY,
        severity=Severity.MEDIUM, message="test", raw="",
        metadata={"pid": 42, "user": "newus"},
    )
    payload = dispatcher._build_payload(sparse_event)
    fields = {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}
    for name in (
        "Project", "Project Path", "Executable", "Executable SHA256", "Command",
        "Working Directory", "Parent PID", "Parent User", "Parent Executable",
        "Process Fingerprint", "Start Time", "Listening Ports", "Related File",
        "Deployment", "Correlation ID",
    ):
        assert fields.get(name) == "UNKNOWN", f"{name} must render as UNKNOWN when unavailable, got {fields.get(name)!r}"
    assert fields["PID"] == "42"
    assert fields["User"] == "newus"
    print("Scenario 23 (fields RTSA has no data for render as literal UNKNOWN, never guessed) PASSED")

    print("\nALL HTTP->FILE->PROCESS CORRELATION / REMOTE-ACCESS ENRICHMENT TESTS PASSED")
    print("(Scenario 24 -- existing PRIORITAS 1-4 tests unmodified -- verified by the full suite run, not here)")


asyncio.run(main())
