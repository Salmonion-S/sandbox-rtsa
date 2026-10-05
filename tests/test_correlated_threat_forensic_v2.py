import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import TceConfig
from modules.threat_correlation_engine import (
    CorrelationCandidateEvent, ContributorGroup, classify_event, group_classified_events, score_group,
    build_message, build_assessment, build_recommendation, build_clean_score_breakdown, build_process_tree,
    _event_identity,
)
from discord_integration.webhook import _split_embed_for_send


def _pad_event(
    event_id, timestamp, *, pid, ppid=100, uid=1083, gid=1083, user="simpuskes-api",
    exe="/usr/bin/node", cwd="/home/simpuskes-api/htdocs/api.example.com", cmdline="node server.js",
    project="simpuskes-api", process_fingerprint="fp-a", parent_fingerprint="fp-parent",
    parent_user="simpuskes-api", parent_uid=1083, parent_executable="/usr/bin/pm2",
    remote_endpoints=None, discord_eligible=True, confidence=50, start_time=1000.0,
    process_age_seconds=120.0, rules=None,
) -> CorrelationCandidateEvent:
    remote_endpoints = remote_endpoints or []
    if rules is None:
        rules = ["SHELL_SPAWN_NETWORK_TOOL"] if discord_eligible else []
    kind_category = "PROCESS_ANOMALY"
    raw_metadata = {
        "pid": pid, "ppid": ppid, "user": user, "uid": uid, "gid": gid,
        "exe": exe, "exe_basename": exe.rsplit("/", 1)[-1], "cwd": cwd, "cmdline": cmdline,
        "project": project, "project_root": f"/home/{user}/htdocs/{project}",
        "process_fingerprint": process_fingerprint, "parent_fingerprint": parent_fingerprint,
        "parent_user": parent_user, "parent_uid": parent_uid, "parent_executable": parent_executable,
        "parent_ppid": 1, "executable_sha256": "deadbeef" * 8,
        "start_time": start_time, "process_age_seconds": process_age_seconds,
        "listening_ports": [], "deployment_status": "INACTIVE",
        "remote_endpoints": [{"ip": ip, "port": port} for ip, port in remote_endpoints],
        "discord_eligible": discord_eligible, "rules": rules,
    }
    return CorrelationCandidateEvent(
        event_id=event_id, timestamp=timestamp, category=kind_category, severity="MEDIUM",
        message=f"Anomali proses (pid={pid})", source_module="process_anomaly_detector",
        project=project, pid=pid, ppid=ppid, user=user, executable=exe, command_line=cmdline,
        confidence=confidence, process_fingerprint=process_fingerprint,
        discord_eligible=discord_eligible, rules=rules,
        remote_endpoints=remote_endpoints, raw_metadata=raw_metadata,
    )


def _fim_event(event_id, timestamp, *, path, project="simpuskes-api", user="simpuskes-api",
                change_type="created", domain="api.example.com") -> CorrelationCandidateEvent:
    return CorrelationCandidateEvent(
        event_id=event_id, timestamp=timestamp, category="FILE_INTEGRITY_CHANGE", severity="HIGH",
        message=f"File berubah: {path}", source_module="file_integrity_detector",
        project=project, user=user, path=path, domain=domain, confidence=80,
        raw_metadata={
            "path": path, "change_type": change_type, "sha256_old": None,
            "sha256_new": "cafebabe" * 8, "linux_user": user, "domain": domain,
        },
    )


def _web_attack_event(event_id, timestamp, *, domain="api.example.com", source_ip="203.0.113.9",
                       success=True) -> CorrelationCandidateEvent:
    return CorrelationCandidateEvent(
        event_id=event_id, timestamp=timestamp, category="WEB_ATTACK_RCE", severity="HIGH",
        message="RCE signature cocok", source_module="nginx_monitor",
        domain=domain, source_ip=source_ip, confidence=85, pattern="cmdi_structural",
        raw_metadata={
            "full_url": f"https://{domain}/api/upload", "http_method": "POST",
            "technique": "Command Injection", "classification": "CONFIRMED_SUCCESS" if success else "ATTEMPT",
            "success": success,
        },
    )


async def main() -> None:
    tce_config = TceConfig()

    rs1 = _pad_event("rs1", 100.0, pid=9001, process_fingerprint="fp-rs1", remote_endpoints=[("1.2.3.4", 4444)])
    companion = _fim_event("fim-companion", 101.0, path="/home/simpuskes-api/htdocs/simpuskes-api/x.php",
                            project="simpuskes-api", user="simpuskes-api")
    classified = [classify_event(e, tce_config) for e in (rs1, companion)]
    assert classified[0].kind == "Reverse Shell", classified[0].kind
    groups = group_classified_events(classified)
    assert len(groups) == 1
    result = score_group(groups[0], tce_config)
    breakdown = build_clean_score_breakdown(result)
    rs_entries = [b for b in breakdown if b["kind"] == "Reverse Shell"]
    assert len(rs_entries) == 1
    assert "PID 9001" in rs_entries[0]["detail"], rs_entries[0]
    message = build_message("Likely Compromise", result)
    assert "Reverse Shell x" not in message, "must never collapse a single contributor into an x-suffixed line"
    print("Test 1 (single reverse shell: itemized detail, no bare score) PASSED")

    rs_a = _pad_event("rsa", 100.0, pid=9001, process_fingerprint="fp-A", remote_endpoints=[("1.2.3.4", 4444)])
    rs_b = _pad_event("rsb", 100.5, pid=9002, process_fingerprint="fp-B", remote_endpoints=[("5.6.7.8", 5555)])
    classified = [classify_event(e, tce_config) for e in (rs_a, rs_b)]
    groups = group_classified_events(classified)
    assert len(groups) == 1, "same project/user must still union them into one group"
    result = score_group(groups[0], tce_config)
    breakdown = build_clean_score_breakdown(result)
    rs_entries = [b for b in breakdown if b["kind"] == "Reverse Shell"]
    assert len(rs_entries) == 2, f"two genuinely independent reverse shells must both count: {rs_entries}"
    single_weight = tce_config.detector_weights.get("Reverse Shell", 0)
    assert result.total == min(100, single_weight * 2), (result.total, single_weight)
    pids_seen = {e["detail"].split(",")[0] for e in rs_entries}
    assert len(pids_seen) == 2, "each contributor line must show its OWN distinguishing PID"
    print("Test 2 (two independent reverse shells: both counted, distinct detail) PASSED")

    same_a = _pad_event("sa1", 100.0, pid=9001, process_fingerprint="fp-same", remote_endpoints=[("9.9.9.9", 1234)])
    same_b = _pad_event("sa2", 105.0, pid=9001, process_fingerprint="fp-same", remote_endpoints=[("9.9.9.9", 1234)])
    classified = [classify_event(e, tce_config) for e in (same_a, same_b)]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    assert len(result.contributor_groups) == 1, "identical identity must collapse to ONE contributor group"
    group = result.contributor_groups[0]
    assert group.occurrences == 2, group.occurrences
    assert group.weight == tce_config.detector_weights.get("Reverse Shell", 0), (
        "weight must be counted once, never doubled by the raw-duplicate observation"
    )
    assert group.first_seen == 100.0 and group.last_seen == 105.0
    print("Test 3 (same reverse shell observed twice: score counted once, occurrences=2) PASSED")

    anomaly_a = _pad_event(
        "an1", 200.0, pid=8001, process_fingerprint="fp-anom", discord_eligible=False, confidence=15,
    )
    anomaly_b = _pad_event(
        "an2", 210.0, pid=8001, process_fingerprint="fp-anom", discord_eligible=False, confidence=15,
    )
    classified = [classify_event(e, tce_config) for e in (anomaly_a, anomaly_b)]
    assert classified[0].kind == "Process anomaly"
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    assert len(result.contributor_groups) == 1
    assert result.contributor_groups[0].occurrences == 2
    print("Test 4 (same PID repeated Process anomaly: aggregated, not double-counted) PASSED")

    diff_a = _pad_event("da1", 300.0, pid=7001, uid=1000, cwd="/home/usera/htdocs/site", user="usera",
                         process_fingerprint="fp-diff-a")
    diff_b = _pad_event("da2", 300.5, pid=7002, uid=2000, cwd="/home/userb/htdocs/site", user="userb",
                         project="userb", process_fingerprint="fp-diff-b")
    classified = [classify_event(e, tce_config) for e in (diff_a, diff_b)]
    identities = {_event_identity(c.event, c.kind) for c in classified}
    assert len(identities) == 2, "different fingerprint must never collapse to the same identity"
    print("Test 5 (different PID/context, same basename: distinct identity, not basename-alone) PASSED")

    rs = _pad_event("uidtest", 100.0, pid=9001, user="simpuskes-api", uid=1083)
    classified = [classify_event(e, tce_config) for e in (rs, companion)]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    from modules.threat_correlation_engine import _process_contributor_payload
    process_groups = [g for g in result.contributor_groups if g.kind in ("Reverse Shell", "Process anomaly")]
    payload = _process_contributor_payload(process_groups[0])
    assert payload["user"] == "simpuskes-api" and payload["uid"] == 1083
    print("Test 6 (UID resolution: username carried through, not a bare UID) PASSED")

    assert payload["parent_user"] == "simpuskes-api"
    assert payload["parent_executable"] == "/usr/bin/pm2"
    assert payload["project"] == "simpuskes-api"
    assert payload["deployment_status"] == "INACTIVE"
    tree = build_process_tree([payload])
    assert any("PID 9001" in hop for hop in tree), tree
    assert any("pm2" in hop.lower() for hop in tree), tree
    print("Test 7-8 (parent process + project/deployment enrichment reach payload + tree) PASSED")

    rs_net = _pad_event("nettest", 100.0, pid=9001, remote_endpoints=[("198.51.100.7", 4444)])
    classified = [classify_event(e, tce_config) for e in (rs_net, companion)]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    process_groups = [g for g in result.contributor_groups if g.kind == "Reverse Shell"]
    payload = _process_contributor_payload(process_groups[0])
    assert payload["remote_endpoints"] == [{"ip": "198.51.100.7", "port": 4444}]

    rs_no_net = _pad_event("nonettest", 100.0, pid=9002, remote_endpoints=None)
    classified = [classify_event(e, tce_config) for e in (rs_no_net, companion)]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    process_groups = [g for g in result.contributor_groups if g.kind == "Reverse Shell"]
    payload = _process_contributor_payload(process_groups[0])
    assert payload["remote_endpoints"] is None, "must never fabricate a remote endpoint when none was observed"
    print("Test 9 (network endpoint enrichment: real data through, never fabricated) PASSED")

    rs_secret = _pad_event("secrettest", 100.0, pid=9003, cmdline="node server.js --api-key=[REDACTED]")
    classified = [classify_event(e, tce_config) for e in (rs_secret, companion)]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    process_groups = [g for g in result.contributor_groups if g.kind == "Reverse Shell"]
    payload = _process_contributor_payload(process_groups[0])
    assert "[REDACTED]" in payload["cmdline"]
    assert "sk-" not in payload["cmdline"]
    print("Test 10 (command line sanitization: redacted value carried through unchanged) PASSED")

    rs_fim = _pad_event("fimrs", 100.0, pid=9004, process_fingerprint="fp-fim-rs")
    fim = _fim_event("fim1", 101.0, path="/home/simpuskes-api/htdocs/simpuskes-api/shell.php",
                      project="simpuskes-api", user="simpuskes-api")
    classified = [classify_event(e, tce_config) for e in (rs_fim, fim)]
    groups = group_classified_events(classified)
    assert len(groups) == 1
    result = score_group(groups[0], tce_config)
    from modules.threat_correlation_engine import _fim_contributor_payload
    fim_groups = [g for g in result.contributor_groups if g.kind == "FIM modify"]
    assert len(fim_groups) == 1
    fim_payload = _fim_contributor_payload(fim_groups[0])
    assert fim_payload["path"].endswith("shell.php")
    assert fim_payload["linux_user"] == "simpuskes-api"
    print("Test 11 (FIM + reverse shell correlation: fim_contributors populated) PASSED")

    rs_web = _pad_event("webrs", 100.0, pid=9005, project="api.example.com")
    web = _web_attack_event("web1", 99.0, domain="api.example.com", source_ip="203.0.113.9", success=True)
    from modules.threat_correlation_engine import _web_attack_contributor_payload
    web_classified = classify_event(web, tce_config)
    fake_group = ContributorGroup(
        kind=web_classified.kind, identity="x", representative=web_classified,
        weight=web_classified.weight, occurrences=1, first_seen=99.0, last_seen=99.0,
    )
    web_payload = _web_attack_contributor_payload(fake_group)
    assert web_payload["domain"] == "api.example.com"
    assert web_payload["success"] is True
    assert web_payload["classification"] == "CONFIRMED_SUCCESS"

    web_attempt = _web_attack_event("web2", 99.0, success=False)
    web_attempt_classified = classify_event(web_attempt, tce_config)
    fake_group2 = ContributorGroup(
        kind=web_attempt_classified.kind, identity="y", representative=web_attempt_classified,
        weight=web_attempt_classified.weight, occurrences=1, first_seen=99.0, last_seen=99.0,
    )
    web_payload2 = _web_attack_contributor_payload(fake_group2)
    assert web_payload2["success"] is False
    assert web_payload2["classification"] == "ATTEMPT"
    print("Test 12 (web attack correlation: confirmed vs attempt never conflated) PASSED")

    mix_a1 = _pad_event("mixa1", 100.0, pid=9001, process_fingerprint="fp-mix-a", remote_endpoints=[("1.1.1.1", 1)])
    mix_a2 = _pad_event("mixa2", 102.0, pid=9001, process_fingerprint="fp-mix-a", remote_endpoints=[("1.1.1.1", 1)])
    mix_b1 = _pad_event("mixb1", 100.0, pid=9002, process_fingerprint="fp-mix-b", remote_endpoints=[("2.2.2.2", 2)])
    classified = [classify_event(e, tce_config) for e in (mix_a1, mix_a2, mix_b1)]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    assert len(result.contributor_groups) == 2, "2 raw duplicates of A + 1 B must yield exactly 2 contributor groups"
    assert result.total == min(100, single_weight * 2)
    print("Test 13 (score deduplication end-to-end: unique evidence count, not raw event count) PASSED")

    many_fields = [{"name": f"Field {i}", "value": "x", "inline": True} for i in range(40)]
    many_fields.insert(0, {"name": "Correlation ID", "value": "abc123", "inline": False})
    base_embed = {"title": "RTSA Alert — CORRELATED_THREAT", "color": 0xE74C3C, "fields": many_fields}
    parts = _split_embed_for_send(base_embed)
    assert len(parts) > 1, "a 41-field embed must be split into multiple parts"
    assert all(len(p["fields"]) <= 25 for p in parts), [len(p["fields"]) for p in parts]
    assert all(
        any(f.get("name") == "Correlation ID" for f in p["fields"]) for p in parts
    ), "every split part must still carry the Correlation ID field"
    small_embed = {"title": "x", "fields": many_fields[:5]}
    assert _split_embed_for_send(small_embed) == [small_embed], "a small embed must pass through unchanged"
    print("Test 14 (Discord embed field-count safety net: deterministic split, Correlation ID preserved) PASSED")

    from discord_integration.webhook import _field_or_unknown
    bare_payload = {"pid": 1234}
    assert _field_or_unknown("Primary Process GID", bare_payload.get("gid"))["value"] == "UNKNOWN"
    assert _field_or_unknown("Primary Process User", bare_payload.get("user"))["value"] == "UNKNOWN"
    print("Test 15-16 (missing forensic fields: None internally, UNKNOWN when rendered, never fabricated) PASSED")

    low_only = _pad_event("lowonly1", 100.0, pid=6001, discord_eligible=False, process_fingerprint="fp-low")
    low_only2 = _fim_event("lowfim", 101.0, path="/home/simpuskes-api/htdocs/simpuskes-api/readme.txt")
    classified = [classify_event(e, tce_config) for e in (low_only, low_only2)]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    assessment = build_assessment(result)
    assert assessment in ("Informational", "Suspicious activity -- low confidence"), assessment
    print("Test 17 (low-weight-only contributor never inflates assessment) PASSED")

    real_rs = _pad_event("realrs", 100.0, pid=9010, process_fingerprint="fp-real")
    context_event = CorrelationCandidateEvent(
        event_id="pm2ctx", timestamp=101.0, category="PM2_EVENT", severity="INFO",
        message="pm2 reload", source_module="pm2_monitor", project="simpuskes-api",
    )
    classified = [classify_event(e, tce_config) for e in (real_rs, context_event)]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    breakdown = build_clean_score_breakdown(result)
    assert all(b["kind"] != "PM2 event" for b in breakdown), "a weight-0 kind must never appear in Security Evidence"
    print("Test 18 (context-only kind never becomes a Security Evidence contributor) PASSED")

    from modules.threat_correlation_engine import _build_timeline_lines
    classified = [classify_event(e, tce_config) for e in (same_a, same_b)]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    timeline = _build_timeline_lines(result)
    assert any("2x" in line for line in timeline), timeline
    print("Test 19 (timeline surfaces occurrence count for collapsed duplicates) PASSED")

    many_dupes = [
        _pad_event(f"dupe{i}", 100.0 + i, pid=9001, process_fingerprint="fp-dupe", remote_endpoints=[("7.7.7.7", 7)])
        for i in range(10)
    ]
    classified = [classify_event(e, tce_config) for e in many_dupes]
    groups = group_classified_events(classified)
    result = score_group(groups[0], tce_config)
    assert result.total == single_weight, (
        f"10 raw observations of the SAME identity must score identically to 1: got {result.total}"
    )
    assert result.contributor_groups[0].occurrences == 10
    print("Test 20 (final score based on unique evidence, immune to raw event volume) PASSED")

    print("\nALL PRIORITAS 8 CORRELATED_THREAT FORENSIC OUTPUT 2.0 TESTS PASSED")


asyncio.run(main())
