import asyncio
import logging
import os
import sys
import time
from types import SimpleNamespace
from typing import List

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import psutil

import modules.process_anomaly_detector as process_anomaly_detector
from config.manager import ConfigValidationError, DiscordConfig, RTSAConfig, TceConfig
from core import correlation_enrichment as enrichment
from core import correlation_evidence as ce
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.correlation_alert import build_investigation_description
from discord_integration.webhook import DiscordWebhookDispatcher, discord_safe_inline
from modules import threat_correlation_engine as tce
from modules.host_persistence_detector import HostPersistenceDetector

NOW = 1_800_000_000.0
SSHD = "/usr/sbin/sshd"
SHA_A, SHA_B = "a" * 64, "b" * 64


def port_event(
    event_id, ts, pid, *, ppid=1, start=1000.0, exe=SSHD, sha=SHA_A, unit="ssh.service", port=23109,
    name=None, fp=None, user="root", bind="0.0.0.0", protocol="TCP", parent_name="systemd",
    source_module="host_persistence_detector", category="PERSISTENCE_NEW_PORT", severity="HIGH",
):
    name = name or (exe.rsplit("/", 1)[-1] if exe else "sshd")
    meta = {
        "port": port, "pid": pid, "ppid": ppid, "related_process": name, "parent_process_name": parent_name,
        "linux_user": user, "uid": 0, "gid": 0, "binary_path": exe, "cwd": "/", "cmdline": f"{exe} -D",
        "pid_create_time": start, "bind_address": bind, "protocol": protocol, "state": "LISTEN",
        "exposure": "INTERNET_EXPOSED", "process_fingerprint": fp or f"fp-{pid}", "executable_sha256": sha,
        "systemd_unit": unit, "first_seen": ts, "last_seen": ts, "classification": "UNVERIFIED",
    }
    meta = {k: v for k, v in meta.items() if v is not None}
    return tce.CorrelationCandidateEvent(
        event_id=event_id, timestamp=ts, category=category, severity=severity,
        message=f"Listening port baru terdeteksi: {port} (proses: {name})", source_module=source_module,
        pid=pid, ppid=ppid, user=user, port=port, process_fingerprint=meta.get("process_fingerprint"),
        confidence=80, raw_metadata=meta,
    )


def webshell_event(event_id, ts, *, user="root", path="/home/site/htdocs/x.php"):
    return tce.CorrelationCandidateEvent(
        event_id=event_id, timestamp=ts, category="WEBSHELL_DETECTED", severity="HIGH", message="webshell",
        source_module="webshell_detector", user=user, path=path, confidence=90,
        raw_metadata={"path": path, "linux_user": user, "change_type": "created", "sha256_new": "c" * 64},
    )


def fim_event(event_id, ts, *, user="root", path="/etc/cron.d/evil"):
    return tce.CorrelationCandidateEvent(
        event_id=event_id, timestamp=ts, category="FILE_INTEGRITY_CHANGE", severity="HIGH", message="fim",
        source_module="file_integrity_detector", user=user, path=path, confidence=80,
        raw_metadata={"path": path, "linux_user": user, "change_type": "modified", "sha256_old": "d" * 64,
                      "sha256_new": "e" * 64, "uid_new": 0},
    )


def score(events, config=None):
    config = config or TceConfig()
    classified = [tce.classify_event(e, config) for e in events]
    groups = tce.group_classified_events(classified)
    assert len(groups) == 1, f"expected one correlated group, got {len(groups)}"
    return tce.score_group(groups[0], config)


def by_pid(result):
    return {g.representative.event.pid: g for g in result.contributor_groups if g.weight > 0}


def make_engine(**overrides):
    config = TceConfig(enabled=True, min_publish_confidence=10, incident_stable_window_seconds=300.0, **overrides)
    engine = tce.ThreatCorrelationEngine(EventBus(), config)
    published: List[BaseEvent] = []
    engine.publish = published.append
    return engine, published, config


def dispatch(metadata, *, message="stored message"):
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    event = BaseEvent(
        source_module="tce", category=EventCategory.CORRELATED_THREAT, severity=Severity.MEDIUM,
        message=message, raw="", metadata=metadata,
    )
    return dispatcher._build_payload(event)["embeds"][0]


class FakeProbe:
    def __init__(self, *, process=None, unit="ssh.service", sockets=None, raises=None, delay=0.0):
        self.process_calls = self.unit_calls = self.socket_calls = 0
        self._process, self._unit, self._sockets, self._raises, self._delay = process, unit, sockets or [], raises, delay

    def process(self, pid):
        self.process_calls += 1
        if self._delay:
            time.sleep(self._delay)
        if self._raises is not None:
            raise self._raises
        if isinstance(self._process, dict):
            return self._process[pid]
        return self._process

    def systemd_unit(self, pid):
        self.unit_calls += 1
        if isinstance(self._unit, Exception):
            raise self._unit
        return self._unit

    def sockets(self, pid):
        self.socket_calls += 1
        return self._sockets


def live_process(pid, create_time, **kw):
    defaults = dict(name="sshd", exe=SSHD, cmdline=f"{SSHD} -D", cwd="/", user="root", uid=0, gid=0, ppid=1,
                    parent_name="systemd", parent_exe="/usr/lib/systemd/systemd")
    defaults.update(kw)
    return enrichment.LiveProcess(pid=pid, create_time=create_time, **defaults)


def test_1_identical_events_deduplicated():
    a = port_event("e1", NOW, 3757, start=NOW - 500)
    b = port_event("e2", NOW + 2, 3757, start=NOW - 500)
    result = score([a, b])
    groups = [g for g in result.contributor_groups if g.weight > 0]
    assert len(groups) == 1 and groups[0].occurrences == 2, "identical observations collapse into one group"
    assert result.total == 30 and result.independent_count == 1 and result.duplicate_count == 1
    ident = ce.build_evidence_identity(
        event_id="e1", kind="Persistence new port", category="PERSISTENCE_NEW_PORT", detector="d", severity="HIGH",
        confidence=80, timestamp=NOW, metadata=a.raw_metadata, pid=3757, port=23109,
    )
    assessments = ce.assess_evidence([(ident, 30, 1), (ident, 30, 1)], relationship_kinds={"Persistence new port"})
    assert [x.relationship for x in assessments] == [ce.INDEPENDENT, ce.SAME_EVENT]
    assert [x.contribution for x in assessments] == [30, 0]
    print("Test 1 (two identical events -> deduplicated, raw events untouched, score counted once) PASSED")


def test_2_same_service_different_pid_is_lifecycle():
    old = port_event("e1", NOW, 3757, start=NOW - 500)
    restarted = port_event("e2", NOW, 840, start=NOW - 90000)
    result = score([old, restarted])
    assert result.gross_total == 60 and result.total == 30, (result.gross_total, result.total)
    groups = by_pid(result)
    assert groups[3757].assessment.relationship == ce.INDEPENDENT and groups[3757].assessment.role == "PRIMARY"
    assert groups[840].assessment.relationship == ce.PROCESS_RESTART and groups[840].effective_weight == 0
    assert groups[840].assessment.related_to == "e1"
    assert result.independent_count == 1 and result.related_count == 1 and result.duplicate_count == 0
    assert "same executable" in groups[840].assessment.reason and "same systemd unit" in groups[840].assessment.reason
    lines = tce._build_evidence_lines(result)
    assert lines[0].startswith("✓ Persistence new port (+30)") and lines[1].startswith("↳ Persistence new port (+0 of +30, PROCESS_RESTART)")
    print("Test 2 (same service, different PID -> PROCESS_RESTART lifecycle evidence, effective score 30 not 60) PASSED")


def test_3_same_unit_and_port_not_automatically_independent():
    first = port_event("e1", NOW, 100, start=NOW - 900, sha=None)
    second = port_event("e2", NOW, 200, start=NOW - 10, sha=None)
    result = score([first, second])
    assert by_pid(result)[200].assessment.relationship in (ce.SAME_SERVICE, ce.PROCESS_RESTART)
    assert result.total == 30
    replaced = port_event("e3", NOW, 300, start=NOW - 5, sha=SHA_B)
    result2 = score([port_event("e1", NOW, 100, start=NOW - 900), replaced])
    assert by_pid(result2)[300].assessment.relationship == ce.INDEPENDENT
    assert ce.FLAG_HASH_CHANGED in by_pid(result2)[300].assessment.flags and result2.total == 60
    vague_a = port_event("e4", NOW, 400, unit=None, sha=None, start=NOW - 900)
    vague_b = port_event("e5", NOW, 500, unit=None, sha=None, start=NOW - 10)
    result3 = score([vague_a, vague_b])
    assert by_pid(result3)[500].assessment.relationship == ce.UNKNOWN and result3.total == 60
    print("Test 3 (same unit+port is not automatically independent; changed hash / unproven identity IS counted) PASSED")


def test_4_parent_child_classified():
    master = port_event("e1", NOW, 100, ppid=1, exe="/usr/sbin/nginx", unit="nginx.service", port=80, start=NOW - 900, name="nginx")
    worker = port_event("e2", NOW, 101, ppid=100, exe="/usr/sbin/nginx", unit="nginx.service", port=80, start=NOW - 899, name="nginx")
    result = score([master, worker])
    worker_group = by_pid(result)[101]
    assert worker_group.assessment.relationship == ce.PARENT_CHILD, worker_group.assessment.relationship
    assert worker_group.effective_weight == 0 and result.total == 30
    assert "child of" in worker_group.assessment.reason
    print("Test 4 (nginx master + worker sharing the port -> PARENT_CHILD, one lifecycle) PASSED")


def test_5_different_service_same_port_is_independent_and_suspicious():
    legit = port_event("e1", NOW, 100, start=NOW - 900)
    imposter = port_event("e2", NOW, 666, exe="/tmp/.x/sshd", unit=None, sha="f" * 64, start=NOW - 5, ppid=1)
    result = score([legit, imposter])
    verdict = by_pid(result)[666].assessment
    assert verdict.relationship == ce.INDEPENDENT and ce.FLAG_EXECUTABLE_CONFLICT in verdict.flags
    assert result.total == 60 and result.independent_count == 2
    meta = engine_publish(result)
    assert "suspicious" in meta["interpretation"].lower() and "writable location" in meta["interpretation"]
    print("Test 5 (different service on the same port -> INDEPENDENT + suspicious, both counted) PASSED")


def engine_publish(result, **kw):
    engine, published, _ = make_engine()
    engine._process_scored_group(result, NOW, **kw)
    assert published, "expected a publish"
    return published[-1].metadata


def test_6_unexpected_executable_hash_is_independent():
    a = port_event("e1", NOW, 100, start=NOW - 900)
    b = port_event("e2", NOW, 101, start=NOW - 10, sha=SHA_B)
    result = score([a, b])
    verdict = by_pid(result)[101].assessment
    assert verdict.relationship == ce.INDEPENDENT and ce.FLAG_HASH_CHANGED in verdict.flags
    assert "SHA256" in verdict.reason and result.total == 60
    meta = engine_publish(result)
    assert "different or modified executable" in meta["interpretation"]
    print("Test 6 (same socket, changed executable hash -> independent security evidence) PASSED")


def test_7_fim_plus_persistence_two_independent_signals():
    result = score([port_event("e1", NOW, 3757, start=NOW - 500), webshell_event("w1", NOW + 1)])
    assert result.independent_count == 2 and result.related_count == 0 and result.total == 80
    assert all(g.effective_weight == g.weight for g in result.contributor_groups)
    assert result.has_high_confidence and result.tier == "Possible Webshell"
    fim_result = score([port_event("e1", NOW, 3757, start=NOW - 500), fim_event("f1", NOW + 1)])
    assert fim_result.independent_count == 2 and fim_result.total == 35
    meta = engine_publish(fim_result)
    assert meta["fim_context"] and meta["fim_context"][0]["path"] == "/etc/cron.d/evil"
    print("Test 7 (persistence + FIM/webshell -> two independent signals, still add up) PASSED")


def test_8_ssh_bruteforce_plus_login_correlated():
    ip = "203.0.113.50"
    brute = tce.CorrelationCandidateEvent(
        event_id="b1", timestamp=NOW, category="BRUTE_FORCE", severity="HIGH", message="brute", source_module="analyzer",
        source_ip=ip, raw_metadata={"source_ip": ip},
    )
    login = tce.CorrelationCandidateEvent(
        event_id="l1", timestamp=NOW + 30, category="SSH_LOGIN_AFTER_BRUTE_FORCE", severity="CRITICAL", message="login",
        source_module="analyzer", source_ip=ip, user="root",
        raw_metadata={"source_ip": ip, "username": "root", "auth_method": "publickey", "success": True,
                      "fingerprint": "SHA256:abc", "key_owner": "ops@example.com", "session_id": "77:1", "ssh_port": 23109},
    )
    result = score([brute, login])
    kinds = {g.kind for g in result.contributor_groups}
    assert kinds == {"Brute force", "SSH login after brute force"}, kinds
    assert result.independent_count == 2 and result.total == 50
    meta = engine_publish(result)
    ssh = meta["ssh_context"]
    assert ssh["brute_force_correlation"] == "YES" and ssh["successful_login_correlation"] == "YES"
    assert ssh["source_ip"] == ip and ssh["auth_method"] == "publickey" and ssh["key_owner"] == "ops@example.com"
    text = build_investigation_description(meta, escape=discord_safe_inline)
    assert "SSH CONTEXT" in text and "Successful Login Correlation: YES" in text and "Key Owner" in text
    print("Test 8 (SSH brute force + successful login -> correlated, SSH context reused from the events) PASSED")


def test_9_inbound_never_reported_as_outbound():
    listening = {80, 443}
    assert ce.classify_direction(state="ESTABLISHED", local_port=443, remote_port=51234, listening_ports=listening) == ce.DIRECTION_INBOUND
    assert ce.classify_direction(state="ESTABLISHED", local_port=51234, remote_port=443, listening_ports=listening) == ce.DIRECTION_OUTBOUND
    assert ce.classify_direction(state="LISTEN", local_port=443, remote_port=None) == ce.DIRECTION_LISTENING
    assert ce.classify_direction(state="ESTABLISHED", local_port=8080, remote_port=9999) == ce.DIRECTION_UNKNOWN, "never guess"

    Addr = lambda ip, port: SimpleNamespace(ip=ip, port=port)
    conns = [
        SimpleNamespace(status=psutil.CONN_LISTEN, laddr=Addr("0.0.0.0", 443), raddr=(), type=1),
        SimpleNamespace(status=psutil.CONN_ESTABLISHED, laddr=Addr("10.0.0.5", 443), raddr=Addr("198.51.100.7", 51234), type=1),
        SimpleNamespace(status=psutil.CONN_ESTABLISHED, laddr=Addr("10.0.0.5", 40000), raddr=Addr("203.0.113.9", 443), type=1),
    ]

    class FakeProcess:
        def __init__(self, pid):
            pass

        def connections(self, kind="inet"):
            return conns

    original = process_anomaly_detector.psutil.Process
    process_anomaly_detector.psutil.Process = FakeProcess
    try:
        details = process_anomaly_detector._get_established_connection_directions(1234)
    finally:
        process_anomaly_detector.psutil.Process = original
    assert details[("198.51.100.7", 51234)]["direction"] == ce.DIRECTION_INBOUND
    assert details[("203.0.113.9", 443)]["direction"] == ce.DIRECTION_OUTBOUND

    item = {"kind": "Process anomaly", "category": "PROCESS_ANOMALY", "weight": 15, "contribution": 15, "role": "PRIMARY",
            "relationship": "INDEPENDENT", "pid": 1234, "process_name": "nginx", "executable": "/usr/sbin/nginx",
            "network": ce.network_context(ce.EvidenceIdentity(
                event_id="x", state="ESTABLISHED", local_address="10.0.0.5", local_port=443,
                remote_address="198.51.100.7", remote_port=51234, direction=ce.DIRECTION_INBOUND, protocol="TCP"))}
    from discord_integration.correlation_alert import evidence_block_lines
    rendered = "\n".join(evidence_block_lines(item, "standard", discord_safe_inline))
    assert "INBOUND\\_ACCEPTED" in rendered and "OUTBOUND" not in rendered
    print("Test 9 (accepted inbound nginx socket is INBOUND_ACCEPTED, never OUTBOUND; unknown stays UNKNOWN) PASSED")


def test_10_missing_process_renders_unknown():
    item = {"kind": "Process anomaly", "category": "PROCESS_ANOMALY", "weight": 15, "contribution": 15,
            "role": "PRIMARY", "relationship": "INDEPENDENT", "pid": 4242}
    from discord_integration.correlation_alert import evidence_block_lines
    rendered = "\n".join(evidence_block_lines(item, "standard", discord_safe_inline))
    assert "Process: UNKNOWN · PID 4242" in rendered and "Executable: UNKNOWN" in rendered
    assert "User: UNKNOWN" in rendered and "Executable SHA256: UNKNOWN" in rendered
    ident = ce.EvidenceIdentity(event_id="x", pid=4242, timestamp=NOW)
    report = enrichment.enrich_identities(
        [ident], cache=enrichment.EnrichmentCache(process_ttl=10, service_ttl=30, network_ttl=5),
        probe=FakeProbe(raises=psutil.NoSuchProcess(4242)),
    )
    assert ident.enrichment_status == enrichment.STATUS_PROCESS_GONE and ident.process_name is None
    assert report.enriched == 0
    assert "executable" in ident.missing_process_fields()
    print("Test 10 (missing process -> UNKNOWN rendered, nothing fabricated) PASSED")


def test_11_process_exits_before_enrichment():
    logging.disable(logging.CRITICAL)
    for exc, expected in (
        (psutil.NoSuchProcess(1), enrichment.STATUS_PROCESS_GONE), (psutil.AccessDenied(1), enrichment.STATUS_ACCESS_DENIED),
        (ProcessLookupError(), enrichment.STATUS_PROCESS_GONE), (RuntimeError("boom"), enrichment.STATUS_ERROR),
    ):
        ident = ce.EvidenceIdentity(event_id="x", pid=1, timestamp=NOW)
        report = enrichment.enrich_identities(
            [ident], cache=enrichment.EnrichmentCache(process_ttl=10, service_ttl=30, network_ttl=5), probe=FakeProbe(raises=exc),
        )
        assert ident.enrichment_status == expected and report.enriched == 0, (exc, ident.enrichment_status)

    async def through_engine():
        engine, published, config = make_engine()
        engine._enrichment_probe = FakeProbe(raises=psutil.NoSuchProcess(3757))
        events = [port_event("e1", NOW, 3757, start=None, unit=None, exe=None, sha=None), port_event("e2", NOW, 840, start=None, unit=None, exe=None, sha=None)]
        classified = [tce.classify_event(e, config) for e in events]
        group = tce.group_classified_events(classified)[0]
        result = tce.score_group(group, config)
        new_result, summary = await engine._enrich_result(group, result, asyncio.get_running_loop())
        assert new_result.total == result.total and summary["enriched"] == 0
        assert summary["statuses"] == {enrichment.STATUS_PROCESS_GONE: 2}
        engine._process_scored_group(new_result, NOW, enrichment=summary)
        assert published and published[0].metadata["enrichment"]["statuses"] == {enrichment.STATUS_PROCESS_GONE: 2}
    asyncio.run(through_engine())
    logging.disable(logging.NOTSET)
    print("Test 11 (process gone/denied/erroring before enrichment -> no exception, evidence published as reported) PASSED")


def test_12_systemd_unit_unavailable_degrades_gracefully():
    for unit in (None, OSError("cgroup unreadable")):
        ident = ce.EvidenceIdentity(event_id="x", pid=77, timestamp=NOW, start_time=NOW - 100)
        live = live_process(77, NOW - 100)
        report = enrichment.enrich_identities(
            [ident], cache=enrichment.EnrichmentCache(process_ttl=10, service_ttl=30, network_ttl=5),
            probe=FakeProbe(process=live, unit=unit),
        )
        assert ident.enrichment_status == enrichment.STATUS_OK and ident.process_name == "sshd", ident.enrichment_status
        assert ident.systemd_unit is None, "an unknown unit stays unknown"
        assert report.enriched == 1 and "executable" in ident.enriched_fields
    unitless_a = port_event("e1", NOW, 100, unit=None, sha=None, start=NOW - 900)
    unitless_b = port_event("e2", NOW, 200, unit=None, sha=None, start=NOW - 10)
    assert score([unitless_a, unitless_b]).total == 60, "no unit and no hash: never assumed to be the same service"
    print("Test 12 (systemd unit unavailable -> graceful degradation, conservative classification) PASSED")


def test_13_formatter_handles_missing_fields():
    minimal = {"investigation_v2": True}
    assert build_investigation_description(minimal, escape=discord_safe_inline)
    sparse = {
        "investigation_v2": True, "label": "Suspicious Activity", "confidence": 30,
        "evidence_items": [{"kind": "Persistence new port", "weight": 30, "contribution": 30, "role": "PRIMARY"}],
    }
    text = build_investigation_description(sparse, escape=discord_safe_inline, server_name="Server2")
    assert "EVIDENCE #0" in text or "EVIDENCE" in text and "Server2" in text
    embed = dispatch(sparse)
    assert embed["description"] and "WHY THIS ALERT FIRED" in embed["description"]
    update = {"investigation_v2": True, "lifecycle_state": "UPDATED", "confidence": 61, "label": "Potential Intrusion",
              "new_evidence": [{"kind": "FIM modify", "weight": 5, "event_id": "zz"}], "evidence_items": []}
    assert "Update #2" in build_investigation_description(update, escape=discord_safe_inline)
    print("Test 13 (Discord formatter survives missing/sparse metadata) PASSED")


def test_14_large_evidence_bounded():
    events = [port_event(f"e{i}", NOW + i, 1000 + i, port=20000 + i, exe=f"/opt/app{i}/bin/srv{i}", unit=f"app{i}.service",
                         sha=f"{i:064x}", start=NOW - 5000 + i) for i in range(60)]
    result = score(events, TceConfig(max_evidence_per_correlation=20))
    assert result.independent_count == 60 and result.total == 100 and result.score_cap_applied
    engine, published, _ = make_engine(max_evidence_per_correlation=20)
    engine._process_scored_group(result, NOW)
    meta = published[0].metadata
    assert len(meta["evidence_items"]) == 20 and meta["evidence_omitted"] == 40
    assert len(meta["evidence_event_ids"]) <= 200
    description = build_investigation_description(meta, escape=discord_safe_inline)
    assert len(description) <= 4000, len(description)
    assert "more evidence item" in description
    embed = dispatch(meta)
    assert len(embed["description"]) <= 4000
    print("Test 14 (60 independent evidence items -> 20 shown, 40 counted as omitted, alert <= 4000 chars) PASSED")


def test_15_duplicate_correlation_no_alert_storm():
    engine, published, config = make_engine()
    first = port_event("e1", NOW, 3757, start=NOW - 500)
    engine._process_scored_group(score([first]), NOW)
    assert len(published) == 1
    events = [first]
    for i in range(10):
        events.append(port_event(f"r{i}", NOW + i, 5000 + i, start=NOW - 10 + i))
        engine._process_scored_group(score(events), NOW + i)
    assert len(published) == 1, f"restarts of the same service must not re-alert: {len(published)}"
    events.append(webshell_event("w1", NOW + 20))
    engine._process_scored_group(score(events), NOW + 20)
    assert len(published) == 2, "new INDEPENDENT evidence updates the correlation"
    update = published[1].metadata
    assert update["lifecycle_state"] == "UPDATED" and update["update_number"] == 2
    assert update["correlation_status"] == "ESCALATED" and update["previous_confidence"] == 30
    assert [e["kind"] for e in update["new_evidence"]] == ["Webshell Signature"]
    body = build_investigation_description(update, escape=discord_safe_inline)
    assert "Update #2" in body and "Previous Confidence" in body and "ESCALATED" in body and "Webshell Signature" in body
    engine._process_scored_group(score(events), NOW + 21)
    assert len(published) == 2, "the same evidence again publishes nothing"
    print("Test 15 (10 restarts -> no alert; new independent evidence -> one UPDATED with status/previous confidence) PASSED")


def test_16_deterministic_scoring():
    events = [port_event("e1", NOW, 3757, start=NOW - 500), port_event("e2", NOW, 840, start=NOW - 90000),
              webshell_event("w1", NOW + 1), port_event("e3", NOW + 2, 841, start=NOW - 89000)]
    import itertools
    snapshots = set()
    for order in itertools.permutations(range(len(events))):
        ordered = [events[i] for i in order]
        result = score(ordered)
        snapshots.add((result.total, result.gross_total, tuple(
            (b["kind"], b.get("pid"), b["contribution"], b.get("relationship"), b.get("related_to"))
            for b in tce.build_clean_score_breakdown(result)
        )))
    assert len(snapshots) == 1, f"scoring depends on event order: {snapshots}"
    print("Test 16 (24 event orderings -> identical score, roles and relationships) PASSED")


def test_17_no_polling_loop_bounded_and_cached():
    import ast
    banned_imports = {"subprocess", "glob", "shutil"}
    banned_calls = {"walk", "scandir", "rglob", "sleep", "create_task", "run_periodic", "Popen", "system", "create_subprocess_exec"}
    for path in ("core/correlation_evidence.py", "core/correlation_enrichment.py", "discord_integration/correlation_alert.py"):
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {a.name.split(".")[0] for a in node.names} & banned_imports, (path, node.lineno)
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in banned_imports, (path, node.lineno)
            elif isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                assert name not in banned_calls, f"{path}:{node.lineno} calls {name}()"
            elif isinstance(node, ast.While):
                assert not (isinstance(node.test, ast.Constant) and node.test.value is True), f"{path}:{node.lineno} while True"
    engine_source = open("modules/threat_correlation_engine.py", encoding="utf-8").read()
    assert engine_source.count("run_periodic(") == 2, "the TCE keeps exactly its two existing periodic tasks"
    assert "while True" not in engine_source and "asyncio.sleep" not in engine_source

    cache = enrichment.EnrichmentCache(process_ttl=10, service_ttl=30, network_ttl=5)
    probe = FakeProbe(process=live_process(50, NOW - 100), unit="ssh.service")
    for _ in range(3):
        ident = ce.EvidenceIdentity(event_id="x", pid=50, timestamp=NOW, start_time=NOW - 100)
        enrichment.enrich_identities([ident], cache=cache, probe=probe)
    assert probe.process_calls == 1 and probe.unit_calls == 1, (probe.process_calls, probe.unit_calls)

    clock = [0.0]
    ttl_cache = enrichment.EnrichmentCache(process_ttl=10, service_ttl=30, network_ttl=5, clock=lambda: clock[0])
    ttl_probe = FakeProbe(process=live_process(51, NOW - 100))
    enrichment.enrich_identities([ce.EvidenceIdentity(event_id="a", pid=51, timestamp=NOW, start_time=NOW - 100)], cache=ttl_cache, probe=ttl_probe)
    clock[0] = 11.0
    enrichment.enrich_identities([ce.EvidenceIdentity(event_id="b", pid=51, timestamp=NOW, start_time=NOW - 100)], cache=ttl_cache, probe=ttl_probe)
    assert ttl_probe.process_calls == 2, "process cache entry expires after its TTL"

    slow = FakeProbe(process=live_process(60, NOW - 100), delay=0.05)
    idents = [ce.EvidenceIdentity(event_id=f"s{i}", pid=60 + i, timestamp=NOW, start_time=NOW - 100) for i in range(30)]
    started = time.monotonic()
    report = enrichment.enrich_identities(
        idents, cache=enrichment.EnrichmentCache(process_ttl=0, service_ttl=0, network_ttl=0), probe=slow, max_seconds=0.12, max_items=30,
    )
    elapsed = time.monotonic() - started
    assert report.timed_out and elapsed < 0.5, elapsed
    assert report.statuses.get(enrichment.STATUS_TIMEOUT, 0) > 0
    capped = enrichment.enrich_identities(
        [ce.EvidenceIdentity(event_id=f"c{i}", pid=100 + i, timestamp=NOW) for i in range(50)],
        cache=enrichment.EnrichmentCache(process_ttl=0, service_ttl=0, network_ttl=0), probe=FakeProbe(process=live_process(100, NOW - 100)), max_items=5,
    )
    assert sum(capped.statuses.values()) == 5, "only max_items evidence items are ever enriched"
    print("Test 17 (no polling/scan/subprocess added; enrichment cached by TTL, deadline-bounded, item-capped) PASSED")


def test_18_pid_reuse_guard():
    ident = ce.EvidenceIdentity(event_id="x", pid=90, timestamp=NOW, start_time=1000.0)
    enrichment.enrich_identities(
        [ident], cache=enrichment.EnrichmentCache(process_ttl=10, service_ttl=30, network_ttl=5),
        probe=FakeProbe(process=live_process(90, NOW - 50)),
    )
    assert ident.enrichment_status == enrichment.STATUS_PID_REUSED and ident.executable is None
    later = ce.EvidenceIdentity(event_id="y", pid=91, timestamp=NOW - 1000)
    enrichment.enrich_identities(
        [later], cache=enrichment.EnrichmentCache(process_ttl=10, service_ttl=30, network_ttl=5),
        probe=FakeProbe(process=live_process(91, NOW - 10)),
    )
    assert later.enrichment_status == enrichment.STATUS_PID_REUSED, "a process started after the event is not the event's process"
    unverifiable = ce.EvidenceIdentity(event_id="z", pid=92)
    enrichment.enrich_identities(
        [unverifiable], cache=enrichment.EnrichmentCache(process_ttl=10, service_ttl=30, network_ttl=5),
        probe=FakeProbe(process=live_process(92, NOW - 10)),
    )
    assert unverifiable.enrichment_status == enrichment.STATUS_UNVERIFIED and unverifiable.executable is None
    print("Test 18 (PID reuse guard: enrichment never attaches another process's facts) PASSED")


def test_19_enrichment_fills_gaps_and_changes_classification():
    async def run():
        engine, published, config = make_engine()
        a = port_event("e1", NOW, 100, unit=None, sha=None, start=NOW - 900)
        b = port_event("e2", NOW, 200, unit=None, sha=None, start=NOW - 10)
        classified = [tce.classify_event(e, config) for e in (a, b)]
        group = tce.group_classified_events(classified)[0]
        before = tce.score_group(group, config)
        assert before.total == 60 and by_pid(before)[200].assessment.relationship == ce.UNKNOWN
        engine._enrichment_probe = FakeProbe(
            process={100: live_process(100, NOW - 900), 200: live_process(200, NOW - 10)}, unit="ssh.service",
        )
        return before, *(await engine._enrich_result(group, before, asyncio.get_running_loop()))
    before, after, summary = asyncio.run(run())
    assert summary["enriched"] == 2 and summary["statuses"] == {enrichment.STATUS_OK: 2}
    assert all(g.assessment.identity.systemd_unit == "ssh.service" for g in after.contributor_groups)
    assert all("systemd_unit" in g.assessment.identity.enriched_fields for g in after.contributor_groups)
    assert after.total == 30 and by_pid(after)[200].assessment.relationship == ce.PROCESS_RESTART
    engine, published, _ = make_engine()
    engine._process_scored_group(after, NOW, enrichment=summary)
    assert published[0].metadata["enrichment"]["enriched"] == 2
    print("Test 19 (enrichment fills only missing fields, then the deterministic classifier sees the shared unit) PASSED")


def test_20_cross_detector_same_socket_counted_once():
    persistence = port_event("e1", NOW, 3757, start=NOW - 500)
    remote = tce.CorrelationCandidateEvent(
        event_id="r1", timestamp=NOW + 1, category="REMOTE_ACCESS_BACKDOOR", severity="HIGH", message="listener",
        source_module="remote_access_detector", pid=3757, user="root", port=23109,
        raw_metadata={"port": 23109, "pid": 3757, "process": SSHD, "bind_address": "0.0.0.0", "protocol": "TCP",
                      "user": "root", "pid_create_time": NOW - 500},
    )
    result = score([persistence, remote])
    groups = {g.kind: g for g in result.contributor_groups}
    assert groups["Remote Access Backdoor"].effective_weight == 40, "the higher-weight observation carries the socket"
    assert groups["Persistence new port"].effective_weight == 0
    assert groups["Persistence new port"].assessment.relationship == ce.SAME_PROCESS
    assert result.total == 40 and result.gross_total == 70
    off = score([persistence, remote], TceConfig(relationship_classification_enabled=False))
    assert off.total == 70, "classification can be switched off"
    print("Test 20 (one socket reported by two detectors -> counted once at the higher weight; switchable) PASSED")


def test_21_config_and_detector_metadata():
    config = TceConfig()
    assert (config.max_evidence_per_correlation, config.max_enrichment_seconds) == (20, 2.0)
    assert (config.process_cache_ttl_seconds, config.service_cache_ttl_seconds, config.network_cache_ttl_seconds) == (10.0, 30.0, 5.0)
    assert config.detailed_correlated_threat and config.enrichment_enabled and config.relationship_classification_enabled
    import dataclasses
    from config.manager import ConfigManager
    base = RTSAConfig()
    for field_name, value in (("max_evidence_per_correlation", 0), ("max_enrichment_seconds", 0.0), ("process_cache_ttl_seconds", -1.0)):
        bad = dataclasses.replace(base, modules=dataclasses.replace(base.modules, tce=TceConfig(**{field_name: value})))
        try:
            ConfigManager._validate_semantics(bad)
        except ConfigValidationError as exc:
            assert f"modules.tce.{field_name}" in str(exc), str(exc)
        else:
            raise AssertionError(f"{field_name}={value} must be rejected")
    assert TceConfig().detector_weights["SSH login after brute force"] == 40
    fields = HostPersistenceDetector._port_forensic_fields(23109, {"pid": 1, "systemd_unit": "ssh.service", "service_identity": "ssh.service|/usr/sbin/sshd"})
    assert fields["systemd_unit"] == "ssh.service" and fields["service_identity"].endswith("/usr/sbin/sshd")
    for path in ("config/config.yaml", "config/config2.yaml"):
        text = open(path, encoding="utf-8").read()
        assert "max_evidence_per_correlation: 20" in text and "detailed_correlated_threat: true" in text, path
    print("Test 21 (TCE config defaults, config.yaml/config2.yaml entries, persistence events carry systemd_unit) PASSED")


def test_22_webhook_v2_and_legacy():
    engine, published, _ = make_engine()
    engine._process_scored_group(score([port_event("e1", NOW, 3757, start=NOW - 500), port_event("e2", NOW, 840, start=NOW - 90000)]), NOW)
    meta = published[0].metadata
    embed = dispatch(meta, message=published[0].message)
    text = embed["description"]
    for needle in ("WHY THIS ALERT FIRED", "EVIDENCE #1 — PRIMARY", "EVIDENCE #2 — RELATED", "PROCESS\\_RESTART", "SCORE BREAKDOWN",
                   "TIMELINE", "SECURITY INTERPRETATION", "VERIFICATION CHECKLIST", "RECOMMENDATION", "Effective Score: 30 (gross 60)"):
        assert needle in text, f"missing {needle!r}"
    names = {f["name"] for f in embed["fields"]}
    assert {"Assessment", "Confidence"} <= names and "Primary Process PID" not in names
    legacy = dict(meta)
    legacy.pop("investigation_v2")
    legacy_embed = dispatch(legacy, message="legacy body")
    assert legacy_embed["description"] == "legacy body", "events without the v2 metadata keep the previous format"
    off_engine, off_published, _ = make_engine(detailed_correlated_threat=False)
    off_engine._process_scored_group(score([port_event("e1", NOW, 3757, start=NOW - 500)]), NOW)
    assert "investigation_v2" not in off_published[0].metadata
    print("Test 22 (v2 embed carries every section; legacy events and detailed_correlated_threat=false unchanged) PASSED")


def test_23_depth_levels():
    low = engine_publish(score([port_event("e1", NOW, 1, start=NOW - 500), fim_event("f1", NOW + 1)]))
    assert low["investigation_depth"] == "compact"
    high = engine_publish(score([port_event("e1", NOW, 1, start=NOW - 500), webshell_event("w1", NOW + 1)]))
    assert high["investigation_depth"] == "full"
    low_text = build_investigation_description(low, escape=discord_safe_inline)
    high_text = build_investigation_description(high, escape=discord_safe_inline)
    assert "Working Directory" not in low_text and "Working Directory: /" in high_text
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in high_text, "full depth shows the whole SHA256"
    print("Test 23 (investigation depth: compact stays compact, high confidence shows full lineage/hash) PASSED")


def main() -> None:
    test_1_identical_events_deduplicated()
    test_2_same_service_different_pid_is_lifecycle()
    test_3_same_unit_and_port_not_automatically_independent()
    test_4_parent_child_classified()
    test_5_different_service_same_port_is_independent_and_suspicious()
    test_6_unexpected_executable_hash_is_independent()
    test_7_fim_plus_persistence_two_independent_signals()
    test_8_ssh_bruteforce_plus_login_correlated()
    test_9_inbound_never_reported_as_outbound()
    test_10_missing_process_renders_unknown()
    test_11_process_exits_before_enrichment()
    test_12_systemd_unit_unavailable_degrades_gracefully()
    test_13_formatter_handles_missing_fields()
    test_14_large_evidence_bounded()
    test_15_duplicate_correlation_no_alert_storm()
    test_16_deterministic_scoring()
    test_17_no_polling_loop_bounded_and_cached()
    test_18_pid_reuse_guard()
    test_19_enrichment_fills_gaps_and_changes_classification()
    test_20_cross_detector_same_socket_counted_once()
    test_21_config_and_detector_metadata()
    test_22_webhook_v2_and_legacy()
    test_23_depth_levels()
    print("\nALL CORRELATION EVIDENCE HARDENING TESTS PASSED")


if __name__ == "__main__":
    main()
