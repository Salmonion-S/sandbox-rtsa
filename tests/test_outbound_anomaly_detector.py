import asyncio
import os
import resource
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import psutil

from config.manager import OutboundAnomalyDetectorConfig, ResourceGovernorConfig
from core.cpu_governor import configure_cpu_governor, get_cpu_governor
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.outbound_baseline import (
    EXPOSURE_PRIVATE, EXPOSURE_PUBLIC, OutboundBaseline, classify_destination, destination_group,
)
from modules.outbound_anomaly_detector import (
    RULE_CONNECTION_ATTEMPT_STORM, RULE_FILELESS_EXECUTABLE, RULE_NEW_PROCESS_NEW_DESTINATION,
    RULE_PROCESS_FROM_WRITABLE_PROJECT, RULE_RECENT_FILE_CHANGE, RULE_SHORT_LIVED_PROCESS,
    RULE_UNCOMMON_PORT, OutboundAnomalyDetector,
)


def cpu_seconds():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime


def make_detector(tmpdir, **overrides):
    overrides.setdefault("enabled", True)
    overrides.setdefault("learning_period_seconds", 0.0)
    overrides.setdefault("baseline_state_path", os.path.join(tmpdir, "outbound.json"))
    detector = OutboundAnomalyDetector(EventBus(), OutboundAnomalyDetectorConfig(**overrides))
    published = []
    detector.publish = lambda event: published.append(event)
    detector._baseline.seed_started_at(time.time() - 100000.0)
    return detector, published


def seed_process(detector, pid, *, exe, cwd=None, start_time=None, username="app", ppid=1):
    meta = {
        "pid": pid, "ppid": ppid, "uid": 1000, "username": username,
        "exe": exe, "cwd": cwd, "cmdline": exe,
        "start_time": start_time if start_time is not None else time.time() - 86400.0,
        "start_time_ticks": 1, "project": None, "exe_key": exe,
    }
    detector._process_meta.set(pid, meta)
    return meta


async def scan(detector, rows, listening_ports=None):
    normalized = []
    for i, row in enumerate(rows):
        if len(row) == 5:
            normalized.append(row)
        else:
            pid, ip, port, status = row
            normalized.append((pid, ip, port, status, 50000 + i))
    detector.__class__._collect_connections = staticmethod(
        lambda: (list(normalized), set(listening_ports or set()))
    )
    await detector._scan_connections()


async def main() -> None:
    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    get_cpu_governor().reset_for_tests()

    assert classify_destination("127.0.0.1") == "LOOPBACK"
    assert classify_destination("10.1.2.3") == EXPOSURE_PRIVATE
    assert classify_destination("192.168.1.5") == EXPOSURE_PRIVATE
    assert classify_destination("8.8.8.8") == EXPOSURE_PUBLIC
    assert destination_group("203.0.113.55") == "203.0.113.0/24"
    assert destination_group("203.0.113.99") == destination_group("203.0.113.1"), (
        "addresses in the same /24 must collapse to one destination so a rotating C2 or a CDN "
        "does not inflate the baseline"
    )
    print(
        "Test 1 [DESTINATION CLASSIFICATION] (loopback, RFC1918 and public are separated, and a "
        "/24 collapses to one destination group so subnet rotation cannot inflate the baseline) "
        "PASSED"
    )

    baseline = OutboundBaseline(ttl_seconds=100.0, max_entries=5, learning_seconds=0.0)
    now = time.time()
    for index in range(20):
        baseline.observe(f"/usr/bin/app{index}", f"198.51.100.{index}", 443, now)
    assert baseline.profile_count <= 5, (
        f"the baseline must stay under max_entries=5, got {baseline.profile_count} profiles"
    )
    assert baseline.evicted_total > 0, "eviction must be counted"
    baseline.observe("/usr/bin/keep", "203.0.113.1", 443, now - 500.0)
    removed = baseline.prune(now)
    assert removed > 0, "entries older than the TTL must be pruned"
    print(
        f"Test 2 [BOUNDED BASELINE] (20 processes into a 5-entry baseline leaves "
        f"{baseline.profile_count} profiles with {baseline.evicted_total} evictions counted, and "
        f"TTL pruning removed {removed} stale entries -- memory cannot grow without limit) PASSED"
    )

    with tempfile.TemporaryDirectory(prefix="rtsa-outbound-") as tmpdir:
        detector, published = make_detector(tmpdir)
        seed_process(detector, 4001, exe="/usr/bin/curl")
        for _ in range(6):
            await scan(detector, [(4001, "203.0.113.10", 443, psutil.CONN_ESTABLISHED)])
        known = [e for e in published if e.metadata.get("destination_ip") == "203.0.113.10"]
        assert len(known) <= 1, (
            f"a destination seen repeatedly must stop alerting once it is part of the profile, got "
            f"{len(known)} alerts"
        )
        print(
            f"Test 3 [KNOWN DESTINATION STOPS ALERTING] (the same process/destination pair observed "
            f"6 times produced {len(known)} alert -- the baseline learns rather than repeating) "
            f"PASSED"
        )

        detector, published = make_detector(tmpdir, min_score_to_alert=1000)
        seed_process(detector, 4100, exe="/usr/bin/node", cwd="/home/site/htdocs/example.com")
        await scan(detector, [(4100, "203.0.113.20", 443, psutil.CONN_ESTABLISHED)])
        assert not published, (
            f"below min_score_to_alert nothing must be published, got {len(published)}"
        )
        print(
            "Test 4 [SCORE THRESHOLD] (an observation scoring under min_score_to_alert publishes "
            "nothing -- a single outbound connection is never treated as malicious by itself) PASSED"
        )

        detector, published = make_detector(tmpdir, learning_period_seconds=3600.0)
        detector._baseline.seed_started_at(time.time())
        seed_process(detector, 4200, exe="/tmp/dropper", cwd="/tmp")
        await scan(detector, [(4200, "203.0.113.30", 4444, psutil.CONN_ESTABLISHED)])
        assert not published, (
            f"during the learning period the detector must observe silently, got {len(published)}"
        )
        assert detector._suppressed_learning_total >= 1
        print(
            f"Test 5 [LEARNING PERIOD] (during the learning window observations are recorded but "
            f"nothing is published -- {detector._suppressed_learning_total} suppressed -- so a "
            f"restart does not spam every existing connection) PASSED"
        )

        detector, published = make_detector(tmpdir)
        seed_process(detector, 4300, exe="/home/site/htdocs/example.com/public/uploads/.x",
                     cwd="/home/site/htdocs/example.com/public/uploads")
        await scan(detector, [(4300, "203.0.113.40", 4444, psutil.CONN_ESTABLISHED)])
        assert published, "a process running from a web-writable upload directory must alert"
        event = published[0]
        rules = event.metadata["rules"]
        assert RULE_PROCESS_FROM_WRITABLE_PROJECT in rules, rules
        assert RULE_UNCOMMON_PORT in rules, rules
        assert RULE_NEW_PROCESS_NEW_DESTINATION in rules, rules
        assert event.severity in (Severity.HIGH, Severity.CRITICAL), (
            f"three corroborating signals must escalate above MEDIUM, got {event.severity}"
        )
        assert event.category == EventCategory.OUTBOUND_ANOMALY
        print(
            f"Test 6 [WEB-WRITABLE ORIGIN] (a process running from public/uploads connecting out on "
            f"port 4444 raises {len(rules)} corroborating rules {rules} at {event.severity.value}) "
            f"PASSED"
        )

        detector, published = make_detector(tmpdir)
        seed_process(detector, 4400, exe="/usr/bin/python3 (deleted)", cwd="/tmp")
        await scan(detector, [(4400, "198.51.100.7", 443, psutil.CONN_ESTABLISHED)])
        assert published, "a deleted executable making outbound connections must alert"
        assert RULE_FILELESS_EXECUTABLE in published[0].metadata["rules"]
        assert published[0].severity == Severity.CRITICAL, (
            f"fileless execution with outbound activity is the strongest single signal, got "
            f"{published[0].severity}"
        )
        print(
            "Test 7 [FILELESS EXECUTABLE] (a process whose executable no longer exists on disk "
            "connecting outbound is reported CRITICAL even on port 443) PASSED"
        )

        detector, published = make_detector(tmpdir)
        seed_process(detector, 4500, exe="/usr/local/bin/agent", start_time=time.time() - 5.0)
        await scan(detector, [(4500, "203.0.113.50", 9001, psutil.CONN_ESTABLISHED)])
        assert published, "a brand-new process connecting out must be evaluated"
        assert RULE_SHORT_LIVED_PROCESS in published[0].metadata["rules"]
        print(
            "Test 8 [SHORT-LIVED PROCESS] (a process 5 seconds old already connecting outbound is "
            "flagged, which is the pattern a dropper shows and a stable service does not) PASSED"
        )

        detector, published = make_detector(tmpdir, connection_attempt_threshold=3)
        meta = seed_process(detector, 4600, exe="/usr/local/bin/beacon")
        for _ in range(4):
            await scan(detector, [(4600, "198.51.100.200", 8443, psutil.CONN_SYN_SENT)])
        observation = detector._observations[
            ("/usr/local/bin/beacon", destination_group("198.51.100.200"), 8443)
        ]
        assert observation.attempt_count >= 4, (
            f"repeated SYN_SENT attempts must be counted, got {observation.attempt_count}"
        )
        assert observation.status == psutil.CONN_SYN_SENT, (
            "the observation must retain the fact that the connection never established"
        )
        finding = detector._evaluate(
            meta, observation, EXPOSURE_PUBLIC, False, False, 4,
            detector._baseline.profile_for("/usr/local/bin/beacon"), time.time(),
        )
        assert RULE_CONNECTION_ATTEMPT_STORM in finding.rules, (
            f"repeated SYN_SENT attempts that never establish are the beacon pattern and must be "
            f"detected -- these never appear in an ESTABLISHED-only view. Got {finding.rules}"
        )
        print(
            f"Test 9 [CONNECTION ATTEMPT STORM] (4 repeated SYN_SENT attempts to a destination that "
            f"never answers are tracked to attempt_count={observation.attempt_count} and raise "
            f"{RULE_CONNECTION_ATTEMPT_STORM}; the previous implementation inspected only "
            f"ESTABLISHED and would have seen none of this) PASSED"
        )

        detector, published = make_detector(tmpdir)
        project = "/home/site/htdocs/example.com"
        seed_process(detector, 4700, exe=f"{project}/vendor/bin/worker", cwd=project)
        await detector._on_file_change(BaseEvent(
            source_module="file_integrity_detector",
            category=EventCategory.FILE_INTEGRITY_CHANGE, severity=Severity.MEDIUM,
            message="changed", raw="",
            metadata={"project_root": project, "change_type": "created", "path": f"{project}/public/x.php"},
        ))
        await scan(detector, [(4700, "203.0.113.60", 8080, psutil.CONN_ESTABLISHED)])
        assert published, "an outbound connection after a project file change must be evaluated"
        correlated = published[0].metadata["rules"]
        assert RULE_RECENT_FILE_CHANGE in correlated, (
            f"the file-change correlation must raise confidence, got {correlated}"
        )
        print(
            f"Test 10 [FILE CHANGE CORRELATION] (a file created in the project followed by an "
            f"outbound connection from a process in that project raises "
            f"{RULE_RECENT_FILE_CHANGE} -- the chain the spec asks for) PASSED"
        )

        detector, published = make_detector(tmpdir)
        seed_process(detector, 4800, exe="/usr/sbin/chronyd", username="_chrony")
        seed_process(detector, 4801, exe="/usr/sbin/nginx", username="www-data")
        seed_process(detector, 4802, exe="/usr/bin/php-fpm8.2", username="app")
        for _ in range(5):
            await scan(detector, [
                (4800, "162.159.200.1", 123, psutil.CONN_ESTABLISHED),
                (4801, "203.0.113.90", 443, psutil.CONN_ESTABLISHED),
                (4802, "203.0.113.91", 443, psutil.CONN_ESTABLISHED),
            ])
        assert not published, (
            f"chronyd on NTP and web runtimes on 443 are ordinary egress and must not alert, got "
            f"{[e.metadata['rules'] for e in published]}"
        )
        print(
            "Test 11 [LEGITIMATE SERVICE EGRESS] (chronyd on port 123 and nginx/php-fpm on 443, "
            "repeated across 5 cycles, produce zero alerts -- the false positives the systemd work "
            "fixed do not come back through a new detector) PASSED"
        )

        detector, published = make_detector(tmpdir)
        seed_process(detector, 4900, exe="/usr/bin/backup")
        await scan(detector, [(4900, "10.0.0.5", 9999, psutil.CONN_ESTABLISHED)])
        assert not published, (
            f"private-range destinations are excluded by default, got {len(published)}"
        )
        detector, published = make_detector(tmpdir, include_private_destinations=True)
        seed_process(detector, 4901, exe="/usr/bin/backup")
        await scan(detector, [(4901, "10.0.0.5", 9999, psutil.CONN_ESTABLISHED)])
        assert published, "with include_private_destinations enabled the same connection is examined"
        print(
            "Test 12 [PRIVATE DESTINATIONS OPT-IN] (RFC1918 destinations are ignored by default "
            "because internal service traffic is normal, and examined when "
            "include_private_destinations is enabled) PASSED"
        )

        detector, published = make_detector(tmpdir)
        seed_process(detector, 5000, exe="/tmp/x", cwd="/tmp")
        for _ in range(8):
            await scan(detector, [(5000, "203.0.113.70", 4444, psutil.CONN_ESTABLISHED)])
        assert len(published) <= 2, (
            f"one persistent anomalous connection must be one incident with bounded reminders, got "
            f"{len(published)} alerts"
        )
        print(
            f"Test 13 [NO ALERT SPAM] (the same anomalous connection observed across 8 cycles "
            f"produced {len(published)} alert(s) through the shared incident engine, not one per "
            f"cycle) PASSED"
        )

        detector, published = make_detector(tmpdir)
        for pid in range(6000, 6300):
            seed_process(detector, pid, exe=f"/usr/bin/svc{pid % 40}")
        rows = [
            (6000 + i, f"203.0.113.{i % 250}", 443 if i % 3 else 8443, psutil.CONN_ESTABLISHED)
            for i in range(300)
        ]
        start_cpu, start_wall = cpu_seconds(), time.monotonic()
        await scan(detector, rows)
        wall = max(time.monotonic() - start_wall, 1e-9)
        used = cpu_seconds() - start_cpu
        assert wall < 2.0, f"a 300-connection cycle must stay fast, took {wall:.2f}s"
        assert len(detector._observations) <= 4096
        health = await detector.health()
        assert health["connections_examined_total"] == 300
        print(
            f"Test 14 [CYCLE COST] (300 connections across 300 processes examined in {wall:.3f}s "
            f"using {used:.3f}s CPU; tracked observations bounded at "
            f"{len(detector._observations)} and every connection accounted for in health) PASSED"
        )

        detector, published = make_detector(tmpdir)
        seed_process(detector, 7000, exe="/usr/bin/svc")
        await scan(detector, [(7000, "203.0.113.80", 443, psutil.CONN_ESTABLISHED)])
        await detector._persist_baseline()
        reloaded, _ = make_detector(tmpdir)
        await reloaded.setup()
        assert reloaded._baseline.profile_count >= 1, (
            "the baseline must survive a restart, otherwise every restart re-alerts on known traffic"
        )
        assert reloaded._baseline.is_known_destination("/usr/bin/svc", "203.0.113.80")
        print(
            f"Test 15 [BASELINE PERSISTENCE] (the learned profile survives a restart -- "
            f"{reloaded._baseline.profile_count} profile(s) reloaded, and the known destination is "
            f"still recognised) PASSED"
        )

        detector, published = make_detector(tmpdir)
        seed_process(detector, 7100, exe="/tmp/x", cwd="/tmp")
        await scan(detector, [(7100, "203.0.113.99", 4444, psutil.CONN_ESTABLISHED)])
        assert published
        event = published[0]
        for field in (
            "pid", "ppid", "username", "executable", "cwd", "destination_ip", "destination_port",
            "connection_status", "exposure", "first_seen", "rules", "reasons", "score", "confidence",
        ):
            assert field in event.metadata, f"the alert must carry '{field}' for investigation"
        assert "RTSA tidak melakukan tindakan otomatis" in event.message, (
            "the alert must state plainly that RTSA takes no automatic action"
        )
        assert len(event.message) < 4000, "the alert must be a summary, not a raw dump"
        print(
            f"Test 16 [ALERT CONTENT] (the alert carries process, parent, user, working directory, "
            f"destination, state, evidence and confidence in {len(event.message)} characters, and "
            f"states explicitly that RTSA takes no automatic action) PASSED"
        )

        detector, published = make_detector(tmpdir)
        seed_process(detector, 8000, exe="/usr/sbin/nginx", username="www-data")
        inbound_rows = [
            (8000, f"198.51.100.{i}", 40000 + i, psutil.CONN_ESTABLISHED, 443)
            for i in range(30)
        ]
        await scan(detector, inbound_rows, listening_ports={443})
        assert not published, (
            f"nginx accepting many inbound client connections on its own listening port must never "
            f"be treated as candidate outbound egress just because it owns many sockets, got "
            f"{len(published)} alerts"
        )
        health = await detector.health()
        assert health["inbound_skipped_total"] >= 30, (
            f"every inbound-accepted connection must be counted as skipped, got "
            f"{health['inbound_skipped_total']}"
        )
        print(
            f"Test 17 [INBOUND vs OUTBOUND DIRECTION] (nginx accepting {len(inbound_rows)} inbound "
            f"client connections on its own listening port 443 produces zero alerts and "
            f"{health['inbound_skipped_total']} connections correctly skipped as inbound-accepted, "
            f"not candidate egress -- this is the exact false positive the audit reported for a real "
            f"'nginx: worker process') PASSED"
        )

        detector, published = make_detector(tmpdir)
        seed_process(detector, 8100, exe="/usr/bin/python3 (deleted)", cwd="/tmp")
        await scan(
            detector, [(8100, "198.51.100.7", 443, psutil.CONN_ESTABLISHED, 51000)],
            listening_ports={443},
        )
        assert published, (
            "a genuine outbound connection from a process that is not itself listening on the "
            "matching local port must still be evaluated normally"
        )
        assert RULE_FILELESS_EXECUTABLE in published[0].metadata["rules"]
        print(
            "Test 18 [GENUINE OUTBOUND STILL VISIBLE] (a real client-initiated outbound connection "
            "whose local port does not match any listening port is still evaluated and alerted -- "
            "the inbound-direction fix narrows to accepted sockets only, it does not blanket-exempt "
            "any process or port) PASSED"
        )

    print("\nALL OUTBOUND ANOMALY DETECTOR TESTS PASSED")


asyncio.run(main())
