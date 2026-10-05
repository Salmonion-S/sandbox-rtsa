import asyncio
import json
import os
import sqlite3
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import shutil
import tempfile

from config.manager import FileIntegrityDetectorConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from modules.file_integrity_detector import FileIntegrityDetector
from modules.threat_correlation_engine import (
    ACTOR_CONFIRMED, ACTOR_LIKELY, ACTOR_UNKNOWN, deployment_actor_for, deployment_status_for,
)

BASE = os.path.join(tempfile.gettempdir(), "rtsa_deployment_actor_test")


def _make_events_db(path: str, rows: list) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE events (event_id TEXT, timestamp REAL, source_module TEXT, "
        "category TEXT, severity TEXT, message TEXT, host TEXT, metadata TEXT)"
    )
    for row in rows:
        conn.execute(
            "INSERT INTO events (event_id, timestamp, source_module, category, severity, "
            "message, host, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row.get("event_id", "e1"), row["timestamp"], row.get("source_module", "audit_monitor"),
                row.get("category", "AUDIT_GENERIC"), row.get("severity", "INFO"),
                row.get("message", "test"), row.get("host", "server1"), json.dumps(row["metadata"]),
            ),
        )
    conn.commit()
    conn.close()


def main() -> None:
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)
    now = time.time()

    missing_db = os.path.join(BASE, "does_not_exist.db")
    assert deployment_actor_for(events_db_path=missing_db) == ACTOR_UNKNOWN
    print("Scenario 1 (missing events DB -> ACTOR_UNKNOWN) PASSED")

    db2 = os.path.join(BASE, "s2.db")
    _make_events_db(db2, [
        {"timestamp": now, "metadata": {"executable": "sshd", "command_line": "sshd: user@pts/0"}},
    ])
    assert deployment_actor_for(events_db_path=db2, project_root="/home/x/htdocs/x.com") == ACTOR_UNKNOWN
    print("Scenario 2 (no maintenance signal in window -> ACTOR_UNKNOWN) PASSED")

    db3 = os.path.join(BASE, "s3.db")
    _make_events_db(db3, [
        {"timestamp": now, "metadata": {"executable": "/usr/bin/git", "command_line": "git pull"}},
    ])
    assert deployment_actor_for(events_db_path=db3, project_root="/home/x/htdocs/x.com") == ACTOR_LIKELY
    assert deployment_status_for(events_db_path=db3) == "ACTIVE", "deployment_status_for must be unaffected by this change"
    print("Scenario 3 (git signal, no project/user match -> ACTOR_LIKELY; deployment_status_for unaffected) PASSED")

    db4 = os.path.join(BASE, "s4.db")
    _make_events_db(db4, [
        {
            "timestamp": now,
            "metadata": {
                "executable": "/usr/bin/git", "command_line": "git pull",
                "project_root": "/home/x/htdocs/x.com", "user": "deployuser",
            },
        },
    ])
    assert deployment_actor_for(events_db_path=db4, project_root="/home/x/htdocs/x.com") == ACTOR_CONFIRMED
    print("Scenario 4 (git signal with matching project + known user -> ACTOR_CONFIRMED) PASSED")

    assert deployment_actor_for(events_db_path=db4, project_root="/home/other/htdocs/other.com") == ACTOR_LIKELY
    print("Scenario 5 (same git signal, different project -> ACTOR_LIKELY not ACTOR_CONFIRMED) PASSED")

    db6 = os.path.join(BASE, "s6.db")
    _make_events_db(db6, [
        {"timestamp": now - 10000, "metadata": {"executable": "/usr/bin/git", "command_line": "git pull"}},
    ])
    assert deployment_actor_for(events_db_path=db6, lookback_seconds=300.0) == ACTOR_UNKNOWN
    print("Scenario 6 (stale maintenance signal outside lookback window is ignored) PASSED")

    print("\nALL deployment_actor_for TESTS PASSED")


def _bulk_change(i, *, extension=".js", assessment=None, project_root=None):
    return {
        "path": f"/home/x/htdocs/x.com/file{i}{extension}", "target_class": "php_source", "change_type": "modified",
        "severity": Severity.MEDIUM, "message": f"file{i} modified", "project": "x.com",
        "project_root": project_root, "linux_user": None, "domain": None, "runtime": None,
        "risk_reason": None, "recommendation": None, "confidence": None, "assessment": assessment,
        "sha256_old": "a", "sha256_new": "b", "mode_old": None, "mode_new": None,
        "uid_old": None, "uid_new": None, "gid_old": None, "gid_new": None,
    }


async def async_main() -> None:
    from core.fim_risk_classifier import HIGH_RISK, SUSPICIOUS as SUSPICIOUS_ASSESSMENT

    detector = FileIntegrityDetector(EventBus(), FileIntegrityDetectorConfig())
    published = []
    detector.publish = lambda ev: published.append(ev)

    changes = (
        [_bulk_change(i, extension=".js", project_root="/home/x/htdocs/x.com") for i in range(40)]
        + [_bulk_change(i + 40, extension=".php", project_root="/home/x/htdocs/x.com") for i in range(3)]
        + [_bulk_change(i + 43, extension=".svg", project_root="/home/x/htdocs/x.com") for i in range(2)]
        + [_bulk_change(i + 45, extension=".html", project_root="/home/x/htdocs/x.com") for i in range(1)]
        + [
            _bulk_change(46, extension=".php", assessment=SUSPICIOUS_ASSESSMENT, project_root="/home/x/htdocs/x.com"),
            _bulk_change(47, extension=".php", assessment=HIGH_RISK, project_root="/home/x/htdocs/x.com"),
        ]
    )
    await detector._publish_changes("php_source", changes)
    assert len(published) == 1, f"a large burst must still collapse into exactly one summary event: {len(published)}"
    ev = published[0]
    meta = ev.metadata
    assert meta["files_changed"] == len(changes)
    assert meta["php_changed"] == 5, meta
    assert meta["svg_changed"] == 2, meta
    assert meta["html_changed"] == 1, meta
    assert meta["suspicious_count"] == 1, meta
    assert meta["high_risk_count"] == 1, meta
    assert meta["deployment_id"], "deployment_id must be present and non-empty"
    assert meta["deployment_actor"] in (ACTOR_CONFIRMED, ACTOR_LIKELY, ACTOR_UNKNOWN)
    assert meta["htdocs_path"] == "/home/x/htdocs/x.com"
    print(
        "Scenario 7 (burst aggregate carries deployment_id/php_changed/svg_changed/html_changed/"
        "suspicious_count/high_risk_count/deployment_actor) PASSED"
    )

    published.clear()
    critical_change = dict(_bulk_change(99, extension=".php", project_root="/home/x/htdocs/x.com"))
    critical_change["severity"] = Severity.CRITICAL
    mixed = [critical_change] + [_bulk_change(i, project_root="/home/x/htdocs/x.com") for i in range(10)]
    await detector._publish_changes("php_source", mixed)
    critical_events = [e for e in published if e.severity == Severity.CRITICAL]
    assert len(critical_events) == 1, (
        f"a CRITICAL file change must always publish immediately and separately, never folded "
        f"into a bulk summary: {[e.severity for e in published]}"
    )
    assert critical_events[0].metadata.get("change_type") != "bulk_activity"
    print("Scenario 8 (CRITICAL change is never absorbed into a burst summary, publishes separately) PASSED")

    published.clear()
    deployment_changes = [
        _bulk_change(i, extension=".php" if i % 2 == 0 else ".js", project_root="/home/x/htdocs/x.com")
        for i in range(12)
    ]
    for c in deployment_changes:
        c["deployment_status"] = "ACTIVE"
        c["git_commit"] = "abc123def456abcdef0123456789abcdef01234"
    await detector._publish_changes("uploads", deployment_changes)
    assert len(published) == 1
    ev = published[0]
    assert ev.metadata["deployment_status"] == "ACTIVE", ev.metadata
    assert ev.metadata["git_commit"] == "abc123def456abcdef0123456789abcdef01234", ev.metadata
    assert "Deployment Status: ACTIVE" in ev.message, ev.message
    assert "abc123def456" in ev.message, ev.message
    assert f"Files={len(deployment_changes)}" in ev.message, ev.message
    print(
        "Scenario 9 (git-deployment burst surfaces a uniform Deployment Status + git commit in both "
        "metadata and the rendered aggregate summary, alongside the file-count breakdown) PASSED"
    )

    published.clear()
    mixed_status_changes = [
        _bulk_change(i, extension=".js", project_root="/home/x/htdocs/x.com") for i in range(12)
    ]
    for i, c in enumerate(mixed_status_changes):
        c["deployment_status"] = "ACTIVE" if i % 2 == 0 else "INACTIVE"
    await detector._publish_changes("configs", mixed_status_changes)
    assert len(published) == 1
    ev = published[0]
    assert ev.metadata["deployment_status"] == "MIXED", (
        f"a burst spanning two different deployment_status values must be surfaced honestly as "
        f"MIXED, never silently collapsed to one: {ev.metadata}"
    )
    print("Scenario 10 (a burst with mixed deployment_status values across files is surfaced as MIXED, not silently collapsed) PASSED")

    print("\nALL BURST-AGGREGATION ENRICHMENT TESTS PASSED")


main()
asyncio.run(async_main())
