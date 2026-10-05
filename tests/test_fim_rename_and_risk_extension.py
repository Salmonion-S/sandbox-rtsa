import asyncio
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import FileIntegrityDetectorConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from core.file_identity import stat_identity
from core.fim_risk_classifier import classify_risk
from modules.file_integrity_detector import FileIntegrityDetector


async def main():
    d = tempfile.mkdtemp()
    proj = os.path.join(d, "project")
    os.makedirs(proj)
    risky_path = os.path.join(proj, "c99.php")
    with open(risky_path, "w") as f:
        f.write("<?php system($_GET['cmd']); ?>")

    bus = EventBus()
    events = []

    async def collector(e):
        events.append(e)

    sub = await bus.subscribe("c", collector, categories=None)
    cfg = FileIntegrityDetectorConfig(enabled=True, use_inotify=False)
    mon = FileIntegrityDetector(bus, cfg)

    def discover():
        return {risky_path: "php_source"}

    task = asyncio.create_task(mon._watch_class_loop(
        "php_source", discover, os.path.join(d, "baseline.json"),
        lambda: 5.0, initial_offset_seconds=0.0,
    ))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    await sub.queue.join()
    assert events == [], f"initial file baseline must publish zero events: {events}"
    assert risky_path in mon._known_state_by_group["php_source"]
    assert mon._known_state_by_group["php_source"][risky_path].inode is not None
    print("Scenario 2 (initial file baseline: zero alerts, even for a risky-looking file; inode captured) PASSED")

    mon2 = FileIntegrityDetector(EventBus(), FileIntegrityDetectorConfig())

    normal = os.path.join(proj, "README.md")
    with open(normal, "w") as f:
        f.write("# hello")
    new_normal = stat_identity(normal)
    evaluated_normal = mon2._evaluate_change(normal, "php_source", None, new_normal)
    assert evaluated_normal["severity"] in (Severity.LOW, Severity.INFO), evaluated_normal
    print(f"Scenario 8 (normal new file -> {evaluated_normal['severity'].value}, not flagged as attack) PASSED")

    new_risky = stat_identity(risky_path)
    evaluated_risky = mon2._evaluate_change(risky_path, "php_source", None, new_risky)
    assert evaluated_risky["severity"] in (Severity.HIGH, Severity.CRITICAL), evaluated_risky
    print(f"Scenario 9 (webshell-named new file 'c99.php' -> {evaluated_risky['severity'].value}) PASSED")

    changing = os.path.join(proj, "config.js")
    with open(changing, "w") as f:
        f.write("var x = 1;")
    old_id = stat_identity(changing)
    time.sleep(0.01)
    with open(changing, "w") as f:
        f.write("var x = 2;")
    new_id = stat_identity(changing)
    evaluated_mod = mon2._evaluate_change(changing, "php_source", old_id, new_id)
    assert evaluated_mod is not None and evaluated_mod["change_type"] == "modified", evaluated_mod
    assert evaluated_mod["sha256_old"] != evaluated_mod["sha256_new"]
    print("Scenario 10 (content hash change -> change_type='modified') PASSED")

    evaluated_deleted = mon2._evaluate_change(changing, "php_source", new_id, None)
    assert evaluated_deleted is not None and evaluated_deleted["change_type"] == "deleted", evaluated_deleted
    print("Scenario 12 (file deletion -> change_type='deleted', recorded) PASSED")

    old_path = os.path.join(proj, "old_name.js")
    with open(old_path, "w") as f:
        f.write("console.log('same content');")
    old_before_move = stat_identity(old_path)
    new_path = os.path.join(proj, "new_name.js")
    os.rename(old_path, new_path)
    new_after_move = stat_identity(new_path)
    assert old_before_move.inode == new_after_move.inode, "same-filesystem rename must preserve inode"

    deleted_eval = mon2._evaluate_change(old_path, "php_source", old_before_move, None)
    created_eval = mon2._evaluate_change(new_path, "php_source", None, new_after_move)
    correlated = mon2._correlate_renames([deleted_eval, created_eval])
    assert len(correlated) == 1, f"delete+create sharing an inode must correlate into one entry: {correlated}"
    assert correlated[0]["change_type"] == "renamed"
    assert correlated[0]["renamed_from"] == old_path
    assert correlated[0]["path"] == new_path
    print("Scenario 4/11 (same-inode rename correlated into one 'renamed' entry, not delete+create) PASSED")

    unrelated_created = os.path.join(proj, "unrelated.js")
    with open(unrelated_created, "w") as f:
        f.write("totally different content, unrelated file")
    unrelated_new = stat_identity(unrelated_created)
    unrelated_created_eval = mon2._evaluate_change(unrelated_created, "php_source", None, unrelated_new)
    not_correlated = mon2._correlate_renames([deleted_eval, unrelated_created_eval])
    assert len(not_correlated) == 2, f"unrelated delete+create must NOT be merged: {not_correlated}"
    assert {c["change_type"] for c in not_correlated} == {"deleted", "created"}
    print("Scenario 11b (unrelated delete+create with different content/inode -- NOT merged) PASSED")

    upload_path = os.path.join(proj, "public", "uploads", "cache.php")
    r_www_data = classify_risk(
        upload_path, "created", proj, False, owner_username="www-data",
    )
    assert r_www_data is not None and r_www_data.severity == Severity.HIGH, r_www_data
    print("Scenario 6b (risky script created by 'www-data' owner -- HIGH) PASSED")

    r_http_correlated = classify_risk(
        upload_path, "created", proj, False, http_correlated=True,
    )
    assert r_http_correlated is not None and r_http_correlated.severity == Severity.CRITICAL, r_http_correlated
    print("Scenario 6c (risky script created right after a suspicious HTTP request -- CRITICAL) PASSED")

    r_medium_active = classify_risk(
        os.path.join(proj, "package.json"), "modified", proj, False, deployment_status="ACTIVE",
    )
    r_medium_unknown = classify_risk(
        os.path.join(proj, "package.json"), "modified", proj, False,
    )
    assert r_medium_active.confidence < r_medium_unknown.confidence, (
        r_medium_active, r_medium_unknown,
    )
    assert r_medium_active.severity == r_medium_unknown.severity == Severity.MEDIUM
    r_critical_active = classify_risk(
        os.path.join(proj, ".env"), "modified", proj, False, deployment_status="ACTIVE",
    )
    r_critical_unknown = classify_risk(
        os.path.join(proj, ".env"), "modified", proj, False,
    )
    assert r_critical_active.confidence == r_critical_unknown.confidence == 0.95, (
        "deployment_status must NEVER soften a CRITICAL classification"
    )
    print("Scenario 10 (deployment ACTIVE damps MEDIUM confidence, never softens CRITICAL/.env) PASSED")

    mon3 = FileIntegrityDetector(EventBus(), FileIntegrityDetectorConfig())
    published = []
    mon3.publish = lambda ev: published.append(ev)
    bulk_changes = [
        {
            "path": f"/home/x/project/file{i}.js", "target_class": "php_source", "change_type": "modified",
            "severity": Severity.MEDIUM, "message": f"file{i} modified", "project": "project",
            "project_root": None, "linux_user": None, "domain": None, "runtime": None,
            "risk_reason": None, "recommendation": None, "confidence": None,
            "sha256_old": "a", "sha256_new": "b", "mode_old": None, "mode_new": None,
            "uid_old": None, "uid_new": None, "gid_old": None, "gid_new": None,
        }
        for i in range(50)
    ]
    await mon3._publish_changes("php_source", bulk_changes)
    assert len(published) == 1, (
        f"50 simultaneous MEDIUM changes must aggregate into exactly one summarized event, got {len(published)}"
    )
    assert published[0].category == EventCategory.FILE_INTEGRITY_CHANGE
    print("Scenario 15 (50 simultaneous file changes -- aggregated into one event, not a storm) PASSED")

    print("\nALL FIM RENAME/RISK-EXTENSION REGRESSION TESTS PASSED")


asyncio.run(main())
