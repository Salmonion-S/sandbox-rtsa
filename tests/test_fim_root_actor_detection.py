from __future__ import annotations

import os
import pwd
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import FileIntegrityDetectorConfig
from core.datatypes import Severity
from core.event_bus import EventBus
from core.file_identity import FileIdentity
from core.fim_risk_classifier import HIGH_RISK, SUSPICIOUS as SUSPICIOUS_ASSESSMENT
from modules.file_integrity_detector import FileIntegrityDetector, _project_info

_PROJECT_ROOT = "/home/puhantranztravel/htdocs/puhantranztravel.com"
_ROOT_UID = 0
_PROJECT_USER_UID = 4242


def _identity(*, uid: int, sha256: str = "a" * 64, mode: int = 0o644, mtime: float = 1_700_000_000.0) -> FileIdentity:
    return FileIdentity(sha256=sha256, mode=mode, uid=uid, gid=uid, size=123, mtime=mtime)


def _resolve_root_username() -> str:
    return pwd.getpwuid(0).pw_name


def main() -> None:
    root_username = _resolve_root_username()
    assert root_username == "root", f"unexpected /etc/passwd uid 0 name in this sandbox: {root_username}"

    detector = FileIntegrityDetector(EventBus(), FileIntegrityDetectorConfig())

    info = _project_info(f"{_PROJECT_ROOT}/shell.php")
    assert info == (_PROJECT_ROOT, "puhantranztravel", "puhantranztravel.com"), info
    print("Test 1 (project boundary correctly recognizes the target path -> project=puhantranztravel.com) PASSED")

    root_create = detector._evaluate_change(
        f"{_PROJECT_ROOT}/shell.php", "php_source", None, _identity(uid=_ROOT_UID),
    )
    assert root_create is not None, "a root-originated CREATE inside a monitored project must never be dropped"
    assert root_create["owner_username"] == "root", root_create
    assert root_create["change_type"] == "created"
    assert root_create["severity"] == Severity.HIGH, (
        f"a new PHP file must be HIGH severity regardless of actor -- got {root_create['severity']}"
    )
    assert root_create["project_root"] == _PROJECT_ROOT
    print("Test 2 (ROOT CREATE of a new PHP file -> event produced, actor=root, severity=HIGH) PASSED")

    user_create = detector._evaluate_change(
        f"{_PROJECT_ROOT}/shell.php", "php_source", None, _identity(uid=_PROJECT_USER_UID),
    )
    assert user_create is not None
    assert user_create["severity"] == root_create["severity"] == Severity.HIGH
    assert user_create["risk_reason"] == root_create["risk_reason"], (
        "risk reasoning must be identical for user vs root -- actor must never enter the "
        "severity decision"
    )
    print("Test 3 (project-user CREATE of the same file -> same severity/reason as root -- no actor-based discount) PASSED")

    old_id = _identity(uid=_ROOT_UID, sha256="a" * 64, mtime=1_700_000_000.0)
    new_id = _identity(uid=_ROOT_UID, sha256="b" * 64, mtime=1_700_000_100.0)
    root_modify = detector._evaluate_change(f"{_PROJECT_ROOT}/shell.php", "php_source", old_id, new_id)
    assert root_modify is not None
    assert root_modify["change_type"] == "modified"
    assert root_modify["owner_username"] == "root"
    print("Test 4 (ROOT MODIFY -> event produced, change_type=modified, actor=root) PASSED")

    root_delete = detector._evaluate_change(f"{_PROJECT_ROOT}/shell.php", "php_source", old_id, None)
    assert root_delete is not None
    assert root_delete["change_type"] == "deleted"
    assert root_delete["owner_username"] == "root"
    print("Test 5 (ROOT DELETE -> event produced, change_type=deleted, actor=root) PASSED")

    same_content = "c" * 64
    deleted_entry = detector._evaluate_change(
        f"{_PROJECT_ROOT}/fim-root-test.php", "php_source",
        _identity(uid=_ROOT_UID, sha256=same_content), None,
    )
    created_entry = detector._evaluate_change(
        f"{_PROJECT_ROOT}/fim-root-renamed.php", "php_source",
        None, _identity(uid=_ROOT_UID, sha256=same_content),
    )
    correlated = detector._correlate_renames([deleted_entry, created_entry])
    assert len(correlated) == 2, "identical content without inode evidence must NOT be declared a rename"
    assert all(c.get("possible_rename") is True for c in correlated), correlated
    assert {c["change_type"] for c in correlated} == {"deleted", "created"}
    print("Test 6a (ROOT delete+create of identical content, no inode evidence -> stays DELETE+CREATE, possible_rename=true) PASSED")

    inode_old = _identity(uid=_ROOT_UID, sha256=same_content)
    inode_old.inode, inode_old.device = 777, 64769
    inode_new = _identity(uid=_ROOT_UID, sha256=same_content)
    inode_new.inode, inode_new.device = 777, 64769
    deleted_entry = detector._evaluate_change(f"{_PROJECT_ROOT}/fim-root-test.php", "php_source", inode_old, None)
    created_entry = detector._evaluate_change(f"{_PROJECT_ROOT}/fim-root-renamed.php", "php_source", None, inode_new)
    correlated = detector._correlate_renames([deleted_entry, created_entry])
    assert len(correlated) == 1, f"expected the delete+create pair to correlate into one rename, got {correlated}"
    assert correlated[0]["change_type"] == "renamed" and correlated[0]["rename_evidence"] == "INODE_MATCH"
    print("Test 6 (ROOT RENAME with same inode+device -> correlates into one RENAMED event) PASSED")

    user_old = _identity(uid=_PROJECT_USER_UID, sha256="a" * 64, mtime=1_700_000_000.0)
    user_new = _identity(uid=_PROJECT_USER_UID, sha256="b" * 64, mtime=1_700_000_100.0)
    u_create = detector._evaluate_change(f"{_PROJECT_ROOT}/user-file.php", "php_source", None, user_new)
    u_modify = detector._evaluate_change(f"{_PROJECT_ROOT}/user-file.php", "php_source", user_old, user_new)
    u_delete = detector._evaluate_change(f"{_PROJECT_ROOT}/user-file.php", "php_source", user_old, None)
    assert u_create is not None and u_create["change_type"] == "created"
    assert u_modify is not None and u_modify["change_type"] == "modified"
    assert u_delete is not None and u_delete["change_type"] == "deleted"
    assert all(c["owner_username"] != "root" for c in (u_create, u_modify, u_delete))
    print("Test 7 (project-user CREATE/MODIFY/DELETE all produce events with a non-root actor) PASSED")

    assert _project_info("/tmp/rtsa-root-test/foo.php") is None
    outside_change = detector._evaluate_change(
        "/tmp/rtsa-root-test/foo.php", "php_source", None, _identity(uid=_ROOT_UID),
    )
    assert outside_change is not None
    assert outside_change["project_root"] is None and outside_change["project"] is None, (
        "a path outside the /home/*/htdocs/*/ project boundary must never be attributed to a "
        "project, regardless of actor"
    )
    print("Test 8 (a non-project path like /tmp never resolves to a project, root or not -- no full-filesystem monitoring) PASSED")

    assert detector._resolve_owner_username(0) == "root"
    assert detector._resolve_owner_username(999_999_999) is None
    unresolvable = detector._evaluate_change(
        f"{_PROJECT_ROOT}/orphan.php", "php_source", None, _identity(uid=999_999_999),
    )
    assert unresolvable is not None and unresolvable["owner_username"] is None
    print("Test 9 (actor resolution: uid 0 -> literal 'root'; an unresolvable uid -> None/UNKNOWN, event still produced) PASSED")

    def _bulk_change(i: int, *, actor: str, assessment=None, project_root=_PROJECT_ROOT):
        return {
            "path": f"{project_root}/file{i}.js", "target_class": "php_source", "change_type": "modified",
            "severity": Severity.MEDIUM, "message": f"file{i} modified", "project": "puhantranztravel.com",
            "project_root": project_root, "linux_user": None, "domain": None, "runtime": None,
            "risk_reason": None, "recommendation": None, "confidence": None, "assessment": assessment,
            "owner_username": actor,
            "sha256_old": "a", "sha256_new": "b", "mode_old": None, "mode_new": None,
            "uid_old": None, "uid_new": None, "gid_old": None, "gid_new": None,
        }

    published = []
    detector.publish = lambda ev: published.append(ev)

    burst = [_bulk_change(i, actor="root") for i in range(20)]
    risky = dict(_bulk_change(20, actor="root", assessment=HIGH_RISK))
    risky["path"] = f"{_PROJECT_ROOT}/shell.php"
    burst.append(risky)

    import asyncio
    asyncio.run(detector._publish_changes("php_source", burst))
    assert len(published) == 1, f"expected one coalesced burst alert, got {len(published)}"
    burst_event = published[0]
    assert burst_event.metadata["event_count"] == 21
    assert "shell.php" in burst_event.message, (
        "a HIGH_RISK file pushed past the sample cutoff by burst volume must still be named "
        f"explicitly in the coalesced alert, not just counted -- message was:\n{burst_event.message}"
    )
    assert "File Berisiko" in burst_event.message
    print("Test 10 (a HIGH_RISK file buried past the burst sample cutoff is still named explicitly, actor=root) PASSED")

    published.clear()
    burst_user = [_bulk_change(i, actor="puhantranztravel") for i in range(20)]
    risky_user = dict(_bulk_change(20, actor="puhantranztravel", assessment=SUSPICIOUS_ASSESSMENT))
    risky_user["path"] = f"{_PROJECT_ROOT}/upload.php"
    burst_user.append(risky_user)
    asyncio.run(detector._publish_changes("configs", burst_user))
    assert len(published) == 1
    assert "upload.php" in published[0].message, published[0].message
    print("Test 10b (same security override for a project-user actor, not root-specific) PASSED")

    published.clear()
    critical = dict(_bulk_change(0, actor="root"))
    critical["severity"] = Severity.CRITICAL
    critical["path"] = f"{_PROJECT_ROOT}/webshell.php"
    asyncio.run(detector._publish_changes("php_source", [critical]))
    assert len(published) == 1
    assert published[0].metadata.get("change_type") != "bulk_activity", (
        "a lone CRITICAL change must publish individually, never absorbed into a bulk summary"
    )
    print("Test 11 (a lone CRITICAL change, actor=root, still publishes individually, never summarized) PASSED")

    print("\nALL FIM ROOT ACTOR DETECTION TESTS PASSED")


main()
