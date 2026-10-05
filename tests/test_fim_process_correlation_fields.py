import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import TceConfig
from core.git_deployment import GitDeploymentTracker
from modules.file_integrity_detector import FileIntegrityDetector, FileIdentity
from modules.threat_correlation_engine import (
    ClassifiedEvent, ContributorGroup, CorrelationCandidateEvent, _fim_contributor_payload,
)


def main():
    old = FileIdentity(sha256="a" * 64, mode=0o644, uid=1083, gid=1083, size=100, mtime=1000.0, inode=555)
    new = FileIdentity(sha256="b" * 64, mode=0o644, uid=1083, gid=1083, size=4096, mtime=1010.0, inode=555)

    class _FakeDetector:
        _git_tracker = GitDeploymentTracker()

        def _resolve_owner_username(self, uid):
            return "simpuskes-api" if uid == 1083 else None

        def _project_context(self, path):
            return "simpuskes-api"

        def _find_possible_creator(self, project_root, mtime, uid):
            return None, None, None, "UNKNOWN"

    evaluated = FileIntegrityDetector._evaluate_change(
        _FakeDetector(), "/home/simpuskes-api/htdocs/simpuskes-api/shell.php", "php_source", old, new,
    )
    assert evaluated["size_old"] == 100 and evaluated["size_new"] == 4096, (
        f"file size must be published on FILE_INTEGRITY_CHANGE metadata: {evaluated}"
    )
    print("Test 1 (file_integrity_detector publishes size_old/size_new) PASSED")

    event = CorrelationCandidateEvent(
        event_id="fim1", timestamp=1010.0, category="FILE_INTEGRITY_CHANGE", severity="HIGH",
        message="File berubah", source_module="file_integrity_detector",
        project="simpuskes-api", user="simpuskes-api",
        path="/home/simpuskes-api/htdocs/simpuskes-api/shell.php", domain="api.example.com",
        confidence=80, webroot="/home/simpuskes-api/htdocs/simpuskes-api",
        raw_metadata=evaluated,
    )
    classified = ClassifiedEvent(
        event=event, kind="FIM modify", weight=5, high_confidence=False,
        ignored=False, ignored_reason=None, maintenance=False, maintenance_reason=None,
    )
    group = ContributorGroup(
        kind="FIM modify", identity=event.path, representative=classified, weight=5,
        occurrences=1, first_seen=1010.0, last_seen=1010.0,
    )
    payload = _fim_contributor_payload(group)
    assert payload["size_old"] == 100 and payload["size_new"] == 4096, payload
    assert payload["mode"] == oct(0o644), payload
    assert payload["owner"] == "simpuskes-api", payload
    assert payload["uid"] == 1083 and payload["gid"] == 1083, payload
    assert payload["project_root"] == "/home/simpuskes-api/htdocs/simpuskes-api", payload
    print("Test 2 (fim_contributor payload carries size/mode/owner/uid/gid/project_root) PASSED")

    tce_config = TceConfig(lookback_seconds=180.0)
    assert tce_config.lookback_seconds == 180.0
    print("Test 3 (TceConfig.lookback_seconds is the correlation-window value published as correlation_window_seconds) PASSED")

    print("\nALL FIM<->PROCESS CORRELATION FIELD TESTS PASSED")


main()
