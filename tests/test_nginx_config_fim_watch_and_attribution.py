import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import CriticalSystemWatchConfig
from core import cloudpanel_resolver
from core.cloudpanel_resolver import CloudPanelAsset
from core.fim_risk_classifier import classify_risk
from core.git_deployment import GitDeploymentTracker
from modules.file_integrity_detector import FileIntegrityDetector, _cloudpanel_context_for_nginx_conf


def main():
    cfg = CriticalSystemWatchConfig()
    assert "/etc/nginx/sites-enabled" in cfg.watched_system_directories, (
        f"nginx vhost configs must be a watched critical-system directory by default so config "
        f"changes are actually detected, got {cfg.watched_system_directories}"
    )
    print("Test 1 (default watched_system_directories includes /etc/nginx/sites-enabled) PASSED")

    classification = classify_risk(
        "/etc/nginx/sites-enabled/example.com.conf", "modified", None, False,
    )
    assert classification is not None and classification.severity.value == "HIGH", classification
    print("Test 2 (nginx config change already classified HIGH by fim_risk_classifier) PASSED")

    real_assets = dict(cloudpanel_resolver._assets_by_domain)
    try:
        cloudpanel_resolver._assets_by_domain.clear()
        cloudpanel_resolver._assets_by_domain["example.com"] = CloudPanelAsset(
            domain="example.com", linux_user="exampleuser",
            project_root="/home/exampleuser", htdocs_path="/home/exampleuser/htdocs/example.com",
            nginx_vhost="/etc/nginx/sites-enabled/example.com.conf", pm2_user="exampleuser",
            discovered_at=0.0,
        )

        asset = _cloudpanel_context_for_nginx_conf("/etc/nginx/sites-enabled/example.com.conf")
        assert asset is not None and asset.domain == "example.com" and asset.linux_user == "exampleuser"
        print("Test 3 (nginx conf filename resolves to CloudPanel domain/user/project via sync cache) PASSED")

        assert _cloudpanel_context_for_nginx_conf("/etc/nginx/nginx.conf") is None, (
            "a non-sites-enabled nginx file must never be force-matched to a domain"
        )
        assert _cloudpanel_context_for_nginx_conf("/etc/nginx/sites-enabled/unknown-domain.conf") is None, (
            "an unresolvable domain must return None, never a fabricated asset"
        )
        print("Test 4 (unmatched paths/domains never fabricate a CloudPanel asset) PASSED")

        class _FakeDetector:
            _git_tracker = GitDeploymentTracker()

            def _resolve_owner_username(self, uid):
                return None

            def _project_context(self, path):
                return None

            def _find_possible_creator(self, project_root, mtime, uid):
                return None, None, None, "UNKNOWN"

        from core.file_identity import FileIdentity
        old = FileIdentity(sha256="a" * 64, mode=0o644, uid=0, gid=0, size=500, mtime=1000.0, inode=1)
        new = FileIdentity(sha256="b" * 64, mode=0o644, uid=0, gid=0, size=520, mtime=1010.0, inode=1)
        evaluated = FileIntegrityDetector._evaluate_change(
            _FakeDetector(), "/etc/nginx/sites-enabled/example.com.conf", "system_file", old, new,
        )
        assert evaluated["domain"] == "example.com", evaluated
        assert evaluated["linux_user"] == "exampleuser", evaluated
        assert evaluated["project_root"] == "/home/exampleuser", evaluated
        print("Test 5 (FIM event for nginx config change carries resolved domain/user/project_root, end to end) PASSED")
    finally:
        cloudpanel_resolver._assets_by_domain.clear()
        cloudpanel_resolver._assets_by_domain.update(real_assets)

    print("\nALL NGINX CONFIG FIM WATCH + CLOUDPANEL ATTRIBUTION TESTS PASSED")


main()
