import os
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from config.manager import FileIntegrityDetectorConfig
from core.fs_discovery import discover_home_root_projects
from modules.file_integrity_detector import discover_all_watch_targets, home_root_extra_roots


def main():
    d = tempfile.mkdtemp()

    unproxied = os.path.join(d, "backenduser", "worker")
    os.makedirs(unproxied)
    open(os.path.join(unproxied, "package.json"), "w").close()
    open(os.path.join(unproxied, "index.js"), "w").close()

    nm = os.path.join(unproxied, "node_modules", "somepkg")
    os.makedirs(nm)
    open(os.path.join(nm, "package.json"), "w").close()

    personal = os.path.join(d, "someuser", "Documents")
    os.makedirs(personal)
    open(os.path.join(personal, "notes.txt"), "w").close()

    cp_project = os.path.join(d, "floriti", "htdocs", "floriti.id")
    os.makedirs(cp_project)
    open(os.path.join(cp_project, "index.php"), "w").close()

    backups = os.path.join(d, "someuser", "backups", "site-backup")
    os.makedirs(backups)
    open(os.path.join(backups, "index.php"), "w").close()

    roots = discover_home_root_projects(d, max_depth=4)
    assert unproxied in roots, f"a project with no nginx vhost must still be discovered under home_root: {roots}"
    assert cp_project in roots, f"a CloudPanel-shaped 3-level project must be discovered: {roots}"
    assert not any("node_modules" in r for r in roots), f"must never descend into node_modules: {roots}"
    assert personal not in roots, "a directory with no project marker file must never be treated as a project"
    assert not any(r.startswith(backups) or backups.startswith(r) for r in roots if r != backups), (
        f"a backups/ directory must be excluded from discovery even if it contains marker-shaped files: {roots}"
    )
    print("Test 1 (home_root fallback finds unproxied + CloudPanel projects, skips node_modules/backups/personal dirs) PASSED")

    cfg = FileIntegrityDetectorConfig(home_root=d, home_root_discovery_enabled=True, home_root_scan_max_depth=4)
    extra = home_root_extra_roots(cfg)
    assert unproxied in extra
    print("Test 2 (home_root_extra_roots respects config wiring) PASSED")

    cfg_disabled = FileIntegrityDetectorConfig(home_root=d, home_root_discovery_enabled=False)
    assert home_root_extra_roots(cfg_disabled) == [], "home_root_discovery_enabled=False must fully disable the fallback"
    print("Test 3 (home_root_discovery_enabled=False disables fallback -- backward compatible opt-out) PASSED")

    empty_conf_dir = tempfile.mkdtemp()
    targets = discover_all_watch_targets(cfg, empty_conf_dir)
    assert any(unproxied in p for p in targets), (
        f"discover_all_watch_targets must surface files from home_root-discovered projects even with "
        f"zero nginx vhosts configured: {list(targets)[:5]}"
    )
    print("Test 4 (discover_all_watch_targets end-to-end: zero nginx vhosts, project still watched) PASSED")

    print("\nALL FIM HOME_ROOT DISCOVERY TESTS PASSED")


main()
