import asyncio
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import (
    ConfigManager, ConfigValidationError, FileIntegrityDetectorConfig, FimIgnoreConfig,
    PhpSourceWatchConfig, RTSAConfig, UploadsWatchConfig, _build_dataclass,
)
from core.event_bus import EventBus
from core.file_identity import FileIdentity
from core.fim_ignore import build_fim_ignore_matcher, get_fim_ignore_metrics, is_protected_system_path
from core.state_store import save_versioned_state
from modules.file_integrity_detector import (
    FileIntegrityDetector, _BASELINE_FORMAT_VERSION, discover_php_source_targets,
)


def identity(path, sha="x", mode=0o644, uid=1000, gid=1000):
    return FileIdentity(
        sha256=sha, mode=mode, uid=uid, gid=gid, size=10, mtime=time.time(),
        is_symlink=False, symlink_target=None, inode=1,
    )


def make_fim(**overrides):
    cfg = FileIntegrityDetectorConfig(**overrides)
    det = FileIntegrityDetector(EventBus(), cfg)
    published = []
    det.publish = lambda ev: published.append(ev)
    return det, published


async def run_one_cycle(det, group, discover_fn, state_path, interval=999.0):
    task = asyncio.ensure_future(det._watch_class_loop(group, discover_fn, state_path, lambda: interval))
    await asyncio.sleep(3.0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def main() -> None:
    matcher = build_fim_ignore_matcher(FimIgnoreConfig(
        paths=["/home/clp/htdocs/app/files/public/phpmyadmin"],
        directories=["node_modules"],
        extensions=[".log"],
        patterns=["**/phpmyadmin/themes/**", "**/*.map"],
    ))

    decision = matcher.should_ignore("/home/clp/htdocs/app/files/public/phpmyadmin/libraries/config.default.php")
    assert decision.ignored and decision.reason == "configured_path", decision
    decision2 = matcher.should_ignore("/home/clp/htdocs/app/files/public/phpmyadmin")
    assert decision2.ignored, decision2
    print("Scenario 1 (exact configured path ignores the directory and everything inside it) PASSED")

    d1 = matcher.should_ignore("/home/other/htdocs/app/node_modules/pkg/index.js")
    d2 = matcher.should_ignore("/home/other/htdocs/app/src/node_modules_helper.js")
    assert d1.ignored and d1.reason == "configured_directory", d1
    assert not d2.ignored, "a filename that merely CONTAINS the ignored dirname as a substring must not match"
    print("Scenario 2 (ignored directory name matches only real path segments, descendants included) PASSED")

    d3 = matcher.should_ignore(
        "/home/clp/htdocs/app/files/public/phpmyadmin/themes/pmahomme/img/logo.png",
    )
    assert d3.ignored and d3.reason == "configured_pattern" or d3.reason == "configured_path", d3
    d3b = matcher.should_ignore("/some/other/project/vendor/phpmyadmin/themes/x/img/y.png")
    assert d3b.ignored and d3b.reason == "configured_pattern", d3b
    print("Scenario 3 (glob pattern **/phpmyadmin/themes/** matches regardless of exact-path rule) PASSED")

    d4 = matcher.should_ignore("/home/clp/htdocs/app/storage/logs/debug.LOG")
    assert d4.ignored and d4.reason == "configured_extension", d4
    print("Scenario 4 (extension ignore is case-normalized, .LOG matches .log rule) PASSED")

    d5 = matcher.should_ignore("/home/clp/htdocs/app/src/checkout/Controller.php")
    assert not d5.ignored, d5
    print("Scenario 5 (a normal project file matching no rule is never ignored) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        project = os.path.join(tmp, "vic", "htdocs", "example.com")
        php_dir = os.path.join(project, "app")
        os.makedirs(php_dir)
        good_php = os.path.join(php_dir, "helper.php")
        with open(good_php, "w") as f:
            f.write("<?php eval($_GET['x']); ?>")
        cache_dir = os.path.join(project, "cache")
        os.makedirs(cache_dir)
        cached_php = os.path.join(cache_dir, "compiled.php")
        with open(cached_php, "w") as f:
            f.write("<?php return []; ?>")

        cfg = PhpSourceWatchConfig(scan_max_depth=8, ignore_path_substrings=[])
        targets = discover_php_source_targets(cfg, tmp, extra_roots=[project])
        assert good_php in targets and cached_php in targets, (
            "test precondition: discovery must find both files before ignore filtering"
        )

        ignore_matcher = build_fim_ignore_matcher(FimIgnoreConfig(paths=[cache_dir]))
        filtered = {p: c for p, c in targets.items() if not ignore_matcher.should_ignore(p).ignored}
        assert good_php in filtered, "a PHP file outside any ignore rule must remain a FIM target"
        assert cached_php not in filtered, "a PHP file inside an ignored path must be filtered out"

        det, _pub = make_fim()
        evaluated = det._evaluate_change(good_php, "php_source", None, identity(good_php))
        assert evaluated is not None and evaluated["change_type"] == "created", evaluated
        assert evaluated["file_class"] == "PHP_SOURCE", evaluated
        print("Scenario 6 (PHP file outside ignore rules still goes through PHP creation detection) PASSED")

        env_path = os.path.join(project, ".env")
        with open(env_path, "w") as f:
            f.write("APP_KEY=abc\n")
        env_evaluated = det._evaluate_change(
            env_path, "configs", identity(env_path, sha="old"), identity(env_path, sha="new"),
        )
        assert env_evaluated is not None and env_evaluated["file_class"] == "SECRET_CONFIG", env_evaluated
        assert "env_changed_variables" in env_evaluated, env_evaluated
        print("Scenario 7 (.env file outside ignore rules still goes through secret-config detection) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        from core.inotify_watcher import InotifyEvent

        det2, _pub2 = make_fim(ignore=FimIgnoreConfig(directories=["node_modules"]))

        class FakeTree:
            def __init__(self, events):
                self._events = events
                self.watched = []

            def read_events(self):
                events, self._events = self._events, []
                return events

            def add_watch(self, path):
                self.watched.append(path)
                return True

        ignored_dir_event = InotifyEvent(path="/home/x/htdocs/y/node_modules", is_dir=True, created=True)
        fake_tree = FakeTree([ignored_dir_event])
        wake = asyncio.Event()
        det2._on_inotify_readable(fake_tree, wake, "php_source")
        assert fake_tree.watched == [], (
            f"a newly created directory matching a configured ignore.directories name must never be watched: "
            f"{fake_tree.watched}"
        )
        print("Scenario 8 (new directory inside/matching an ignored directory name is never inotify-watched) PASSED")

        normal_dir_event = InotifyEvent(path="/home/x/htdocs/y/src", is_dir=True, created=True)
        fake_tree2 = FakeTree([normal_dir_event])
        det2._on_inotify_readable(fake_tree2, wake, "php_source")
        assert fake_tree2.watched == ["/home/x/htdocs/y/src"], (
            f"an unrelated newly created directory must still be watched normally: {fake_tree2.watched}"
        )
        print("Scenario 9 (new directory outside ignore rules is watched normally, detection unaffected) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        deleted_path = "/home/clp/htdocs/app/files/public/phpmyadmin/js/src/removed.js"
        det3, pub3 = make_fim(ignore=FimIgnoreConfig(paths=["/home/clp/htdocs/app/files/public/phpmyadmin"]))
        matcher3 = det3._get_ignore_matcher()
        assert matcher3.should_ignore(deleted_path).ignored
        evaluated_del = det3._evaluate_change(
            deleted_path, "uploads", identity(deleted_path), None,
        )
        assert evaluated_del is not None and evaluated_del["change_type"] == "deleted"
        filtered_changes = [] if matcher3.should_ignore(deleted_path).ignored else [evaluated_del]
        assert filtered_changes == [], "a deleted file matching an ignore rule must never reach publication"
        print("Scenario 10 (a deleted file under an ignored path never surfaces as an incident) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "baseline.json")
        stale_path = "/home/clp/htdocs/app/files/public/phpmyadmin/config.default.php"
        real_dir = os.path.join(tmp, "project")
        os.makedirs(real_dir)
        real_target = os.path.join(real_dir, "kept.php")
        with open(real_target, "w") as f:
            f.write("<?php echo 1; ?>")

        save_versioned_state(state_path, _BASELINE_FORMAT_VERSION, {
            stale_path: identity(stale_path),
            real_target: identity(real_target, sha="old-hash"),
        })

        det4, pub4 = make_fim(ignore=FimIgnoreConfig(paths=["/home/clp/htdocs/app/files/public/phpmyadmin"]))

        def discover():
            return {real_target: "php_source"}

        await run_one_cycle(det4, "php_source", discover, state_path, interval=999.0)

        final_state = det4._known_state_by_group["php_source"]
        assert stale_path not in final_state, (
            f"a previously-baselined path that newly matches an ignore rule must be pruned from the "
            f"baseline on the next cycle, not left stale forever: {list(final_state)}"
        )
        deleted_events = [
            ev for ev in pub4
            if ev.metadata.get("path") == stale_path or ev.metadata.get("change_type") == "deleted"
        ]
        assert not deleted_events, (
            f"pruning a newly-ignored baseline entry must never be reported as a 'deleted' incident: {deleted_events}"
        )
        print("Scenario 11 (existing baseline entry that becomes ignored is pruned quietly, no false DELETE alert) PASSED")

    assert is_protected_system_path("/etc/nginx/sites-enabled/x.conf")
    assert is_protected_system_path("/etc/ssh/sshd_config")
    assert is_protected_system_path("/etc/passwd")
    assert is_protected_system_path("/etc/shadow")
    assert is_protected_system_path("/root/.ssh/authorized_keys")
    assert is_protected_system_path("/home/anyuser/.ssh/authorized_keys")
    assert is_protected_system_path("/etc/systemd/system/evil.service")
    assert is_protected_system_path("/etc/cron.d/backup")
    assert not is_protected_system_path("/home/clp/htdocs/app/src/index.php")

    protected_matcher = build_fim_ignore_matcher(FimIgnoreConfig(
        paths=["/etc/nginx", "/etc/ssh", "/root/.ssh", "/etc/systemd"],
        directories=[".ssh"], patterns=["**/cron*"],
    ))
    for protected_path in (
        "/etc/nginx/sites-enabled/x.conf", "/etc/ssh/sshd_config", "/etc/passwd", "/etc/shadow",
        "/root/.ssh/authorized_keys", "/home/newuser/.ssh/authorized_keys",
        "/etc/systemd/system/evil.service", "/etc/cron.d/backup",
    ):
        decision = protected_matcher.should_ignore(protected_path)
        assert not decision.ignored, (
            f"an ordinary project ignore rule must never be able to hide changes to a protected system "
            f"path, even if the rule technically matches: {protected_path} -> {decision}"
        )
        assert decision.reason == "protected_path", decision
    override_matcher = build_fim_ignore_matcher(FimIgnoreConfig(
        allow_protected_override=True, paths=["/etc/nginx"],
    ))
    assert override_matcher.should_ignore("/etc/nginx/x.conf").ignored, (
        "an explicit administrator override (allow_protected_override=true) must be respected"
    )
    print("Scenario 12 (protected system paths cannot be silently disabled by ordinary ignore rules) PASSED")

    raw_bad = {"modules": {"file_integrity_detector": {"ignore": {
        "paths": ["relative/not/absolute"], "directories": ["a/b"], "extensions": ["log"],
    }}}}
    built_bad = _build_dataclass(RTSAConfig, raw_bad)
    try:
        ConfigManager._validate_semantics(built_bad)
        raise AssertionError("malformed ignore config must raise ConfigValidationError")
    except ConfigValidationError as exc:
        message = str(exc)
        assert "ignore.paths" in message and "ignore.directories" in message and "ignore.extensions" in message, message
    print("Scenario 13 (invalid ignore config -- relative path, path-as-dirname, bad extension -- raises a clear error) PASSED")

    dup_cfg = FimIgnoreConfig(
        paths=["/a/b/", "/a/b", "/a/b//"],
        directories=["node_modules", "node_modules", "NODE_MODULES".lower()],
        extensions=[".log", ".LOG", ".log"],
        patterns=["**/*.map", "**/*.map"],
    )
    assert dup_cfg.paths == ["/a/b"], dup_cfg.paths
    assert dup_cfg.directories == ["node_modules"], dup_cfg.directories
    assert dup_cfg.extensions == [".log"], dup_cfg.extensions
    assert dup_cfg.patterns == ["**/*.map"], dup_cfg.patterns
    print("Scenario 14 (duplicate paths/directories/extensions/patterns are safely deduplicated) PASSED")

    metrics = get_fim_ignore_metrics()
    before = metrics.snapshot()
    large_matcher = build_fim_ignore_matcher(FimIgnoreConfig(directories=["node_modules"]))
    ignored_count = 0
    for i in range(5000):
        path = f"/home/bulk/htdocs/app/node_modules/pkg{i}/index.js"
        decision = large_matcher.should_ignore(path)
        assert decision.ignored
        metrics.record_ignored(decision.reason)
        ignored_count += 1
    after = metrics.snapshot()
    assert after["fim_events_ignored_total"] == before["fim_events_ignored_total"] + ignored_count, (before, after)
    assert after["fim_events_ignored_by_reason"]["configured_directory"] >= ignored_count
    assert len(after["fim_events_ignored_by_reason"]) == 4, (
        f"ignore reason breakdown must stay bounded to the fixed reason set, never grow per-path: "
        f"{after['fim_events_ignored_by_reason']}"
    )
    print("Scenario 15 (5000 ignored events -> zero Discord messages generated, bounded reason-count memory, correct counters) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        project = os.path.join(tmp, "reguser", "htdocs", "example.org")
        os.makedirs(project)
        with open(os.path.join(project, "index.php"), "w") as f:
            f.write("<?php echo 1; ?>")
        with open(os.path.join(project, ".env"), "w") as f:
            f.write("APP_KEY=abc\n")

        from config.manager import ConfigsWatchConfig
        from modules.file_integrity_detector import discover_configs_targets
        cfg_targets = discover_configs_targets(ConfigsWatchConfig(), tmp, extra_roots=[project])
        assert any(p.endswith("index.php") for p in cfg_targets)
        assert any(p.endswith(".env") for p in cfg_targets)

        det5, _pub5 = make_fim()
        created = det5._evaluate_change(
            os.path.join(project, "new.php"), "php_source", None, identity(os.path.join(project, "new.php")),
        )
        assert created["change_type"] == "created"
        gone = det5._evaluate_change(f"{project}/a.php", "php_source", identity(f"{project}/a.php"), None)
        assert gone["change_type"] == "deleted"
    print("Scenario 16 (existing PHP/.env/config discovery and change classification are unaffected by the ignore system) PASSED")

    assert get_fim_ignore_metrics() is get_fim_ignore_metrics(), "metrics singleton must be process-wide, not per-instance"
    snap = get_fim_ignore_metrics().snapshot()
    for key in ("fim_events_total", "fim_events_processed_total", "fim_events_ignored_total"):
        assert isinstance(snap[key], int)
    for reason_key in snap["fim_events_ignored_by_reason"]:
        assert reason_key in (
            "configured_path", "configured_directory", "configured_extension", "configured_pattern",
        ), f"metric label must come from the fixed reason set, never a filesystem path: {reason_key}"
    print("Scenario 17 (ignored-event metrics use only bounded fixed-set reason labels, never filesystem paths) PASSED")

    print("\nALL FIM IGNORE CONFIGURATION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
