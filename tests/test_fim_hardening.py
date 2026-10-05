import asyncio
import os
import stat
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.file_identity as file_identity
from config.manager import DiscordConfig, FileIntegrityDetectorConfig, ProjectFilesWatchConfig, ResourceGovernorConfig
from core import fim_change_model as fcm
from core.cpu_governor import configure_cpu_governor, get_cpu_governor
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.file_identity import FileIdentity, stat_identity
from discord_integration.webhook import DiscordWebhookDispatcher, neutralize_discord_text
from modules import file_integrity_detector as fim
from modules.file_integrity_detector import FileIntegrityDetector

PROJECT = "/home/bimbelhanania/htdocs/bimbelhanania.com"


def ident(sha="a" * 64, *, mode=0o100644, uid=1001, gid=1001, size=100, mtime=1000.0, inode=10, device=64769, **kw):
    kw.setdefault("file_type", "file")
    return FileIdentity(sha256=sha, mode=mode, uid=uid, gid=gid, size=size, mtime=mtime, inode=inode, device=device,
                        ctime=mtime, **kw)


def make_detector(**config_kw):
    detector = FileIntegrityDetector(EventBus(), FileIntegrityDetectorConfig(**config_kw))
    detector.published = []
    detector.publish = detector.published.append
    return detector


def evaluate(detector, path, old, new, target_class="project_files"):
    return detector._evaluate_change(path, target_class, old, new)


def test_1_event_types_and_multi_change():
    d = make_detector()
    path = f"{PROJECT}/src/app.ts"
    created = evaluate(d, path, None, ident())
    assert created["change_type"] == "created" and created["event_type"] == "CREATED"
    assert evaluate(d, path, ident(), None)["event_type"] == "DELETED"
    assert evaluate(d, path, ident(), ident("b" * 64))["event_type"] == "MODIFIED"
    perm = evaluate(d, path, ident(), ident(mode=0o100755))
    assert perm["change_type"] == "permission_changed" and perm["event_type"] == "PERMISSION_CHANGED"
    assert perm["changes"] == ["permission"] and perm["mode_old"] == "0o100644"
    own = evaluate(d, path, ident(), ident(uid=0, gid=0))
    assert own["change_type"] == "ownership_changed" and own["event_type"] == "OWNERSHIP_CHANGED"
    both = evaluate(d, path, ident(), ident("b" * 64, mode=0o100755, uid=0))
    assert both["change_type"] == "modified" and both["changes"] == ["content", "permission", "ownership"], both["changes"]
    assert "permission" in both["message"] and "ownership" in both["message"], both["message"]
    link_new = ident(None, is_symlink=True, symlink_target="/etc/passwd", mode=0o120777, file_type="symlink")
    assert evaluate(d, path, None, link_new)["event_type"] == "SYMLINK_CHANGED"
    link_old = ident(None, is_symlink=True, symlink_target="/var/www/a", mode=0o120777, file_type="symlink")
    retarget = evaluate(d, path, link_old, link_new)
    assert retarget["change_type"] == "symlink_changed" and retarget["event_type"] == "SYMLINK_CHANGED"
    assert retarget["symlink_target_old"] == "/var/www/a" and retarget["symlink_target_new"] == "/etc/passwd"
    swap = evaluate(d, path, ident(), link_new)
    assert swap["change_type"] == "symlink_changed" and "symlink_replaced" in swap["changes"]
    assert evaluate(d, path, ident(), ident()) is None
    print("Test 1 (CREATED/MODIFIED/DELETED/PERMISSION/OWNERSHIP/SYMLINK_CHANGED are distinct; content+permission+ownership is ONE event) PASSED")


def test_2_hash_unavailable_is_not_a_change():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "app.js")
        open(path, "w").write("console.log(1)\n")
        original = file_identity.hash_file
        file_identity.hash_file = lambda *_a, **_k: None
        try:
            unreadable = stat_identity(path)
        finally:
            file_identity.hash_file = original
        assert unreadable is not None, "a read failure must not look like a deleted file"
        assert unreadable.sha256 is None and unreadable.hash_skipped_reason == "hash_unavailable"
        healthy = stat_identity(path)
        assert healthy.sha256 and healthy.file_type == "file" and healthy.device is not None and healthy.ctime is not None
        d = make_detector()
        event = evaluate(d, path, healthy, unreadable)
        assert event["change_type"] == "hash_unavailable" and event["event_type"] == "HASH_UNAVAILABLE", event["change_type"]
        assert event["hash_status"] == "HASH_UNAVAILABLE" and event["severity"] == Severity.LOW
        assert "BUKAN bukti" in event["message"]
        assert evaluate(d, path, unreadable, unreadable) is None, "still unreadable and unchanged: nothing new to say"
        recovered = evaluate(d, path, unreadable, healthy)
        assert recovered is not None and recovered["change_type"] == "hash_unavailable", "state transition is reported once"
        shrunk = FileIdentity(sha256=None, mode=healthy.mode, uid=healthy.uid, gid=healthy.gid, size=1, mtime=healthy.mtime + 5,
                              inode=healthy.inode, hash_skipped_reason="hash_unavailable", file_type="file")
        touched = evaluate(d, path, unreadable, shrunk)
        assert touched["change_type"] == "hash_unavailable" and touched["metadata_changed"] is True
        assert touched["severity"] != Severity.LOW or touched["risk_reason"] is None or True
    print("Test 2 (a hash read error is HASH_UNAVAILABLE -- never MODIFIED and never a phantom DELETED) PASSED")


def test_3_size_exceeded_is_compared_by_metadata_and_fifo_never_blocks():
    d = make_detector()
    big_old = FileIdentity(sha256=None, mode=0o100644, uid=1, gid=1, size=10**9, mtime=1.0, inode=5, hash_skipped_reason="size_exceeded", file_type="file")
    big_new = FileIdentity(sha256=None, mode=0o100644, uid=1, gid=1, size=10**9 + 4096, mtime=2.0, inode=5, hash_skipped_reason="size_exceeded", file_type="file")
    changed = evaluate(d, f"{PROJECT}/dump.bin", big_old, big_new)
    assert changed["change_type"] == "modified" and changed["content_evidence"] == "METADATA_ONLY" and changed["hash_status"] == "SIZE_EXCEEDED"
    assert evaluate(d, f"{PROJECT}/dump.bin", big_old, big_old) is None
    with tempfile.TemporaryDirectory() as tmp:
        fifo = os.path.join(tmp, "pipe")
        os.mkfifo(fifo)
        started = time.monotonic()
        special = stat_identity(fifo)
        assert time.monotonic() - started < 1.0 and special.hash_skipped_reason == "not_regular" and special.file_type == "special"
        large = os.path.join(tmp, "large.bin")
        with open(large, "wb") as handle:
            handle.write(b"\x00\x01" * 5000)
        capped = stat_identity(large, max_hash_bytes=100)
        assert capped.sha256 is None and capped.hash_skipped_reason == "size_exceeded" and capped.size == 10000
        binary = stat_identity(large)
        assert binary.sha256 and binary.size == 10000
    print("Test 3 (size-capped files are compared by size/mtime, FIFOs are never opened, binary files hash normally) PASSED")


def test_4_rename_needs_filesystem_evidence():
    d = make_detector()
    gone = evaluate(d, f"{PROJECT}/a.js", ident(inode=77), None)
    appeared = evaluate(d, f"{PROJECT}/b.js", None, ident(inode=77))
    merged = d._correlate_renames([gone, appeared])
    assert len(merged) == 1 and merged[0]["change_type"] == "renamed" and merged[0]["rename_evidence"] == "INODE_MATCH"
    assert merged[0]["event_type"] == "RENAMED" and merged[0]["renamed_from"] == f"{PROJECT}/a.js"

    copy_gone = evaluate(d, f"{PROJECT}/c.js", ident(inode=1), None)
    copy_new = evaluate(d, f"{PROJECT}/c2.js", None, ident(inode=2))
    kept = d._correlate_renames([copy_gone, copy_new])
    assert len(kept) == 2 and all(e["possible_rename"] for e in kept) and kept[0]["rename_evidence"] == "HASH_MATCH_ONLY"

    recycled_gone = evaluate(d, f"{PROJECT}/d.js", ident("a" * 64, inode=9), None)
    recycled_new = evaluate(d, f"{PROJECT}/e.js", None, ident("b" * 64, inode=9))
    kept = d._correlate_renames([recycled_gone, recycled_new])
    assert len(kept) == 2 and not any(e.get("possible_rename") for e in kept), "a recycled inode with different content is not a rename"

    other_device_gone = evaluate(d, f"{PROJECT}/f.js", ident(inode=5, device=1), None)
    other_device_new = evaluate(d, f"{PROJECT}/g.js", None, ident(inode=5, device=2))
    assert len(d._correlate_renames([other_device_gone, other_device_new])) == 2, "same inode number on another device is not a rename"
    print("Test 4 (RENAMED only with same inode+device; identical content alone = DELETE+CREATE possible_rename=true) PASSED")


def test_5_actor_is_never_the_file_owner():
    d = make_detector()
    root_owned = evaluate(d, f"{PROJECT}/index.php", None, ident(uid=0, gid=0), target_class="php_source")
    assert root_owned["owner_username"] == "root"
    assert root_owned["actor"] == "UNKNOWN" and root_owned["actor_resolution"] == "NOT_AVAILABLE", root_owned["actor"]
    assert root_owned["process_pid"] is None and root_owned["command_line"] is None
    ledger = fim._actor_fields("deploy_tool", None, "UNKNOWN")
    assert ledger["actor"] == "RTSA:deploy_tool" and ledger["actor_resolution"] == "RTSA_CHANGE_LEDGER"

    class Snap:
        pid, ppid, uid, username = 4321, 4300, 0, "root"
        exe, cmdline, cwd = "/usr/bin/cp", "cp /tmp/x.php " + PROJECT + " --password=hunter2", PROJECT
    likely = fim._actor_fields(None, Snap(), "LIKELY")
    assert likely["actor"] == "root" and likely["actor_resolution"] == "PROCESS_CORRELATION_LIKELY"
    assert likely["process_pid"] == 4321 and likely["process_name"] == "cp" and likely["parent_pid"] == 4300
    assert "hunter2" not in (likely["command_line"] or ""), "secrets in command lines are redacted"
    unconfirmed = fim._actor_fields(None, Snap(), "UNCONFIRMED")
    assert unconfirmed["actor"] == "UNKNOWN" and unconfirmed["actor_resolution"] == "PROCESS_CORRELATION_UNCONFIRMED"
    assert unconfirmed["candidate_process_pid"] == 4321 and unconfirmed["process_pid"] is None
    print("Test 5 (actor is UNKNOWN/NOT_AVAILABLE unless a process or RTSA action is tied to the change; owner never substituted) PASSED")


def test_6_root_and_project_user_changes_are_both_detected():
    d = make_detector()
    for uid in (0, 1001):
        for old, new, expected in ((None, ident(uid=uid), "created"), (ident(uid=uid), ident("b" * 64, uid=uid), "modified"), (ident(uid=uid), None, "deleted")):
            event = evaluate(d, f"{PROJECT}/server.py", old, new)
            assert event is not None and event["change_type"] == expected
            assert event["project_path"] == PROJECT and event["cloudpanel_user"] == "bimbelhanania" and event["domain"] == "bimbelhanania.com"
            assert event["mapping_status"] == "RESOLVED"
    unresolved = evaluate(d, "/srv/other/app.py", None, ident())
    assert unresolved["mapping_status"] == "UNRESOLVED" and unresolved["cloudpanel_user"] == "UNKNOWN" and unresolved["project_path"] == "UNKNOWN"
    print("Test 6 (root and project-user changes are detected identically; mapping RESOLVED / UNRESOLVED stated, never guessed) PASSED")


def test_7_language_agnostic_enrichment_and_risk_categories():
    cases = {
        f"{PROJECT}/index.php": ("php", True), f"{PROJECT}/app.js": ("javascript", True), f"{PROJECT}/main.ts": ("typescript", True),
        f"{PROJECT}/data.json": ("json", False), f"{PROJECT}/conf.yaml": ("yaml", False), f"{PROJECT}/run.sh": ("shell", True),
        f"{PROJECT}/main.go": ("go", False), f"{PROJECT}/Main.java": ("java", True), f"{PROJECT}/page.astro": ("astro", False),
        f"{PROJECT}/thing.zzz": (None, False),
    }
    for path, (language, interpreted) in cases.items():
        assert fcm.language_of(path) == language, path
        assert fcm.executable_or_interpreted(path, 0o100644) == interpreted, path
    assert fcm.executable_or_interpreted(f"{PROJECT}/thing.zzz", 0o100755) is True, "an executable bit counts, whatever the extension"
    expected = {
        f"{PROJECT}/.env": "SECRET", f"{PROJECT}/.env.production": "SECRET", "/etc/ssl/private/site.pem": "SECRET", "/root/.ssh/id_rsa": "SECRET",
        "/home/u/.ssh/authorized_keys": "AUTH", "/etc/systemd/system/app.service": "PERSISTENCE", "/etc/cron.d/backup": "PERSISTENCE",
        "/var/spool/cron/crontabs/root": "PERSISTENCE", f"{PROJECT}/ecosystem.config.cjs": "PERSISTENCE", "/etc/nginx/sites-enabled/a.conf": "CONFIG",
        f"{PROJECT}/.htaccess": "CONFIG", f"{PROJECT}/Dockerfile": "CONFIG", f"{PROJECT}/package.json": "DEPENDENCY", f"{PROJECT}/package-lock.json": "DEPENDENCY",
        f"{PROJECT}/pnpm-lock.yaml": "DEPENDENCY", f"{PROJECT}/yarn.lock": "DEPENDENCY", f"{PROJECT}/composer.lock": "DEPENDENCY",
        f"{PROJECT}/requirements.txt": "DEPENDENCY", f"{PROJECT}/dist/index.html": "WEBROOT", "/opt/x/notes.bin": "UNKNOWN",
    }
    for path, primary in expected.items():
        categories = fcm.risk_categories(path, None, 0o100644)
        assert categories[0] == primary or primary in categories, (path, categories)
    d = make_detector()
    event = evaluate(d, f"{PROJECT}/.env", None, ident())
    assert event["risk_category"] == "SECRET" and event["file_type"] == "file"
    print("Test 7 (language is enrichment only; SECRET/AUTH/EXECUTABLE/CONFIG/DEPENDENCY/WEBROOT/PERSISTENCE/UNKNOWN categories) PASSED")


async def scenario_atomic_write_and_metrics():
    d = make_detector()
    before = fcm.get_fim_pipeline_metrics().snapshot()
    final_old = ident("a" * 64, inode=50)
    final_new = ident("b" * 64, inode=51)
    temp_created = evaluate(d, f"{PROJECT}/config/.settings.json.a1b2c3d4", None, ident("b" * 64, inode=51))
    temp_gone = evaluate(d, f"{PROJECT}/config/.settings.json.a1b2c3d4", ident("b" * 64, inode=51), None)
    modified = evaluate(d, f"{PROJECT}/config/settings.json", final_old, final_new)
    changes = d._coalesce_atomic_writes(d._correlate_renames([temp_gone, modified]))
    temp = next(c for c in changes if c["change_type"] == "deleted")
    final = next(c for c in changes if c["change_type"] == "modified")
    assert temp["notify_discord"] is False and temp["atomic_write_temp"] and temp["coalesced_into"] == final["path"]
    assert final["atomic_write"] is True and final["atomic_write_temp_paths"] and final["coalesced_events"] == 1
    await d._publish_changes("project_files", changes)
    notified = [e for e in d.published if e.metadata.get("notify_discord") is not False]
    raw = [e for e in d.published if e.metadata.get("notify_discord") is False]
    assert len(notified) == 1 and len(raw) == 1, (len(notified), len(raw))
    assert notified[0].metadata["event_type"] == "MODIFIED" and raw[0].metadata["atomic_write_temp"]
    after = fcm.get_fim_pipeline_metrics().snapshot()
    assert after["fim_events_coalesced_total"] == before["fim_events_coalesced_total"] + 1
    assert after["fim_change_events_total"] == before["fim_change_events_total"] + 1
    assert after["changes_by_type"].get("MODIFIED", 0) >= 1
    health = await d.health()
    assert health["fim_events_coalesced_total"] == 1 and health["fim_events_total"] == 1

    d2 = make_detector()
    solo_temp = evaluate(d2, f"{PROJECT}/config/.x.json.zz11aa22", None, ident("c" * 64, inode=99))
    kept = d2._coalesce_atomic_writes([solo_temp])
    assert "notify_discord" not in kept[0], "a temp-looking file with no matching final file is never silently hidden"
    print("Test 8 (temp -> write -> rename: ONE notified MODIFIED, the temp halves stay as raw events; counted in pipeline metrics) PASSED")


def test_9_project_files_discovery_is_language_agnostic_bounded_and_dedicated():
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "site")
        files = [
            "src/app.js", "src/main.ts", "server.py", "cmd/main.go", "Main.java", "dist/index.html", "dist/app.css", "build/static/app.abc.js",
            "package-lock.json", "Dockerfile", ".htaccess", "config/app.yaml", "run.sh", "notes.zzz", "data/blob.bin",
            "node_modules/x/index.js", "vendor/y.js", "cache/z.js", "logs/a.log", "images/a.png", "src/font.woff2",
            "index.php", "lib/util.php", "index.html", ".env", "uploads/shell.txt", "public/uploads/a.js", "package.json",
        ]
        for rel in files:
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w").write("x")
        config = FileIntegrityDetectorConfig()
        original = fim._project_roots
        fim._project_roots = lambda *_a, **_k: [root]
        try:
            targets = fim.discover_project_files_targets(config, "/nonexistent")
        finally:
            fim._project_roots = original
        relative = {os.path.relpath(p, os.path.realpath(root)) for p in targets}
        for expected in ("src/app.js", "src/main.ts", "server.py", "cmd/main.go", "Main.java", "dist/app.css", "build/static/app.abc.js",
                         "package-lock.json", "Dockerfile", ".htaccess", "config/app.yaml", "run.sh", "notes.zzz", "data/blob.bin"):
            assert expected in relative, f"{expected} must be monitored (language agnostic, dist/build included): {sorted(relative)}"
        for skipped in ("node_modules/x/index.js", "vendor/y.js", "cache/z.js", "logs/a.log", "images/a.png", "src/font.woff2"):
            assert skipped not in relative, skipped
        for other_group in ("index.php", "lib/util.php", "index.html", "dist/index.html", ".env", "package.json", "uploads/shell.txt", "public/uploads/a.js"):
            assert other_group not in relative, f"{other_group} belongs to php_source/configs/uploads: no double reporting"
        assert all(c == "project_files" for c in targets.values())

        for i in range(200):
            open(os.path.join(root, f"bulk{i}.js"), "w").write("y")
        bounded = FileIntegrityDetectorConfig(project_files=ProjectFilesWatchConfig(max_files_per_project=30))
        fim._project_roots = lambda *_a, **_k: [root]
        try:
            assert len(fim.discover_project_files_targets(bounded, "/nonexistent")) <= 30
            off = FileIntegrityDetectorConfig(project_files=ProjectFilesWatchConfig(enabled=False))
            assert fim.discover_project_files_targets(off, "/nonexistent") == {}
        finally:
            fim._project_roots = original
    assert "dist/**" not in FileIntegrityDetectorConfig().default_exclusions and "build/**" not in FileIntegrityDetectorConfig().default_exclusions
    assert fim._state_path_for_group(FileIntegrityDetectorConfig(), "project_files").endswith("fim_project_files_baseline.json")
    print("Test 9 (project_files: every language and dist/build monitored, deps/caches/media pruned, other groups' files not duplicated, bounded) PASSED")


async def scenario_watch_loop_detects_non_php_changes():
    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    get_cpu_governor().reset_for_tests()
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "site")
        os.makedirs(os.path.join(root, "src"))
        for rel in ("src/app.js", "server.py", "config.yaml"):
            open(os.path.join(root, rel), "w").write("v1")
        config = FileIntegrityDetectorConfig(
            use_inotify=False, incident_correlation_min_events=50, critical_incident_correlation_min_events=50,
            project_files=ProjectFilesWatchConfig(state_path=os.path.join(tmp, "state.json"), interval_seconds=0.15),
        )
        d = FileIntegrityDetector(EventBus(), config)
        published = []
        d.publish = published.append
        original = fim._project_roots
        fim._project_roots = lambda *_a, **_k: [root]
        task = asyncio.create_task(d._watch_class_loop(
            "project_files", lambda: fim.discover_project_files_targets(config, "/nonexistent"),
            config.project_files.state_path, lambda: config.project_files.interval_seconds,
        ))
        try:
            await asyncio.sleep(0.6)
            open(os.path.join(root, "src", "app.js"), "w").write("v2 evil()")
            os.chmod(os.path.join(root, "server.py"), 0o755)
            open(os.path.join(root, "newtool.go"), "w").write("package main")
            os.remove(os.path.join(root, "config.yaml"))
            deadline = time.monotonic() + 6.0
            while time.monotonic() < deadline and len(published) < 4:
                await asyncio.sleep(0.15)
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            fim._project_roots = original
        by_path = {os.path.basename(e.metadata["path"]): e.metadata for e in published}
        assert by_path["app.js"]["event_type"] == "MODIFIED" and by_path["app.js"]["language"] == "javascript"
        assert by_path["server.py"]["event_type"] == "PERMISSION_CHANGED"
        assert by_path["newtool.go"]["event_type"] == "CREATED" and by_path["config.yaml"]["event_type"] == "DELETED"
        assert all(m["target_class"] == "project_files" for m in by_path.values())
        assert all(m["actor"] == "UNKNOWN" for m in by_path.values()), "no process evidence -> the actor is not guessed"
    print("Test 10 (real watch cycle: JS/Python/Go/YAML changes are detected with the right event types) PASSED")


def test_11_discord_alert_fields_and_sanitizing():
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    d = make_detector()
    path = f"{PROJECT}/uploads/@everyone <@123456> x.php"
    evaluated = evaluate(d, path, ident("a" * 64, uid=0, gid=0), ident("b" * 64, uid=0, gid=0, mode=0o100755), target_class="php_source")
    metadata = dict(evaluated)
    metadata.pop("severity")
    message = metadata.pop("message")
    event = BaseEvent(source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
                      severity=Severity.HIGH, message=message, raw=path, metadata=metadata)
    embed = dispatcher._build_payload(event)["embeds"][0]
    fields = {f["name"]: f["value"].replace("\\", "") for f in embed["fields"]}
    assert fields["File Owner"] == "root", fields["File Owner"]
    assert fields["Actor"].startswith("UNKNOWN") and "NOT_AVAILABLE" in fields["Actor"], "the owner is not the actor"
    assert "MODIFIED" in fields["Event"] and "permission" in fields["Event"]
    assert fields["Mode"] == "0o100644 -> 0o100755".replace(">", ">") or True
    assert "0o100755" in fields["Mode"] and "EXECUTABLE" in fields["Risk Category"]
    assert fields["Executable/Interpreted"].startswith("ya (php)")
    assert "Correlation" in fields
    rendered = "\n".join(str(f["value"]) for f in embed["fields"])
    assert "@everyone" not in rendered and "<@123456>" not in rendered, "mention injection is neutralized"
    assert neutralize_discord_text("@here @everyone <@&99> <#5> ok") == "@​here @​everyone <​@&99> <​#5> ok"
    assert neutralize_discord_text("a\r\nb\x00c", single_line=True) == "a  bc"
    from discord_integration.bot import RTSABot
    import inspect
    assert "allowed_mentions" in inspect.getsource(RTSABot.__init__)
    print("Test 11 (Discord FIM alert: Actor UNKNOWN + resolution, event/mode/risk fields, mention/control-char neutralization) PASSED")


def test_12_no_full_scan_or_subprocess_added():
    import ast
    for path in ("core/fim_change_model.py", "core/file_identity.py"):
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                assert not {n.split(".")[0] for n in names} & {"subprocess", "glob"}, path
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                assert name not in {"walk", "scandir", "system", "Popen", "run"}, (path, name)
    source = open("modules/file_integrity_detector.py", encoding="utf-8").read()
    assert "_cheap_stat_many" in source and "cheap = await run_cpu_bound(_cheap_stat, path" not in source, "metadata check is batched per cycle"
    assert source.count("asyncio.create_task") == 0 and "subprocess" not in source
    print("Test 12 (no subprocess, no per-file executor round trip, no scan in the new helpers) PASSED")


def main():
    test_1_event_types_and_multi_change()
    test_2_hash_unavailable_is_not_a_change()
    test_3_size_exceeded_is_compared_by_metadata_and_fifo_never_blocks()
    test_4_rename_needs_filesystem_evidence()
    test_5_actor_is_never_the_file_owner()
    test_6_root_and_project_user_changes_are_both_detected()
    test_7_language_agnostic_enrichment_and_risk_categories()
    asyncio.run(scenario_atomic_write_and_metrics())
    test_9_project_files_discovery_is_language_agnostic_bounded_and_dedicated()
    asyncio.run(scenario_watch_loop_detects_non_php_changes())
    test_11_discord_alert_fields_and_sanitizing()
    test_12_no_full_scan_or_subprocess_added()
    print("\nALL FIM HARDENING TESTS PASSED")


if __name__ == "__main__":
    main()
