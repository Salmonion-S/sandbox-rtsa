import asyncio
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig, FileIntegrityDetectorConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.file_identity import FileIdentity, stat_identity
from core.fim_forensics import (
    CONTENT_BINARY, CONTENT_LARGE_TEXT, CONTENT_SECRET_CONFIG, CONTENT_TEXT, CONTENT_UNKNOWN,
    DEFAULT_MAX_DIFF_LINES, DEFAULT_MAX_SNAPSHOT_BYTES, classify_content_type, compute_unified_diff,
    get_forensic_metrics, read_bounded_snapshot, redact_secret_like_assignments,
)
from discord_integration.webhook import DiscordWebhookDispatcher, _forensic_diff_language
from modules.file_integrity_detector import FileIntegrityDetector, _stat_state_for_forensics

PROJECT = "/home/vic/htdocs/example.com"


def make_fim(**overrides):
    cfg = FileIntegrityDetectorConfig(**overrides)
    det = FileIntegrityDetector(EventBus(), cfg)
    published = []
    det.publish = lambda ev: published.append(ev)
    return det, published


def field_map(payload):
    return {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}


def build_event(metadata, change_type="modified", path="/x.php"):
    meta = {"path": path, "change_type": change_type, **metadata}
    return BaseEvent(
        source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
        severity=Severity.HIGH, message="File berubah", raw="", metadata=meta,
    )


async def main():
    with tempfile.TemporaryDirectory() as tmp:
        det, _pub = make_fim()

        small_php = os.path.join(tmp, "small.php")
        with open(small_php, "w") as f:
            f.write("<?php\necho 'hello world';\n")
        new_id = _stat_state_for_forensics(small_php)
        created = det._evaluate_change(small_php, "php_source", None, new_id)
        assert created["change_type"] == "created", created
        assert created["before_available"] is False and created["before_content_excerpt"] is None
        assert created["after_available"] is True, created
        assert "echo 'hello world'" in created["after_content_excerpt"], created
        assert created["content_type"] == CONTENT_TEXT, created
        print("Scenario 1 (CREATED small PHP: after_content_excerpt shows exact bounded content) PASSED")

        shell_php = os.path.join(tmp, "shell.php")
        with open(shell_php, "w") as f:
            f.write("<?php\nsystem($_GET['cmd']);\n")
        shell_id = _stat_state_for_forensics(shell_php)
        created_shell = det._evaluate_change(shell_php, "php_source", None, shell_id)
        assert "system($_GET['cmd'])" in created_shell["after_content_excerpt"], created_shell
        print("Scenario 2 (CREATED suspicious PHP: dangerous sink visible in after_content_excerpt) PASSED")

        large_php = os.path.join(tmp, "large.php")
        with open(large_php, "w") as f:
            f.write("<?php\n" + ("A" * 300000) + "\n")
        large_id = _stat_state_for_forensics(large_php)
        assert large_id.content_type == CONTENT_LARGE_TEXT, large_id
        assert large_id.content_snapshot is None, "LARGE_TEXT must never be dumped as a content snapshot"
        created_large = det._evaluate_change(large_php, "php_source", None, large_id)
        assert created_large["after_content_excerpt"] is None, created_large
        assert created_large["content_type"] == CONTENT_LARGE_TEXT, created_large
        print("Scenario 3 (CREATED large PHP: bounded metadata only, no full-content dump) PASSED")

        old_normal = _stat_state_for_forensics(small_php)
        with open(small_php, "w") as f:
            f.write("<?php\necho 'hello world';\necho 'second line';\n")
        new_normal = _stat_state_for_forensics(small_php)
        modified_normal = det._evaluate_change(small_php, "php_source", old_normal, new_normal)
        assert modified_normal["change_type"] == "modified", modified_normal
        assert modified_normal["before_available"] and modified_normal["after_available"], modified_normal
        assert modified_normal["unified_diff"], modified_normal
        assert modified_normal["changed_lines"] and modified_normal["changed_lines"] > 0, modified_normal
        print("Scenario 4 (MODIFIED normal PHP: BEFORE + AFTER + unified_diff present) PASSED")

        old_suspicious = _stat_state_for_forensics(shell_php)
        with open(shell_php, "w") as f:
            f.write("<?php\nsystem($_GET['cmd']);\neval(base64_decode($_POST['x']));\n")
        new_suspicious = _stat_state_for_forensics(shell_php)
        modified_suspicious = det._evaluate_change(shell_php, "php_source", old_suspicious, new_suspicious)
        assert modified_suspicious["security_relevant_diff"], modified_suspicious
        assert "eval(base64_decode" in modified_suspicious["security_relevant_diff"], modified_suspicious
        print("Scenario 5 (MODIFIED suspicious PHP: security_relevant_diff isolates the dangerous line) PASSED")

        no_baseline_old = FileIdentity(
            sha256="deadbeef", mode=0o644, uid=1000, gid=1000, size=10, mtime=time.time(),
            content_snapshot=None, content_type=CONTENT_TEXT,
        )
        metrics_before = get_forensic_metrics().snapshot()["forensic_baseline_missing_total"]
        modified_no_baseline = det._evaluate_change(shell_php, "php_source", no_baseline_old, new_suspicious)
        assert modified_no_baseline["before_available"] is False, modified_no_baseline
        assert modified_no_baseline["unified_diff"] is None, (
            "must never fabricate a diff when the prior snapshot is missing"
        )
        metrics_after = get_forensic_metrics().snapshot()["forensic_baseline_missing_total"]
        assert metrics_after == metrics_before + 1, "missing-baseline MODIFIED must increment the metric"
        print("Scenario 6 (MODIFIED no-baseline: honest UNAVAILABLE, no fabricated diff) PASSED")

        deleted_with_snapshot = det._evaluate_change(shell_php, "php_source", new_suspicious, None)
        assert deleted_with_snapshot["change_type"] == "deleted", deleted_with_snapshot
        assert deleted_with_snapshot["before_available"] is True, deleted_with_snapshot
        assert "eval(base64_decode" in deleted_with_snapshot["before_content_excerpt"], deleted_with_snapshot
        print("Scenario 7 (DELETED with retained snapshot: last-known content shown) PASSED")

        no_snapshot_old = FileIdentity(
            sha256="cafebabe", mode=0o644, uid=1000, gid=1000, size=10, mtime=time.time(),
            content_snapshot=None, content_type=CONTENT_TEXT,
        )
        metrics_before_del = get_forensic_metrics().snapshot()["forensic_baseline_missing_total"]
        deleted_without_snapshot = det._evaluate_change("/x/gone.php", "php_source", no_snapshot_old, None)
        assert deleted_without_snapshot["before_available"] is False, deleted_without_snapshot
        assert deleted_without_snapshot["before_content_excerpt"] is None, (
            "must never fabricate previous content for a file whose snapshot was never captured"
        )
        metrics_after_del = get_forensic_metrics().snapshot()["forensic_baseline_missing_total"]
        assert metrics_after_del == metrics_before_del + 1
        print("Scenario 8 (DELETED without retained snapshot: honest UNAVAILABLE, never fabricated) PASSED")

        env_path = os.path.join(tmp, ".env")
        with open(env_path, "w") as f:
            f.write("DB_PASSWORD=supersecret123\nAPP_ENV=production\n")
        env_id = _stat_state_for_forensics(env_path)
        assert env_id.content_type == CONTENT_SECRET_CONFIG, env_id
        assert env_id.content_snapshot is None, ".env content must never be captured as a raw snapshot"
        created_env = det._evaluate_change(env_path, "critical_system", None, env_id)
        assert created_env["before_content_excerpt"] is None and created_env["after_content_excerpt"] is None, created_env
        assert created_env["before_available"] is False and created_env["after_available"] is False, created_env
        print("Scenario 9 (.env CREATED: forensic excerpts never populated for secret filenames) PASSED")

        with open(env_path, "w") as f:
            f.write("DB_PASSWORD=changed456\nAPP_ENV=production\n")
        env_id2 = _stat_state_for_forensics(env_path)
        modified_env = det._evaluate_change(env_path, "critical_system", env_id, env_id2)
        assert modified_env["unified_diff"] is None, "the generic diff path must never leak .env content"
        assert modified_env["before_content_excerpt"] is None and modified_env["after_content_excerpt"] is None
        print("Scenario 9b (.env MODIFIED: generic forensic diff path stays empty, no raw value leakage) PASSED")

        binary_path = os.path.join(tmp, "payload.sql")
        with open(binary_path, "wb") as f:
            f.write(b"\x00\x01\x02\xff\xfe\xfd" * 100)
        binary_id = _stat_state_for_forensics(binary_path)
        assert binary_id.content_type == CONTENT_BINARY, binary_id
        assert binary_id.content_snapshot is None, "binary content must never be dumped"
        created_binary = det._evaluate_change(binary_path, "critical_system", None, binary_id)
        assert created_binary["after_content_excerpt"] is None, created_binary
        assert created_binary["content_type"] == CONTENT_BINARY, created_binary
        print("Scenario 10 (binary file: metadata+hash only, no content dump) PASSED")

        config_json = os.path.join(tmp, "config.json")
        with open(config_json, "w") as f:
            f.write('{\n  "app_name": "myapp",\n  "api_key": "SUPERSECRETVALUE12345",\n  "debug": true\n}\n')
        config_id = _stat_state_for_forensics(config_json)
        assert config_id.content_type == CONTENT_TEXT, config_id
        assert config_id.redaction_applied is True, config_id
        assert "SUPERSECRETVALUE12345" not in (config_id.content_snapshot or ""), (
            "secret-like keys outside .env must still be redacted centrally"
        )
        assert "[REDACTED]" in config_id.content_snapshot, config_id
        assert "myapp" in config_id.content_snapshot, "non-secret fields must be preserved"
        print("Scenario 11 (secret-like key in non-.env config: centralized redaction applies) PASSED")

        invalid_utf8_path = os.path.join(tmp, "broken.php")
        with open(invalid_utf8_path, "wb") as f:
            f.write(b"<?php\necho 'text';\n\xff\xfe broken continuation\n")
        text, truncated = read_bounded_snapshot(invalid_utf8_path)
        assert text is not None and truncated is False
        assert "echo 'text'" in text, "invalid UTF-8 elsewhere in the file must not prevent a bounded read"
        print("Scenario 12 (invalid UTF-8 bytes: bounded read degrades gracefully, never crashes) PASSED")

        huge_text = "X" * (DEFAULT_MAX_SNAPSHOT_BYTES + 5000)
        huge_path = os.path.join(tmp, "huge_inline.txt.php")
        with open(huge_path, "w") as f:
            f.write(huge_text)
        snap_text, snap_truncated = read_bounded_snapshot(huge_path)
        assert snap_truncated is True and len(snap_text) == DEFAULT_MAX_SNAPSHOT_BYTES
        print("Scenario 13 (content snapshot exceeding byte bound: truncated deterministically) PASSED")

        before_lines = "\n".join(f"line{i}" for i in range(500))
        after_lines = "\n".join(f"line{i}-changed" for i in range(500))
        diff_result = compute_unified_diff(before_lines, after_lines)
        assert diff_result.truncated is True
        assert len(diff_result.lines) <= DEFAULT_MAX_DIFF_LINES
        print("Scenario 14 (large unified diff: bounded and deterministically truncated) PASSED")

        assert classify_content_type("/x/unknownextension.bin", 10) == CONTENT_UNKNOWN
        print("Scenario 15 (unrecognized extension: honest UNKNOWN, not guessed) PASSED")

    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())

    created_event = build_event(
        {
            "target_class": "php_source", "content_type": CONTENT_TEXT,
            "after_content_excerpt": "<?php\necho 'hi';\n",
            "before_content_excerpt": None, "before_available": False, "after_available": True,
        },
        change_type="created", path="/home/vic/htdocs/example.com/new.php",
    )
    payload = dispatcher._build_payload(created_event)
    fields = field_map(payload)
    assert "echo 'hi'" in fields["What Was Added"], fields
    print("Scenario 16 (Discord render: CREATED shows 'What Was Added' code block) PASSED")

    deleted_event_available = build_event(
        {
            "target_class": "php_source", "content_type": CONTENT_TEXT,
            "before_content_excerpt": "<?php\necho 'bye';\n", "after_content_excerpt": None,
            "before_available": True, "after_available": False,
        },
        change_type="deleted", path="/home/vic/htdocs/example.com/old.php",
    )
    payload_del = dispatcher._build_payload(deleted_event_available)
    fields_del = field_map(payload_del)
    assert "echo 'bye'" in fields_del["Last Known Content"], fields_del

    deleted_event_unavailable = build_event(
        {
            "target_class": "php_source", "content_type": CONTENT_TEXT,
            "before_content_excerpt": None, "after_content_excerpt": None,
            "before_available": False, "after_available": False,
        },
        change_type="deleted", path="/home/vic/htdocs/example.com/gone.php",
    )
    payload_del2 = dispatcher._build_payload(deleted_event_unavailable)
    fields_del2 = field_map(payload_del2)
    assert fields_del2["Last Known Content"] == "UNAVAILABLE (no retained baseline/snapshot)", fields_del2
    print("Scenario 17 (Discord render: DELETED with/without snapshot -- honest UNAVAILABLE label) PASSED")

    modified_event = build_event(
        {
            "target_class": "php_source", "content_type": CONTENT_TEXT,
            "before_content_excerpt": "a", "after_content_excerpt": "b", "before_available": True,
            "after_available": True,
            "unified_diff": "--- before\n+++ after\n-old line\n+new line",
            "security_relevant_diff": None, "changed_lines": 2,
        },
        change_type="modified", path="/home/vic/htdocs/example.com/mod.php",
    )
    payload_mod = dispatcher._build_payload(modified_event)
    fields_mod = field_map(payload_mod)
    assert "old line" in fields_mod["Diff"] and "new line" in fields_mod["Diff"], fields_mod
    assert fields_mod["Changed Lines"] == "2", fields_mod
    print("Scenario 18 (Discord render: MODIFIED shows bounded unified diff + changed line count) PASSED")

    secret_config_event = build_event(
        {
            "file_class": "SECRET_CONFIG", "content_type": CONTENT_SECRET_CONFIG,
            "before_content_excerpt": None, "after_content_excerpt": None,
            "before_available": False, "after_available": False,
        },
        change_type="modified", path="/home/vic/htdocs/example.com/.env",
    )
    payload_secret = dispatcher._build_payload(secret_config_event)
    fields_secret = field_map(payload_secret)
    assert "Diff" not in fields_secret and "What Was Added" not in fields_secret, fields_secret
    assert "Last Known Content" not in fields_secret, fields_secret
    print("Scenario 19 (Discord render: SECRET_CONFIG never renders generic forensic content fields) PASSED")

    assert _forensic_diff_language("/x/y/shell.php") == "php"
    assert _forensic_diff_language("/x/app.js") == "javascript"
    assert _forensic_diff_language("/x/style.css") == "css"
    assert _forensic_diff_language("/x/unknownfile.xyz") == ""
    print("Scenario 20 (Discord code-fence language mapping: known extensions mapped, unknown safe-default) PASSED")

    from modules.webshell_detector import DECODE_FUNCS, EXEC_FUNCS, REMOTE_FETCH_FUNCS
    from modules.webshell_detector import _DECODE_FUNCS, _EXEC_FUNCS, _REMOTE_FETCH_FUNCS
    assert DECODE_FUNCS is _DECODE_FUNCS and EXEC_FUNCS is _EXEC_FUNCS and REMOTE_FETCH_FUNCS is _REMOTE_FETCH_FUNCS, (
        "the forensic diff engine must reuse the canonical webshell signature sets by identity, not a copy"
    )
    print("Scenario 21 (no duplicate PHP-danger signature engine: canonical webshell sets reused by identity) PASSED")

    redacted, count = redact_secret_like_assignments("password=hunter2\nAPP_ENV=production\n")
    assert "hunter2" not in redacted and "[REDACTED]" in redacted and count == 1
    assert "APP_ENV=production" in redacted
    print("Scenario 22 (redact_secret_like_assignments: generic KEY=VALUE redaction, safe keys preserved) PASSED")

    m = get_forensic_metrics().snapshot()
    assert m["forensic_read_total"] > 0, m
    assert m["forensic_diff_total"] > 0, m
    assert m["forensic_redaction_total"] > 0, m
    assert m["forensic_baseline_missing_total"] >= 2, m
    print("Scenario 23 (forensic metrics counters: read/diff/redaction/baseline-missing all incremented) PASSED")

    print("\nALL FIM FORENSIC BEFORE/AFTER DIFF TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
