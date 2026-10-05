import os
import re
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import discord_integration.bot as bot
from config.manager import DiscordConfig
from core.bounded_cache import BoundedLRUDict
from core.datatypes import BaseEvent, EventCategory, Severity
from core.env_file_analysis import (
    EXPECTED_CONFIG_CHANGE, HIGH_RISK_SECRET_CHANGE, SUSPICIOUS_CONFIG_CHANGE,
    classify_env_change_risk, diff_env_variables, is_env_filename, parse_env_variables,
    redact_variable_value,
)
from core.event_bus import EventBus
from core.file_identity import FileIdentity
from core.git_deployment import GitDeploymentTracker
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.file_integrity_detector import FileIntegrityDetector


def make_detector():
    fd = FileIntegrityDetector.__new__(FileIntegrityDetector)
    fd._env_variable_cache = BoundedLRUDict(maxsize=500)
    fd._git_tracker = GitDeploymentTracker()
    fd._resolve_owner_username = lambda uid: None
    fd._project_context = lambda path: None
    fd._find_possible_creator = lambda project_root, mtime, uid: (None, None, None, "UNKNOWN")
    return fd


def main() -> None:
    assert is_env_filename(".env")
    assert is_env_filename(".env.production")
    assert is_env_filename(".env.local")
    assert not is_env_filename(".environment")
    assert not is_env_filename("config.env")
    assert not is_env_filename("environment.php")
    print("Scenario 1 (.env / .env.* filename detection, no false positives on unrelated names) PASSED")

    content1 = "DATABASE_URL=postgres://u:p@h/db\nAPP_ENV=production\nJWT_SECRET=abc123\n"
    variables = parse_env_variables(content1)
    assert variables == {
        "DATABASE_URL": "postgres://u:p@h/db", "APP_ENV": "production", "JWT_SECRET": "abc123",
    }
    quoted = parse_env_variables('API_KEY="sk-quoted-value"\n# a comment\n\nDEBUG=true\n')
    assert quoted == {"API_KEY": "sk-quoted-value", "DEBUG": "true"}
    print("Scenario 2 (env file parsing: comments/blanks skipped, quoted values unwrapped) PASSED")

    assert redact_variable_value("APP_ENV", "production") == "production"
    assert redact_variable_value("DATABASE_URL", "postgres://u:p@h/db") == "[REDACTED]"
    assert redact_variable_value("API_KEY", "sk-anything") == "[REDACTED]"
    assert redact_variable_value("UNKNOWN_VAR", "some_value_here") == "[REDACTED]", (
        "an unrecognized variable name must default to REDACTED -- never guess a value is safe"
    )
    print("Scenario 3 (value redaction: only an explicit safe-name allowlist with a plain value is ever shown) PASSED")

    old_vars = {"DATABASE_URL": "postgres://u:p@h/db", "APP_ENV": "production"}
    new_vars = {"DATABASE_URL": "postgres://u:p@h/db", "APP_ENV": "staging", "API_KEY": "sk-new"}
    diff = diff_env_variables(old_vars, new_vars)
    assert [c.name for c in diff.added] == ["API_KEY"]
    assert diff.added[0].new_display == "[REDACTED]"
    assert diff.modified[0].name == "APP_ENV"
    assert diff.modified[0].old_display == "production" and diff.modified[0].new_display == "staging"
    print("Scenario 4 (variable-name diff: added/removed/modified computed correctly, values redacted appropriately) PASSED")

    assessment_secret, _ = classify_env_change_risk(diff, git_commit_match=None, git_deployment_recent=False)
    assert assessment_secret == HIGH_RISK_SECRET_CHANGE
    assessment_git, _ = classify_env_change_risk(diff, git_commit_match=True, git_deployment_recent=True)
    assert assessment_git == EXPECTED_CONFIG_CHANGE, (
        "a secret-name change that is confirmed part of the deployed git commit must not be HIGH_RISK"
    )
    non_secret_diff = diff_env_variables({"APP_ENV": "production"}, {"APP_ENV": "staging"})
    assessment_nonsecret, _ = classify_env_change_risk(non_secret_diff, git_commit_match=None, git_deployment_recent=False)
    assert assessment_nonsecret == SUSPICIOUS_CONFIG_CHANGE
    no_change_diff = diff_env_variables({"APP_ENV": "production"}, {"APP_ENV": "production"})
    assessment_none, _ = classify_env_change_risk(no_change_diff, git_commit_match=None, git_deployment_recent=False)
    assert assessment_none == EXPECTED_CONFIG_CHANGE
    print("Scenario 5 (risk tiers: HIGH_RISK for secret names, git-verified change downgrades, no-op change is expected) PASSED")

    fd = make_detector()
    tmpdir = tempfile.mkdtemp()
    env_path = os.path.join(tmpdir, ".env")
    with open(env_path, "w") as f:
        f.write("APP_ENV=production\n")
    old1 = FileIdentity(sha256="a" * 64, mode=0o640, uid=1000, gid=1000, size=10, mtime=1000.0, inode=1)
    new1 = FileIdentity(sha256="b" * 64, mode=0o640, uid=1000, gid=1000, size=20, mtime=1010.0, inode=1)
    result1 = fd._evaluate_change(env_path, "configs", None, new1)
    assert result1["file_class"] == "SECRET_CONFIG"
    assert result1["env_diff_unavailable"] is False, "a genuine file creation (old=None) is not DIFF_UNAVAILABLE"

    with open(env_path, "w") as f:
        f.write("APP_ENV=production\nAPI_KEY=sk-added-later\n")
    new2 = FileIdentity(sha256="c" * 64, mode=0o640, uid=1000, gid=1000, size=40, mtime=1020.0, inode=1)
    result2 = fd._evaluate_change(env_path, "configs", new1, new2)
    assert result2["severity"] == Severity.CRITICAL
    assert result2["assessment"] == HIGH_RISK_SECRET_CHANGE
    assert "API_KEY" in result2["env_changed_variables"]
    print("Scenario 6 (end-to-end FIM integration: new secret variable added -> CRITICAL/HIGH_RISK_SECRET_CHANGE) PASSED")

    fd2 = make_detector()
    env_path2 = os.path.join(tmpdir, ".env.production")
    with open(env_path2, "w") as f:
        f.write("APP_ENV=production\n")
    old3 = FileIdentity(sha256="x" * 64, mode=0o640, uid=1000, gid=1000, size=10, mtime=1000.0, inode=2)
    new3 = FileIdentity(sha256="y" * 64, mode=0o640, uid=1000, gid=1000, size=15, mtime=1010.0, inode=2)
    result3 = fd2._evaluate_change(env_path2, "configs", old3, new3)
    assert result3["env_diff_unavailable"] is True, (
        "a MODIFY event with no prior cached baseline must be explicitly marked DIFF_UNAVAILABLE, "
        "never silently claim a fabricated added/removed diff"
    )
    assert "DIFF_UNAVAILABLE" in result3["risk_reason"]
    print("Scenario 7 (modification with no prior baseline is honestly marked DIFF_UNAVAILABLE, never fabricated) PASSED")

    fd3 = make_detector()
    env_path3 = os.path.join(tmpdir, ".env.staging")
    with open(env_path3, "w") as f:
        f.write("APP_ENV=production\n")
    old4 = FileIdentity(sha256="p" * 64, mode=0o640, uid=1000, gid=1000, size=10, mtime=1000.0, inode=3)
    new4 = FileIdentity(sha256="q" * 64, mode=0o640, uid=1000, gid=1000, size=10, mtime=1010.0, inode=3)
    with open(env_path3, "w") as f:
        f.write("APP_ENV=production\n")
    baseline = fd3._evaluate_change(env_path3, "configs", None, old4)
    assert baseline["env_diff_unavailable"] is False

    new5 = FileIdentity(sha256="r" * 64, mode=0o640, uid=1000, gid=8888, size=10, mtime=1020.0, inode=3)
    result4 = fd3._evaluate_change(env_path3, "configs", new4, new5)
    assert result4["owner_changed"] is True
    assert result4["assessment"] == SUSPICIOUS_CONFIG_CHANGE
    print("Scenario 8 (ownership change on a secret-config file with an unchanged variable set is flagged SUSPICIOUS) PASSED")

    fd4 = make_detector()
    env_path4 = os.path.join(tmpdir, ".env.deploy")
    with open(env_path4, "w") as f:
        f.write("APP_ENV=production\n")
    old6 = FileIdentity(sha256="s" * 64, mode=0o640, uid=1000, gid=1000, size=10, mtime=1000.0, inode=4)
    new6 = FileIdentity(sha256="t" * 64, mode=0o640, uid=1000, gid=1000, size=10, mtime=1010.0, inode=4)
    fd4._evaluate_change(env_path4, "configs", None, old6)
    with open(env_path4, "w") as f:
        f.write("APP_VERSION=2.1.0\n")
    new7 = FileIdentity(sha256="u" * 64, mode=0o640, uid=1000, gid=1000, size=15, mtime=1020.0, inode=4)
    result5 = fd4._evaluate_change(env_path4, "configs", new6, new7, deployment_status=None)
    assert result5["assessment"] == SUSPICIOUS_CONFIG_CHANGE, (
        f"a non-secret variable rename with no git repo and no verified deployment context must "
        f"never be silently classified as EXPECTED -- it should read SUSPICIOUS pending review: "
        f"{result5['assessment']}"
    )
    assert result5["severity"] == Severity.HIGH
    print("Scenario 9 (non-secret variable rename with no git repo: SUSPICIOUS_CONFIG_CHANGE, not silently expected) PASSED")

    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    secret_event = BaseEvent(
        source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
        severity=Severity.CRITICAL, message="test", raw="",
        metadata={
            "path": "/home/user/htdocs/site/.env", "change_type": "modified", "file_class": "SECRET_CONFIG",
            "assessment": HIGH_RISK_SECRET_CHANGE, "env_changed_variables": ["API_KEY"],
            "env_variable_changes": [
                {"name": "API_KEY", "change_type": "modified", "old_value": "[REDACTED]", "new_value": "[REDACTED]"},
            ],
            "mode_old": "0o640", "mode_new": "0o644", "permission_widened": True,
        },
    )
    payload = dispatcher._build_payload(secret_event)
    field_map = {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}
    assert field_map["File Class"] == "SECRET_CONFIG"
    assert "API_KEY" in field_map["Changed Variables"]
    assert "[REDACTED]" in field_map["Sensitive Values"]
    assert field_map["Permissions"] == "0o640 -> 0o644"
    all_text = str(payload)
    assert "sk-" not in all_text and "postgres://" not in all_text, "no raw secret value may ever reach the Discord payload"
    print("Scenario 10 (Discord rendering: File Class + redacted variable changes + permission delta, never raw secrets) PASSED")

    marker = bot._HIDDEN_FILE_PROTECTION_MARKER
    inner = marker[len("location ~ "):]
    nginx_pattern = re.compile(inner)
    assert nginx_pattern.search("/.env"), "the existing hidden-file Nginx rule must already block direct .env access"
    assert nginx_pattern.search("/.env.production")
    assert nginx_pattern.search("/.git/config")
    assert not nginx_pattern.search("/.well-known/acme-challenge/token"), (
        "the well-known ACME challenge path must remain excluded from the hidden-file block"
    )
    print("Scenario 11 (the existing /sofix hidden-file rule already blocks .env/.git web access -- confirmed, no new rule needed) PASSED")

    print("\nALL ENV / SECRET-CONFIG FILE MONITORING TESTS PASSED")


main()
