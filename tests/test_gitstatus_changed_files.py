import asyncio
import os
import subprocess
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import shutil
import tempfile

from config.manager import CloudflareConfig, DiscordConfig, RTSAConfig
from core.event_bus import EventBus
from discord_integration.bot import (
    RTSABot, _build_gitstatus_fields, _gitstatus_is_security_relevant, _parse_git_porcelain_status,
)

BASE = os.path.join(tempfile.gettempdir(), "rtsa_gitstatus_test")


def _fields_dict(fields):
    return {name: value for name, value, _inline in fields}


def main() -> None:
    porcelain_basic = "\n".join([
        " M src/app/page.tsx",
        "A  public/assets/logo.svg",
        " D old-file.php",
        "R  legacy/name.txt -> legacy/renamed.txt",
    ])
    entries = _parse_git_porcelain_status(porcelain_basic)
    by_path = {e.path: e for e in entries}

    assert by_path["src/app/page.tsx"].status == "M"
    print("Scenario 1 (modified file appears with status M) PASSED")

    assert by_path["public/assets/logo.svg"].status == "A"
    print("Scenario 2 (added file appears with status A) PASSED")

    assert by_path["old-file.php"].status == "D"
    print("Scenario 3 (deleted file appears with status D) PASSED")

    renamed = by_path["legacy/renamed.txt"]
    assert renamed.status == "R"
    assert renamed.renamed_from == "legacy/name.txt"
    print("Scenario 4 (renamed file appears with status R and records its origin path) PASSED")

    untracked_entries = _parse_git_porcelain_status("?? brand-new-untracked.php")
    assert untracked_entries[0].status == "A", "an untracked new file must be reported as Added"
    print("Scenario 2b (untracked new file is treated as Added) PASSED")

    many_entries = []
    for i in range(40):
        many_entries.append(_parse_git_porcelain_status(f" M src/file{i}.ts")[0])
    many_entries.append(_parse_git_porcelain_status("A  public/uploads/shell.php")[0])
    fields = _build_gitstatus_fields(many_entries)
    changed_field = _fields_dict(fields)
    header = [name for name in changed_field if name.startswith("Changed Files")][0]
    assert header == "Changed Files: 41"
    body = changed_field[header]
    assert body.count("\n• ") < 41, "a large changeset must never list every single file inline"
    assert "Added: 1" in body and "Modified: 40" in body
    assert "lainnya" in body, "a truncated listing must say how many more files were omitted"
    print("Scenario 5 (a large changeset is summarized by counts instead of spamming every file) PASSED")

    assert "Security Relevant" in changed_field
    assert "public/uploads/shell.php" in changed_field["Security Relevant"]
    assert "src/file0.ts" not in changed_field["Security Relevant"]
    shown_in_changed_files = body.split("\n\n", 1)[1] if "\n\n" in body else body
    assert "public/uploads/shell.php" in shown_in_changed_files, (
        "a security-relevant file must be among the files actually listed, not just counted"
    )
    print("Scenario 6 (security-relevant files are prioritized into the shown/listed set, even in a large changeset) PASSED")

    assert _gitstatus_is_security_relevant("public/uploads/shell.php")
    assert _gitstatus_is_security_relevant("index.html")
    assert _gitstatus_is_security_relevant("assets/icon.svg")
    assert _gitstatus_is_security_relevant("webroot/config.phtml")
    assert _gitstatus_is_security_relevant(".env")
    assert not _gitstatus_is_security_relevant("src/components/Header.tsx")
    assert not _gitstatus_is_security_relevant("README.md")
    print("Scenario 6b (security classifier matches php/phtml/phar/svg/index/public/webroot/config, ignores ordinary source) PASSED")

    small_entries = _parse_git_porcelain_status(" M relative/nested/path/file.ts")
    fields_small = _build_gitstatus_fields(small_entries)
    body_small = _fields_dict(fields_small)["Changed Files: 1"]
    assert "relative/nested/path/file.ts" in body_small
    assert body_small.startswith("• M relative/nested/path/file.ts")
    print("Scenario 7 (paths are shown exactly as git reports them -- relative to the repo/project root) PASSED")

    clean_fields = _fields_dict(_build_gitstatus_fields([]))
    assert clean_fields["Changed Files: 0"] == "Clean (no uncommitted changes)"
    print("Scenario 8a (zero changes preserves the original 'Clean' message text) PASSED")

    print("\nALL PURE-FUNCTION GITSTATUS TESTS PASSED")


class FakeResponse:
    def __init__(self):
        self.deferred = False

    async def defer(self, ephemeral=False):
        self.deferred = True


class FakeFollowup:
    def __init__(self):
        self.sent_embeds = []

    async def send(self, embed=None, ephemeral=False):
        self.sent_embeds.append(embed)


class FakeInteraction:
    def __init__(self, user):
        self.user = user
        self.response = FakeResponse()
        self.followup = FakeFollowup()


class FakeDbWorker:
    def enqueue_action(self, *a, **kw):
        pass

    def enqueue_incident_create(self, **kwargs):
        pass

    def enqueue_incident_update(self, *a, **kw):
        pass


def _git(repo_dir, *args):
    subprocess.run(["git", *args], cwd=repo_dir, check=True, capture_output=True)


async def async_main() -> None:
    shutil.rmtree(BASE, ignore_errors=True)
    repo_dir = os.path.join(BASE, "project")
    os.makedirs(repo_dir, exist_ok=True)

    _git(repo_dir, "init", "-q")
    _git(repo_dir, "config", "user.email", "test@example.com")
    _git(repo_dir, "config", "user.name", "Test")

    with open(os.path.join(repo_dir, "src_app.ts"), "w") as f:
        f.write("console.log('hi');\n")
    with open(os.path.join(repo_dir, "old-file.php"), "w") as f:
        f.write("<?php echo 'old'; ?>\n")
    _git(repo_dir, "add", "-A")
    _git(repo_dir, "commit", "-q", "-m", "initial commit")

    with open(os.path.join(repo_dir, "src_app.ts"), "w") as f:
        f.write("console.log('changed');\n")
    os.remove(os.path.join(repo_dir, "old-file.php"))
    os.makedirs(os.path.join(repo_dir, "public", "uploads"), exist_ok=True)
    with open(os.path.join(repo_dir, "public", "uploads", "shell.php"), "w") as f:
        f.write("<?php system($_GET['c']); ?>\n")
    _git(repo_dir, "add", "public/uploads/shell.php", "old-file.php")

    cfg = RTSAConfig(cloudflare=CloudflareConfig(enabled=False))
    disc_cfg = DiscordConfig(enabled=True, admin_role_ids=[42])
    bot = RTSABot(disc_cfg, cfg, EventBus(), db_worker=FakeDbWorker(), supervisor=None)

    async def fake_run_git(account, cwd, args, timeout):
        proc = await asyncio.create_subprocess_exec(
            "git", *args, cwd=cwd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode(errors="replace").strip(), stderr.decode(errors="replace").strip()

    async def fake_resolve(user_linux):
        return object(), "example.com", repo_dir, None

    bot._run_git_as_user_detailed = fake_run_git
    bot._resolve_cloudpanel_project = fake_resolve

    embed = await bot._gitstatus("testuser", requested_by="tester")

    field_by_name = {f.name: f.value for f in embed.fields}
    changed_key = [k for k in field_by_name if k.startswith("Changed Files")][0]
    assert changed_key == "Changed Files: 3", changed_key
    changed_value = field_by_name[changed_key]
    assert "M src_app.ts" in changed_value
    assert "D old-file.php" in changed_value
    assert "A public/uploads/shell.php" in changed_value
    assert "Security Relevant" in field_by_name
    assert "public/uploads/shell.php" in field_by_name["Security Relevant"]
    assert "src_app.ts" not in field_by_name["Security Relevant"]
    assert field_by_name["Current Branch"]
    assert field_by_name["Latest Commit"]
    print("Scenario 9 (end-to-end /gitstatus against a real git repo: correct fields, no extra filesystem scan beyond git status) PASSED")

    with open(os.path.join(repo_dir, "src_app.ts"), "w") as f:
        f.write("console.log('changed');\n")
    _git(repo_dir, "add", "-A")
    _git(repo_dir, "commit", "-q", "-m", "second commit")
    embed_clean = await bot._gitstatus("testuser", requested_by="tester")
    field_by_name_clean = {f.name: f.value for f in embed_clean.fields}
    assert field_by_name_clean["Changed Files: 0"] == "Clean (no uncommitted changes)"
    print("Scenario 8b (end-to-end: a clean repo still reports the original 'Clean' message) PASSED")

    print("\nALL END-TO-END /gitstatus TESTS PASSED")


main()
asyncio.run(async_main())
