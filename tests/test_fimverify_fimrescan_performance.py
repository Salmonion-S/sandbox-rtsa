import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import shutil
import tempfile
from unittest import mock

import discord

import discord_integration.bot as bot_module
from config.manager import (
    CloudflareConfig, ConfigsWatchConfig, CriticalSystemWatchConfig, DiscordConfig,
    FileIntegrityDetectorConfig, PhpSourceWatchConfig, RTSAConfig, UploadsWatchConfig,
)
from core.event_bus import EventBus
from core.file_identity import stat_identity
from discord_integration.bot import RTSABot, _fim_light_stat, _fim_run_bounded

BASE = os.path.join(tempfile.gettempdir(), "rtsa_fimverify_perf_test")
_ADMIN_ROLE_ID = 999


class FakeRole:
    def __init__(self, role_id):
        self.id = role_id


class FakeResponse:
    def __init__(self):
        self.messages = []
        self.deferred = False

    async def send_message(self, content=None, ephemeral=False):
        self.messages.append(content)

    async def defer(self, ephemeral=False):
        self.deferred = True


class FakeFollowup:
    def __init__(self):
        self.sent = []

    async def send(self, content=None, ephemeral=False):
        self.sent.append(content)


class FakeInteraction:
    def __init__(self, member):
        self.user = member
        self.response = FakeResponse()
        self.followup = FakeFollowup()


def make_member(role_ids, member_id=1):
    member = mock.Mock(spec=discord.Member)
    member.roles = [FakeRole(r) for r in role_ids]
    member.id = member_id
    member.__str__ = mock.Mock(return_value="tester#0001")
    return member


def make_bot(state_dir):
    fim_cfg = FileIntegrityDetectorConfig(
        critical_system=CriticalSystemWatchConfig(state_path=os.path.join(state_dir, "critical.json")),
        configs=ConfigsWatchConfig(state_path=os.path.join(state_dir, "configs.json")),
        php_source=PhpSourceWatchConfig(state_path=os.path.join(state_dir, "php_source.json")),
        uploads=UploadsWatchConfig(state_path=os.path.join(state_dir, "uploads.json")),
    )
    cfg = RTSAConfig(cloudflare=CloudflareConfig(enabled=False))
    object.__setattr__(cfg.modules, "file_integrity_detector", fim_cfg)
    disc_cfg = DiscordConfig(enabled=True, admin_role_ids=[_ADMIN_ROLE_ID])
    return RTSABot(disc_cfg, cfg, EventBus(), db_worker=None, supervisor=None)


def get_callback(bot, name):
    for cmd in bot.tree.get_commands():
        if cmd.name == name:
            return cmd.callback
    raise AssertionError(f"command '{name}' not registered")


async def async_main() -> None:
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)

    limiter = _fim_light_stat(os.path.join(BASE, "does_not_exist_at_all"))
    assert limiter is None
    real_file = os.path.join(BASE, "probe.txt")
    with open(real_file, "w") as f:
        f.write("hello")
    light = _fim_light_stat(real_file)
    assert light is not None
    mtime, size, mode, uid, gid, is_symlink = light
    assert size == 5
    assert is_symlink is False
    print("Scenario 1 (_fim_light_stat: missing file -> None, real file -> correct light stat tuple) PASSED")

    probe_paths = [os.path.join(BASE, f"bounded{i}.txt") for i in range(20)]
    for p in probe_paths:
        with open(p, "w") as f:
            f.write("x")
    loop = asyncio.get_running_loop()
    results = await _fim_run_bounded(loop, _fim_light_stat, probe_paths, concurrency=4)
    assert len(results) == 20
    assert all(r[1] is not None for r in results)
    assert {p for p, _ in results} == set(probe_paths)
    print("Scenario 2 (_fim_run_bounded processes all paths correctly under a concurrency cap) PASSED")

    project = os.path.join(BASE, "project")
    os.makedirs(project, exist_ok=True)
    unchanged_path = os.path.join(project, "unchanged.php")
    content_changed_path = os.path.join(project, "content_changed.php")
    perm_changed_path = os.path.join(project, "perm_changed.php")
    deleted_path = os.path.join(project, "deleted.php")
    new_path = os.path.join(project, "new.php")

    for p, content in (
        (unchanged_path, "<?php echo 'unchanged'; ?>"),
        (content_changed_path, "<?php echo 'before'; ?>"),
        (perm_changed_path, "<?php echo 'perm'; ?>"),
        (deleted_path, "<?php echo 'will be deleted'; ?>"),
    ):
        with open(p, "w") as f:
            f.write(content)
        os.chmod(p, 0o644)

    baseline = {
        p: stat_identity(p) for p in (unchanged_path, content_changed_path, perm_changed_path, deleted_path)
    }
    assert all(v is not None for v in baseline.values())

    with open(content_changed_path, "w") as f:
        f.write("<?php echo 'AFTER -- modified content'; ?>")
    os.chmod(perm_changed_path, 0o755)
    os.remove(deleted_path)
    with open(new_path, "w") as f:
        f.write("<?php echo 'brand new file'; ?>")

    fake_targets = {
        unchanged_path: "php_source", content_changed_path: "php_source",
        perm_changed_path: "php_source", new_path: "php_source",
    }

    state_dir = os.path.join(BASE, "state")
    os.makedirs(state_dir, exist_ok=True)
    bot = make_bot(state_dir)
    member = make_member([_ADMIN_ROLE_ID])

    hash_calls = []
    real_stat_state = bot_module._stat_state

    def counting_stat_state(path):
        hash_calls.append(path)
        return real_stat_state(path)

    with mock.patch.object(bot_module, "load_all_baseline_states", return_value=baseline), \
         mock.patch.object(bot_module, "fim_discover_watch_targets", return_value=fake_targets), \
         mock.patch.object(bot_module, "_stat_state", side_effect=counting_stat_state):
        fimverify = get_callback(bot, "fimverify")
        interaction = FakeInteraction(member)
        await fimverify(interaction)

    assert interaction.response.deferred, "fimverify must defer immediately"
    assert len(interaction.followup.sent) == 1
    message = interaction.followup.sent[0]

    assert f"`{new_path}`" in message and "(dibuat)" in message
    assert f"`{deleted_path}`" in message and "(dihapus)" in message
    assert f"`{content_changed_path}`" in message and "(konten diubah)" in message
    assert f"`{perm_changed_path}`" in message and "(permission diubah)" in message
    assert unchanged_path not in message, "an unchanged file must never be reported"
    print("Scenario 3 (fimverify correctly detects created/deleted/content/permission changes) PASSED")

    assert content_changed_path in hash_calls, "the file whose content actually changed must be hashed"
    assert unchanged_path not in hash_calls, (
        "an unchanged file (same mtime+size+symlink-status as baseline) must NEVER be hashed -- "
        "this is the whole point of the performance fix"
    )
    assert perm_changed_path not in hash_calls, (
        "a chmod-only change does not alter mtime/size, so it must be detected via the cheap "
        "light-stat alone, without a full SHA256 re-hash"
    )
    assert new_path not in hash_calls, "a brand-new file (no baseline entry) needs no hash to be reported as created"
    print("Scenario 4 (hashing is skipped for unchanged AND permission-only-changed files -- the actual fix) PASSED")

    fake_targets_rescan = {unchanged_path: "php_source", content_changed_path: "php_source", new_path: "php_source"}
    hash_calls.clear()
    with mock.patch.object(bot_module, "fim_discover_watch_targets", return_value=fake_targets_rescan), \
         mock.patch.object(bot_module, "_stat_state", side_effect=counting_stat_state):
        fimrescan = get_callback(bot, "fimrescan")
        interaction2 = FakeInteraction(member)
        await fimrescan(interaction2)

    assert interaction2.response.deferred
    assert len(interaction2.followup.sent) == 1
    assert "3 file" in interaction2.followup.sent[0]
    assert set(hash_calls) == set(fake_targets_rescan.keys()), (
        "with no pre-existing baseline on disk to compare against, every target has nothing to "
        "reuse from and must be freshly hashed"
    )
    reloaded = bot_module.load_all_baseline_states(bot.rtsa_config.modules.file_integrity_detector)
    assert set(reloaded.keys()) == set(fake_targets_rescan.keys())
    print("Scenario 5 (fimrescan with no prior baseline hashes every target, via bounded-parallel work, persists correctly) PASSED")

    hash_calls.clear()
    still_unchanged = unchanged_path
    now_also_changed = new_path
    with open(now_also_changed, "w") as f:
        f.write("<?php echo 'changed again after the rescan baseline was written'; ?>")
    fake_targets_rescan_2 = dict(fake_targets_rescan)
    with mock.patch.object(bot_module, "fim_discover_watch_targets", return_value=fake_targets_rescan_2), \
         mock.patch.object(bot_module, "_stat_state", side_effect=counting_stat_state):
        interaction3 = FakeInteraction(member)
        await fimrescan(interaction3)

    assert interaction3.response.deferred
    followup_msg = interaction3.followup.sent[0]
    assert "1 di-hash ulang" in followup_msg, followup_msg
    assert "2 dipertahankan" in followup_msg, followup_msg
    assert hash_calls == [now_also_changed], (
        f"a second fimrescan run must reuse the baseline it just wrote for every file that "
        f"provably has not changed (mtime+size+symlink-status identical), and only re-hash the "
        f"one that actually did change: {hash_calls}"
    )
    assert still_unchanged not in hash_calls
    assert content_changed_path not in hash_calls, (
        "a file that was already correctly hashed in the PREVIOUS rescan and hasn't changed "
        "since must not be re-hashed a second time either"
    )
    print("Scenario 6 (a second fimrescan reuses the baseline for unchanged files, only re-hashes what actually changed) PASSED")

    print("\nALL FIMVERIFY/FIMRESCAN PERFORMANCE-FIX TESTS PASSED")


asyncio.run(async_main())
