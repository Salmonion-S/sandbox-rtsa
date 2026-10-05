import asyncio
import os
import shutil
import stat as stat_module
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import grp as grp_module
import pwd as pwd_module

import discord_integration.bot as bot_module
from config.manager import CloudflareConfig, DiscordConfig, ModulesConfig, ResponseEngineConfig, RTSAConfig
from core.event_bus import EventBus
from discord_integration.bot import RTSABot


class FakeDb:
    def __init__(self):
        self.actions = []

    def enqueue_action(self, action_dict, result="pending"):
        self.actions.append((dict(action_dict), result))

    def enqueue_incident_create(self, **k):
        pass

    def enqueue_incident_update(self, *a, **k):
        pass


class FakePwEntry:
    def __init__(self, pw_name, pw_uid, pw_gid, pw_dir):
        self.pw_name = pw_name
        self.pw_uid = pw_uid
        self.pw_gid = pw_gid
        self.pw_dir = pw_dir


class FakeGrEntry:
    def __init__(self, gr_name, gr_gid):
        self.gr_name = gr_name
        self.gr_gid = gr_gid


class FakeProc:
    def __init__(self, returncode=0, stdout=b"", stderr=b"", on_communicate=None):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self._on_communicate = on_communicate

    async def communicate(self):
        if self._on_communicate is not None:
            self._on_communicate()
        return self._stdout, self._stderr

    def kill(self):
        pass

    async def wait(self):
        return None


def make_bot(db=None):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False),
        modules=ModulesConfig(),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=db or FakeDb(), supervisor=None)


class HomeFixture:
    def __init__(self, owner, uid, gid):
        self.owner = owner
        self.uid = uid
        self.gid = gid
        self.home = f"/home/{owner}"

    def pw_entry(self):
        return FakePwEntry(self.owner, self.uid, self.gid, self.home)

    def gr_entry(self):
        return FakeGrEntry(self.owner, self.gid)

    def cleanup(self):
        shutil.rmtree(self.home, ignore_errors=True)


class PwdGrpPatch:
    def __init__(self, pw_by_name=None, gr_by_name=None, pw_by_uid=None, gr_by_gid=None):
        self.pw_by_name = pw_by_name or {}
        self.gr_by_name = gr_by_name or {}
        self.pw_by_uid = pw_by_uid or {}
        self.gr_by_gid = gr_by_gid or {}
        self._orig = {}

    def __enter__(self):
        self._orig["getpwnam"] = pwd_module.getpwnam
        self._orig["getpwuid"] = pwd_module.getpwuid
        self._orig["getgrnam"] = grp_module.getgrnam
        self._orig["getgrgid"] = grp_module.getgrgid

        def fake_getpwnam(name):
            if name in self.pw_by_name:
                return self.pw_by_name[name]
            raise KeyError(name)

        def fake_getpwuid(uid):
            if uid in self.pw_by_uid:
                return self.pw_by_uid[uid]
            raise KeyError(uid)

        def fake_getgrnam(name):
            if name in self.gr_by_name:
                return self.gr_by_name[name]
            raise KeyError(name)

        def fake_getgrgid(gid):
            if gid in self.gr_by_gid:
                return self.gr_by_gid[gid]
            raise KeyError(gid)

        pwd_module.getpwnam = fake_getpwnam
        pwd_module.getpwuid = fake_getpwuid
        grp_module.getgrnam = fake_getgrnam
        grp_module.getgrgid = fake_getgrgid
        return self

    def __exit__(self, *exc):
        pwd_module.getpwnam = self._orig["getpwnam"]
        pwd_module.getpwuid = self._orig["getpwuid"]
        grp_module.getgrnam = self._orig["getgrnam"]
        grp_module.getgrgid = self._orig["getgrgid"]


def patch_for(fx: HomeFixture) -> PwdGrpPatch:
    return PwdGrpPatch(
        pw_by_name={fx.owner: fx.pw_entry()},
        gr_by_name={fx.owner: fx.gr_entry()},
        pw_by_uid={fx.uid: fx.pw_entry(), 0: FakePwEntry("root", 0, 0, "/root")},
        gr_by_gid={fx.gid: fx.gr_entry(), 0: FakeGrEntry("root", 0)},
    )


def real_chown_exec_factory(calls):
    async def fake_exec(*argv, **kwargs):
        calls.append(argv)
        args = list(argv)
        no_dereference = "--no-dereference" in args
        non_flag_args = [a for a in args[2:] if a != "--no-dereference"]
        spec = non_flag_args[0]
        paths = non_flag_args[1:]
        owner_name, _, group_name = spec.partition(":")
        uid = pwd_module.getpwnam(owner_name).pw_uid
        gid = grp_module.getgrnam(group_name).gr_gid

        def do_chown():
            for p in paths:
                try:
                    if no_dereference:
                        os.lchown(p, uid, gid)
                    else:
                        os.chown(p, uid, gid)
                except OSError:
                    pass

        return FakeProc(returncode=0, on_communicate=do_chown)

    return fake_exec


async def main() -> None:
    assert os.geteuid() == 0, "these tests need root to create real /home/<owner> fixtures"

    fx1 = HomeFixture("rtsa_fh_a", 590301, 590302)
    try:
        os.makedirs(fx1.home, exist_ok=True)
        os.chown(fx1.home, fx1.uid, fx1.gid)
        paths_to_seed = {
            ".pm2/dump.pm2": "pm2home",
            ".pm2/logs/app.log": "pm2home",
            ".ssh/authorized_keys": "ssh",
            "htdocs/example.com/index.php": "web",
            "logs/access.log": "logs",
            "tmp/upload.tmp": "tmp",
            "backups/db.sql": "backups",
            ".bashrc": "dotfile",
            ".profile": "dotfile",
        }
        for rel, _tag in paths_to_seed.items():
            full = os.path.join(fx1.home, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as f:
                f.write("x")
            os.chown(full, 0, 0)
            os.chown(os.path.dirname(full), 0, 0)

        with patch_for(fx1):
            preflight = bot_module.RTSABot._changeowner_preflight_home(make_bot(), fx1.owner)
        assert preflight["ok"] is True, preflight
        assert preflight["no_change_required"] is False
        audit = preflight["audit"]
        fixable_rel_paths = {os.path.relpath(p, fx1.home) for p in audit["fixable_paths"]}
        for rel in paths_to_seed:
            assert rel in fixable_rel_paths, f"{rel} missing from fixable paths: {fixable_rel_paths}"
            assert os.path.dirname(rel) in fixable_rel_paths or os.path.dirname(rel) == "", rel
        assert audit["pm2_home"]["exists"] is True and audit["pm2_home"]["matches"] is False
        assert audit["ssh_dir"]["exists"] is True and audit["ssh_dir"]["matches"] is False
    finally:
        fx1.cleanup()
    print("Scenario 1 (full home scan covers .pm2, .ssh, htdocs, logs, tmp, backups, dotfiles) PASSED")

    fx2 = HomeFixture("rtsa_fh_b", 590303, 590304)
    try:
        os.makedirs(fx2.home, exist_ok=True)
        os.chown(fx2.home, fx2.uid, fx2.gid)
        pm2home = os.path.join(fx2.home, ".pm2")
        os.makedirs(pm2home, exist_ok=True)
        os.chown(pm2home, 0, 0)
        dump = os.path.join(pm2home, "dump.pm2")
        with open(dump, "w") as f:
            f.write("{}")
        os.chown(dump, 0, 0)

        db = FakeDb()
        bot = make_bot(db)
        calls = []
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"
        asyncio.create_subprocess_exec = real_chown_exec_factory(calls)
        try:
            with patch_for(fx2):
                embed = await bot._changeowner_execute_home(fx2.owner, requested_by="tester#pm2")
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        field_map = {f.name: f.value for f in embed.fields}
        assert field_map["Result"] == "FIXED", field_map
        st_pm2home = os.stat(pm2home)
        st_dump = os.stat(dump)
        assert (st_pm2home.st_uid, st_pm2home.st_gid) == (fx2.uid, fx2.gid), "PM2_HOME must be corrected to user:user"
        assert (st_dump.st_uid, st_dump.st_gid) == (fx2.uid, fx2.gid), "dump.pm2 must be corrected to user:user"
    finally:
        fx2.cleanup()
    print("Scenario 2 (root-owned PM2_HOME is safely corrected to <user>:<user>, never to root) PASSED")

    fx3 = HomeFixture("rtsa_fh_c", 590305, 590306)
    try:
        os.makedirs(fx3.home, exist_ok=True)
        os.chown(fx3.home, fx3.uid, fx3.gid)
        ssh_dir = os.path.join(fx3.home, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        os.chmod(ssh_dir, 0o700)
        os.chown(ssh_dir, 0, 0)
        authorized_keys = os.path.join(ssh_dir, "authorized_keys")
        with open(authorized_keys, "w") as f:
            f.write("ssh-ed25519 AAAA...\n")
        os.chmod(authorized_keys, 0o600)
        os.chown(authorized_keys, 0, 0)
        mode_before_ssh = stat_module.S_IMODE(os.stat(ssh_dir).st_mode)
        mode_before_keys = stat_module.S_IMODE(os.stat(authorized_keys).st_mode)

        db = FakeDb()
        bot = make_bot(db)
        calls = []
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"
        asyncio.create_subprocess_exec = real_chown_exec_factory(calls)
        try:
            with patch_for(fx3):
                embed = await bot._changeowner_execute_home(fx3.owner, requested_by="tester#ssh")
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        st_ssh_after = os.stat(ssh_dir)
        st_keys_after = os.stat(authorized_keys)
        assert (st_ssh_after.st_uid, st_ssh_after.st_gid) == (fx3.uid, fx3.gid), ".ssh ownership must be corrected"
        assert (st_keys_after.st_uid, st_keys_after.st_gid) == (fx3.uid, fx3.gid), "authorized_keys ownership must be corrected"
        assert stat_module.S_IMODE(st_ssh_after.st_mode) == mode_before_ssh, (
            "/changeowner must NEVER change .ssh permissions, only ownership"
        )
        assert stat_module.S_IMODE(st_keys_after.st_mode) == mode_before_keys, (
            "/changeowner must NEVER change authorized_keys permissions, only ownership"
        )
    finally:
        fx3.cleanup()
    print("Scenario 3 (.ssh ownership corrected, permission bits provably untouched) PASSED")

    fx4 = HomeFixture("rtsa_fh_d", 590307, 590308)
    outside_dir = tempfile.mkdtemp(prefix="rtsa_fh_outside_")
    try:
        os.makedirs(os.path.join(fx4.home, "htdocs"), exist_ok=True)
        os.chown(fx4.home, fx4.uid, fx4.gid)
        os.chown(os.path.join(fx4.home, "htdocs"), fx4.uid, fx4.gid)
        outside_file = os.path.join(outside_dir, "secret.txt")
        with open(outside_file, "w") as f:
            f.write("outside")
        os.chown(outside_file, 0, 0)
        os.chown(outside_dir, 0, 0)
        link_path = os.path.join(fx4.home, "htdocs", "escape_link")
        os.symlink(outside_dir, link_path)
        os.lchown(link_path, 0, 0)

        with patch_for(fx4):
            audit = bot_module.RTSABot._changeowner_audit_home_tree(fx4.home, fx4.uid, fx4.gid)
        assert audit["symlinks_scanned"] == 1, audit
        assert audit["symlink_targets_outside_home_count"] == 1, audit
        assert audit["files_scanned"] == 0, (
            "a file only reachable via the out-of-home symlink target must never be scanned"
        )
        link_rel = os.path.relpath(link_path, fx4.home)
        assert link_rel in {os.path.relpath(p, fx4.home) for p in audit["fixable_paths"]}

        db = FakeDb()
        bot = make_bot(db)
        calls = []
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"
        asyncio.create_subprocess_exec = real_chown_exec_factory(calls)
        try:
            with patch_for(fx4):
                await bot._changeowner_execute_home(fx4.owner, requested_by="tester#symlink")
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        st_link = os.lstat(link_path)
        assert (st_link.st_uid, st_link.st_gid) == (fx4.uid, fx4.gid), "the symlink's OWN ownership may be corrected"
        st_outside = os.lstat(outside_file)
        assert st_outside.st_uid == 0, "a file outside home reached only via symlink must NEVER be touched"
        st_outside_dir = os.lstat(outside_dir)
        assert st_outside_dir.st_uid == 0, "the symlink target directory itself must NEVER be touched"
    finally:
        shutil.rmtree(outside_dir, ignore_errors=True)
        fx4.cleanup()
    print("Scenario 4 (symlink's own ownership fixable via lchown; target outside home never touched) PASSED")

    fx5 = HomeFixture("rtsa_fh_e", 590309, 590310)
    try:
        os.makedirs(fx5.home, exist_ok=True)
        os.chown(fx5.home, fx5.uid, fx5.gid)
        boundary_dir = os.path.join(fx5.home, "mounted_elsewhere")
        os.makedirs(boundary_dir, exist_ok=True)
        os.chown(boundary_dir, 0, 0)
        inside_boundary_file = os.path.join(boundary_dir, "only_reachable_via_mount.txt")
        with open(inside_boundary_file, "w") as f:
            f.write("x")
        os.chown(inside_boundary_file, 0, 0)

        orig_lstat = os.lstat

        def fake_lstat(path, *a, **k):
            st = orig_lstat(path, *a, **k)
            if path == boundary_dir:
                seq = (st.st_mode, st.st_ino, 999999999, st.st_nlink, st.st_uid, st.st_gid, st.st_size, 0, 0, 0)
                return os.stat_result(seq)
            return st

        os.lstat = fake_lstat
        try:
            with patch_for(fx5):
                audit = bot_module.RTSABot._changeowner_audit_home_tree(fx5.home, fx5.uid, fx5.gid)
        finally:
            os.lstat = orig_lstat

        assert audit["mount_boundary_skipped_count"] == 1, audit
        assert audit["files_scanned"] == 0, "a file only reachable by crossing the mount boundary must never be scanned"
        boundary_rel = "mounted_elsewhere"
        fixable_rel = {os.path.relpath(p, fx5.home) for p in audit["fixable_paths"]}
        assert boundary_rel not in fixable_rel, "the mount-boundary directory itself must never be classified/fixable"
    finally:
        fx5.cleanup()
    print("Scenario 5 (mount/filesystem boundary excluded entirely -- never crossed, classified, or fixed) PASSED")

    fx6 = HomeFixture("rtsa_fh_f", 590311, 590312)
    try:
        os.makedirs(fx6.home, exist_ok=True)
        os.chown(fx6.home, fx6.uid, fx6.gid)
        weird_dir = os.path.join(fx6.home, "unrecognized_custom_dir")
        os.makedirs(weird_dir, exist_ok=True)
        os.chown(weird_dir, 0, 0)

        with patch_for(fx6):
            audit = bot_module.RTSABot._changeowner_audit_home_tree(fx6.home, fx6.uid, fx6.gid)
        assert audit["suspicious_root_mismatched"] == 1, audit
        assert audit["fixable_mismatched"] == 0, audit
        fixable_rel = {os.path.relpath(p, fx6.home) for p in audit["fixable_paths"]}
        assert "unrecognized_custom_dir" not in fixable_rel
        assert any(s["path"] == "unrecognized_custom_dir" for s in audit["suspicious_samples"])
    finally:
        fx6.cleanup()
    print("Scenario 6 (unrecognized root-owned top-level dir -> SUSPICIOUS_ROOT_OWNED, never auto-chowned) PASSED")

    fx7 = HomeFixture("rtsa_fh_g", 590313, 590314)
    try:
        os.makedirs(fx7.home, exist_ok=True)
        os.chown(fx7.home, fx7.uid, fx7.gid)
        other_owned = os.path.join(fx7.home, "someone_elses_stuff")
        with open(other_owned, "w") as f:
            f.write("x")
        os.chown(other_owned, 65534, 65534)

        with patch_for(fx7):
            audit = bot_module.RTSABot._changeowner_audit_home_tree(fx7.home, fx7.uid, fx7.gid)
        assert audit["unknown_mismatched"] == 1, audit
        assert audit["fixable_mismatched"] == 0, audit
        assert any(s["path"] == "someone_elses_stuff" for s in audit["unknown_samples"])
    finally:
        fx7.cleanup()
    print("Scenario 7 (unrecognized entry owned by unrelated uid -> UNKNOWN, report-only) PASSED")

    fx8 = HomeFixture("rtsa_fh_h", 590315, 590316)
    try:
        os.makedirs(fx8.home, exist_ok=True)
        os.chown(fx8.home, fx8.uid, fx8.gid)
        os.makedirs(os.path.join(fx8.home, "htdocs"), exist_ok=True)
        os.chown(os.path.join(fx8.home, "htdocs"), 0, 0)
        weird_dir = os.path.join(fx8.home, "unrecognized_dir")
        os.makedirs(weird_dir, exist_ok=True)
        os.chown(weird_dir, 0, 0)
        weird_child = os.path.join(weird_dir, "child.txt")
        with open(weird_child, "w") as f:
            f.write("x")
        os.chown(weird_child, 0, 0)

        db = FakeDb()
        bot = make_bot(db)
        calls = []
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"
        asyncio.create_subprocess_exec = real_chown_exec_factory(calls)
        try:
            with patch_for(fx8):
                await bot._changeowner_execute_home(fx8.owner, requested_by="tester#norecursive")
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        assert calls, "expected at least one chown invocation"
        for argv in calls:
            joined = " ".join(argv)
            assert "-R" not in argv and "--recursive" not in argv, f"blind recursive chown must never be used: {argv}"
        st_htdocs = os.stat(os.path.join(fx8.home, "htdocs"))
        assert (st_htdocs.st_uid, st_htdocs.st_gid) == (fx8.uid, fx8.gid), "recognized htdocs must be fixed"
        st_weird = os.lstat(weird_dir)
        st_weird_child = os.lstat(weird_child)
        assert st_weird.st_uid == 0, "SUSPICIOUS_ROOT_OWNED directory must never be auto-chowned"
        assert st_weird_child.st_uid == 0, (
            "a child of a SUSPICIOUS_ROOT_OWNED (unrecognized) directory must never be reached/chowned -- "
            "proves no blind recursion happened"
        )
    finally:
        fx8.cleanup()
    print("Scenario 8 (no blind chown -R: argv never recursive, unrecognized subtree provably untouched) PASSED")

    fx9 = HomeFixture("www-data", 33, 33)
    with patch_for(fx9):
        result = bot_module.RTSABot._changeowner_preflight_home(make_bot(), "www-data")
    assert result["ok"] is False and result["error_code"] == "SYSTEM_ACCOUNT_REFUSED", result
    print("Scenario 9 (well-known system account refused before any filesystem audit) PASSED")

    fx10 = HomeFixture("rtsa_fh_i", 590317, 590318)
    escape_target = tempfile.mkdtemp(prefix="rtsa_fh_escape_")
    try:
        os.symlink(escape_target, fx10.home)
        with patch_for(fx10):
            result = bot_module.RTSABot._changeowner_preflight_home(make_bot(), fx10.owner)
        assert result["ok"] is False and result["error_code"] == "PATH_ESCAPE_ATTEMPT", result
    finally:
        shutil.rmtree(escape_target, ignore_errors=True)
        if os.path.islink(fx10.home):
            os.unlink(fx10.home)
        else:
            fx10.cleanup()
    print("Scenario 10 (home directory itself being a symlink -> PATH_ESCAPE_ATTEMPT) PASSED")

    fx11 = HomeFixture("rtsa_fh_j", 590319, 590320)
    try:
        os.makedirs(fx11.home, exist_ok=True)
        os.chown(fx11.home, fx11.uid, fx11.gid)
        os.makedirs(os.path.join(fx11.home, "logs"), exist_ok=True)
        os.chown(os.path.join(fx11.home, "logs"), 0, 0)
        unresolved = os.path.join(fx11.home, "unrecognized_leftover")
        os.makedirs(unresolved, exist_ok=True)
        os.chown(unresolved, 0, 0)

        db = FakeDb()
        bot = make_bot(db)
        calls = []
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"
        asyncio.create_subprocess_exec = real_chown_exec_factory(calls)
        try:
            with patch_for(fx11):
                embed1 = await bot._changeowner_execute_home(fx11.owner, requested_by="run1")
                field_map1 = {f.name: f.value for f in embed1.fields}
                assert field_map1["Result"] == "FIXED", field_map1

                preflight2 = bot_module.RTSABot._changeowner_preflight_home(bot, fx11.owner)
                assert preflight2["no_change_required"] is True, (
                    f"run 2 must converge to NO_CHANGE despite the permanently-unresolved "
                    f"report-only path: {preflight2['audit']}"
                )
                calls_before_run2_exec = len(calls)
                embed2 = await bot._changeowner_execute_home(fx11.owner, requested_by="run2")
                field_map2 = {f.name: f.value for f in embed2.fields}
                assert field_map2["Result"] == "NO_CHANGE", field_map2
                assert len(calls) == calls_before_run2_exec, "NO_CHANGE must trigger zero chown invocations"

                preflight3 = bot_module.RTSABot._changeowner_preflight_home(bot, fx11.owner)
                assert preflight3["no_change_required"] is True
                embed3 = await bot._changeowner_execute_home(fx11.owner, requested_by="run3")
                field_map3 = {f.name: f.value for f in embed3.fields}
                assert field_map3["Result"] == "NO_CHANGE", field_map3
                assert len(calls) == calls_before_run2_exec, "run 3 must also trigger zero chown invocations"
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        assert os.lstat(unresolved).st_uid == 0
    finally:
        fx11.cleanup()
    print("Scenario 11 (idempotent: run1 FIXED, run2/run3 NO_CHANGE, no ownership churn) PASSED")

    fx12 = HomeFixture("rtsa_fh_k", 590321, 590322)
    try:
        os.makedirs(fx12.home, exist_ok=True)
        os.chown(fx12.home, fx12.uid, fx12.gid)
        tmp_dir = os.path.join(fx12.home, "tmp")
        os.makedirs(tmp_dir, exist_ok=True)
        os.chown(tmp_dir, fx12.uid, fx12.gid)
        n_files = 250
        for i in range(n_files):
            p = os.path.join(tmp_dir, f"f{i}.tmp")
            with open(p, "w") as f:
                f.write("x")
            os.chown(p, 0, 0)

        orig_batch_size = bot_module._CHANGEOWNER_HOME_CHOWN_BATCH_SIZE
        bot_module._CHANGEOWNER_HOME_CHOWN_BATCH_SIZE = 50
        db = FakeDb()
        bot = make_bot(db)
        calls = []
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"
        asyncio.create_subprocess_exec = real_chown_exec_factory(calls)
        try:
            with patch_for(fx12):
                embed = await bot._changeowner_execute_home(fx12.owner, requested_by="tester#perf")
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
            bot_module._CHANGEOWNER_HOME_CHOWN_BATCH_SIZE = orig_batch_size
        field_map = {f.name: f.value for f in embed.fields}
        assert field_map["Result"] == "FIXED", field_map
        assert len(calls) == 5, f"expected exactly 5 batched chown calls, got {len(calls)}"
        for argv in calls:
            assert len(argv) - 4 <= 50, "each batch must respect the configured batch size"
    finally:
        fx12.cleanup()
    print("Scenario 12 (250 mismatches applied via 5 batched chown calls, not 250 subprocess calls) PASSED")

    fx13 = HomeFixture("rtsa_fh_l", 590323, 590324)
    try:
        os.makedirs(fx13.home, exist_ok=True)
        os.chown(fx13.home, fx13.uid, fx13.gid)
        os.makedirs(os.path.join(fx13.home, "backups"), exist_ok=True)
        os.chown(os.path.join(fx13.home, "backups"), 0, 0)

        db = FakeDb()
        bot = make_bot(db)
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"
        asyncio.create_subprocess_exec = real_chown_exec_factory([])
        try:
            with patch_for(fx13):
                await bot._changeowner_execute_home(fx13.owner, requested_by="auditor#home")
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        results_in_order = [r for _, r in db.actions]
        assert results_in_order == ["CHANGE_OWNER_HOME_EXECUTING", "CHANGE_OWNER_HOME_APPLIED"], results_in_order
        for action_dict, _ in db.actions:
            assert action_dict["target"] == fx13.owner
            assert action_dict["requested_by"] == "auditor#home"
            assert action_dict["action_type"].value == "CHANGE_OWNER"
    finally:
        fx13.cleanup()
    print("Scenario 13 (audit trail records EXECUTING then APPLIED with owner/operator/action_type intact) PASSED")

    fx14 = HomeFixture("rtsa_fh_m", 590325, 590326)
    try:
        os.makedirs(fx14.home, exist_ok=True)
        os.chown(fx14.home, fx14.uid, fx14.gid)
        os.makedirs(os.path.join(fx14.home, "logs"), exist_ok=True)
        os.chown(os.path.join(fx14.home, "logs"), 0, 0)

        db = FakeDb()
        bot = make_bot(db)
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"

        async def lying_exec(*a, **k):
            return FakeProc(returncode=0)

        asyncio.create_subprocess_exec = lying_exec
        try:
            with patch_for(fx14):
                embed = await bot._changeowner_execute_home(fx14.owner, requested_by="tester#lie")
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        assert embed.title == "RTSA Action -- CHANGE_OWNER_VERIFICATION_FAILED", embed.title
        field_map = {f.name: f.value for f in embed.fields}
        assert field_map.get("Status") != "SUCCESS"
        st_logs = os.stat(os.path.join(fx14.home, "logs"))
        assert st_logs.st_uid == 0, "filesystem must be unchanged when chown lied about success"
    finally:
        fx14.cleanup()
    print("Scenario 14 (chown lies about success -> VERIFICATION_FAILED, never a false FIXED) PASSED")

    fx15 = HomeFixture("rtsa_fh_n", 590327, 590328)
    try:
        os.makedirs(fx15.home, exist_ok=True)
        os.chown(fx15.home, fx15.uid, fx15.gid)
        for rel in (".pm2", ".ssh", "htdocs", "logs"):
            p = os.path.join(fx15.home, rel)
            os.makedirs(p, exist_ok=True)
            os.chown(p, fx15.uid, fx15.gid)

        db = FakeDb()
        bot = make_bot(db)
        calls = []
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"
        asyncio.create_subprocess_exec = real_chown_exec_factory(calls)
        try:
            with patch_for(fx15):
                embed = await bot._changeowner_execute_home(fx15.owner, requested_by="tester#clean")
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        assert embed.title == "RTSA Action -- NO CHANGE REQUIRED (full home)", embed.title
        assert not calls, "a fully-compliant home must trigger zero chown invocations"
    finally:
        fx15.cleanup()
    print("Scenario 15 (already fully compliant home -> NO_CHANGE, zero chown calls) PASSED")

    class FakeResponse:
        def __init__(self):
            self.messages = []

        async def send_message(self, content=None, ephemeral=False):
            self.messages.append(content)

    class FakeInteraction:
        def __init__(self, user_id=1):
            self.user = type("U", (), {"id": user_id})()
            self.response = FakeResponse()

    bot16 = make_bot()
    interaction16 = FakeInteraction()
    await bot16._changeowner_run_home_command(interaction16, "not a valid owner!!", requested_by="tester#wire")
    assert any("INVALID_OWNER" in (m or "") for m in interaction16.response.messages), interaction16.response.messages
    print("Scenario 16 (Discord wrapper rejects invalid owner before any filesystem audit) PASSED")

    fx17 = HomeFixture("rtsa_fh_o", 590329, 590330)
    try:
        os.makedirs(fx17.home, exist_ok=True)
        os.chown(fx17.home, fx17.uid, fx17.gid)
        os.makedirs(os.path.join(fx17.home, "htdocs"), exist_ok=True)
        os.chown(os.path.join(fx17.home, "htdocs"), 0, 0)

        cfg17 = RTSAConfig(
            response_engine=ResponseEngineConfig(detection_only=True),
            modules=ModulesConfig(), cloudflare=CloudflareConfig(enabled=False),
        )
        bot17 = RTSABot(DiscordConfig(enabled=True), cfg17, EventBus(), db_worker=FakeDb(), supervisor=None)
        with patch_for(fx17):
            embed = await bot17._changeowner_execute_home(fx17.owner, requested_by="tester#detonly")
        assert embed.title == "RTSA Action -- CHANGE_OWNER_BLOCKED", embed.title
        st_htdocs = os.stat(os.path.join(fx17.home, "htdocs"))
        assert st_htdocs.st_uid == 0, "detection-only mode must never mutate anything"
    finally:
        fx17.cleanup()
    print("Scenario 17 (detection-only mode blocks full-home execute, filesystem untouched) PASSED")

    fx18 = HomeFixture("rtsa_fh_p", 590331, 590332)
    try:
        os.makedirs(fx18.home, exist_ok=True)
        os.chown(fx18.home, fx18.uid, fx18.gid)
        os.makedirs(os.path.join(fx18.home, "logs"), exist_ok=True)
        os.chown(os.path.join(fx18.home, "logs"), 0, 0)

        db = FakeDb()
        bot = make_bot(db)
        calls = []
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"

        async def fake_slow_chown(*argv, **kwargs):
            await asyncio.sleep(0.05)
            calls.append(argv)
            args = list(argv)
            non_flag_args = [a for a in args[2:] if a != "--no-dereference"]
            spec = non_flag_args[0]
            paths = non_flag_args[1:]
            owner_name, _, group_name = spec.partition(":")
            uid = pwd_module.getpwnam(owner_name).pw_uid
            gid = grp_module.getgrnam(group_name).gr_gid
            for p in paths:
                os.lchown(p, uid, gid)
            return FakeProc(returncode=0)

        asyncio.create_subprocess_exec = fake_slow_chown
        try:
            with patch_for(fx18):
                results = await asyncio.gather(
                    bot._changeowner_execute_home(fx18.owner, requested_by="alice"),
                    bot._changeowner_execute_home(fx18.owner, requested_by="bob"),
                    bot._changeowner_execute_home(fx18.owner, requested_by="carol"),
                )
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        assert len(calls) == 1, f"3 concurrent requests for the SAME owner must chown exactly once, got {len(calls)}"
        titles = {r.title for r in results}
        assert "RTSA Action -- OWNERSHIP CHANGED (full home)" in titles, titles
    finally:
        fx18.cleanup()
    print("Scenario 18 (3 concurrent full-home requests for same owner execute chown exactly once) PASSED")

    classify = RTSABot._changeowner_home_classify
    assert classify(".", 100, 100, 100, 100) == "EXPECTED_USER_OWNED"
    assert classify(".pm2/dump.pm2", 0, 0, 100, 100) == "EXPECTED_USER_OWNED"
    assert classify("htdocs/site/deep/nested/file.php", 0, 0, 100, 100) == "EXPECTED_USER_OWNED"
    assert classify("unrecognized_dir", 0, 0, 100, 100) == "SUSPICIOUS_ROOT_OWNED"
    assert classify("unrecognized_dir", 65534, 65534, 100, 100) == "UNKNOWN"
    assert classify("unrecognized_dir", 100, 100, 100, 100) == "EXPECTED_USER_OWNED"
    assert RTSABot._changeowner_home_is_recognized_path(".") is True
    assert RTSABot._changeowner_home_is_recognized_path(".ssh/config") is True
    assert RTSABot._changeowner_home_is_recognized_path("random_thing/file") is False
    print("Scenario 19 (classification taxonomy: all four buckets + nested-path recognition) PASSED")

    domain_ok, domain_err = RTSABot._validate_changeowner_domain("still-works.example.com")
    assert domain_ok == "still-works.example.com" and domain_err is None
    owner_ok, owner_err = RTSABot._validate_changeowner_owner("stillworksuser")
    assert owner_ok == "stillworksuser" and owner_err is None
    print("Scenario 20 (legacy domain-scoped validation functions unaffected by the full-home extension) PASSED")

    print("\nALL /changeowner FULL-HOME (1-20) TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=180))
