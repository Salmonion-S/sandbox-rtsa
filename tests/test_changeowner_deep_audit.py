import asyncio
import os
import shutil
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
        self.killed = False

    async def communicate(self):
        if self._on_communicate is not None:
            self._on_communicate()
        return self._stdout, self._stderr

    def kill(self):
        self.killed = True

    async def wait(self):
        return None


def make_bot(db=None):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False),
        modules=ModulesConfig(),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=db or FakeDb(), supervisor=None)


class ChownFixture:
    def __init__(self, owner, domain="rtsa-deep.example", uid=590201, gid=590202):
        self.owner = owner
        self.domain = domain
        self.uid = uid
        self.gid = gid
        self.home = f"/home/{owner}"
        self.htdocs = os.path.join(self.home, "htdocs")
        self.target = os.path.join(self.htdocs, domain)

    def makedirs(self):
        os.makedirs(self.target, exist_ok=True)

    def cleanup(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def pw_entry(self):
        return FakePwEntry(self.owner, self.uid, self.gid, self.home)

    def gr_entry(self):
        return FakeGrEntry(self.owner, self.gid)

    def chown_all(self, uid, gid):
        os.chown(self.target, uid, gid)
        for dirpath, dirnames, filenames in os.walk(self.target):
            for name in list(dirnames) + list(filenames):
                os.chown(os.path.join(dirpath, name), uid, gid)


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


def patch_for(fixture: ChownFixture) -> PwdGrpPatch:
    return PwdGrpPatch(
        pw_by_name={fixture.owner: fixture.pw_entry()},
        gr_by_name={fixture.owner: fixture.gr_entry()},
        pw_by_uid={fixture.uid: fixture.pw_entry(), 0: FakePwEntry("root", 0, 0, "/root")},
        gr_by_gid={fixture.gid: fixture.gr_entry(), 0: FakeGrEntry("root", 0)},
    )


def real_chown_exec_factory(calls):
    async def fake_exec(*argv, **kwargs):
        calls.append(argv)
        spec = argv[3]
        target = argv[4]
        owner_name, _, group_name = spec.partition(":")

        def do_chown():
            uid = pwd_module.getpwnam(owner_name).pw_uid
            gid = grp_module.getgrnam(group_name).gr_gid
            os.chown(target, uid, gid)
            for dirpath, dirnames, filenames in os.walk(target):
                for name in list(dirnames) + list(filenames):
                    os.chown(os.path.join(dirpath, name), uid, gid)

        return FakeProc(returncode=0, on_communicate=do_chown)

    return fake_exec


async def main() -> None:
    assert os.geteuid() == 0, "these tests need root to create real /home/<owner> fixtures"

    fx_a = ChownFixture(owner="rtsa_da_a", domain="rtsa-deep.example")
    try:
        fx_a.makedirs()
        os.chown(fx_a.target, fx_a.uid, fx_a.gid)
        with open(os.path.join(fx_a.target, "package-lock.json"), "w") as f:
            f.write("{}")
        os.chown(os.path.join(fx_a.target, "package-lock.json"), 0, 0)
        with patch_for(fx_a):
            preflight = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_a.domain, fx_a.owner)
        assert preflight["ok"] is True
        assert preflight["no_change_required"] is False, (
            "root correct but a child FILE is root:root -- must be CHANGE REQUIRED, not NO CHANGE REQUIRED"
        )
        audit = preflight["audit"]
        assert audit["files_mismatched"] == 1 and audit["dirs_mismatched"] == 0, audit
    finally:
        fx_a.cleanup()
    print("Scenario A (child file root:root, correct root -> CHANGE REQUIRED) PASSED")

    fx_b = ChownFixture(owner="rtsa_da_b", domain="rtsa-deep.example")
    try:
        fx_b.makedirs()
        os.chown(fx_b.target, fx_b.uid, fx_b.gid)
        sub = os.path.join(fx_b.target, "node_modules")
        os.makedirs(sub)
        os.chown(sub, 0, 0)
        with patch_for(fx_b):
            preflight = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_b.domain, fx_b.owner)
        assert preflight["ok"] is True
        assert preflight["no_change_required"] is False, (
            "root correct but a child DIRECTORY is root:root -- must be CHANGE REQUIRED"
        )
        audit = preflight["audit"]
        assert audit["dirs_mismatched"] == 1 and audit["files_mismatched"] == 0, audit
    finally:
        fx_b.cleanup()
    print("Scenario B (child directory root:root, correct root -> CHANGE REQUIRED) PASSED")

    fx_c = ChownFixture(owner="rtsa_da_c", domain="rtsa-deep.example")
    try:
        fx_c.makedirs()
        sub = os.path.join(fx_c.target, "src")
        os.makedirs(sub)
        with open(os.path.join(sub, "index.js"), "w") as f:
            f.write("x")
        fx_c.chown_all(fx_c.uid, fx_c.gid)
        with patch_for(fx_c):
            preflight = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_c.domain, fx_c.owner)
        assert preflight["ok"] is True and preflight["no_change_required"] is True, preflight
        audit = preflight["audit"]
        assert audit["files_mismatched"] == 0 and audit["dirs_mismatched"] == 0, audit
    finally:
        fx_c.cleanup()
    print("Scenario C (entire tree correctly owned -> NO CHANGE REQUIRED) PASSED")

    fx_d = ChownFixture(owner="rtsa_da_d", domain="rtsa-deep.example")
    try:
        fx_d.makedirs()
        os.chown(fx_d.target, fx_d.uid, fx_d.gid)
        expected_mismatches = 0
        for i in range(25):
            sub = os.path.join(fx_d.target, f"dir{i}")
            os.makedirs(sub)
            os.chown(sub, 0, 0)
            expected_mismatches += 1
            fpath = os.path.join(sub, "file.txt")
            with open(fpath, "w") as f:
                f.write("x")
            os.chown(fpath, 0, 0)
            expected_mismatches += 1
        with patch_for(fx_d):
            preflight = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_d.domain, fx_d.owner)
        audit = preflight["audit"]
        total = int(audit["files_mismatched"]) + int(audit["dirs_mismatched"])
        assert total == expected_mismatches, (total, expected_mismatches)
        assert len(audit["mismatch_samples"]) == bot_module._CHANGEOWNER_MAX_MISMATCH_SAMPLES, audit["mismatch_samples"]
        rendered = bot_module.RTSABot._format_changeowner_mismatch_samples(audit)
        assert "mismatch lainnya" in rendered, rendered
    finally:
        fx_d.cleanup()
    print("Scenario D (multiple mismatches -> bounded samples, accurate counters) PASSED")

    fx_e = ChownFixture(owner="rtsa_da_e", domain="rtsa-deep.example")
    try:
        fx_e.makedirs()
        os.chown(fx_e.target, fx_e.uid, fx_e.gid)
        for i in range(3000):
            fpath = os.path.join(fx_e.target, f"f{i}.txt")
            with open(fpath, "w") as f:
                f.write("x")
            os.chown(fpath, fx_e.uid, fx_e.gid)
        with patch_for(fx_e):
            audit = bot_module.RTSABot._changeowner_audit_tree(fx_e.target, fx_e.uid, fx_e.gid)
        assert audit["files_scanned"] == 3000, audit["files_scanned"]
        assert len(audit["mismatch_samples"]) == 0, "no mismatches expected, sample list must stay empty"
        assert sys.getsizeof(audit["mismatch_samples"]) < 500, "mismatch_samples must never grow proportional to tree size"
    finally:
        fx_e.cleanup()
    print("Scenario E (large simulated project -> no unbounded in-memory storage) PASSED")

    fx_f = ChownFixture(owner="rtsa_da_f", domain="rtsa-deep.example")
    try:
        fx_f.makedirs()
        os.chown(fx_f.target, fx_f.uid, fx_f.gid)
        vanish = os.path.join(fx_f.target, "vanish.txt")
        with open(vanish, "w") as f:
            f.write("x")
        os.chown(vanish, 0, 0)

        orig_lstat = os.lstat

        def flaky_lstat(path, *a, **k):
            if path == vanish:
                raise FileNotFoundError(2, "No such file or directory", path)
            return orig_lstat(path, *a, **k)

        os.lstat = flaky_lstat
        try:
            audit = bot_module.RTSABot._changeowner_audit_tree(fx_f.target, fx_f.uid, fx_f.gid)
        finally:
            os.lstat = orig_lstat
        assert audit["ok"] is True, audit
        assert audit["skipped_not_found"] == 1, audit
        assert audit["files_mismatched"] == 0, "a file that disappeared mid-scan must not be counted as a mismatch"
    finally:
        fx_f.cleanup()
    print("Scenario F (file disappears mid-scan -> handled safely, not crashed, not miscounted) PASSED")

    fx_g = ChownFixture(owner="rtsa_da_g", domain="rtsa-deep.example")
    try:
        fx_g.makedirs()
        os.chown(fx_g.target, fx_g.uid, fx_g.gid)
        denied = os.path.join(fx_g.target, "denied.txt")
        with open(denied, "w") as f:
            f.write("x")
        os.chown(denied, fx_g.uid, fx_g.gid)

        orig_lstat = os.lstat

        def denying_lstat(path, *a, **k):
            if path == denied:
                raise PermissionError(13, "Permission denied", path)
            return orig_lstat(path, *a, **k)

        os.lstat = denying_lstat
        try:
            audit = bot_module.RTSABot._changeowner_audit_tree(fx_g.target, fx_g.uid, fx_g.gid)
        finally:
            os.lstat = orig_lstat
        assert audit["skipped_permission_denied"] == 1, audit
        assert bot_module.RTSABot._changeowner_fully_verified(audit) is False, (
            "a permission-denied path during audit must block a compliance verdict, never be silently treated as OK"
        )
    finally:
        fx_g.cleanup()
    print("Scenario G (permission error mid-scan -> reported, never falsely compliant) PASSED")

    _, err = RTSABot._validate_changeowner_domain("not a domain !!")
    assert err is not None
    print("Scenario H (invalid domain rejected before any filesystem audit) PASSED")

    fx_i = ChownFixture(owner="rtsa_da_i", domain="rtsa-deep.example")
    try:
        os.makedirs(fx_i.home, exist_ok=True)
        with patch_for(fx_i):
            result = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_i.domain, fx_i.owner)
        assert result["ok"] is False and result["error_code"] == "PROJECT_NOT_FOUND", result
    finally:
        fx_i.cleanup()
    print("Scenario I (domain does not resolve to an existing CloudPanel project path -> rejected) PASSED")

    fx_j = ChownFixture(owner="rtsa_da_j", domain="rtsa-deep.example")
    try:
        os.makedirs(fx_j.htdocs, exist_ok=True)
        escape_dir = tempfile.mkdtemp(prefix="rtsa_deep_escape_")
        os.symlink(escape_dir, fx_j.target)
        with patch_for(fx_j):
            result = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_j.domain, fx_j.owner)
        assert result["ok"] is False and result["error_code"] == "PATH_ESCAPE_ATTEMPT", result
        shutil.rmtree(escape_dir, ignore_errors=True)
    finally:
        fx_j.cleanup()
    print("Scenario J (path traversal / escape attempt via target symlink -> rejected) PASSED")

    fx_k = ChownFixture(owner="rtsa_da_k", domain="rtsa-deep.example")
    outside_dir = tempfile.mkdtemp(prefix="rtsa_deep_outside_")
    try:
        fx_k.makedirs()
        os.chown(fx_k.target, fx_k.uid, fx_k.gid)
        outside_file = os.path.join(outside_dir, "secret.txt")
        with open(outside_file, "w") as f:
            f.write("outside")
        os.chown(outside_file, 0, 0)
        os.chown(outside_dir, 0, 0)
        link_path = os.path.join(fx_k.target, "escape_link")
        os.symlink(outside_dir, link_path)

        audit = bot_module.RTSABot._changeowner_audit_tree(fx_k.target, fx_k.uid, fx_k.gid)
        assert audit["symlinks_encountered"] == 1, audit
        sampled_paths = {s["path"] for s in audit["mismatch_samples"]}
        assert "escape_link/secret.txt" not in sampled_paths, (
            "audit must never descend into a symlinked directory's contents outside the project"
        )
        assert audit["files_scanned"] == 0, (
            "the file living outside the project (only reachable via the symlink) must never be scanned"
        )
        st_outside = os.lstat(outside_file)
        assert st_outside.st_uid == 0, "a file outside the project must never be touched by the audit"
    finally:
        shutil.rmtree(outside_dir, ignore_errors=True)
        fx_k.cleanup()
    print("Scenario K (symlink to outside the project -> not recursively followed or modified) PASSED")

    fx_l = ChownFixture(owner="rtsa_da_l", domain="rtsa-deep.example")
    try:
        fx_l.makedirs()
        os.chown(fx_l.target, 0, 0)
        good_sub = os.path.join(fx_l.target, "already_fixed")
        os.makedirs(good_sub)
        os.chown(good_sub, fx_l.uid, fx_l.gid)
        stuck_sub = os.path.join(fx_l.target, "still_root")
        os.makedirs(stuck_sub)
        os.chown(stuck_sub, 0, 0)

        db = FakeDb()
        bot = make_bot(db)
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"

        async def partial_chown_exec(*argv, **kwargs):
            return FakeProc(returncode=0)

        asyncio.create_subprocess_exec = partial_chown_exec
        try:
            with patch_for(fx_l):
                embed = await bot._changeowner_execute(fx_l.domain, fx_l.owner, requested_by="tester#L")
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        assert embed.title == "RTSA Action -- CHANGE_OWNER_VERIFICATION_FAILED", (
            f"chown that changes nothing on disk must never report SUCCESS or PARTIAL_SUCCESS: {embed.title}"
        )
        field_map = {f.name: f.value for f in embed.fields}
        assert field_map.get("Status") != "SUCCESS", field_map
    finally:
        fx_l.cleanup()
    print("Scenario L (chown exit 0 but verification still finds mismatches -> never a false SUCCESS) PASSED")

    fx_l2 = ChownFixture(owner="rtsa_da_l2", domain="rtsa-deep.example")
    try:
        fx_l2.makedirs()
        os.chown(fx_l2.target, 0, 0)
        stuck_sub = os.path.join(fx_l2.target, "still_root")
        os.makedirs(stuck_sub)
        os.chown(stuck_sub, 0, 0)

        db = FakeDb()
        bot = make_bot(db)
        orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
        shutil.which = lambda n: f"/usr/bin/{n}"

        async def only_root_chown_exec(*argv, **kwargs):
            target = argv[4]
            uid = pwd_module.getpwnam(fx_l2.owner).pw_uid
            gid = grp_module.getgrnam(fx_l2.owner).gr_gid
            os.chown(target, uid, gid)
            return FakeProc(returncode=0)

        asyncio.create_subprocess_exec = only_root_chown_exec
        try:
            with patch_for(fx_l2):
                embed = await bot._changeowner_execute(fx_l2.domain, fx_l2.owner, requested_by="tester#L2")
        finally:
            shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        assert embed.title == "RTSA Action -- OWNERSHIP CHANGED", embed.title
        field_map = {f.name: f.value for f in embed.fields}
        assert field_map["Status"] == "PARTIAL_SUCCESS", (
            f"an improvement that leaves mismatches behind must be PARTIAL_SUCCESS, never SUCCESS: {field_map}"
        )
        assert field_map["Post-change mismatches"] == "1", field_map
    finally:
        fx_l2.cleanup()
    print("Scenario L2 (chown fixes root but leaves a child mismatched -> PARTIAL_SUCCESS, not SUCCESS) PASSED")

    fx_m = ChownFixture(owner="rtsa_da_m", domain="rtsa-deep.example")
    try:
        fx_m.makedirs()
        os.chown(fx_m.target, fx_m.uid, fx_m.gid)
        for i in range(40):
            fpath = os.path.join(fx_m.target, f"leftover{i}.txt")
            with open(fpath, "w") as f:
                f.write("x")
            os.chown(fpath, 0, 0)
        with patch_for(fx_m):
            preflight = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_m.domain, fx_m.owner)
        preview_embed = bot_module.RTSABot._build_changeowner_preview_embed(fx_m.domain, fx_m.owner, preflight)
        assert len(preview_embed.fields) < 15, (
            f"a single consolidated embed must stay small regardless of mismatch count: {len(preview_embed.fields)} fields"
        )
        sample_field = next(f for f in preview_embed.fields if f.name == "Sample Mismatches")
        assert sample_field.value.count("\n- ") <= bot_module._CHANGEOWNER_MAX_MISMATCH_SAMPLES, sample_field.value
        assert len(sample_field.value) <= 1024, "Discord embed field must stay within the 1024-char limit"
    finally:
        fx_m.cleanup()
    print("Scenario M (Discord output stays a single bounded embed, no per-file spam) PASSED")

    import discord
    from unittest import mock

    class FakeRole:
        def __init__(self, role_id):
            self.id = role_id

    class FakeResponseSent:
        def __init__(self):
            self.messages = []

        async def send_message(self, content=None, ephemeral=False):
            self.messages.append(content)

    class FakeInteractionAuth:
        def __init__(self, member):
            self.user = member
            self.response = FakeResponseSent()

    def make_fake_member(role_ids, member_id=1):
        member = mock.Mock(spec=discord.Member)
        member.roles = [FakeRole(r) for r in role_ids]
        member.id = member_id
        return member

    disc_cfg_auth = DiscordConfig(enabled=True, admin_role_ids=[111], critical_command_role_ids=[222])
    cfg_auth = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False),
        modules=ModulesConfig(), cloudflare=CloudflareConfig(enabled=False),
    )
    bot_auth = RTSABot(disc_cfg_auth, cfg_auth, EventBus(), db_worker=FakeDb(), supervisor=None)
    unauthorized_member = make_fake_member(role_ids=[333])
    interaction_unauth = FakeInteractionAuth(unauthorized_member)
    assert bot_auth._authorized_interaction(interaction_unauth, critical=True) is False, (
        "an unauthorized user must still be blocked after the deep-audit rewrite"
    )
    print("Scenario N (existing command authorization is unaffected by the deep-audit rewrite) PASSED")

    print("\nALL /changeowner DEEP-AUDIT (A-N) TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
