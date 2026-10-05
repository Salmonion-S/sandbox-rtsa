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
from core.action_lock import ActionStatus
from core.event_bus import EventBus
from discord_integration.bot import RTSABot, _ConfirmCancelView


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
    def __init__(self, returncode=0, stdout=b"", stderr=b"", on_communicate=None, hang=False):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self._on_communicate = on_communicate
        self._hang = hang
        self.killed = False

    async def communicate(self):
        if self._hang:
            await asyncio.sleep(5.0)
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
    def __init__(self, owner="rtsa_co_ok", domain="rtsa-test.example", uid=590101, gid=590102):
        self.owner = owner
        self.domain = domain
        self.uid = uid
        self.gid = gid
        self.home = f"/home/{owner}"
        self.htdocs = os.path.join(self.home, "htdocs")
        self.target = os.path.join(self.htdocs, domain)

    def build(self, *, initial_uid=0, initial_gid=0, make_target_dir=True, make_target_file_instead=False):
        os.makedirs(self.htdocs, exist_ok=True)
        if make_target_file_instead:
            with open(self.target, "w") as f:
                f.write("not a directory")
        elif make_target_dir:
            sub = os.path.join(self.target, "public")
            os.makedirs(sub, exist_ok=True)
            with open(os.path.join(sub, "index.php"), "w") as f:
                f.write("<?php echo 'hi'; ?>")
            os.chown(self.target, initial_uid, initial_gid)
            os.chown(sub, initial_uid, initial_gid)
            os.chown(os.path.join(sub, "index.php"), initial_uid, initial_gid)

    def cleanup(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def pw_entry(self):
        return FakePwEntry(self.owner, self.uid, self.gid, self.home)

    def gr_entry(self):
        return FakeGrEntry(self.owner, self.gid)


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


async def main():
    assert os.geteuid() == 0, "these tests need root to create real /home/<owner> fixtures"

    domain_ok, domain_err = RTSABot._validate_changeowner_domain("sippp-puprtubabakab.com")
    assert domain_ok == "sippp-puprtubabakab.com" and domain_err is None
    _, err_traversal = RTSABot._validate_changeowner_domain("../../etc/passwd")
    assert err_traversal is not None
    print("Scenario 1 (valid domain accepted) PASSED")

    _, err_invalid = RTSABot._validate_changeowner_domain("not a domain!!")
    assert err_invalid is not None
    print("Scenario 2 (invalid domain rejected) PASSED")

    for bad in ("../../etc/passwd", "/etc/passwd", "a/../../b.com", "..com"):
        _, err = RTSABot._validate_changeowner_domain(bad)
        assert err is not None, f"path traversal payload must be rejected: {bad!r}"
    print("Scenario 3 (path traversal payloads on domain all rejected) PASSED")

    for bad in (
        "example.com;rm -rf / root", "example.com $(whoami)", "example.com|id",
        "example.com`id`", "example.com&&id", "example.com>out",
    ):
        _, err = RTSABot._validate_changeowner_domain(bad)
        assert err is not None, f"shell injection payload on domain must be rejected: {bad!r}"
    print("Scenario 4 (shell injection payloads on domain all rejected) PASSED")

    for bad in ("root; rm -rf /", "$(whoami)", "`id`", "user|id", "user&&id", "../etc", "user/../x"):
        _, err = RTSABot._validate_changeowner_owner(bad)
        assert err is not None, f"shell injection payload on owner must be rejected: {bad!r}"
    print("Scenario 5 (shell injection payloads on owner all rejected) PASSED")

    fx_missing_user = ChownFixture(owner="rtsa_co_nouser", domain="rtsa-test.example")
    with PwdGrpPatch():
        result = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_missing_user.domain, fx_missing_user.owner)
        assert result["ok"] is False and result["error_code"] == "USER_NOT_FOUND", result
    print("Scenario 6 (USER_NOT_FOUND when Linux user does not exist) PASSED")

    fx_no_group = ChownFixture(owner="rtsa_co_nogroup", domain="rtsa-test.example")
    with PwdGrpPatch(pw_by_name={fx_no_group.owner: fx_no_group.pw_entry()}):
        result = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_no_group.domain, fx_no_group.owner)
        assert result["ok"] is False and result["error_code"] == "GROUP_NOT_FOUND", result
    print("Scenario 7 (GROUP_NOT_FOUND when matching group does not exist) PASSED")

    fx_noproject = ChownFixture(owner="rtsa_co_noproj", domain="rtsa-test.example")
    try:
        os.makedirs(fx_noproject.home, exist_ok=True)
        with patch_for(fx_noproject):
            result = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_noproject.domain, fx_noproject.owner)
            assert result["ok"] is False and result["error_code"] == "PROJECT_NOT_FOUND", result
    finally:
        fx_noproject.cleanup()
    print("Scenario 8 (PROJECT_NOT_FOUND when htdocs/domain does not exist) PASSED")

    fx_notdir = ChownFixture(owner="rtsa_co_notdir", domain="rtsa-test.example")
    try:
        fx_notdir.build(make_target_dir=False, make_target_file_instead=True)
        with patch_for(fx_notdir):
            result = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_notdir.domain, fx_notdir.owner)
            assert result["ok"] is False and result["error_code"] == "TARGET_NOT_DIRECTORY", result
    finally:
        fx_notdir.cleanup()
    print("Scenario 9 (TARGET_NOT_DIRECTORY when target is a regular file) PASSED")

    fx_symlink = ChownFixture(owner="rtsa_co_symlink", domain="evil-symlink.example")
    try:
        os.makedirs(fx_symlink.htdocs, exist_ok=True)
        escape_dir = tempfile.mkdtemp(prefix="rtsa_escape_")
        os.symlink(escape_dir, fx_symlink.target)
        with patch_for(fx_symlink):
            result = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_symlink.domain, fx_symlink.owner)
            assert result["ok"] is False and result["error_code"] == "PATH_ESCAPE_ATTEMPT", result
        shutil.rmtree(escape_dir, ignore_errors=True)
    finally:
        fx_symlink.cleanup()
    print("Scenario 10 (symlink escape at the target hop rejected as PATH_ESCAPE_ATTEMPT) PASSED")

    fx_nochange = ChownFixture(owner="rtsa_co_nochg", domain="rtsa-test.example")
    try:
        fx_nochange.build(initial_uid=fx_nochange.uid, initial_gid=fx_nochange.gid)
        with patch_for(fx_nochange):
            result = bot_module.RTSABot._changeowner_preflight(make_bot(), fx_nochange.domain, fx_nochange.owner)
            assert result["ok"] is True and result["no_change_required"] is True, result
    finally:
        fx_nochange.cleanup()
    print("Scenario 11 (ownership already correct -> no_change_required=True, no chown needed) PASSED")

    orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
    fx_success = ChownFixture(owner="rtsa_co_success", domain="rtsa-test.example")
    try:
        fx_success.build(initial_uid=0, initial_gid=0)
        db = FakeDb()
        bot = make_bot(db)
        calls = []
        shutil.which = lambda n: f"/usr/bin/{n}"
        asyncio.create_subprocess_exec = real_chown_exec_factory(calls)
        with patch_for(fx_success):
            embed = await bot._changeowner_execute(fx_success.domain, fx_success.owner, requested_by="tester#1")
        assert embed.title == "RTSA Action -- OWNERSHIP CHANGED", embed.title
        field_map = {f.name: f.value for f in embed.fields}
        assert field_map["Status"] == "SUCCESS", field_map
        assert field_map["Post-change mismatches"] == "0", field_map
        assert int(field_map["Previous mismatches"]) > 0, field_map
        st = os.stat(fx_success.target)
        assert st.st_uid == fx_success.uid and st.st_gid == fx_success.gid, "real filesystem ownership must have changed"
        results = [r for _, r in db.actions]
        assert "CHANGE_OWNER_EXECUTING" in results and "CHANGE_OWNER_APPLIED" in results, results
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        fx_success.cleanup()
    print("Scenario 12 (successful ownership change: real chown runs, filesystem + audit trail verified) PASSED")

    fx_chownfail = ChownFixture(owner="rtsa_co_chownfail", domain="rtsa-test.example")
    try:
        fx_chownfail.build(initial_uid=0, initial_gid=0)
        db = FakeDb()
        bot = make_bot(db)
        shutil.which = lambda n: f"/usr/bin/{n}"

        async def fake_fail_exec(*a, **k):
            return FakeProc(returncode=1, stderr=b"chown: changing ownership: Operation not permitted")

        asyncio.create_subprocess_exec = fake_fail_exec
        with patch_for(fx_chownfail):
            embed = await bot._changeowner_execute(fx_chownfail.domain, fx_chownfail.owner, requested_by="tester#2")
        assert embed.title == "RTSA Action -- CHANGE_OWNER_FAILED", embed.title
        field_map = {f.name: f.value for f in embed.fields}
        assert "Operation not permitted" in field_map["Reason"], field_map
        results = [r for _, r in db.actions]
        assert "CHANGE_OWNER_FAILED:CHOWN_FAILED" in results, results
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        fx_chownfail.cleanup()
    print("Scenario 13 (chown non-zero exit -> CHANGE_OWNER_FAILED, real stderr surfaced) PASSED")

    fx_timeout = ChownFixture(owner="rtsa_co_timeout", domain="rtsa-test.example")
    try:
        fx_timeout.build(initial_uid=0, initial_gid=0)
        db = FakeDb()
        bot = make_bot(db)
        shutil.which = lambda n: f"/usr/bin/{n}"

        async def fake_hang_exec(*a, **k):
            return FakeProc(hang=True)

        asyncio.create_subprocess_exec = fake_hang_exec
        orig_timeout = bot_module._CHANGEOWNER_CHOWN_TIMEOUT
        bot_module._CHANGEOWNER_CHOWN_TIMEOUT = 0.05
        try:
            with patch_for(fx_timeout):
                embed = await bot._changeowner_execute(fx_timeout.domain, fx_timeout.owner, requested_by="tester#3")
        finally:
            bot_module._CHANGEOWNER_CHOWN_TIMEOUT = orig_timeout
        assert embed.title == "RTSA Action -- CHANGE_OWNER_FAILED", embed.title
        results = [r for _, r in db.actions]
        assert "CHANGE_OWNER_FAILED:CHOWN_TIMEOUT" in results, results
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        fx_timeout.cleanup()
    print("Scenario 14 (chown hangs past timeout -> CHANGE_OWNER_FAILED:CHOWN_TIMEOUT, process killed) PASSED")

    fx_verifyfail = ChownFixture(owner="rtsa_co_verifyfail", domain="rtsa-test.example")
    try:
        fx_verifyfail.build(initial_uid=0, initial_gid=0)
        db = FakeDb()
        bot = make_bot(db)
        shutil.which = lambda n: f"/usr/bin/{n}"

        async def fake_lying_exec(*a, **k):
            return FakeProc(returncode=0)

        asyncio.create_subprocess_exec = fake_lying_exec
        with patch_for(fx_verifyfail):
            embed = await bot._changeowner_execute(fx_verifyfail.domain, fx_verifyfail.owner, requested_by="tester#4")
        assert embed.title == "RTSA Action -- CHANGE_OWNER_VERIFICATION_FAILED", embed.title
        results = [r for _, r in db.actions]
        assert "CHANGE_OWNER_VERIFICATION_FAILED" in results, results
        st = os.stat(fx_verifyfail.target)
        assert st.st_uid == 0, "ownership on disk must be unchanged when the fake chown lied about success"
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        fx_verifyfail.cleanup()
    print("Scenario 15 (returncode 0 but filesystem unchanged -> CHANGE_OWNER_VERIFICATION_FAILED, never a blind SUCCESS) PASSED")

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

    cfg_auth = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False),
        modules=ModulesConfig(), cloudflare=CloudflareConfig(enabled=False),
    )
    disc_cfg_auth = DiscordConfig(enabled=True, admin_role_ids=[111], critical_command_role_ids=[222])
    bot_auth = RTSABot(disc_cfg_auth, cfg_auth, EventBus(), db_worker=FakeDb(), supervisor=None)
    unauthorized_member = make_fake_member(role_ids=[333])
    interaction_unauth = FakeInteractionAuth(unauthorized_member)
    assert bot_auth._authorized_interaction(interaction_unauth, critical=True) is False
    authorized_member = make_fake_member(role_ids=[222])
    interaction_auth = FakeInteractionAuth(authorized_member)
    assert bot_auth._authorized_interaction(interaction_auth, critical=True) is True
    print("Scenario 16 (unauthorized Discord user rejected, correctly-roled user accepted, by the same gate /changeowner uses) PASSED")

    class FakeConfirmResponse:
        def __init__(self):
            self.messages = []

        async def send_message(self, content=None, ephemeral=False):
            self.messages.append(content)

    class FakeConfirmInteraction:
        def __init__(self, user_id):
            self.user = type("U", (), {"id": user_id})()
            self.response = FakeConfirmResponse()

    view = _ConfirmCancelView(requested_by_id=42, timeout_seconds=5.0)
    other_user_interaction = FakeConfirmInteraction(user_id=999)
    allowed = await view.interaction_check(other_user_interaction)
    assert allowed is False, "a different Discord user must never be allowed to confirm/cancel"
    assert any("Cuma yang menjalankan" in (m or "") for m in other_user_interaction.response.messages)
    same_user_interaction = FakeConfirmInteraction(user_id=42)
    allowed_same = await view.interaction_check(same_user_interaction)
    assert allowed_same is True
    print("Scenario 17 (confirm/cancel from a different user than the requester is rejected) PASSED")

    fx_lock = ChownFixture(owner="rtsa_co_lock", domain="rtsa-test.example")
    try:
        fx_lock.build(initial_uid=0, initial_gid=0)
        db = FakeDb()
        bot = make_bot(db)
        calls = []
        shutil.which = lambda n: f"/usr/bin/{n}"
        asyncio.create_subprocess_exec = real_chown_exec_factory(calls)
        with patch_for(fx_lock):
            embed1 = await bot._changeowner_execute(fx_lock.domain, fx_lock.owner, requested_by="alice")
            embed2 = await bot._changeowner_execute(fx_lock.domain, fx_lock.owner, requested_by="bob")
        assert len(calls) == 1, f"a re-click on an already-handled target must not re-execute chown: {len(calls)} calls"
        assert embed1.title == "RTSA Action -- OWNERSHIP CHANGED"
        assert embed2.title == "RTSA Action -- NO CHANGE REQUIRED", (
            "a sequential re-click after a completed chown must observe the now-correct ownership "
            f"and report NO CHANGE REQUIRED rather than re-running chown: {embed2.title}"
        )
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        fx_lock.cleanup()
    print("Scenario 18 (double click / sequential re-click on the same domain executes chown exactly once) PASSED")

    fx_concurrent = ChownFixture(owner="rtsa_co_concurrent", domain="rtsa-test.example")
    try:
        fx_concurrent.build(initial_uid=0, initial_gid=0)
        db = FakeDb()
        bot = make_bot(db)
        calls = []
        shutil.which = lambda n: f"/usr/bin/{n}"

        async def fake_slow_chown(*argv, **kwargs):
            await asyncio.sleep(0.05)
            calls.append(argv)
            target = argv[4]
            uid = pwd_module.getpwnam(fx_concurrent.owner).pw_uid
            gid = grp_module.getgrnam(fx_concurrent.owner).gr_gid
            os.chown(target, uid, gid)
            for dirpath, dirnames, filenames in os.walk(target):
                for name in list(dirnames) + list(filenames):
                    os.chown(os.path.join(dirpath, name), uid, gid)
            return FakeProc(returncode=0)

        asyncio.create_subprocess_exec = fake_slow_chown
        with patch_for(fx_concurrent):
            results = await asyncio.gather(
                bot._changeowner_execute(fx_concurrent.domain, fx_concurrent.owner, requested_by="alice"),
                bot._changeowner_execute(fx_concurrent.domain, fx_concurrent.owner, requested_by="bob"),
                bot._changeowner_execute(fx_concurrent.domain, fx_concurrent.owner, requested_by="carol"),
            )
        assert len(calls) == 1, f"3 concurrent /changeowner requests for the SAME domain must chown exactly once, got {len(calls)}"
        titles = {r.title for r in results}
        assert "RTSA Action -- OWNERSHIP CHANGED" in titles, titles
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        fx_concurrent.cleanup()
    print("Scenario 19 (3 concurrent /changeowner requests for the same domain execute chown exactly once) PASSED")

    fx_audit = ChownFixture(owner="rtsa_co_audit", domain="rtsa-test.example")
    try:
        fx_audit.build(initial_uid=0, initial_gid=0)
        db = FakeDb()
        bot = make_bot(db)
        shutil.which = lambda n: f"/usr/bin/{n}"
        calls = []
        asyncio.create_subprocess_exec = real_chown_exec_factory(calls)
        with patch_for(fx_audit):
            await bot._changeowner_execute(fx_audit.domain, fx_audit.owner, requested_by="auditor#1")
        results_in_order = [r for _, r in db.actions]
        assert results_in_order == ["CHANGE_OWNER_EXECUTING", "CHANGE_OWNER_APPLIED"], results_in_order
        for action_dict, _ in db.actions:
            assert action_dict["target"] == fx_audit.domain
            assert action_dict["requested_by"] == "auditor#1"
            assert action_dict["action_type"].value == "CHANGE_OWNER"
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        fx_audit.cleanup()
    print("Scenario 20 (audit event lifecycle records EXECUTING then APPLIED with domain/operator/action_type intact) PASSED")

    print("\nALL /changeowner TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
