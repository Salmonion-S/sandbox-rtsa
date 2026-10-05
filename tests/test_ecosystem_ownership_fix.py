import asyncio
import json
import os
import shutil
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import grp as grp_module
import pwd as pwd_module

import core.cloudpanel_resolver as cloudpanel_resolver
import core.project_ownership as project_ownership
from config.manager import (
    CloudflareConfig, DiscordConfig, EcosystemBackendClusterConfig, EcosystemConfigSettings,
    EcosystemNodeRuntimeConfig, ModulesConfig, ResponseEngineConfig, RTSAConfig,
)
from core.cloudpanel_resolver import CloudPanelAsset
from core.event_bus import EventBus
from discord_integration.bot import RTSABot


class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass


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


class PwdGrpPatch:
    def __init__(self, owner, uid, gid):
        self.owner = owner
        self.uid = uid
        self.gid = gid
        self._orig = {}

    def __enter__(self):
        self._orig["getpwnam"] = pwd_module.getpwnam
        self._orig["getpwuid"] = pwd_module.getpwuid
        self._orig["getgrnam"] = grp_module.getgrnam
        self._orig["getgrgid"] = grp_module.getgrgid

        pw = FakePwEntry(self.owner, self.uid, self.gid, f"/home/{self.owner}")
        gr = FakeGrEntry(self.owner, self.gid)

        def fake_getpwnam(name):
            if name == self.owner:
                return pw
            return self._orig["getpwnam"](name)

        def fake_getpwuid(uid):
            if uid == self.uid:
                return pw
            return self._orig["getpwuid"](uid)

        def fake_getgrnam(name):
            if name == self.owner:
                return gr
            return self._orig["getgrnam"](name)

        def fake_getgrgid(gid):
            if gid == self.gid:
                return gr
            return self._orig["getgrgid"](gid)

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


def make_bot(db=None):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False),
        modules=ModulesConfig(),
        cloudflare=CloudflareConfig(enabled=False),
        ecosystem_config=EcosystemConfigSettings(
            backend_cluster=EcosystemBackendClusterConfig(mode="auto", max_instances=8, reserve_cpu=1),
            node_runtime=EcosystemNodeRuntimeConfig(),
        ),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=db or FakeDb(), supervisor=None)


class ProjectFixture:
    def __init__(self, owner, domain, uid, gid):
        self.owner = owner
        self.domain = domain
        self.uid = uid
        self.gid = gid
        self.home = f"/home/{owner}"
        self.project = f"{self.home}/htdocs/{domain}"

    def build(self):
        os.makedirs(self.project, exist_ok=True)
        with open(f"{self.project}/package.json", "w") as f:
            json.dump({"scripts": {"start": "next start"}}, f)

    def asset(self):
        return CloudPanelAsset(
            domain=self.domain, linux_user=self.owner, project_root=self.home, htdocs_path=self.project,
            nginx_vhost=None, pm2_user=self.owner, discovered_at=time.time(),
        )

    def config_path(self):
        return f"{self.project}/ecosystem.config.js"

    def cleanup(self):
        shutil.rmtree(self.home, ignore_errors=True)


def patch_resolver(asset):
    orig = cloudpanel_resolver.resolve_domain

    async def fake_resolve(domain):
        return asset if domain == asset.domain else None

    cloudpanel_resolver.resolve_domain = fake_resolve
    return orig


def restore_resolver(orig):
    cloudpanel_resolver.resolve_domain = orig


async def main() -> None:
    assert os.geteuid() == 0, "these tests need root to create real /home/<user> fixtures"

    fx1 = ProjectFixture("newus_perkim_like", "perkim.newus.id.example", 590501, 590501)
    try:
        fx1.build()
        with PwdGrpPatch(fx1.owner, fx1.uid, fx1.gid):
            orig = patch_resolver(fx1.asset())
            try:
                bot = make_bot()
                embed_created = await bot._feaddeco_execute(fx1.domain, 4021, requested_by="tester", replace=False)
            finally:
                restore_resolver(orig)
        assert embed_created.title == "RTSA Action -- FRONTEND ECOSYSTEM CONFIG CREATED", embed_created.title
        field_map = {f.name: f.value for f in embed_created.fields}
        assert field_map["Ownership Status"] == "VERIFIED", field_map
        st = os.stat(fx1.config_path())
        assert (st.st_uid, st.st_gid) == (fx1.uid, fx1.gid), (
            f"newly-created ecosystem.config.js must be owned by the project user, not root: "
            f"got uid={st.st_uid} gid={st.st_gid}"
        )
        assert st.st_uid != 0 and st.st_gid != 0, "must never be root-owned"

        with PwdGrpPatch(fx1.owner, fx1.uid, fx1.gid):
            orig = patch_resolver(fx1.asset())
            try:
                bot2 = make_bot()
                embed_replaced = await bot2._feaddeco_execute(fx1.domain, 4099, requested_by="tester", replace=True)
            finally:
                restore_resolver(orig)
        assert embed_replaced.title == "RTSA Action -- FRONTEND ECOSYSTEM CONFIG REPLACED", embed_replaced.title
        field_map_2 = {f.name: f.value for f in embed_replaced.fields}
        assert field_map_2["Ownership Status"] == "VERIFIED", field_map_2
        st_after_replace = os.stat(fx1.config_path())
        assert (st_after_replace.st_uid, st_after_replace.st_gid) == (fx1.uid, fx1.gid), (
            "replaced ecosystem.config.js must still be owned by the project user"
        )

        backup_field = field_map_2.get("Backup")
        assert backup_field, f"expected a Backup field on replace: {field_map_2}"
        st_backup = os.stat(backup_field)
        assert (st_backup.st_uid, st_backup.st_gid) == (fx1.uid, fx1.gid), (
            f"backup file must be owned by the project user, not root: uid={st_backup.st_uid} gid={st_backup.st_gid}"
        )
        assert st_backup.st_uid != 0, "backup must never be root-owned"
    finally:
        fx1.cleanup()
    print("Scenario 1 (create -> replace -> backup: all <user>:<user>, never root:root) PASSED")

    fx2 = ProjectFixture("ownerfail_user", "ownerfail.example", 590502, 590502)
    try:
        fx2.build()
        orig_chown = os.chown

        def failing_chown(path, uid, gid, *a, **k):
            if path == fx2.config_path():
                raise OSError(13, "Permission denied (simulated)")
            return orig_chown(path, uid, gid, *a, **k)

        os.chown = failing_chown
        try:
            with PwdGrpPatch(fx2.owner, fx2.uid, fx2.gid):
                orig = patch_resolver(fx2.asset())
                try:
                    db = FakeDb()
                    bot = make_bot(db)
                    embed = await bot._feaddeco_execute(fx2.domain, 4021, requested_by="tester", replace=False)
                finally:
                    restore_resolver(orig)
        finally:
            os.chown = orig_chown

        assert embed.title == "RTSA Action -- ECOSYSTEM CONFIG FAILED", (
            f"an ownership-repair failure must never be reported as CREATED/success: {embed.title}"
        )
        assert os.path.isfile(fx2.config_path()), "content must remain on disk for manual recovery"
    finally:
        fx2.cleanup()
    print("Scenario 2 (ownership repair fails -> whole action FAILED, never a false success) PASSED")

    fx3 = ProjectFixture("scoped_user", "scoped.example", 590503, 590503)
    try:
        fx3.build()
        sibling = f"{fx3.project}/unrelated_file.txt"
        with open(sibling, "w") as f:
            f.write("do not touch me")
        os.chown(sibling, 0, 0)

        with PwdGrpPatch(fx3.owner, fx3.uid, fx3.gid):
            orig = patch_resolver(fx3.asset())
            try:
                bot = make_bot()
                embed = await bot._feaddeco_execute(fx3.domain, 4021, requested_by="tester", replace=False)
            finally:
                restore_resolver(orig)
        assert embed.title == "RTSA Action -- FRONTEND ECOSYSTEM CONFIG CREATED", embed.title
        st_config = os.stat(fx3.config_path())
        assert (st_config.st_uid, st_config.st_gid) == (fx3.uid, fx3.gid)
        st_sibling = os.stat(sibling)
        assert st_sibling.st_uid == 0 and st_sibling.st_gid == 0, (
            "an unrelated sibling file must NEVER be touched by an ecosystem.config.js write -- "
            "proves no recursive/blanket chown happened"
        )
    finally:
        fx3.cleanup()
    print("Scenario 3 (no recursive chown -- unrelated sibling file provably untouched) PASSED")

    with PwdGrpPatch("unituser", 590504, 590504):
        ids = project_ownership.resolve_linux_user_uid_gid("unituser")
        assert ids == (590504, 590504), ids
        assert project_ownership.resolve_linux_user_uid_gid("no_such_user_xyz") is None
    print("Scenario 4a (resolve_linux_user_uid_gid: real lookup, never a hardcoded mapping) PASSED")

    fx4 = ProjectFixture("directuser", "direct.example", 590505, 590505)
    try:
        os.makedirs(fx4.project, exist_ok=True)
        target = f"{fx4.project}/somefile.txt"
        with open(target, "w") as f:
            f.write("x")
        os.chown(target, 0, 0)
        result = project_ownership.ensure_path_ownership(target, fx4.uid, fx4.gid)
        assert result.ok is True and result.repaired is True, result
        st = os.stat(target)
        assert (st.st_uid, st.st_gid) == (fx4.uid, fx4.gid)

        result2 = project_ownership.ensure_path_ownership(target, fx4.uid, fx4.gid)
        assert result2.ok is True and result2.repaired is False, result2
    finally:
        fx4.cleanup()
    print("Scenario 4b (ensure_path_ownership: repairs once, idempotent on re-check) PASSED")

    fx5 = ProjectFixture("boundaryuser", "boundary.example", 590506, 590506)
    outside_dir = "/tmp/rtsa_ownership_boundary_escape"
    try:
        os.makedirs(fx5.home, exist_ok=True)
        shutil.rmtree(outside_dir, ignore_errors=True)
        os.makedirs(outside_dir, exist_ok=True)
        outside_file = f"{outside_dir}/not_in_project.txt"
        with open(outside_file, "w") as f:
            f.write("x")
        os.chown(outside_file, 0, 0)

        with PwdGrpPatch(fx5.owner, fx5.uid, fx5.gid):
            result = project_ownership.ensure_project_ownership(outside_file, fx5.owner)
        assert result.ok is False, "a path outside the project user's home must be refused"
        assert "luar scope" in (result.error or ""), result
        st = os.stat(outside_file)
        assert st.st_uid == 0, "a path outside the allowed boundary must never be chowned"
    finally:
        fx5.cleanup()
        shutil.rmtree(outside_dir, ignore_errors=True)
    print("Scenario 4c (ensure_project_ownership: refuses a path outside the user's home boundary) PASSED")

    fx6 = ProjectFixture("symlinkuser", "symlink.example", 590507, 590507)
    outside_target_dir = "/tmp/rtsa_ownership_symlink_target"
    try:
        os.makedirs(fx6.project, exist_ok=True)
        shutil.rmtree(outside_target_dir, ignore_errors=True)
        os.makedirs(outside_target_dir, exist_ok=True)
        target_file = f"{outside_target_dir}/target.txt"
        with open(target_file, "w") as f:
            f.write("x")
        os.chown(target_file, 0, 0)
        link_path = f"{fx6.project}/link_to_outside"
        os.symlink(target_file, link_path)
        os.lchown(link_path, 0, 0)

        with PwdGrpPatch(fx6.owner, fx6.uid, fx6.gid):
            result = project_ownership.ensure_project_ownership(link_path, fx6.owner)
        assert result.ok is True, result
        st_link = os.lstat(link_path)
        assert (st_link.st_uid, st_link.st_gid) == (fx6.uid, fx6.gid), (
            "the symlink's OWN ownership may be corrected (lchown-equivalent)"
        )
        st_target = os.stat(target_file)
        assert st_target.st_uid == 0, "the symlink TARGET outside the project must never be touched"
    finally:
        fx6.cleanup()
        shutil.rmtree(outside_target_dir, ignore_errors=True)
    print("Scenario 4d (ensure_project_ownership never follows a symlink to its target) PASSED")

    print("\nALL ecosystem.config.js OWNERSHIP FIX regression tests PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
