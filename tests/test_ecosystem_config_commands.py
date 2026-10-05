import asyncio
import json
import os
import shutil
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import grp as grp_module
import pwd as pwd_module

import core.cloudpanel_resolver as cloudpanel_resolver
from config.manager import (
    CloudflareConfig, DiscordConfig, EcosystemBackendClusterConfig, EcosystemConfigSettings,
    EcosystemNodeRuntimeConfig, FileIntegrityDetectorConfig, ModulesConfig, ResponseEngineConfig, RTSAConfig,
)
from core import ecosystem_config as ec
from core.action_lock import ActionStatus
from core.change_attribution import BEADDECO, FEADDECO, MONOADDECO, WBEADDECO, load_recent_changes
from core.cloudpanel_resolver import CloudPanelAsset
from core.event_bus import EventBus
from core.file_identity import FileIdentity
from discord_integration.bot import RTSABot, _parse_cekport_port
from modules.file_integrity_detector import FileIntegrityDetector


class FakeDb:
    def __init__(self):
        self.actions = []

    def enqueue_action(self, action_dict, result="pending"):
        self.actions.append((dict(action_dict), result))

    def enqueue_incident_create(self, **k):
        pass

    def enqueue_incident_update(self, *a, **k):
        pass


def identity(path, sha="x", mode=0o644, uid=1000, gid=1000):
    return FileIdentity(
        sha256=sha, mode=mode, uid=uid, gid=gid, size=10, mtime=time.time(),
        is_symlink=False, symlink_target=None, inode=1,
    )


def make_bot(db=None, ledger_path=None, cluster_max=8, cluster_reserve=1, cluster_mode="auto"):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False),
        modules=ModulesConfig(
            file_integrity_detector=FileIntegrityDetectorConfig(
                change_ledger_path=ledger_path or tempfile.mktemp(suffix=".json"),
            ),
        ),
        cloudflare=CloudflareConfig(enabled=False),
        ecosystem_config=EcosystemConfigSettings(
            backend_cluster=EcosystemBackendClusterConfig(
                mode=cluster_mode, max_instances=cluster_max, reserve_cpu=cluster_reserve,
            ),
            node_runtime=EcosystemNodeRuntimeConfig(),
        ),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=db or FakeDb(), supervisor=None)


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


_FAKE_PW_BY_NAME: dict = {}
_FAKE_PW_BY_UID: dict = {}
_FAKE_GR_BY_NAME: dict = {}
_FAKE_GR_BY_GID: dict = {}
_next_fake_id = [590400]


def _install_fake_pwd_grp():
    def fake_getpwnam(name):
        if name in _FAKE_PW_BY_NAME:
            return _FAKE_PW_BY_NAME[name]
        return _orig_getpwnam(name)

    def fake_getpwuid(uid):
        if uid in _FAKE_PW_BY_UID:
            return _FAKE_PW_BY_UID[uid]
        return _orig_getpwuid(uid)

    def fake_getgrnam(name):
        if name in _FAKE_GR_BY_NAME:
            return _FAKE_GR_BY_NAME[name]
        return _orig_getgrnam(name)

    def fake_getgrgid(gid):
        if gid in _FAKE_GR_BY_GID:
            return _FAKE_GR_BY_GID[gid]
        return _orig_getgrgid(gid)

    pwd_module.getpwnam = fake_getpwnam
    pwd_module.getpwuid = fake_getpwuid
    grp_module.getgrnam = fake_getgrnam
    grp_module.getgrgid = fake_getgrgid


_orig_getpwnam = pwd_module.getpwnam
_orig_getpwuid = pwd_module.getpwuid
_orig_getgrnam = grp_module.getgrnam
_orig_getgrgid = grp_module.getgrgid


def _restore_real_pwd_grp():
    pwd_module.getpwnam = _orig_getpwnam
    pwd_module.getpwuid = _orig_getpwuid
    grp_module.getgrnam = _orig_getgrnam
    grp_module.getgrgid = _orig_getgrgid


class EcosystemFixture:
    def __init__(self, user, domain):
        self.user = user
        self.domain = domain
        self.home = f"/home/{user}"
        self.project = f"{self.home}/htdocs/{domain}"
        if user not in _FAKE_PW_BY_NAME:
            uid = _next_fake_id[0]
            _next_fake_id[0] += 1
            pw = FakePwEntry(user, uid, uid, self.home)
            gr = FakeGrEntry(user, uid)
            _FAKE_PW_BY_NAME[user] = pw
            _FAKE_PW_BY_UID[uid] = pw
            _FAKE_GR_BY_NAME[user] = gr
            _FAKE_GR_BY_GID[uid] = gr
        self.uid = _FAKE_PW_BY_NAME[user].pw_uid
        self.gid = _FAKE_PW_BY_NAME[user].pw_gid

    def build_frontend(self, start_script=True, package_json=True):
        os.makedirs(self.project, exist_ok=True)
        if package_json:
            data = {"scripts": ({"start": "next start"} if start_script else {})}
            with open(f"{self.project}/package.json", "w") as f:
                json.dump(data, f)

    def build_backend(self, entrypoint=True, package_json=True):
        os.makedirs(f"{self.project}/dist", exist_ok=True)
        if entrypoint:
            with open(f"{self.project}/dist/app.js", "w") as f:
                f.write("console.log(1);\n")
        if package_json:
            with open(f"{self.project}/package.json", "w") as f:
                json.dump({"name": self.domain}, f)

    def build_worker(self, entrypoint=True):
        os.makedirs(f"{self.project}/dist/src/workers", exist_ok=True)
        if entrypoint:
            with open(f"{self.project}/dist/src/workers/index.js", "w") as f:
                f.write("console.log(1);\n")

    def write_package_json(self, data):
        os.makedirs(self.project, exist_ok=True)
        with open(f"{self.project}/package.json", "w") as f:
            json.dump(data, f)

    def write_file(self, relpath, content="console.log(1);\n"):
        full = os.path.join(self.project, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)

    def build_node_interpreter(self, version="v22.23.1"):
        node_dir = f"{self.home}/.nvm/versions/node/{version}/bin"
        os.makedirs(node_dir, exist_ok=True)
        node_bin = f"{node_dir}/node"
        with open(node_bin, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(node_bin, 0o755)

    def write_existing_config(self, content):
        os.makedirs(self.project, exist_ok=True)
        with open(f"{self.project}/ecosystem.config.js", "w") as f:
            f.write(content)

    def asset(self):
        return CloudPanelAsset(
            domain=self.domain, linux_user=self.user, project_root=self.home, htdocs_path=self.project,
            nginx_vhost=None, pm2_user=self.user, discovered_at=time.time(),
        )

    def config_path(self):
        return f"{self.project}/ecosystem.config.js"

    def cleanup(self):
        shutil.rmtree(self.home, ignore_errors=True)


def patch_resolver(assets_by_domain):
    orig = cloudpanel_resolver.resolve_domain

    async def fake_resolve(domain):
        return assets_by_domain.get(domain)

    cloudpanel_resolver.resolve_domain = fake_resolve
    return orig


def restore_resolver(orig):
    cloudpanel_resolver.resolve_domain = orig


async def main() -> None:
    assert os.geteuid() == 0, "these tests need root to create real /home/<user> fixtures"

    domain_ok, domain_err = RTSABot._validate_changeowner_domain("backend-disdik.newus.id")
    assert domain_ok == "backend-disdik.newus.id" and domain_err is None
    print("Scenario 1 (well-formed domain passes format validation) PASSED")

    for bad in ("", "../../etc/passwd", "a/b.com", "example.com;rm -rf /", "example.com $(whoami)"):
        _, err = RTSABot._validate_changeowner_domain(bad)
        assert err is not None, f"invalid domain must be rejected: {bad!r}"
    print("Scenario 2 (invalid domain strings rejected before resolution) PASSED")

    fx3 = EcosystemFixture("rtsa_ec_notfound", "no-such-domain.example")
    orig = patch_resolver({})
    try:
        bot = make_bot()
        preflight = await bot._feaddeco_preflight(fx3.domain, 4026)
    finally:
        restore_resolver(orig)
    assert preflight["ok"] is False and preflight["error_code"] == "DOMAIN_NOT_FOUND", preflight
    print("Scenario 3 (domain not found by resolver -> DOMAIN_NOT_FOUND, no path guessed) PASSED")

    for bad in ("../../etc/passwd", "a/../../b.com", "..com"):
        _, err = RTSABot._validate_changeowner_domain(bad)
        assert err is not None, f"path traversal payload must be rejected: {bad!r}"
    print("Scenario 4 (path traversal attempt in domain rejected) PASSED")

    fx5 = EcosystemFixture("rtsa_ec_escape", "escape.example")
    escape_asset = CloudPanelAsset(
        domain=fx5.domain, linux_user=fx5.user, project_root="/etc", htdocs_path="/etc/nginx",
        nginx_vhost=None, pm2_user=fx5.user, discovered_at=time.time(),
    )
    orig = patch_resolver({fx5.domain: escape_asset})
    try:
        bot = make_bot()
        preflight = await bot._feaddeco_preflight(fx5.domain, 4026)
    finally:
        restore_resolver(orig)
    assert preflight["ok"] is False and preflight["error_code"] == "PATH_ESCAPE_ATTEMPT", preflight
    print("Scenario 5 (canonical path escape outside /home rejected) PASSED")

    assert _parse_cekport_port(0) is None
    assert _parse_cekport_port(65536) is None
    assert _parse_cekport_port("4026; rm -rf /") is None
    assert _parse_cekport_port("$(whoami)") is None
    assert _parse_cekport_port("../4026") is None
    assert _parse_cekport_port(4022.5) is None
    assert _parse_cekport_port(4026) == 4026
    print("Scenarios 6-9 (invalid port / port 0 / port 65536 / non-integer port all rejected, valid port accepted) PASSED")

    fx10 = EcosystemFixture("rtsa_ec_noover", "noover.example")
    try:
        fx10.build_frontend()
        fx10.write_existing_config("module.exports = { apps: [{}] };\n")
        orig = patch_resolver({fx10.domain: fx10.asset()})
        db = FakeDb()
        try:
            bot = make_bot(db)
            embed = await bot._feaddeco_execute(fx10.domain, 4026, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "EXISTING ECOSYSTEM CONFIG DETECTED", embed.title
        with open(fx10.config_path()) as f:
            assert f.read() == "module.exports = { apps: [{}] };\n"
        print("Scenario 10 (existing config is never overwritten automatically) PASSED")
    finally:
        fx10.cleanup()

    fx11 = EcosystemFixture("rtsa_ec_replconfirm", "replconfirm.example")
    try:
        fx11.build_frontend()
        original = "module.exports = { apps: [{}] };\n"
        fx11.write_existing_config(original)
        orig = patch_resolver({fx11.domain: fx11.asset()})
        db = FakeDb()
        try:
            bot = make_bot(db)
            embed = await bot._feaddeco_execute(fx11.domain, 4026, requested_by="tester", replace=True)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- FRONTEND ECOSYSTEM CONFIG REPLACED", embed.title
        with open(fx11.config_path()) as f:
            assert f.read() != original, "replace=True (simulating a confirmed replace) must actually write"
        print("Scenario 11 (replace path, once explicitly invoked, performs the write -- confirmation gate lives in the Discord View layer) PASSED")
    finally:
        fx11.cleanup()

    fx12 = EcosystemFixture("rtsa_ec_dblclick", "dblclick.example")
    try:
        fx12.build_frontend()
        orig = patch_resolver({fx12.domain: fx12.asset()})
        db = FakeDb()
        try:
            bot = make_bot(db)
            e1 = await bot._feaddeco_execute(fx12.domain, 4026, requested_by="alice", replace=False)
            os.remove(fx12.config_path())
            e2 = await bot._feaddeco_execute(fx12.domain, 4026, requested_by="alice", replace=False)
        finally:
            restore_resolver(orig)
        assert e1.title == "RTSA Action -- FRONTEND ECOSYSTEM CONFIG CREATED", e1.title
        assert e2.title == "RTSA Action -- ECOSYSTEM (cached result)", (
            f"double click on an already-completed target must not re-execute: {e2.title}"
        )
        assert not os.path.isfile(fx12.config_path()), "cached-result re-click must not recreate the file"
        print("Scenario 12 (double click replace/create does not cause two writes) PASSED")
    finally:
        fx12.cleanup()

    fx13 = EcosystemFixture("rtsa_ec_concurrent", "concurrent.example")
    try:
        fx13.build_frontend()
        orig = patch_resolver({fx13.domain: fx13.asset()})
        db = FakeDb()
        try:
            bot = make_bot(db)
            results = await asyncio.gather(
                bot._feaddeco_execute(fx13.domain, 4026, requested_by="alice", replace=False),
                bot._feaddeco_execute(fx13.domain, 4026, requested_by="bob", replace=False),
                bot._feaddeco_execute(fx13.domain, 4026, requested_by="carol", replace=False),
            )
        finally:
            restore_resolver(orig)
        created = [r for r in results if r.title == "RTSA Action -- FRONTEND ECOSYSTEM CONFIG CREATED"]
        assert len(created) == 1, f"concurrent action must not cause a race: {[r.title for r in results]}"
        print("Scenario 13 (concurrent action for same project does not cause a race) PASSED")
    finally:
        fx13.cleanup()

    fx14 = EcosystemFixture("rtsa_ec_backupatomic", "backupatomic.example")
    try:
        fx14.build_frontend()
        original = "module.exports = { apps: [{ name: 'old' }] };\n"
        fx14.write_existing_config(original)
        orig = patch_resolver({fx14.domain: fx14.asset()})
        db = FakeDb()
        try:
            bot = make_bot(db)
            embed = await bot._feaddeco_execute(fx14.domain, 4027, requested_by="tester", replace=True)
        finally:
            restore_resolver(orig)
        field_map = {f.name: f.value for f in embed.fields}
        backup_path = field_map["Backup"]
        assert os.path.isfile(backup_path)
        with open(backup_path) as f:
            assert f.read() == original
        assert os.path.basename(backup_path).startswith("ecosystem.config.js.rtsa-backup-")
        leftover_tmp = [f for f in os.listdir(fx14.project) if ".tmp-" in f]
        assert leftover_tmp == [], f"no orphaned temp files after a successful atomic backup+replace: {leftover_tmp}"
        print("Scenario 14 (backup is created atomically with the correct naming, no leftover temp files) PASSED")
    finally:
        fx14.cleanup()

    fx15 = EcosystemFixture("rtsa_ec_backupfail", "backupfail.example")
    try:
        fx15.build_frontend()
        original = "module.exports = { apps: [{ name: 'protected' }] };\n"
        fx15.write_existing_config(original)
        orig_fsync = os.fsync
        call_count = {"n": 0}

        def failing_first_fsync(fd):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise OSError("simulated backup fsync failure")
            return orig_fsync(fd)

        os.fsync = failing_first_fsync
        orig = patch_resolver({fx15.domain: fx15.asset()})
        db = FakeDb()
        try:
            bot = make_bot(db)
            embed = await bot._feaddeco_execute(fx15.domain, 4028, requested_by="tester", replace=True)
        finally:
            os.fsync = orig_fsync
            restore_resolver(orig)
        with open(fx15.config_path()) as f:
            surviving = f.read()
        assert surviving == original, "if backup creation fails, the main config must remain fully untouched"
        assert embed.title == "RTSA Action -- ECOSYSTEM CONFIG FAILED", embed.title
        leftover_tmp = [f for f in os.listdir(fx15.project) if ".tmp-" in f]
        assert leftover_tmp == [], f"failed backup write must not leave an orphaned temp file: {leftover_tmp}"
        backups = [f for f in os.listdir(fx15.project) if "rtsa-backup" in f]
        assert backups == [], f"a failed backup must not leave a partial backup file either: {backups}"
        print("Scenario 15 (backup failure never touches or corrupts the main config) PASSED")
    finally:
        fx15.cleanup()

    fx16 = EcosystemFixture("rtsa_ec_writefail", "writefail.example")
    try:
        fx16.build_frontend()
        original = "module.exports = { apps: [{ name: 'stable' }] };\n"
        fx16.write_existing_config(original)
        orig_fsync = os.fsync
        call_count = {"n": 0}

        def fail_second_fsync(fd):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise OSError("simulated main-config fsync failure")
            return orig_fsync(fd)

        os.fsync = fail_second_fsync
        orig = patch_resolver({fx16.domain: fx16.asset()})
        db = FakeDb()
        try:
            bot = make_bot(db)
            embed = await bot._feaddeco_execute(fx16.domain, 4029, requested_by="tester", replace=True)
        finally:
            os.fsync = orig_fsync
            restore_resolver(orig)
        with open(fx16.config_path()) as f:
            surviving = f.read()
        assert surviving == original, "old config must survive a write failure even after a successful backup"
        assert embed.title == "RTSA Action -- ECOSYSTEM CONFIG FAILED", embed.title
        print("Scenario 16 (config write failure never corrupts/truncates the old config) PASSED")
    finally:
        fx16.cleanup()

    fx17 = EcosystemFixture("rtsa_ec_tmpclean", "tmpclean.example")
    try:
        fx17.build_frontend()
        orig = patch_resolver({fx17.domain: fx17.asset()})
        db = FakeDb()
        try:
            bot = make_bot(db)
            await bot._feaddeco_execute(fx17.domain, 4030, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        leftover_tmp = [f for f in os.listdir(fx17.project) if ".tmp-" in f]
        assert leftover_tmp == [], f"successful create must leave zero temp files behind: {leftover_tmp}"
        print("Scenario 17 (temporary file cleanup after successful write) PASSED")
    finally:
        fx17.cleanup()

    fx18 = EcosystemFixture("rtsa_ec_fimtrust", "fimtrust.example")
    ledger_path = tempfile.mktemp(suffix=".json")
    try:
        fx18.build_frontend()
        orig = patch_resolver({fx18.domain: fx18.asset()})
        try:
            bot = make_bot(ledger_path=ledger_path)
            embed = await bot._feaddeco_execute(fx18.domain, 4026, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- FRONTEND ECOSYSTEM CONFIG CREATED"
        with open(fx18.config_path()) as f:
            written_content = f.read()
        recent = load_recent_changes(ledger_path, 3600.0)
        record = recent.get(os.path.realpath(fx18.config_path()))
        assert record is not None and record.source == FEADDECO, recent

        det = FileIntegrityDetector(EventBus(), FileIntegrityDetectorConfig(change_ledger_path=ledger_path))
        import hashlib
        actual_sha256 = hashlib.sha256(written_content.encode("utf-8")).hexdigest()
        evaluated = det._evaluate_change(
            fx18.config_path(), "configs", None, identity(fx18.config_path(), sha=actual_sha256),
            recent_command_changes=recent,
        )
        assert evaluated is not None
        assert evaluated["change_source"] == FEADDECO
        assert evaluated["attribution_status"] == "CONFIRMED"
        assert evaluated["assessment"] == "LIKELY_LEGITIMATE", (
            f"RTSA's own write must be attributed LIKELY_LEGITIMATE, never flagged as a raw security alert: {evaluated}"
        )
        print("Scenario 18 (FIM self-action attribution: RTSA's own write never surfaces as a false-positive security alert) PASSED")

        tampered_sha = hashlib.sha256(b"module.exports = { apps: [{ name: 'evil' }] };").hexdigest()
        evaluated_external = det._evaluate_change(
            fx18.config_path(), "configs", identity(fx18.config_path(), sha=actual_sha256),
            identity(fx18.config_path(), sha=tampered_sha),
            recent_command_changes=recent,
        )
        assert evaluated_external is not None, "an externally modified ecosystem.config.js must still be detected"
        assert evaluated_external["change_source"] is None
        assert evaluated_external["attribution_status"] == "SUSPICIOUS"
        assert evaluated_external["assessment"] != "LIKELY_LEGITIMATE"
        print("Scenario 19 (external modification of ecosystem.config.js is still detected normally by FIM) PASSED")
    finally:
        fx18.cleanup()
        try:
            os.remove(ledger_path)
        except OSError:
            pass

    fx20 = EcosystemFixture("rtsa_ec_fe_nopkg", "fenopkg.example")
    try:
        os.makedirs(fx20.project)
        orig = patch_resolver({fx20.domain: fx20.asset()})
        try:
            bot = make_bot()
            preflight = await bot._feaddeco_preflight(fx20.domain, 4026)
        finally:
            restore_resolver(orig)
        assert preflight["ok"] is False and preflight["error_code"] == "PACKAGE_JSON_NOT_FOUND"
        print("Scenario 20 (feaddeco: package.json missing -> fail) PASSED")
    finally:
        fx20.cleanup()

    fx21 = EcosystemFixture("rtsa_ec_fe_nostart", "fenostart.example")
    try:
        fx21.build_frontend(start_script=False)
        orig = patch_resolver({fx21.domain: fx21.asset()})
        try:
            bot = make_bot()
            preflight = await bot._feaddeco_preflight(fx21.domain, 4026)
        finally:
            restore_resolver(orig)
        assert preflight["ok"] is False and preflight["error_code"] == "START_SCRIPT_NOT_FOUND"
        print("Scenario 21 (feaddeco: scripts.start missing -> fail) PASSED")
    finally:
        fx21.cleanup()

    fx22 = EcosystemFixture("rtsa_ec_fe_ok", "feok.example")
    try:
        fx22.build_frontend()
        orig = patch_resolver({fx22.domain: fx22.asset()})
        try:
            bot = make_bot()
            embed = await bot._feaddeco_execute(fx22.domain, 4026, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- FRONTEND ECOSYSTEM CONFIG CREATED"
        with open(fx22.config_path()) as f:
            content = f.read()
        assert ec.validate_existing_ecosystem_config(content) == ec.VALIDATION_VALID
        print("Scenario 22 (feaddeco: valid config created) PASSED")

        assert f'"{os.path.realpath(fx22.project)}"' in content
        print("Scenario 23 (feaddeco: cwd is correct canonical path) PASSED")

        assert "PORT: 4026," in content and 'PORT: "4026"' not in content
        print("Scenario 24 (feaddeco: PORT emitted as integer) PASSED")
    finally:
        fx22.cleanup()
    print("Scenario 25 (feaddeco: PM2 never started -- no pm2/npm/node subprocess invoked anywhere in this module) PASSED")

    fx26 = EcosystemFixture("rtsa_ec_be_noentry", "benoentry.example")
    try:
        fx26.build_backend(entrypoint=False)
        orig = patch_resolver({fx26.domain: fx26.asset()})
        try:
            bot = make_bot()
            preflight = await bot._beaddeco_preflight(fx26.domain, 4041)
        finally:
            restore_resolver(orig)
        assert preflight["ok"] is False and preflight["error_code"] == "BACKEND_ENTRYPOINT_NOT_FOUND"
        print("Scenario 26 (beaddeco: dist/app.js missing -> fail) PASSED")
    finally:
        fx26.cleanup()

    fx27 = EcosystemFixture("rtsa_ec_be_nonode", "benonode.example")
    try:
        fx27.build_backend()
        orig = patch_resolver({fx27.domain: fx27.asset()})
        try:
            bot = make_bot()
            preflight = await bot._beaddeco_preflight(fx27.domain, 4041)
        finally:
            restore_resolver(orig)
        assert preflight["ok"] is False and preflight["error_code"] == "NODE_INTERPRETER_NOT_FOUND"
        print("Scenario 27 (beaddeco: Node interpreter not found -> fail) PASSED")
    finally:
        fx27.cleanup()

    fx28 = EcosystemFixture("rtsa_ec_be_ok", "beok.example")
    try:
        fx28.build_backend()
        fx28.build_node_interpreter()
        orig = patch_resolver({fx28.domain: fx28.asset()})
        try:
            bot = make_bot()
            embed = await bot._beaddeco_execute(fx28.domain, 4041, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- BACKEND ECOSYSTEM CONFIG CREATED", embed.title
        print("Scenario 28 (beaddeco: executable Node interpreter -> success) PASSED")

        with open(fx28.config_path()) as f:
            content = f.read()
        assert '"./dist/app.js"' in content
        print("Scenario 29 (beaddeco: config has correct entrypoint) PASSED")
        assert '"512M"' in content
        print("Scenario 30 (beaddeco: max_memory_restart is 512M) PASSED")
        assert '"fork"' in content
        print("Scenario 31 (beaddeco: exec_mode is fork) PASSED")
        assert "instances: 1," in content
        print("Scenario 32 (beaddeco: instances is 1) PASSED")
    finally:
        fx28.cleanup()

    fx33 = EcosystemFixture("rtsa_ec_wb_noapp", "wbnoapp.example")
    try:
        os.makedirs(fx33.project, exist_ok=True)
        with open(f"{fx33.project}/package.json", "w") as f:
            json.dump({"name": fx33.domain}, f)
        fx33.build_worker()
        orig = patch_resolver({fx33.domain: fx33.asset()})
        try:
            bot = make_bot()
            preflight = await bot._wbeaddeco_preflight(fx33.domain, 4041)
        finally:
            restore_resolver(orig)
        assert preflight["ok"] is False and preflight["error_code"] == "BACKEND_ENTRYPOINT_NOT_FOUND"
        print("Scenario 33 (wbeaddeco: dist/app.js required, missing -> fail) PASSED")
    finally:
        fx33.cleanup()

    fx34 = EcosystemFixture("rtsa_ec_wb_noworker", "wbnoworker.example")
    try:
        fx34.build_backend()
        orig = patch_resolver({fx34.domain: fx34.asset()})
        try:
            bot = make_bot()
            preflight = await bot._wbeaddeco_preflight(fx34.domain, 4041)
        finally:
            restore_resolver(orig)
        assert preflight["ok"] is False and preflight["error_code"] == "WORKER_ENTRYPOINT_NOT_FOUND"
        print("Scenario 34 (wbeaddeco: worker entrypoint required) PASSED")

        embed = bot._ecosystem_build_preflight_error_embed(preflight, ec.CONFIG_TYPE_BACKEND_WORKER)
        assert not os.path.isfile(fx34.config_path()), "missing worker must not produce any config"
        print("Scenario 35 (wbeaddeco: missing worker entrypoint -> no config created at all, not partial) PASSED")
    finally:
        fx34.cleanup()

    fx36 = EcosystemFixture("rtsa_ec_wb_ok", "wbok.example")
    try:
        fx36.build_backend()
        fx36.build_worker()
        fx36.build_node_interpreter()
        orig = patch_resolver({fx36.domain: fx36.asset()})
        try:
            bot = make_bot(cluster_max=8, cluster_reserve=1)
            embed = await bot._wbeaddeco_execute(fx36.domain, 4041, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- BACKEND WORKER ECOSYSTEM CONFIG CREATED", embed.title
        with open(fx36.config_path()) as f:
            content = f.read()
        assert content.count('"cwd"') == 0
        app_entries_count = content.count("interpreter:")
        assert app_entries_count == 2, f"generated config must contain exactly 2 apps: {content}"
        print("Scenario 36 (wbeaddeco: generated config has two apps -- HTTP app and worker) PASSED")

        worker_entry_start = content.index("worker-")
        worker_section = content[worker_entry_start:]
        assert "PORT" not in worker_section, "the worker app must never receive the HTTP PORT env var by default"
        print("Scenario 37 (wbeaddeco: worker does not receive PORT by default) PASSED")
    finally:
        fx36.cleanup()

    fx38 = EcosystemFixture("rtsa_ec_wb_maxcap", "wbmaxcap.example")
    try:
        fx38.build_backend()
        fx38.build_worker()
        fx38.build_node_interpreter()
        orig = patch_resolver({fx38.domain: fx38.asset()})
        try:
            bot = make_bot(cluster_max=2, cluster_reserve=0)
            embed = await bot._wbeaddeco_execute(fx38.domain, 4041, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        field_map = {f.name: f.value for f in embed.fields}
        assert int(field_map["Cluster Instances"]) <= 2, (
            f"cluster instances must never exceed the configured maximum, even with abundant CPU: {field_map}"
        )
        print("Scenario 38 (wbeaddeco: cluster instances never exceed configured maximum) PASSED")
    finally:
        fx38.cleanup()

    assert ec.compute_cluster_instances("auto", 8, 1, logical_cpu=4) == 3
    print("Scenario 39 (wbeaddeco: reserve CPU is applied -- 4 logical CPU, reserve 1 -> 3 instances) PASSED")

    assert ec.compute_cluster_instances("auto", 8, 1, logical_cpu=4) != 8
    print("Scenario 40 (wbeaddeco: a small server is never forced to 8 instances) PASSED")

    fx41 = EcosystemFixture("rtsa_ec_mono_nopkg", "mononopkg.example")
    try:
        os.makedirs(fx41.project)
        orig = patch_resolver({fx41.domain: fx41.asset()})
        try:
            bot = make_bot()
            preflight = await bot._feaddeco_preflight(fx41.domain, 4022)
        finally:
            restore_resolver(orig)
        assert preflight["ok"] is False and preflight["error_code"] == "PACKAGE_JSON_NOT_FOUND"
        print("Scenario 41 (monoaddeco: package.json required) PASSED")
    finally:
        fx41.cleanup()

    fx42 = EcosystemFixture("rtsa_ec_mono_nostart", "mononostart.example")
    try:
        fx42.build_frontend(start_script=False)
        orig = patch_resolver({fx42.domain: fx42.asset()})
        try:
            bot = make_bot()
            preflight = await bot._feaddeco_preflight(fx42.domain, 4022)
        finally:
            restore_resolver(orig)
        assert preflight["ok"] is False and preflight["error_code"] == "START_SCRIPT_NOT_FOUND"
        print("Scenario 42 (monoaddeco: scripts.start required) PASSED")
    finally:
        fx42.cleanup()

    fx43 = EcosystemFixture("rtsa_ec_mono_ok", "monook.example")
    try:
        fx43.build_frontend()
        orig = patch_resolver({fx43.domain: fx43.asset()})
        try:
            bot = make_bot()
            embed = await bot._monoaddeco_execute(fx43.domain, 4022, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- MONOLITH ECOSYSTEM CONFIG CREATED", embed.title
        with open(fx43.config_path()) as f:
            content = f.read()
        assert "start -- --port 4022" in content
        print("Scenario 43 (monoaddeco: args produce 'start -- --port <PORT>') PASSED")
        assert "instances: 1," in content
        print("Scenario 44 (monoaddeco: instances is 1) PASSED")
        assert '"fork"' in content
        print("Scenario 45 (monoaddeco: exec_mode is fork) PASSED")
    finally:
        fx43.cleanup()
    print("Scenario 46 (monoaddeco: PM2 never started automatically -- no subprocess execution in this module) PASSED")

    valid_content = ec.generate_frontend_config("d.com", "/home/x/htdocs/d.com", 4000)
    assert ec.validate_existing_ecosystem_config(valid_content) == ec.VALIDATION_VALID
    print("Scenario 47 (a real RTSA-generated ecosystem config validates as VALID) PASSED")

    trick_content = "const a = 1; module.exports = a; const apps = []; // just words: module.exports apps"
    assert ec.validate_existing_ecosystem_config(trick_content) != ec.VALIDATION_VALID, (
        "a file merely containing the substrings 'module.exports' and 'apps' must never be waved through as VALID"
    )
    print("Scenario 48 (substring-trick file is not auto-classified VALID) PASSED")

    manual_content = "module.exports = { apps: [ { name: 'manual-app' } ] };\n"
    assert ec.validate_existing_ecosystem_config(manual_content) == ec.VALIDATION_UNKNOWN
    print("Scenario 49 (an incomplete manually-written config is classified UNKNOWN, not VALID or INVALID) PASSED")

    fx50 = EcosystemFixture("rtsa_ec_replace_needs_confirm", "replaceconfirm.example")
    try:
        fx50.build_frontend()
        fx50.write_existing_config(manual_content)
        orig = patch_resolver({fx50.domain: fx50.asset()})
        db = FakeDb()
        try:
            bot = make_bot(db)
            embed = await bot._feaddeco_execute(fx50.domain, 4026, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "EXISTING ECOSYSTEM CONFIG DETECTED", (
            "even an UNKNOWN-validation manual config must still require explicit confirmation before replace"
        )
        with open(fx50.config_path()) as f:
            assert f.read() == manual_content
        print("Scenario 50 (replace still requires explicit confirmation even for an UNKNOWN-validation config) PASSED")
    finally:
        fx50.cleanup()


    fxA = EcosystemFixture("rtsa_ec_ep_nodist", "epnodist.example")
    try:
        fxA.write_package_json({"scripts": {"start": "node index.js"}})
        fxA.write_file("index.js")
        fxA.build_node_interpreter()
        orig = patch_resolver({fxA.domain: fxA.asset()})
        try:
            bot = make_bot()
            embed = await bot._beaddeco_execute(fxA.domain, 4050, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- BACKEND ECOSYSTEM CONFIG CREATED", embed.title
        with open(fxA.config_path()) as f:
            content = f.read()
        assert '"./index.js"' in content, content
        assert 'args: "--port 4050"' in content, (
            f"args must always carry --port even though package.json's start script "
            f"('node index.js') never mentions --port itself -- the app may need it as a CLI "
            f"arg regardless of what package.json says: {content}"
        )
        print("Scenario 51 (CASE A: no dist/ at all -- not an error, start script resolves to root index.js) PASSED")
    finally:
        fxA.cleanup()

    fxB = EcosystemFixture("rtsa_ec_ep_distinvalid", "epdistinvalid.example")
    try:
        fxB.write_package_json({"scripts": {"start": "node server.js"}})
        os.makedirs(f"{fxB.project}/dist", exist_ok=True)
        with open(f"{fxB.project}/dist/readme.txt", "w") as f:
            f.write("not an entrypoint\n")
        fxB.write_file("server.js")
        fxB.build_node_interpreter()
        orig = patch_resolver({fxB.domain: fxB.asset()})
        try:
            bot = make_bot()
            embed = await bot._beaddeco_execute(fxB.domain, 4051, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- BACKEND ECOSYSTEM CONFIG CREATED", embed.title
        with open(fxB.config_path()) as f:
            content = f.read()
        assert '"./server.js"' in content, content
        print("Scenario 52 (CASE B: dist/ exists but has no valid entrypoint -- falls back to package.json start) PASSED")
    finally:
        fxB.cleanup()

    fxC = EcosystemFixture("rtsa_ec_ep_portarg", "epportarg.example")
    try:
        fxC.write_package_json({"scripts": {"start": "node dist/server.js --port 9999"}})
        fxC.write_file("dist/server.js")
        fxC.build_node_interpreter()
        orig = patch_resolver({fxC.domain: fxC.asset()})
        try:
            bot = make_bot()
            embed = await bot._beaddeco_execute(fxC.domain, 4052, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- BACKEND ECOSYSTEM CONFIG CREATED", embed.title
        with open(fxC.config_path()) as f:
            content = f.read()
        assert 'args: "--port 4052"' in content, (
            f"operator-supplied port (4052) must be used in the --port arg, never the literal from "
            f"package.json (9999): {content}"
        )
        assert "PORT: 4052," in content, "existing env-var PORT delivery must be preserved alongside --port"
        print("Scenario 53 (CASE C: start script's --port pattern preserved, value taken from operator port) PASSED")
    finally:
        fxC.cleanup()

    fxD = EcosystemFixture("rtsa_ec_ep_mainfield", "epmainfield.example")
    try:
        fxD.write_package_json({"main": "build/main.js"})
        fxD.write_file("build/main.js")
        fxD.build_node_interpreter()
        orig = patch_resolver({fxD.domain: fxD.asset()})
        try:
            bot = make_bot()
            embed = await bot._beaddeco_execute(fxD.domain, 4053, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- BACKEND ECOSYSTEM CONFIG CREATED", embed.title
        with open(fxD.config_path()) as f:
            content = f.read()
        assert '"./build/main.js"' in content, content
        print("Scenario 54 (CASE D: no start script -- package.json 'main' field used as entrypoint) PASSED")
    finally:
        fxD.cleanup()

    fxE = EcosystemFixture("rtsa_ec_ep_nowhere", "epnowhere.example")
    try:
        fxE.write_package_json({"name": fxE.domain})
        orig = patch_resolver({fxE.domain: fxE.asset()})
        try:
            bot = make_bot()
            preflight = await bot._beaddeco_preflight(fxE.domain, 4054)
        finally:
            restore_resolver(orig)
        assert preflight["ok"] is False and preflight["error_code"] == "BACKEND_ENTRYPOINT_NOT_FOUND", preflight
        assert not os.path.isfile(fxE.config_path())
        print("Scenario 55 (CASE E: no start/main/dist/root candidate anywhere -- safe failure, no config written) PASSED")
    finally:
        fxE.cleanup()

    fxF = EcosystemFixture("rtsa_ec_ep_escape", "epescape.example")
    try:
        fxF.write_package_json({"scripts": {"start": "node ../../etc/passwd"}})
        orig = patch_resolver({fxF.domain: fxF.asset()})
        try:
            bot = make_bot()
            preflight = await bot._beaddeco_preflight(fxF.domain, 4055)
        finally:
            restore_resolver(orig)
        assert preflight["ok"] is False and preflight["error_code"] == "ENTRYPOINT_PATH_ESCAPE", preflight
        assert not os.path.isfile(fxF.config_path())
        print("Scenario 56 (CASE F: package.json start script escaping project root is rejected outright) PASSED")
    finally:
        fxF.cleanup()

    fxF2 = EcosystemFixture("rtsa_ec_ep_escape_main", "epescapemain.example")
    try:
        fxF2.write_package_json({"main": "../outside.js"})
        orig = patch_resolver({fxF2.domain: fxF2.asset()})
        try:
            bot = make_bot()
            preflight = await bot._beaddeco_preflight(fxF2.domain, 4056)
        finally:
            restore_resolver(orig)
        assert preflight["ok"] is False and preflight["error_code"] == "ENTRYPOINT_PATH_ESCAPE", preflight
        print("Scenario 57 (CASE F: package.json 'main' field escaping project root is rejected outright) PASSED")
    finally:
        fxF2.cleanup()

    fxG = EcosystemFixture("rtsa_ec_ep_backcompat", "epbackcompat.example")
    try:
        fxG.write_package_json({"scripts": {"start": "node dist/app.js"}})
        fxG.write_file("dist/app.js")
        fxG.build_node_interpreter()
        orig = patch_resolver({fxG.domain: fxG.asset()})
        try:
            bot = make_bot()
            embed = await bot._beaddeco_execute(fxG.domain, 4057, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        with open(fxG.config_path()) as f:
            content = f.read()
        assert '"./dist/app.js"' in content, (
            f"a project whose package.json start script itself points at dist/app.js must still "
            f"resolve to the same ./dist/app.js RTSA has always generated: {content}"
        )
        print("Scenario 58 (CASE G: backward compatibility -- dist/app.js via start script resolves unchanged) PASSED")
    finally:
        fxG.cleanup()

    fxH = EcosystemFixture("rtsa_ec_ep_workerroot", "epworkerroot.example")
    try:
        fxH.write_package_json({"name": fxH.domain})
        fxH.write_file("dist/app.js")
        fxH.write_file("workers/index.js")
        fxH.build_node_interpreter()
        orig = patch_resolver({fxH.domain: fxH.asset()})
        try:
            bot = make_bot()
            embed = await bot._wbeaddeco_execute(fxH.domain, 4058, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- BACKEND WORKER ECOSYSTEM CONFIG CREATED", embed.title
        with open(fxH.config_path()) as f:
            content = f.read()
        assert '"./workers/index.js"' in content, (
            f"with no dist/ worker candidate present, the root-level workers/index.js fallback "
            f"must be used: {content}"
        )
        print("Scenario 59 (CASE H: worker entrypoint falls back to root workers/index.js when dist/ has none) PASSED")
    finally:
        fxH.cleanup()

    fxAstro = EcosystemFixture("rtsa_ec_astro_ok", "astrook.example")
    try:
        fxAstro.write_package_json({"name": fxAstro.domain})
        fxAstro.write_file("dist/server/entry.mjs")
        fxAstro.build_node_interpreter()
        orig = patch_resolver({fxAstro.domain: fxAstro.asset()})
        try:
            bot = make_bot()
            embed = await bot._astroeco_execute(fxAstro.domain, 4059, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- ASTRO ECOSYSTEM CONFIG CREATED", embed.title
        with open(fxAstro.config_path()) as f:
            content = f.read()
        assert '"./dist/server/entry.mjs"' in content, content
        field_map = {f.name: f.value for f in embed.fields}
        assert field_map["Config Type"] == ec.CONFIG_TYPE_ASTRO
        print("Scenario 60 (/astroeco: Astro Node-adapter standalone dist/server/entry.mjs convention resolves) PASSED")
    finally:
        fxAstro.cleanup()

    fxRace = EcosystemFixture("rtsa_ec_ep_racecheck", "epracecheck.example")
    try:
        fxRace.write_package_json({"scripts": {"start": "node server.js"}})
        fxRace.write_file("server.js")
        fxRace.build_node_interpreter()
        orig = patch_resolver({fxRace.domain: fxRace.asset()})
        try:
            bot = make_bot()
            preflight = await bot._beaddeco_preflight(fxRace.domain, 4060)
            assert preflight["ok"] is True
            script = str(preflight["entrypoint_script"])
            interpreter = str(preflight["node_interpreter"])
            project_path = str(preflight["project_path"])
            content = ec.generate_backend_config(fxRace.domain, project_path, interpreter, 4060, script=script)
            os.remove(f"{fxRace.project}/server.js")
            commit = await bot._ecosystem_commit_write(
                domain=fxRace.domain, project_path=project_path, config_path=str(preflight["config_path"]),
                content=content, source=BEADDECO, requested_by="tester", replace=False,
                command_label="/beaddeco race-test", linux_user=str(preflight["linux_user"]), script=script,
            )
        finally:
            restore_resolver(orig)
        assert commit["ok"] is False and commit["error_code"] == "CONFIG_VALIDATION_FAILED", commit
        assert not os.path.isfile(fxRace.config_path()), (
            "a script that vanished between preflight and write must never produce a partial/broken config"
        )
        print("Scenario 61 (PM2 config validation: entrypoint removed after preflight -> write blocked, no partial config) PASSED")
    finally:
        fxRace.cleanup()

    ok, reason = ec.validate_generated_config("/nonexistent-project-path-xyz", "./dist/app.js", "module.exports = {};")
    assert ok is False and reason is not None
    print("Scenario 61b (unit: validate_generated_config rejects a cwd that no longer exists) PASSED")

    assert ec._parse_node_start_script("node dist/server.js --port 3025") == ("dist/server.js", True)
    assert ec._parse_node_start_script("node ./index.js") == ("./index.js", False)
    assert ec._parse_node_start_script("next start") == (None, False)
    print("Scenario 62 (unit: _parse_node_start_script extracts file + --port flag from common start patterns) PASSED")


    fxMpp = EcosystemFixture("newus-backend-mpp", "backend-mpp.newus.id")
    try:
        fxMpp.write_package_json({"name": "backend-mpp", "main": "index.js", "scripts": {"start": "node index.js"}})
        fxMpp.write_file("index.js")
        fxMpp.build_node_interpreter()
        orig = patch_resolver({fxMpp.domain: fxMpp.asset()})
        try:
            bot = make_bot()
            embed = await bot._beaddeco_execute(fxMpp.domain, 3004, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- BACKEND ECOSYSTEM CONFIG CREATED", embed.title
        with open(fxMpp.config_path()) as f:
            content = f.read()
        assert f'name: "{fxMpp.domain}"' in content, (
            f"process name must be exactly the domain, never a filename-derived name like "
            f"'ecosystemconfig': {content}"
        )
        assert '"./index.js"' in content, content
        assert f'"{os.path.realpath(fxMpp.project)}"' in content
        assert 'args: "--port 3004"' in content, (
            f"must preserve the exact semantic of the proven-working manual command "
            f"'pm2 start index.js --name backend-mpp.newus.id -- --port 3004': {content}"
        )
        assert "PORT: 3004," in content
        assert content.count("name:") == 1, (
            f"exactly one app must be declared -- no accidental second entry "
            f"(e.g. a stray 'ecosystemconfig' app) can come from this generator: {content}"
        )
        field_map = {f.name: f.value for f in embed.fields}
        assert field_map["PM2 Args"] == "--port 3004"
        assert field_map["Entrypoint"] == "./index.js"
        print(
            "Scenario 63 (/beaddeco backend-mpp.newus.id exact production shape: script=./index.js, "
            "args=--port 3004, name=domain, single app -- matches proven-working manual pm2 command) PASSED"
        )
    finally:
        fxMpp.cleanup()

    fxMpp2 = EcosystemFixture("newus-backend-mpp2", "backend-mpp2.newus.id")
    try:
        fxMpp2.write_package_json({"name": "backend-mpp2"})
        fxMpp2.write_file("dist/app.js")
        fxMpp2.build_node_interpreter()
        orig = patch_resolver({fxMpp2.domain: fxMpp2.asset()})
        try:
            bot = make_bot()
            embed = await bot._beaddeco_execute(fxMpp2.domain, 3005, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- BACKEND ECOSYSTEM CONFIG CREATED", embed.title
        with open(fxMpp2.config_path()) as f:
            content = f.read()
        assert 'args: "--port 3005"' in content, (
            f"args must be preserved even when the entrypoint came from the dist candidate "
            f"tier rather than package.json's start script: {content}"
        )
        print("Scenario 64 (args=--port preserved regardless of which entrypoint-priority tier resolved the script) PASSED")
    finally:
        fxMpp2.cleanup()

    fxMppW = EcosystemFixture("newus-backend-mpp-worker", "backend-mpp-worker.newus.id")
    try:
        fxMppW.write_package_json({"name": "backend-mpp-worker"})
        fxMppW.write_file("index.js")
        fxMppW.write_file("workers/index.js")
        fxMppW.build_node_interpreter()
        orig = patch_resolver({fxMppW.domain: fxMppW.asset()})
        try:
            bot = make_bot()
            embed = await bot._wbeaddeco_execute(fxMppW.domain, 3006, requested_by="tester", replace=False)
        finally:
            restore_resolver(orig)
        assert embed.title == "RTSA Action -- BACKEND WORKER ECOSYSTEM CONFIG CREATED", embed.title
        with open(fxMppW.config_path()) as f:
            content = f.read()
        assert content.count('args: "--port 3006"') == 1, (
            f"the HTTP app must receive --port args exactly once; the worker app must never "
            f"receive it: {content}"
        )
        assert content.count("name:") == 2, "wbeaddeco must always declare exactly two apps"
        print("Scenario 65 (/wbeaddeco: HTTP app gets --port args, worker app does not, exactly two apps) PASSED")
    finally:
        fxMppW.cleanup()

    print("\nALL ECOSYSTEM CONFIG COMMAND TESTS PASSED")


_install_fake_pwd_grp()
try:
    asyncio.run(asyncio.wait_for(main(), timeout=180))
finally:
    _restore_real_pwd_grp()
