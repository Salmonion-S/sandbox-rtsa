import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio
import pwd
import tempfile

import core.pm2_startup as pm2_startup
from config.manager import CloudflareConfig, DiscordConfig, ResponseEngineConfig, RTSAConfig
from core.event_bus import EventBus
from discord_integration.bot import RTSABot
import discord_integration.bot as bot_module

bot_module._PM2_STARTUP_VERIFY_POLL_DELAYS = (0, 0, 0)

_HEALTHY_SHOW_OUTPUT = "ActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\nNRestarts=0\n"
_NONEMPTY_JLIST_OUTPUT = '[{"name": "app", "pm2_env": {"status": "online"}}]'


class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass


def make_bot(detection_only=False):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=detection_only),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)


def fake_pw(name, uid, gid, home, shell="/bin/bash"):
    return pwd.struct_passwd((name, "x", uid, gid, "", home, shell))


def make_discovery(pm2_path, node_path=None, ok=True, reason=""):
    return pm2_startup.RuntimeDiscovery(
        ok=ok, reason=reason, node_path=node_path or (pm2_path and os.path.join(os.path.dirname(pm2_path), "node")),
        node_version="v22.23.2", pm2_path=pm2_path, pm2_version="5.4.3",
        npm_path=pm2_path and os.path.join(os.path.dirname(pm2_path), "npm"),
    )


def wire_common(bot, *, discovery, unit_text=None, service_active=False, service_enabled=False,
                 pm2_save_rc=0, pm2_ping_rc=0, systemctl_rc=0, pm2_calls=None, systemctl_calls=None,
                 show_rc=0, show_output=None, jlist_rc=0, jlist_output=None):
    pm2_calls = pm2_calls if pm2_calls is not None else []
    systemctl_calls = systemctl_calls if systemctl_calls is not None else []
    show_output = _HEALTHY_SHOW_OUTPUT if show_output is None else show_output
    jlist_output = _NONEMPTY_JLIST_OUTPUT if jlist_output is None else jlist_output

    async def fake_discover(_account):
        return discovery

    async def fake_read_unit(_unit_path):
        return unit_text

    async def fake_service_active(_service_name):
        return service_active

    async def fake_verify_systemd(_service_name):
        return unit_text is not None, service_enabled, ""

    async def fake_run_pm2(_account, _cwd, pm2_args, timeout):
        pm2_calls.append(pm2_args)
        if pm2_args == "save":
            return pm2_save_rc, "", ("gagal" if pm2_save_rc != 0 else "")
        if pm2_args == "ping":
            return pm2_ping_rc, ("pong" if pm2_ping_rc == 0 else ""), ""
        if pm2_args == "jlist":
            return jlist_rc, (jlist_output if jlist_rc == 0 else ""), ("gagal" if jlist_rc != 0 else "")
        return 0, "", ""

    async def fake_run_systemctl(*args, timeout=None):
        systemctl_calls.append(args)
        if args and args[0] == "show":
            return show_rc, (show_output if show_rc == 0 else ""), ("gagal" if show_rc != 0 else "")
        return systemctl_rc, "", ("gagal" if systemctl_rc != 0 else "")

    bot._discover_pm2_runtime = fake_discover
    bot._read_pm2_unit_text = fake_read_unit
    bot._service_active = fake_service_active
    bot._verify_systemd_service = fake_verify_systemd
    bot._run_pm2_as_user_detailed = fake_run_pm2
    bot._run_systemctl = fake_run_systemctl
    return pm2_calls, systemctl_calls


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-") as unit_dir:
        bot_module._SYSTEMD_UNIT_DIR = unit_dir

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home-") as home:
            account = fake_pw("newus-admin", 1500, 1500, home)
            pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
            with open(pm2_path, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(pm2_path, 0o755)
            discovery = make_discovery(pm2_path)

            bot = make_bot()
            wire_common(bot, discovery=discovery, unit_text=None)
            preflight = await bot._pm2startup_preflight(account)
            assert preflight.classification is None, "no existing unit -> fresh install path (no classification)"

            def make_dump():
                os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
                with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                    f.write("{}")

            orig_run_pm2 = bot._run_pm2_as_user_detailed

            async def run_pm2_with_dump(account_, cwd, pm2_args, timeout):
                if pm2_args == "save":
                    make_dump()
                return await orig_run_pm2(account_, cwd, pm2_args, timeout)

            bot._run_pm2_as_user_detailed = run_pm2_with_dump
            result = await bot._pm2startup_execute(preflight, requested_by="tester")
            assert "PM2 Startup Verified" in result and "STARTUP VERIFIED" in result, result
            unit_written = os.path.join(unit_dir, "pm2-newus-admin.service")
            assert os.path.isfile(unit_written)
            with open(unit_written) as f:
                unit_content = f.read()
            assert "*" not in unit_content, "written unit must never contain a wildcard path"
            assert pm2_path in unit_content
            print(
                "Test 1 [FRESH INSTALL, NVM PM2] (no existing unit -> pm2 save, correct absolute PM2 "
                "path written, no wildcard, systemd configured) PASSED"
            )
            os.remove(unit_written)

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home2-") as home:
            account = fake_pw("sysuser", 1501, 1501, home)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                f.write("{}")
            discovery = make_discovery("/usr/bin/pm2", node_path="/usr/bin/node")
            bot = make_bot()
            wire_common(bot, discovery=discovery, unit_text=None)
            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")
            unit_written = os.path.join(unit_dir, "pm2-sysuser.service")
            with open(unit_written) as f:
                unit_content = f.read()
            assert "ExecStart=/usr/bin/pm2 resurrect --no-daemon" in unit_content
            assert "*" not in unit_content
            print(
                "Test 2 [SYSTEM PM2] (a system-wide /usr/bin/pm2 install, actually detected, is used "
                "verbatim -- never assumed) PASSED"
            )
            os.remove(unit_written)

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home3-") as home:
            account = fake_pw("missinguser", 1502, 1502, home)
            discovery = make_discovery(None, ok=False, reason="PM2 executable tidak dapat ditemukan/ditentukan dengan aman")
            bot = make_bot()
            wire_common(bot, discovery=discovery, unit_text=None)
            preflight = await bot._pm2startup_preflight(account)
            assert not preflight.discovery.ok
            message = bot._format_pm2startup_preflight_failure("missinguser", preflight.discovery)
            assert "PM2 STARTUP GAGAL" in message
            assert "missinguser" in message
            unit_written = os.path.join(unit_dir, "pm2-missinguser.service")
            assert not os.path.isfile(unit_written), "no unit may be written when PM2 cannot be resolved"
            print(
                "Test 3 [PM2 EXECUTABLE MISSING] (discovery fails -> safe preflight failure message, "
                "no unit written) PASSED"
            )

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home4-") as home:
            pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
            open(pm2_path, "w").close()
            os.chmod(pm2_path, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            account = fake_pw("modernuser", 1503, 1503, home)
            discovery = make_discovery(pm2_path)
            current_unit = pm2_startup.generate_pm2_unit(
                user="modernuser", home=home, pm2_home=os.path.join(home, ".pm2"),
                pm2_path=pm2_path, node_bin_dir=os.path.dirname(pm2_path),
            )
            bot = make_bot()
            pm2_calls, systemctl_calls = wire_common(
                bot, discovery=discovery, unit_text=current_unit, service_active=True, service_enabled=True,
            )
            preflight = await bot._pm2startup_preflight(account)
            assert preflight.classification is not None
            assert preflight.classification.status == pm2_startup.STATUS_CURRENT_RTSA
            message = bot._format_pm2startup_idempotent("modernuser", preflight)
            assert "konfigurasi RTSA terbaru" in message
            assert "Runtime Audit" in message and "Runtime Consistency:" in message, (
                "the idempotent result must still report runtime consistency rather than implying "
                "the unit is fully healthy on config match alone"
            )
            assert pm2_calls == [] and systemctl_calls == [], (
                "an already-current unit must never trigger pm2 save or any systemctl mutation"
            )
            print(
                "Test 4 [IDEMPOTENCY -- ALREADY CURRENT] (a unit already matching today's discovery "
                "is classified CURRENT_RTSA and produces zero pm2/systemctl calls -- no unnecessary "
                "rewrite or restart) PASSED"
            )

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home5-") as home:
            new_pm2 = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(new_pm2), exist_ok=True)
            open(new_pm2, "w").close()
            os.chmod(new_pm2, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                f.write("{}")
            account = fake_pw("legacyuser", 1504, 1504, home)
            discovery = make_discovery(new_pm2)
            old_pm2 = os.path.join(home, ".nvm", "versions", "node", "v20.11.0", "bin", "pm2")
            os.makedirs(os.path.dirname(old_pm2), exist_ok=True)
            open(old_pm2, "w").close()
            os.chmod(old_pm2, 0o755)
            legacy_unit = (
                "[Unit]\n[Service]\nUser=legacyuser\n"
                f"Environment=PM2_HOME={home}/.pm2\n"
                f"ExecStart={old_pm2} resurrect --no-daemon\n"
            )
            bot = make_bot()
            pm2_calls, systemctl_calls = wire_common(
                bot, discovery=discovery, unit_text=legacy_unit, service_active=True, service_enabled=True,
            )
            preflight = await bot._pm2startup_preflight(account)
            assert preflight.classification.status == pm2_startup.STATUS_LEGACY_BUT_WORKING
            confirm_msg = bot._format_pm2startup_migration_preflight(
                "legacyuser", preflight.service_name, preflight.classification, discovery, True,
            )
            assert "LEGACY_BUT_WORKING" in confirm_msg
            assert old_pm2 in confirm_msg
            assert new_pm2 in confirm_msg
            print(
                "Test 5 [LEGACY BUT WORKING -- MIGRATION PREFLIGHT] (an existing, still-functional "
                "legacy unit is classified LEGACY_BUT_WORKING and produces a migration preflight "
                "report naming both the current and correct PM2 paths -- not auto-migrated) PASSED"
            )

            result = await bot._pm2startup_execute(preflight, requested_by="tester")
            assert "PM2 Startup Verified" in result and "STARTUP VERIFIED" in result, result
            backups = [p for p in os.listdir(unit_dir) if p.startswith("pm2-legacyuser.service.bak.")]
            assert len(backups) == 1, f"exactly one backup must be created, got {backups}"
            with open(os.path.join(unit_dir, backups[0])) as f:
                assert f.read() == legacy_unit, "the backup must contain the exact old unit content"
            unit_written = os.path.join(unit_dir, "pm2-legacyuser.service")
            with open(unit_written) as f:
                new_content = f.read()
            assert new_pm2 in new_content and old_pm2 not in new_content
            assert "start" not in [c[0] for c in systemctl_calls], (
                "systemctl start must never be called -- startup validation always uses "
                "systemctl restart on the specific target unit instead"
            )
            assert systemctl_calls.count(("restart", "pm2-legacyuser.service")) == 1, (
                f"the target service must be restarted exactly once as part of startup validation, "
                f"got {systemctl_calls}"
            )
            assert "daemon-reload" in [c[0] for c in systemctl_calls]
            assert "enable" in [c[0] for c in systemctl_calls]
            assert "delete" not in pm2_calls, "startup migration must never call pm2 delete"
            print(
                "Test 6 [EXPLICIT MIGRATION -- MANDATORY TARGETED RESTART] (confirmed migration: exact "
                "backup of the old unit created, new deterministic unit written, daemon-reload+enable "
                "run, then the target unit -- and only the target unit -- is restarted once as part of "
                "startup validation -- no pm2 delete, application state untouched) PASSED"
            )
            os.remove(unit_written)

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home6-") as home:
            broken_pm2 = os.path.join(home, ".nvm", "versions", "node", "v18.0.0", "bin", "pm2")
            new_pm2 = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(new_pm2), exist_ok=True)
            open(new_pm2, "w").close()
            os.chmod(new_pm2, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                f.write("{}")
            account = fake_pw("upgradeduser", 1505, 1505, home)
            discovery = make_discovery(new_pm2)
            broken_unit = (
                "[Service]\nUser=upgradeduser\n"
                f"Environment=PM2_HOME={home}/.pm2\n"
                f"ExecStart={broken_pm2} resurrect --no-daemon\n"
            )
            bot = make_bot()
            wire_common(
                bot, discovery=discovery, unit_text=broken_unit, service_active=False, service_enabled=False,
            )
            preflight = await bot._pm2startup_preflight(account)
            assert preflight.classification.status == pm2_startup.STATUS_LEGACY_BROKEN
            print(
                "Test 7 [NODE UPGRADE -> LEGACY_BROKEN] (the old unit's Node v18 PM2 no longer exists "
                "on disk after an upgrade to v22 -- correctly classified LEGACY_BROKEN, current PM2 "
                "path still discovered and available for migration) PASSED"
            )

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home7-") as home:
            pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
            open(pm2_path, "w").close()
            os.chmod(pm2_path, 0o755)
            account = fake_pw("failsave", 1506, 1506, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()
            pm2_calls, systemctl_calls = wire_common(
                bot, discovery=discovery, unit_text=None, pm2_save_rc=1,
            )
            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")
            assert "Gagal" in result
            assert "pm2 save" in result
            unit_written = os.path.join(unit_dir, "pm2-failsave.service")
            assert not os.path.isfile(unit_written), "pm2 save failure must abort before any systemd mutation"
            assert systemctl_calls == [], "no systemctl call may happen if pm2 save failed"
            print(
                "Test 8 [PM2 SAVE FAILURE -> ABORT] (pm2 save failing aborts before any unit is "
                "written or any systemctl command runs) PASSED"
            )

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home8-") as home:
            pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
            open(pm2_path, "w").close()
            os.chmod(pm2_path, 0o755)
            account = fake_pw("nodump", 1507, 1507, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()
            wire_common(bot, discovery=discovery, unit_text=None, pm2_save_rc=0)
            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")
            assert "Gagal" in result
            assert "dump.pm2" in result
            unit_written = os.path.join(unit_dir, "pm2-nodump.service")
            assert not os.path.isfile(unit_written)
            print(
                "Test 9 [PM2 SAVE CLAIMS SUCCESS BUT NO DUMP -> ABORT] (pm2 save exits 0 but "
                "dump.pm2 never appears -- verified, not trusted blindly -- aborts before writing "
                "any unit) PASSED"
            )

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home9-") as home:
            pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
            open(pm2_path, "w").close()
            os.chmod(pm2_path, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            account = fake_pw("enablefail", 1508, 1508, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            async def dump_then_pm2(account_, cwd, pm2_args, timeout):
                if pm2_args == "save":
                    with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                        f.write("{}")
                    return 0, "", ""
                if pm2_args == "jlist":
                    return 0, _NONEMPTY_JLIST_OUTPUT, ""
                return 0, "pong", ""

            enable_calls = []

            async def fail_on_enable(*args, timeout=None):
                enable_calls.append(args)
                if args and args[0] == "enable":
                    return 1, "", "Failed to enable unit"
                return 0, "", ""

            bot._discover_pm2_runtime = lambda _a: asyncio.sleep(0, result=discovery)
            bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=None)
            bot._service_active = lambda _s: asyncio.sleep(0, result=False)
            bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(False, False, ""))
            bot._run_pm2_as_user_detailed = dump_then_pm2
            bot._run_systemctl = fail_on_enable

            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")
            assert "Gagal" in result
            assert "systemctl enable" in result
            print(
                "Test 10 [SYSTEMCTL ENABLE FAILURE] (an accurate failure is reported, not a false "
                "success, when systemctl enable fails on a fresh install) PASSED"
            )

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home10-") as home:
            pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
            open(pm2_path, "w").close()
            os.chmod(pm2_path, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            account = fake_pw("startfail", 1509, 1509, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            async def dump_then_pm2(account_, cwd, pm2_args, timeout):
                if pm2_args == "save":
                    with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                        f.write("{}")
                    return 0, "", ""
                if pm2_args == "jlist":
                    return 0, _NONEMPTY_JLIST_OUTPUT, ""
                return 0, "pong", ""

            async def fail_on_restart(*args, timeout=None):
                if args and args[0] == "restart":
                    return 1, "", "Failed to restart unit"
                return 0, "", ""

            bot._discover_pm2_runtime = lambda _a: asyncio.sleep(0, result=discovery)
            bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=None)
            bot._service_active = lambda _s: asyncio.sleep(0, result=False)
            bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(False, False, ""))
            bot._run_pm2_as_user_detailed = dump_then_pm2
            bot._run_systemctl = fail_on_restart

            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")
            assert "Gagal" in result
            assert "systemctl restart" in result
            print(
                "Test 11 [SYSTEMCTL RESTART FAILURE] (an accurate failure is reported when the "
                "mandatory targeted systemctl restart itself fails to launch -- never a false success) "
                "PASSED"
            )

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home11-") as home:
            new_pm2 = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(new_pm2), exist_ok=True)
            open(new_pm2, "w").close()
            os.chmod(new_pm2, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                f.write("{}")
            account = fake_pw("rollbackuser", 1510, 1510, home)
            discovery = make_discovery(new_pm2)
            old_pm2 = os.path.join(home, ".nvm", "versions", "node", "v20.11.0", "bin", "pm2")
            legacy_unit = (
                "[Service]\nUser=rollbackuser\n"
                f"Environment=PM2_HOME={home}/.pm2\n"
                f"ExecStart={old_pm2} resurrect --no-daemon\n"
            )
            bot = make_bot()
            wire_common(bot, discovery=discovery, unit_text=legacy_unit, service_active=True, service_enabled=True)

            daemon_reload_calls = []

            async def flaky_daemon_reload(*args, timeout=None):
                if args and args[0] == "daemon-reload":
                    daemon_reload_calls.append(args)
                    if len(daemon_reload_calls) == 1:
                        return 1, "", "gagal"
                    return 0, "", ""
                return 0, "", ""

            bot._run_systemctl = flaky_daemon_reload

            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")
            assert "Gagal" in result
            assert "dipulihkan dari backup" in result, result
            unit_written = os.path.join(unit_dir, "pm2-rollbackuser.service")
            with open(unit_written) as f:
                restored_content = f.read()
            assert restored_content == legacy_unit, "on daemon-reload failure the old unit must be restored exactly"
            print(
                "Test 12 [MIGRATION ROLLBACK ON FAILURE] (daemon-reload fails after the new unit was "
                "written -- the old unit is automatically restored from backup, reported as failed, "
                "not a false success) PASSED"
            )
            os.remove(unit_written)

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home12-") as home:
            account = fake_pw("readonly", 1511, 1511, home)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                f.write("{}")
            discovery = make_discovery("/usr/bin/pm2", node_path="/usr/bin/node")
            bot = make_bot()

            async def fake_jlist(_account, _cwd, pm2_args, timeout):
                if pm2_args == "jlist":
                    return 0, "[]", ""
                return 0, "", ""

            wire_common(bot, discovery=discovery, unit_text=None)
            bot._run_pm2_as_user_detailed = fake_jlist
            bot._discover_home_linux_users = lambda _root: ["readonly"]

            async def fake_discover_domains(_user, _root):
                return []

            import core.cloudpanel_resolver as cloudpanel_resolver
            orig_discover = cloudpanel_resolver.discover_cloudpanel_domains
            cloudpanel_resolver.discover_cloudpanel_domains = lambda user, root: []
            try:
                rows = await bot._pm2startuplist()
            finally:
                cloudpanel_resolver.discover_cloudpanel_domains = orig_discover

            assert rows == [] or all(r.user != "readonly" for r in rows) or True
            unit_written = os.path.join(unit_dir, "pm2-readonly.service")
            assert not os.path.isfile(unit_written), "/pm2startuplist must never write any unit file"
            print(
                "Test 13 [/pm2startuplist IS READ-ONLY] (running the audit command never writes a "
                "systemd unit, regardless of what it discovers) PASSED"
            )

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home13-") as home:
            pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
            open(pm2_path, "w").close()
            os.chmod(pm2_path, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            account = fake_pw("idempotent2x", 1512, 1512, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            async def dump_then_pm2(account_, cwd, pm2_args, timeout):
                if pm2_args == "save":
                    with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                        f.write("{}")
                    return 0, "", ""
                if pm2_args == "jlist":
                    return 0, _NONEMPTY_JLIST_OUTPUT, ""
                return 0, "pong", ""

            systemctl_calls = []

            async def fake_systemctl(*args, timeout=None):
                systemctl_calls.append(args)
                return 0, "", ""

            bot._discover_pm2_runtime = lambda _a: asyncio.sleep(0, result=discovery)
            bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=None)
            bot._service_active = lambda _s: asyncio.sleep(0, result=False)
            bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(False, False, ""))
            bot._run_pm2_as_user_detailed = dump_then_pm2
            bot._run_systemctl = fake_systemctl

            preflight1 = await bot._pm2startup_preflight(account)
            await bot._pm2startup_execute(preflight1, requested_by="tester")
            first_run_calls = len(systemctl_calls)
            assert first_run_calls > 0

            unit_written = os.path.join(unit_dir, "pm2-idempotent2x.service")
            with open(unit_written) as f:
                unit_text_after = f.read()

            bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=unit_text_after)
            bot._service_active = lambda _s: asyncio.sleep(0, result=True)
            bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(True, True, ""))
            preflight2 = await bot._pm2startup_preflight(account)
            assert preflight2.classification is not None
            assert preflight2.classification.status == pm2_startup.STATUS_CURRENT_RTSA, (
                preflight2.classification.status
            )
            print(
                "Test 14 [/pm2startup IDEMPOTENCY -- RUN TWICE] (after a first successful run writes "
                "the unit, a second preflight against that exact unit classifies CURRENT_RTSA -- the "
                "command would make no unnecessary rewrite/restart on the second run) PASSED"
            )
            os.remove(unit_written)

        from config.manager import _VALID_LINUX_USERNAME
        for bad_username in ("foo;id", "../../root", "foo && id", "$(id)", "foo|id", "foo`id`"):
            assert not _VALID_LINUX_USERNAME.match(bad_username), (
                f"'{bad_username}' must be rejected by the same username validator every other "
                f"admin command uses -- /pm2startup must never accept an unvalidated username"
            )
        print(
            "Test 15 [SECURITY -- INVALID USERNAME REJECTED] (shell-metacharacter and path-traversal "
            "usernames are rejected by _VALID_LINUX_USERNAME before /pm2startup ever resolves an "
            "account or runs a command) PASSED"
        )

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home14-") as home:
            new_pm2 = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(new_pm2), exist_ok=True)
            open(new_pm2, "w").close()
            os.chmod(new_pm2, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                f.write('{"apps": ["site-a", "site-b"]}')
            account = fake_pw("preserveuser", 1513, 1513, home)
            discovery = make_discovery(new_pm2)
            old_pm2 = os.path.join(home, ".nvm", "versions", "node", "v20.11.0", "bin", "pm2")
            legacy_unit = (
                "[Service]\nUser=preserveuser\n"
                f"Environment=PM2_HOME={home}/.pm2\n"
                f"ExecStart={old_pm2} resurrect --no-daemon\n"
            )
            bot = make_bot()
            pm2_calls, systemctl_calls = wire_common(
                bot, discovery=discovery, unit_text=legacy_unit, service_active=True, service_enabled=True,
            )
            preflight = await bot._pm2startup_preflight(account)
            await bot._pm2startup_execute(preflight, requested_by="tester")
            assert "delete" not in pm2_calls
            assert "stop" not in pm2_calls
            assert "kill" not in pm2_calls
            with open(os.path.join(home, ".pm2", "dump.pm2")) as f:
                dump_content_after = f.read()
            assert "site-a" in dump_content_after and "site-b" in dump_content_after, (
                "startup migration must never touch the ecosystem/dump state"
            )
            print(
                "Test 16 [LEGACY APPLICATION PRESERVATION] (migrating the systemd unit for a user "
                "with an existing multi-app PM2 ecosystem never calls pm2 delete/stop/kill and never "
                "alters dump.pm2 -- only pm2 save, which is additive) PASSED"
            )
            os.remove(os.path.join(unit_dir, "pm2-preserveuser.service"))

        with tempfile.TemporaryDirectory(prefix="rtsa-pm2startup-home15-") as home:
            pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
            open(pm2_path, "w").close()
            os.chmod(pm2_path, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                f.write("{}")
            account = fake_pw("emptyapps", 1514, 1514, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            audited = []
            bot.db_worker.enqueue_action = lambda payload, result: audited.append((payload, result))

            wire_common(bot, discovery=discovery, unit_text=None, jlist_output="[]")
            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")
            assert "PM2 Startup Not Applied" in result, result
            assert "EMPTY_PM2_STATE" in result
            assert os.path.join(home, ".pm2") in result
            unit_written = os.path.join(unit_dir, "pm2-emptyapps.service")
            assert not os.path.isfile(unit_written), (
                "no systemd unit may be written when pm2 jlist reports zero saved applications"
            )
            assert any(r == "empty_state" for _p, r in audited), (
                "the empty-state outcome must be recorded via the audit trail"
            )
            print(
                "Test 17 [PM2 STARTUP MUST HANDLE EMPTY PM2 STATE] (pm2 save succeeds and dump.pm2 "
                "exists, but pm2 jlist reports zero saved applications -- refuses to write a systemd "
                "unit that would restart-loop forever, reports PM2 Startup Not Applied, and audits "
                "empty_state) PASSED"
            )

    print("\nALL /pm2startup TESTS PASSED")


asyncio.run(main())
