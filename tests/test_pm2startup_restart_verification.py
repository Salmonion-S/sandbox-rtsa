import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio
import json
import pwd
import tempfile

import core.pm2_startup as pm2_startup
from config.manager import CloudflareConfig, DiscordConfig, ResponseEngineConfig, RTSAConfig
from core.event_bus import EventBus
from discord_integration.bot import RTSABot
import discord_integration.bot as bot_module

bot_module._PM2_STARTUP_VERIFY_POLL_DELAYS = (0, 0, 0)

_HEALTHY_SHOW = "ActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\nNRestarts=0\n"
_FAILED_SHOW = "ActiveState=activating\nSubState=auto-restart\nResult=exit-code\nExecMainStatus=1\nNRestarts=1\n"


class _FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass


def make_bot(detection_only=False):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=detection_only),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=_FakeDb(), supervisor=None)


def fake_pw(name, uid, gid, home, shell="/bin/bash"):
    return pwd.struct_passwd((name, "x", uid, gid, "", home, shell))


def make_discovery(pm2_path, node_path=None, node_version="v22.23.2"):
    return pm2_startup.RuntimeDiscovery(
        ok=True, node_path=node_path or os.path.join(os.path.dirname(pm2_path), "node"),
        node_version=node_version, pm2_path=pm2_path, pm2_version="5.4.3",
        npm_path=os.path.join(os.path.dirname(pm2_path), "npm"),
    )


def _setup_home(home, user):
    pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
    os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
    open(pm2_path, "w").close()
    os.chmod(pm2_path, 0o755)
    os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
    with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
        f.write("{}")
    return pm2_path


async def scenario_1_full_happy_path_items_1_to_7():
    with tempfile.TemporaryDirectory(prefix="rtsa-restartverify-unit1-") as unit_dir:
        bot_module._SYSTEMD_UNIT_DIR = unit_dir
        with tempfile.TemporaryDirectory(prefix="rtsa-restartverify-home1-") as home:
            pm2_path = _setup_home(home, "happyuser")
            account = fake_pw("happyuser", 1700, 1700, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            systemctl_calls = []

            async def fake_systemctl(*args, timeout=None):
                systemctl_calls.append(args)
                if args and args[0] == "show":
                    return 0, _HEALTHY_SHOW, ""
                return 0, "", ""

            jlist_payload = json.dumps([
                {"name": "landing-app", "pm2_env": {"status": "online", "restart_time": 0}},
            ])

            async def fake_pm2(_account, _cwd, pm2_args, timeout):
                if pm2_args == "save":
                    return 0, "", ""
                if pm2_args == "ping":
                    return 0, "pong", ""
                if pm2_args == "jlist":
                    return 0, jlist_payload, ""
                return 0, "", ""

            bot._discover_pm2_runtime = lambda _a: asyncio.sleep(0, result=discovery)
            bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=None)
            bot._service_active = lambda _s: asyncio.sleep(0, result=False)
            bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(False, False, ""))
            bot._run_pm2_as_user_detailed = fake_pm2
            bot._run_systemctl = fake_systemctl

            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")

            assert "PM2 Startup Verified" in result and "STARTUP VERIFIED" in result, result
            assert "landing-app" in result and "ONLINE" in result

            restart_calls = [c for c in systemctl_calls if c and c[0] == "restart"]
            assert restart_calls == [("restart", "pm2-happyuser.service")], (
                f"item 4/5: exactly one targeted restart of the correct service must happen, "
                f"got {restart_calls}"
            )
            assert ("daemon-reload",) in systemctl_calls, "item 2: daemon-reload must run"
            assert ("enable", "pm2-happyuser.service") in systemctl_calls, "item 3: enable must run"
            assert "start" not in [c[0] for c in systemctl_calls], (
                "systemctl start must never be used -- restart is the mandatory validation path"
            )
            print(
                "Scenario 1 [ITEMS 1-7: FULL HAPPY PATH] (new service created, daemon-reload+enable "
                "succeed, the target service -- and only the target service -- is restarted once, "
                "remains active, resurrect succeeds, and the pre-restart app list is confirmed restored "
                "post-restart) PASSED"
            )


async def scenario_2_targeted_restart_fails_item_8():
    with tempfile.TemporaryDirectory(prefix="rtsa-restartverify-unit2-") as unit_dir:
        bot_module._SYSTEMD_UNIT_DIR = unit_dir
        with tempfile.TemporaryDirectory(prefix="rtsa-restartverify-home2-") as home:
            pm2_path = _setup_home(home, "restartfail")
            account = fake_pw("restartfail", 1701, 1701, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            show_calls = {"n": 0}

            async def fake_systemctl(*args, timeout=None):
                if args and args[0] == "restart":
                    return 1, "", "Failed to restart pm2-restartfail.service: unit busy"
                if args and args[0] == "show":
                    show_calls["n"] += 1
                    return 0, _HEALTHY_SHOW, ""
                return 0, "", ""

            async def fake_pm2(_account, _cwd, pm2_args, timeout):
                if pm2_args == "save":
                    return 0, "", ""
                if pm2_args == "jlist":
                    return 0, '[{"name": "app", "pm2_env": {"status": "online"}}]', ""
                return 0, "", ""

            bot._discover_pm2_runtime = lambda _a: asyncio.sleep(0, result=discovery)
            bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=None)
            bot._service_active = lambda _s: asyncio.sleep(0, result=False)
            bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(False, False, ""))
            bot._run_pm2_as_user_detailed = fake_pm2
            bot._run_systemctl = fake_systemctl

            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")

            assert "Gagal" in result and "systemctl restart" in result, result
            assert "PM2 Startup Verified" not in result and "STARTUP VERIFIED" not in result
            assert show_calls["n"] == 0, (
                "if the restart command itself never launched, there is nothing to poll -- "
                "systemctl show must never be called after a failed restart command"
            )
            print(
                "Scenario 2 [ITEM 8: TARGETED RESTART FAILS] (systemctl restart itself returns "
                "non-zero -- reported as a failure immediately, no false success, and no wasted "
                "post-restart polling since the restart never actually launched) PASSED"
            )


def scenario_3_ping_ok_but_applications_not_restored_item_11():
    samples = [pm2_startup.SystemdShowState(
        active_state="active", sub_state="running", result="success", exec_main_status="0", n_restarts="0",
    )]
    verification = pm2_startup.classify_startup_verification(
        show_states=samples, apps=[], pm2_reachable=True,
        expected_app_names=["landing-app"],
    )
    assert verification.state == pm2_startup.STARTUP_RESURRECT_FAILED, verification.state
    assert verification.missing_apps == ("landing-app",)
    assert "0 dari 1" in verification.reason
    print(
        "Scenario 3 [ITEM 11: PM2 REACHABLE BUT APPLICATIONS NOT RESTORED] (systemd stable and PM2 "
        "RPC answers, but the one application that was running before the restart never comes back at "
        "all -- explicitly RESURRECT_FAILED, not HEALTHY just because PM2 itself answered) PASSED"
    )


def scenario_4_partial_restore_mixed_missing_and_unhealthy_item_12():
    samples = [pm2_startup.SystemdShowState(
        active_state="active", sub_state="running", result="success", exec_main_status="0", n_restarts="0",
    )]
    apps = [pm2_startup.Pm2AppStatus(name="site-a", status="online", restart_count=0)]
    verification = pm2_startup.classify_startup_verification(
        show_states=samples, apps=apps, pm2_reachable=True,
        expected_app_names=["site-a", "site-b"],
    )
    assert verification.state == pm2_startup.STARTUP_PARTIAL_RESTORE, verification.state
    assert verification.missing_apps == ("site-b",)
    print(
        "Scenario 4 [ITEM 12: PARTIAL RESTORE] (one of two expected applications came back online, "
        "the other never restored -- PARTIAL_RESTORE naming site-b as missing, never HEALTHY) PASSED"
    )


def scenario_5_runtime_mismatch_item_13():
    discovery = make_discovery("/usr/bin/pm2", node_path="/home/x/.nvm/versions/node/v20.0.0/bin/node")
    directives = pm2_startup.UnitDirectives(
        exec_start="/usr/bin/pm2 resurrect --no-daemon", exec_start_path="/usr/bin/pm2",
        user="x", pm2_home="/home/x/.pm2", path_value="/usr/bin:/usr/local/bin",
    )

    def exists_fn(path):
        return path in ("/usr/bin/pm2", "/usr/bin/node")

    audit = pm2_startup.audit_runtime_consistency(directives=directives, discovery=discovery, exists_fn=exists_fn)
    assert audit.state == pm2_startup.RUNTIME_NODE_BINARY_MISMATCH, audit.state
    print(
        "Scenario 5 [ITEM 13: RUNTIME MISMATCH] (unit's PATH resolves to a different Node binary than "
        "the one PM2 was actually set up with -- NODE_BINARY_MISMATCH; full matrix in "
        "tests/test_pm2startup_verification.py scenarios 5-9) PASSED"
    )


def scenario_6_nvm_path_missing_item_14():
    discovery = make_discovery(
        "/home/x/.nvm/versions/node/v20.0.0/bin/pm2", node_path="/home/x/.nvm/versions/node/v20.0.0/bin/node",
    )
    directives = pm2_startup.UnitDirectives(
        exec_start="/home/x/.nvm/versions/node/v18.0.0/bin/pm2 resurrect --no-daemon",
        exec_start_path="/home/x/.nvm/versions/node/v18.0.0/bin/pm2",
        user="x", pm2_home="/home/x/.pm2", path_value="/home/x/.nvm/versions/node/v18.0.0/bin:/usr/bin",
    )

    def exists_fn(path):
        return path == directives.exec_start_path

    audit = pm2_startup.audit_runtime_consistency(directives=directives, discovery=discovery, exists_fn=exists_fn)
    assert audit.state == pm2_startup.RUNTIME_NVM_PATH_MISSING, audit.state
    print(
        "Scenario 6 [ITEM 14: NVM PATH MISSING] (unit's PATH points into an NVM version directory "
        "whose `node` binary no longer exists -- NVM_PATH_MISSING) PASSED"
    )


async def scenario_7_unrelated_service_never_restarted_item_15():
    with tempfile.TemporaryDirectory(prefix="rtsa-restartverify-unit7-") as unit_dir:
        bot_module._SYSTEMD_UNIT_DIR = unit_dir
        other_unit_path = os.path.join(unit_dir, "pm2-otheruser.service")
        with open(other_unit_path, "w") as f:
            f.write("[Unit]\n[Service]\nUser=otheruser\nExecStart=/usr/bin/pm2 resurrect --no-daemon\n")
        other_mtime_before = os.path.getmtime(other_unit_path)

        with tempfile.TemporaryDirectory(prefix="rtsa-restartverify-home7-") as home:
            pm2_path = _setup_home(home, "targetuser")
            account = fake_pw("targetuser", 1702, 1702, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            restart_targets = []

            async def fake_systemctl(*args, timeout=None):
                if args and args[0] == "restart":
                    restart_targets.append(args[1] if len(args) > 1 else None)
                if args and args[0] == "show":
                    return 0, _HEALTHY_SHOW, ""
                return 0, "", ""

            async def fake_pm2(_account, _cwd, pm2_args, timeout):
                if pm2_args == "save":
                    return 0, "", ""
                if pm2_args == "jlist":
                    return 0, '[{"name": "app", "pm2_env": {"status": "online"}}]', ""
                return 0, "", ""

            bot._discover_pm2_runtime = lambda _a: asyncio.sleep(0, result=discovery)
            bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=None)
            bot._service_active = lambda _s: asyncio.sleep(0, result=False)
            bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(False, False, ""))
            bot._run_pm2_as_user_detailed = fake_pm2
            bot._run_systemctl = fake_systemctl

            preflight = await bot._pm2startup_preflight(account)
            await bot._pm2startup_execute(preflight, requested_by="tester")

            assert restart_targets == ["pm2-targetuser.service"], (
                f"only the target user's own service may ever be passed to systemctl restart, "
                f"got {restart_targets}"
            )
            assert "otheruser" not in restart_targets
            assert os.path.getmtime(other_unit_path) == other_mtime_before, (
                "the unrelated user's unit file must not be touched at all"
            )
            with open(other_unit_path) as f:
                assert "otheruser" in f.read(), "the unrelated unit's content must be untouched"
            print(
                "Scenario 7 [ITEM 15: UNRELATED PM2 SERVICE NEVER RESTARTED] (/pm2startup for "
                "targetuser restarts pm2-targetuser.service only -- pm2-otheruser.service is never "
                "named in any systemctl call and its file is left byte-for-byte untouched) PASSED"
            )


async def scenario_8_bounded_poll_never_unbounded_item_16():
    with tempfile.TemporaryDirectory(prefix="rtsa-restartverify-unit8-") as unit_dir:
        bot_module._SYSTEMD_UNIT_DIR = unit_dir
        with tempfile.TemporaryDirectory(prefix="rtsa-restartverify-home8-") as home:
            pm2_path = _setup_home(home, "boundeduser")
            account = fake_pw("boundeduser", 1703, 1703, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            show_count = {"n": 0}

            async def fake_systemctl(*args, timeout=None):
                if args and args[0] == "show":
                    show_count["n"] += 1
                    return 0, _FAILED_SHOW, ""
                return 0, "", ""

            async def fake_pm2(_account, _cwd, pm2_args, timeout):
                if pm2_args == "jlist":
                    return 0, '[{"name": "app", "pm2_env": {"status": "online"}}]', ""
                return 0, "", ""

            bot._discover_pm2_runtime = lambda _a: asyncio.sleep(0, result=discovery)
            bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=None)
            bot._service_active = lambda _s: asyncio.sleep(0, result=False)
            bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(False, False, ""))
            bot._run_pm2_as_user_detailed = fake_pm2
            bot._run_systemctl = fake_systemctl

            preflight = await bot._pm2startup_preflight(account)
            await bot._pm2startup_execute(preflight, requested_by="tester")

            assert show_count["n"] == len(bot_module._PM2_STARTUP_VERIFY_POLL_DELAYS), (
                f"the post-restart poll must sample exactly the configured bounded number of times "
                f"({len(bot_module._PM2_STARTUP_VERIFY_POLL_DELAYS)}), even when the unit never "
                f"stabilizes -- got {show_count['n']} samples, never an unbounded retry loop"
            )
            print(
                "Scenario 8 [ITEM 16: BOUNDED RESTART VERIFICATION] (a unit that never stabilizes still "
                "only gets polled exactly the configured number of times -- no infinite wait even when "
                "the service keeps auto-restarting) PASSED"
            )


async def scenario_9_journal_only_fetched_on_failure_item_17():
    with tempfile.TemporaryDirectory(prefix="rtsa-restartverify-unit9-") as unit_dir:
        bot_module._SYSTEMD_UNIT_DIR = unit_dir

        async def run_once(user, show_output, pm2_ok):
            with tempfile.TemporaryDirectory(prefix=f"rtsa-restartverify-home9-{user}-") as home:
                pm2_path = _setup_home(home, user)
                account = fake_pw(user, 1704, 1704, home)
                discovery = make_discovery(pm2_path)
                bot = make_bot()
                journal_calls = {"n": 0}

                async def fake_root_command(argv, timeout):
                    if argv and "journalctl" in argv[0]:
                        journal_calls["n"] += 1
                        return 0, "-- bounded journal tail --", ""
                    return 0, "", ""

                async def fake_systemctl(*args, timeout=None):
                    if args and args[0] == "show":
                        return 0, show_output, ""
                    return 0, "", ""

                async def fake_pm2(_account, _cwd, pm2_args, timeout):
                    if pm2_args == "jlist":
                        return (
                            (0, '[{"name": "app", "pm2_env": {"status": "online"}}]', "")
                            if pm2_ok else (1, "", "gagal")
                        )
                    return 0, "", ""

                bot._discover_pm2_runtime = lambda _a: asyncio.sleep(0, result=discovery)
                bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=None)
                bot._service_active = lambda _s: asyncio.sleep(0, result=False)
                bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(False, False, ""))
                bot._run_pm2_as_user_detailed = fake_pm2
                bot._run_systemctl = fake_systemctl
                bot._run_root_command = fake_root_command

                preflight = await bot._pm2startup_preflight(account)
                result = await bot._pm2startup_execute(preflight, requested_by="tester")
                return result, journal_calls["n"]

        healthy_result, healthy_journal_calls = await run_once("journalhealthy", _HEALTHY_SHOW, True)
        assert "PM2 Startup Verified" in healthy_result
        assert healthy_journal_calls == 0, (
            "journalctl must never be fetched on a healthy startup -- only used for failure diagnosis"
        )

        failed_result, failed_journal_calls = await run_once("journalfailed", _FAILED_SHOW, True)
        assert "PM2 Startup Verified" not in failed_result
        assert failed_journal_calls == 1, "exactly one bounded journalctl tail must be fetched on failure"
        assert "-- bounded journal tail --" in failed_result, "the journal tail must appear in the failure report"

        print(
            "Scenario 9 [ITEM 17: JOURNAL ONLY FETCHED ON FAILURE, WITH BOUNDED TAIL SHOWN] (a healthy "
            "startup never runs journalctl at all; a failed one runs it exactly once and the bounded "
            "tail is included in the Discord failure report) PASSED"
        )


def scenario_10_legacy_service_protected_item_18():
    legacy_unit = (
        "[Service]\nUser=legacyuser\n"
        "Environment=PM2_HOME=/home/legacyuser/.pm2\n"
        "ExecStart=/home/legacyuser/.nvm/versions/node/v18.0.0/bin/pm2 resurrect --no-daemon\n"
    )

    def exec_exists_fn(path):
        return path == "/home/legacyuser/.nvm/versions/node/v18.0.0/bin/pm2"

    classification = pm2_startup.classify_pm2_unit(
        legacy_unit, target_user="legacyuser",
        discovered_pm2_path="/home/legacyuser/.nvm/versions/node/v20.0.0/bin/pm2",
        discovered_pm2_home="/home/legacyuser/.pm2",
        exec_exists_fn=exec_exists_fn, service_active=True, service_enabled=True,
    )
    assert classification.status == pm2_startup.STATUS_LEGACY_BUT_WORKING
    assert classification.status != pm2_startup.STATUS_CURRENT_RTSA
    print(
        "Scenario 10 [ITEM 18: EXISTING LEGACY SERVICE REMAINS PROTECTED] (a still-working legacy unit "
        "is classified LEGACY_BUT_WORKING, requiring an explicit operator confirm before any write -- "
        "full end-to-end proof (byte-exact backup, no auto-overwrite) in tests/test_pm2startup.py Test "
        "5/Test 6) PASSED"
    )


async def scenario_11_written_unit_user_safety_check():
    with tempfile.TemporaryDirectory(prefix="rtsa-restartverify-unit11-") as unit_dir:
        bot_module._SYSTEMD_UNIT_DIR = unit_dir
        with tempfile.TemporaryDirectory(prefix="rtsa-restartverify-home11-") as home:
            pm2_path = _setup_home(home, "safetyuser")
            account = fake_pw("safetyuser", 1705, 1705, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            restart_calls = []

            async def fake_systemctl(*args, timeout=None):
                if args and args[0] == "restart":
                    restart_calls.append(args)
                if args and args[0] == "show":
                    return 0, _HEALTHY_SHOW, ""
                return 0, "", ""

            async def fake_pm2(_account, _cwd, pm2_args, timeout):
                if pm2_args == "jlist":
                    return 0, '[{"name": "app", "pm2_env": {"status": "online"}}]', ""
                return 0, "", ""

            bot._discover_pm2_runtime = lambda _a: asyncio.sleep(0, result=discovery)
            bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=None)
            bot._service_active = lambda _s: asyncio.sleep(0, result=False)
            bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(False, False, ""))
            bot._run_pm2_as_user_detailed = fake_pm2
            bot._run_systemctl = fake_systemctl

            orig_generate = pm2_startup.generate_pm2_unit
            pm2_startup.generate_pm2_unit = lambda **kw: orig_generate(**{**kw, "user": "someoneelse"})
            try:
                preflight = await bot._pm2startup_preflight(account)
                result = await bot._pm2startup_execute(preflight, requested_by="tester")
            finally:
                pm2_startup.generate_pm2_unit = orig_generate

            assert restart_calls == [], (
                f"if the just-written unit's User= doesn't match the requested target, restart must "
                f"NEVER be issued -- got {restart_calls}"
            )
            assert "Gagal" in result
            assert "User=" in result
            print(
                "Scenario 11 [SECTION 17 SAFETY NET: WRITTEN-UNIT USER MISMATCH ABORTS BEFORE RESTART] "
                "(a defense-in-depth check confirms the just-written unit's User= matches the requested "
                "Linux user before ever issuing systemctl restart -- a mismatch aborts with no restart "
                "call at all) PASSED"
            )


async def main() -> None:
    await scenario_1_full_happy_path_items_1_to_7()
    await scenario_2_targeted_restart_fails_item_8()
    scenario_3_ping_ok_but_applications_not_restored_item_11()
    scenario_4_partial_restore_mixed_missing_and_unhealthy_item_12()
    scenario_5_runtime_mismatch_item_13()
    scenario_6_nvm_path_missing_item_14()
    await scenario_7_unrelated_service_never_restarted_item_15()
    await scenario_8_bounded_poll_never_unbounded_item_16()
    await scenario_9_journal_only_fetched_on_failure_item_17()
    scenario_10_legacy_service_protected_item_18()
    await scenario_11_written_unit_user_safety_check()
    print("\nALL /pm2startup MANDATORY RESTART VERIFICATION TESTS PASSED")


asyncio.run(main())
