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


def make_bot(detection_only=False):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=detection_only),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=_FakeDb(), supervisor=None)


class _FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass


def fake_pw(name, uid, gid, home, shell="/bin/bash"):
    return pwd.struct_passwd((name, "x", uid, gid, "", home, shell))


def make_discovery(pm2_path, node_path=None, ok=True, reason="", node_version="v22.23.2"):
    return pm2_startup.RuntimeDiscovery(
        ok=ok, reason=reason, node_path=node_path or (pm2_path and os.path.join(os.path.dirname(pm2_path), "node")),
        node_version=node_version, pm2_path=pm2_path, pm2_version="5.4.3",
        npm_path=pm2_path and os.path.join(os.path.dirname(pm2_path), "npm"),
    )


def make_directives(exec_start_path, path_value, user="testuser", pm2_home="/home/testuser/.pm2"):
    return pm2_startup.UnitDirectives(
        exec_start=f"{exec_start_path} resurrect --no-daemon",
        exec_start_path=exec_start_path, user=user, pm2_home=pm2_home, path_value=path_value,
    )


def scenario_1_ping_works_but_resurrect_fails():
    samples = [
        pm2_startup.SystemdShowState(
            active_state="activating", sub_state="auto-restart", result="exit-code", exec_main_status="1",
            n_restarts="1",
        ),
    ]
    verification = pm2_startup.classify_startup_verification(
        show_states=samples, apps=[], pm2_reachable=True,
    )
    assert verification.state == pm2_startup.STARTUP_RESURRECT_FAILED, verification.state
    assert not verification.is_healthy
    print(
        "Scenario 1 [PING WORKS BUT RESURRECT FAILS -> FAILURE] (pm2 ping reachable is NOT enough -- "
        "ExecStart's Result=exit-code / activating+auto-restart alone forces RESURRECT_FAILED) PASSED"
    )


def scenario_2_systemd_briefly_active_then_exits():
    flicker_samples = [
        pm2_startup.SystemdShowState(
            active_state="active", sub_state="running", result=None, exec_main_status="0", n_restarts="0",
        ),
        pm2_startup.SystemdShowState(
            active_state="failed", sub_state="failed", result="exit-code", exec_main_status="1", n_restarts="1",
        ),
    ]
    verification = pm2_startup.classify_startup_verification(
        show_states=flicker_samples, apps=[], pm2_reachable=True,
    )
    assert verification.state == pm2_startup.STARTUP_RESURRECT_FAILED, verification.state

    single_snapshot_only = pm2_startup.classify_startup_verification(
        show_states=flicker_samples[:1], apps=[], pm2_reachable=True,
    )
    assert single_snapshot_only.state == pm2_startup.STARTUP_HEALTHY, (
        "sanity check: a SINGLE early snapshot alone would have wrongly looked healthy -- this is "
        "exactly the false-success bug the bounded multi-sample poll exists to close"
    )
    print(
        "Scenario 2 [SYSTEMD BRIEFLY ACTIVE THEN EXITS -> FAILURE] (a single post-start snapshot would "
        "have misclassified this as healthy -- the bounded multi-sample poll catches the later "
        "Result=exit-code/failed transition and correctly reports RESURRECT_FAILED) PASSED"
    )


def scenario_3_all_apps_online():
    samples = [
        pm2_startup.SystemdShowState(
            active_state="active", sub_state="running", result="success", exec_main_status="0", n_restarts="0",
        ),
    ]
    apps = [
        pm2_startup.Pm2AppStatus(name="site-a", status="online", restart_count=0),
        pm2_startup.Pm2AppStatus(name="site-b", status="online", restart_count=2),
    ]
    verification = pm2_startup.classify_startup_verification(
        show_states=samples, apps=apps, pm2_reachable=True,
    )
    assert verification.state == pm2_startup.STARTUP_HEALTHY, verification.state
    assert verification.is_healthy
    assert verification.apps == tuple(apps)
    print(
        "Scenario 3 [ALL APPS ONLINE -> HEALTHY] (stable systemd unit + PM2 reachable + every saved "
        "app online -- genuinely healthy, not just 'ping ONLINE') PASSED"
    )


def scenario_4_one_app_errored():
    samples = [
        pm2_startup.SystemdShowState(
            active_state="active", sub_state="running", result="success", exec_main_status="0", n_restarts="0",
        ),
    ]
    apps = [
        pm2_startup.Pm2AppStatus(name="site-a", status="online", restart_count=0),
        pm2_startup.Pm2AppStatus(name="site-b", status="errored", restart_count=3),
    ]
    verification = pm2_startup.classify_startup_verification(
        show_states=samples, apps=apps, pm2_reachable=True,
    )
    assert verification.state == pm2_startup.STARTUP_PARTIAL_RESTORE, verification.state
    assert verification.unhealthy_apps == ("site-b",)
    print(
        "Scenario 4 [ONE APP ERRORED -> PARTIAL_RESTORE] (systemd stable and PM2 reachable, but one "
        "saved app came back errored -- reported PARTIAL_RESTORE, explicitly naming which app, never "
        "HEALTHY) PASSED"
    )


def scenario_5_nvm_missing():
    discovery = make_discovery(
        "/home/testuser/.nvm/versions/node/v20.0.0/bin/pm2",
        node_path="/home/testuser/.nvm/versions/node/v20.0.0/bin/node",
    )
    directives = make_directives(
        exec_start_path="/home/testuser/.nvm/versions/node/v18.0.0/bin/pm2",
        path_value="/home/testuser/.nvm/versions/node/v18.0.0/bin:/usr/local/bin:/usr/bin:/bin",
    )

    def exists_fn(path):
        return path == directives.exec_start_path

    audit = pm2_startup.audit_runtime_consistency(directives=directives, discovery=discovery, exists_fn=exists_fn)
    assert audit.state == pm2_startup.RUNTIME_NVM_PATH_MISSING, audit.state
    assert audit.is_drift
    print(
        "Scenario 5 [NVM MISSING -> NVM_PATH_MISSING] (unit's PATH points into an NVM version dir "
        "whose `node` binary no longer exists on disk -- classified NVM_PATH_MISSING, not silently "
        "CONSISTENT) PASSED"
    )


def scenario_6_node_binary_differs():
    discovery = make_discovery(
        "/usr/bin/pm2", node_path="/home/testuser/.nvm/versions/node/v20.0.0/bin/node",
    )
    directives = make_directives(exec_start_path="/usr/bin/pm2", path_value="/usr/bin:/usr/local/bin")

    def exists_fn(path):
        return path in ("/usr/bin/pm2", "/usr/bin/node")

    audit = pm2_startup.audit_runtime_consistency(directives=directives, discovery=discovery, exists_fn=exists_fn)
    assert audit.state == pm2_startup.RUNTIME_NODE_BINARY_MISMATCH, audit.state
    print(
        "Scenario 6 [NODE BINARY DIFFERS -> NODE_BINARY_MISMATCH] (unit's PATH resolves `node` to a "
        "different binary than the one PM2/apps were actually built with) PASSED"
    )


def scenario_7_node_version_differs():
    discovery = make_discovery("/usr/bin/pm2", node_path="/usr/bin/node", node_version="v18.19.0")
    directives = make_directives(exec_start_path="/usr/bin/pm2", path_value="/usr/bin:/usr/local/bin")

    def exists_fn(path):
        return path in ("/usr/bin/pm2", "/usr/bin/node")

    def resolved_node_version_fn(path):
        return "v20.11.0" if path == "/usr/bin/node" else None

    audit = pm2_startup.audit_runtime_consistency(
        directives=directives, discovery=discovery, exists_fn=exists_fn,
        resolved_node_version_fn=resolved_node_version_fn,
    )
    assert audit.state == pm2_startup.RUNTIME_NODE_VERSION_MISMATCH, audit.state
    assert audit.is_drift
    assert audit.node_version == "v20.11.0"

    audit_no_probe = pm2_startup.audit_runtime_consistency(directives=directives, discovery=discovery, exists_fn=exists_fn)
    assert audit_no_probe.state == pm2_startup.RUNTIME_CONSISTENT, (
        "without a version probe function the same binary path is still reported CONSISTENT -- "
        "the new check is additive and never regresses existing callers that don't supply it"
    )
    print(
        "Scenario 7 [NODE VERSION DIFFERS -> NODE_VERSION_MISMATCH] (unit's PATH resolves to the SAME "
        "Node binary path PM2 was set up with, but an actual version probe shows the binary was "
        "upgraded/downgraded in place -- classified NODE_VERSION_MISMATCH; without the probe function "
        "the pre-existing CONSISTENT behavior is unchanged) PASSED"
    )


def scenario_8_pm2_binary_differs():
    discovery = make_discovery(
        "/home/testuser/.nvm/versions/node/v20.0.0/bin/pm2",
        node_path="/home/testuser/.nvm/versions/node/v20.0.0/bin/node",
    )
    directives = make_directives(
        exec_start_path="/home/testuser/.nvm/versions/node/v20.0.0/bin/pm2-old",
        path_value="/home/testuser/.nvm/versions/node/v20.0.0/bin:/usr/bin",
    )

    def exists_fn(path):
        return path in (
            directives.exec_start_path, "/home/testuser/.nvm/versions/node/v20.0.0/bin/node",
        )

    audit = pm2_startup.audit_runtime_consistency(directives=directives, discovery=discovery, exists_fn=exists_fn)
    assert audit.state == pm2_startup.RUNTIME_PM2_BINARY_MISMATCH, audit.state
    print(
        "Scenario 8 [PM2 BINARY DIFFERS -> PM2_BINARY_MISMATCH] (ExecStart's PM2 binary exists on disk "
        "but is not the PM2 actually active for this user -- Node matched, so the drift is correctly "
        "isolated to PM2, not misreported as a Node problem) PASSED"
    )


def scenario_9_runtime_unknown():
    discovery = make_discovery(None, ok=False, reason="probe login shell gagal")
    directives = make_directives(exec_start_path="/usr/bin/pm2", path_value="/usr/bin:/usr/local/bin")

    def exists_fn(path):
        return path == "/usr/bin/pm2"

    audit = pm2_startup.audit_runtime_consistency(directives=directives, discovery=discovery, exists_fn=exists_fn)
    assert audit.state == pm2_startup.RUNTIME_UNKNOWN, audit.state
    assert not audit.is_known
    assert not audit.is_drift, "UNKNOWN must never be silently treated as drift OR as consistent"
    print(
        "Scenario 9 [RUNTIME UNDETERMINABLE -> UNKNOWN_RUNTIME] (the login-shell probe could not "
        "resolve a Node runtime for this user at all -- reported UNKNOWN_RUNTIME rather than assuming "
        "either CONSISTENT or DRIFT) PASSED"
    )


def scenario_10_legacy_service_detected_preserved():
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
    assert classification.status == pm2_startup.STATUS_LEGACY_BUT_WORKING, classification.status
    assert classification.status != pm2_startup.STATUS_CURRENT_RTSA, (
        "a working legacy unit must never be silently classified as already-current -- that would "
        "skip the confirm-before-migrate gate"
    )
    print(
        "Scenario 10 [LEGACY SERVICE DETECTED -> PRESERVED, NOT AUTO-OVERWRITTEN] (a still-functional "
        "legacy unit is classified LEGACY_BUT_WORKING; end-to-end proof that this requires an explicit "
        "operator confirm before any write -- and that a confirmed migration creates a byte-exact "
        "backup first -- is in tests/test_pm2startup.py Test 5/Test 6) PASSED"
    )


async def scenario_11_end_to_end_false_success_no_longer_possible():
    with tempfile.TemporaryDirectory(prefix="rtsa-pm2verify-unit-") as unit_dir:
        bot_module._SYSTEMD_UNIT_DIR = unit_dir
        with tempfile.TemporaryDirectory(prefix="rtsa-pm2verify-home-") as home:
            pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
            open(pm2_path, "w").close()
            os.chmod(pm2_path, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                f.write("{}")
            account = fake_pw("falsesuccess", 1600, 1600, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            show_calls = {"n": 0}
            unstable_samples = [
                "ActiveState=active\nSubState=running\nResult=\nExecMainStatus=0\nNRestarts=0\n",
                "ActiveState=activating\nSubState=auto-restart\nResult=exit-code\nExecMainStatus=1\nNRestarts=1\n",
                "ActiveState=activating\nSubState=auto-restart\nResult=exit-code\nExecMainStatus=1\nNRestarts=2\n",
            ]

            async def fake_run(*args, timeout=None):
                if args and args[0] == "show":
                    idx = min(show_calls["n"], len(unstable_samples) - 1)
                    show_calls["n"] += 1
                    return 0, unstable_samples[idx], ""
                return 0, "", ""

            async def fake_run_pm2(_account, _cwd, pm2_args, timeout):
                if pm2_args == "save":
                    return 0, "", ""
                if pm2_args == "ping":
                    return 0, "pong", ""
                if pm2_args == "jlist":
                    return 0, '[{"name":"landing-app","pm2_env":{"status":"online","restart_time":0}}]', ""
                return 0, "", ""

            bot._discover_pm2_runtime = lambda _a: asyncio.sleep(0, result=discovery)
            bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=None)
            bot._service_active = lambda _s: asyncio.sleep(0, result=False)
            bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(False, False, ""))
            bot._run_pm2_as_user_detailed = fake_run_pm2
            bot._run_systemctl = fake_run

            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")

            assert "Terkonfigurasi" not in result, (
                f"THE BUG: pm2 ping ONLINE + a briefly-active systemd sample must NOT be reported as "
                f"'PM2 Startup Terkonfigurasi' when the unit is actually flapping in Restart=on-failure "
                f"-- got:\n{result}"
            )
            assert "Verification FAILED" in result, result
            assert "Resurrect" in result and "FAILED" in result, result
            assert "PONG" not in result.upper() or "PM2" in result, result
            print(
                "Scenario 11 [END-TO-END: PM2 PING ONLINE + BRIEFLY-ACTIVE SYSTEMD NO LONGER FALSELY "
                "'TERKONFIGURASI'] (reproduces the exact production report -- pm2 ping succeeds and the "
                "first systemd sample looks active/running, but later samples show the "
                "Restart=on-failure loop -- /pm2startup now reports Verification FAILED with the "
                "Resurrect/Systemd/Applications detail instead of a false success) PASSED"
            )


async def scenario_12_end_to_end_healthy_still_reports_success():
    with tempfile.TemporaryDirectory(prefix="rtsa-pm2verify-unit2-") as unit_dir:
        bot_module._SYSTEMD_UNIT_DIR = unit_dir
        with tempfile.TemporaryDirectory(prefix="rtsa-pm2verify-home2-") as home:
            pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
            open(pm2_path, "w").close()
            os.chmod(pm2_path, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                f.write("{}")
            account = fake_pw("realhealthy", 1601, 1601, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            healthy_show = "ActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\nNRestarts=0\n"

            async def fake_run(*args, timeout=None):
                if args and args[0] == "show":
                    return 0, healthy_show, ""
                return 0, "", ""

            async def fake_run_pm2(_account, _cwd, pm2_args, timeout):
                if pm2_args == "save":
                    return 0, "", ""
                if pm2_args == "ping":
                    return 0, "pong", ""
                if pm2_args == "jlist":
                    return 0, '[{"name":"site-a","pm2_env":{"status":"online","restart_time":0}}]', ""
                return 0, "", ""

            bot._discover_pm2_runtime = lambda _a: asyncio.sleep(0, result=discovery)
            bot._read_pm2_unit_text = lambda _p: asyncio.sleep(0, result=None)
            bot._service_active = lambda _s: asyncio.sleep(0, result=False)
            bot._verify_systemd_service = lambda _s: asyncio.sleep(0, result=(False, False, ""))
            bot._run_pm2_as_user_detailed = fake_run_pm2
            bot._run_systemctl = fake_run

            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")

            assert "PM2 Startup Verified" in result and "STARTUP VERIFIED" in result, result
            assert "site-a" in result and "ONLINE" in result, (
                "a genuinely healthy startup should still surface the confirmed application list, "
                f"got:\n{result}"
            )
            print(
                "Scenario 12 [END-TO-END: GENUINELY HEALTHY STARTUP STILL REPORTS SUCCESS] (stable "
                "systemd across all polled samples + PM2 reachable + saved app confirmed online -- "
                "still reports 'PM2 Startup Verified' / 'STARTUP VERIFIED', now with the confirmed "
                "application list attached) PASSED"
            )


async def scenario_13_end_to_end_partial_restore_not_healthy():
    with tempfile.TemporaryDirectory(prefix="rtsa-pm2verify-unit3-") as unit_dir:
        bot_module._SYSTEMD_UNIT_DIR = unit_dir
        with tempfile.TemporaryDirectory(prefix="rtsa-pm2verify-home3-") as home:
            pm2_path = os.path.join(home, ".nvm", "versions", "node", "v22.23.2", "bin", "pm2")
            os.makedirs(os.path.dirname(pm2_path), exist_ok=True)
            open(pm2_path, "w").close()
            os.chmod(pm2_path, 0o755)
            os.makedirs(os.path.join(home, ".pm2"), exist_ok=True)
            with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as f:
                f.write("{}")
            account = fake_pw("partialrestore", 1602, 1602, home)
            discovery = make_discovery(pm2_path)
            bot = make_bot()

            healthy_show = "ActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\nNRestarts=0\n"

            async def fake_run(*args, timeout=None):
                if args and args[0] == "show":
                    return 0, healthy_show, ""
                return 0, "", ""

            jlist_payload = (
                '[{"name":"site-a","pm2_env":{"status":"online","restart_time":0}},'
                '{"name":"site-b","pm2_env":{"status":"errored","restart_time":4}}]'
            )

            async def fake_run_pm2(_account, _cwd, pm2_args, timeout):
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
            bot._run_pm2_as_user_detailed = fake_run_pm2
            bot._run_systemctl = fake_run

            preflight = await bot._pm2startup_preflight(account)
            result = await bot._pm2startup_execute(preflight, requested_by="tester")

            assert "PM2 Startup Verified" not in result and "STARTUP VERIFIED" not in result, (
                f"a systemd-stable unit with one errored PM2 app must NOT be reported as fully "
                f"successful -- got:\n{result}"
            )
            assert "PARTIAL_RESTORE" in result, result
            assert "site-b" in result, "the failing application must be named explicitly, not just counted"
            print(
                "Scenario 13 [END-TO-END: PARTIAL_RESTORE NEVER REPORTED AS HEALTHY] (systemd unit "
                "stable, PM2 daemon reachable, but one saved app came back errored -- reported "
                "PARTIAL_RESTORE naming site-b, never 'PM2 Startup Verified') PASSED"
            )


async def main() -> None:
    scenario_1_ping_works_but_resurrect_fails()
    scenario_2_systemd_briefly_active_then_exits()
    scenario_3_all_apps_online()
    scenario_4_one_app_errored()
    scenario_5_nvm_missing()
    scenario_6_node_binary_differs()
    scenario_7_node_version_differs()
    scenario_8_pm2_binary_differs()
    scenario_9_runtime_unknown()
    scenario_10_legacy_service_detected_preserved()
    await scenario_11_end_to_end_false_success_no_longer_possible()
    await scenario_12_end_to_end_healthy_still_reports_success()
    await scenario_13_end_to_end_partial_restore_not_healthy()
    print("\nALL /pm2startup VERIFICATION-LAYER TESTS PASSED")


asyncio.run(main())
