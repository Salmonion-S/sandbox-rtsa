from __future__ import annotations

import asyncio
import json
import os
import pwd
import sys
import tempfile
import types
from unittest import mock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

import psutil

from config.manager import CloudflareConfig, DiscordConfig, ResponseEngineConfig, RTSAConfig, _derive_events_db_paths
from core import process_cleanup
from core.claim_store import PersistentClaimStore
from core.event_bus import EventBus
from discord_integration import bot as bot_module
from discord_integration.bot import RTSABot, _PM2_STARTUP_PROBE_COMMAND, _pm2_button_target_refusal, _port_block_succeeded
from modules.file_integrity_detector import _baseline_changed
from modules.process_anomaly_detector import drop_expected_self_spawn_rules


class Capture:
    def __init__(self) -> None:
        self.calls = []
        self.original = asyncio.create_subprocess_exec

    async def __call__(self, *argv, **kwargs):
        self.calls.append(argv)
        raise AssertionError(f"no subprocess expected, got {argv}")

    def __enter__(self):
        asyncio.create_subprocess_exec = self
        return self

    def __exit__(self, *exc):
        asyncio.create_subprocess_exec = self.original
        return False


class FakeDb:
    db_path = ":memory:"

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def make_bot(detection_only: bool = False) -> RTSABot:
    cfg = RTSAConfig(response_engine=ResponseEngineConfig(detection_only=detection_only), cloudflare=CloudflareConfig(enabled=False))
    return RTSABot(DiscordConfig(enabled=True, admin_role_ids=[1], critical_command_role_ids=[2]), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)


def fake_account(home: str):
    me = pwd.getpwuid(os.getuid())
    return types.SimpleNamespace(pw_name="labuser", pw_uid=me.pw_uid, pw_gid=me.pw_gid, pw_dir=home, pw_shell="/bin/bash")


async def test_1_pm2start_respects_detection_only():
    bot = make_bot(detection_only=True)

    async def resolve(user):
        raise AssertionError("project resolution must not run in detection_only")

    bot._resolve_cloudpanel_project = resolve
    with Capture() as cap:
        embed = await bot._pm2start("lab-001", requested_by="tester")
    assert not cap.calls and "Detection Only" in (embed.title or ""), embed.title
    print("Test 1 (/pm2start refuses to run `pm2 start` when response_engine.detection_only is true, like its peers) PASSED")


async def test_2_read_only_pm2_commands_never_spawn_a_daemon():
    bot = make_bot()
    with tempfile.TemporaryDirectory() as home:
        account = fake_account(home)
        os.makedirs(os.path.join(home, ".pm2"))
        with Capture() as cap:
            assert await bot._check_pm2_ping(account) is None, "a user with no PM2 evidence is not a PM2 user and must be skipped"
            with open(os.path.join(home, ".pm2", "dump.pm2"), "w") as handle:
                handle.write("[]")
            row = await bot._check_pm2_ping(account)
            assert row is not None and row.status == "offline", row
            pm2_calls = []

            async def record_pm2(*args, **kwargs):
                pm2_calls.append(args)
                return 0, "[]", ""

            class Reached(Exception):
                pass

            async def preflight(acct):
                raise Reached()

            bot._run_pm2_as_user_detailed = record_pm2
            bot._pm2startup_preflight = preflight
            try:
                await bot._audit_pm2_user(account, home)
            except Reached:
                pass
            assert not pm2_calls, "pm2 jlist must not run for a user whose daemon is down"

            async def resolve(user):
                return account, "x.lab.test", home, None

            bot._resolve_cloudpanel_project = resolve
            embed = await bot._pm2list("labuser", requested_by="tester")
            assert "Not Running" in (embed.title or ""), embed.title
        assert not cap.calls, cap.calls
    assert "pm2 --version" not in _PM2_STARTUP_PROBE_COMMAND, "`pm2 --version` launches a God daemon in PM2 >= 6"
    print("Test 2 (/cekpm2, /pm2startuplist and /pm2list never invoke pm2 when the user's daemon is down; the probe reads pm2's package.json) PASSED")


def test_3_process_discovery_works_with_real_psutil():
    records = process_cleanup.discover_user_processes(os.getuid(), process_iter=psutil.process_iter)
    assert any(r.pid == os.getpid() for r in records), "the current process must be discovered for its own uid"
    print("Test 3 (/clearproses and /deluser process discovery runs against the real psutil API: no invalid 'uid' attribute) PASSED")


def test_4_rtsa_children_are_not_flagged_for_expected_rules():
    matches = [("UID_SWITCH", 20, "a"), ("NEW_PROCESS_FINGERPRINT", 15, "b"), ("TEMP_DIRECTORY_EXECUTION", 40, "c"), ("FILELESS_EXECUTION", 55, "d")]
    own = os.getpid()
    kept = [m[0] for m in drop_expected_self_spawn_rules(matches, own, own)]
    assert kept == ["TEMP_DIRECTORY_EXECUTION", "FILELESS_EXECUTION"], kept
    assert drop_expected_self_spawn_rules(matches, own + 1, own) == matches, "other parents are untouched"
    print("Test 4 (RTSA's own privilege-dropped children no longer raise UID_SWITCH/NEW_PROCESS_FINGERPRINT; high-signal rules stay) PASSED")


def test_5_fim_baseline_written_only_when_changed():
    a, b = object(), object()
    assert not _baseline_changed({"x": a, "y": b}, {"x": a, "y": b})
    assert _baseline_changed({"x": a}, {"x": object()})
    assert _baseline_changed({"x": a}, {"x": a, "y": b})
    assert _baseline_changed({"x": a, "y": b}, {"x": a})
    print("Test 5 (FIM rewrites a baseline only when an entry was added, removed or replaced) PASSED")


def test_6_events_db_path_follows_database_path():
    raw = {"database": {"path": "/srv/rtsa/data/rtsa.db"}, "modules": {"tce": {"enabled": True}}}
    _derive_events_db_paths(raw)
    assert raw["modules"]["tce"]["events_db_path"] == "/srv/rtsa/data/rtsa.db"
    assert raw["modules"]["host_persistence_detector"]["events_db_path"] == "/srv/rtsa/data/rtsa.db"
    raw = {"database": {"path": "/srv/a.db"}, "modules": {"tce": {"events_db_path": "/explicit.db"}}}
    _derive_events_db_paths(raw)
    assert raw["modules"]["tce"]["events_db_path"] == "/explicit.db"
    print("Test 6 (TCE and host persistence read the configured database.path unless an explicit events_db_path is set) PASSED")


async def test_7_protected_targets_refused_on_alert_buttons():
    bot = make_bot()
    for unit in ("ssh.service", "sshd", "nginx", "rtsa.service"):
        assert bot._is_protected_systemd_unit(unit), unit
    assert not bot._is_protected_systemd_unit("lab-campaign.service")
    assert _pm2_button_target_refusal("all", pwd.getpwuid(os.getuid()).pw_name)
    assert _pm2_button_target_refusal("app", "root")
    assert _port_block_succeeded("🚫 Port 8080 diblokir") and not _port_block_succeeded("🚫 Refused to block port 22")
    replies = []

    class Resp:
        def is_done(self):
            return False

        async def send_message(self, content=None, **kwargs):
            replies.append(content)

    member = mock.Mock(spec=bot_module.discord.Member)
    member.id = 7
    role = mock.Mock()
    role.id = 2
    member.roles = [role]
    interaction = types.SimpleNamespace(type=bot_module.discord.InteractionType.component, data={"custom_id": "rtsa_action:stopservice:evt"}, user=member,
                                        response=Resp(), message=types.SimpleNamespace(id=99), followup=None)

    async def corr(event_id):
        return {"event_id": event_id}, {"systemd_unit": "ssh.service"}

    bot._get_port_correlation = corr
    with Capture() as cap:
        await bot.on_interaction(interaction)
    assert not cap.calls and replies and "dilindungi" in replies[0], replies
    print("Test 7 (stop/restart/disable of protected units, PM2 app 'all' and root/system users are refused on alert buttons) PASSED")


def test_8_alert_claims_survive_restart():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "alert_claims.json")
        store = PersistentClaimStore(path)
        store.set(1234, "operator-a")
        assert PersistentClaimStore(path).get(1234) == "operator-a", "a new process must see the claim"
        store.pop(1234)
        assert PersistentClaimStore(path).get(1234) is None
        with open(path, "w") as handle:
            handle.write("{corrupt")
        assert PersistentClaimStore(path).get(1) is None
        assert PersistentClaimStore(None).get(1) is None
        with open(path, "w") as handle:
            json.dump({"version": 1, "claims": {"5": ["old", 1.0]}}, handle)
        assert PersistentClaimStore(path).get(5) is None, "expired claims are dropped"
    print("Test 8 (alert-button claims persist across restarts, tolerate corrupt files and expire) PASSED")


async def test_9_hostile_domains_do_not_crash_open_commands():
    bot = make_bot()
    for value in ("../../../../etc/x", "a" * 300 + ".lab", "ok\x00x", "аpp‮x.lab.test"):
        text = await bot._check_domain(value)
        assert text.startswith("🔴"), text
        _, behind, _detail = await bot._check_behind_cloudflare(value)
        assert behind is None
    print("Test 9 (/cekdomain and /cfcheck answer 'resolution failed' for malformed hostnames instead of raising) PASSED")


async def test_10_background_modules_never_start_pm2_daemons():
    from core import process_correlation
    from core.cloudpanel_resolver import CloudPanelAsset
    from config.manager import CloudPanelMonitorConfig
    from modules.cloudpanel_monitor import CloudPanelMonitor
    me = pwd.getpwuid(os.getuid())
    with tempfile.TemporaryDirectory() as home:
        original_getpwnam = pwd.getpwnam
        pwd.getpwnam = lambda name: types.SimpleNamespace(pw_name=name, pw_uid=me.pw_uid, pw_gid=me.pw_gid, pw_dir=home, pw_shell="/bin/bash")
        try:
            monitor = CloudPanelMonitor(EventBus(), CloudPanelMonitorConfig(enabled=True))
            asset = CloudPanelAsset(domain="x.lab.test", linux_user="labuser", project_root=home, htdocs_path=home, nginx_vhost=None, pm2_user="labuser", discovered_at=0.0)
            with Capture() as cap:
                assert await monitor._detect_pm2_info(asset) is None
                assert await process_correlation._lookup_pm2_app("labuser", 1234, 1) is None
            assert not cap.calls
        finally:
            pwd.getpwnam = original_getpwnam
    print("Test 10 (CloudPanel monitor and process correlation skip `pm2 jlist` for users without a live PM2 daemon) PASSED")


def test_11_static_review_fixes():
    import time as _time
    from config.manager import _enforce_detection_only_remediation
    from core.php_analysis import _tokenize
    from core.state_store import atomic_write_text
    started = _time.monotonic()
    _tokenize("a" * 400_000)
    assert _time.monotonic() - started < 2.0, "PHP tokenizer must stay linear on long identifier runs (was quadratic)"
    _strings, calls = _tokenize("<?php foo (1); baz; obj->m(2);")
    assert [c.name for c in calls] == ["foo", "m"], calls
    assert not bot_module._VALID_PM2_ARGS.fullmatch("stop app\nid") and bot_module._VALID_PM2_ARGS.fullmatch("stop app")
    assert not bot_module._VALID_LINUX_USERNAME.fullmatch("lab-001\n")
    raw = {"response_engine": {"detection_only": True}, "modules": {"host_persistence_detector": {"auto_remediate": True}}}
    _enforce_detection_only_remediation(raw)
    assert raw["modules"]["host_persistence_detector"]["auto_remediate"] is False
    raw = {"response_engine": {"detection_only": False}, "modules": {"host_persistence_detector": {"auto_remediate": True}}}
    _enforce_detection_only_remediation(raw)
    assert raw["modules"]["host_persistence_detector"]["auto_remediate"] is True
    with tempfile.TemporaryDirectory() as d:
        victim = os.path.join(d, "victim")
        with open(victim, "w") as handle:
            handle.write("keep")
        tenant = os.path.join(d, "tenant")
        os.mkdir(tenant)
        os.symlink(victim, os.path.join(tenant, "authorized_keys"))
        atomic_write_text(os.path.join(tenant, "authorized_keys"), "new", tenant_tree=True)
        assert open(victim).read() == "keep" and not os.path.islink(os.path.join(tenant, "authorized_keys"))
        os.symlink(d, os.path.join(tenant, "up"))
        try:
            atomic_write_text(os.path.join(tenant, "up", "x"), "y", tenant_tree=True)
            raise AssertionError("tenant-tree write followed a symlinked directory")
        except OSError:
            pass
    print("Test 11 (linear PHP tokenizer, newline-free validators, detection_only disables host remediation, tenant-tree writes never follow symlinks) PASSED")


async def main() -> None:
    await test_1_pm2start_respects_detection_only()
    await test_2_read_only_pm2_commands_never_spawn_a_daemon()
    test_3_process_discovery_works_with_real_psutil()
    test_4_rtsa_children_are_not_flagged_for_expected_rules()
    test_5_fim_baseline_written_only_when_changed()
    test_6_events_db_path_follows_database_path()
    await test_7_protected_targets_refused_on_alert_buttons()
    test_8_alert_claims_survive_restart()
    await test_9_hostile_domains_do_not_crash_open_commands()
    await test_10_background_modules_never_start_pm2_daemons()
    test_11_static_review_fixes()
    print("\nALL VALIDATION CAMPAIGN FIX TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
