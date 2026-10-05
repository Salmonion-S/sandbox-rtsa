import asyncio
import os
import pwd
import shutil
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import discord_integration.bot as bot_module
import core.firewall_manager as firewall_manager
from config.manager import (
    CloudflareConfig, DiscordConfig, ModulesConfig, ResponseEngineConfig, RTSAConfig,
)
from core.event_bus import EventBus
from discord_integration.bot import RTSABot


class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass
    def enqueue_ban(self, *a, **k): pass
    def enqueue_cloudflare_rules_created(self, *a, **k): pass
    def enqueue_cloudflare_rules_removed(self, *a, **k): pass
    def enqueue_firewall_rule_created(self, *a, **k): pass
    def enqueue_firewall_rule_removed_by_port(self, *a, **k): pass


def make_bot():
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False),
        modules=ModulesConfig(),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)


class CountingTerminate:
    def __init__(self, ok=True, detail="killed", delay=0.05):
        self.calls = []
        self.ok = ok
        self.detail = detail
        self.delay = delay

    def __call__(self, pid, expected_create_time=None, timeout=3.0, *, force=True):
        import time
        self.calls.append(pid)
        time.sleep(self.delay)
        return self.ok, self.detail


async def main():
    bot = make_bot()
    fake_terminate = CountingTerminate()
    orig_terminate = bot_module.terminate_process
    bot_module.terminate_process = fake_terminate
    try:
        status1, msg1 = await bot._kill_process(9001, None, "alice")
        assert status1 == "success"
        assert len(fake_terminate.calls) == 1

        status2, msg2 = await bot._kill_process(9001, None, "bob")
        assert status2 == "success", (status2, msg2)
        assert len(fake_terminate.calls) == 1, "a sequential re-click on an already-SUCCEEDED target must not re-execute"
        assert msg2 == msg1, "the cached result must be returned verbatim on re-click"
    finally:
        bot_module.terminate_process = orig_terminate
    print("Scenario 1 (single click executes once; immediate re-click returns cached result, no re-execution) PASSED")

    bot2 = make_bot()
    fake_terminate2 = CountingTerminate(delay=0.1)
    bot_module.terminate_process = fake_terminate2
    try:
        results = await asyncio.gather(
            bot2._kill_process(9002, None, "alice"),
            bot2._kill_process(9002, None, "bob"),
            bot2._kill_process(9002, None, "carol"),
        )
        assert len(fake_terminate2.calls) == 1, (
            f"3 concurrent clicks on the SAME target must result in exactly 1 real execution, "
            f"got {len(fake_terminate2.calls)}"
        )
        statuses = {r[0] for r in results}
        assert "success" in statuses or "in_progress" in statuses
    finally:
        bot_module.terminate_process = orig_terminate
    print("Scenario 2 (concurrent identical interactions execute exactly once) PASSED")

    bot3 = make_bot()
    fake_terminate3 = CountingTerminate(delay=0.05)
    bot_module.terminate_process = fake_terminate3
    try:
        await asyncio.gather(
            bot3._kill_process(9003, None, "alice"),
            bot3._kill_process(9004, None, "alice"),
        )
        assert sorted(fake_terminate3.calls) == [9003, 9004], (
            f"two DIFFERENT pids must both execute independently: {fake_terminate3.calls}"
        )
    finally:
        bot_module.terminate_process = orig_terminate
    print("Scenario 3 (unrelated targets execute independently, never blocked by each other) PASSED")

    bot4 = make_bot()
    fake_terminate4 = CountingTerminate(delay=0.05)
    bot_module.terminate_process = fake_terminate4
    try:
        r1, r2 = await asyncio.gather(
            bot4._kill_process(9005, None, "alice"),
            bot4._kick_ssh_session(9005, 0.0, "bob"),
        )
        assert len(fake_terminate4.calls) == 1, (
            f"Kill Process and Kick SSH Session targeting the SAME pid must not both execute: "
            f"{fake_terminate4.calls}"
        )
    finally:
        bot_module.terminate_process = orig_terminate
    print("Scenario 4 (Kill Process + Kick SSH Session on the same pid share one lock) PASSED")

    bot5 = make_bot()
    block_calls = []

    async def fake_block_port(backend, port):
        block_calls.append(port)
        await asyncio.sleep(0.05)
        return True, f"rule ditambahkan untuk port {port}"

    async def fake_is_port_blocked(backend, port):
        return len(block_calls) > 0

    orig_block, orig_is_blocked = firewall_manager.block_port, firewall_manager.is_port_blocked
    firewall_manager.block_port = fake_block_port
    firewall_manager.is_port_blocked = fake_is_port_blocked
    orig_which = shutil.which
    shutil.which = lambda n: f"/usr/sbin/{n}"
    try:
        results = await asyncio.gather(
            bot5._block_port(8080, "alice", "test"),
            bot5._block_port(8080, "bob", "test"),
        )
        assert len(block_calls) == 1, f"2 concurrent Block Port 8080 clicks must result in 1 real block: {block_calls}"
    finally:
        firewall_manager.block_port = orig_block
        firewall_manager.is_port_blocked = orig_is_blocked
        shutil.which = orig_which
    print("Scenario 5 (Block Port immediately followed by Block Port does not duplicate) PASSED")

    bot6 = make_bot()
    block_calls2 = []

    async def fake_block_port2(backend, port):
        block_calls2.append(port)
        await asyncio.sleep(0.05)
        return True, "ok"

    async def fake_is_port_blocked2(backend, port):
        return True

    firewall_manager.block_port = fake_block_port2
    firewall_manager.is_port_blocked = fake_is_port_blocked2
    shutil.which = lambda n: f"/usr/sbin/{n}"
    try:
        await asyncio.gather(
            bot6._block_port(8081, "alice", "test"),
            bot6._block_port(8082, "alice", "test"),
        )
        assert sorted(block_calls2) == [8081, 8082], f"unrelated ports must both execute: {block_calls2}"
    finally:
        firewall_manager.block_port = orig_block
        firewall_manager.is_port_blocked = orig_is_blocked
        shutil.which = orig_which
    print("Scenario 6 (unrelated ports do not block each other) PASSED")

    bot7 = make_bot()
    pm2_calls = []
    real_username = pwd.getpwuid(os.getuid()).pw_name

    async def fake_run_pm2(account, cwd, cmd, timeout):
        pm2_calls.append(cmd)
        await asyncio.sleep(0.05)
        if cmd.startswith("jlist"):
            return 0, '[{"name":"myapp","pm2_env":{"status":"stopped"}}]', ""
        return 0, "stopped", ""

    bot7._run_pm2_as_user_detailed = fake_run_pm2
    try:
        results = await asyncio.gather(
            bot7._pm2_port_action(real_username, "myapp", "stop", "alice"),
            bot7._pm2_port_action(real_username, "myapp", "stop", "bob"),
        )
        stop_calls = [c for c in pm2_calls if c.startswith("stop")]
        assert len(stop_calls) == 1, f"2 concurrent PM2 stop clicks must result in 1 real stop: {pm2_calls}"
    finally:
        pass
    print("Scenario 7 (PM2 stop immediately followed by PM2 stop does not duplicate) PASSED")

    bot8 = make_bot()
    fake_terminate5 = CountingTerminate(ok=False, detail="permission denied", delay=0.01)
    bot_module.terminate_process = fake_terminate5
    try:
        status_fail, _msg = await bot8._kill_process(9006, None, "alice")
        assert status_fail == "failed"
        fake_terminate5.ok = True
        fake_terminate5.detail = "killed"
        status_retry, _msg2 = await bot8._kill_process(9006, None, "alice")
        assert status_retry == "success", "a FAILED action must allow an immediate retry, not leave a permanent lock"
        assert len(fake_terminate5.calls) == 2
    finally:
        bot_module.terminate_process = orig_terminate
    print("Scenario 8 (failed action does not leave a permanent lock, retry succeeds) PASSED")

    bot9 = make_bot()
    fake_terminate6 = CountingTerminate(delay=0.01)
    bot_module.terminate_process = fake_terminate6
    try:
        await bot9._kill_process(9007, None, "alice")
        status3, msg3 = await bot9._kill_process(9007, None, "mallory")
        assert status3 == "success"
        assert len(fake_terminate6.calls) == 1
        assert "9007" in msg3
    finally:
        bot_module.terminate_process = orig_terminate
    print("Scenario 9 (a different user's re-click on an already-handled target gets the cached result) PASSED")

    bot10 = make_bot()
    real_username10 = pwd.getpwuid(os.getuid()).pw_name

    async def fake_run_pm2_mismatch(account, cwd, cmd, timeout):
        await asyncio.sleep(0.01)
        if cmd.startswith("jlist"):
            return 0, '[{"name":"myapp","pm2_env":{"status":"online"}}]', ""
        return 0, "stopped", ""

    bot10._run_pm2_as_user_detailed = fake_run_pm2_mismatch
    _, msg_mismatch = "stop", await bot10._pm2_port_action(real_username10, "myapp", "stop", "alice")
    assert "TIDAK berubah" in msg_mismatch, (
        f"a command that exits 0 but jlist shows the app is still online after 'stop' must report "
        f"FAILED_VERIFICATION, never a blind SUCCESS: {msg_mismatch}"
    )

    bot11 = make_bot()

    async def fake_run_pm2_jlist_fails(account, cwd, cmd, timeout):
        await asyncio.sleep(0.01)
        if cmd.startswith("jlist"):
            return 1, "", "pm2 daemon not reachable"
        return 0, "stopped", ""

    bot11._run_pm2_as_user_detailed = fake_run_pm2_jlist_fails
    msg_unverified = await bot11._pm2_port_action(real_username10, "otherapp", "stop", "alice")
    assert "belum terverifikasi" in msg_unverified, (
        f"a command that exits 0 but whose verification step (jlist) itself cannot be read must report "
        f"ACTION_EXECUTED_UNVERIFIED, never a blind SUCCESS: {msg_unverified}"
    )

    bot12 = make_bot()

    async def fake_run_pm2_match(account, cwd, cmd, timeout):
        await asyncio.sleep(0.01)
        if cmd.startswith("jlist"):
            return 0, '[{"name":"thirdapp","pm2_env":{"status":"stopped"}}]', ""
        return 0, "stopped", ""

    bot12._run_pm2_as_user_detailed = fake_run_pm2_match
    msg_verified = await bot12._pm2_port_action(real_username10, "thirdapp", "stop", "alice")
    assert "terverifikasi" in msg_verified and "belum terverifikasi" not in msg_verified, (
        f"a command whose post-action state genuinely matches the expected outcome must report "
        f"verified SUCCESS, distinct from the unverified/mismatch cases: {msg_verified}"
    )
    print(
        "Scenario 10 (result verification distinguishes SUCCESS / FAILED_VERIFICATION / "
        "ACTION_EXECUTED_UNVERIFIED -- never a blind success from exit code alone) PASSED"
    )

    bot13 = make_bot()
    fake_terminate7 = CountingTerminate(delay=0.0)
    bot_module.terminate_process = fake_terminate7
    try:
        for pid in range(10050, 10050 + 4500):
            await bot13._kill_process(pid, None, "alice")
        assert len(bot13._action_lock) <= 4000, (
            f"the idempotency cache must stay bounded even after 4500 distinct targets, "
            f"got {len(bot13._action_lock)}"
        )
    finally:
        bot_module.terminate_process = orig_terminate
    print("Scenario 11 (idempotency cache stays bounded under thousands of distinct targets) PASSED")

    print("\nALL ACTION LOCK BOT INTEGRATION TESTS PASSED")


asyncio.run(main())
