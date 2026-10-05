from __future__ import annotations

import ast
import asyncio
import os
import pwd
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from config.manager import CloudflareConfig, CloudPanelMonitorConfig, DiscordConfig, Pm2MonitorConfig, RTSAConfig
from core.child_env import INHERITED_KEYS, tenant_environment
from core.cloudpanel_resolver import CloudPanelAsset
from core.event_bus import EventBus
from discord_integration.bot import RTSABot
from modules import pm2_monitor as pm2_module
from modules.cloudpanel_monitor import CloudPanelMonitor
from modules.pm2_monitor import Pm2Monitor

SECRETS = {
    "RTSA_DISCORD_BOT_TOKEN": "discord-token-must-not-leak-0123456789",
    "RTSA_CLOUDFLARE_API_TOKEN": "cloudflare-token-must-not-leak-0123456789",
    "RTSA_LB_REPORT_KEY": "lb-report-key-must-not-leak-0123456789",
    "AWS_SECRET_ACCESS_KEY": "aws-secret-must-not-leak-0123456789",
    "SOME_OTHER_API_TOKEN": "generic-token-must-not-leak-0123456789",
}
ALLOWED = set(INHERITED_KEYS) | {"HOME", "USER", "LOGNAME", "SHELL"}
ACCOUNT = pwd.getpwuid(os.getuid())


def seed_secrets() -> None:
    os.environ.update(SECRETS)


def assert_clean(env: dict, extra_keys: set = frozenset(), where: str = "") -> None:
    assert env is not None, f"{where}: no explicit env was passed, so the child would inherit RTSA's whole environment"
    leaked = [k for k, v in env.items() if k in SECRETS or v in SECRETS.values()]
    assert not leaked, f"{where}: secrets reached a tenant-user child: {leaked}"
    unexpected = set(env) - ALLOWED - set(extra_keys)
    assert not unexpected, f"{where}: unexpected variables passed to a tenant-user child: {sorted(unexpected)}"
    assert env["HOME"] == ACCOUNT.pw_dir and env["USER"] == ACCOUNT.pw_name and env["LOGNAME"] == ACCOUNT.pw_name, where


class FakeProc:
    returncode = 0

    async def communicate(self):
        return b"[]", b""

    async def wait(self):
        return 0

    def kill(self):
        return None


class Capture:
    def __init__(self) -> None:
        self.calls = []
        self.original = asyncio.create_subprocess_exec

    async def __call__(self, *argv, **kwargs):
        self.calls.append((argv, kwargs))
        return FakeProc()

    def __enter__(self):
        asyncio.create_subprocess_exec = self
        return self

    def __exit__(self, *exc):
        asyncio.create_subprocess_exec = self.original
        return False


def test_1_builder_is_an_allow_list():
    seed_secrets()
    env = tenant_environment(ACCOUNT, {"PM2_HOME": "/x/.pm2", "GIT_TERMINAL_PROMPT": "0"})
    assert_clean(env, {"PM2_HOME", "GIT_TERMINAL_PROMPT"}, "tenant_environment")
    assert env["PM2_HOME"] == "/x/.pm2" and env["PATH"]
    os.environ.pop("PATH", None)
    try:
        assert tenant_environment(ACCOUNT)["PATH"], "a missing PATH falls back to a fixed safe default"
    finally:
        os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/node22/bin"
    print("Test 1 (tenant environment is an allow-list: no secret-named or arbitrary variables, HOME/USER/LOGNAME set) PASSED")


async def test_2_pm2_monitor_poll_does_not_leak_tokens():
    seed_secrets()
    monitor = Pm2Monitor(EventBus(), Pm2MonitorConfig(enabled=True))
    original = pm2_module.pm2_daemon_alive
    pm2_module.pm2_daemon_alive = lambda path: True
    try:
        with Capture() as cap:
            await monitor._list_pm2_processes(ACCOUNT.pw_name)
    finally:
        pm2_module.pm2_daemon_alive = original
    assert len(cap.calls) == 1, cap.calls
    argv, kwargs = cap.calls[0]
    assert kwargs.get("user") == ACCOUNT.pw_uid and argv[-1] == "pm2 jlist"
    assert_clean(kwargs.get("env"), {"PM2_HOME"}, "pm2_monitor")
    print("Test 2 (PM2 monitor runs the tenant login shell with an allow-listed environment: no Discord/Cloudflare tokens) PASSED")


async def test_3_cloudpanel_monitor_passes_an_explicit_clean_env():
    seed_secrets()
    monitor = CloudPanelMonitor(EventBus(), CloudPanelMonitorConfig(enabled=True))
    asset = CloudPanelAsset(domain="x.lab.test", linux_user=ACCOUNT.pw_name, project_root=ACCOUNT.pw_dir, htdocs_path="/tmp", nginx_vhost=None, pm2_user=ACCOUNT.pw_name,
                            discovered_at=0.0)
    with Capture() as cap:
        await monitor._run_as_site_user(asset, "node --version")
    assert cap.calls, "the CloudPanel monitor did not spawn"
    argv, kwargs = cap.calls[0]
    assert kwargs.get("user") == ACCOUNT.pw_uid
    assert_clean(kwargs.get("env"), set(), "cloudpanel_monitor")
    print("Test 3 (CloudPanel monitor passes an explicit allow-listed env instead of inheriting RTSA's environment) PASSED")


async def test_4_bot_run_as_user_real_child_sees_no_secrets():
    seed_secrets()
    bot = RTSABot(DiscordConfig(enabled=True), RTSAConfig(cloudflare=CloudflareConfig(enabled=False)), EventBus(), db_worker=None, supervisor=None)
    code, out, err = await bot._run_as_user_detailed(ACCOUNT, "/tmp", ["/usr/bin/env"], 10.0, {"GIT_TERMINAL_PROMPT": "0"})
    text = out.decode()
    assert code == 0, err
    for value in SECRETS.values():
        assert value not in text, "a real child process printed a secret from its environment"
    names = {line.split("=", 1)[0] for line in text.splitlines() if "=" in line}
    assert names <= ALLOWED | {"GIT_TERMINAL_PROMPT"}, sorted(names - ALLOWED)
    with Capture() as cap:
        await bot._run_git_as_user(ACCOUNT, "/tmp", ["status"], 5.0)
    assert_clean(cap.calls[0][1].get("env"), {"GIT_TERMINAL_PROMPT", "GIT_SSH_COMMAND"}, "bot git as user")
    print("Test 4 (a real child spawned by the bot as the project user sees only the allow-listed environment; git keeps its two GIT_* settings) PASSED")


def test_5_no_privilege_drop_without_an_explicit_env():
    offenders = []
    copies = []
    for directory in ("core", "modules", "discord_integration", "database", "config"):
        for name in sorted(os.listdir(os.path.join(_REPO_ROOT, directory))):
            if not name.endswith(".py"):
                continue
            rel = f"{directory}/{name}"
            source = open(os.path.join(_REPO_ROOT, rel), encoding="utf-8").read()
            for pattern in ("dict(os.environ)", "os.environ.copy()", "{**os.environ"):
                if pattern in source:
                    copies.append(f"{rel}: {pattern}")
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, ast.Call):
                    keys = {kw.arg for kw in node.keywords}
                    if "user" in keys and ("preexec_fn" in keys or "group" in keys or ast.unparse(node.func).endswith(("create_subprocess_exec", "Popen", "run"))):
                        if "env" not in keys:
                            offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, f"subprocesses that drop to a tenant user without an explicit env: {offenders}"
    assert not copies, f"full environment copies in source: {copies}"
    print("Test 5 (every privilege-dropping subprocess passes an explicit env; no full os.environ copies remain in source) PASSED")


async def main() -> None:
    test_1_builder_is_an_allow_list()
    await test_2_pm2_monitor_poll_does_not_leak_tokens()
    await test_3_cloudpanel_monitor_passes_an_explicit_clean_env()
    await test_4_bot_run_as_user_real_child_sees_no_secrets()
    test_5_no_privilege_drop_without_an_explicit_env()
    for key in SECRETS:
        os.environ.pop(key, None)
    print("\nALL TENANT ENV ISOLATION TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
