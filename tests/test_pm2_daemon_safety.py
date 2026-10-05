import asyncio
import os
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import pwd

from config.manager import Pm2MonitorConfig
from core.event_bus import EventBus
from modules.pm2_monitor import Pm2Monitor, pm2_daemon_alive


def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        assert pm2_daemon_alive(tmpdir) is False, (
            "a .pm2 home with no pm2.pid file at all must never be treated as a running daemon"
        )
    print("Scenario 1 (missing pm2.pid -- daemon is correctly reported as not alive) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "pm2.pid"), "w") as f:
            f.write("999999999\n")
        assert pm2_daemon_alive(tmpdir) is False, (
            "a pm2.pid referencing a PID that does not exist on this system (stale/crashed daemon) "
            "must never be treated as alive"
        )
    print("Scenario 2 (pm2.pid points at a dead/nonexistent PID -- correctly not alive) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "pm2.pid"), "w") as f:
            f.write(str(os.getpid()))
        assert pm2_daemon_alive(tmpdir) is False, (
            "a live PID alone is not sufficient -- the rpc.sock/pub.sock evidence must also be present, "
            "otherwise this is not confidently a running PM2 daemon"
        )
    print("Scenario 3 (live PID but missing rpc.sock/pub.sock -- not confidently alive, stays False) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "pm2.pid"), "w") as f:
            f.write(str(os.getpid()))
        open(os.path.join(tmpdir, "rpc.sock"), "w").close()
        open(os.path.join(tmpdir, "pub.sock"), "w").close()
        assert pm2_daemon_alive(tmpdir) is True, (
            "a live PID plus both rpc.sock and pub.sock present is the full positive signal -- must be alive"
        )
    print("Scenario 4 (live PID + both sockets present -- correctly reported alive) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "pm2.pid"), "w") as f:
            f.write("not-a-number")
        assert pm2_daemon_alive(tmpdir) is False, "a malformed pm2.pid must fail safe to 'not alive', never crash"
    print("Scenario 5 (malformed pm2.pid content -- fails safe to not-alive, no crash) PASSED")

    async def _async_scenarios() -> None:
        mon = Pm2Monitor(EventBus(), Pm2MonitorConfig(enabled=True))
        spawn_calls = {"n": 0}
        original = asyncio.create_subprocess_exec

        async def counting(*args, **kwargs):
            spawn_calls["n"] += 1
            raise AssertionError(
                "asyncio.create_subprocess_exec must NEVER be called for 'pm2 jlist' when the "
                "daemon-alive pre-check reports the daemon is not running -- this is the exact "
                "side effect (RTSA starting a user's PM2 God Daemon just to monitor it) the fix "
                "must eliminate"
            )

        asyncio.create_subprocess_exec = counting
        try:
            real_user = pwd.getpwuid(os.getuid()).pw_name
            result = await mon._list_pm2_processes(real_user, quiet=True)
            assert result is None, "no live PM2 daemon evidence -> must return None without spawning anything"
            assert spawn_calls["n"] == 0
        finally:
            asyncio.create_subprocess_exec = original

    asyncio.run(_async_scenarios())
    print(
        "Scenario 6 (no PM2 daemon evidence for a real, resolvable Linux user -- _list_pm2_processes "
        "never calls create_subprocess_exec, i.e. never risks starting 'pm2 jlist') PASSED"
    )

    print("\nALL PM2 DAEMON-SAFETY TESTS PASSED")


main()
