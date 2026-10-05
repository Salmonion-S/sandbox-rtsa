import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import SSHMonitorConfig
from core.event_bus import EventBus
from modules.ssh_monitor import SSHMonitor


def accepted_line(user: str, ip: str, port: int = 22345) -> str:
    return f"sshd[1]: Accepted publickey for {user} from {ip} port {port} ssh2"


async def main() -> None:
    release = asyncio.Event()
    started = {"n": 0}

    async def fake_enriched(user, ip, method, sport, keytype, fingerprint, line):
        started["n"] += 1
        await release.wait()

    mon = SSHMonitor(EventBus(), SSHMonitorConfig(enabled=True, max_pending_background_tasks=3))
    mon._publish_login_enriched = fake_enriched
    published = []
    mon.publish = lambda ev: published.append(ev)

    for i in range(10):
        mon._process_line(accepted_line(f"attacker{i}", f"9.9.9.{i}"))
    await asyncio.sleep(0.05)

    assert len(mon._background_tasks) == 3, (
        f"pending background enrichment tasks must never exceed max_pending_background_tasks=3, "
        f"got {len(mon._background_tasks)}"
    )
    assert started["n"] == 3, f"only 3 enrichment coroutines should ever have been started, got {started['n']}"
    assert mon._background_tasks_overflow_total == 7, (
        f"the 7 excess logins must fall back to synchronous publish and be counted as overflow, "
        f"got {mon._background_tasks_overflow_total}"
    )
    assert len(published) == 7, (
        f"the 7 overflow logins must still be published (without enrichment), got {len(published)}"
    )
    print(
        "Scenario 1 (10 distinct-user SSH logins, max_pending_background_tasks=3 -- background "
        "task set stays capped at 3, remaining 7 fall back to synchronous publish, overflow counted) PASSED"
    )

    release.set()
    await asyncio.sleep(0.05)
    assert len(mon._background_tasks) == 0, "completed background tasks must be discarded from the tracked set"
    print("Scenario 2 (completed background tasks are discarded once they finish) PASSED")

    health = await mon.health()
    assert health["background_tasks_overflow_total"] == 7
    assert health["pending_background_tasks"] == 0
    print("Scenario 3 (health() reports background_tasks_overflow_total and pending_background_tasks) PASSED")

    mon2 = SSHMonitor(EventBus(), SSHMonitorConfig(enabled=True, max_pending_background_tasks=1000))
    started2 = {"n": 0}

    async def fake_enriched2(user, ip, method, sport, keytype, fingerprint, line):
        started2["n"] += 1

    mon2._publish_login_enriched = fake_enriched2
    published2 = []
    mon2.publish = lambda ev: published2.append(ev)
    mon2._process_line(accepted_line("trusted_normal_user", "1.1.1.1"))
    await asyncio.sleep(0.02)
    assert started2["n"] == 1, "well below the cap, a login must still take the enriched background path"
    assert mon2._background_tasks_overflow_total == 0
    print("Scenario 4 (well below the cap, the enriched background path is unaffected) PASSED")

    print("\nALL SSH BACKGROUND-TASK BOUND TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
