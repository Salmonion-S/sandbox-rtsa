import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig
from core.datatypes import EventCategory
from core.event_bus import EventBus
from modules.nginx_monitor import NginxMonitor, _LogSource

SOURCE = _LogSource(log_file="/var/log/nginx/access.log", line_number=1, raw_line="")


def make_monitor(max_concurrent=2, max_pending=5):
    cfg = NginxMonitorConfig(
        enabled=True, rce_correlation_enabled=False,
        max_concurrent_verify_fetches=max_concurrent, max_pending_verify_tasks=max_pending,
    )
    mon = NginxMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_meta(domain, source):
        return "", {"domain": domain or "example.com"}
    mon._build_web_attack_metadata = fake_meta
    return mon, published


async def main() -> None:
    in_flight = {"current": 0, "max_seen": 0}
    release = asyncio.Event()

    async def slow_classify(domain, path):
        in_flight["current"] += 1
        in_flight["max_seen"] = max(in_flight["max_seen"], in_flight["current"])
        await release.wait()
        in_flight["current"] -= 1
        return "false_positive", None, None

    mon, pub = make_monitor(max_concurrent=2, max_pending=5)
    mon._classify_response = slow_classify

    for i in range(20):
        await mon._check_web_attack_signature(
            f"9.9.9.{i}", "/.env", "GET", "", 200, "example.com", SOURCE,
        )
        assert len(mon._verify_tasks) <= mon.config.max_pending_verify_tasks, (
            f"20 signature-matching 2xx requests must never let pending verify tasks exceed "
            f"max_pending_verify_tasks={mon.config.max_pending_verify_tasks}, saw "
            f"{len(mon._verify_tasks)} after request {i}"
        )

    await asyncio.sleep(0.05)
    assert in_flight["max_seen"] <= 2, (
        f"max_concurrent_verify_fetches=2 must bound actual concurrent live-content fetches "
        f"regardless of how many requests matched a signature, saw {in_flight['max_seen']} concurrent"
    )
    assert mon._verify_dropped_total > 0, (
        f"once the pending cap is hit, excess verify attempts must be counted as dropped "
        f"(and downgraded to a cheap scan-attempt record) rather than silently spawning more "
        f"unbounded tasks -- got _verify_dropped_total={mon._verify_dropped_total}"
    )
    print(
        f"Scenario 1 (20 concurrent signature-matching 2xx hits: pending task count bounded "
        f"at {mon.config.max_pending_verify_tasks}, concurrent live fetches bounded at "
        f"{in_flight['max_seen']} <= 2, {mon._verify_dropped_total} excess requests downgraded "
        f"to cheap scan-attempt recording instead of spawning unbounded tasks) PASSED"
    )

    release.set()
    await asyncio.sleep(0.05)
    for t in list(mon._verify_tasks):
        await t
    assert len(mon._verify_tasks) == 0, "all verify tasks must drain and self-remove once released"
    print("Scenario 2 (verify tasks drain cleanly once the slow fetch completes) PASSED")

    print("\nALL NGINX VERIFY-TASK BOUND TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
