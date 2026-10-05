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


def make_monitor(max_active=5, max_paths=3):
    cfg = NginxMonitorConfig(
        enabled=True, scan_batch_max_active=max_active, scan_batch_max_tracked_paths=max_paths,
    )
    mon = NginxMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_meta(domain, source):
        return "", {"domain": domain or "example.com"}
    mon._build_web_attack_metadata = fake_meta
    return mon, published


async def main() -> None:
    mon, pub = make_monitor(max_active=5, max_paths=100)
    for i in range(50):
        mon._record_scan_attempt(f"9.9.9.{i}", "/.env", None, 0.5, SOURCE)
    assert len(mon._scan_batches) == 5, (
        f"a distributed scan from 50 unique source IPs must never grow _scan_batches past "
        f"scan_batch_max_active=5, got {len(mon._scan_batches)}"
    )
    assert mon._scan_batches_overflow_total == 45, (
        f"the 45 excess unique-key attempts must be counted as overflow, not silently created "
        f"anyway, got {mon._scan_batches_overflow_total}"
    )
    print(
        "Scenario 1 (50 unique attacker IPs against scan_batch_max_active=5 -- table stays "
        "capped at 5, 45 overflow attempts counted, not silently unbounded) PASSED"
    )

    for state in mon._scan_batches.values():
        assert "task" not in state, (
            "no per-key asyncio task may exist on a scan-batch state -- flushing must be done "
            "by a single shared sweep, not one-task-per-attacker-key"
        )
    print("Scenario 2 (no per-key asyncio task exists on any scan-batch state) PASSED")

    mon2, pub2 = make_monitor(max_active=1000, max_paths=3)
    for i in range(50):
        mon2._record_scan_attempt("9.9.9.9", f"/path{i}", "example.com", 0.5, SOURCE)
    state = mon2._scan_batches["9.9.9.9:example.com"]
    assert len(state["paths"]) == 3, (
        f"tracked unique paths per batch must be capped at scan_batch_max_tracked_paths=3, "
        f"got {len(state['paths'])}"
    )
    assert state["distinct_paths_seen"] == 50, (
        f"the TRUE distinct-path count must still be tracked even once the detail cap is hit "
        f"(for accurate reporting), got {state['distinct_paths_seen']}"
    )
    assert state["count"] == 50
    print(
        "Scenario 3 (50 unique paths from one attacker, tracked-path detail capped at 3, but "
        "true distinct_paths_seen=50 and request count=50 both stay accurate) PASSED"
    )

    mon3, pub3 = make_monitor(max_active=1000, max_paths=100)
    mon3._record_scan_attempt("1.2.3.4", "/.env", "example.com", 0.9, SOURCE)
    state3 = mon3._scan_batches["1.2.3.4:example.com"]
    state3["first_seen"] -= 999.0
    await mon3._sweep_scan_batches()
    assert "1.2.3.4:example.com" not in mon3._scan_batches, "a due batch must be removed from the active table once flushed"
    assert len(pub3) == 1
    assert pub3[0].category == EventCategory.WEB_ATTACK_SCAN
    print("Scenario 4 (a due batch is flushed and published by the shared sweep, then removed from the active table) PASSED")

    mon4, pub4 = make_monitor(max_active=1000, max_paths=100)
    mon4._record_scan_attempt("5.5.5.5", "/.env", "example.com", 0.9, SOURCE)
    await mon4._sweep_scan_batches()
    assert "5.5.5.5:example.com" in mon4._scan_batches, "a batch whose window has NOT elapsed must not be flushed early"
    assert len(pub4) == 0
    print("Scenario 5 (a batch whose aggregation window has not elapsed yet is never flushed early) PASSED")

    print("\nALL NGINX SCAN-BATCH BOUND TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
