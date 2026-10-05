import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import CloudPanelMonitorConfig, Pm2MonitorConfig
from core.event_bus import EventBus
import modules.cloudpanel_monitor as cloudpanel_module
import modules.pm2_monitor as pm2_module
from modules.cloudpanel_monitor import CloudPanelMonitor
from modules.pm2_monitor import Pm2Monitor


class _FakeHealthMonitor:
    def __init__(self, allowed: bool, state: str = "NORMAL"):
        self._allowed = allowed
        self.state = state

    def should_run(self, capability: str) -> bool:
        return self._allowed


async def main() -> None:
    mon = Pm2Monitor(EventBus(), Pm2MonitorConfig(enabled=True))
    original = pm2_module.get_self_health_monitor
    pm2_module.get_self_health_monitor = lambda: _FakeHealthMonitor(allowed=False)
    called = {"poll": False}

    async def fake_maybe_refresh():
        called["poll"] = True

    mon._maybe_refresh_discovery = fake_maybe_refresh
    try:
        await mon._poll_once()
        assert not called["poll"], (
            "when should_run('pm2_routine_poll') is False (RTSA overloaded/emergency), the poll "
            "cycle must be skipped entirely -- no discovery refresh, no user polling, no subprocess work"
        )
    finally:
        pm2_module.get_self_health_monitor = original
    print("Scenario 1 (PM2 poll cycle fully skipped when should_run('pm2_routine_poll') is False) PASSED")

    mon2 = Pm2Monitor(EventBus(), Pm2MonitorConfig(enabled=True))
    pm2_module.get_self_health_monitor = lambda: _FakeHealthMonitor(allowed=True)
    called2 = {"effective_users": False}
    original_effective_users = mon2._effective_users

    def tracking_effective_users():
        called2["effective_users"] = True
        return original_effective_users()

    mon2._effective_users = tracking_effective_users
    try:
        await mon2._poll_once()
        assert called2["effective_users"], "when RTSA is NORMAL/DEGRADED, PM2 polling must proceed past the gate as usual"
    finally:
        pm2_module.get_self_health_monitor = original
    print("Scenario 2 (PM2 poll cycle proceeds normally when should_run allows it) PASSED")

    cp = CloudPanelMonitor(EventBus(), CloudPanelMonitorConfig(enabled=True))
    cp._is_first_ever_run = False
    original_cp = cloudpanel_module.get_self_health_monitor
    cloudpanel_module.get_self_health_monitor = lambda: _FakeHealthMonitor(allowed=False)
    poll_called = {"n": 0}

    async def fake_poll_once(is_first_ever_run):
        poll_called["n"] += 1

    cp._poll_once = fake_poll_once
    cp._sweep_stale_change_incidents = lambda: None
    try:
        await cp._poll_cycle()
        assert poll_called["n"] == 0, (
            "a ROUTINE (non-first-run) CloudPanel discovery cycle must be skipped entirely when "
            "should_run('cloudpanel_routine_discovery') is False -- this calls the real _poll_cycle "
            "method wired into run(), not a re-implementation"
        )
    finally:
        cloudpanel_module.get_self_health_monitor = original_cp
    print("Scenario 3 (CloudPanel routine discovery skipped under overload, via the real _poll_cycle method) PASSED")

    cp2 = CloudPanelMonitor(EventBus(), CloudPanelMonitorConfig(enabled=True))
    cp2._is_first_ever_run = True
    cloudpanel_module.get_self_health_monitor = lambda: _FakeHealthMonitor(allowed=False)
    poll_called2 = {"n": 0}

    async def fake_poll_once2(is_first_ever_run):
        poll_called2["n"] += 1

    cp2._poll_once = fake_poll_once2
    cp2._sweep_stale_change_incidents = lambda: None
    try:
        await cp2._poll_cycle()
        assert poll_called2["n"] == 1, (
            "the very first-ever CloudPanel baseline build must NEVER be skipped, even if RTSA "
            "is overloaded at startup -- without a baseline there is nothing to compare future "
            "changes against"
        )
    finally:
        cloudpanel_module.get_self_health_monitor = original_cp
    print("Scenario 4 (the first-ever baseline build is never skipped, even under overload) PASSED")

    print("\nALL RESOURCE GOVERNOR MODULE WIRING TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
