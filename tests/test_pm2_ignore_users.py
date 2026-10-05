import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from config.manager import Pm2MonitorConfig, Pm2UserConfig
from core.event_bus import EventBus
from modules.pm2_monitor import Pm2Monitor


def main():
    bus = EventBus()

    cfg = Pm2MonitorConfig(enabled=True, ignore_users=["jens"])
    mon = Pm2Monitor(bus, cfg)
    mon._discovered_users = ["jens", "newus-admin", "kupastuntas"]
    effective = {u.user for u in mon._effective_users()}
    assert "jens" not in effective, f"ignore_users must exclude the user from auto-discovered set: {effective}"
    assert effective == {"newus-admin", "kupastuntas"}, effective
    print("Test 1 (ignore_users excludes an auto-discovered user) PASSED")

    cfg2 = Pm2MonitorConfig(
        enabled=True, ignore_users=["jens"],
        users=[Pm2UserConfig(user="jens", include=["important-app"])],
    )
    mon2 = Pm2Monitor(bus, cfg2)
    mon2._discovered_users = []
    effective2 = {u.user for u in mon2._effective_users()}
    assert "jens" not in effective2, (
        f"ignore_users must override an explicit config.users entry for the same user too: {effective2}"
    )
    print("Test 2 (ignore_users overrides an explicit config.users entry) PASSED")

    cfg3 = Pm2MonitorConfig(enabled=True, ignore_users=[])
    mon3 = Pm2Monitor(bus, cfg3)
    mon3._discovered_users = ["jens", "newus-admin"]
    effective3 = {u.user for u in mon3._effective_users()}
    assert effective3 == {"jens", "newus-admin"}, "empty ignore_users must not exclude anyone"
    print("Test 3 (empty ignore_users -- backward compatible, no exclusion) PASSED")

    print("\nALL PM2 IGNORE_USERS TESTS PASSED")


main()
