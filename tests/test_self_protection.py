import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.self_protection import SelfProtectionMonitor
from core.state_store import atomic_write_json


async def main():
    bus = EventBus()
    mon = SelfProtectionMonitor(
        bus, enabled=True, install_dir="/opt/security/rtsa",
        config_paths={"/opt/security/rtsa/config/config.yaml"},
        systemd_unit="rtsa.service",
        detector_disabled_threshold_seconds=1.0,
        baseline_paths={"/tmp/rtsa_self_protection_test_baseline.json"},
    )
    await mon.subscribe()

    captured = []

    async def _capture(event):
        captured.append(event)

    await bus.subscribe("test_capture", _capture, categories=None)

    def count(category):
        return sum(1 for e in captured if e.category == category)

    await bus.publish(BaseEvent(
        source_module="fim", category=EventCategory.FILE_INTEGRITY_CHANGE, severity=Severity.LOW,
        message="x", metadata={"path": "/home/newus/site/file.php"},
    ))
    await asyncio.sleep(0.05)
    assert count(EventCategory.RTSA_SELF_TAMPER) == 0
    print("Test 1 (FIM change outside RTSA's install dir -- ignored) PASSED")

    await bus.publish(BaseEvent(
        source_module="fim", category=EventCategory.FILE_INTEGRITY_CHANGE, severity=Severity.LOW,
        message="x", metadata={"path": "/opt/security/rtsa/main.py"},
    ))
    await asyncio.sleep(0.05)
    assert count(EventCategory.RTSA_SELF_TAMPER) == 1
    print("Test 2 (FIM change inside RTSA's own install dir -- RTSA_SELF_TAMPER) PASSED")

    await bus.publish(BaseEvent(
        source_module="fim", category=EventCategory.FILE_INTEGRITY_CHANGE, severity=Severity.LOW,
        message="x", metadata={"path": "/opt/security/rtsa/config/config.yaml"},
    ))
    await asyncio.sleep(0.05)
    assert count(EventCategory.RTSA_CONFIG_CHANGED) == 1
    print("Test 3 (FIM change matching a registered config_path -- RTSA_CONFIG_CHANGED) PASSED")

    before = count(EventCategory.RTSA_SELF_TAMPER)
    await bus.publish(BaseEvent(
        source_module="systemd_monitor", category=EventCategory.SYSTEMD_SERVICE_CHANGED, severity=Severity.LOW,
        message="x", metadata={"unit": "nginx.service"},
    ))
    await asyncio.sleep(0.05)
    assert count(EventCategory.RTSA_SELF_TAMPER) == before
    print("Test 4 (systemd change for an unrelated unit -- ignored) PASSED")

    await bus.publish(BaseEvent(
        source_module="systemd_monitor", category=EventCategory.SYSTEMD_SERVICE_CHANGED, severity=Severity.LOW,
        message="x", metadata={"unit": "rtsa.service"},
    ))
    await asyncio.sleep(0.05)
    assert count(EventCategory.RTSA_SELF_TAMPER) == before + 1
    print("Test 5 (systemd change for RTSA's own unit -- RTSA_SELF_TAMPER) PASSED")

    events = mon.check_detector_disabled({"cap_a": False}, now=1000.0)
    assert events == [], "first tick just seeds state, no alert yet"
    events = mon.check_detector_disabled({"cap_a": False}, now=1002.0)
    assert len(events) == 1 and events[0].category == EventCategory.RTSA_DETECTOR_DISABLED
    events = mon.check_detector_disabled({"cap_a": False}, now=1003.0)
    assert events == [], "must not re-alert while still disabled"
    events = mon.check_detector_disabled({"cap_a": True}, now=1004.0)
    assert events == [], "recovery clears state silently, no alert-on-recovery"
    events = mon.check_detector_disabled({"cap_a": False}, now=2000.0)
    assert events == [], "freshly re-disabled capability must re-seed, not immediately re-alert"
    events = mon.check_detector_disabled({"cap_a": False}, now=2002.0)
    assert len(events) == 1
    print("Test 6 (detector-disabled: seed / alert-once / no-dup / silent-recovery / re-arms) PASSED")

    path = "/tmp/rtsa_self_protection_test_baseline.json"
    atomic_write_json(path, {"a": 1})
    assert mon.check_baseline_tamper() == [], "own write must not be flagged as tamper"
    os.utime(path, None)
    events = mon.check_baseline_tamper()
    assert len(events) == 1 and events[0].category == EventCategory.RTSA_BASELINE_TAMPER
    assert mon.check_baseline_tamper() == [], "must not duplicate the alert for the same still-tampered file"
    atomic_write_json(path, {"a": 2})
    assert mon.check_baseline_tamper() == [], "RTSA's own re-write clears the tamper condition"
    os.remove(path)
    print("Test 7 (baseline tamper: no-tamper-after-write / detected-once / no-dup / clears-on-rewrite) PASSED")

    disabled_mon = SelfProtectionMonitor(
        bus, enabled=False, install_dir="/opt/security/rtsa",
        config_paths=set(), systemd_unit="rtsa.service",
    )
    assert disabled_mon.check_detector_disabled({"cap_b": False}, now=5000.0) == []
    assert disabled_mon.check_detector_disabled({"cap_b": False}, now=6000.0) == []
    print("Test 8 (self_protection.enabled=False -- no alerts emitted at all) PASSED")

    print("\nALL SELF-PROTECTION MONITOR REGRESSION TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(), timeout=30))
