import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import HostPersistenceDetectorConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
import modules.host_persistence_detector as hpd
from modules.host_persistence_detector import HostPersistenceDetector

_REAL_SLEEP = asyncio.sleep


def make_detector(**overrides):
    cfg = HostPersistenceDetectorConfig(enabled=True, **overrides)
    mon = HostPersistenceDetector(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def timer_events(published):
    return [e for e in published if e.category == EventCategory.PERSISTENCE_TIMER_CHANGE]


async def _async_ret(value):
    return value


class FakeLoop:
    async def run_in_executor(self, _executor, fn, *args):
        return fn(*args)


async def main():
    loop = FakeLoop()

    mon, pub = make_detector()
    mon._baseline = {"timers": {}}
    hpd.list_systemd_timers = lambda: _async_ret({
        "evil-cleanup.timer": {"enabled": True, "active": True},
    })
    hpd.get_timer_properties = lambda unit: _async_ret({
        "Unit": "evil-cleanup.service",
        "FragmentPath": "/tmp/.hidden/evil-cleanup.timer",
        "TimersCalendar": "*-*-* *:00:00",
        "TimersMonotonic": "",
    })
    await mon._check_systemd_timers(loop, maintenance_active=False, first_run=False)
    events = timer_events(pub)
    assert len(events) == 1, events
    assert events[0].severity == Severity.HIGH, events[0].severity
    assert events[0].metadata["unit"] == "evil-cleanup.timer"
    assert events[0].metadata["triggers_unit"] == "evil-cleanup.service"
    assert "evil-cleanup.timer" in mon._baseline["timers"]
    print("Test 1 (timer baru, fragment di lokasi mencurigakan -- alert HIGH) PASSED")

    good_units = list(HostPersistenceDetectorConfig().systemd_known_good_units) + ["logrotate.*"]
    mon, pub = make_detector(systemd_known_good_units=good_units)
    mon._baseline = {"timers": {}}
    hpd.list_systemd_timers = lambda: _async_ret({
        "logrotate.timer": {"enabled": True, "active": True},
    })
    hpd.get_timer_properties = lambda unit: _async_ret({
        "Unit": "logrotate.service",
        "FragmentPath": "/usr/lib/systemd/system/logrotate.timer",
        "TimersCalendar": "daily",
        "TimersMonotonic": "",
    })
    await mon._check_systemd_timers(loop, maintenance_active=False, first_run=False)
    events = timer_events(pub)
    assert len(events) == 1, events
    assert events[0].severity == Severity.LOW, events[0].severity
    assert events[0].metadata["known_good"] is True
    assert "logrotate.timer" not in mon._timer_incidents_present
    print("Test 2 (timer known-good -- severity LOW, bukan incident) PASSED")

    mon, pub = make_detector()
    mon._baseline = {}
    hpd.list_systemd_timers = lambda: _async_ret({
        "some.timer": {"enabled": True, "active": True},
    })
    await mon._check_systemd_timers(loop, maintenance_active=False, first_run=True)
    assert timer_events(pub) == []
    assert "some.timer" in mon._baseline["timers"]
    print("Test 3 (first_run -- baseline di-seed, tidak ada alert) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"timers": {}}
    hpd.list_systemd_timers = lambda: _async_ret({
        "evil-cleanup.timer": {"enabled": True, "active": True},
    })
    hpd.get_timer_properties = lambda unit: _async_ret({
        "Unit": "evil-cleanup.service",
        "FragmentPath": "/tmp/.hidden/evil-cleanup.timer",
        "TimersCalendar": "*-*-* *:00:00",
        "TimersMonotonic": "",
    })
    await mon._check_systemd_timers(loop, maintenance_active=False, first_run=False)
    assert len(timer_events(pub)) == 1
    await mon._check_systemd_timers(loop, maintenance_active=False, first_run=False)
    assert len(timer_events(pub)) == 1, "state tak berubah tidak boleh memicu alert ulang"
    print("Test 4 (state timer tak berubah -- tidak ada alert berulang) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"timers": {}}
    hpd.list_systemd_timers = lambda: _async_ret({
        "evil-cleanup.timer": {"enabled": True, "active": True},
    })
    hpd.get_timer_properties = lambda unit: _async_ret({
        "Unit": "evil-cleanup.service",
        "FragmentPath": "/tmp/.hidden/evil-cleanup.timer",
        "TimersCalendar": "*-*-* *:00:00",
        "TimersMonotonic": "",
    })
    await mon._check_systemd_timers(loop, maintenance_active=False, first_run=False)
    assert "evil-cleanup.timer" in mon._timer_incidents_present
    hpd.list_systemd_timers = lambda: _async_ret({})
    await mon._check_systemd_timers(loop, maintenance_active=False, first_run=False)
    assert "evil-cleanup.timer" not in mon._timer_incidents_present
    assert mon._baseline["timers"] == {}
    print("Test 5 (timer hilang -- incident diresolve, baseline dibersihkan) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"timers": {"quiet.timer": {"enabled": False, "active": False}}}
    hpd.list_systemd_timers = lambda: _async_ret({
        "quiet.timer": {"enabled": True, "active": False},
    })
    hpd.get_timer_properties = lambda unit: _async_ret({
        "Unit": "quiet.service",
        "FragmentPath": "/etc/systemd/system/quiet.timer",
        "TimersCalendar": "weekly",
        "TimersMonotonic": "",
    })
    await mon._check_systemd_timers(loop, maintenance_active=False, first_run=False)
    events = timer_events(pub)
    assert len(events) == 1, events
    assert events[0].metadata["why_detected"].startswith("Timer baru saja diaktifkan")
    print("Test 6 (enabled_transition pada timer lama -- dievaluasi ulang) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"timers": {}}
    hpd.list_systemd_timers = lambda: _async_ret({
        "evil-cleanup.timer": {"enabled": True, "active": True},
    })
    hpd.get_timer_properties = lambda unit: _async_ret({
        "Unit": "evil-cleanup.service",
        "FragmentPath": "/tmp/.hidden/evil-cleanup.timer",
        "TimersCalendar": "*-*-* *:00:00",
        "TimersMonotonic": "",
    })
    await mon._check_systemd_timers(loop, maintenance_active=True, first_run=False)
    assert timer_events(pub) == [], "maintenance mode harus mendampen alert, bukan mempublish"
    print("Test 7 (maintenance mode aktif -- alert didampen) PASSED")

    print("\nALL SYSTEMD TIMER PERSISTENCE REGRESSION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
