import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import HostPersistenceDetectorConfig
from core.datatypes import EventCategory
from core.event_bus import EventBus
import modules.host_persistence_detector as hpd
from modules.host_persistence_detector import HostPersistenceDetector

_REAL_SLEEP = asyncio.sleep


def port_info(process_name=None, pid=None):
    return {
        "process_name": process_name, "pid": pid, "binary_path": None, "ppid": None,
        "parent_process_name": None, "linux_user": None, "cwd": None, "cmdline": None,
        "pid_create_time": None,
    }


def make_detector(**overrides):
    overrides.setdefault("port_confirmation_delay_seconds", 0.05)
    cfg = HostPersistenceDetectorConfig(enabled=True, **overrides)
    mon = HostPersistenceDetector(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def port_events(published):
    return [e for e in published if e.category == EventCategory.PERSISTENCE_NEW_PORT]


class FakeLoop:
    async def run_in_executor(self, _executor, fn, *args):
        return fn(*args)


async def main():
    loop = FakeLoop()

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    calls = iter([{15413: port_info(pid=None)}, {}])
    hpd.list_listening_ports = lambda *_: next(calls)
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    assert port_events(pub) == [], f"a port that vanishes before confirmation must not alert: {pub}"
    assert "15413" not in mon._baseline["ports"], (
        f"a transient port must not be baked into the baseline: {mon._baseline['ports']}"
    )
    print("Test 1 (port menghilang sebelum konfirmasi -- tidak dialert, tidak masuk baseline) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    calls = iter([{15413: port_info(process_name="nginx", pid=1234)}] * 2)
    hpd.list_listening_ports = lambda *_: next(calls)
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    events = port_events(pub)
    assert len(events) == 1, f"a port still listening at confirmation must alert exactly as before: {pub}"
    assert events[0].metadata["port"] == 15413
    assert "15413" in mon._baseline["ports"]
    print("Test 2 (port masih listening saat konfirmasi -- tetap dialert seperti sebelumnya) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    calls = iter([
        {111: port_info(pid=1), 222: port_info(pid=2), 333: port_info(pid=3)},
        {222: port_info(pid=2)},
    ])
    hpd.list_listening_ports = lambda *_: next(calls)
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    alerted_ports = sorted(e.metadata["port"] for e in port_events(pub))
    assert alerted_ports == [222], f"only the port still present at confirmation must alert: {alerted_ports}"
    assert set(mon._baseline["ports"].keys()) == {"222"}, mon._baseline["ports"]
    print("Test 3 (3 port baru, hanya 1 masih listening -- hanya itu yang dialert & masuk baseline) PASSED")

    mon, pub = make_detector()
    mon._baseline = {}
    sleep_calls = []
    async def tracking_sleep(seconds):
        sleep_calls.append(seconds)
    asyncio.sleep = tracking_sleep
    try:
        hpd.list_listening_ports = lambda *_: {15413: port_info(pid=None)}
        await mon._check_listening_ports(loop, maintenance_active=False, first_run=True)
    finally:
        asyncio.sleep = _REAL_SLEEP
    assert port_events(pub) == [], "first_run must never alert (baseline seeding only)"
    assert sleep_calls == [], f"first_run must never trigger the confirmation delay: {sleep_calls}"
    assert "15413" in mon._baseline["ports"], "first_run must still seed the baseline with what's live now"
    print("Test 4 (first_run -- tidak ada confirmation delay, baseline langsung di-seed) PASSED")

    mon, pub = make_detector(port_confirmation_delay_seconds=0.0)
    mon._baseline = {"ports": {}}
    sleep_calls = []
    async def tracking_sleep2(seconds):
        sleep_calls.append(seconds)
    asyncio.sleep = tracking_sleep2
    try:
        hpd.list_listening_ports = lambda *_: {15413: port_info(process_name="x", pid=99)}
        await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    finally:
        asyncio.sleep = _REAL_SLEEP
    assert sleep_calls == [], "port_confirmation_delay_seconds=0 must skip the confirmation step entirely"
    assert len(port_events(pub)) == 1, "with confirmation disabled, behavior must match the pre-fix immediate alert"
    print("Test 5 (port_confirmation_delay_seconds=0 -- verifikasi dimatikan, alert langsung seperti semula) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {}}
    sleep_calls = []
    async def tracking_sleep3(seconds):
        sleep_calls.append(seconds)
    asyncio.sleep = tracking_sleep3
    try:
        hpd.list_listening_ports = lambda *_: {22: port_info(process_name="sshd", pid=1)}
        await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    finally:
        asyncio.sleep = _REAL_SLEEP
    assert port_events(pub) == [], "an allowed_ports entry must never alert"
    assert sleep_calls == [], "an allowed_ports entry must never trigger the confirmation delay"
    print("Test 6 (port di allowed_ports -- tidak memicu confirmation delay maupun alert) PASSED")

    import yaml
    raw = yaml.safe_load(open("config/config.yaml"))
    shipped = raw["modules"]["host_persistence_detector"]
    assert shipped["port_confirmation_delay_seconds"] == 5.0, shipped
    default_cfg = HostPersistenceDetectorConfig()
    assert default_cfg.port_confirmation_delay_seconds == 5.0
    print("Test 7 (default & config.yaml port_confirmation_delay_seconds -- 5.0 detik) PASSED")

    print("\nALL PERSISTENCE_NEW_PORT CONFIRMATION REGRESSION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
