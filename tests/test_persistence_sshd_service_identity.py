from __future__ import annotations

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

_REAL_LIST_LISTENING_PORTS = hpd.list_listening_ports


class FakeLoop:
    async def run_in_executor(self, _executor, fn, *args):
        return fn(*args)


def sshd_info(
    *, pid=3757, ppid=1, fingerprint="fp-sshd-1", cmdline="sshd: /usr/sbin/sshd -D [listener] 1 of 10-100 startups",
    binary_path="/usr/sbin/sshd", bind_address="0.0.0.0",
):
    return {
        "process_name": "sshd", "pid": pid, "binary_path": binary_path,
        "ppid": ppid, "parent_process_name": "systemd", "linux_user": "root", "uid": 0, "gid": 0,
        "cwd": "/", "cmdline": cmdline, "pid_create_time": 1749772800.0,
        "bind_address": bind_address, "protocol": "TCP", "state": "LISTEN",
        "bind_classification": "ALL_INTERFACES", "exposure": "INTERNET_EXPOSED",
        "process_fingerprint": fingerprint, "parent_fingerprint": "fp-systemd",
        "executable_sha256": "a" * 64,
        "trust_classification": None, "trust_match_detail": None,
    }


def backdoor_info(*, pid=9999, fingerprint="fp-backdoor", binary_path="/tmp/fake-sshd", ppid=9998):
    return {
        "process_name": "fake-sshd", "pid": pid, "binary_path": binary_path,
        "ppid": ppid, "parent_process_name": "bash", "linux_user": "root", "uid": 0, "gid": 0,
        "cwd": "/tmp", "cmdline": binary_path, "pid_create_time": 1749900000.0,
        "bind_address": "0.0.0.0", "protocol": "TCP", "state": "LISTEN",
        "bind_classification": "ALL_INTERFACES", "exposure": "INTERNET_EXPOSED",
        "process_fingerprint": fingerprint, "parent_fingerprint": "fp-bash",
        "executable_sha256": "b" * 64,
        "trust_classification": None, "trust_match_detail": None,
    }


def make_detector(**overrides):
    overrides.setdefault("port_confirmation_delay_seconds", 0.0)
    cfg = HostPersistenceDetectorConfig(enabled=True, **overrides)
    mon = HostPersistenceDetector(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def port_events(published):
    return [e for e in published if e.category == EventCategory.PERSISTENCE_NEW_PORT]


def install_fake_systemd_unit(mapping):
    original = hpd._systemd_unit_for_pid
    hpd._systemd_unit_for_pid = lambda pid: mapping.get(pid)
    return original


async def seed_baseline(loop, port_infos):
    mon, _pub = make_detector()
    mon._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: dict(port_infos)
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=True)
    return mon._baseline["ports"]


async def main() -> None:
    loop = FakeLoop()

    original_systemd_lookup = install_fake_systemd_unit({
        3757: "ssh.service", 4000: "ssh.service", 6666: None,
    })
    try:
        seeded = await seed_baseline(loop, {23109: sshd_info()})
        assert seeded["23109"]["service_identity"] == "ssh.service|/usr/sbin/sshd"

        mon, pub = make_detector()
        mon._baseline = {"ports": {"23109": dict(seeded["23109"])}}
        hpd.list_listening_ports = lambda *_: {23109: dict(sshd_info())}
        await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
        assert port_events(pub) == [], f"an unchanged known listener must never alert: {port_events(pub)}"
        print("Test 1 (known sshd listener, nothing changed -> no alert) PASSED")

        mon2, pub2 = make_detector()
        mon2._baseline = {"ports": {"23109": dict(seeded["23109"])}}
        restarted = sshd_info(pid=4000, fingerprint="fp-sshd-2")
        hpd.list_listening_ports = lambda *_: {23109: dict(restarted)}
        await mon2._check_listening_ports(loop, maintenance_active=False, first_run=False)
        events = port_events(pub2)
        assert len(events) == 1, f"expected exactly one internal (suppressed) event, got {events}"
        assert events[0].metadata.get("notify_discord") is False, (
            f"sshd restart on a known port must not alert Discord: {events[0].metadata}"
        )
        assert events[0].metadata["classification"] == "KNOWN_SERVICE_RESTART"
        assert mon2._baseline["ports"]["23109"]["process_fingerprint"] == "fp-sshd-2", (
            "the baseline must still be updated to the new fingerprint/PID"
        )
        assert mon2._baseline["ports"]["23109"]["pid"] == 4000
        print("Test 2/3/4 (sshd restart -- PID/fingerprint/start-time all change, service_identity doesn't -> NO PERSISTENCE_NEW_PORT, baseline updated) PASSED")

        mon5, pub5 = make_detector()
        mon5._baseline = {"ports": {}}
        hpd.list_listening_ports = lambda *_: {45678: backdoor_info(pid=9999)}
        await mon5._check_listening_ports(loop, maintenance_active=False, first_run=False)
        events5 = port_events(pub5)
        assert len(events5) == 1
        assert events5[0].metadata.get("notify_discord") is not False, "a new suspicious listener must never be suppressed"
        assert events5[0].metadata["classification"] == "UNVERIFIED"
        assert events5[0].severity.value == "HIGH"
        print("Test 5 (new suspicious port 45678, /tmp/backdoor, no systemd unit -> HIGH, not suppressed) PASSED")

        mon6, pub6 = make_detector()
        mon6._baseline = {"ports": {"23109": dict(seeded["23109"])}}
        hijack = backdoor_info(pid=6666, fingerprint="fp-hijack", binary_path="/tmp/fake-sshd")
        hpd.list_listening_ports = lambda *_: {23109: hijack}
        await mon6._check_listening_ports(loop, maintenance_active=False, first_run=False)
        events6 = port_events(pub6)
        assert len(events6) == 1
        assert events6[0].metadata.get("notify_discord") is not False, "a genuine hijack of a known service port must alert"
        assert events6[0].severity.value == "HIGH"
        assert events6[0].metadata.get("previous_process_fingerprint") == "fp-sshd-1"
        assert "ownership change" in events6[0].metadata["detection_reason"].lower()
        print("Test 6 (23109 hijacked by /tmp/fake-sshd, no systemd unit -> full HIGH ownership-change alert) PASSED")
    finally:
        hpd._systemd_unit_for_pid = original_systemd_lookup

    original_systemd_lookup = install_fake_systemd_unit({3757: "ssh.service", 4000: "ssh.service"})
    try:
        seeded7 = await seed_baseline(loop, {23109: sshd_info()})
        mon7, pub7 = make_detector()
        mon7._baseline = {"ports": {"23109": dict(seeded7["23109"])}}
        hpd.list_listening_ports = lambda *_: {23109: dict(sshd_info(pid=4000, fingerprint="fp-sshd-2"))}
        await mon7._check_listening_ports(loop, maintenance_active=False, first_run=True)
        assert port_events(pub7) == [], (
            f"first_run must never emit PERSISTENCE_NEW_PORT, even for entries not yet in baseline: {port_events(pub7)}"
        )
        print("Test 7 (RTSA restart / first_run -- no replay of existing listeners as NEW) PASSED")

        old_pids = {p: 1000 + p for p in range(20)}
        new_pids = {p: 2000 + p for p in range(20)}
        install_fake_systemd_unit({**{pid: "ssh.service" for pid in old_pids.values()}, **{pid: "ssh.service" for pid in new_pids.values()}})
        seeded8 = await seed_baseline(loop, {p: sshd_info(pid=old_pids[p], fingerprint=f"fp-{p}-old") for p in range(20)})

        mon8, pub8 = make_detector()
        mon8._baseline = {"ports": dict(seeded8)}
        current8 = {p: sshd_info(pid=new_pids[p], fingerprint=f"fp-{p}-new") for p in range(20)}
        hpd.list_listening_ports = lambda *_: current8
        await mon8._check_listening_ports(loop, maintenance_active=False, first_run=False)
        loud8 = [e for e in port_events(pub8) if e.metadata.get("notify_discord") is not False]
        assert loud8 == [], f"20 simultaneous known-service restarts must produce zero Discord-visible alerts, got {len(loud8)}"
        print("Test 8 (20 simultaneous known-service restarts, e.g. a reboot -- no alert storm) PASSED")

        import psutil
        from collections import namedtuple
        FakeAddr = namedtuple("FakeAddr", ["ip", "port"])
        FakeConn = namedtuple("FakeConn", ["status", "laddr", "raddr", "pid"])
        session_child_conn = [FakeConn(psutil.CONN_ESTABLISHED, FakeAddr("10.0.0.5", 22), FakeAddr("203.0.113.9", 51000), 7000)]
        original_net_connections = psutil.net_connections
        psutil.net_connections = lambda kind="inet": session_child_conn
        try:
            result = _REAL_LIST_LISTENING_PORTS(HostPersistenceDetectorConfig())
        finally:
            psutil.net_connections = original_net_connections
        assert result == {}, f"an established SSH session child must never appear as a listening port: {result}"
        print("Test 9 (SSH session child, sshd: user@pts/0 -- never treated as a new listener) PASSED")

        install_fake_systemd_unit({3757: "ssh.service", 3758: "ssh.service", 3759: "ssh.service"})
        seeded10 = await seed_baseline(loop, {
            23109: sshd_info(pid=3757, fingerprint="fp-a-old"),
            23110: sshd_info(pid=3758, fingerprint="fp-b-old"),
            23111: sshd_info(pid=3759, fingerprint="fp-c-old"),
        })
        mon10, pub10 = make_detector()
        mon10._baseline = {"ports": dict(seeded10)}
        current10 = {
            23109: sshd_info(pid=5001, fingerprint="fp-a-new"),
            23110: sshd_info(pid=5002, fingerprint="fp-b-new"),
            23111: backdoor_info(pid=5003, fingerprint="fp-c-hijack"),
        }
        hpd.list_listening_ports = lambda *_: current10
        install_fake_systemd_unit({5001: "ssh.service", 5002: "ssh.service"})
        await mon10._check_listening_ports(loop, maintenance_active=False, first_run=False)
        all_events = port_events(pub10)
        loud = [e for e in all_events if e.metadata.get("notify_discord") is not False]
        assert len(loud) == 1, f"expected exactly one Discord-visible alert (the hijack), got {len(loud)}: {[e.metadata for e in loud]}"
        assert loud[0].metadata["port"] == 23111
        print("Test 10 (mixed: 2 benign restarts + 1 real hijack -> exactly one Discord-visible alert, for the hijack) PASSED")
    finally:
        hpd._systemd_unit_for_pid = original_systemd_lookup

    print("\nALL PERSISTENCE sshd SERVICE-IDENTITY TESTS PASSED")


asyncio.run(main())
