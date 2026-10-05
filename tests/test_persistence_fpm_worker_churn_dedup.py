import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import HostPersistenceDetectorConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from core.process_fingerprint import multi_worker_application_identity
import modules.host_persistence_detector as hpd
from modules.host_persistence_detector import HostPersistenceDetector


class FakeLoop:
    async def run_in_executor(self, _executor, fn, *args):
        return fn(*args)


def fpm_port_info(
    pid=5001, ppid=830, fingerprint="fp-fpm-cycle-1", cmdline="php-fpm: pool lampunggo.com",
    exe_sha256="d" * 64, uid=1062,
):
    return {
        "process_name": "php-fpm7.4", "pid": pid, "binary_path": "/usr/sbin/php-fpm7.4",
        "ppid": ppid, "parent_process_name": "php-fpm7.4", "linux_user": "newus-lampunggo",
        "uid": uid, "gid": uid, "cwd": "/", "cmdline": cmdline, "pid_create_time": 1000.0,
        "bind_address": "127.0.0.1", "protocol": "TCP", "state": "LISTEN",
        "bind_classification": "LOOPBACK_ONLY", "exposure": "LOCAL_ONLY",
        "process_fingerprint": fingerprint, "parent_fingerprint": f"parent-{fingerprint}",
        "executable_sha256": exe_sha256,
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


async def main() -> None:
    loop = FakeLoop()

    assert multi_worker_application_identity("php-fpm7.4", "php-fpm: pool lampunggo.com") == "pool:lampunggo.com"
    assert multi_worker_application_identity("php-fpm7.4", "php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)") == "master"
    assert multi_worker_application_identity("chrome", "php-fpm: pool lampunggo.com") is None
    assert multi_worker_application_identity("php-fpm7.4", "curl http://evil.tld") is None
    print("Scenario 1 (multi_worker_application_identity extracts pool/master identity only for php-fpm-shaped executables) PASSED")

    mon, pub = make_detector()
    mon._baseline = {"ports": {"14005": fpm_port_info(pid=5001, fingerprint="fp-fpm-cycle-1")}}
    hpd.list_listening_ports = lambda *_: {
        14005: fpm_port_info(pid=5002, fingerprint="fp-fpm-cycle-2"),
    }
    await mon._check_listening_ports(loop, maintenance_active=False, first_run=False)
    assert port_events(pub) == [], (
        "a raw process_fingerprint change alone must never alert when the executable path, "
        "executable content hash (exe_sha256), owning user, and php-fpm pool identity are all "
        "unchanged -- this is the exact PHP-FPM worker-respawn scenario the spec requires be "
        "treated as benign churn, not a security incident"
    )
    assert mon._baseline["ports"]["14005"]["process_fingerprint"] == "fp-fpm-cycle-2", (
        "the baseline must still advance to the new fingerprint so a REAL future ownership change "
        "is compared against the current state, not a stale one"
    )
    print("Scenario 2 (PHP-FPM worker/master respawn: same binary+hash+uid+pool, fingerprint churns -- zero alerts, matches the reported PDF evidence) PASSED")

    mon2, pub2 = make_detector()
    mon2._baseline = {"ports": {"14005": fpm_port_info(pid=5001, fingerprint="fp-fpm-cycle-1")}}
    hpd.list_listening_ports = lambda *_: {
        14005: fpm_port_info(pid=5002, fingerprint="fp-fpm-cycle-2"),
    }
    for _ in range(5):
        await mon2._check_listening_ports(loop, maintenance_active=False, first_run=False)
    assert port_events(pub2) == [], (
        f"repeated benign FPM churn across many polling cycles must never accumulate into alerts: {port_events(pub2)}"
    )
    print("Scenario 3 (5 consecutive benign FPM churn cycles -- still zero alerts, no accumulation) PASSED")

    mon3, pub3 = make_detector()
    mon3._baseline = {"ports": {"14005": fpm_port_info(pid=5001, fingerprint="fp-fpm-cycle-1", exe_sha256="d" * 64)}}
    hpd.list_listening_ports = lambda *_: {
        14005: fpm_port_info(pid=6001, fingerprint="fp-attacker-1", exe_sha256="e" * 64),
    }
    await mon3._check_listening_ports(loop, maintenance_active=False, first_run=False)
    events3 = port_events(pub3)
    assert len(events3) == 1, f"a genuine binary replacement on the same port must still alert: {events3}"
    assert events3[0].metadata["classification"] == "SUSPICIOUS_PHP_FPM"
    assert events3[0].severity == Severity.HIGH
    assert "PHP_FPM_BINARY_IDENTITY_CHANGED" in events3[0].metadata["php_fpm_reasons"]
    assert events3[0].metadata.get("notify_discord") is not False, (
        "a replaced php-fpm binary must never be routed into the expected-listener suppression path"
    )
    assert "previous_process_fingerprint" in events3[0].metadata
    print("Scenario 4 (binary REPLACED on the same port, same pool name spoofed in cmdline -- exe_sha256 mismatch still forces a HIGH alert naming PHP_FPM_BINARY_IDENTITY_CHANGED, security not weakened) PASSED")

    mon4, pub4 = make_detector()
    mon4._baseline = {"ports": {"14005": fpm_port_info(pid=5001, fingerprint="fp-fpm-cycle-1", cmdline="php-fpm: pool lampunggo.com")}}
    hpd.list_listening_ports = lambda *_: {
        14005: fpm_port_info(pid=5002, fingerprint="fp-fpm-cycle-2", cmdline="php-fpm: pool otherproject.com"),
    }
    await mon4._check_listening_ports(loop, maintenance_active=False, first_run=False)
    events4 = port_events(pub4)
    assert len(events4) == 1, f"a DIFFERENT pool taking over the same port must still alert as a real ownership change: {events4}"
    print("Scenario 5 (a DIFFERENT FPM pool takes over the same port -- still a full ownership-change alert) PASSED")

    mon5, pub5 = make_detector()
    mon5._baseline = {"ports": {"14005": fpm_port_info(pid=5001, fingerprint="fp-fpm-cycle-1", uid=1062)}}
    hpd.list_listening_ports = lambda *_: {
        14005: fpm_port_info(pid=5002, fingerprint="fp-fpm-cycle-2", uid=1099),
    }
    await mon5._check_listening_ports(loop, maintenance_active=False, first_run=False)
    events5 = port_events(pub5)
    assert len(events5) == 1, f"a DIFFERENT owning uid on the same port must still alert as a real ownership change: {events5}"
    print("Scenario 6 (same pool name but a DIFFERENT owning UID takes the port -- still a full ownership-change alert) PASSED")

    mon6, pub6 = make_detector()
    mon6._baseline = {"ports": {"14005": fpm_port_info(pid=5001, fingerprint="fp-fpm-cycle-1")}}
    hpd.list_listening_ports = lambda *_: {}
    await mon6._check_listening_ports(loop, maintenance_active=False, first_run=False)
    resolved6 = [e for e in pub6 if e.category == EventCategory.PERSISTENCE_CONDITION_RESOLVED]
    assert len(resolved6) == 1, f"a listener that stops being observed must emit exactly one RECOVERED-style event: {resolved6}"
    assert "14005" in resolved6[0].message
    assert "14005" not in mon6._baseline["ports"], "a vanished port must be dropped from baseline, not lingered on"
    print("Scenario 7 (listener disappears -- single RECOVERED notification, port dropped from baseline) PASSED")

    hpd.list_listening_ports = lambda *_: {}
    pub6.clear()
    await mon6._check_listening_ports(loop, maintenance_active=False, first_run=False)
    resolved6b = [e for e in pub6 if e.category == EventCategory.PERSISTENCE_CONDITION_RESOLVED]
    assert resolved6b == [], f"a port that already recovered must never re-fire RECOVERED on subsequent empty cycles: {resolved6b}"
    print("Scenario 8 (already-recovered listener does not repeat RECOVERED notifications on later cycles) PASSED")

    hpd.list_listening_ports = lambda *_: {14005: fpm_port_info(pid=7001, fingerprint="fp-fpm-new-incident")}
    pub6.clear()
    await mon6._check_listening_ports(loop, maintenance_active=False, first_run=False)
    new_events6 = port_events(pub6)
    assert len(new_events6) == 1, f"a listener returning after it was CLOSED must be treated as a brand-new incident: {new_events6}"
    assert new_events6[0].metadata["classification"] in (
        "UNVERIFIED", "TRUSTED_EXPECTED_PROCESS", "SUSPICIOUS_COMMAND_OVERRIDE", "SUSPICIOUS_PHP_FPM",
    )
    print("Scenario 9 (listener returns after CLOSED -- treated as a new incident, not silently merged with the old one) PASSED")

    print("\nALL PHP-FPM WORKER-CHURN DEDUP TESTS PASSED")


asyncio.run(main())
