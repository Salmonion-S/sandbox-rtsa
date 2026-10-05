import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import HostPersistenceDetectorConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from core.php_fpm_identity import (
    CLASSIFICATION_EXPECTED,
    CLASSIFICATION_NOT_PHP_FPM,
    CLASSIFICATION_SUSPICIOUS,
    REASON_ANCESTRY_INCONSISTENT,
    REASON_BINARY_IDENTITY_CHANGED,
    REASON_EXEC_WRITABLE_NON_ROOT,
    REASON_NAME_IMPERSONATION,
    REASON_NOT_PACKAGE_MANAGED,
    REASON_EXEC_UNVERIFIABLE,
    REASON_POOL_IDENTITY_CHANGED,
    REASON_PUBLIC_EXPOSURE,
    REASON_SUSPICIOUS_CMDLINE,
    REASON_SUSPICIOUS_EXEC_DIR,
    REASON_UNIT_MISMATCH,
    assess_php_fpm_listener,
    is_php_fpm_family,
    php_fpm_pool_identity,
)
import modules.host_persistence_detector as hpd
from modules.host_persistence_detector import HostPersistenceDetector, select_stable_listener

_TRUSTED_PREFIXES = ["/usr/sbin/", "/usr/bin/", "/usr/lib/", "/lib/", "/sbin/", "/bin/"]


class FakeLoop:
    async def run_in_executor(self, _executor, fn, *args):
        return fn(*args)


def expected_pool_kwargs(**overrides):
    base = dict(
        exe="/usr/sbin/php-fpm8.2",
        cmdline="php-fpm: pool ppdbsmaperintis2.id",
        process_name="php-fpm8.2",
        uid=1062,
        exposure="LOCAL_ONLY",
        bind_classification="LOOPBACK_ONLY",
        systemd_unit="php8.2-fpm.service",
        parent_exe="/usr/sbin/php-fpm8.2",
        parent_pid=830,
        package_owner="php8.2-fpm",
        exe_owner_uid=0,
        exe_mode=0o755,
        trusted_path_prefixes=_TRUSTED_PREFIXES,
    )
    base.update(overrides)
    return base


def fpm_port_info(**overrides):
    base = {
        "process_name": "php-fpm: pool ppdbsmaperintis2.id", "pid": 5001,
        "binary_path": "/usr/sbin/php-fpm8.2", "ppid": 830,
        "parent_process_name": "php-fpm8.2", "parent_binary_path": "/usr/sbin/php-fpm8.2",
        "linux_user": "ppdbsma", "uid": 1062, "gid": 1062, "cwd": "/",
        "cmdline": "php-fpm: pool ppdbsmaperintis2.id", "pid_create_time": 1000.0,
        "bind_address": "127.0.0.1", "protocol": "TCP", "state": "LISTEN",
        "bind_classification": "LOOPBACK_ONLY", "exposure": "LOCAL_ONLY",
        "listener_pid_count": 6,
        "process_fingerprint": "fp-worker-1", "parent_fingerprint": "fp-master",
        "executable_sha256": "a" * 64,
        "trust_classification": None, "trust_match_detail": None,
    }
    base.update(overrides)
    return base


def make_detector(**overrides):
    overrides.setdefault("port_confirmation_delay_seconds", 0.0)
    cfg = HostPersistenceDetectorConfig(enabled=True, **overrides)
    detector = HostPersistenceDetector(EventBus(), cfg)
    published = []
    detector.publish = lambda event: published.append(event)

    async def fake_package_owner(path):
        return "php8.2-fpm" if path and path.startswith("/usr/sbin/php-fpm") else None

    detector._package_owner_for = fake_package_owner
    return detector, published


def port_events(published):
    return [e for e in published if e.category == EventCategory.PERSISTENCE_NEW_PORT]


def discord_events(published):
    return [e for e in port_events(published) if e.metadata.get("notify_discord") is not False]


def patch_systemd_unit(mapping):
    hpd._systemd_unit_for_pid = lambda pid: mapping.get(pid)


async def main() -> None:
    loop = FakeLoop()

    assert is_php_fpm_family("/usr/sbin/php-fpm8.2", None, None) is True
    assert is_php_fpm_family("/usr/sbin/php8.2-fpm", None, None) is True
    assert is_php_fpm_family(None, "php-fpm: pool example.com", None) is True
    assert is_php_fpm_family("/usr/bin/nc", "php-fpm: pool example.com", None) is True
    assert is_php_fpm_family("/usr/sbin/nginx", "nginx: worker process", "nginx") is False
    print("Test 1 (php-fpm family recognition covers versioned binaries and retitled pool processes, and never matches nginx) PASSED")

    assert php_fpm_pool_identity("php-fpm8.2", "php-fpm: pool ppdbsmaperintis2.id") == "pool:ppdbsmaperintis2.id"
    assert php_fpm_pool_identity("php-fpm8.2", "php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)") == "master"
    assert php_fpm_pool_identity("php-fpm8.2", "php-fpm: pool a") != php_fpm_pool_identity("php-fpm8.2", "php-fpm: pool b")
    print("Test 2 (pool identity is derived from the process title, independent of PID and UID) PASSED")

    verdict = assess_php_fpm_listener(**expected_pool_kwargs())
    assert verdict.classification == CLASSIFICATION_EXPECTED, verdict.reasons
    assert verdict.expected is True and verdict.reasons == []
    assert verdict.php_version == "8.2"
    assert verdict.pool_identity == "pool:ppdbsmaperintis2.id"
    print("Test 3 [A1] (the exact reported production listener -- package-managed /usr/sbin/php-fpm8.2, php8.2-fpm.service, loopback pool -- classifies EXPECTED_PHP_FPM) PASSED")

    for version in ("8.1", "8.2", "8.3", "8.4"):
        versioned = assess_php_fpm_listener(**expected_pool_kwargs(
            exe=f"/usr/sbin/php-fpm{version}", process_name=f"php-fpm{version}",
            systemd_unit=f"php{version}-fpm.service", parent_exe=f"/usr/sbin/php-fpm{version}",
            package_owner=f"php{version}-fpm",
        ))
        assert versioned.expected is True, (version, versioned.reasons)
        assert versioned.php_version == version
    master = assess_php_fpm_listener(**expected_pool_kwargs(
        cmdline="php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)", uid=0, parent_pid=1,
        parent_exe="/usr/lib/systemd/systemd",
    ))
    assert master.expected is True and master.pool_identity == "master", master.reasons
    print("Test 4 [A1] (every installed PHP version 8.1-8.4 and the root-owned master process are all expected, with no per-domain or per-port allowlisting) PASSED")

    impersonator = assess_php_fpm_listener(**expected_pool_kwargs(exe="/tmp/php-fpm"))
    assert impersonator.expected is False
    assert impersonator.classification == CLASSIFICATION_SUSPICIOUS
    assert REASON_SUSPICIOUS_EXEC_DIR in impersonator.reasons
    assert impersonator.severity == Severity.HIGH
    print("Test 5 [A2] (process name says php-fpm but the executable is /tmp/php-fpm -- HIGH alert, never suppressed) PASSED")

    renamed = assess_php_fpm_listener(**expected_pool_kwargs(exe="/usr/bin/nc"))
    assert renamed.expected is False
    assert REASON_NAME_IMPERSONATION in renamed.reasons
    print("Test 6 [A2] (a process wearing a php-fpm title over a completely unrelated executable is flagged as impersonation) PASSED")

    public = assess_php_fpm_listener(**expected_pool_kwargs(
        exposure="INTERNET_EXPOSED", bind_classification="ALL_INTERFACES",
    ))
    assert public.expected is False
    assert REASON_PUBLIC_EXPOSURE in public.reasons
    assert public.severity == Severity.HIGH
    public_unknown_binary = assess_php_fpm_listener(**expected_pool_kwargs(
        exposure="INTERNET_EXPOSED", bind_classification="ALL_INTERFACES",
        package_owner=None, exe_owner_uid=1000,
    ))
    assert public_unknown_binary.severity == Severity.CRITICAL, public_unknown_binary.reasons
    print("Test 7 [A2] (0.0.0.0 exposure alerts HIGH; 0.0.0.0 combined with an unknown binary escalates to CRITICAL) PASSED")

    unpackaged = assess_php_fpm_listener(**expected_pool_kwargs(package_owner=None, exe_owner_uid=1000))
    assert unpackaged.expected is False and REASON_NOT_PACKAGE_MANAGED in unpackaged.reasons
    root_owned_no_package_db = assess_php_fpm_listener(**expected_pool_kwargs(package_owner=None, exe_owner_uid=0))
    assert root_owned_no_package_db.expected is True, (
        "a host without dpkg/rpm must still be able to verify a root-owned system binary, "
        "otherwise every PHP-FPM pool would alert forever on RPM-less or minimal images"
    )
    print("Test 8 [A1/A2] (unpackaged non-root binary alerts; a root-owned system binary still verifies when no package database is available) PASSED")

    writable = assess_php_fpm_listener(**expected_pool_kwargs(exe_mode=0o777))
    assert writable.expected is False and REASON_EXEC_WRITABLE_NON_ROOT in writable.reasons
    hash_changed = assess_php_fpm_listener(**expected_pool_kwargs(binary_identity_changed=True))
    assert hash_changed.expected is False
    assert REASON_BINARY_IDENTITY_CHANGED in hash_changed.reasons
    assert hash_changed.severity == Severity.HIGH
    print("Test 9 [A2] (group/world-writable binary and an unexpectedly changed binary hash both alert HIGH) PASSED")

    wrong_unit = assess_php_fpm_listener(**expected_pool_kwargs(systemd_unit="cron.service"))
    assert wrong_unit.expected is False and REASON_UNIT_MISMATCH in wrong_unit.reasons
    no_unit = assess_php_fpm_listener(**expected_pool_kwargs(systemd_unit=None))
    assert no_unit.expected is False and REASON_UNIT_MISMATCH in no_unit.reasons
    bad_ancestry = assess_php_fpm_listener(**expected_pool_kwargs(parent_exe="/bin/bash", parent_pid=4242))
    assert bad_ancestry.expected is False and REASON_ANCESTRY_INCONSISTENT in bad_ancestry.reasons
    print("Test 10 [A1/A2] (a listener outside a php*-fpm.service cgroup, or parented by a shell instead of the master, is never expected) PASSED")

    evil_cmdline = assess_php_fpm_listener(**expected_pool_kwargs(suspicious_cmdline=True))
    assert evil_cmdline.expected is False and REASON_SUSPICIOUS_CMDLINE in evil_cmdline.reasons
    fake_master = assess_php_fpm_listener(**expected_pool_kwargs(
        cmdline="php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)", uid=1062,
    ))
    assert fake_master.expected is False
    print("Test 11 [A2] (suspicious command line, and a master process that is not running as root, both block suppression) PASSED")

    not_php = assess_php_fpm_listener(
        exe="/usr/sbin/nginx", cmdline="nginx: master process", process_name="nginx",
        exposure="LOCAL_ONLY", systemd_unit="nginx.service", trusted_path_prefixes=_TRUSTED_PREFIXES,
    )
    assert not_php.classification == CLASSIFICATION_NOT_PHP_FPM
    assert not_php.is_php_fpm_like is False and not_php.expected is False
    print("Test 12 (a non-php-fpm listener is left entirely alone by this policy -- no new suppression surface) PASSED")

    patch_systemd_unit({
        pid: "php8.2-fpm.service" for pid in (830, 5001, 5002, 5003, 5004)
    })

    detector, published = make_detector()
    detector._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {17007: fpm_port_info()}
    await detector._check_listening_ports(loop, maintenance_active=False, first_run=False)
    assert discord_events(published) == [], (
        f"the exact reported production alert must no longer reach Discord: {discord_events(published)}"
    )
    internal = port_events(published)
    assert len(internal) == 1, "the event must still be recorded internally, never dropped entirely"
    assert internal[0].metadata["classification"] == CLASSIFICATION_EXPECTED
    assert internal[0].metadata["suppressed_alert"] == "PERSISTENCE_NEW_PORT"
    assert internal[0].metadata["php_fpm_pool"] == "pool:ppdbsmaperintis2.id"
    print("Test 13 [A1/O] (port 17007, 127.0.0.1, php-fpm pool ppdbsmaperintis2.id -- the reported alert is suppressed from Discord but fully retained internally) PASSED")

    health = await detector.health()
    assert health["suppressed_expected_php_fpm_events"] == 1
    assert health["php_fpm_security_events"] == 0
    print("Test 14 [A3] (suppressed_expected_php_fpm_events is counted and exposed in module diagnostics) PASSED")

    detector2, published2 = make_detector()
    detector2._baseline = {"ports": {"17007": fpm_port_info()}}
    rotations = [
        fpm_port_info(pid=5002, process_fingerprint="fp-worker-2"),
        fpm_port_info(pid=830, uid=0, gid=0, linux_user="root", process_fingerprint="fp-master",
                      cmdline="php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)",
                      process_name="php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)"),
        fpm_port_info(pid=5003, process_fingerprint="fp-worker-3"),
        fpm_port_info(pid=5004, process_fingerprint="fp-worker-4"),
    ]
    for rotation in rotations:
        hpd.list_listening_ports = lambda *_, _r=rotation: {17007: _r}
        await detector2._check_listening_ports(loop, maintenance_active=False, first_run=False)
    assert discord_events(published2) == [], (
        f"master/worker PID rotation must never produce a Discord alert: {discord_events(published2)}"
    )
    health2 = await detector2.health()
    assert health2["suppressed_expected_php_fpm_events"] >= 1
    print("Test 15 [A4/O] (4 cycles of php-fpm PID rotation, including a root master/site-user worker flip that changes UID and process title, produce zero Discord alerts) PASSED")

    detector3, published3 = make_detector()
    detector3._baseline = {"ports": {"17007": fpm_port_info()}}
    hpd.list_listening_ports = lambda *_: {
        17007: fpm_port_info(pid=9001, binary_path="/tmp/php-fpm", parent_binary_path="/bin/bash",
                             ppid=9000, process_fingerprint="fp-evil", executable_sha256="f" * 64),
    }
    await detector3._check_listening_ports(loop, maintenance_active=False, first_run=False)
    evil_events = discord_events(published3)
    assert len(evil_events) == 1, f"an impersonating listener must alert exactly once: {evil_events}"
    assert evil_events[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert evil_events[0].metadata["classification"] == CLASSIFICATION_SUSPICIOUS
    assert REASON_SUSPICIOUS_EXEC_DIR in evil_events[0].metadata["php_fpm_reasons"]
    print("Test 16 [A2/O] (a /tmp binary taking over the pool's port is never silenced by the expected-php-fpm path -- it alerts with its disqualifying evidence) PASSED")

    detector4, published4 = make_detector()
    detector4._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {
        17007: fpm_port_info(bind_address="0.0.0.0", bind_classification="ALL_INTERFACES",
                             exposure="INTERNET_EXPOSED"),
    }
    await detector4._check_listening_ports(loop, maintenance_active=False, first_run=False)
    public_events = discord_events(published4)
    assert len(public_events) == 1, f"a publicly bound php-fpm listener must alert: {public_events}"
    assert REASON_PUBLIC_EXPOSURE in public_events[0].metadata["php_fpm_reasons"]
    print("Test 17 [A2/O] (the same package-managed pool binary bound to 0.0.0.0 instead of loopback still alerts -- exposure is evaluated, not assumed) PASSED")

    detector5, published5 = make_detector(suppress_expected_php_fpm_listeners=False)
    detector5._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {17007: fpm_port_info()}
    await detector5._check_listening_ports(loop, maintenance_active=False, first_run=False)
    assert (await detector5.health())["suppressed_expected_php_fpm_events"] == 0
    assert port_events(published5)[0].metadata["classification"] != CLASSIFICATION_EXPECTED, (
        "with the switch off the listener must fall back to the pre-existing generic handling "
        "instead of being classified by the new php-fpm policy"
    )

    detector6, published6 = make_detector(
        suppress_expected_php_fpm_listeners=False, suppress_loopback_systemd_service_alerts=False,
    )
    detector6._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {17007: fpm_port_info()}
    await detector6._check_listening_ports(loop, maintenance_active=False, first_run=False)
    assert len(discord_events(published6)) == 1, (
        "with every suppression switch off, operators get the original full-alerting behaviour back"
    )
    print("Test 18 (the policy is configurable: switching it off falls back to the pre-existing generic loopback handling, and disabling both switches restores full alerting) PASSED")

    detector7, published7 = make_detector()
    detector7._baseline = {"ports": {}}
    hpd.list_listening_ports = lambda *_: {
        4444: {
            "process_name": "unknown-daemon", "pid": 7777, "binary_path": "/opt/unknown/daemon",
            "ppid": 1, "parent_process_name": "systemd", "parent_binary_path": "/usr/lib/systemd/systemd",
            "linux_user": "root", "uid": 0, "gid": 0, "cwd": "/", "cmdline": "/opt/unknown/daemon",
            "pid_create_time": 1000.0, "bind_address": "0.0.0.0", "protocol": "TCP", "state": "LISTEN",
            "bind_classification": "ALL_INTERFACES", "exposure": "INTERNET_EXPOSED",
            "listener_pid_count": 1, "process_fingerprint": "fp-unknown", "parent_fingerprint": None,
            "executable_sha256": "b" * 64, "trust_classification": None, "trust_match_detail": None,
        },
    }
    await detector7._check_listening_ports(loop, maintenance_active=False, first_run=False)
    unknown_events = discord_events(published7)
    assert len(unknown_events) == 1, f"a new unexpected public listener must still alert: {unknown_events}"
    assert unknown_events[0].severity == Severity.HIGH
    print("Test 19 [O] (an unrelated new public listener still produces its normal HIGH alert -- no detection was traded away) PASSED")

    candidates = [
        (17007, "php-fpm8.2", 5004, "127.0.0.1"),
        (17007, "php-fpm8.2", 830, "127.0.0.1"),
        (17007, "php-fpm8.2", 5002, "127.0.0.1"),
    ]
    real_ticks = hpd._process_start_ticks
    hpd._process_start_ticks = lambda pid: {830: 100, 5002: 900, 5004: 950}.get(pid)
    try:
        chosen = select_stable_listener(candidates)
        assert chosen[2] == 830, f"the longest-running owner (the master) must win: {chosen}"
        chosen_reordered = select_stable_listener(list(reversed(candidates)))
        assert chosen_reordered[2] == 830, "selection must not depend on enumeration order"
        mixed = [
            (8080, "app", 5002, "127.0.0.1"),
            (8080, "app", 5003, "0.0.0.0"),
        ]
        hpd._process_start_ticks = lambda pid: {5002: 100, 5003: 999}.get(pid)
        exposed = select_stable_listener(mixed)
        assert exposed[3] == "0.0.0.0", (
            "when one socket on a port is public and another is loopback, the public one must win "
            "so exposure can never be masked by picking the older loopback process"
        )
    finally:
        hpd._process_start_ticks = real_ticks
    print("Test 20 [A4] (listener selection is deterministic: most-exposed bind wins first, then the longest-running PID -- fixing the enumeration-order flapping at its source) PASSED")

    takeover = assess_php_fpm_listener(**expected_pool_kwargs(
        previous_pool_identity="pool:site-a.id",
        cmdline="php-fpm: pool site-b.id",
    ))
    assert takeover.expected is False, "a different pool taking over the port is a material identity change"
    assert REASON_POOL_IDENTITY_CHANGED in takeover.reasons
    assert takeover.severity == Severity.HIGH
    print("Test 21 [A4] (a DIFFERENT pool taking over the same port is a material identity change and alerts HIGH -- suppression only covers the same logical listener) PASSED")

    master_flip = assess_php_fpm_listener(**expected_pool_kwargs(
        previous_pool_identity="pool:ppdbsmaperintis2.id",
        cmdline="php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)", uid=0, parent_pid=1,
        parent_exe="/usr/lib/systemd/systemd",
    ))
    assert master_flip.expected is True, (
        f"the master and its pool workers share one inherited listening socket, so a master/worker "
        f"flip is not a pool takeover: {master_flip.reasons}"
    )
    print("Test 22 [A4] (a master/worker flip on the same shared socket is NOT treated as a pool takeover -- only pool-to-pool changes are) PASSED")

    unverifiable = assess_php_fpm_listener(**expected_pool_kwargs(package_owner=None, exe_owner_uid=None))
    assert unverifiable.expected is False
    assert REASON_EXEC_UNVERIFIABLE in unverifiable.reasons, unverifiable.reasons
    assert REASON_NOT_PACKAGE_MANAGED not in unverifiable.reasons, (
        "an executable we could not inspect must not be reported as positively unowned -- the "
        "evidence has to say what was actually observed"
    )
    unknown_parent = assess_php_fpm_listener(**expected_pool_kwargs(parent_exe=None, parent_pid=None))
    assert REASON_ANCESTRY_INCONSISTENT not in unknown_parent.reasons, (
        "an unreadable parent is missing evidence, not contradictory evidence, and must not by "
        "itself disqualify an otherwise verified pool"
    )
    print("Test 23 (evidence honesty: an uninspectable binary is not reported as unowned, and unknown ancestry is not reported as inconsistent) PASSED")

    print("\nALL PHP-FPM LISTENER POLICY TESTS PASSED")


asyncio.run(main())
