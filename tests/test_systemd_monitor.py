import asyncio
import json
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

_TEST_BASELINE_DIR = tempfile.mkdtemp(prefix="rtsa_systemd_monitor_test_")
_SYSTEMD_CHANNEL_ID = 1545778622902833214

from config.manager import SystemdMonitorConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
import modules.systemd_monitor as systemd_monitor
from modules.systemd_monitor import (
    SystemdMonitor,
    _bounded_metadata,
    _classify_unit_file_origin,
    _read_runtime_process_evidence,
    classify_execution_chain,
    classify_new_service_risk,
)
from tests._isolated_config import build_isolated_config, isolated_config_dir
from modules.threat_correlation_engine import CorrelationCandidateEvent, TceConfig, classify_event


def _new_baseline_path() -> str:
    return os.path.join(_TEST_BASELINE_DIR, f"baseline_{time.time_ns()}.json")


def _make_config(**overrides) -> SystemdMonitorConfig:
    base = dict(
        enabled=True, integrity_scan_interval_seconds=300.0, dedup_window_seconds=300.0,
        aggregation_window_seconds=60.0, aggregation_spike_threshold=5,
        failure_threshold_count=3, failure_threshold_window_seconds=300.0,
        max_units_per_scan=500, max_events_per_cycle=100, max_metadata_bytes=4096,
        max_incident_services=20, max_tracked_units=1000, package_cache_refresh_seconds=3600.0,
        max_process_ancestry_depth=2,
        ignore_services=["php*-fpm.service", "systemd-*.service"],
        baseline_state_path=_new_baseline_path(),
    )
    base.update(overrides)
    return SystemdMonitorConfig(**base)


def _make_monitor(**overrides) -> SystemdMonitor:
    bus = EventBus()
    return SystemdMonitor(bus, _make_config(**overrides))


async def _collect(monitor: SystemdMonitor):
    collected = []

    async def collector(event):
        collected.append(event)

    sub = await monitor.bus.subscribe("collector", collector, categories=None)
    return collected, sub


def _reference_categories_for_test():
    from config.manager import _REFERENCE_DISCORD_CATEGORIES

    return list(_REFERENCE_DISCORD_CATEGORIES)


_SYSTEMD_EVENT_CATEGORIES = [
    "SYSTEMD_SERVICE_INCIDENT", "SYSTEMD_SECURITY", "SYSTEMD_MEMFD_EXECUTION",
    "SYSTEMD_DELETED_EXECUTABLE", "SYSTEMD_PROCESS_MISMATCH", "NEW_SYSTEMD_SERVICE",
    "SYSTEMD_SERVICE_CHANGED", "SYSTEMD_SERVICE_REMOVED",
]


async def main():
    monitor = _make_monitor()
    ran_periodic = {"called": False}

    async def fake_run_periodic(*args, **kwargs):
        ran_periodic["called"] = True

    monitor.run_periodic = fake_run_periodic
    await monitor.run()
    assert ran_periodic["called"] is True
    print("Test 1 (module enabled schedules periodic scan) PASSED")

    monitor_disabled = _make_monitor(enabled=False)
    monitor_disabled.run_periodic = fake_run_periodic
    ran_periodic["called"] = False
    await monitor_disabled.run()
    assert ran_periodic["called"] is False
    print("Test 2 (module disabled: no periodic scan scheduled) PASSED")

    cfg = _make_config(service_profile="server1service")
    assert isinstance(cfg.service_profile, str)
    print("Test 3 (service_profile is a single scalar string, never multiple) PASSED")

    import yaml as _yaml

    os.environ.setdefault("RTSA_DISCORD_BOT_TOKEN", "test_fixture_token_never_a_real_credential_0123456789abcdef")
    os.environ.setdefault("RTSA_CLOUDFLARE_API_TOKEN", "test_fixture_cf_token_never_real_fedcba9876543210")

    with isolated_config_dir() as tmpdir:
        server1_profile = {"systemd": {"alert_channel_id": _SYSTEMD_CHANNEL_ID}}
        server2_profile = {"systemd": {"alert_channel_id": _SYSTEMD_CHANNEL_ID}}
        with open(os.path.join(tmpdir, "server1service.yaml"), "w") as f:
            _yaml.safe_dump(server1_profile, f)
        with open(os.path.join(tmpdir, "server2service.yaml"), "w") as f:
            _yaml.safe_dump(server2_profile, f)
        with open(os.path.join(tmpdir, "discord-empty.yaml"), "w") as f:
            _yaml.safe_dump(
                {"category_channels": {}, "known_missing_categories": _reference_categories_for_test()}, f,
            )

        base_config = {
            "discord": {"enabled": True, "channel_config_file": "discord-empty.yaml"},
            "modules": {"systemd_monitor": {"enabled": True, "service_profile": "server1service"}},
        }
        mgr1 = build_isolated_config(tmpdir, base_config)
        cfg1 = mgr1.config
        for category in _SYSTEMD_EVENT_CATEGORIES:
            assert cfg1.discord.category_channels.get(category) == _SYSTEMD_CHANNEL_ID
        print("Test 4 (Server1 profile: every systemd category, including the new taxonomy, routes to the one channel) PASSED")

        base_config["modules"]["systemd_monitor"]["service_profile"] = "server2service"
        mgr2 = build_isolated_config(tmpdir, base_config)
        cfg2 = mgr2.config
        for category in _SYSTEMD_EVENT_CATEGORIES:
            assert cfg2.discord.category_channels.get(category) == _SYSTEMD_CHANNEL_ID
        print("Test 5 (Server2 profile: every systemd category routes to the one Systemd Monitor channel) PASSED")

        with open(os.path.join(tmpdir, "server2service.yaml"), "w") as f:
            _yaml.safe_dump({"systemd": {"alert_channel_id": 999999999999999999}}, f)
        base_config["modules"]["systemd_monitor"]["service_profile"] = "server1service"
        mgr1_reloaded = build_isolated_config(tmpdir, base_config)
        assert mgr1_reloaded.config.discord.category_channels.get("SYSTEMD_SECURITY") == _SYSTEMD_CHANNEL_ID
        assert mgr1_reloaded.config.discord.category_channels.get("SYSTEMD_SECURITY") != 999999999999999999
        print(
            "Test 6 (selecting server1service never pulls in server2service's channel -- only ONE "
            "profile file is ever read) PASSED"
        )

    monitor = _make_monitor(ignore_services=["nginx.service", "php*-fpm.service"])
    from modules.host_persistence_detector import unit_matches_known_good
    assert unit_matches_known_good("nginx.service", monitor.config.ignore_services) is True
    assert unit_matches_known_good("php8.1-fpm.service", monitor.config.ignore_services) is True
    assert unit_matches_known_good("mynginx.service", monitor.config.ignore_services) is False
    assert unit_matches_known_good("nginx-extra.service", monitor.config.ignore_services) is False
    print("Test 7/8 (ignore list: exact match + glob match, substring never matches) PASSED")

    async def fake_resolve_owner_none(path):
        return None

    systemd_monitor.resolve_path_package_owner = fake_resolve_owner_none

    monitor = _make_monitor(ignore_services=["nginx.service"])
    calls = {"get_unit_properties": 0}

    async def fake_list_systemd_services():
        return {"nginx.service": {"enabled": True, "active": True}}

    async def fake_get_unit_properties(unit):
        calls["get_unit_properties"] += 1
        return {}

    systemd_monitor.list_systemd_services = fake_list_systemd_services
    systemd_monitor.get_unit_properties = fake_get_unit_properties
    await monitor._run_scan_cycle()
    assert calls["get_unit_properties"] == 0
    assert monitor._ignored_units_total == 1
    print("Test 9 (ignored unit never reaches expensive per-unit inspection) PASSED")

    monitor = _make_monitor(ignore_services=[])
    collected, sub = await _collect(monitor)

    async def fake_list_initial_fleet():
        return {
            "chrony.service": {"enabled": True, "active": True},
            "fail2ban.service": {"enabled": True, "active": True},
            "nginx.service": {"enabled": True, "active": True},
            "grafana-server.service": {"enabled": True, "active": True},
            "apport-autoreport.service": {"enabled": False, "active": False},
        }

    async def fake_props_initial(unit):
        if unit == "chrony.service":
            return {
                "ExecStart": "{ path=/usr/lib/systemd/scripts/chronyd-starter.sh ; "
                             "argv[]=/usr/lib/systemd/scripts/chronyd-starter.sh ; ignore_errors=no }",
                "FragmentPath": "/usr/lib/systemd/system/chrony.service",
                "User": "", "ActiveState": "active", "SubState": "running", "LoadState": "loaded",
                "MainPID": "1001",
            }
        if unit == "fail2ban.service":
            return {
                "ExecStart": "{ path=/usr/bin/fail2ban-server ; argv[]=/usr/bin/fail2ban-server -xf start ; "
                             "ignore_errors=no }",
                "FragmentPath": "/usr/lib/systemd/system/fail2ban.service",
                "User": "root", "ActiveState": "active", "SubState": "running", "LoadState": "loaded",
                "MainPID": "1002",
            }
        if unit == "nginx.service":
            return {
                "ExecStart": "{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; "
                             "ignore_errors=no }",
                "FragmentPath": "/usr/lib/systemd/system/nginx.service",
                "User": "", "ActiveState": "active", "SubState": "running", "LoadState": "loaded",
                "MainPID": "1003",
            }
        if unit == "grafana-server.service":
            return {
                "ExecStart": "{ path=/usr/sbin/grafana-server ; argv[]=/usr/sbin/grafana-server ; "
                             "ignore_errors=no }",
                "FragmentPath": "/usr/lib/systemd/system/grafana-server.service",
                "User": "grafana", "ActiveState": "active", "SubState": "running", "LoadState": "loaded",
                "MainPID": "1004",
            }
        return {
            "ExecStart": "{ path=/usr/lib/apport/apport ; argv[]=/usr/lib/apport/apport ; ignore_errors=no }",
            "FragmentPath": "/usr/lib/systemd/system/apport-autoreport.service",
            "User": "root", "ActiveState": "inactive", "SubState": "dead", "LoadState": "loaded",
            "MainPID": "0",
        }

    async def fake_resolve_owner_packaged(path):
        mapping = {
            "/usr/lib/systemd/scripts/chronyd-starter.sh": "chrony",
            "/usr/sbin/chronyd": "chrony",
            "/usr/bin/fail2ban-server": "fail2ban",
            "/usr/bin/python3.12": "python3.12",
            "/usr/sbin/nginx": "nginx",
            "/usr/sbin/grafana-server": "grafana",
            "/usr/lib/apport/apport": "apport",
        }
        return mapping.get(path)

    systemd_monitor.list_systemd_services = fake_list_initial_fleet
    systemd_monitor.get_unit_properties = fake_props_initial
    systemd_monitor.resolve_path_package_owner = fake_resolve_owner_packaged

    real_read_runtime = systemd_monitor._read_runtime_process_evidence

    def fake_read_runtime_initial(pid, max_ancestry_depth=2):
        mapping = {
            1001: {"pid": 1001, "runtime_exe": "/usr/sbin/chronyd", "runtime_exe_resolved": "/usr/sbin/chronyd",
                    "cmdline": "/usr/sbin/chronyd -F 1", "runtime_user": "_chrony"},
            1002: {"pid": 1002, "runtime_exe": "/usr/bin/python3.12", "runtime_exe_resolved": "/usr/bin/python3.12",
                    "cmdline": "/usr/bin/python3 /usr/bin/fail2ban-server -xf start", "runtime_user": "root"},
            1003: {"pid": 1003, "runtime_exe": "/usr/sbin/nginx", "runtime_exe_resolved": "/usr/sbin/nginx",
                    "cmdline": "nginx: master process /usr/sbin/nginx", "runtime_user": "root"},
            1004: {"pid": 1004, "runtime_exe": "/usr/sbin/grafana-server", "runtime_exe_resolved": "/usr/sbin/grafana-server",
                    "cmdline": "/usr/sbin/grafana-server", "runtime_user": "grafana"},
        }
        return mapping.get(pid, {})

    systemd_monitor._read_runtime_process_evidence = fake_read_runtime_initial

    assert monitor._baseline_initialized is False
    await monitor._run_scan_cycle()
    await sub.queue.join()
    assert monitor._baseline_initialized is True
    assert len(collected) == 0, (
        f"initial baseline creation must publish ZERO security events, got {len(collected)}"
    )
    assert set(monitor._baseline.keys()) == {
        "chrony.service", "fail2ban.service", "nginx.service", "grafana-server.service",
        "apport-autoreport.service",
    }
    assert monitor._baseline["chrony.service"].chain_state == "MATCH"
    assert monitor._baseline["fail2ban.service"].chain_state == "MATCH"
    print(
        "Test 10 [REQUIRED Test 1] (initial baseline: chrony/fail2ban/nginx/grafana-server/apport all "
        "recorded silently, 0 security alerts, baseline_initialized becomes True) PASSED"
    )
    await monitor.bus.unsubscribe("collector")

    baseline_path = monitor.config.baseline_state_path
    monitor._save_baseline()
    restarted = _make_monitor(baseline_state_path=baseline_path, ignore_services=[])
    restarted._load_baseline()
    assert restarted._baseline_initialized is True
    assert set(restarted._baseline.keys()) == set(monitor._baseline.keys())

    collected2, sub2 = await _collect(restarted)
    systemd_monitor.list_systemd_services = fake_list_initial_fleet
    systemd_monitor.get_unit_properties = fake_props_initial
    await restarted._run_scan_cycle()
    await sub2.queue.join()
    assert len(collected2) == 0, (
        f"an RTSA restart against an unchanged fleet must never re-alert, got {len(collected2)}"
    )
    print(
        "Test 11 [REQUIRED Test 2] (RTSA restart: baseline persists via existing storage, unchanged "
        "fleet produces 0 duplicate alerts across process restart) PASSED"
    )
    await restarted.bus.unsubscribe("collector")

    systemd_monitor._read_runtime_process_evidence = real_read_runtime
    systemd_monitor.resolve_path_package_owner = fake_resolve_owner_none

    chrony_runtime_evidence = {
        "pid": 1001, "runtime_exe": "/usr/sbin/chronyd", "runtime_exe_resolved": "/usr/sbin/chronyd",
        "cmdline": "/usr/sbin/chronyd -F 1",
    }
    chain_state, reasons = classify_execution_chain(
        "/usr/lib/systemd/scripts/chronyd-starter.sh", chrony_runtime_evidence, "chrony", "chrony",
    )
    assert chain_state == "MATCH", f"chrony wrapper chain must MATCH via same-package evidence, got {reasons}"
    assert "same_package_wrapper_chain" in reasons
    print("Test 12 [REQUIRED Test 3] (chrony exec-replacement wrapper chain classifies MATCH, NO PROCESS_MISMATCH) PASSED")

    fail2ban_runtime_evidence = {
        "pid": 1002, "runtime_exe": "/usr/bin/python3.12", "runtime_exe_resolved": "/usr/bin/python3.12",
        "cmdline": "/usr/bin/python3 /usr/bin/fail2ban-server -xf start",
    }
    chain_state, reasons = classify_execution_chain(
        "/usr/bin/fail2ban-server", fail2ban_runtime_evidence, "fail2ban", "python3.12",
    )
    assert chain_state == "MATCH", f"fail2ban interpreter chain must MATCH via cmdline evidence, got {reasons}"
    assert "interpreter_wrapper_cmdline_match" in reasons
    print("Test 13 [REQUIRED Test 4] (fail2ban shebang-interpreter chain classifies MATCH, NO PROCESS_MISMATCH) PASSED")

    evil_runtime_evidence = {
        "pid": 4242, "runtime_exe": "/tmp/evil", "runtime_exe_resolved": "/tmp/evil",
        "cmdline": "/tmp/evil --daemon",
    }
    chain_state, reasons = classify_execution_chain(
        "/opt/legitimate/wrapper.sh", evil_runtime_evidence, "some-package", "some-package",
    )
    assert chain_state == "MISMATCH", "a wrapper that launches a binary in /tmp must remain MISMATCH"
    assert "runtime_executable_in_suspicious_location" in reasons
    print(
        "Test 14 [REQUIRED Test 5] (legitimate-looking wrapper -> suspicious /tmp executable stays "
        "MISMATCH -- an attacker cannot evade detection with a convincing wrapper) PASSED"
    )

    fake_chronyd_evidence = {
        "pid": 4243, "runtime_exe": "/tmp/.hidden/chronyd", "runtime_exe_resolved": "/tmp/.hidden/chronyd",
        "cmdline": "/tmp/.hidden/chronyd -F 1",
    }
    chain_state, reasons = classify_execution_chain(
        "/usr/lib/systemd/scripts/chronyd-starter.sh", fake_chronyd_evidence, "chrony", "chrony",
    )
    assert chain_state == "MISMATCH", "naming a binary 'chronyd' in /tmp must not evade detection"
    print("Test 15 (impersonating a trusted binary name inside /tmp still classifies MISMATCH) PASSED")

    memfd_evidence = {"runtime_exe": "/memfd:evil (deleted)", "memfd_execution": True}
    chain_state, reasons = classify_execution_chain("/usr/bin/legit", memfd_evidence, "pkg", "pkg")
    assert chain_state == "MISMATCH" and reasons == ["memfd_execution"]
    deleted_evidence = {"runtime_exe": "/usr/bin/legit (deleted)", "deleted_executable": True}
    chain_state, reasons = classify_execution_chain("/usr/bin/legit", deleted_evidence, "pkg", "pkg")
    assert chain_state == "MISMATCH" and reasons == ["deleted_executable"]
    print("Test 16 (memfd execution and deleted executables always classify MISMATCH) PASSED")

    unknown_evidence = {"runtime_exe": "/usr/bin/true", "runtime_exe_resolved": "/usr/bin/true"}
    chain_state, reasons = classify_execution_chain(None, unknown_evidence, None, None)
    assert chain_state == "UNKNOWN"
    print("Test 17 (no declared ExecStart + no suspicious location -> UNKNOWN, not a false MISMATCH) PASSED")

    direct_evidence = {"runtime_exe": "/usr/sbin/sshd", "runtime_exe_resolved": "/usr/sbin/sshd"}
    chain_state, reasons = classify_execution_chain("/usr/sbin/sshd", direct_evidence, "openssh-server", "openssh-server")
    assert chain_state == "MATCH" and reasons == []
    print("Test 18 (direct declared==runtime executable path match classifies MATCH with no extra reasons) PASSED")

    tier, reasons = classify_new_service_risk("/usr/sbin/nginx", "nginx", "MATCH", "root")
    assert tier == "LOW", f"a packaged, standard-path, matched-chain new service must be LOW risk, got {tier} {reasons}"
    print("Test 19 [REQUIRED Test 6] (new legitimate service: packaged/standard-path/matched-chain -> LOW risk, no HIGH alert) PASSED")

    tier, reasons = classify_new_service_risk("/tmp/.hidden/backdoor", None, "MISMATCH", "root")
    assert tier == "HIGH", f"unpackaged + suspicious path + mismatch + root must be HIGH risk, got {tier} {reasons}"
    assert "EXEC_PATH_SUSPICIOUS" in reasons and "UNPACKAGED_EXECUTABLE" in reasons
    print("Test 20 [REQUIRED Test 7] (new suspicious service: unknown package + suspicious path + mismatch + root -> HIGH risk) PASSED")

    tier, reasons = classify_new_service_risk("/opt/vendor/agent", None, "MATCH", "svc")
    assert tier == "MEDIUM", f"unpackaged-but-otherwise-clean new service should be MEDIUM, not HIGH, got {tier}"
    print("Test 21 (a single weak signal alone -- unpackaged, non-root, matched chain -- never escalates to HIGH) PASSED")

    assert _classify_unit_file_origin("/usr/lib/systemd/system/chrony.service") == "usr_lib_package"
    assert _classify_unit_file_origin("/etc/systemd/system/custom.service") == "etc_local"
    assert _classify_unit_file_origin("/run/systemd/system/transient.service") == "run_transient"
    assert _classify_unit_file_origin(None) is None
    assert _classify_unit_file_origin("/opt/weird/place.service") == "other"
    print("Test 22 (unit file origin classification: etc_local/run_transient/usr_lib_package/other/None) PASSED")

    monitor = _make_monitor(ignore_services=[])
    collected, sub = await _collect(monitor)
    monitor._baseline_initialized = True
    from modules.systemd_monitor import _UnitBaseline
    monitor._baseline["custom.service"] = _UnitBaseline(
        unit="custom.service", enabled=True, active=True, exec_path="/opt/app/old_binary",
        fragment_path="/etc/systemd/system/custom.service", user="svc", first_seen=time.time(),
        declared_package=None, chain_state="MATCH", risk_tier="LOW",
    )

    async def fake_props_changed(unit):
        return {
            "ExecStart": "{ path=/opt/app/new_binary ; argv[]=/opt/app/new_binary ; ignore_errors=no }",
            "FragmentPath": "/etc/systemd/system/custom.service", "User": "svc",
            "ActiveState": "active", "SubState": "running", "LoadState": "loaded", "MainPID": "0",
        }

    systemd_monitor.get_unit_properties = fake_props_changed
    systemd_monitor.resolve_path_package_owner = fake_resolve_owner_none
    failed_now, published, mismatch_hit, security_hit = await monitor._handle_trigger(
        "custom.service", {"enabled": True, "active": True}, "unit_file_changed", False,
    )
    await sub.queue.join()
    changed_events = [e for e in collected if e.metadata.get("event_type") == "SYSTEMD_SERVICE_CHANGED"]
    assert len(changed_events) == 1, f"ExecStart change must publish exactly one SYSTEMD_SERVICE_CHANGED, got {len(changed_events)}"
    assert changed_events[0].metadata["before"] == "/opt/app/old_binary"
    assert changed_events[0].metadata["after"] == "/opt/app/new_binary"
    assert changed_events[0].metadata["changed_field"] == "exec_start"
    print("Test 23 [REQUIRED Test 8] (ExecStart change on existing unit publishes SYSTEMD_SERVICE_CHANGED with before/after) PASSED")
    await monitor.bus.unsubscribe("collector")

    monitor = _make_monitor(ignore_services=[])
    monitor._baseline_initialized = True
    monitor._baseline["gone.service"] = _UnitBaseline(
        unit="gone.service", enabled=True, active=True, exec_path="/usr/bin/gone", first_seen=time.time(),
    )
    collected, sub = await _collect(monitor)

    async def fake_list_empty():
        return {}

    systemd_monitor.list_systemd_services = fake_list_empty
    await monitor._run_scan_cycle()
    await sub.queue.join()
    removed_events = [e for e in collected if e.category == EventCategory.SYSTEMD_SERVICE_REMOVED]
    assert len(removed_events) == 1, f"exactly one removal event expected, got {len(removed_events)}"
    assert "gone.service" not in monitor._baseline
    print("Test 24 [REQUIRED Test 9] (service removal handled with exactly one SYSTEMD_SERVICE_REMOVED, no alert storm) PASSED")
    await monitor.bus.unsubscribe("collector")

    monitor = _make_monitor(ignore_services=[], reminder_enabled=False)
    collected, sub = await _collect(monitor)
    monitor._baseline["evil.service"] = _UnitBaseline(
        unit="evil.service", enabled=True, active=True, exec_path="/opt/legit/wrapper.sh",
        fragment_path="/etc/systemd/system/evil.service", user="root", first_seen=time.time(),
    )

    async def fake_props_evil(unit):
        return {
            "ExecStart": "{ path=/opt/legit/wrapper.sh ; argv[]=/opt/legit/wrapper.sh ; ignore_errors=no }",
            "FragmentPath": "/etc/systemd/system/evil.service", "User": "root",
            "ActiveState": "active", "SubState": "running", "LoadState": "loaded", "MainPID": "4242",
        }

    def fake_read_runtime_evil(pid, max_ancestry_depth=2):
        return {"pid": 4242, "runtime_exe": "/tmp/evil", "runtime_exe_resolved": "/tmp/evil", "cmdline": "/tmp/evil"}

    systemd_monitor.get_unit_properties = fake_props_evil
    systemd_monitor._read_runtime_process_evidence = fake_read_runtime_evil
    systemd_monitor.resolve_path_package_owner = fake_resolve_owner_none

    for _ in range(5):
        await monitor._handle_trigger("evil.service", {"enabled": True, "active": True}, "unit_file_changed", False)
    await sub.queue.join()
    mismatch_events = [e for e in collected if e.category == EventCategory.SYSTEMD_PROCESS_MISMATCH]
    assert len(mismatch_events) == 1, (
        f"repeated identical polling of the same mismatch must be ONE logical event, got {len(mismatch_events)} "
        f"-- a random event_id must never defeat deduplication"
    )
    print("Test 25 [REQUIRED Test 10] (repeated identical polling of a genuine mismatch -> exactly ONE logical alert) PASSED")
    await monitor.bus.unsubscribe("collector")

    assert classify_execution_chain(
        "/usr/sbin/chronyd", {"pid": 1001, "runtime_exe": "/usr/sbin/chronyd", "runtime_exe_resolved": "/usr/sbin/chronyd"},
        "chrony", "chrony",
    )[0] == classify_execution_chain(
        "/usr/sbin/chronyd", {"pid": 9999, "runtime_exe": "/usr/sbin/chronyd", "runtime_exe_resolved": "/usr/sbin/chronyd"},
        "chrony", "chrony",
    )[0] == "MATCH"
    print("Test 26 [REQUIRED Test 11] (PID change alone never affects chain classification -- PID is never used as identity) PASSED")

    evidence = _read_runtime_process_evidence(999999999, max_ancestry_depth=2)
    assert evidence == {"pid": 999999999}, "a vanished PID must yield partial (not crashing) evidence"
    print("Test 27 [REQUIRED Test 12] (process disappears mid-inspection -- no crash, partial evidence returned) PASSED")

    import psutil as _psutil
    real_psutil_process = _psutil.Process

    class _RaisingProcess:
        def __init__(self, pid):
            raise _psutil.AccessDenied(pid)

    _psutil.Process = _RaisingProcess
    try:
        evidence = _read_runtime_process_evidence(os.getpid(), max_ancestry_depth=2)
    finally:
        _psutil.Process = real_psutil_process
    assert "runtime_user" not in evidence, "AccessDenied resolving runtime user must be swallowed, not crash"
    assert evidence.get("pid") == os.getpid()
    print("Test 28 [REQUIRED Test 13] (psutil.AccessDenied while resolving runtime user handled gracefully) PASSED")

    monitor = _make_monitor(baseline_state_path=os.path.join(_TEST_BASELINE_DIR, "does_not_exist.json"))
    monitor._load_baseline()
    assert monitor._baseline_initialized is False
    assert monitor._baseline == {}
    print("Test 29 [REQUIRED Test 14] (missing/empty baseline file on first run: not initialized, not a security incident) PASSED")

    corrupt_path = os.path.join(_TEST_BASELINE_DIR, f"corrupt_{time.time_ns()}.json")
    with open(corrupt_path, "w") as f:
        f.write("{not valid json!!!")
    monitor = _make_monitor(baseline_state_path=corrupt_path)
    monitor._load_baseline()
    assert monitor._baseline_initialized is False
    assert monitor._baseline == {}
    print("Test 30 [REQUIRED Test 15] (corrupt baseline JSON: fails safely, treated as uninitialized, no crash) PASSED")

    non_dict_path = os.path.join(_TEST_BASELINE_DIR, f"nondict_{time.time_ns()}.json")
    with open(non_dict_path, "w") as f:
        json.dump([1, 2, 3], f)
    monitor = _make_monitor(baseline_state_path=non_dict_path)
    monitor._load_baseline()
    assert monitor._baseline_initialized is False
    print("Test 31 (baseline file with unrecognized top-level type also fails safely) PASSED")

    old_flat_path = os.path.join(_TEST_BASELINE_DIR, f"oldflat_{time.time_ns()}.json")
    with open(old_flat_path, "w") as f:
        json.dump({"nginx.service": {"enabled": True, "active": True, "exec_path": "/usr/sbin/nginx"}}, f)
    monitor = _make_monitor(baseline_state_path=old_flat_path)
    monitor._load_baseline()
    assert monitor._baseline_initialized is True, "an old flat-format baseline must be treated as already initialized"
    assert "nginx.service" in monitor._baseline
    print("Test 32 (old pre-rework flat-format baseline migrates cleanly, marked already-initialized) PASSED")

    monitor = _make_monitor()
    monitor._baseline["svc.service"] = _UnitBaseline(
        unit="svc.service", enabled=True, active=True, exec_path="/usr/bin/svc", first_seen=time.time(),
        declared_package="svc-pkg", chain_state="MATCH", risk_tier="LOW",
    )
    monitor._baseline_initialized = True
    monitor._baseline_created_at = time.time()
    monitor._save_baseline()
    with open(monitor.config.baseline_state_path) as f:
        on_disk = json.load(f)
    assert on_disk["_meta"]["initialized"] is True
    assert on_disk["units"]["svc.service"]["declared_package"] == "svc-pkg"
    reloaded = _make_monitor(baseline_state_path=monitor.config.baseline_state_path)
    reloaded._load_baseline()
    assert reloaded._baseline_initialized is True
    assert reloaded._baseline["svc.service"].declared_package == "svc-pkg"
    assert reloaded._baseline["svc.service"].chain_state == "MATCH"
    print("Test 33 (baseline round-trips through the new _meta-wrapped format, including new fields) PASSED")

    monitor = _make_monitor(failure_threshold_count=2, failure_threshold_window_seconds=300.0)
    collected, sub = await _collect(monitor)
    for _ in range(5):
        monitor._record_failure("flaky.service")
    assert monitor._failure_crossed_threshold("flaky.service") is True
    monitor._publish_service_incident("flaky.service")
    monitor._publish_service_incident("flaky.service")
    monitor._publish_service_incident("flaky.service")
    await sub.queue.join()
    incident_events = [e for e in collected if e.category == EventCategory.SYSTEMD_SERVICE_INCIDENT]
    assert len(incident_events) == 1, (
        f"a service cycling through repeated failures must become ONE incident, not {len(incident_events)}"
    )
    assert len(monitor._incident_engine) == 1
    print("Test 34 (repeated restart/failure cycling coalesces into exactly one incident) PASSED")
    await monitor.bus.unsubscribe("collector")

    monitor = _make_monitor()
    collected, sub = await _collect(monitor)
    monitor._incident_engine.report("systemd_service:flaky.service", "flaky.service", kind="SYSTEMD_SERVICE_INCIDENT")
    monitor._open_incident_units.add("flaky.service")
    monitor._maybe_handle_recovery("flaky.service")
    monitor._maybe_handle_recovery("flaky.service")
    await sub.queue.join()
    recovered_events = [
        e for e in collected
        if e.category == EventCategory.SYSTEMD_SERVICE_INCIDENT
        and e.metadata.get("event_type") == "SYSTEMD_SERVICE_RECOVERED"
    ]
    assert len(recovered_events) == 1, f"recovery must be reported exactly once, got {len(recovered_events)}"
    print("Test 35 (recovery notification sent exactly once, never repeatedly) PASSED")
    await monitor.bus.unsubscribe("collector")

    monitor = _make_monitor(aggregation_spike_threshold=5)
    collected, sub = await _collect(monitor)
    units = [f"svc{i}.service" for i in range(10)]
    await monitor._handle_failures(units)
    await sub.queue.join()
    incident_events = [e for e in collected if e.category == EventCategory.SYSTEMD_SERVICE_INCIDENT]
    assert len(incident_events) == 1, f"10 simultaneous failures must become ONE spike event, got {len(incident_events)}"
    assert incident_events[0].metadata["event_type"] == "SYSTEMD_SERVICE_FAILURE_SPIKE"
    assert incident_events[0].metadata["affected_count"] == 10
    print("Test 36 (10 simultaneous service failures aggregate into one SYSTEMD_SERVICE_FAILURE_SPIKE) PASSED")
    await monitor.bus.unsubscribe("collector")

    long_list = list(range(500))
    long_string = "x" * 5000
    bounded = _bounded_metadata({"units": long_list, "note": long_string, "count": 3})
    assert len(bounded["units"]) <= 50
    assert len(bounded["note"]) <= 500
    assert bounded["count"] == 3
    print("Test 37 (metadata lists/strings are bounded before publish) PASSED")

    monitor = _make_monitor()
    monitor._scan_in_progress = True
    await monitor._scan_once()
    assert monitor._scans_skipped_overlap_total == 1
    assert monitor._scans_completed_total == 0
    print("Test 38 (overlapping scan attempt is skipped, never runs concurrently) PASSED")

    with open("modules/systemd_monitor.py", "r") as f:
        source = f.read()
    assert "create_task" not in source
    assert "ensure_future" not in source
    print("Test 39 (module never creates per-unit/per-event asyncio tasks) PASSED")

    monitor = _make_monitor()

    async def raising_list_systemd_services():
        raise OSError("systemctl unavailable")

    systemd_monitor.list_systemd_services = raising_list_systemd_services
    await monitor._scan_once()
    assert monitor._scans_completed_total == 1
    print("Test 40 (systemd reader error is caught, does not crash the module or process) PASSED")

    assert "main.py" not in source
    assert "subprocess.Popen" not in source
    assert "os.fork" not in source
    assert "os.exec" not in source
    print("Test 41 (module contains no mechanism capable of spawning another main.py/RTSA process) PASSED")

    forbidden_calls = [
        "systemctl start", "systemctl stop", "systemctl restart", "systemctl enable",
        "systemctl disable", "daemon-reload", "os.kill",
    ]
    for forbidden in forbidden_calls:
        assert forbidden not in source, f"forbidden remediation call found: {forbidden}"
    print("Test 42 (no remediation/mutating systemctl calls anywhere in the module) PASSED")

    assert "DiscordWebhookDispatcher(" not in source
    assert "aiohttp.ClientSession(" not in source
    assert "self.publish(" in source
    print("Test 43 (module reuses BaseModule.publish()/EventBus, builds no new Discord client) PASSED")

    for forbidden_exception in ("unit ==", "unit_base ==", 'if unit == "chrony', 'if unit == "fail2ban'):
        assert forbidden_exception not in source, (
            f"forbidden per-unit-name hardcoded exception found: {forbidden_exception!r} -- the detector must "
            f"understand legitimate chains generically, never via a narrow per-service allowlist"
        )
    print("Test 44 (no hardcoded per-unit-name exceptions like 'if unit == chrony.service: ignore()') PASSED")

    monitor = _make_monitor(aggregation_spike_threshold=5)
    collected, sub = await _collect(monitor)
    units_100 = [f"synthetic{i}.service" for i in range(100)]
    await monitor._handle_failures(units_100)
    await sub.queue.join()
    incident_events = [e for e in collected if e.category == EventCategory.SYSTEMD_SERVICE_INCIDENT]
    assert len(incident_events) == 1, f"100 synthetic failures must not explode into many alerts, got {len(incident_events)}"
    print("Test 45 (100 synthetic simultaneous service failures produce exactly ONE aggregated alert) PASSED")
    await monitor.bus.unsubscribe("collector")

    tce_config = TceConfig()
    memfd_candidate = CorrelationCandidateEvent(
        event_id="1", timestamp=time.time(), category="SYSTEMD_MEMFD_EXECUTION", severity="HIGH",
        message="", source_module="systemd_monitor",
    )
    classified = classify_event(memfd_candidate, tce_config)
    assert classified.kind == "Systemd memfd execution"
    assert classified.weight >= 45
    assert classified.high_confidence is True
    print("Test 46 (SYSTEMD_MEMFD_EXECUTION classifies as a high-confidence correlation contributor) PASSED")

    incident_candidate = CorrelationCandidateEvent(
        event_id="2", timestamp=time.time(), category="SYSTEMD_SERVICE_INCIDENT", severity="MEDIUM",
        message="", source_module="systemd_monitor",
    )
    classified2 = classify_event(incident_candidate, tce_config)
    assert classified2.kind == "Systemd service incident"
    assert classified2.weight < classify_event(memfd_candidate, tce_config).weight
    print("Test 47 (a bare flapping-service incident correlates at low weight, never auto-concluded malicious alone) PASSED")

    for unit_count in (100, 500, 1000):
        monitor = _make_monitor(max_units_per_scan=unit_count, ignore_services=["systemd-*.service"])
        collected, sub = await _collect(monitor)
        service_dict = {f"bench{i}.service": {"enabled": True, "active": True} for i in range(unit_count)}

        subprocess_calls = {"properties": 0, "package_owner": 0}

        async def fake_list_bench():
            return service_dict

        async def fake_props_bench(unit):
            subprocess_calls["properties"] += 1
            return {
                "ExecStart": "{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no }", "FragmentPath": "", "User": "root",
                "ActiveState": "active", "SubState": "running", "LoadState": "loaded", "MainPID": "0",
            }

        async def fake_resolve_owner_bench(path):
            subprocess_calls["package_owner"] += 1
            return "coreutils"

        systemd_monitor.list_systemd_services = fake_list_bench
        systemd_monitor.get_unit_properties = fake_props_bench
        systemd_monitor.resolve_path_package_owner = fake_resolve_owner_bench

        started = time.monotonic()
        await monitor._run_scan_cycle()
        await sub.queue.join()
        duration = time.monotonic() - started

        assert subprocess_calls["properties"] == unit_count
        assert subprocess_calls["package_owner"] == 1, (
            "package ownership lookups for the same declared path must be cached, not repeated per unit "
            f"-- got {subprocess_calls['package_owner']} calls for {unit_count} units sharing one path"
        )
        assert duration < 5.0, f"{unit_count}-unit scan took {duration:.2f}s -- too slow for a lightweight monitor"
        print(
            f"Test 48.{unit_count} (SYNTHETIC benchmark: {unit_count} units -> "
            f"{subprocess_calls['properties']} property lookups, {subprocess_calls['package_owner']} package "
            f"lookup (cached), {duration:.3f}s, single-flight scan, no per-unit Discord flood) PASSED"
        )
        assert len(monitor._baseline) <= monitor.config.max_units_per_scan
        assert len(collected) == 0, "first-scan baseline creation must never publish events even at scale"
        await monitor.bus.unsubscribe("collector")

    monitor = _make_monitor(max_tracked_units=10, max_units_per_scan=500)
    monitor._baseline_initialized = True
    service_dict = {f"cap{i}.service": {"enabled": True, "active": True} for i in range(50)}

    async def fake_list_cap():
        return service_dict

    async def fake_props_cap(unit):
        return {"ExecStart": "{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no }", "FragmentPath": "", "User": "root",
                "ActiveState": "active", "SubState": "running", "LoadState": "loaded", "MainPID": "0"}

    systemd_monitor.list_systemd_services = fake_list_cap
    systemd_monitor.get_unit_properties = fake_props_cap
    systemd_monitor.resolve_path_package_owner = fake_resolve_owner_bench
    await monitor._run_scan_cycle()
    assert len(monitor._baseline) <= 10, (
        f"baseline must be bounded by max_tracked_units=10, got {len(monitor._baseline)}"
    )
    print("Test 49 (baseline dict is bounded by max_tracked_units, oldest entries evicted first) PASSED")

    from config.manager import DiscordConfig
    from discord_integration.webhook import DiscordWebhookDispatcher

    systemd_only_channels = {category: _SYSTEMD_CHANNEL_ID for category in _SYSTEMD_EVENT_CATEGORIES}
    dispatcher_cfg = DiscordConfig(
        alert_channel_id=999000999000999000,
        category_channels={
            **systemd_only_channels,
            "SSH_AUTH": 111000111000111000,
            "WEBSITE_DOWN": 222000222000222000,
            "FILE_INTEGRITY_CHANGE": 333000333000333000,
            "NGINX_RATE_ANOMALY": 444000444000444000,
        },
    )
    dispatcher = DiscordWebhookDispatcher(EventBus(), dispatcher_cfg)

    monitor = _make_monitor()
    fim_event = BaseEvent(
        source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
        severity=Severity.MEDIUM, message="", raw="",
        metadata={"path": "/etc/systemd/system/systemds.service"},
    )
    await monitor._on_fim_event(fim_event)
    assert "systemds.service" in monitor._fim_unit_signals
    monitor._update_baseline_state("systemds.service", {"enabled": True, "active": True})
    fim_trigger = monitor._determine_trigger(
        "systemds.service", {"enabled": True, "active": True}, fim_changed=True,
    )
    assert fim_trigger == "unit_file_changed"
    print("Test 50a (FIM path change mapped to unit name, feeds trigger detection -- no second crawler) PASSED")

    monitor = _make_monitor()
    collected, sub = await _collect(monitor)
    monitor._update_baseline_state("stable.service", {"enabled": True, "active": True})
    trigger = monitor._determine_trigger("stable.service", {"enabled": True, "active": True}, fim_changed=False)
    assert trigger is None
    await sub.queue.join()
    assert len(collected) == 0, "a plain unchanged/normal systemd state must never publish a bus event"
    print("Test 50 (normal systemd event stays INTERNAL_ONLY -- no bus event, no Discord message) PASSED")
    await monitor.bus.unsubscribe("collector")

    for category in _SYSTEMD_EVENT_CATEGORIES:
        resolved = dispatcher._resolve_channel_id(category, "systemd_monitor")
        assert resolved == _SYSTEMD_CHANNEL_ID
    print("Test 51 (every systemd category, including the new taxonomy, resolves to the Systemd Monitor channel) PASSED")

    unrelated = {
        "SSH_AUTH": 111000111000111000, "WEBSITE_DOWN": 222000222000222000,
        "FILE_INTEGRITY_CHANGE": 333000333000333000, "NGINX_RATE_ANOMALY": 444000444000444000,
    }
    for category, expected_channel in unrelated.items():
        resolved = dispatcher._resolve_channel_id(category, "some_other_module")
        assert resolved == expected_channel
        assert resolved != _SYSTEMD_CHANNEL_ID
    for category in _SYSTEMD_EVENT_CATEGORIES:
        resolved = dispatcher._resolve_channel_id(category, "systemd_monitor")
        assert resolved not in unrelated.values()
    print(
        "Test 52 (no systemd category routes to SSH/Website/FIM/Nginx channels, and none of those "
        "route to the systemd channel) PASSED"
    )

    with open("modules/systemd_monitor.py", "r") as f:
        module_source = f.read()
    assert "1545778622902833214" not in module_source
    assert "alert_channel_id" not in module_source
    print("Test 53 (the systemd channel ID is never hardcoded in modules/systemd_monitor.py) PASSED")

    print("\nALL SYSTEMD MONITOR TESTS PASSED")


asyncio.run(main())
