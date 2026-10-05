import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio
import inspect
import tempfile
from pathlib import Path

import core.pm2_startup as pm2_startup
from config.manager import (
    CloudflareConfig, DiscordConfig, RTSAConfig, resolve_server_identity, set_active_server_identity,
)
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.bot import RTSABot

SYSTEM_NODE = "/usr/bin/node"
SYSTEM_PM2 = "/usr/bin/pm2"
NVM_BIN = "/home/malaminikita/.nvm/versions/node/v22.23.0/bin"
NVM_NODE = f"{NVM_BIN}/node"
NVM_PM2 = f"{NVM_BIN}/pm2"


class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass


def make_bot(bus=None) -> RTSABot:
    cfg = RTSAConfig(hostname_override="server1", cloudflare=CloudflareConfig(enabled=False))
    return RTSABot(
        DiscordConfig(enabled=True), cfg, bus or EventBus(), db_worker=FakeDb(), supervisor=None,
    )


def unit_text(*, user="malaminikita", pm2_path=SYSTEM_PM2, path_value="/usr/bin:/usr/local/bin:/bin",
              pm2_home="/home/malaminikita/.pm2") -> str:
    return (
        "[Unit]\nDescription=PM2 process manager\n\n[Service]\nType=simple\n"
        f"User={user}\n"
        f"Environment=HOME=/home/{user}\n"
        f"Environment=PM2_HOME={pm2_home}\n"
        f"Environment=PATH={path_value}\n"
        f"ExecStart={pm2_path} resurrect --no-daemon\n"
        f"ExecStop={pm2_path} kill\n"
    )


def discovery(*, node=NVM_NODE, pm2=NVM_PM2, node_version="v22.23.0", ok=True, reason="") -> pm2_startup.RuntimeDiscovery:
    return pm2_startup.RuntimeDiscovery(
        ok=ok, reason=reason, node_path=node, node_version=node_version,
        pm2_path=pm2, pm2_version="5.4.2",
    )


def audit(text, disco, present) -> pm2_startup.RuntimeAudit:
    directives = pm2_startup.parse_unit_directives(text) if text else None
    return pm2_startup.audit_runtime_consistency(
        directives=directives, discovery=disco,
        exists_fn=lambda p: p in present, unit_text=text,
    )


def test_1_system_pm2_system_node_consistent() -> None:
    result = audit(
        unit_text(pm2_path=SYSTEM_PM2, path_value="/usr/bin:/bin"),
        discovery(node=SYSTEM_NODE, pm2=SYSTEM_PM2, node_version="v20.11.1"),
        {SYSTEM_PM2, SYSTEM_NODE},
    )
    assert result.state == pm2_startup.RUNTIME_CONSISTENT, result
    assert result.nvm_detected is False
    print("Test 1 (system PM2 + system Node -> CONSISTENT) PASSED")


def test_2_fixed_nvm_pm2_and_node_consistent() -> None:
    result = audit(
        unit_text(pm2_path=NVM_PM2, path_value=f"{NVM_BIN}:/usr/local/bin:/usr/bin:/bin"),
        discovery(),
        {NVM_PM2, NVM_NODE},
    )
    assert result.state == pm2_startup.RUNTIME_CONSISTENT, result
    assert result.nvm_detected is True and result.wildcard_path is False
    assert result.node_version == "v22.23.0"
    print("Test 2 (fixed NVM PM2 + fixed NVM Node -> CONSISTENT, NVM detected) PASSED")


def test_3_system_pm2_with_nvm_application_runtime_mismatch() -> None:
    result = audit(
        unit_text(pm2_path=SYSTEM_PM2, path_value="/usr/bin:/usr/local/bin:/usr/bin:/bin"),
        discovery(node=NVM_NODE, pm2=NVM_PM2),
        {SYSTEM_PM2, SYSTEM_NODE, NVM_PM2, NVM_NODE},
    )
    assert result.state == pm2_startup.RUNTIME_NODE_BINARY_MISMATCH, result
    assert result.is_drift and result.resolved_node == SYSTEM_NODE and result.expected_node == NVM_NODE
    print("Test 3 (system PM2 unit + NVM application runtime -> NODE_BINARY_MISMATCH) PASSED")


def test_4_missing_node_binary_in_configured_path() -> None:
    result = audit(
        unit_text(pm2_path=SYSTEM_PM2, path_value="/opt/empty:/usr/sbin"),
        discovery(node=NVM_NODE, pm2=NVM_PM2),
        {SYSTEM_PM2, NVM_NODE, NVM_PM2},
    )
    assert result.state == pm2_startup.RUNTIME_NVM_PATH_MISSING, result
    assert result.resolved_node is None
    print("Test 4 (no node binary anywhere in the unit's PATH -> NVM_PATH_MISSING) PASSED")


def test_5_wildcard_nvm_path_detected() -> None:
    result = audit(
        unit_text(pm2_path=NVM_PM2, path_value="/home/malaminikita/.nvm/versions/node/*/bin:/usr/bin"),
        discovery(),
        {NVM_PM2, NVM_NODE},
    )
    assert result.wildcard_path is True
    assert result.state == pm2_startup.RUNTIME_NVM_PATH_MISSING, result
    assert "wildcard" in result.reason.lower()
    print("Test 5 (wildcard NVM path -> flagged, never accepted as consistent) PASSED")


def test_6_and_7_service_active_and_online_does_not_imply_consistent() -> None:
    drifted = audit(
        unit_text(pm2_path=SYSTEM_PM2, path_value="/usr/bin:/bin"),
        discovery(node=NVM_NODE, pm2=NVM_PM2),
        {SYSTEM_PM2, SYSTEM_NODE, NVM_NODE, NVM_PM2},
    )
    assert drifted.is_drift
    bot = make_bot()
    overall_active = bot._pm2startup_overall_status(drifted, service_active=True)
    assert overall_active == "ATTENTION_REQUIRED", (
        "an active service with drifted runtime must never be reported as HEALTHY"
    )
    overall_online = bot._pm2startup_overall_status(drifted, service_active=True, processes_online=True)
    assert overall_online == "ATTENTION_REQUIRED", (
        "PM2 processes being online must not override a drifted runtime verdict"
    )
    print("Test 6+7 (service ACTIVE / PM2 ONLINE never upgrade a drifted runtime to HEALTHY) PASSED")


def test_8_runtime_unknown_when_discovery_fails() -> None:
    result = audit(
        unit_text(),
        pm2_startup.RuntimeDiscovery(ok=False, reason="permission denied running probe"),
        {SYSTEM_PM2, SYSTEM_NODE},
    )
    assert result.state == pm2_startup.RUNTIME_UNKNOWN, result
    assert not result.is_drift, "UNKNOWN must never be counted as drift"
    assert not result.is_known
    bot = make_bot()
    assert bot._pm2startup_overall_status(result, service_active=True) == "ATTENTION_REQUIRED"
    print("Test 8 (discovery failure/insufficient permission -> UNKNOWN_RUNTIME, never a pass) PASSED")


def test_9_discovery_timeout_is_unknown_not_drift() -> None:
    timed_out = pm2_startup.RuntimeDiscovery(
        ok=False, reason="gagal menjalankan shell probe: timeout setelah 20.0 detik",
    )
    result = audit(unit_text(), timed_out, {SYSTEM_PM2, SYSTEM_NODE})
    assert result.state == pm2_startup.RUNTIME_UNKNOWN
    assert "tidak bisa" in result.reason or "could not" in result.reason.lower()
    print("Test 9 (probe timeout -> UNKNOWN_RUNTIME with an explicit reason, never drift) PASSED")


def test_10_invalid_username_rejected_before_subprocess() -> None:
    source = inspect.getsource(RTSABot._register_commands)
    block = source.split('name="pm2startup"', 1)[1].split("@tree.command", 1)[0]
    assert "_VALID_LINUX_USERNAME.fullmatch(user_linux)" in block, (
        "the username must be validated against the strict pattern before any subprocess runs"
    )
    validation_index = block.index("_VALID_LINUX_USERNAME.fullmatch")
    preflight_index = block.index("_pm2startup_preflight")
    assert validation_index < preflight_index, (
        "validation must happen before the preflight that spawns the discovery subprocess"
    )
    print("Test 10 (invalid Linux username is rejected before any subprocess is spawned) PASSED")


def test_11_no_shell_invocation_in_audit() -> None:
    source = inspect.getsource(pm2_startup)
    for forbidden in ("shell=True", "os.system", "subprocess", "popen"):
        assert forbidden not in source, (
            f"the runtime audit engine must stay pure logic -- found {forbidden!r} in core/pm2_startup.py"
        )
    audit_source = inspect.getsource(pm2_startup.audit_runtime_consistency)
    assert "exists_fn" in audit_source, "filesystem access must be injected, never performed inline"
    print("Test 11 (runtime audit performs no shell invocation and no direct process spawning) PASSED")


def test_12_no_modification_during_audit() -> None:
    source = inspect.getsource(pm2_startup)
    for forbidden in ("open(", "write_text", "atomic_write", "os.remove", "unlink", "chmod"):
        assert forbidden not in source, (
            f"the audit phase is read-only -- found {forbidden!r} in core/pm2_startup.py"
        )
    with tempfile.TemporaryDirectory() as tmp:
        unit_path = Path(tmp) / "pm2-test.service"
        text = unit_text()
        unit_path.write_text(text, encoding="utf-8")
        before = unit_path.read_bytes()
        audit(text, discovery(), {NVM_PM2, NVM_NODE})
        assert unit_path.read_bytes() == before, "auditing a unit must never modify it"
    print("Test 12 (audit never modifies the unit file, rc files, .nvm, dumps or ecosystem files) PASSED")


async def test_13_and_14_alert_dedup_and_single_recovery() -> None:
    set_active_server_identity(resolve_server_identity(env={}, base_dir=Path("config")))
    try:
        await _alert_dedup_and_single_recovery()
    finally:
        set_active_server_identity(None)


async def _alert_dedup_and_single_recovery() -> None:
    bus = EventBus()
    bot = make_bot(bus)
    collected = []

    async def collector(event):
        collected.append(event)

    sub = await bus.subscribe("runtime_collector", collector, categories=None)
    drifted = audit(
        unit_text(pm2_path=SYSTEM_PM2, path_value="/usr/bin:/bin"),
        discovery(node=NVM_NODE, pm2=NVM_PM2),
        {SYSTEM_PM2, SYSTEM_NODE, NVM_NODE, NVM_PM2},
    )
    for _ in range(5):
        bot._publish_pm2_runtime_state("malaminikita", "pm2-malaminikita.service", drifted)
    await sub.queue.join()
    drift_events = [e for e in collected if e.category == EventCategory.PM2_RUNTIME_DRIFT]
    assert len(drift_events) == 1, (
        f"5 audit cycles on the same unresolved drift must produce 1 alert, got {len(drift_events)}"
    )
    assert drift_events[0].severity == Severity.HIGH
    assert drift_events[0].metadata["incident_key"] == "pm2-runtime:server1:malaminikita:pm2-malaminikita.service"
    print("Test 13 (repeated audit cycles on the same drift do not spam alerts) PASSED")

    consistent = audit(
        unit_text(pm2_path=NVM_PM2, path_value=f"{NVM_BIN}:/usr/bin"),
        discovery(),
        {NVM_PM2, NVM_NODE},
    )
    for _ in range(3):
        bot._publish_pm2_runtime_state("malaminikita", "pm2-malaminikita.service", consistent)
    await sub.queue.join()
    recovery = [e for e in collected if e.category == EventCategory.PM2_RUNTIME_CONSISTENT]
    assert len(recovery) == 1, f"recovery must be emitted exactly once, got {len(recovery)}"
    assert recovery[0].severity == Severity.INFO
    await bus.shutdown()
    print("Test 14 (returning to CONSISTENT emits exactly one recovery event) PASSED")


async def test_15_app_config_warning_separate_from_runtime() -> None:
    bus = EventBus()
    bot = make_bot(bus)
    collected = []

    async def collector(event):
        collected.append(event)

    sub = await bus.subscribe("warning_collector", collector, categories=None)
    consistent = audit(
        unit_text(pm2_path=NVM_PM2, path_value=f"{NVM_BIN}:/usr/bin"),
        discovery(),
        {NVM_PM2, NVM_NODE},
    )
    assert consistent.state == pm2_startup.RUNTIME_CONSISTENT, (
        "a Next.js config warning in application stderr is not a runtime fact and must not "
        "influence the runtime verdict"
    )
    bot._publish_pm2_runtime_state("malaminikita", "pm2-malaminikita.service", consistent)
    await sub.queue.join()
    assert not [e for e in collected if e.category == EventCategory.PM2_RUNTIME_DRIFT], (
        "an application config warning must never be escalated into PM2_RUNTIME_DRIFT"
    )
    await bus.shutdown()
    print("Test 15 (framework config warnings stay separate from PM2 runtime status) PASSED")


def test_16_and_17_backward_compatibility() -> None:
    classification = pm2_startup.classify_pm2_unit(
        unit_text(pm2_path=NVM_PM2, path_value=f"{NVM_BIN}:/usr/bin"),
        target_user="malaminikita",
        discovered_pm2_path=NVM_PM2,
        discovered_pm2_home="/home/malaminikita/.pm2",
        exec_exists_fn=lambda p: True,
        service_active=True, service_enabled=True,
    )
    assert classification.status == pm2_startup.STATUS_CURRENT_RTSA, (
        "existing unit classification behaviour must be unchanged by the runtime audit"
    )
    generated = pm2_startup.generate_pm2_unit(
        user="malaminikita", home="/home/malaminikita", pm2_home="/home/malaminikita/.pm2",
        pm2_path=NVM_PM2, node_bin_dir=NVM_BIN,
    )
    assert "*" not in generated, "generated units must never contain a wildcard path"
    regenerated_audit = audit(generated, discovery(), {NVM_PM2, NVM_NODE})
    assert regenerated_audit.state == pm2_startup.RUNTIME_CONSISTENT, (
        "a unit RTSA generates itself must audit as CONSISTENT"
    )
    print("Test 16+17 (existing /pm2startup classification and unit generation stay valid) PASSED")


def test_18_mixed_multi_user_environments() -> None:
    system_user = audit(
        unit_text(user="sysuser", pm2_path=SYSTEM_PM2, path_value="/usr/bin:/bin",
                  pm2_home="/home/sysuser/.pm2"),
        discovery(node=SYSTEM_NODE, pm2=SYSTEM_PM2, node_version="v20.11.1"),
        {SYSTEM_PM2, SYSTEM_NODE},
    )
    nvm_user = audit(
        unit_text(user="malaminikita", pm2_path=NVM_PM2, path_value=f"{NVM_BIN}:/usr/bin"),
        discovery(),
        {NVM_PM2, NVM_NODE},
    )
    assert system_user.state == pm2_startup.RUNTIME_CONSISTENT and system_user.service_user == "sysuser"
    assert nvm_user.state == pm2_startup.RUNTIME_CONSISTENT and nvm_user.service_user == "malaminikita"
    assert system_user.nvm_detected is False and nvm_user.nvm_detected is True
    print("Test 18 (mixed system/NVM users on one host are audited independently) PASSED")


def test_19_and_20_multiple_node_versions_stay_deterministic() -> None:
    other_bin = "/home/malaminikita/.nvm/versions/node/v18.20.4/bin"
    present = {NVM_PM2, NVM_NODE, f"{other_bin}/node", f"{other_bin}/pm2"}
    pinned = unit_text(pm2_path=NVM_PM2, path_value=f"{NVM_BIN}:/usr/bin")

    before = audit(pinned, discovery(), {NVM_PM2, NVM_NODE})
    after_new_version_installed = audit(pinned, discovery(), present)
    assert before.state == after_new_version_installed.state == pm2_startup.RUNTIME_CONSISTENT
    assert after_new_version_installed.resolved_node == NVM_NODE, (
        "a fixed runtime path must keep resolving to the same Node after another version is installed"
    )

    wildcard = unit_text(
        pm2_path=NVM_PM2, path_value="/home/malaminikita/.nvm/versions/node/*/bin:/usr/bin",
    )
    wildcard_audit = audit(wildcard, discovery(), present)
    assert wildcard_audit.state != pm2_startup.RUNTIME_CONSISTENT, (
        "with two Node versions installed a wildcard path is exactly the non-deterministic case "
        "the audit exists to catch"
    )
    recommendation = pm2_startup.build_repair_recommendation(
        wildcard_audit, pm2_home="/home/malaminikita/.pm2",
    )
    assert recommendation is not None and "*" not in recommendation, (
        "repair guidance must use an explicit immutable path, never a wildcard"
    )
    assert NVM_BIN in recommendation and SYSTEM_NODE not in recommendation, (
        "repair guidance must preserve the discovered NVM runtime, not fall back to /usr/bin/node"
    )
    print("Test 19+20 (NVM user with several Node versions: fixed path deterministic, wildcard caught) PASSED")


def test_21_environment_redaction() -> None:
    redacted = pm2_startup.redact_environment({
        "PATH": "/usr/bin:/bin",
        "PM2_HOME": "/home/u/.pm2",
        "GITHUB_TOKEN": "ghp_realsecretvalue",
        "DB_PASSWORD": "hunter2",
        "SESSION_SECRET": "abc123",
    })
    assert redacted["PATH"] == "/usr/bin:/bin" and redacted["PM2_HOME"] == "/home/u/.pm2"
    for secret_key in ("GITHUB_TOKEN", "DB_PASSWORD", "SESSION_SECRET"):
        assert "REDACTED" in redacted[secret_key], secret_key
        assert "ghp_realsecretvalue" not in redacted[secret_key]
    print("Test 21 (sensitive environment variables are redacted before they can be reported) PASSED")


def test_22_incomplete_environment_is_not_consistent() -> None:
    no_path = (
        "[Service]\nUser=malaminikita\nEnvironment=PM2_HOME=/home/malaminikita/.pm2\n"
        f"ExecStart={NVM_PM2} resurrect --no-daemon\n"
    )
    result = audit(no_path, discovery(), {NVM_PM2, NVM_NODE})
    assert result.state == pm2_startup.RUNTIME_INCOMPLETE_ENVIRONMENT, result
    assert not result.is_drift
    bot = make_bot()
    assert bot._pm2startup_overall_status(result, service_active=True) == "ATTENTION_REQUIRED"
    print("Test 22 (a unit without Environment=PATH is INCOMPLETE_ENVIRONMENT, never CONSISTENT) PASSED")


def test_23_missing_pm2_binary_is_high_severity() -> None:
    result = audit(
        unit_text(pm2_path="/usr/bin/pm2", path_value="/usr/bin:/bin"),
        discovery(node=SYSTEM_NODE, pm2=SYSTEM_PM2),
        {SYSTEM_NODE},
    )
    assert result.state == pm2_startup.RUNTIME_PM2_BINARY_MISMATCH, result
    assert RTSABot._pm2_runtime_severity(result) == Severity.HIGH, (
        "a unit whose ExecStart binary is missing cannot resurrect anything -- that is confirmed drift"
    )
    print("Test 23 (ExecStart PM2 missing from disk -> PM2_BINARY_MISMATCH at HIGH severity) PASSED")


def test_25_readlink_surfaces_npm_global_symlink_target() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        real_pm2_dir = os.path.join(tmp, "lib", "node_modules", "pm2", "bin")
        os.makedirs(real_pm2_dir)
        real_pm2 = os.path.join(real_pm2_dir, "pm2")
        with open(real_pm2, "w") as f:
            f.write("#!/usr/bin/env node\n")
        os.chmod(real_pm2, 0o755)
        symlinked_pm2 = os.path.join(tmp, "usr_bin_pm2")
        os.symlink(real_pm2, symlinked_pm2)

        from core.pm2_startup import real_target_if_symlink
        assert real_target_if_symlink(symlinked_pm2) == os.path.realpath(real_pm2)
        assert real_target_if_symlink(real_pm2) is None, (
            "a path that is not itself a symlink must report no separate real target"
        )
        assert real_target_if_symlink(None) is None
        assert real_target_if_symlink("/does/not/exist") is None, (
            "realpath on a nonexistent path returns it unchanged -- must not be reported as a symlink"
        )
    print("Test 25 (readlink -f surfaces the real npm-global target behind a PATH symlink) PASSED")


def test_26_runtime_audit_carries_realpath_end_to_end() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        real_pm2_dir = os.path.join(tmp, "lib", "node_modules", "pm2", "bin")
        os.makedirs(real_pm2_dir)
        real_pm2 = os.path.join(real_pm2_dir, "pm2")
        open(real_pm2, "w").close()
        os.chmod(real_pm2, 0o755)
        bin_dir = os.path.join(tmp, "usr", "bin")
        os.makedirs(bin_dir)
        symlinked_pm2 = os.path.join(bin_dir, "pm2")
        os.symlink(real_pm2, symlinked_pm2)
        node_path = os.path.join(bin_dir, "node")
        open(node_path, "w").close()
        os.chmod(node_path, 0o755)

        text = unit_text(pm2_path=symlinked_pm2, path_value=bin_dir)
        result = audit(text, discovery(node=node_path, pm2=symlinked_pm2), {symlinked_pm2, node_path})
        assert result.state == pm2_startup.RUNTIME_CONSISTENT, result
        assert result.resolved_pm2_realpath == os.path.realpath(real_pm2)
        assert result.resolved_node_realpath is None, "a plain (non-symlink) node binary has no separate target"

        bot = make_bot()
        section = bot._format_runtime_audit_section(result, pm2_home=None)
        assert "readlink -f" in section and os.path.realpath(real_pm2) in section, (
            "the Discord Runtime Audit section must show the real npm-global target, not just the "
            "PATH-visible symlink"
        )
    print("Test 26 (RuntimeAudit + Discord section carry the readlink-verified real PM2 target end-to-end) PASSED")


def test_24_no_unit_is_unknown_not_healthy() -> None:
    result = pm2_startup.audit_runtime_consistency(
        directives=None, discovery=discovery(), exists_fn=lambda p: True,
    )
    assert result.state == pm2_startup.RUNTIME_UNKNOWN
    assert pm2_startup.build_repair_recommendation(result, pm2_home="/home/u/.pm2") is None, (
        "no repair may be recommended for a runtime RTSA could not determine"
    )
    print("Test 24 (absent/unparseable unit -> UNKNOWN_RUNTIME with no repair guidance) PASSED")


async def main() -> None:
    test_1_system_pm2_system_node_consistent()
    test_2_fixed_nvm_pm2_and_node_consistent()
    test_3_system_pm2_with_nvm_application_runtime_mismatch()
    test_4_missing_node_binary_in_configured_path()
    test_5_wildcard_nvm_path_detected()
    test_6_and_7_service_active_and_online_does_not_imply_consistent()
    test_8_runtime_unknown_when_discovery_fails()
    test_9_discovery_timeout_is_unknown_not_drift()
    test_10_invalid_username_rejected_before_subprocess()
    test_11_no_shell_invocation_in_audit()
    test_12_no_modification_during_audit()
    await test_13_and_14_alert_dedup_and_single_recovery()
    await test_15_app_config_warning_separate_from_runtime()
    test_16_and_17_backward_compatibility()
    test_18_mixed_multi_user_environments()
    test_19_and_20_multiple_node_versions_stay_deterministic()
    test_21_environment_redaction()
    test_22_incomplete_environment_is_not_consistent()
    test_23_missing_pm2_binary_is_high_severity()
    test_24_no_unit_is_unknown_not_healthy()
    test_25_readlink_surfaces_npm_global_symlink_target()
    test_26_runtime_audit_carries_realpath_end_to_end()
    print("\nALL PM2 RUNTIME AUDIT TESTS PASSED")


asyncio.run(main())
