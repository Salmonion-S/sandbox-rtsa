from __future__ import annotations

import asyncio
import os
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.analyzer as analyzer_module
from config.manager import DiscordConfig, SSHMonitorConfig
from core.analyzer import StatefulAnalyzer
from core.datatypes import BaseEvent, EventCategory, SSHEvent, Severity
from core.event_bus import EventBus
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.ssh_monitor import (
    SSHMonitor, _discover_listening_ssh_ports, _read_ssh_dest_ports, _resolve_ssh_dest_ports,
)


class _FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _make_analyzer(clock: _FakeClock, **overrides) -> StatefulAnalyzer:
    kwargs = dict(
        ssh_brute_force_threshold=5, ssh_brute_force_window_seconds=60,
        ssh_credential_stuffing_threshold=8, ssh_credential_stuffing_window_seconds=1800,
        ssh_credential_stuffing_min_distinct_ips=3, ssh_red_zone_cooldown_seconds=300.0,
    )
    kwargs.update(overrides)
    analyzer = StatefulAnalyzer(EventBus(), **kwargs)
    analyzer_module.time = clock
    return analyzer


def _failed_event(username: str, ip: str, *, status: str, ts: float, metadata: dict) -> SSHEvent:
    return SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.MEDIUM,
        message=f"SSH login GAGAL untuk '{username}' dari {ip}", raw="", username=username,
        source_ip=ip, auth_method=None, success=False, timestamp=ts,
        metadata={"username_status": status, **metadata},
    )


def main_sync() -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write("# example sshd_config\nPort 23109\nPermitRootLogin no\n")
        path = f.name
    try:
        ports = _read_ssh_dest_ports(path)
        assert ports == {23109}, f"expected the configured port, got {ports}"
        resolved, source = _resolve_ssh_dest_ports(path)
        assert resolved == {23109} and source == "sshd_config"
    finally:
        os.unlink(path)
    print("Test 1 (an explicit sshd_config Port directive is read and reported as source=sshd_config) PASSED")

    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write("Port 22\nPort 2222\n")
        path = f.name
    try:
        ports = _read_ssh_dest_ports(path)
        assert ports == {22, 2222}, f"expected both configured ports, got {ports}"
    finally:
        os.unlink(path)
    print("Test 2 (multiple sshd_config Port directives are all captured) PASSED")

    missing_path = "/nonexistent/path/sshd_config_for_test"
    assert _read_ssh_dest_ports(missing_path) == set(), "an unreadable config must yield an empty set, not a silent {22}"

    import modules.ssh_monitor as ssh_monitor_module
    orig_scan = ssh_monitor_module.RemoteAccessDetector._scan_listeners
    try:
        ssh_monitor_module.RemoteAccessDetector._scan_listeners = staticmethod(
            lambda: [(23109, "sshd", 4242, "0.0.0.0"), (443, "nginx", 100, "0.0.0.0")]
        )
        discovered = _discover_listening_ssh_ports()
        assert discovered == {23109}, f"expected the actual listening sshd port, got {discovered}"
        resolved, source = _resolve_ssh_dest_ports(missing_path)
        assert resolved == {23109} and source == "listening_socket", (
            f"missing sshd_config must fall back to the real listening socket before defaulting -- got {(resolved, source)}"
        )
    finally:
        ssh_monitor_module.RemoteAccessDetector._scan_listeners = orig_scan
    print("Test 3 (missing sshd_config falls back to the actual listening socket, not a guess) PASSED")

    try:
        ssh_monitor_module.RemoteAccessDetector._scan_listeners = staticmethod(lambda: [])
        resolved, source = _resolve_ssh_dest_ports(missing_path)
        assert resolved == {22} and source == "default_fallback"
    finally:
        ssh_monitor_module.RemoteAccessDetector._scan_listeners = orig_scan
    print("Test 4 (no config and no listening socket -> port 22 used only as a labeled last-resort fallback) PASSED")

    clock = _FakeClock()
    an = _make_analyzer(clock)

    async def _drive() -> BaseEvent:
        ip = "94.177.195.107"
        base_meta = {
            "hostname": "srv-jkt-02", "server_name": "Server2",
            "ssh_service": "sshd", "ssh_port": 23109, "ssh_port_source": "sshd_config",
        }
        captured = []

        async def _sink(event: BaseEvent) -> None:
            captured.append(event)

        await an.bus.subscribe("test-sink", _sink, categories=[EventCategory.BRUTE_FORCE])
        for i in range(6):
            await an._on_event(_failed_event(f"user{i}", ip, status="INVALID_USER", ts=clock.now, metadata=base_meta))
            clock.advance(1.0)
        await an.bus.unsubscribe("test-sink")
        assert len(captured) == 1, f"expected exactly one BRUTE_FORCE alert, got {len(captured)}"
        return captured[0]

    alert = asyncio.run(_drive())
    assert alert.metadata.get("ssh_port") == 23109, alert.metadata
    assert alert.metadata.get("ssh_port_source") == "sshd_config", alert.metadata
    assert alert.metadata.get("server_name") == "Server2", alert.metadata
    assert alert.metadata.get("hostname") == "srv-jkt-02", alert.metadata
    print("Test 5 (ssh_port/server_name/hostname on the triggering SSH_AUTH event survive into the BRUTE_FORCE alert) PASSED")

    dispatcher = DiscordWebhookDispatcher(
        EventBus(), DiscordConfig(enabled=True, alert_channel_id=555000), detection_only=False,
    )
    payload = dispatcher._build_payload(alert)
    field_map = {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}
    assert field_map["SSH Port"] == "23109", field_map
    assert field_map["Protocol"] == "TCP", field_map
    assert field_map["Source IP"] == "94.177.195.107", field_map
    assert field_map["Target Server"] == "Server2", field_map
    print("Test 6 (BRUTE_FORCE Discord embed shows real SSH Port/Protocol/Source IP/Target Server, not N/A) PASSED")

    bare_alert = BaseEvent(
        source_module="analyzer", category=EventCategory.BRUTE_FORCE, severity=Severity.HIGH,
        message="Correlated rule 'ssh_brute_force' triggered", raw="",
        metadata={"source_ip": "1.2.3.4", "observed_count": 5, "window_seconds": 60, "unique_usernames": 1},
    )
    bare_payload = dispatcher._build_payload(bare_alert)
    bare_fields = {f["name"]: f["value"] for f in bare_payload["embeds"][0]["fields"]}
    assert bare_fields["SSH Port"] == "N/A", bare_fields
    assert bare_fields["Protocol"] == "N/A", bare_fields
    assert bare_fields["Target Server"] == "N/A", bare_fields
    print("Test 7 (when the port genuinely isn't known, the field shows N/A instead of guessing) PASSED")

    mon = SSHMonitor(EventBus(), SSHMonitorConfig(enabled=True, geoip_lookup=False))
    mon._ssh_dest_port = 23109
    mon._ssh_dest_port_source = "sshd_config"
    meta = mon._base_metadata("40001")
    assert meta["ssh_port"] == 23109
    assert meta["ssh_port_source"] == "sshd_config"
    assert meta["source_port"] == 40001
    print("Test 8 (SSHMonitor._base_metadata attaches the resolved ssh_port/source to every SSH event) PASSED")

    fallback_alert = BaseEvent(
        source_module="analyzer", category=EventCategory.BRUTE_FORCE, severity=Severity.HIGH,
        message="Correlated rule 'ssh_brute_force' triggered", raw="",
        metadata={
            "source_ip": "5.6.7.8", "observed_count": 5, "window_seconds": 60, "unique_usernames": 1,
            "ssh_port": 22, "ssh_port_source": "default_fallback",
        },
    )
    fallback_payload = dispatcher._build_payload(fallback_alert)
    fallback_fields = {f["name"]: f["value"] for f in fallback_payload["embeds"][0]["fields"]}
    assert fallback_fields["SSH Port"] == "UNKNOWN", fallback_fields
    assert fallback_fields["Protocol"] == "TCP", fallback_fields
    print("Test 9 (an unresolved port shows the literal UNKNOWN, never a guessed number) PASSED")

    print("\nALL BRUTE_FORCE SSH PORT FIELD TESTS PASSED")


main_sync()
