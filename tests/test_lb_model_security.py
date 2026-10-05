from __future__ import annotations

import os
import sys
import tempfile

_TESTS = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_TESTS)
sys.path.insert(0, _TESTS)
sys.path.insert(0, _REPO)
os.chdir(_REPO)
os.environ.setdefault("RTSA_DISCORD_BOT_TOKEN", "t0k3nAbCdEf0123456789QwErTy")
os.environ.setdefault("RTSA_CLOUDFLARE_API_TOKEN", "c10udF1areAbCdEf0123456789Zx")

import yaml

from config.manager import ConfigManager, ConfigValidationError, LoadBalancingConfig, RTSAConfig, _build_dataclass, _validate_load_balancing
from core.lb_model import (
    ServerInventoryEntry, forbidden_ip_reason, normalize_address, parse_lb_arguments, resolve_origin_arguments, scan_health_body,
    scrub, split_origin_arguments, validate_domain, validate_health_path, validate_port, validate_server_id,
)
from core.lb_state import LbStateStore, OperationRecord, redact_mapping
from core.lb_model import OpStatus

INVENTORY = [
    ServerInventoryEntry("server1", "Server1", "s1.internal", "203.0.113.11", "10.0.0.11", "both"),
    ServerInventoryEntry("server2", "Server2", "", "203.0.113.12", "10.0.0.12", "origin"),
    ServerInventoryEntry("orch", "Orch", "", "203.0.113.50", "", "orchestrator"),
]


def test_1_validators() -> None:
    assert validate_domain("Example.COM.")[0] == "example.com"
    for bad in ("", "localhost", "a/b.com", "../../etc/passwd", "exa mple.com", "1.2.3.4", "*.example.com", "x" * 300 + ".com", "a..com", "http://a.com"):
        assert validate_domain(bad)[0] is None, bad
    assert validate_server_id("Server2")[0] == "server2"
    for bad in ("", "1server", "a b", "a;b", "x" * 40, "../x"):
        assert validate_server_id(bad)[0] is None, bad
    assert validate_port("443")[0] == 443 and validate_port(3000)[0] == 3000
    for bad in (0, 65536, -1, "abc", None, True, "80;rm"):
        assert validate_port(bad)[0] is None, bad
    assert validate_health_path("/healthz")[0] == "/healthz"
    for bad in ("healthz", "/a?b=1", "/a#x", "/../etc", "//x", "/a b", "/a;rm -rf", "", "/" + "a" * 300):
        assert validate_health_path(bad)[0] is None, bad
    print("Test 1 (domain, server_id, port and health path validators reject hostile input) PASSED")


def test_2_forbidden_targets() -> None:
    for text in ("127.0.0.1", "127.1.2.3", "::1", "169.254.169.254", "169.254.0.1", "0.0.0.0", "::", "224.0.0.1", "255.255.255.255", "::ffff:127.0.0.1"):
        assert forbidden_ip_reason(text), text
        address, error = normalize_address(text)
        assert address is None and "FORBIDDEN_TARGET" in error, (text, error)
    for text in ("localhost", "LOCALHOST", "metadata.google.internal", "foo.localhost", "host.local"):
        address, error = normalize_address(text)
        assert address is None and "FORBIDDEN_TARGET" in error, (text, error)
    for text in ("http://x.com", "x.com/path", "user@x.com", "x.com:8080", "1.2.3.4:80", "a b", "", "x\x00y", "x.com?q=1"):
        assert normalize_address(text)[0] is None, text
    assert normalize_address("203.0.113.11")[0] == "203.0.113.11"
    assert normalize_address("S1.Internal.")[0] == "s1.internal"
    print("Test 2 (loopback, link-local/metadata, unspecified, multicast, broadcast, localhost and URL-like targets are rejected) PASSED")


def test_3_inventory_authorization() -> None:
    specs = resolve_origin_arguments(["203.0.113.11", "10.0.0.12", "s1.internal", "203.0.113.50", "198.51.100.9", "10.9.9.9", "169.254.169.254"], INVENTORY)
    by_addr = {s.address: s for s in specs}
    assert by_addr["203.0.113.11"].server_id == "server1" and not by_addr["203.0.113.11"].error
    assert by_addr["10.0.0.12"].server_id == "server2" and not by_addr["10.0.0.12"].error
    assert by_addr["s1.internal"].error and "already listed" in by_addr["s1.internal"].error, "one server cannot appear twice under different addresses"
    assert by_addr["203.0.113.50"].reason == "ORIGIN_NOT_AUTHORIZED", "an orchestrator-only server is not an origin"
    assert by_addr["198.51.100.9"].reason == "ORIGIN_NOT_AUTHORIZED" and by_addr["10.9.9.9"].reason == "ORIGIN_NOT_AUTHORIZED"
    assert by_addr["169.254.169.254"].reason == "FORBIDDEN_TARGET"
    items, error = split_origin_arguments("203.0.113.11, 203.0.113.12  --apply 203.0.113.11", 16)
    assert items == ["203.0.113.11", "203.0.113.12"] and error is None
    items, error = split_origin_arguments("a b c d", 3)
    assert error and "TOO_MANY_ORIGINS" in error
    assert split_origin_arguments("", 3)[1] is not None
    print("Test 3 (origins must come from the authorized inventory with an origin role; duplicates, unknown public/private IPs and metadata rejected) PASSED")


def test_4_argument_parsing() -> None:
    assert parse_lb_arguments("example.com --dry-run", "1.1.1.1 2.2.2.2") == ("example.com", "1.1.1.1 2.2.2.2", {"dry_run": True, "apply": False, "prune": False}, None)
    domain, origins, flags, error = parse_lb_arguments("example.com", "1.1.1.1 --apply --prune")
    assert flags == {"dry_run": False, "apply": True, "prune": True} and error is None
    assert parse_lb_arguments("example.com --rm-rf")[3] and parse_lb_arguments("")[3]
    assert parse_lb_arguments("a" * 5000)[3]
    print("Test 4 (--dry-run/--apply/--prune parsed; unknown flags, empty and oversized input rejected) PASSED")


def test_5_health_body_leak_scan() -> None:
    clean = ['{"status":"ok","uptime":12}', "ok", '{"status":"ok","secretsManager":"up"}', "<html>OK</html>", ""]
    for body in clean:
        assert scan_health_body(body) == "", body
    leaks = {
        "DB_PASSWORD=hunter2\nAPP_KEY=abc123": "credential", "-----BEGIN RSA PRIVATE KEY-----\nabc": "private_key",
        "Traceback (most recent call last):\n  File": "stack_trace", "Error\n    at Object.<anonymous> (/srv/app.js:10:5)": "stack_trace",
        '{"api_key": "sk_live_abcdef"}': "credential", "AKIAABCDEFGHIJKLMNOP": "cloud_key",
    }
    for body, expected in leaks.items():
        assert scan_health_body(body) == expected, (body, scan_health_body(body))
    print("Test 5 (health responses exposing credentials, private keys, stack traces or cloud keys are flagged; benign JSON is not) PASSED")


def test_6_secret_scrubbing() -> None:
    token = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
    text = f"Authorization: Bearer {token} and --token {token} password=hunter2hunter2 api_key: {token}"
    cleaned = scrub(text, 500)
    assert token not in cleaned and "hunter2" not in cleaned and "[REDACTED]" in cleaned
    redacted = redact_mapping({"token": token, "nested": {"api_key": token, "name": "ok", "password": "p"}, "list": [{"secret": "s"}], "note": f"bearer {token}"})
    blob = str(redacted)
    assert token not in blob and "'p'" not in blob and redacted["nested"]["name"] == "ok"
    with tempfile.TemporaryDirectory() as tmp:
        store = LbStateStore(os.path.join(tmp, "s.json"))
        record = store.begin_operation(OperationRecord("op1", "genloadbalance", "example.com", "me", "server1"))
        store.push_undo(record, {"kind": "x", "token": token, "api_key": token})
        store.step(record, "step", "FAILED", f"Authorization: Bearer {token}")
        record.snapshot = {"headers": {"Authorization": f"Bearer {token}"}}
        store.finish_operation(record, OpStatus.FAILED, f"password=hunter2hunter2 {token}")
        content = open(os.path.join(tmp, "s.json"), encoding="utf-8").read()
        assert token not in content and "hunter2" not in content
    print("Test 6 (bearer tokens, passwords and API keys are scrubbed from audit text, undo entries and persisted state) PASSED")


def test_7_repository_config_defaults() -> None:
    for name in ("config/config.yaml", "config/config2.yaml"):
        manager = ConfigManager(name)
        lb = manager.config.load_balancing
        assert lb.enabled is False, "load balancing is disabled by default in both profiles"
        assert lb.servers == [] and lb.domains == [], "no production values are invented"
        assert lb.orchestrator_server_id == "" and lb.max_origins == 16
        assert lb.safety.minimum_healthy_origins == 1 and lb.safety.require_confirmation is True
        assert lb.safety.allow_insecure_tls is False and lb.safety.allow_http_origin is False
        assert lb.monitor.interval_seconds >= 30 and lb.monitor.consecutive_down >= 2
        assert lb.steering_policy == "off" and lb.origin_steering_policy == "random"
        assert lb.poll_interval_seconds >= 30
    print("Test 7 (both repository configs load with load_balancing disabled, empty inventory and conservative defaults) PASSED")


def _validate(raw: dict) -> list:
    lb = _build_dataclass(LoadBalancingConfig, raw)
    errors: list = []
    _validate_load_balancing(lb, errors)
    return errors


def test_8_config_validation() -> None:
    good = {
        "enabled": True, "orchestrator_server_id": "server1",
        "servers": [{"server_id": "server1", "public_ip": "203.0.113.11", "role": "both"}, {"server_id": "server2", "private_ip": "10.0.0.12"}],
        "domains": [{"domain": "example.com", "origins": ["server1", "server2"], "db_mode": "PRIMARY_SHARED", "shared_state": {"uploads": "shared"}}],
    }
    assert _validate(good) == []
    bad_cases = {
        "loopback origin": {**good, "servers": [{"server_id": "server1", "public_ip": "127.0.0.1"}]},
        "metadata origin": {**good, "servers": [{"server_id": "server1", "public_ip": "169.254.169.254"}]},
        "localhost hostname": {**good, "servers": [{"server_id": "server1", "hostname": "localhost"}]},
        "no address": {**good, "servers": [{"server_id": "server1"}]},
        "duplicate id": {**good, "servers": [{"server_id": "server1", "public_ip": "1.1.1.1"}, {"server_id": "server1", "public_ip": "2.2.2.2"}]},
        "shared address": {**good, "servers": [{"server_id": "server1", "public_ip": "1.1.1.1"}, {"server_id": "server2", "public_ip": "1.1.1.1"}]},
        "bad role": {**good, "servers": [{"server_id": "server1", "public_ip": "1.1.1.1", "role": "root"}]},
        "missing orchestrator": {**good, "orchestrator_server_id": ""},
        "unknown orchestrator": {**good, "orchestrator_server_id": "ghost"},
        "unknown origin": {**good, "domains": [{"domain": "example.com", "origins": ["ghost"]}]},
        "bad domain": {**good, "domains": [{"domain": "../x"}]},
        "bad health path": {**good, "domains": [{"domain": "example.com", "health_path": "/a?b=1"}]},
        "bad db mode": {**good, "domains": [{"domain": "example.com", "db_mode": "MAGIC"}]},
        "bad shared state": {**good, "domains": [{"domain": "example.com", "shared_state": {"uploads": "maybe"}}]},
        "zero min healthy": {**good, "safety": {"minimum_healthy_origins": 0}},
        "aggressive monitor": {**good, "monitor": {"interval_seconds": 5}},
        "aggressive poll": {**good, "poll_interval_seconds": 1},
        "too many origins": {**good, "max_origins": 500},
        "bad steering": {**good, "steering_policy": "round_robin_magic"},
        "bad key env": {**good, "report_key_env_var": "not an env name"},
    }
    for label, raw in bad_cases.items():
        assert _validate(raw), f"{label} must be rejected"
    try:
        _build_dataclass(LoadBalancingConfig, {"enabled": "yes-please"})
        raise AssertionError("a non-bool flag must be rejected")
    except ConfigValidationError:
        pass
    print(f"Test 8 (good inventory accepted; {len(bad_cases)} unsafe or malformed load_balancing configurations rejected) PASSED")


def test_9_no_secret_in_config_yaml() -> None:
    with open("config/config.yaml", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    section = raw["load_balancing"]
    assert "report_key_env_var" in section and section["report_key_env_var"].isupper(), "only the NAME of the signing-key variable is configured"
    text = yaml.safe_dump(section).lower()
    for forbidden in ("password", "bearer", "api_token:"):
        assert forbidden not in text
    print("Test 9 (repository config carries only environment variable names, never secrets) PASSED")


def test_10_identity_is_not_guessed() -> None:
    import socket
    from unittest import mock

    from config.manager import CloudflareConfig, DiscordConfig
    from core.event_bus import EventBus
    from discord_integration.bot import RTSABot

    cfg = RTSAConfig(cloudflare=CloudflareConfig(enabled=False))
    bot = RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=None, supervisor=None)
    with mock.patch("discord_integration.lb_bot_ports.get_active_server_identity", return_value=None), \
            mock.patch.object(socket, "gethostname", return_value="server1"):
        assert bot.lb_service.ports.local_server_id() == "", "the hostname must never be used to decide which server this is"
    from types import SimpleNamespace

    with mock.patch("discord_integration.lb_bot_ports.get_active_server_identity", return_value=SimpleNamespace(server_id="server2", server_name="Server2")), \
            mock.patch.object(socket, "gethostname", return_value="server1"):
        assert bot.lb_service.ports.local_server_id() == "server2"
    print("Test 10 (server identity comes only from config/server.config.yaml, never from the hostname) PASSED")


def main() -> None:
    for test in (
        test_1_validators, test_2_forbidden_targets, test_3_inventory_authorization, test_4_argument_parsing,
        test_5_health_body_leak_scan, test_6_secret_scrubbing, test_7_repository_config_defaults, test_8_config_validation,
        test_9_no_secret_in_config_yaml, test_10_identity_is_not_guessed,
    ):
        test()
    print("\nALL LOAD BALANCER MODEL/SECURITY TESTS PASSED")


if __name__ == "__main__":
    main()
