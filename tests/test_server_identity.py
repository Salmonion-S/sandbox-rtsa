from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import discord

import config.manager as manager_module
from config.manager import (
    ConfigManager, ConfigValidationError, DiscordConfig, ModulesConfig, RTSAConfig, ServerIdentityError,
    SSHMonitorConfig, get_active_server_identity, resolve_server_identity, set_active_server_identity,
)
from core.datatypes import BaseEvent, EventCategory, Severity, SSHEvent
from core.event_bus import EventBus
from core.server_name import configured_server_name, server_display_name, server_scope_id
from core.state_identity import STATE_IDENTITY_FILENAME, check_state_identity
from discord_integration.bot import RTSABot
from discord_integration.webhook import DiscordWebhookDispatcher

_REPO_CONFIG = os.path.join(_REPO_ROOT, "config")
_PROFILE_FILES = (
    "config.yaml", "config2.yaml", "discord-server1.yaml", "discord-server2.yaml",
    "ignore-domains-server1.yaml", "ignore-domains-server2.yaml", "server1service.yaml", "server2service.yaml",
)
SERVER1_YAML = "server_1: true\nserver_2: false\n"
SERVER2_YAML = "server_1: false\nserver_2: true\n"
_TOKEN_ENV = {"RTSA_DISCORD_BOT_TOKEN": "x", "RTSA_CLOUDFLARE_API_TOKEN": "y"}


def make_config_dir(tmp: str, identity_yaml: str | None) -> Path:
    directory = Path(tmp) / "config"
    directory.mkdir()
    for name in _PROFILE_FILES:
        shutil.copy(os.path.join(_REPO_CONFIG, name), directory / name)
    if identity_yaml is not None:
        (directory / "server.config.yaml").write_text(identity_yaml)
    return directory


def subdir(tmp: str, name: str) -> str:
    path = os.path.join(tmp, name)
    os.makedirs(path)
    return path


def expect_error(callable_, *needles: str, exc_type=ConfigValidationError) -> str:
    try:
        callable_()
    except exc_type as exc:
        text = str(exc)
        for needle in needles:
            assert needle in text, f"{needle!r} not in error:\n{text}"
        return text
    raise AssertionError(f"expected {exc_type.__name__} containing {needles}")


def test_1_server1() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        identity = resolve_server_identity(env={}, base_dir=make_config_dir(tmp, SERVER1_YAML))
        assert (identity.server_id, identity.server_name) == ("server1", "Server1")
        assert identity.profile_config == "config/config.yaml"
        assert identity.discord_config == "config/discord-server1.yaml"
        assert identity.ignore_domains_config == "config/ignore-domains-server1.yaml"
        assert identity.service_profile == "server1service"
        assert identity.server_1 is True and identity.server_2 is False
        assert identity.source == "config/server.config.yaml"
        assert identity.profile_config_path.name == "config.yaml"
    print("Test 1 (server_1: true -> server1 / Server1 / config.yaml / discord-server1 / ignore-domains-server1 / server1service) PASSED")


def test_2_server2() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        identity = resolve_server_identity(env={}, base_dir=make_config_dir(tmp, SERVER2_YAML))
        assert (identity.server_id, identity.server_name) == ("server2", "Server2")
        assert identity.profile_config == "config/config2.yaml"
        assert identity.discord_config == "config/discord-server2.yaml"
        assert identity.ignore_domains_config == "config/ignore-domains-server2.yaml"
        assert identity.service_profile == "server2service"
        assert identity.server_1 is False and identity.server_2 is True
        assert identity.profile_config_path.name == "config2.yaml"
    print("Test 2 (server_2: true -> server2 / Server2 / config2.yaml / discord-server2 / ignore-domains-server2 / server2service) PASSED")


def test_3_4_invalid_flags() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = make_config_dir(tmp, "server_1: true\nserver_2: true\n")
        text = expect_error(
            lambda: resolve_server_identity(env={}, base_dir=directory),
            "Invalid server identity configuration:", "Exactly one of server_1 / server_2 must be true.",
            exc_type=ServerIdentityError,
        )
        assert text == "Invalid server identity configuration:\nExactly one of server_1 / server_2 must be true."
        (directory / "server.config.yaml").write_text("server_1: false\nserver_2: false\n")
        expect_error(
            lambda: resolve_server_identity(env={}, base_dir=directory),
            "Invalid server identity configuration:", "Exactly one of server_1 / server_2 must be true.",
            exc_type=ServerIdentityError,
        )
        for bad, needle in (
            ("server_1: true\n", "Missing key 'server_2'"),
            ("server_1: 'true'\nserver_2: false\n", "must be the YAML boolean"),
            ("server_1: 1\nserver_2: 0\n", "must be the YAML boolean"),
            ("server_1: true\nserver_2: false\nserver1: true\n", "Unknown key(s)"),
            ("server_1: true\nserver_2: false\ndiscord_token: abc\n", "no credentials"),
            ("- server_1\n- server_2\n", "must be a mapping"),
            ("server_1: [unclosed\n", "could not be read as YAML"),
            ("", "must be a mapping"),
        ):
            (directory / "server.config.yaml").write_text(bad)
            expect_error(lambda: resolve_server_identity(env={}, base_dir=directory), needle, exc_type=ServerIdentityError)
    print("Test 3/4 (both true / both false -> the specified fail-fast message; missing/non-bool/unknown keys/non-mapping/bad YAML also refused) PASSED")


def test_5_missing_file_no_fallback() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = make_config_dir(tmp, None)
        text = expect_error(
            lambda: resolve_server_identity(env={}, base_dir=directory),
            "RTSA STARTUP FAILED", "server.config.yaml", "never guesses", exc_type=ServerIdentityError,
        )
        assert "Server1" not in text and "Server2" not in text, "a missing identity file must not pick any server"
        empty_dir = Path(tmp) / "empty"
        empty_dir.mkdir()
        expect_error(lambda: resolve_server_identity(env={}, base_dir=empty_dir), "RTSA STARTUP FAILED", exc_type=ServerIdentityError)
    print("Test 5 (missing server.config.yaml -> clear startup failure, no guessed/default server) PASSED")


def test_6_hostname_never_decides() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = make_config_dir(tmp, SERVER2_YAML)
        for hostname in ("srv1847565", "server1", "Server1-prod", "rtsa-server-1"):
            with mock.patch("socket.gethostname", return_value=hostname):
                identity = resolve_server_identity(env={}, base_dir=directory)
                assert identity.server_id == "server2" and identity.server_name == "Server2", hostname
    source = Path(_REPO_ROOT, "config", "manager.py").read_text()
    assert "gethostname" not in source and "getfqdn" not in source and "platform.node" not in source
    print("Test 6 (hostname 'srv1847565' / 'server1' / ... with server_2: true -> still Server2; config.manager never reads the hostname) PASSED")


def test_7_environment_never_overrides() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = make_config_dir(tmp, SERVER2_YAML)
        text = expect_error(
            lambda: resolve_server_identity(env={"RTSA_SERVER_ID": "server1"}, base_dir=directory),
            "Server identity conflict", "server2", "server1", "never overrides", exc_type=ServerIdentityError,
        )
        assert "startup stopped" in text
        assert resolve_server_identity(env={"RTSA_SERVER_ID": "SERVER2"}, base_dir=directory).server_id == "server2"
        assert resolve_server_identity(env={"RTSA_SERVER_ID": ""}, base_dir=directory).server_id == "server2"
        expect_error(
            lambda: resolve_server_identity(env={"RTSA_SERVER_ID": "server99"}, base_dir=directory),
            "Server identity conflict", exc_type=ServerIdentityError,
        )
        directory1 = make_config_dir(subdir(tmp, "s1"), SERVER1_YAML)
        assert resolve_server_identity(env={"RTSA_SERVER_ID": "server1"}, base_dir=directory1).server_id == "server1"

        expect_error(
            lambda: resolve_server_identity(env={"RTSA_CONFIG_PATH": str(directory / "config.yaml")}, base_dir=directory),
            "Server identity conflict", "config2.yaml", exc_type=ServerIdentityError,
        )
        expect_error(
            lambda: resolve_server_identity(env={"RTSA_CONFIG_FILE": "config.yaml"}, base_dir=directory),
            "Server identity conflict", exc_type=ServerIdentityError,
        )
        ok = resolve_server_identity(env={"RTSA_CONFIG_PATH": str(directory / "config2.yaml")}, base_dir=directory)
        assert ok.server_id == "server2"

        assert resolve_server_identity(env={"RTSA_CONFIG_DIR": str(directory)}).server_id == "server2"
        assert resolve_server_identity(env={"RTSA_CONFIG_PATH": str(directory / "config2.yaml")}).config_dir == directory, (
            "the directory of an explicit config path only LOCATES server.config.yaml"
        )
    print("Test 7 (RTSA_SERVER_ID / RTSA_CONFIG_PATH never override server.config.yaml: a conflict fails startup clearly, agreement is fine) PASSED")


def test_8_missing_referenced_files() -> None:
    for yaml_text, name, missing_cases in (
        (SERVER1_YAML, "Server1", ["config/discord-server1.yaml", "config/ignore-domains-server1.yaml", "config/server1service.yaml", "config/config.yaml"]),
        (SERVER2_YAML, "Server2", ["config/discord-server2.yaml", "config/ignore-domains-server2.yaml", "config/server2service.yaml", "config/config2.yaml"]),
    ):
        for missing in missing_cases:
            with tempfile.TemporaryDirectory() as tmp:
                directory = make_config_dir(tmp, yaml_text)
                (directory / Path(missing).name).unlink()
                text = expect_error(
                    lambda: resolve_server_identity(env={}, base_dir=directory), exc_type=ServerIdentityError,
                )
                assert text == f"RTSA STARTUP FAILED\n\nServer Identity:\n{name}\n\nMissing configuration:\n{missing}", text
    with tempfile.TemporaryDirectory() as tmp:
        directory = make_config_dir(tmp, SERVER1_YAML)
        (directory / "discord-server1.yaml").unlink()
        assert (directory / "discord-server2.yaml").exists()
        text = expect_error(lambda: resolve_server_identity(env={}, base_dir=directory), "Server1", exc_type=ServerIdentityError)
        assert "Server2" not in text, "Server1 with a missing file must never fall back to Server2's files"
        (directory / "config2.yaml").unlink()
        (directory / "discord-server2.yaml").unlink()
        expect_error(lambda: resolve_server_identity(env={}, base_dir=directory), "config/discord-server1.yaml", exc_type=ServerIdentityError)
        identity_no_check = resolve_server_identity(env={}, base_dir=directory, validate_files=False)
        assert identity_no_check.server_id == "server1"
    print("Test 8 (a missing profile file for the SELECTED server -> 'RTSA STARTUP FAILED / Server Identity / Missing configuration', never a fallback to the other server) PASSED")


def test_9_config_manager_uses_identity() -> None:
    with mock.patch.dict(os.environ, _TOKEN_ENV):
        for yaml_text, sid, name, cfg_name in ((SERVER1_YAML, "server1", "Server1", "config.yaml"), (SERVER2_YAML, "server2", "Server2", "config2.yaml")):
            with tempfile.TemporaryDirectory() as tmp:
                directory = make_config_dir(tmp, yaml_text)
                identity = resolve_server_identity(env={}, base_dir=directory)
                manager = ConfigManager(str(identity.profile_config_path), identity=identity)
                cfg = manager.config
                assert manager.path.name == cfg_name and manager.identity is identity
                assert cfg.server_id == sid and cfg.hostname_override == name
                assert Path(cfg.discord.channel_config_file).name == f"discord-{sid}.yaml"
                assert Path(cfg.modules.website_monitor.ignore_domains_file).name == f"ignore-domains-{sid}.yaml"
                assert cfg.modules.systemd_monitor.service_profile == f"{sid}service"
        print("Test 9a (identity drives which profile ConfigManager loads; every referenced file belongs to that server) PASSED")

        with tempfile.TemporaryDirectory() as tmp:
            directory = make_config_dir(tmp, SERVER2_YAML)
            identity = resolve_server_identity(env={}, base_dir=directory)
            text = expect_error(
                lambda: ConfigManager(str(directory / "config.yaml"), identity=identity),
                "Server2", "cross-server profile mixing refused", "loaded config file is 'config.yaml'",
                exc_type=ServerIdentityError,
            )
            assert text.startswith("RTSA STARTUP FAILED\n\nServer Identity:\nServer2")
            mixed = (directory / "config2.yaml").read_text().replace("discord-server2.yaml", "discord-server1.yaml")
            (directory / "config2.yaml").write_text(mixed)
            expect_error(
                lambda: ConfigManager(str(directory / "config2.yaml"), identity=identity),
                "discord.channel_config_file is 'discord-server1.yaml'", "expected 'discord-server2.yaml'",
                exc_type=ServerIdentityError,
            )
            (directory / "config2.yaml").write_text(
                (directory / "config2.yaml").read_text().replace("discord-server1.yaml", "discord-server2.yaml")
                .replace("ignore-domains-server2.yaml", "ignore-domains-server1.yaml").replace('service_profile: "server2service"', 'service_profile: "server1service"')
            )
            text = expect_error(
                lambda: ConfigManager(str(directory / "config2.yaml"), identity=identity),
                "ignore_domains_file", "service_profile", exc_type=ServerIdentityError,
            )
            (directory / "config2.yaml").write_text(
                (directory / "config2.yaml").read_text().replace('hostname_override: "Server2"', 'hostname_override: "srv1847565"')
            )
            expect_error(lambda: ConfigManager(str(directory / "config2.yaml"), identity=identity), "hostname_override", exc_type=ServerIdentityError)
    print("Test 9b (Server2 identity + Server1's config file / Discord / ignore / systemd / name -> startup refused: no cross-server profile mixing) PASSED")


def test_10_reload_rejects_identity_change() -> None:
    with mock.patch.dict(os.environ, _TOKEN_ENV), tempfile.TemporaryDirectory() as tmp:
        directory = make_config_dir(tmp, SERVER1_YAML)
        identity = resolve_server_identity(env={}, base_dir=directory)
        manager = ConfigManager(str(identity.profile_config_path), identity=identity)
        manager.reload()
        assert manager.config.server_id == "server1", "a reload with an unchanged identity works as before"

        (directory / "server.config.yaml").write_text(SERVER2_YAML)
        text = expect_error(
            manager.reload, "Server identity change detected.", "Restart required.", "Hot reload rejected.", exc_type=ServerIdentityError,
        )
        assert "Server1" in text and "Server2" in text
        assert manager.config.server_id == "server1", "the running configuration stays untouched after a rejected reload"
        assert manager.identity.server_id == "server1", "no automatic self-migration"

        (directory / "server.config.yaml").write_text("server_1: true\nserver_2: true\n")
        expect_error(manager.reload, "hot reload rejected", "Exactly one of server_1 / server_2 must be true.", exc_type=ServerIdentityError)
        (directory / "server.config.yaml").unlink()
        expect_error(manager.reload, "hot reload rejected", "server.config.yaml", exc_type=ServerIdentityError)
        (directory / "server.config.yaml").write_text(SERVER1_YAML)
        manager.reload()

        import main as main_module

        async def engine_reload() -> dict:
            (directory / "server.config.yaml").write_text(SERVER2_YAML)
            engine = main_module.RTSAEngine(manager)
            return await engine.reload_config()

        result = asyncio.run(engine_reload())
        assert result["success"] is False and "Hot reload rejected." in result["error"], result
    print("Test 10 (/rtsareload path: server.config.yaml changed while running -> 'Server identity change detected. Restart required. Hot reload rejected.', running config untouched) PASSED")


def test_11_state_isolation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        data = os.path.join(tmp, "data")
        ok, detail = check_state_identity(data, "server1", stamp=False)
        assert ok and not os.path.exists(os.path.join(data, STATE_IDENTITY_FILENAME)), "readiness mode never writes"
        ok, detail = check_state_identity(data, "server1")
        assert ok and "stamped" in detail and os.path.exists(os.path.join(data, STATE_IDENTITY_FILENAME))
        assert check_state_identity(data, "server1")[0] is True
        ok, detail = check_state_identity(data, "server2")
        assert not ok and "belongs to server 'server1'" in detail and "Refusing to read another server's" in detail
        Path(data, STATE_IDENTITY_FILENAME).write_text("{not json")
        ok, detail = check_state_identity(data, "server1")
        assert not ok and "unreadable/corrupt" in detail
    print("Test 11 (state directory is stamped with its server; a directory owned by another server -> refused, no baseline cross-read) PASSED")


def test_12_alerts_use_identity() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        identity = resolve_server_identity(env={}, base_dir=make_config_dir(tmp, SERVER2_YAML))
    previous = get_active_server_identity()
    set_active_server_identity(identity)
    try:
        with mock.patch("socket.gethostname", return_value="srv1847565"):
            assert configured_server_name() == "Server2" and server_display_name() == "Server2" and server_scope_id() == "server2"
            dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig(enabled=True, alert_channel_id=1), detection_only=False)
            categories = [
                (EventCategory.WEBSITE_DOWN, {"domain": "a.example.com", "root_cause": "PM2_DOWN"}),
                (EventCategory.FILE_INTEGRITY_CHANGE, {"path": "/x", "server_name": "srv1847565"}),
                (EventCategory.SYSTEMD_SERVICE_INCIDENT, {"unit": "x.service"}),
                (EventCategory.PERSISTENCE_NEW_PORT, {"port": 4444}),
                (EventCategory.OUTBOUND_ANOMALY, {"ip": "203.0.113.5"}),
                (EventCategory.NGINX_ERROR_SPIKE, {}),
                (EventCategory.CLOUDPANEL_PROJECT_CREATED, {"server_name": "srv1847565"}),
                (EventCategory.SERVICE_DOWN, {"linux_user": "u"}),
                (EventCategory.HEALTH_STATUS, {}),
                (EventCategory.CORRELATED_THREAT, {"server_name": "srv1847565"}),
                (EventCategory.BRUTE_FORCE, {"server_name": "srv1847565", "hostname": "srv1847565"}),
            ]
            for category, metadata in categories:
                event = BaseEvent(source_module="x", category=category, severity=Severity.HIGH, message="m", metadata=dict(metadata))
                fields = {f["name"]: f["value"] for f in dispatcher._build_payload(event)["embeds"][0]["fields"]}
                assert fields.get("Server") == "Server2", (category, fields.get("Server"))
                assert "srv1847565" not in fields.get("Server", "")
            ssh = SSHEvent(
                source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.LOW, message="m",
                username="u", source_ip="1.2.3.4", auth_method="publickey", success=True,
                metadata={"server_name": "srv1847565", "hostname": "srv1847565"},
            )
            fields = {f["name"]: f["value"] for f in dispatcher._build_payload(ssh)["embeds"][0]["fields"]}
            assert fields["Server"] == "Server2" and fields["Hostname"] == "srv1847565", "hostname stays a separate informational field"

            from modules.cloudpanel_monitor import CloudPanelMonitor
            from modules.ssh_monitor import SSHMonitor

            ssh_monitor = SSHMonitor(EventBus(), SSHMonitorConfig(enabled=True, geoip_lookup=False, server_name="Server2"))
            assert ssh_monitor._server_name == "Server2"
            assert ssh_monitor._base_metadata()["server_name"] == "Server2" and ssh_monitor._base_metadata()["hostname"] == "srv1847565"
            cp = CloudPanelMonitor.__new__(CloudPanelMonitor)
            assert CloudPanelMonitor._server_name(cp) == "Server2"
    finally:
        set_active_server_identity(previous)
    assert configured_server_name() is None or previous is not None

    offenders = []
    pattern = re.compile(r"server_name[\w\"']*\s*[=:]\s*(?:self\._hostname|socket\.gethostname\(\)|hostname)\b")
    for directory in ("modules", "core", "discord_integration"):
        for path in Path(_REPO_ROOT, directory).rglob("*.py"):
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if pattern.search(line) and "hostname_" not in line:
                    offenders.append(f"{path.relative_to(_REPO_ROOT)}:{number}: {line.strip()}")
    assert not offenders, "server name must come from the identity, not the hostname:\n" + "\n".join(offenders)
    print("Test 12 (all alert categories carry 'Server: Server2' from the identity even when modules supply a hostname; no module derives server_name from the hostname) PASSED")


class _Role:
    def __init__(self, role_id): self.id = role_id


class _Resp:
    def __init__(self): self.sent = []
    async def send_message(self, content=None, *, embed=None, ephemeral=True, **_k): self.sent.append((content, embed))


def _interaction(role_ids):
    member = mock.Mock(spec=discord.Member)
    member.roles = [_Role(r) for r in role_ids]
    return SimpleNamespace(user=member, response=_Resp())


def test_13_serverinfo_command() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = make_config_dir(tmp, SERVER2_YAML)
        identity = resolve_server_identity(env={}, base_dir=directory)
        before = {p.name: p.read_bytes() for p in directory.iterdir()}
        previous = get_active_server_identity()
        set_active_server_identity(identity)
        try:
            bot = RTSABot(DiscordConfig(enabled=True, admin_role_ids=[10], critical_command_role_ids=[20]), RTSAConfig(), EventBus(), db_worker=mock.Mock(), supervisor=None)
            callback = bot.tree.get_command("serverinfo").callback
            stranger = _interaction([999])
            asyncio.run(callback(stranger))
            assert "Tidak memiliki izin" in stranger.response.sent[0][0]
            admin = _interaction([10])
            asyncio.run(callback(admin))
            embed = admin.response.sent[0][1]
            data = {f.name: f.value for f in embed.fields}
            assert embed.title == "RTSA Server Identity"
            assert data["Server ID"] == "server2" and data["Server Name"] == "Server2"
            assert data["Source"] == "config/server.config.yaml"
            assert data["server_1"] == "false" and data["server_2"] == "true"
            assert data["Profile"] == "config/config2.yaml" and data["Discord Profile"] == "discord-server2.yaml"
            assert data["Ignore Domain Profile"] == "ignore-domains-server2.yaml" and data["Systemd Profile"] == "server2service"
            assert "informational" in " ".join(data)
            assert {p.name: p.read_bytes() for p in directory.iterdir()} == before, "/serverinfo is strictly read-only"
        finally:
            set_active_server_identity(None)
        bare = _interaction([10])
        asyncio.run(callback(bare))
        assert "No server identity is configured" in bare.response.sent[0][1].description
        set_active_server_identity(previous)
    print("Test 13 (/serverinfo shows the spec'd identity fields, admin-only, read-only; reports honestly when no identity is configured) PASSED")


def _run_main(*args: str, env: dict) -> subprocess.CompletedProcess:
    full_env = {k: v for k, v in os.environ.items() if not k.startswith("RTSA_")}
    full_env.update(env)
    return subprocess.run([sys.executable, os.path.join(_REPO_ROOT, "main.py"), *args], capture_output=True, text=True, timeout=120, env=full_env, cwd=_REPO_ROOT)


def test_14_startup_and_readiness_cli() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        empty = Path(tmp) / "empty"
        empty.mkdir()
        result = _run_main(env={"RTSA_CONFIG_DIR": str(empty), "RTSA_LOCK_PATH": os.path.join(tmp, "rtsa.lock")})
        assert result.returncode == 1 and "RTSA STARTUP FAILED" in result.stderr and "server.config.yaml" in result.stderr, result.stderr
        assert "Server1" not in result.stderr and "Server2" not in result.stderr

        both = make_config_dir(subdir(tmp, "b"), "server_1: true\nserver_2: true\n")
        result = _run_main(env={"RTSA_CONFIG_DIR": str(both), "RTSA_LOCK_PATH": os.path.join(tmp, "rtsa2.lock")})
        assert result.returncode == 1 and "Invalid server identity configuration:" in result.stderr
        assert "Exactly one of server_1 / server_2 must be true." in result.stderr

        conflict = make_config_dir(subdir(tmp, "c"), SERVER2_YAML)
        result = _run_main(env={"RTSA_CONFIG_DIR": str(conflict), "RTSA_SERVER_ID": "server1", "RTSA_LOCK_PATH": os.path.join(tmp, "rtsa3.lock")})
        assert result.returncode == 1 and "Server identity conflict" in result.stderr

        good = make_config_dir(subdir(tmp, "g"), SERVER2_YAML)
        result = _run_main("--check", env={"RTSA_CONFIG_DIR": str(good), **_TOKEN_ENV})
        assert "server_identity" in result.stdout and "Server2 (server2)" in result.stdout and "config/config2.yaml" in result.stdout, result.stdout
        assert "state_identity" in result.stdout
        invalid = _run_main("--check", env={"RTSA_CONFIG_DIR": str(both), **_TOKEN_ENV})
        assert invalid.returncode == 1 and "Invalid server identity configuration:" in invalid.stderr
    print("Test 14 (main.py: missing/invalid/conflicting identity -> exit 1 with the specified message and nothing started; --check reports the resolved identity) PASSED")


def test_15_repository_defaults() -> None:
    import yaml

    default = yaml.safe_load(Path(_REPO_CONFIG, "server.config.yaml").read_text())
    assert default == {"server_1": True, "server_2": False}
    identity = resolve_server_identity(env={}, base_dir=Path(_REPO_CONFIG))
    assert identity.server_id == "server1"
    text = Path(_REPO_CONFIG, "server.config.yaml").read_text()
    assert not re.search(r"(?i)(token|secret|password|key)\s*:", text), "no credential fields in server.config.yaml"
    assert "RTSA_CONFIG_DIR" in Path(_REPO_ROOT, "deploy", "rtsa.service").read_text()
    assert "RTSA_CONFIG_PATH" not in Path(_REPO_ROOT, "deploy", "rtsa.service").read_text()
    assert "/opt/security/rtsa/config/server.config.yaml" in RTSAConfig().self_protection.config_paths
    for name in ("config.yaml", "config2.yaml"):
        assert "server.config.yaml" in Path(_REPO_CONFIG, name).read_text()
    assert set(manager_module.SERVER_CONFIG_PROFILES) == {"server1", "server2"}
    print("Test 15 (repository default is a valid Server1 file; systemd unit no longer pins a profile; identity file is tamper-monitored) PASSED")


def main() -> None:
    test_1_server1()
    test_2_server2()
    test_3_4_invalid_flags()
    test_5_missing_file_no_fallback()
    test_6_hostname_never_decides()
    test_7_environment_never_overrides()
    test_8_missing_referenced_files()
    test_9_config_manager_uses_identity()
    test_10_reload_rejects_identity_change()
    test_11_state_isolation()
    test_12_alerts_use_identity()
    test_13_serverinfo_command()
    test_14_startup_and_readiness_cli()
    test_15_repository_defaults()
    print("\nALL SERVER IDENTITY TESTS PASSED")


main()
