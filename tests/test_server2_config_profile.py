from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import yaml

from config.manager import (
    ConfigManager, ConfigValidationError, SERVER_CONFIG_PROFILES, detect_accidental_secrets,
)

_BASE_DIR = os.path.join(_REPO_ROOT, "config")


def main() -> None:
    os.environ["RTSA_DISCORD_BOT_TOKEN"] = "x"
    os.environ["RTSA_CLOUDFLARE_API_TOKEN"] = "y"
    try:
        cm2 = ConfigManager(os.path.join(_BASE_DIR, "config2.yaml"), expected_server_id="server2")
    finally:
        os.environ.pop("RTSA_DISCORD_BOT_TOKEN", None)
        os.environ.pop("RTSA_CLOUDFLARE_API_TOKEN", None)
    assert cm2.config.modules.website_monitor.ignore_domains_file == "ignore-domains-server2.yaml"
    assert cm2.config.modules.website_monitor.ignore_domains_file != "ignore-domains-server1.yaml"
    print("Test 1 (config2.yaml uses ignore-domains-server2.yaml, never Server1's) PASSED")

    os.environ["RTSA_DISCORD_BOT_TOKEN"] = "x"
    os.environ["RTSA_CLOUDFLARE_API_TOKEN"] = "y"
    try:
        cm1 = ConfigManager(os.path.join(_BASE_DIR, "config.yaml"), expected_server_id="server1")
    finally:
        os.environ.pop("RTSA_DISCORD_BOT_TOKEN", None)
        os.environ.pop("RTSA_CLOUDFLARE_API_TOKEN", None)
    assert cm1.config.discord.channel_config_file == "discord-server1.yaml"
    assert cm2.config.discord.channel_config_file == "discord-server2.yaml"
    assert cm1.config.discord.channel_config_file != cm2.config.discord.channel_config_file
    assert cm1.config.modules.systemd_monitor.service_profile == "server1service"
    assert cm2.config.modules.systemd_monitor.service_profile == "server2service"
    print("Test 2 (Server1/Server2 configs point at distinct Discord/systemd profile files -- no cross-server state pointer) PASSED")

    for name in ("config.yaml", "config2.yaml"):
        raw = yaml.safe_load(open(os.path.join(_BASE_DIR, name)))
        findings = detect_accidental_secrets(raw)
        assert findings == [], f"{name}: {findings}"
    print("Test 3 (config.yaml and config2.yaml contain no accidentally-committed secrets) PASSED")

    os.environ["RTSA_DISCORD_BOT_TOKEN"] = "x"
    os.environ["RTSA_CLOUDFLARE_API_TOKEN"] = "y"
    try:
        try:
            ConfigManager(os.path.join(_BASE_DIR, "config.yaml"), expected_server_id="server2")
            raise AssertionError("expected a server_id mismatch to be rejected")
        except ConfigValidationError as exc:
            assert "Identity mismatch" in str(exc)
    finally:
        os.environ.pop("RTSA_DISCORD_BOT_TOKEN", None)
        os.environ.pop("RTSA_CLOUDFLARE_API_TOKEN", None)
    print("Test 4 (a config file whose own server_id disagrees with the selected server is rejected, not silently loaded) PASSED")

    assert cm1.config.server_id == "server1" and cm1.config.hostname_override == "Server1"
    assert cm2.config.server_id == "server2" and cm2.config.hostname_override == "Server2"
    assert set(SERVER_CONFIG_PROFILES) == {"server1", "server2"}
    print("Test 5 (both server profiles load end to end through the one existing ConfigManager pipeline) PASSED")

    print("\nALL SERVER2 CONFIG PROFILE TESTS PASSED")


main()
