import os
import re
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import yaml

from config.manager import (
    ConfigManager, ConfigValidationError, _is_plausible_snowflake, _REFERENCE_DISCORD_CATEGORIES,
)

_CONFIG_DIR = os.path.join(_REPO_ROOT, "config")
_SERVER1_PROFILE = os.path.join(_CONFIG_DIR, "discord-server1.yaml")
_SERVER2_PROFILE = os.path.join(_CONFIG_DIR, "discord-server2.yaml")

_DOCUMENTED_SHARED_CHANNELS = {
    1545250790543720458: (
        "RTSA_COMPONENT_ERROR / RTSA_COMPONENT_RECOVERED / RTSA_STARTUP_HEALTH -- "
        "shared RTSA ops-health channel, intentionally identical in both profiles"
    ),
    1535153919221698630: (
        "PERSISTENCE_NEW_USER / PERSISTENCE_USER_REMOVED -- shared persistence-alert "
        "channel, intentionally identical in both profiles"
    ),
}

_PLACEHOLDER_PATTERN = re.compile(r"190000000000000")


def _write_config_pointing_at(
    tmpdir: str, discord_profile_abs_path: str,
) -> str:
    base_path = os.path.join(tmpdir, "config.yaml")
    with open(base_path, "w") as f:
        f.write(
            "discord:\n"
            "  enabled: false\n"
            f"  channel_config_file: \"{discord_profile_abs_path}\"\n"
        )
    return base_path


def _load_profile_dict(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main() -> None:
    assert os.path.isfile(_SERVER1_PROFILE), "config/discord-server1.yaml must exist"
    assert os.path.isfile(_SERVER2_PROFILE), "config/discord-server2.yaml must exist"

    for path in (_SERVER1_PROFILE, _SERVER2_PROFILE):
        with open(path, "r", encoding="utf-8") as f:
            raw_text = f.read()
        assert not _PLACEHOLDER_PATTERN.search(raw_text), (
            f"{path} still contains a placeholder Discord ID (matches '190000000000000') -- "
            f"production profiles must never ship placeholder IDs"
        )
    print("Scenario 1 (no placeholder Discord IDs in discord-server1.yaml / discord-server2.yaml) PASSED")

    for path in (_SERVER1_PROFILE, _SERVER2_PROFILE):
        data = _load_profile_dict(path)
        cf_id = data.get("cloudflare_scan_channel_id")
        if cf_id is not None:
            assert isinstance(cf_id, int) and not isinstance(cf_id, bool), (
                f"{path}: cloudflare_scan_channel_id must be an int, got {type(cf_id).__name__}"
            )
            assert _is_plausible_snowflake(cf_id, allow_zero=False), (
                f"{path}: cloudflare_scan_channel_id ({cf_id}) is not a plausible Discord snowflake"
            )
        for category, channel_id in (data.get("category_channels") or {}).items():
            assert isinstance(channel_id, int) and not isinstance(channel_id, bool), (
                f"{path}: category_channels['{category}'] must be an int, got {type(channel_id).__name__}"
            )
            assert _is_plausible_snowflake(channel_id, allow_zero=False), (
                f"{path}: category_channels['{category}'] ({channel_id}) is not a plausible Discord snowflake "
                f"({len(str(channel_id))} digits)"
            )
    print("Scenario 2 (no malformed Discord IDs -- all snowflakes are plausible ints) PASSED")

    server1 = _load_profile_dict(_SERVER1_PROFILE)
    server2 = _load_profile_dict(_SERVER2_PROFILE)
    server1_values = set((server1.get("category_channels") or {}).values())
    if server1.get("cloudflare_scan_channel_id"):
        server1_values.add(server1["cloudflare_scan_channel_id"])
    server2_values = set((server2.get("category_channels") or {}).values())
    if server2.get("cloudflare_scan_channel_id"):
        server2_values.add(server2["cloudflare_scan_channel_id"])

    overlap = server1_values & server2_values
    undocumented_overlap = overlap - set(_DOCUMENTED_SHARED_CHANNELS.keys())
    assert not undocumented_overlap, (
        f"Undocumented channel ID(s) shared between discord-server1.yaml and discord-server2.yaml: "
        f"{undocumented_overlap} -- either this is a genuine cross-profile leak (fix the wrong profile), "
        f"or it is intentional and must be added to _DOCUMENTED_SHARED_CHANNELS with an explanation"
    )
    for shared_id in overlap:
        assert shared_id in _DOCUMENTED_SHARED_CHANNELS, shared_id
    print(
        "Scenario 3/4 (no undocumented Server1<->Server2 channel ID leak in either direction; "
        f"documented shared channels: {sorted(overlap)}) PASSED"
    )

    s1_scan = server1["category_channels"]["WEB_ATTACK_SCAN"]
    s2_scan = server2["category_channels"]["WEB_ATTACK_SCAN"]
    assert s1_scan != s2_scan, "Server1 and Server2 WEB_ATTACK_SCAN channels must be distinct"
    assert s1_scan not in server2_values, f"Server1 WEB_ATTACK_SCAN channel {s1_scan} leaked into Server2 profile"
    assert s2_scan not in server1_values, f"Server2 WEB_ATTACK_SCAN channel {s2_scan} leaked into Server1 profile"
    print("Scenario 5 (Server1/Server2 WEB_ATTACK_SCAN channels are distinct and non-leaking) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        missing_path = os.path.join(tmpdir, "does-not-exist.yaml")
        cfg_path = _write_config_pointing_at(tmpdir, missing_path)
        try:
            ConfigManager(cfg_path)
            raise AssertionError("expected ConfigValidationError for a missing channel_config_file")
        except ConfigValidationError as exc:
            assert "tidak ditemukan" in str(exc) or "not found" in str(exc).lower()
    print("Scenario 6 (missing external channel_config_file raises ConfigValidationError, no silent fallback) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        empty_profile = os.path.join(tmpdir, "empty-profile.yaml")
        with open(empty_profile, "w") as f:
            f.write("category_channels: {}\n")
            f.write("known_missing_categories:\n")
            for name in _REFERENCE_DISCORD_CATEGORIES:
                f.write(f'  - "{name}"\n')
        cfg_path = _write_config_pointing_at(tmpdir, empty_profile)
        cm = ConfigManager(cfg_path)
        assert cm.config.discord.category_channels == {}, (
            "an explicitly empty category_channels mapping, with every reference category "
            "acknowledged as known-missing, must load as an empty dict, not silently populated"
        )
    print(
        "Scenario 7 (external profile with an explicitly empty category_channels loads cleanly "
        "ONLY when every reference category is acknowledged in known_missing_categories) PASSED"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        empty_profile = os.path.join(tmpdir, "empty-profile-undocumented.yaml")
        with open(empty_profile, "w") as f:
            f.write("category_channels: {}\n")
        cfg_path = _write_config_pointing_at(tmpdir, empty_profile)
        try:
            ConfigManager(cfg_path)
            raise AssertionError(
                "an empty category_channels with no known_missing_categories acknowledgement "
                "must FAIL config load, not silently succeed with zero routing"
            )
        except ConfigValidationError as exc:
            assert "tidak lengkap" in str(exc) or "known_missing_categories" in str(exc)
    print("Scenario 7b (undocumented incomplete profile -- FAILS config load, not a silent empty profile) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        keyless_profile = os.path.join(tmpdir, "keyless-profile.yaml")
        with open(keyless_profile, "w") as f:
            f.write("cloudflare_scan_channel_id: 123456789012345678\n")
        cfg_path = _write_config_pointing_at(tmpdir, keyless_profile)
        try:
            ConfigManager(cfg_path)
            raise AssertionError("expected ConfigValidationError when category_channels key is entirely absent")
        except ConfigValidationError as exc:
            assert "category_channels" in str(exc)
    print("Scenario 8 (external profile missing the 'category_channels' key entirely raises, not silently empty) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir1:
        cm1 = ConfigManager(_write_config_pointing_at(tmpdir1, _SERVER1_PROFILE))
    assert cm1.config.discord.category_channels["WEB_ATTACK_SCAN"] == 1529424482383695972, (
        "Server1's WEB_ATTACK_SCAN must route to the shared web-attack channel, not a dedicated one"
    )
    assert cm1.config.discord.cloudflare_scan_channel_id == 0, (
        "Server1 has no dedicated Cloudflare channel of its own -- must not carry Server2's value"
    )
    assert cm1.config.discord.alert_channel_id == 1529384348648869989, (
        "Server1's alert_channel_id must now come from the external profile, not be hardcoded "
        "in config.yaml -- switching profiles must never require editing this by hand"
    )
    assert set(_REFERENCE_DISCORD_CATEGORIES) <= set(cm1.config.discord.category_channels.keys()), (
        "Server1 must remain a fully complete reference profile -- every reference category mapped"
    )
    print(
        "Scenario 9 (Server1 profile loads through ConfigManager with the corrected WEB_ATTACK_SCAN "
        "routing and its own externalized alert_channel_id) PASSED"
    )

    with tempfile.TemporaryDirectory() as tmpdir2:
        cm2 = ConfigManager(_write_config_pointing_at(tmpdir2, _SERVER2_PROFILE))
    assert set(_REFERENCE_DISCORD_CATEGORIES) <= set(cm2.config.discord.category_channels.keys()), (
        "Server2 must now be a fully complete reference profile -- every reference category mapped"
    )
    assert cm2.config.discord.cloudflare_scan_channel_id == 1538602043349143612
    assert cm2.config.discord.alert_channel_id == 0, (
        "Server2 has no real alert_channel_id available -- must stay 0/unset, never fabricated"
    )
    assert cm2.config.discord.known_missing_categories == [], (
        "every reference category is now genuinely mapped for Server2 -- known_missing_categories "
        "must be empty, not carry stale placeholder entries"
    )
    print(
        "Scenario 10 (Server2 profile now loads as a fully complete reference profile, "
        "known_missing_categories empty) PASSED"
    )

    server1_ids = set(cm1.config.discord.category_channels.values())
    if cm1.config.discord.cloudflare_scan_channel_id:
        server1_ids.add(cm1.config.discord.cloudflare_scan_channel_id)
    if cm1.config.discord.alert_channel_id:
        server1_ids.add(cm1.config.discord.alert_channel_id)
    server2_ids = set(cm2.config.discord.category_channels.values())
    if cm2.config.discord.cloudflare_scan_channel_id:
        server2_ids.add(cm2.config.discord.cloudflare_scan_channel_id)
    if cm2.config.discord.alert_channel_id:
        server2_ids.add(cm2.config.discord.alert_channel_id)
    shared_ids = server1_ids & server2_ids
    server1_only = server1_ids - server2_ids
    server2_only = server2_ids - server1_ids
    unexpected = shared_ids - _DOCUMENTED_SHARED_CHANNELS.keys()
    print(f"Shared IDs: {sorted(shared_ids)}")
    print(f"Server1-only IDs: {len(server1_only)} entries")
    print(f"Server2-only IDs: {sorted(server2_only)}")
    print(f"Unexpected cross-profile IDs: {sorted(unexpected)}")
    assert not unexpected, f"undocumented overlap between profiles: {unexpected}"
    print("Scenario 11 (cross-server ID report generated, no unexpected/undocumented overlap) PASSED")

    print("\nALL SERVER PROFILE ISOLATION TESTS PASSED")


main()
