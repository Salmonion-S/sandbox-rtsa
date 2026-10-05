import inspect
import os
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import config.manager as manager_module
from config.manager import (
    ConfigManager, ConfigValidationError, NginxMonitorConfig, SvgUploadScannerConfig,
    _REFERENCE_DISCORD_CATEGORIES,
)
from core.datatypes import EventCategory
from core.event_bus import EventBus
from modules.nginx_monitor import NginxMonitor

_CONFIG_DIR = os.path.join(_REPO_ROOT, "config")
_SERVER1_PROFILE = os.path.join(_CONFIG_DIR, "discord-server1.yaml")
_SERVER2_PROFILE = os.path.join(_CONFIG_DIR, "discord-server2.yaml")

_SERVER1_SVG_UPLOAD_CONFIRMED_CHANNEL = 1529424819618316369
_SERVER2_SVG_UPLOAD_CONFIRMED_CHANNEL = 1527175981641764924


def _write_config_pointing_at(tmpdir: str, discord_profile_abs_path: str) -> str:
    base_path = os.path.join(tmpdir, "config.yaml")
    with open(base_path, "w") as f:
        f.write(
            "discord:\n"
            "  enabled: false\n"
            f"  channel_config_file: \"{discord_profile_abs_path}\"\n"
        )
    return base_path


def _resolve_and_build_scanner_config(discord_config) -> SvgUploadScannerConfig:
    resolved = discord_config.category_channels.get(EventCategory.SVG_UPLOAD_CONFIRMED.value)
    return SvgUploadScannerConfig(
        confirmed_branch_id=str(resolved) if resolved is not None else "",
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        cm2 = ConfigManager(_write_config_pointing_at(tmpdir, _SERVER2_PROFILE))
    assert cm2.config.discord.category_channels.get("SVG_UPLOAD_CONFIRMED") == _SERVER2_SVG_UPLOAD_CONFIRMED_CHANNEL, (
        "Server2 startup must PASS with discord.category_channels['SVG_UPLOAD_CONFIRMED'] "
        "resolved from the external Discord profile, the single source of truth"
    )
    print("Test 1 (Server2 profile loads with startup PASS, SVG_UPLOAD_CONFIRMED resolved) PASSED")

    scanner_cfg2 = _resolve_and_build_scanner_config(cm2.config.discord)
    monitor_cfg2 = NginxMonitorConfig(enabled=True, svg_upload_scanner=scanner_cfg2)
    mon2 = NginxMonitor(EventBus(), monitor_cfg2)
    assert mon2.config.svg_upload_scanner.confirmed_branch_id == str(_SERVER2_SVG_UPLOAD_CONFIRMED_CHANNEL), (
        "the scanner must receive the confirmed channel ID via config injection, matching exactly "
        "how main.py._load_modules() resolves discord.category_channels['SVG_UPLOAD_CONFIRMED']"
    )
    print("Test 2 (scanner receives 1527175981641764924 via config injection, not a hardcoded default) PASSED")

    assert SvgUploadScannerConfig().confirmed_branch_id == "", (
        "no hardcoded 1529424819618316369 (or any other channel ID) may remain as the dataclass default"
    )
    assert SvgUploadScannerConfig().confirmed_branch_id != "1529424819618316369"
    print("Test 3 (no hardcoded old Server1 channel ID remains anywhere as a default) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        cm1 = ConfigManager(_write_config_pointing_at(tmpdir, _SERVER1_PROFILE))
    scanner_cfg1 = _resolve_and_build_scanner_config(cm1.config.discord)
    assert scanner_cfg1.confirmed_branch_id == str(_SERVER1_SVG_UPLOAD_CONFIRMED_CHANNEL), (
        "Server1 must resolve to its own confirmed channel, unchanged from before this fix"
    )
    assert scanner_cfg1.confirmed_branch_id != scanner_cfg2.confirmed_branch_id, (
        "Server1 and Server2 must never resolve to the same confirmed_branch_id -- profiles must "
        "never be mixed"
    )
    print("Test 4 (Server1 resolves to its own unchanged channel, never mixed with Server2's) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        first_profile = os.path.join(tmpdir, "first.yaml")
        with open(first_profile, "w") as f:
            f.write("category_channels:\n  SVG_UPLOAD_CONFIRMED: 1111111111111111111\n")
            f.write("known_missing_categories:\n")
            for name in _REFERENCE_DISCORD_CATEGORIES:
                if name != "SVG_UPLOAD_CONFIRMED":
                    f.write(f'  - "{name}"\n')
        cm_first = ConfigManager(_write_config_pointing_at(tmpdir, first_profile))
        resolved_first = _resolve_and_build_scanner_config(cm_first.config.discord).confirmed_branch_id
        assert resolved_first == "1111111111111111111"

        second_profile = os.path.join(tmpdir, "second.yaml")
        with open(second_profile, "w") as f:
            f.write("category_channels:\n  SVG_UPLOAD_CONFIRMED: 2222222222222222222\n")
            f.write("known_missing_categories:\n")
            for name in _REFERENCE_DISCORD_CATEGORIES:
                if name != "SVG_UPLOAD_CONFIRMED":
                    f.write(f'  - "{name}"\n')
        cm_second = ConfigManager(_write_config_pointing_at(tmpdir, second_profile))
        resolved_second = _resolve_and_build_scanner_config(cm_second.config.discord).confirmed_branch_id
        assert resolved_second == "2222222222222222222"
        assert resolved_first != resolved_second, (
            "changing SVG_UPLOAD_CONFIRMED in the external Discord profile must automatically "
            "flow through to the resolved scanner value"
        )
    print("Test 5 (changing the channel in the external Discord profile flows through automatically) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, "config.yaml")
        with open(cfg_path, "w") as f:
            f.write(
                "discord:\n"
                "  enabled: false\n"
                "  category_channels:\n"
                "    SSH_AUTH: 123456789012345678\n"
            )
        try:
            ConfigManager(cfg_path)
            raise AssertionError(
                "svg_upload_scanner enabled with discord.category_channels['SVG_UPLOAD_CONFIRMED'] "
                "unmapped and unacknowledged must fail config load via the new presence-only "
                "semantic check, not silently start with an empty channel"
            )
        except ConfigValidationError as exc:
            assert "SVG_UPLOAD_CONFIRMED" in str(exc) and "svg_upload_scanner" in str(exc)
    print("Test 6 (missing/unacknowledged SVG_UPLOAD_CONFIRMED fails config load safely) PASSED")

    with tempfile.TemporaryDirectory() as tmpdir:
        acknowledged_profile = os.path.join(tmpdir, "acknowledged.yaml")
        with open(acknowledged_profile, "w") as f:
            f.write("category_channels: {}\n")
            f.write("known_missing_categories:\n")
            for name in _REFERENCE_DISCORD_CATEGORIES:
                f.write(f'  - "{name}"\n')
        cm_ack = ConfigManager(_write_config_pointing_at(tmpdir, acknowledged_profile))
        assert cm_ack.config.discord.category_channels.get("SVG_UPLOAD_CONFIRMED") is None
        scanner_cfg_ack = _resolve_and_build_scanner_config(cm_ack.config.discord)
        assert scanner_cfg_ack.confirmed_branch_id == "", (
            "an explicitly acknowledged known-missing SVG_UPLOAD_CONFIRMED must resolve to an "
            "empty (not fabricated) confirmed_branch_id, and must not fail config load"
        )
    print("Test 7 (explicitly acknowledged known-missing SVG_UPLOAD_CONFIRMED loads safely, resolves empty) PASSED")

    manager_source = inspect.getsource(manager_module)
    assert "confirmed_branch_id) != " not in manager_source and "!= svg_scanner.confirmed_branch_id" not in manager_source, (
        "the old two-value equality cross-validation must be fully removed, not merely bypassed"
    )
    print("Test 8 (old confirmed_branch_id-vs-category_channels equality check is gone from config/manager.py) PASSED")

    print("ALL SVG_UPLOAD_CONFIRMED single-source-of-truth tests PASSED")


if __name__ == "__main__":
    main()
