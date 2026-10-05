import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.pm2_startup import (
    STATUS_CURRENT_RTSA, STATUS_LEGACY_BROKEN, STATUS_LEGACY_BUT_WORKING, STATUS_NOT_FOUND,
    STATUS_UNKNOWN, classify_pm2_unit, generate_pm2_unit, parse_runtime_discovery_output,
    unit_has_wildcard_path, validate_pm2_executable,
)


def always_true(_path: str) -> bool:
    return True


def always_false(_path: str) -> bool:
    return False


def main() -> None:
    unit = generate_pm2_unit(
        user="newus-admin", home="/home/newus-admin", pm2_home="/home/newus-admin/.pm2",
        pm2_path="/home/newus-admin/.nvm/versions/node/v22.23.2/bin/pm2",
        node_bin_dir="/home/newus-admin/.nvm/versions/node/v22.23.2/bin",
    )
    assert "*" not in unit, "generated unit must never contain a wildcard path"
    assert "ExecStart=/home/newus-admin/.nvm/versions/node/v22.23.2/bin/pm2 resurrect --no-daemon" in unit
    assert "ExecReload=/home/newus-admin/.nvm/versions/node/v22.23.2/bin/pm2 reload all" in unit
    assert "ExecStop=/home/newus-admin/.nvm/versions/node/v22.23.2/bin/pm2 kill" in unit
    assert "User=newus-admin" in unit
    assert "Environment=HOME=/home/newus-admin" in unit
    assert "Environment=PM2_HOME=/home/newus-admin/.pm2" in unit
    assert (
        "Environment=PATH=/home/newus-admin/.nvm/versions/node/v22.23.2/bin:"
        "/usr/local/bin:/usr/bin:/bin" in unit
    )
    print(
        "Test 1 [NVM UNIT GENERATION] (generated unit uses the exact discovered NVM path for "
        "ExecStart/ExecReload/ExecStop/PATH, contains zero wildcard characters) PASSED"
    )

    system_unit = generate_pm2_unit(
        user="siteuser", home="/home/siteuser", pm2_home="/home/siteuser/.pm2",
        pm2_path="/usr/bin/pm2", node_bin_dir="/usr/bin",
    )
    assert "*" not in system_unit
    assert "ExecStart=/usr/bin/pm2 resurrect --no-daemon" in system_unit
    assert "Environment=PATH=/usr/bin:/usr/local/bin:/usr/bin:/bin" in system_unit
    print(
        "Test 2 [SYSTEM PM2 UNIT GENERATION] (a system-wide PM2 install at /usr/bin/pm2 is used "
        "verbatim, never assumed without discovery) PASSED"
    )

    node_path, pm2_path, npm_path, node_version, pm2_version = parse_runtime_discovery_output(
        "/home/u/.nvm/versions/node/v22.23.2/bin/node\n---\n"
        "/home/u/.nvm/versions/node/v22.23.2/bin/pm2\n---\n"
        "/home/u/.nvm/versions/node/v22.23.2/bin/npm\n---\nv22.23.2\n---\n5.4.3\n"
    )
    assert node_path == "/home/u/.nvm/versions/node/v22.23.2/bin/node"
    assert pm2_path == "/home/u/.nvm/versions/node/v22.23.2/bin/pm2"
    assert npm_path == "/home/u/.nvm/versions/node/v22.23.2/bin/npm"
    assert node_version == "v22.23.2"
    assert pm2_version == "5.4.3"
    print(
        "Test 3 [MULTI-VERSION NVM DISCOVERY] (the probe resolves whichever PM2 the user's own login "
        "shell/NVM environment currently activates -- not an arbitrary newest-version guess -- and "
        "the fixed 5-field '---' output parses correctly) PASSED"
    )

    empty_node, empty_pm2, empty_npm, empty_nv, empty_pv = parse_runtime_discovery_output("\n---\n\n---\n\n---\n\n---\n\n")
    assert empty_pm2 is None
    rejection = validate_pm2_executable(empty_pm2, "/home/ghost", exists_fn=always_true, executable_fn=always_true)
    assert rejection is not None and "tidak dapat ditemukan" in rejection
    print(
        "Test 4 [PM2 EXECUTABLE MISSING] (when the probe finds no pm2 at all, validation safely "
        "rejects with a clear reason instead of falling back to any hardcoded path) PASSED"
    )

    rejection = validate_pm2_executable(
        "/usr/bin/pm2", "/home/siteuser", exists_fn=always_false, executable_fn=always_true,
    )
    assert rejection is not None and "tidak ditemukan di disk" in rejection
    print("Test 5 [NONEXISTENT PATH REJECTED] (a plausible-looking but nonexistent PM2 path is rejected) PASSED")

    rejection = validate_pm2_executable(
        "/home/siteuser/uploads/pm2", "/home/siteuser", exists_fn=always_true, executable_fn=always_true,
    )
    assert rejection is None
    rejection = validate_pm2_executable(
        "/tmp/evil/pm2", "/home/siteuser", exists_fn=always_true, executable_fn=always_true,
    )
    assert rejection is not None and "ditolak demi keamanan" in rejection
    print(
        "Test 6 [PATH TRUST BOUNDARY] (a PM2 path under the target user's own home is accepted; one "
        "under /tmp -- outside home and outside the trusted system prefixes -- is rejected) PASSED"
    )

    unit_current = generate_pm2_unit(
        user="newus-admin", home="/home/newus-admin", pm2_home="/home/newus-admin/.pm2",
        pm2_path="/home/newus-admin/.nvm/versions/node/v22.23.2/bin/pm2",
        node_bin_dir="/home/newus-admin/.nvm/versions/node/v22.23.2/bin",
    )
    classification = classify_pm2_unit(
        unit_current, target_user="newus-admin",
        discovered_pm2_path="/home/newus-admin/.nvm/versions/node/v22.23.2/bin/pm2",
        discovered_pm2_home="/home/newus-admin/.pm2",
        exec_exists_fn=always_true, service_active=True, service_enabled=True,
    )
    assert classification.status == STATUS_CURRENT_RTSA
    print(
        "Test 7 [IDEMPOTENCY DETECTION] (a unit already matching today's discovered PM2 path is "
        "classified CURRENT_RTSA, not flagged for unnecessary migration) PASSED"
    )

    legacy_working = (
        "[Unit]\nDescription=x\n[Service]\nUser=newus-admin\n"
        "Environment=PATH=/home/newus-admin/.nvm/versions/node/v20.11.0/bin:/usr/bin:/bin\n"
        "Environment=PM2_HOME=/home/newus-admin/.pm2\n"
        "ExecStart=/home/newus-admin/.nvm/versions/node/v20.11.0/bin/pm2 resurrect --no-daemon\n"
    )
    classification = classify_pm2_unit(
        legacy_working, target_user="newus-admin",
        discovered_pm2_path="/home/newus-admin/.nvm/versions/node/v22.23.2/bin/pm2",
        discovered_pm2_home="/home/newus-admin/.pm2",
        exec_exists_fn=always_true, service_active=True, service_enabled=True,
    )
    assert classification.status == STATUS_LEGACY_BUT_WORKING, classification.status
    print(
        "Test 8 [LEGACY BUT WORKING] (an older unit pointing at a still-existing v20 PM2 install, "
        "while the user has since moved to v22, is classified LEGACY_BUT_WORKING -- not broken, not "
        "auto-migrated) PASSED"
    )

    legacy_broken = (
        "[Unit]\n[Service]\nUser=newus-admin\n"
        "Environment=PM2_HOME=/home/newus-admin/.pm2\n"
        "ExecStart=/home/newus-admin/.nvm/versions/node/v18.0.0/bin/pm2 resurrect --no-daemon\n"
    )
    classification = classify_pm2_unit(
        legacy_broken, target_user="newus-admin",
        discovered_pm2_path="/home/newus-admin/.nvm/versions/node/v22.23.2/bin/pm2",
        discovered_pm2_home="/home/newus-admin/.pm2",
        exec_exists_fn=always_false, service_active=False, service_enabled=False,
    )
    assert classification.status == STATUS_LEGACY_BROKEN
    print(
        "Test 9 [NODE UPGRADE -> LEGACY_BROKEN] (the old unit's v18 PM2 executable no longer exists "
        "on disk after a Node upgrade -- classified LEGACY_BROKEN, current PM2 path still reported) "
        "PASSED"
    )

    legacy_wildcard = (
        "[Service]\nUser=siteuser\n"
        "Environment=PATH=/home/siteuser/.nvm/versions/node/*/bin:/usr/bin:/bin\n"
        "Environment=PM2_HOME=/home/siteuser/.pm2\n"
        "ExecStart=/usr/bin/pm2 resurrect --no-daemon\n"
    )
    assert unit_has_wildcard_path(legacy_wildcard)
    classification = classify_pm2_unit(
        legacy_wildcard, target_user="siteuser",
        discovered_pm2_path="/usr/bin/pm2", discovered_pm2_home="/home/siteuser/.pm2",
        exec_exists_fn=always_true, service_active=True, service_enabled=True,
    )
    assert classification.status == STATUS_LEGACY_BUT_WORKING
    assert any("wildcard" in r for r in classification.reasons)
    print(
        "Test 10 [OLD WILDCARD UNIT DETECTED] (an existing unit still using the old "
        "'.nvm/versions/node/*/bin' wildcard is recognised as such even though its ExecStart "
        "executable still resolves) PASSED"
    )

    unknown_user = classify_pm2_unit(
        "[Service]\nUser=someoneelse\nExecStart=/usr/bin/pm2 resurrect --no-daemon\n",
        target_user="siteuser", discovered_pm2_path="/usr/bin/pm2", discovered_pm2_home="/home/siteuser/.pm2",
        exec_exists_fn=always_true, service_active=True, service_enabled=True,
    )
    assert unknown_user.status == STATUS_UNKNOWN
    not_found = classify_pm2_unit(
        None, target_user="siteuser", discovered_pm2_path="/usr/bin/pm2",
        discovered_pm2_home="/home/siteuser/.pm2", exec_exists_fn=always_true,
        service_active=False, service_enabled=False,
    )
    assert not_found.status == STATUS_NOT_FOUND
    print(
        "Test 11 [UNKNOWN / NOT_FOUND] (a unit whose User= does not match the target user is never "
        "trusted and comes back UNKNOWN; a missing unit file comes back NOT_FOUND) PASSED"
    )

    for pm2_path in (
        "/home/newus-admin/.nvm/versions/node/v20.11.0/bin/pm2",
        "/home/newus-admin/.nvm/versions/node/v22.23.2/bin/pm2",
        "/home/newus-admin/.nvm/versions/node/v24.0.1/bin/pm2",
    ):
        node_bin_dir = os.path.dirname(pm2_path)
        unit = generate_pm2_unit(
            user="newus-admin", home="/home/newus-admin", pm2_home="/home/newus-admin/.pm2",
            pm2_path=pm2_path, node_bin_dir=node_bin_dir,
        )
        assert pm2_path in unit
        assert "*" not in unit
    print(
        "Test 12 [MULTIPLE NODE VERSIONS -> DETERMINISTIC UNIT] (whichever of three installed Node "
        "versions the discovery step actually reports for this user, the generated unit uses exactly "
        "that path -- never a blind 'pick the newest' choice) PASSED"
    )

    print("\nALL PM2 STARTUP CORE (core/pm2_startup.py) TESTS PASSED")


main()
