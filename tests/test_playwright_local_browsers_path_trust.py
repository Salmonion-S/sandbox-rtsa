import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from config.manager import ProcessAnomalyDetectorConfig, TrustedProcessProfile
from modules.process_anomaly_detector import ProcessSnapshot, match_trusted_profile


def _snap(pid, ppid, uid, exe, cwd, cmdline):
    return ProcessSnapshot(
        pid=pid, ppid=ppid, uid=uid, gid=uid, exe=exe, cwd=cwd, cmdline=cmdline,
        username="newus", start_time=0.0, project=None, network_active=False,
        start_time_ticks=pid * 10,
    )


def main():
    profiles = ProcessAnomalyDetectorConfig().trusted_process_profiles

    exe = "/home/newus/project/node_modules/playwright-core/.local-browsers/chromium-1097/chrome-linux/chrome"
    parent = _snap(500, 1, 1000, "/usr/bin/node", "/home/newus/project", "node server.js")
    child = _snap(600, 500, 1000, exe, "/home/newus/project", f"{exe} --headless --no-sandbox")

    match = match_trusted_profile(child, parent, "chrome", "node", profiles)
    assert match is not None, (
        "PLAYWRIGHT_BROWSERS_PATH=0 project-local .local-browsers/ install must be trusted "
        "by the default profile (same basename+parent+uid semantics, broadened path coverage)"
    )
    assert match.matched_path_substring == ".local-browsers/"
    print("Test 1 (project-local .local-browsers/ Playwright install matches default trust profile) PASSED")

    other_uid_child = _snap(601, 500, 4242, exe, "/home/newus/project", exe)
    no_match = match_trusted_profile(other_uid_child, parent, "chrome", "node", profiles)
    assert no_match is None, (
        "path substring match alone must never be sufficient -- a UID mismatch must still fail trust"
    )
    print("Test 2 (path substring alone insufficient -- UID mismatch still fails trust) PASSED")

    unrelated_parent = _snap(500, 1, 1000, "/usr/bin/bash", "/home/newus/project", "bash")
    no_parent_match = match_trusted_profile(child, unrelated_parent, "chrome", "bash", profiles)
    assert no_parent_match is None, (
        "path substring match alone must never be sufficient -- an unrecognized parent must still fail trust"
    )
    print("Test 3 (path substring alone insufficient -- unrecognized parent still fails trust) PASSED")

    print("\nALL PLAYWRIGHT .local-browsers/ PATH TRUST TESTS PASSED")


main()
