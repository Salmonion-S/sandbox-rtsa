import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import ProcessAnomalyDetectorConfig, TrustedProcessProfile
from modules.process_anomaly_detector import ProcessSnapshot, evaluate_rules

DEFAULT_WEIGHTS = {
    "WEB_PROCESS_SPAWN_SHELL": 60, "SHELL_SPAWN_NETWORK_TOOL": 20, "TEMP_DIRECTORY_EXECUTION": 40,
    "UNKNOWN_EXECUTABLE": 30, "UNEXPECTED_PARENT": 60, "UID_SWITCH": 20,
    "LD_PRELOAD_ENV_SET": 45, "FILELESS_EXECUTION": 55, "WEB_PROCESS_UNEXPECTED_EGRESS": 35,
}

PUPPETEER_CACHE_CHROME = (
    "/home/simpukes-api-sungaibaung/.cache/puppeteer/chrome/linux-131.0.6778.204/"
    "chrome-linux64/chrome"
)


def make_snapshot(**overrides):
    base = dict(
        pid=1000, ppid=1, uid=1000, gid=1000, exe="/usr/bin/node", cwd="/home/exampleuser",
        cmdline="node server.js", username="exampleuser", start_time=0.0, project=None,
        network_active=False, start_time_ticks=0,
    )
    base.update(overrides)
    return ProcessSnapshot(**base)


def rule_names(results):
    return {name for name, _weight, _reason in results}


def main():
    allowed = set(ProcessAnomalyDetectorConfig().allowed_processes)
    assert not ({"chrome", "chromium", "headless_shell"} & allowed), (
        "chrome/chromium/headless_shell must NOT be trusted by basename alone via "
        "allowed_processes -- that was the 9f04443 regression"
    )
    profiles = list(ProcessAnomalyDetectorConfig().trusted_process_profiles)
    assert profiles, "default config must ship a trusted_process_profiles entry for headless browsers"

    puppeteer_node = make_snapshot(pid=1457400, uid=1000, exe="/usr/bin/node", cmdline="node app.js")
    chrome_from_puppeteer_cache = make_snapshot(
        pid=1457427, ppid=1457400, uid=1000,
        exe=PUPPETEER_CACHE_CHROME,
        cwd="/home/simpukes-api-sungaibaung",
        cmdline=f"{PUPPETEER_CACHE_CHROME} --disable-background-networking --disable-extensions --headless",
    )
    results = evaluate_rules(
        chrome_from_puppeteer_cache, puppeteer_node, allowed, DEFAULT_WEIGHTS,
        trusted_process_profiles=profiles,
    )
    assert "UNKNOWN_EXECUTABLE" not in rule_names(results), (
        f"legitimate Puppeteer Chrome (correct path+parent+uid) must not trip UNKNOWN_EXECUTABLE: {results}"
    )
    print("Scenario 1 (legitimate Puppeteer Chrome: path+parent+uid all match) PASSED")

    chrome_renderer_child = make_snapshot(
        pid=1457436, ppid=1457427, uid=1000,
        exe=PUPPETEER_CACHE_CHROME,
        cwd="/home/simpukes-api-sungaibaung",
        cmdline=f"{PUPPETEER_CACHE_CHROME} --type=renderer --headless",
    )
    results = evaluate_rules(
        chrome_renderer_child, chrome_from_puppeteer_cache, allowed, DEFAULT_WEIGHTS,
        trusted_process_profiles=profiles,
    )
    assert "UNKNOWN_EXECUTABLE" not in rule_names(results), (
        f"a Chrome child (renderer/GPU) with the same cache path/uid, parented by Chrome itself, "
        f"must not trip UNKNOWN_EXECUTABLE: {results}"
    )
    print("Scenario 2 (legitimate Chrome child/renderer process, parent is Chrome itself) PASSED")

    attacker_chrome = make_snapshot(
        pid=6001, ppid=1457400, uid=1000,
        exe="/home/attacker/.hidden/chrome",
        cwd="/home/attacker/.hidden",
        cmdline="/home/attacker/.hidden/chrome --headless",
    )
    results = evaluate_rules(
        attacker_chrome, puppeteer_node, allowed, DEFAULT_WEIGHTS,
        trusted_process_profiles=profiles,
    )
    assert "UNKNOWN_EXECUTABLE" in rule_names(results), (
        f"a binary named 'chrome' from an arbitrary attacker-controlled path must still trip "
        f"UNKNOWN_EXECUTABLE (this is the exact 9f04443 bypass): {results}"
    )
    print("Scenario 3 (/home/attacker/.hidden/chrome -- bypass closed, UNKNOWN_EXECUTABLE fires) PASSED")

    chrome_from_tmp = make_snapshot(pid=6002, ppid=1457400, uid=1000, exe="/tmp/chrome", cwd="/tmp")
    results = evaluate_rules(
        chrome_from_tmp, puppeteer_node, allowed, DEFAULT_WEIGHTS,
        trusted_process_profiles=profiles,
    )
    names = rule_names(results)
    assert "UNKNOWN_EXECUTABLE" in names, f"/tmp/chrome must still trip UNKNOWN_EXECUTABLE: {results}"
    assert "TEMP_DIRECTORY_EXECUTION" in names, f"/tmp/chrome must also trip TEMP_DIRECTORY_EXECUTION: {results}"
    print("Scenario 4 (/tmp/chrome -- UNKNOWN_EXECUTABLE and TEMP_DIRECTORY_EXECUTION both fire) PASSED")

    renamed_sh = make_snapshot(
        pid=6003, ppid=1457400, uid=1000,
        exe="/home/exampleuser/bin/chrome",
        cwd="/home/exampleuser/bin",
        cmdline="/home/exampleuser/bin/chrome",
    )
    results = evaluate_rules(
        renamed_sh, puppeteer_node, allowed, DEFAULT_WEIGHTS,
        trusted_process_profiles=profiles,
    )
    assert "UNKNOWN_EXECUTABLE" in rule_names(results), (
        f"a renamed-to-chrome binary outside the Puppeteer/Playwright cache path must still "
        f"trip UNKNOWN_EXECUTABLE: {results}"
    )
    print("Scenario 5 (renamed binary named chrome, non-cache path -- UNKNOWN_EXECUTABLE fires) PASSED")

    unrelated_parent = make_snapshot(pid=7000, ppid=1, uid=1000, exe="/usr/bin/bash", cmdline="bash -i")
    wrong_parent_chrome = make_snapshot(
        pid=7001, ppid=7000, uid=1000,
        exe=PUPPETEER_CACHE_CHROME,
        cwd="/home/simpukes-api-sungaibaung",
        cmdline=f"{PUPPETEER_CACHE_CHROME} --headless",
    )
    results = evaluate_rules(
        wrong_parent_chrome, unrelated_parent, allowed, DEFAULT_WEIGHTS,
        trusted_process_profiles=profiles,
    )
    assert "UNKNOWN_EXECUTABLE" in rule_names(results), (
        f"correct path+basename+uid but spawned by an unexpected parent (bash, not node/chrome) "
        f"must still trip UNKNOWN_EXECUTABLE -- the profile requires ALL attributes together: {results}"
    )
    print("Scenario 6 (correct path but wrong/unexpected parent -- UNKNOWN_EXECUTABLE fires) PASSED")

    wrong_user_chrome = make_snapshot(
        pid=7002, ppid=1457400, uid=1234,
        exe=PUPPETEER_CACHE_CHROME,
        cwd="/home/simpukes-api-sungaibaung",
        cmdline=f"{PUPPETEER_CACHE_CHROME} --headless",
    )
    results = evaluate_rules(
        wrong_user_chrome, puppeteer_node, allowed, DEFAULT_WEIGHTS,
        trusted_process_profiles=profiles,
    )
    assert "UNKNOWN_EXECUTABLE" in rule_names(results), (
        f"correct path+basename+parent but running as a different uid than its parent "
        f"(uid=1234 vs parent uid=1000) must still trip UNKNOWN_EXECUTABLE: {results}"
    )
    print("Scenario 7 (correct path/parent but uid differs from parent's -- UNKNOWN_EXECUTABLE fires) PASSED")

    for exe_name in ("chromium", "headless_shell"):
        path = f"/home/exampleuser/.cache/ms-playwright/chromium-1000/chrome-linux/{exe_name}"
        legit = make_snapshot(
            pid=8000, ppid=1457400, uid=1000, exe=path, cwd="/home/exampleuser",
            cmdline=f"{path} --headless",
        )
        results = evaluate_rules(legit, puppeteer_node, allowed, DEFAULT_WEIGHTS, trusted_process_profiles=profiles)
        assert "UNKNOWN_EXECUTABLE" not in rule_names(results), f"{exe_name}: legitimate case must not flag: {results}"

        attacker = make_snapshot(
            pid=8001, ppid=1457400, uid=1000, exe=f"/home/attacker/.hidden/{exe_name}",
            cwd="/home/attacker/.hidden",
        )
        results = evaluate_rules(attacker, puppeteer_node, allowed, DEFAULT_WEIGHTS, trusted_process_profiles=profiles)
        assert "UNKNOWN_EXECUTABLE" in rule_names(results), f"{exe_name}: attacker-path case must flag: {results}"
    print("Scenario 8 (chromium/headless_shell -- same profile covers legit case, closes attacker bypass) PASSED")

    mystery_binary = make_snapshot(
        pid=9000, uid=1000, exe="/home/exampleuser/.cache/some-random-tool/totally-unknown-binary",
        cwd="/home/exampleuser",
    )
    results = evaluate_rules(mystery_binary, puppeteer_node, allowed, DEFAULT_WEIGHTS, trusted_process_profiles=profiles)
    assert "UNKNOWN_EXECUTABLE" in rule_names(results), (
        f"an unrelated unknown executable outside allowed_processes must still be flagged: {results}"
    )
    print("Scenario 9 (unrelated unknown executable, not chrome/chromium/headless_shell -- still flagged) PASSED")

    results = evaluate_rules(chrome_from_puppeteer_cache, puppeteer_node, allowed, DEFAULT_WEIGHTS)
    assert "UNKNOWN_EXECUTABLE" in rule_names(results), (
        f"without trusted_process_profiles, even the legitimate Puppeteer Chrome must fail closed "
        f"to UNKNOWN_EXECUTABLE -- there must be no silent basename-only trust fallback: {results}"
    )
    print("Scenario 10 (no trusted_process_profiles supplied -- fails closed, no implicit trust) PASSED")

    print("\nALL TRUSTED-PROCESS-PROFILE / HEADLESS-BROWSER REGRESSION TESTS PASSED")


main()
