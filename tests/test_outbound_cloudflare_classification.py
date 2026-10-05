import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio
import inspect
import tempfile
import time

from config.manager import OutboundAnomalyDetectorConfig, ResourceGovernorConfig
from core.cpu_governor import configure_cpu_governor, get_cpu_governor
from core.datatypes import EventCategory
from core.event_bus import EventBus
from core.outbound_baseline import (
    TRUST_CLOUDFLARE_EDGE, TRUST_UNKNOWN, classify_destination_trust, destination_group,
)
from modules.outbound_anomaly_detector import (
    LEGITIMACY_EXECUTABLE_UNTRUSTED_DIR, LEGITIMACY_OWNER_HOME_MISMATCH,
    LEGITIMACY_TRUSTED_PROJECT_RUNTIME, OutboundAnomalyDetector, assess_process_legitimacy,
)

CF_V4 = "104.21.110.5"
CF_V4_OTHER = "172.64.31.9"
CF_V6 = "2606:4700:3032::6815:169"
NON_CF_V4 = "203.0.113.77"
NON_CF_V6 = "2001:db8::1234"

PROJECT_USER = "newus-cat"
PROJECT_NODE = f"/home/{PROJECT_USER}/.nvm/versions/node/v22.23.2/bin/node"
PROJECT_CWD = f"/home/{PROJECT_USER}/htdocs/cat.newus.id"


def make_detector(tmpdir, **overrides):
    overrides.setdefault("enabled", True)
    overrides.setdefault("learning_period_seconds", 0.0)
    overrides.setdefault("baseline_state_path", os.path.join(tmpdir, "outbound.json"))
    detector = OutboundAnomalyDetector(EventBus(), OutboundAnomalyDetectorConfig(**overrides))
    published = []
    detector.publish = lambda event: published.append(event)
    detector._baseline.seed_started_at(time.time() - 100000.0)
    return detector, published


def seed_process(detector, pid, *, exe, cwd=None, start_time=None, username=PROJECT_USER, ppid=1):
    meta = {
        "pid": pid, "ppid": ppid, "uid": 1000, "username": username,
        "exe": exe, "cwd": cwd, "cmdline": exe,
        "start_time": start_time if start_time is not None else time.time() - 86400.0,
        "start_time_ticks": 1, "project": None, "exe_key": exe,
    }
    detector._process_meta.set(pid, meta)
    return meta


async def scan(detector, rows, listening_ports=None):
    normalized = []
    for i, row in enumerate(rows):
        pid, ip, port, status = row
        normalized.append((pid, ip, port, status, 50000 + i))
    detector.__class__._collect_connections = staticmethod(
        lambda: (list(normalized), set(listening_ports or set()))
    )
    await detector._scan_connections()


def outbound_alerts(published):
    return [e for e in published if e.category == EventCategory.OUTBOUND_ANOMALY]


async def test_1_to_4_range_recognition() -> None:
    assert classify_destination_trust(CF_V4) == TRUST_CLOUDFLARE_EDGE
    assert classify_destination_trust(CF_V4_OTHER) == TRUST_CLOUDFLARE_EDGE
    print("Test 1 (Cloudflare IPv4 recognized via CIDR membership) PASSED")

    assert classify_destination_trust(CF_V6) == TRUST_CLOUDFLARE_EDGE
    assert classify_destination_trust("2803:f800::99") == TRUST_CLOUDFLARE_EDGE
    print("Test 2 (Cloudflare IPv6 recognized via CIDR membership) PASSED")

    assert classify_destination_trust(NON_CF_V4) == TRUST_UNKNOWN
    assert classify_destination_trust("8.8.8.8") == TRUST_UNKNOWN
    assert classify_destination_trust("104.99.110.5") == TRUST_UNKNOWN, (
        "an address that merely shares a leading octet with a Cloudflare range must not match -- "
        "this is exactly what prefix/startswith matching would get wrong"
    )
    print("Test 3 (non-Cloudflare IPv4 rejected, no prefix guessing) PASSED")

    assert classify_destination_trust(NON_CF_V6) == TRUST_UNKNOWN
    assert classify_destination_trust("2606:4701::1") == TRUST_UNKNOWN, (
        "an IPv6 address adjacent to but outside 2606:4700::/32 must not match"
    )
    print("Test 4 (non-Cloudflare IPv6 rejected, correct /32 boundary) PASSED")


async def test_5_and_6_legitimate_project_traffic_suppressed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        detector, published = make_detector(tmp)
        seed_process(detector, 4101, exe=PROJECT_NODE, cwd=PROJECT_CWD)
        await scan(detector, [(4101, CF_V4, 443, "ESTABLISHED")])
        assert outbound_alerts(published) == [], (
            f"the exact reported false positive must be silent, got: "
            f"{[e.message[:120] for e in outbound_alerts(published)]}"
        )
        assert detector._cloudflare_suppressed_total == 1
        print("Test 5 (Cloudflare TCP/443 + legitimate NVM Node runtime -> suppressed) PASSED")

        detector2, published2 = make_detector(tmp)
        seed_process(
            detector2, 4102, exe=f"/home/{PROJECT_USER}/app/server", cwd=PROJECT_CWD,
        )
        await scan(detector2, [(4102, CF_V6, 443, "ESTABLISHED")])
        assert outbound_alerts(published2) == [], (
            "the IPv6 form of the same legitimate project connection must also be suppressed"
        )
        assert detector2._cloudflare_suppressed_total == 1
        print("Test 6 (Cloudflare IPv6/443 + legitimate project process -> suppressed) PASSED")


async def test_7_unusual_port_not_suppressed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        detector, published = make_detector(tmp)
        seed_process(detector, 4201, exe=PROJECT_NODE, cwd=PROJECT_CWD)
        await scan(detector, [(4201, CF_V4, 8443, "ESTABLISHED")])
        alerts = outbound_alerts(published)
        assert len(alerts) == 1, "a Cloudflare address on an unusual port must not be auto-suppressed"
        assert detector._cloudflare_suppressed_total == 0
        assert "8443" in alerts[0].message
        print("Test 7 (Cloudflare on an unusual port -> still alerts) PASSED")


async def _alerts_for(tmp, pid, *, exe, cwd, user, start, aware, ip=CF_V4, port=443):
    detector, published = make_detector(tmp, cloudflare_aware=aware)
    seed_process(detector, pid, exe=exe, cwd=cwd, username=user, start_time=start)
    await scan(detector, [(pid, ip, port, "ESTABLISHED")])
    return detector, outbound_alerts(published)


async def test_8_to_11_suspicious_processes_still_detected() -> None:
    cases = [
        ("Test 8", 4302, "/tmp/node", "/tmp", PROJECT_USER, None,
         "/tmp executable (writable-project rule)"),
        ("Test 9", 4303, PROJECT_NODE, "/home/someone-else/htdocs/other.site", PROJECT_USER, None,
         "executable and cwd disagree about the owning home (writable-project rule)"),
        ("Test 10", 4304, f"/home/{PROJECT_USER}/.nvm/versions/node/v22.23.2/bin/node (deleted)",
         PROJECT_CWD, PROJECT_USER, None, "fileless/deleted executable (fileless rule)"),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        for label, pid, exe, cwd, user, start, description in cases:
            detector, alerts = await _alerts_for(
                tmp, pid, exe=exe, cwd=cwd, user=user, start=start, aware=True,
            )
            assert len(alerts) == 1, f"{label}: {description} + Cloudflare must still alert"
            assert detector._cloudflare_suppressed_total == 0, f"{label} must not be suppressed"
            assert detector._cloudflare_suspicious_total == 1, (
                f"{label} must be counted as suspicious-despite-Cloudflare"
            )
            assert "Cloudflare" in alerts[0].message, (
                f"{label}: the alert must say the destination is Cloudflare and why it was kept"
            )
            print(f"{label} ({description} + Cloudflare -> alert retained with context) PASSED")


async def test_11b_parity_for_signals_this_detector_does_not_score() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        without, alerts_without = await _alerts_for(
            tmp, 4401, exe="/usr/local/bin/curl-backdoor", cwd="/root", user="root",
            start=None, aware=False,
        )
        with_cf, alerts_with = await _alerts_for(
            tmp, 4402, exe="/usr/local/bin/curl-backdoor", cwd="/root", user="root",
            start=None, aware=True,
        )
        assert len(alerts_with) == len(alerts_without), (
            "an executable this detector does not otherwise flag must reach the identical "
            "verdict whether or not Cloudflare awareness is enabled"
        )
        assert with_cf._cloudflare_suppressed_total == 0, (
            "an unrecognized executable must never be suppressed as trusted infrastructure"
        )
        print(
            "Test 11b (unscored executable reaches identical verdict with/without Cloudflare "
            "awareness -- Cloudflare classification adds no new blind spot) PASSED"
        )


async def test_12_and_13_first_seen_behaviour() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        detector, published = make_detector(tmp)
        seed_process(detector, 4401, exe=PROJECT_NODE, cwd=PROJECT_CWD)
        for ip in (CF_V4, CF_V4_OTHER, "104.16.5.5", "172.64.9.9"):
            await scan(detector, [(4401, ip, 443, "ESTABLISHED")])
        assert outbound_alerts(published) == [], (
            "Cloudflare rotates edge addresses across many /24s, so first-seen alone must never "
            "be enough to alert for an otherwise legitimate process"
        )
        assert detector._first_seen_destinations_total >= 4
        assert detector._cloudflare_suppressed_total == 4
        print("Test 12 (repeated first-seen Cloudflare destinations -> no anomaly alert) PASSED")

        detector2, published2 = make_detector(tmp)
        seed_process(detector2, 4402, exe=PROJECT_NODE, cwd=PROJECT_CWD)
        await scan(detector2, [(4402, NON_CF_V4, 443, "ESTABLISHED")])
        alerts = outbound_alerts(published2)
        assert len(alerts) == 1, (
            "a first-seen NON-Cloudflare destination must keep the pre-existing behaviour -- the "
            "fix narrows to identified edge infrastructure, it does not relax first-seen globally"
        )
        assert detector2._cloudflare_suppressed_total == 0
        print("Test 13 (first-seen non-Cloudflare destination -> existing behaviour preserved) PASSED")


async def test_14_and_15_fail_safe() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        detector, published = make_detector(tmp, cloudflare_aware=False)
        seed_process(detector, 4501, exe=PROJECT_NODE, cwd=PROJECT_CWD)
        await scan(detector, [(4501, CF_V4, 443, "ESTABLISHED")])
        assert len(outbound_alerts(published)) == 1, (
            "with Cloudflare awareness switched off the detector must fall back to plain outbound "
            "anomaly detection, still fully operational"
        )
        assert detector._cloudflare_suppressed_total == 0
        print("Test 14 (Cloudflare classification unavailable/disabled -> detector stays operational) PASSED")

        for bad in ("", "not-an-ip", "999.999.999.999", None, "104.21.110.5/24"):
            assert classify_destination_trust(bad) == TRUST_UNKNOWN, bad
        detector2, published2 = make_detector(tmp)
        seed_process(detector2, 4502, exe=PROJECT_NODE, cwd=PROJECT_CWD)
        await scan(detector2, [(4502, "not-an-ip", 443, "ESTABLISHED")])
        assert detector2._cloudflare_suppressed_total == 0, (
            "an unparseable destination must never be classified as trusted infrastructure"
        )
        print("Test 15 (invalid/unparseable destination -> UNKNOWN, fails safe toward detection) PASSED")


async def test_16_and_17_cidr_matching_details() -> None:
    assert classify_destination_trust("2a06:98c0::1") == TRUST_CLOUDFLARE_EDGE, "/29 IPv6 range"
    assert classify_destination_trust("2c0f:f248:ffff::1") == TRUST_CLOUDFLARE_EDGE
    assert classify_destination_trust("2a06:98c0::1") == TRUST_CLOUDFLARE_EDGE
    assert classify_destination_trust("2a06:98c7:ffff::1") == TRUST_CLOUDFLARE_EDGE
    assert classify_destination_trust("2a06:98c8::1") == TRUST_UNKNOWN, (
        "just past the /29 boundary (98c8, one above the highest in-range 98c7) must not match -- "
        "proves real prefix-length arithmetic rather than nibble/prefix-string guessing"
    )
    print("Test 16 (IPv6 CIDR matching honours non-nibble-aligned /29 boundaries) PASSED")

    distinct = {
        classify_destination_trust(ip)
        for ip in ("173.245.48.1", "103.21.244.1", "141.101.64.1", "198.41.128.1", "131.0.72.1")
    }
    assert distinct == {TRUST_CLOUDFLARE_EDGE}, "every published Cloudflare range must be matched"
    assert destination_group("104.21.110.5") != destination_group("172.64.31.9"), (
        "different Cloudflare ranges stay distinct destinations in the baseline -- suppression "
        "happens at classification time, the forensic record is not collapsed"
    )
    print("Test 17 (all configured Cloudflare ranges match, baseline keeps them distinct) PASSED")


async def test_18_no_alert_storm() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        detector, published = make_detector(tmp)
        seed_process(detector, 4601, exe="/tmp/beacon", cwd="/tmp", username=PROJECT_USER)
        for _ in range(10):
            await scan(detector, [(4601, CF_V4, 443, "ESTABLISHED")])
        alerts = outbound_alerts(published)
        assert len(alerts) == 1, (
            f"10 cycles of the same suspicious Cloudflare connection must collapse into one "
            f"incident, got {len(alerts)}"
        )
        print("Test 18 (repeated suspicious Cloudflare connection -> one alert, no storm) PASSED")


async def test_19_bounded_state() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        detector, _published = make_detector(tmp)
        rows = []
        for i in range(400):
            pid = 5000 + i
            seed_process(detector, pid, exe=PROJECT_NODE, cwd=PROJECT_CWD)
            rows.append((pid, f"104.21.{i % 256}.{(i * 7) % 256}", 443, "ESTABLISHED"))
        await scan(detector, rows)
        assert len(detector._observations) <= 4096
        assert len(detector._process_meta) <= 2048
        assert detector._cloudflare_suppressed_total > 0
        assert detector._cloudflare_suppressed_total <= 400
        print(
            f"Test 19 (bounded state: {len(detector._observations)} observations, "
            f"{detector._cloudflare_suppressed_total} suppressions counted as aggregates not logs) PASSED"
        )


async def test_20_no_subprocess_or_lookup_per_event() -> None:
    source = inspect.getsource(sys.modules["modules.outbound_anomaly_detector"])
    baseline_source = inspect.getsource(sys.modules["core.outbound_baseline"])
    for forbidden in ("subprocess", "shell=True", "socket.gethostby", "aiohttp", "requests",
                      "urllib.request", "os.popen", "dig ", "whois", "nslookup"):
        assert forbidden not in source, f"outbound detector must not use {forbidden!r} per event"
        assert forbidden not in baseline_source, f"outbound baseline must not use {forbidden!r}"
    assert "_CLOUDFLARE_EDGE_NETWORKS" in inspect.getsource(sys.modules["core.ip_normalization"]), (
        "CIDR objects must be pre-parsed once at import, not rebuilt per event"
    )
    trust_source = inspect.getsource(classify_destination_trust)
    assert "ip_network(" not in trust_source, (
        "classification must reuse the pre-parsed networks rather than parsing CIDRs per call"
    )
    print("Test 20 (no subprocess, DNS, HTTP or repeated CIDR parsing per outbound event) PASSED")


async def test_21_legitimacy_is_not_name_based() -> None:
    malicious_node = {
        "exe": "/tmp/node", "cwd": "/tmp", "username": PROJECT_USER, "pid": 1, "ppid": 1,
    }
    legit_node = {
        "exe": PROJECT_NODE, "cwd": PROJECT_CWD, "username": PROJECT_USER, "pid": 2, "ppid": 1,
    }
    ok_bad, reason_bad = assess_process_legitimacy(malicious_node)
    ok_good, reason_good = assess_process_legitimacy(legit_node)
    assert ok_bad is False and reason_bad == LEGITIMACY_EXECUTABLE_UNTRUSTED_DIR
    assert ok_good is True and reason_good == LEGITIMACY_TRUSTED_PROJECT_RUNTIME
    assert os.path.basename(malicious_node["exe"]) == os.path.basename(legit_node["exe"]) == "node", (
        "both are called 'node' -- the verdict must come from path/ownership, never the name"
    )
    other_home = {
        "exe": "/home/attacker/.nvm/versions/node/v22/bin/node", "cwd": PROJECT_CWD,
        "username": PROJECT_USER, "pid": 3, "ppid": 1,
    }
    ok_other, reason_other = assess_process_legitimacy(other_home)
    assert ok_other is False and reason_other == LEGITIMACY_OWNER_HOME_MISMATCH
    print("Test 21 (legitimacy uses path/ownership agreement, never the executable name) PASSED")


async def test_22_evidence_preserved_for_suppressed_traffic() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        detector, published = make_detector(tmp)
        seed_process(detector, 4701, exe=PROJECT_NODE, cwd=PROJECT_CWD)
        await scan(detector, [(4701, CF_V4, 443, "ESTABLISHED")])
        assert outbound_alerts(published) == []
        assert detector._baseline.is_known_destination(PROJECT_NODE, CF_V4), (
            "a suppressed connection must still be recorded in the outbound baseline -- what is "
            "removed is the notification, not the forensic record"
        )
        health = await detector.health()
        assert health["cloudflare_suppressed_total"] == 1
        assert health["cloudflare_aware"] is True
        assert health["ipv4_ranges"] > 0 and health["ipv6_ranges"] > 0
        print("Test 22 (suppressed Cloudflare traffic stays in the baseline and in health counters) PASSED")


async def main() -> None:
    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    get_cpu_governor().reset_for_tests()
    await test_1_to_4_range_recognition()
    await test_5_and_6_legitimate_project_traffic_suppressed()
    await test_7_unusual_port_not_suppressed()
    await test_8_to_11_suspicious_processes_still_detected()
    await test_12_and_13_first_seen_behaviour()
    await test_14_and_15_fail_safe()
    await test_16_and_17_cidr_matching_details()
    await test_18_no_alert_storm()
    await test_19_bounded_state()
    await test_20_no_subprocess_or_lookup_per_event()
    await test_21_legitimacy_is_not_name_based()
    await test_22_evidence_preserved_for_suppressed_traffic()
    print("\nALL OUTBOUND CLOUDFLARE CLASSIFICATION TESTS PASSED")


asyncio.run(main())
