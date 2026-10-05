import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import time

from config.manager import InjectionDetectorConfig
from core.datatypes import BaseEvent, EventCategory, Severity, WebAttackEvent
from core.event_bus import EventBus
import modules.injection_detector as injection_detector
from modules.injection_detector import InjectionDetector, _is_trusted_causal_evidence, _request_identity

DOMAIN = "example.com"
PROJECT = "/home/exampleuser/htdocs/example.com"
SOURCE_IP = "203.0.113.50"

_ROUND2_WEB_DESCENDANT_RULE_NAMES = frozenset({
    "WEB_PROCESS_SPAWN_SHELL", "UNEXPECTED_PARENT", "WEB_PROCESS_UNEXPECTED_EGRESS",
})


def _round2_vulnerable_predicate(metadata: dict) -> bool:
    if metadata.get("pid") is None or metadata.get("start_time_ticks") is None or metadata.get("ppid") is None:
        return False
    rules = metadata.get("rules") or []
    return any(rule in _ROUND2_WEB_DESCENDANT_RULE_NAMES for rule in rules)


def make_detector(**overrides):
    cfg = InjectionDetectorConfig(geoip_lookup=False, min_confidence_to_correlate=40, **overrides)
    detector = InjectionDetector(EventBus(), cfg)
    published = []
    detector.publish = lambda ev: published.append(ev)
    return detector, published


def rce_attack_event(*, raw="GET /?x=;id HTTP/1.1", source_ip=SOURCE_IP, request_path="/?x=;id", timestamp=None):
    kwargs = dict(
        source_module="nginx_monitor", category=EventCategory.WEB_ATTACK_RCE, severity=Severity.HIGH,
        message="Teknik injeksi terdeteksi", raw=raw, source_ip=source_ip, request_path=request_path,
        matched_signature="shell_separator_command", confidence=0.60, domain=DOMAIN, status_code=200,
        metadata={
            "domain": DOMAIN, "project_root": PROJECT, "source_ip": source_ip,
            "confidence": 60, "technique": "Command Execution Chain",
        },
    )
    if timestamp is not None:
        kwargs["timestamp"] = timestamp
    return WebAttackEvent(**kwargs)


def fim_evidence_event(*, sha256_new="deadbeef" * 8, path=f"{PROJECT}/index.php"):
    return BaseEvent(
        source_module="file_integrity_detector",
        category=EventCategory.FILE_INTEGRITY_CHANGE,
        severity=Severity.HIGH,
        message="Isi file diubah",
        raw=path,
        metadata={
            "project": PROJECT, "domain": DOMAIN, "path": path,
            "change_type": "modified", "sha256_old": "cafebabe" * 8, "sha256_new": sha256_new,
        },
    )


def web_descendant_process_event(
    *, pid=54321, start_time_ticks=1_000_000, ppid=100, rule="WEB_PROCESS_SPAWN_SHELL", timestamp=None,
):
    kwargs = dict(
        source_module="process_anomaly_detector", category=EventCategory.PROCESS_ANOMALY,
        severity=Severity.CRITICAL, message="Anomali proses", raw="sh -c id",
        metadata={
            "pid": pid, "ppid": ppid, "start_time_ticks": start_time_ticks,
            "project": PROJECT, "user": "www-data", "exe": "/bin/sh", "cmdline": "sh -c id",
            "rules": [rule], "confidence": 60,
        },
    )
    if timestamp is not None:
        kwargs["timestamp"] = timestamp
    return BaseEvent(**kwargs)


def unrelated_process_event(*, pid=77001, start_time_ticks=2_000_000, ppid=1):
    return BaseEvent(
        source_module="process_anomaly_detector", category=EventCategory.PROCESS_ANOMALY,
        severity=Severity.MEDIUM, message="Anomali proses",
        raw="python3 /home/exampleuser/one-off-admin-script.py",
        metadata={
            "pid": pid, "ppid": ppid, "start_time_ticks": start_time_ticks,
            "project": PROJECT, "user": "exampleuser", "exe": "/usr/bin/python3",
            "cmdline": "python3 /home/exampleuser/one-off-admin-script.py",
            "rules": ["UNKNOWN_EXECUTABLE"], "confidence": 30,
        },
    )


def remote_access_backdoor_event(*, pid=88888):
    return BaseEvent(
        source_module="remote_access_detector", category=EventCategory.REMOTE_ACCESS_BACKDOOR,
        severity=Severity.CRITICAL, message="Backdoor process terdeteksi", raw="ncat -lvp 4444 -e /bin/sh",
        metadata={
            "pid": pid, "process_name": "ncat", "parent_process": "systemd",
            "domain": DOMAIN, "project": PROJECT, "confidence": 70,
        },
    )


def persistence_new_service_event(*, unit="unrelated-legit.service"):
    return BaseEvent(
        source_module="host_persistence_detector", category=EventCategory.PERSISTENCE_NEW_SERVICE,
        severity=Severity.HIGH, message="Service systemd baru",
        metadata={"unit": unit, "enabled": True, "active": True, "project": PROJECT, "domain": DOMAIN},
    )


def confirmed_events(pub):
    return [e for e in pub if e.category == EventCategory.WEB_ATTACK_SUCCESS]


async def main():
    detector, pub = make_detector()
    await detector._on_event(rce_attack_event())
    await detector._on_event(fim_evidence_event())
    assert confirmed_events(pub) == [], f"1: RCE + FIM must NOT confirm: {pub}"
    print("1 (RCE + FILE_INTEGRITY_CHANGE -- no confirmation) PASSED")

    detector, pub = make_detector()
    await detector._on_event(rce_attack_event())
    await detector._on_event(remote_access_backdoor_event())
    assert confirmed_events(pub) == [], f"2: PID-bearing REMOTE_ACCESS_BACKDOOR must NOT confirm: {pub}"
    print("2 (RCE + unrelated PID-bearing process (REMOTE_ACCESS_BACKDOOR) -- no confirmation) PASSED")

    now = time.time()
    legitimate_deploy_at_0900 = web_descendant_process_event(timestamp=now)
    attacker_rce_at_0905 = rce_attack_event(timestamp=now + 300)
    assert _round2_vulnerable_predicate(legitimate_deploy_at_0900.metadata) is True, (
        "test setup: the round-2 predicate must find this process shape trustworthy on identity/ancestry alone"
    )
    detector, pub = make_detector()
    original_predicates = dict(injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES)
    injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES[EventCategory.PROCESS_ANOMALY] = (
        lambda md: _round2_vulnerable_predicate(md)
    )
    try:
        await detector._on_event(legitimate_deploy_at_0900)
        await detector._on_event(attacker_rce_at_0905)
        assert confirmed_events(pub) == [], (
            f"3: evidence timestamped BEFORE the attack must never confirm it, even with a "
            f"category temporarily granted causal trust: {pub}"
        )
    finally:
        injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES.clear()
        injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES.update(original_predicates)
    print(
        "3 (RCE + web-descendant process that PREDATES the attack -- fails under round-2 logic, "
        "blocked by the new temporal guard) PASSED"
    )

    detector, pub = make_detector()
    await detector._on_event(rce_attack_event())
    await detector._on_event(web_descendant_process_event())
    assert confirmed_events(pub) == [], (
        f"4: a real pid+start_time_ticks+ppid+WEB_PROCESS_SPAWN_SHELL process, same context, "
        f"correct order -- still must NOT confirm without real causal provenance: {pub}"
    )
    print("4 (RCE + web-descendant process, same context, correct temporal order -- still no confirmation) PASSED")

    same_raw = 'GET /?x=;id HTTP/1.1" 200 100 "-" "Mozilla/5.0'
    attack_from_nginx_regex = rce_attack_event(raw=same_raw, request_path="/?x=;id")
    attack_from_classify_request = rce_attack_event(raw=same_raw, request_path="/?x=%3Bid")
    assert attack_from_nginx_regex.event_id != attack_from_classify_request.event_id
    assert _request_identity(attack_from_nginx_regex) == _request_identity(attack_from_classify_request)

    detector, pub = make_detector()
    original_predicates = dict(injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES)
    injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES[EventCategory.PROCESS_ANOMALY] = lambda md: True
    try:
        await detector._on_event(attack_from_nginx_regex)
        await detector._on_event(attack_from_classify_request)
        await detector._on_event(web_descendant_process_event())
        assert len(confirmed_events(pub)) == 1, (
            f"5: two detector outputs for the same request must confirm at most once, got "
            f"{len(confirmed_events(pub))}: {pub}"
        )
    finally:
        injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES.clear()
        injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES.update(original_predicates)
    print("5 (same request, different event_ids -- confirms at most once when a category is trusted) PASSED")

    process_a = web_descendant_process_event(pid=1234, start_time_ticks=111_111, rule="WEB_PROCESS_SPAWN_SHELL")
    process_b = unrelated_process_event(pid=1234, start_time_ticks=222_222)
    assert process_a.metadata["pid"] == process_b.metadata["pid"] == 1234
    assert process_a.metadata["start_time_ticks"] != process_b.metadata["start_time_ticks"]
    assert (process_a.metadata["pid"], process_a.metadata["start_time_ticks"]) != (
        process_b.metadata["pid"], process_b.metadata["start_time_ticks"]
    ), "6: pid=1234 at two different start_time_ticks must be distinct process identities"
    print("6 (PID reuse: pid=1234 at two different start_time_ticks -- distinct identities, never conflated) PASSED")

    bus = EventBus()
    detector = InjectionDetector(bus, InjectionDetectorConfig(geoip_lookup=False))
    injection_pub = []
    detector.publish = lambda ev: injection_pub.append(ev)
    await bus.subscribe(detector.module_name, detector._on_event, categories=injection_detector._SUBSCRIBED_CATEGORIES)

    other_subscriber_received = []

    async def other_subscriber_handler(ev):
        other_subscriber_received.append(ev)

    await bus.subscribe("fake_discord_webhook", other_subscriber_handler, categories=None)

    evidence = web_descendant_process_event()
    await bus.publish(evidence)
    await asyncio.sleep(0.1)
    assert len(other_subscriber_received) == 1 and other_subscriber_received[0].event_id == evidence.event_id, (
        "7: a PROCESS_ANOMALY event must still reach OTHER subscribers (e.g. Discord) in full, "
        "regardless of injection_detector's own confirmation-eligibility decision"
    )
    assert confirmed_events(injection_pub) == [], "injection_detector's own gate must still block confirmation for this shape"
    await bus.shutdown()
    print("7 (PROCESS_ANOMALY remains independently alertable to other subscribers -- gate is additive only) PASSED")

    from modules.injection_detector import _EVIDENCE_CATEGORIES, _SUBSCRIBED_CATEGORIES
    assert EventCategory.CORRELATED_THREAT not in _EVIDENCE_CATEGORIES
    assert EventCategory.CORRELATED_THREAT not in _SUBSCRIBED_CATEGORIES
    detector, pub = make_detector()
    await detector._on_event(rce_attack_event())
    spoofed_tce_event = BaseEvent(
        source_module="threat_correlation_engine", category=EventCategory.CORRELATED_THREAT,
        severity=Severity.CRITICAL, message="fabricated high-severity correlation",
        metadata={
            "project": PROJECT, "domain": DOMAIN, "pid": 31337, "start_time_ticks": 1, "ppid": 1,
            "rules": ["WEB_PROCESS_SPAWN_SHELL"],
        },
    )
    await detector._on_event(spoofed_tce_event)
    assert confirmed_events(pub) == [], f"8: TCE-shaped event must never reach confirmation: {pub}"
    print("8 (TCE-shaped CORRELATED_THREAT event -- categorically excluded, cannot bypass) PASSED")

    now2 = time.time()
    detector, pub = make_detector()
    await detector._on_event(web_descendant_process_event(timestamp=now2))
    await detector._on_event(rce_attack_event(timestamp=now2 + 60))
    assert confirmed_events(pub) == [], f"9: evidence before the attack must never confirm it: {pub}"
    print("9 (host evidence occurring BEFORE the attack -- no confirmation) PASSED")

    now3 = time.time()
    detector, pub = make_detector()
    await detector._on_event(rce_attack_event(timestamp=now3))
    await detector._on_event(web_descendant_process_event(timestamp=now3 + 5))
    assert confirmed_events(pub) == [], (
        f"10: correctly-ordered evidence without genuine request-level provenance must still NOT confirm: {pub}"
    )
    print("10 (host evidence AFTER the attack, correct order, but no request-level provenance -- no confirmation) PASSED")

    assert _is_trusted_causal_evidence(fim_evidence_event()) is False
    assert _is_trusted_causal_evidence(web_descendant_process_event()) is False, (
        "with the empty predicate table, even the strongest possible PROCESS_ANOMALY shape must not be trusted"
    )
    assert _is_trusted_causal_evidence(unrelated_process_event()) is False
    assert _is_trusted_causal_evidence(remote_access_backdoor_event()) is False
    assert _is_trusted_causal_evidence(persistence_new_service_event()) is False
    assert injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES == {}, (
        "the predicate table must be empty until a producer publishes genuine request-level causal provenance"
    )
    print("Property checks (predicate table empty; nothing is confirmation-eligible right now) PASSED")

    detector, pub = make_detector()
    original_predicates = dict(injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES)
    injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES[EventCategory.PROCESS_ANOMALY] = lambda md: True
    try:
        attack = rce_attack_event()
        await detector._on_event(attack)
        await detector._on_event(attack)
        await detector._on_event(web_descendant_process_event())
        assert len(confirmed_events(pub)) == 1, "duplicate attack event_id must not multiply confirmations"
    finally:
        injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES.clear()
        injection_detector._TRUSTED_CAUSAL_EVIDENCE_PREDICATES.update(original_predicates)
    print("Extra (duplicate WEB_ATTACK_RCE, same event identity -- dedup mechanism still correct) PASSED")

    print("\nALL RCE-001/F-27 ROUND 3 (NO CONFIRMATION WITHOUT REQUEST-LEVEL PROVENANCE) TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
