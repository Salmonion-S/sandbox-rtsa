import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import TceConfig
from modules.threat_correlation_engine import (
    CorrelationCandidateEvent, build_event_chain, classify_event, group_classified_events, score_group,
)


def _web_event(event_id, timestamp, *, classification=None, assessment=None, domain="api.example.com",
                source_ip="203.0.113.9", webroot=None, path=None, category="WEB_ATTACK_RCE"):
    raw_metadata = {}
    if classification is not None:
        raw_metadata["classification"] = classification
    if assessment is not None:
        raw_metadata["assessment"] = assessment
    return CorrelationCandidateEvent(
        event_id=event_id, timestamp=timestamp, category=category, severity="HIGH",
        message="web attack", source_module="nginx_monitor",
        domain=domain, source_ip=source_ip, webroot=webroot, path=path, confidence=60,
        raw_metadata=raw_metadata,
    )


def main():
    tce_config = TceConfig()

    unconfirmed = _web_event("w1", 100.0, classification="ATTEMPT")
    classified = classify_event(unconfirmed, tce_config)
    assert classified.kind == "Web attack (unconfirmed)", classified.kind
    assert classified.weight == 0, classified.weight
    print("Test 1 (ATTEMPT/no-execution-evidence web attack -- Context only, weight 0) PASSED")

    no_execution = _web_event("w2", 100.0, assessment="REQUEST_DETECTED_NO_EXECUTION_EVIDENCE")
    classified2 = classify_event(no_execution, tce_config)
    assert classified2.kind == "Web attack (unconfirmed)", classified2.kind
    assert classified2.weight == 0, classified2.weight
    print("Test 2 (REQUEST_DETECTED_NO_EXECUTION_EVIDENCE -- Context only, weight 0) PASSED")

    no_metadata_at_all = _web_event("w3", 100.0)
    classified3 = classify_event(no_metadata_at_all, tce_config)
    assert classified3.kind == "Web attack (unconfirmed)", (
        "an event with no classification/assessment metadata at all must never default to "
        "full-weight Security Evidence -- absence of evidence is not evidence"
    )
    assert classified3.weight == 0
    print("Test 3 (missing classification entirely -- still Context only, never assumed confirmed) PASSED")

    confirmed = _web_event("w4", 100.0, classification="CONFIRMED_SUCCESS")
    classified4 = classify_event(confirmed, tce_config)
    assert classified4.kind == "Web attack", classified4.kind
    assert classified4.weight == 10, classified4.weight
    print("Test 4 (CONFIRMED_SUCCESS -- Security Evidence, real weight) PASSED")

    rce_confirmed = _web_event("w5", 100.0, classification="ATTEMPT", assessment="RCE_EXECUTION_SUSPECTED")
    classified5 = classify_event(rce_confirmed, tce_config)
    assert classified5.kind == "Web attack", classified5.kind
    assert classified5.weight == 10, classified5.weight
    print("Test 5 (RCE_EXECUTION_SUSPECTED -- host-side-confirmed evidence, Security Evidence) PASSED")

    solo_group = [classify_event(_web_event("w6", 100.0, classification="ATTEMPT", source_ip="9.9.9.9"), tce_config)]
    result = score_group(solo_group, tce_config)
    assert result.total == 0, (
        f"an unconfirmed web attack alone in its own group must never raise a nonzero score: {result.total}"
    )
    print("Test 6 (unconfirmed web attack alone -- group score stays 0, never alerts) PASSED")

    repeats = [
        classify_event(_web_event(f"w7-{i}", 100.0 + i, classification="ATTEMPT", source_ip="8.8.4.4"), tce_config)
        for i in range(5)
    ]
    result2 = score_group(repeats, tce_config)
    assert result2.total == 0, (
        f"repeated low-signal probes from the same source must never inflate score by count: {result2.total}"
    )
    print("Test 7 (5 repeated low-signal probes from same IP -- still score 0, no count-based inflation) PASSED")

    http_event = _web_event("h1", 1000.0, classification="ATTEMPT", webroot="/home/victim/htdocs/example.com")
    file_event = CorrelationCandidateEvent(
        event_id="f1", timestamp=1001.0, category="FILE_INTEGRITY_CHANGE", severity="CRITICAL",
        message="shell.php created", source_module="webshell_detector",
        webroot="/home/victim/htdocs/example.com", path="/home/victim/htdocs/example.com/shell.php",
    )
    proc_event = CorrelationCandidateEvent(
        event_id="p1", timestamp=1002.0, category="PROCESS_ANOMALY", severity="CRITICAL",
        message="proc spawned", source_module="process_anomaly_detector",
        webroot="/home/victim/htdocs/example.com", pid=1234, discord_eligible=True,
    )
    grouped = group_classified_events([classify_event(e, tce_config) for e in (http_event, file_event, proc_event)])
    assert len(grouped) == 1
    result3 = score_group(grouped[0], tce_config)
    assert result3.total > 0, "the group's real evidence (webshell + reverse shell) must still score"
    chain = build_event_chain(result3)
    hops = [c["hop"] for c in chain]
    assert "HTTP_REQUEST" in hops, (
        f"an unconfirmed web attack corroborated by file+process evidence in the same group must "
        f"still appear in the chain as context, even though it contributes 0 score: {hops}"
    )
    print("Test 8 (unconfirmed web attack still visible in event_chain when corroborated by other evidence) PASSED")

    print("\nALL WEB ATTACK CORRELATION GATE TESTS PASSED")


main()
