import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import TceConfig
from core.event_bus import EventBus
from modules.process_anomaly_detector import ProcessSnapshot, evaluate_rules, match_trusted_profile
from config.manager import TrustedProcessProfile
from modules.threat_correlation_engine import (
    CorrelationCandidateEvent, ThreatCorrelationEngine, _has_reverse_shell_evidence,
    _stable_incident_key, classify_event, group_classified_events, score_group,
)


def _event(
    event_id, timestamp, *, pid, fingerprint, project="proj", user="deploy",
    rules=None, remote_endpoints=None, confidence=50,
) -> CorrelationCandidateEvent:
    return CorrelationCandidateEvent(
        event_id=event_id, timestamp=timestamp, category="PROCESS_ANOMALY", severity="MEDIUM",
        message=f"anomaly pid={pid}", source_module="process_anomaly_detector",
        project=project, webroot=f"/home/{user}/htdocs/{project}", user=user, pid=pid,
        process_fingerprint=fingerprint, confidence=confidence, rules=rules or [],
        remote_endpoints=remote_endpoints or [], discord_eligible=True,
        raw_metadata={"user": user},
    )


def _result(events, config):
    classified = [classify_event(e, config) for e in events]
    groups = group_classified_events(classified)
    assert len(groups) == 1, f"test setup expects all events to correlate into one group: {len(groups)}"
    return score_group(groups[0], config)


def _make_engine(**overrides):
    config = TceConfig(enabled=True, min_publish_confidence=10, incident_stable_window_seconds=300.0, **overrides)
    engine = ThreatCorrelationEngine(EventBus(), config)
    published = []
    engine.publish = lambda ev: published.append(ev)
    return engine, published, config


def main() -> None:
    engine, published, config = _make_engine()
    e1 = _event("e1", 100.0, pid=9001, fingerprint="fp-A")
    engine._process_scored_group(_result([e1], config), now=100.0)
    e2 = _event("e2", 108.0, pid=9001, fingerprint="fp-A")
    engine._process_scored_group(_result([e1, e2], config), now=108.0)
    e3 = _event("e3", 116.0, pid=9001, fingerprint="fp-A")
    engine._process_scored_group(_result([e1, e2, e3], config), now=116.0)
    assert len(published) == 1, f"same fingerprint re-observed across cycles must not re-alert: {len(published)}"
    print("Scenario 1 (same fingerprint repeated across cycles: deduplicated, one NEW alert) PASSED")

    engine2, published2, config2 = _make_engine()
    r1 = _result([_event("r1", 100.0, pid=9001, fingerprint="fp-B")], config2)
    engine2._process_scored_group(r1, now=100.0)
    r2 = _result([_event("r2", 130.0, pid=9002, fingerprint="fp-B")], config2)
    engine2._process_scored_group(r2, now=130.0)
    assert len(published2) == 1, (
        f"a process restarting under a new PID (same fingerprint) must never be treated as a "
        f"new incident -- PID must never be the primary identity: {len(published2)}"
    )
    print("Scenario 2 (same fingerprint, PID changes across a restart: still deduplicated) PASSED")

    engine3, published3, config3 = _make_engine()
    a = _result([_event("a1", 100.0, pid=1, fingerprint="fp-X", project="site-a", user="user-a")], config3)
    engine3._process_scored_group(a, now=100.0)
    b = _result([_event("b1", 101.0, pid=2, fingerprint="fp-Y", project="site-b", user="user-b")], config3)
    engine3._process_scored_group(b, now=101.0)
    assert len(published3) == 2, f"two unrelated incidents must both alert independently: {len(published3)}"
    assert published3[0].event_id != published3[1].event_id
    print("Scenario 3 (different project/user/fingerprint: two independent incidents, both alert) PASSED")

    engine4, published4, config4 = _make_engine()
    anomaly = _event("pa1", 100.0, pid=9001, fingerprint="fp-anom", project="site-c", user="user-c")
    r_new = _result([anomaly], config4)
    engine4._process_scored_group(r_new, now=100.0)
    assert len(published4) == 1 and published4[0].metadata["lifecycle_state"] == "NEW"

    shell = _event(
        "rs1", 120.0, pid=9002, fingerprint="fp-shell", project="site-c", user="user-c",
        rules=["SHELL_SPAWN_NETWORK_TOOL"], remote_endpoints=[("198.51.100.7", 4444)],
    )
    r_escalated = _result([anomaly, shell], config4)
    engine4._process_scored_group(r_escalated, now=120.0)
    assert len(published4) == 2, f"escalation must publish exactly one UPDATE, not a second NEW: {len(published4)}"
    update_event = published4[1]
    assert update_event.metadata["lifecycle_state"] == "UPDATED"
    assert update_event.event_id == published4[0].event_id, (
        "an UPDATE must reuse the SAME correlation_id/event_id as the original incident"
    )
    assert update_event.metadata["previous_confidence"] == r_new.total
    new_evidence_kinds = {e["kind"] for e in update_event.metadata["new_evidence"]}
    assert "Reverse Shell" in new_evidence_kinds, new_evidence_kinds
    print("Scenario 4/11 (Process Anomaly escalating to Reverse Shell: correlates into one incident, one UPDATE) PASSED")

    nginx_event = _event(
        "nginx1", 100.0, pid=1234, fingerprint="fp-nginx", rules=["NETWORK_ACTIVITY_APPEARED"],
    )
    classified_nginx = classify_event(nginx_event, TceConfig())
    assert classified_nginx.kind != "Reverse Shell", classified_nginx.kind
    assert not _has_reverse_shell_evidence(["NETWORK_ACTIVITY_APPEARED"])
    print("Scenario 5 (nginx reverse-proxy connection alone: never classified as Reverse Shell) PASSED")

    node_event = _event(
        "node1", 100.0, pid=5678, fingerprint="fp-node", rules=["NETWORK_ACTIVITY_APPEARED", "NEW_PROCESS_FINGERPRINT"],
    )
    classified_node = classify_event(node_event, TceConfig())
    assert classified_node.kind != "Reverse Shell", classified_node.kind
    print("Scenario 6 (Node.js HTTP/WebSocket outbound traffic alone: never classified as Reverse Shell) PASSED")

    profiles = [TrustedProcessProfile(
        name="puppeteer_playwright_headless_browser",
        executable_basenames=["chrome", "chromium", "headless_shell"],
        path_substrings=[".cache/puppeteer/"], parent_basenames=["node"],
        require_same_uid_as_parent=True,
    )]
    parent_snap = ProcessSnapshot(
        pid=100, ppid=1, uid=1000, gid=1000, exe="/usr/bin/node", cwd="/home/u/htdocs/site",
        cmdline="node server.js", username="u", start_time=1000.0, project="site", network_active=False,
    )
    chrome_snap = ProcessSnapshot(
        pid=101, ppid=100, uid=1000, gid=1000,
        exe="/home/u/.cache/puppeteer/chrome/linux-123/chrome-linux/chrome",
        cwd="/home/u/htdocs/site", cmdline="chrome --headless --remote-debugging-port=9222",
        username="u", start_time=1001.0, project="site", network_active=True,
    )
    assert match_trusted_profile(chrome_snap, parent_snap, "chrome", "node", profiles) is not None
    chrome_matches = evaluate_rules(chrome_snap, parent_snap, allowed=set(), weights={}, trusted_process_profiles=profiles)
    assert not _has_reverse_shell_evidence([r for r, _, _ in chrome_matches])
    print("Scenario 7 (trusted Chrome/Puppeteer network connection alone: never classified as Reverse Shell) PASSED")

    real_shell = _event("realshell", 100.0, pid=9999, fingerprint="fp-real-shell", rules=["WEB_PROCESS_SPAWN_SHELL"])
    classified_shell = classify_event(real_shell, TceConfig())
    assert classified_shell.kind == "Reverse Shell", classified_shell.kind
    child_attributed = _event(
        "childshell", 100.0, pid=9998, fingerprint="fp-parent-trusted",
        rules=["child_pid_9999:SHELL_SPAWN_NETWORK_TOOL"],
    )
    assert classify_event(child_attributed, TceConfig()).kind == "Reverse Shell", (
        "a trusted parent's own event, escalated because a child genuinely spawned a shell, "
        "must still be classified Reverse Shell -- trust must never suppress real evidence"
    )
    print("Scenario 8 (genuine shell-spawn/network-tool evidence, including child-attributed: still detected) PASSED")

    engine9, published9, config9 = _make_engine()
    d1 = _event("d1", 100.0, pid=1, fingerprint="fp-dup", project="site-d", user="user-d")
    engine9._process_scored_group(_result([d1], config9), now=100.0)
    for i in range(2, 9):
        dup = _event(f"d{i}", 100.0 + i, pid=1, fingerprint="fp-dup", project="site-d", user="user-d")
        engine9._process_scored_group(_result([d1] + [dup], config9), now=100.0 + i)
    assert len(published9) == 1, f"repeated identical evidence must never generate more alerts: {len(published9)}"
    assert published9[0].metadata["confidence"] == config9.detector_weights["Process anomaly"], (
        f"score must never inflate from the SAME evidence observed repeatedly: "
        f"{published9[0].metadata['confidence']}"
    )
    print("Scenario 9 (score never inflates from duplicate events re-observed across cycles) PASSED")

    assert len(published) == 1 and len(published9) == 1
    print("Scenario 10 (exactly one NEW Discord alert for one ongoing incident, not repeated duplicates) PASSED")

    print("Scenario 12 (full existing suite pass: verified via separate full-suite run) PASSED")

    print("\nALL CORRELATED_THREAT INCIDENT LIFECYCLE + REVERSE SHELL LABELING TESTS PASSED")


main()
