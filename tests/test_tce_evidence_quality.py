import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import TceConfig
from modules.threat_correlation_engine import (
    CorrelationCandidateEvent, classify_event, group_classified_events, score_group, build_message,
)


async def main():
    tce_config = TceConfig()

    chrome_listener = CorrelationCandidateEvent(
        event_id="rad-1", timestamp=100.0, category="REMOTE_ACCESS_BACKDOOR", severity="INFO",
        message="Listener terverifikasi milik deployment yang dikenal", source_module="remote_access_detector",
        user="deploy", pid=4242, executable="/usr/bin/chrome", process_fingerprint="fp-chrome-abc",
        confidence=5,
    )
    health_noise = CorrelationCandidateEvent(
        event_id="health-1", timestamp=101.0, category="HEALTH_STATUS", severity="LOW",
        message="cpu ok", source_module="health_monitor", user="deploy",
    )
    classified = [classify_event(e, tce_config) for e in (chrome_listener, health_noise)]
    kinds = {c.kind for c in classified}
    assert kinds == {"Remote listener (managed)", "Health anomaly"}, kinds
    groups = group_classified_events(classified)
    assert len(groups) == 1
    result = score_group(groups[0], tce_config)
    assert result.total == 0, f"a legitimate listener + unrelated noise must score 0: {result.total}"
    assert result.has_high_confidence is False
    assert result.total < tce_config.min_publish_confidence, "must never cross the publish threshold"
    print("Test 1 (legitimate Chrome/Puppeteer listener never produces CORRELATED_THREAT evidence) PASSED")

    unmanaged_listener = CorrelationCandidateEvent(
        event_id="rad-2", timestamp=200.0, category="REMOTE_ACCESS_BACKDOOR", severity="HIGH",
        message="Listener tidak dikelola", source_module="remote_access_detector",
        user="attacker", pid=6666, executable="/tmp/.x/nc", process_fingerprint="fp-nc-evil",
    )
    webshell = CorrelationCandidateEvent(
        event_id="wsh-1", timestamp=201.0, category="FILE_INTEGRITY_CHANGE", severity="CRITICAL",
        message="shell.php created", source_module="webshell_detector", user="attacker",
    )
    classified2 = [classify_event(e, tce_config) for e in (unmanaged_listener, webshell)]
    kinds2 = {c.kind for c in classified2}
    assert kinds2 == {"Remote Access Backdoor", "Webshell Signature"}, kinds2
    result2 = score_group(group_classified_events(classified2)[0], tce_config)
    assert result2.total >= tce_config.min_publish_confidence
    assert result2.has_high_confidence is True
    print("Test 2 (genuine unmanaged listener + webshell still produces strong evidence) PASSED")

    webshell_1 = CorrelationCandidateEvent(
        event_id="wsh-a", timestamp=10.0, category="FILE_INTEGRITY_CHANGE", severity="CRITICAL",
        message="shell.php created", source_module="webshell_detector",
        path="/home/v/htdocs/x/shell.php", user="attacker",
    )
    webshell_1_reminder = CorrelationCandidateEvent(
        event_id="wsh-a-r1", timestamp=40.0, category="FILE_INTEGRITY_CHANGE", severity="CRITICAL",
        message="shell.php still present (reminder)", source_module="webshell_detector",
        path="/home/v/htdocs/x/shell.php", user="attacker",
    )
    webshell_1_reminder2 = CorrelationCandidateEvent(
        event_id="wsh-a-r2", timestamp=70.0, category="FILE_INTEGRITY_CHANGE", severity="CRITICAL",
        message="shell.php still present (reminder)", source_module="webshell_detector",
        path="/home/v/htdocs/x/shell.php", user="attacker",
    )
    classified3 = [classify_event(e, tce_config) for e in (webshell_1, webshell_1_reminder, webshell_1_reminder2)]
    result3 = score_group(group_classified_events(classified3)[0], tce_config)
    assert result3.total == 50, f"3 reminders of the SAME file must count once (weight 50): {result3.total}"
    assert len(result3.contributing) == 1
    print("Test 3 (repeat reminders of the SAME incident don't inflate confidence) PASSED")

    webshell_2 = CorrelationCandidateEvent(
        event_id="wsh-b", timestamp=11.0, category="FILE_INTEGRITY_CHANGE", severity="CRITICAL",
        message="backdoor.php created", source_module="webshell_detector",
        path="/home/v/htdocs/x/backdoor.php", user="attacker",
    )
    classified4 = [classify_event(e, tce_config) for e in (webshell_1, webshell_1_reminder, webshell_2)]
    result4 = score_group(group_classified_events(classified4)[0], tce_config)
    assert result4.total == 100, f"two distinct webshell files (50+50) must both count: {result4.total}"
    assert len(result4.contributing) == 2
    print("Test 4 (distinct targets each still count independently, dedup is target-scoped) PASSED")

    msg = build_message(result3.tier, result3, project="example.com", user="attacker")
    assert "Security Evidence:" in msg
    assert "Other +0" not in msg
    assert "Threat:" in msg
    assert "Confidence: 50%" in msg
    print("Test 5 (message never shows 'Other +0' as evidence, has Threat/Confidence sections) PASSED")

    listener = CorrelationCandidateEvent(
        event_id="rad-x", timestamp=1.0, category="REMOTE_ACCESS_BACKDOOR", severity="HIGH",
        message="Listener tidak dikelola", source_module="remote_access_detector",
        user="attacker", pid=777, executable="/tmp/.hidden/backdoor", process_fingerprint="fp-evil-1",
        port=31337,
    )
    chrome_ctx = CorrelationCandidateEvent(
        event_id="rad-y", timestamp=2.0, category="REMOTE_ACCESS_BACKDOOR", severity="INFO",
        message="Listener terverifikasi (chrome debug port)", source_module="remote_access_detector",
        user="attacker", pid=778, executable="/usr/bin/chrome",
    )
    classified6 = [classify_event(e, tce_config) for e in (listener, chrome_ctx)]
    result6 = score_group(group_classified_events(classified6)[0], tce_config)
    msg6 = build_message(
        result6.tier, result6, user="attacker", process="/tmp/.hidden/backdoor",
        process_fingerprint="fp-evil-1", port=31337,
    )
    assert "Context:" in msg6
    assert "Remote listener (managed)" in msg6.split("Context:", 1)[1].split("Timeline:")[0]
    assert "Remote Access Backdoor" in msg6.split("Security Evidence:", 1)[1].split("Context:")[0]
    assert "Process Fingerprint: fp-evil-1" in msg6
    assert "Port: 31337" in msg6
    print("Test 6 (mixed group: real evidence in Security Evidence, legit listener in Context) PASSED")

    listener_a = CorrelationCandidateEvent(
        event_id="rad-p", timestamp=1.0, category="REMOTE_ACCESS_BACKDOOR", severity="INFO",
        message="chrome listener", source_module="remote_access_detector", user="deploy", pid=1,
    )
    listener_b = CorrelationCandidateEvent(
        event_id="rad-q", timestamp=2.0, category="REMOTE_ACCESS_BACKDOOR", severity="INFO",
        message="node listener", source_module="remote_access_detector", user="deploy", pid=2,
    )
    classified7 = [classify_event(e, tce_config) for e in (listener_a, listener_b)]
    result7 = score_group(group_classified_events(classified7)[0], tce_config)
    assert result7.total == 0
    assert result7.total < tce_config.min_publish_confidence
    print("Test 7 (multiple legitimate listeners alone never cross the publish threshold) PASSED")

    print("\nALL TCE EVIDENCE-QUALITY TESTS PASSED")


asyncio.run(main())
