import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from modules.nginx_monitor import NginxMonitor, _LogSource, _SuccessEvidence

CONFIRMED_BREACH_CATEGORY = EventCategory.WEB_ATTACK_SUCCESS
SOURCE = _LogSource(log_file="/var/log/nginx/access.log", line_number=1, raw_line='1.2.3.4 - - "GET /.env" 200')


def make_monitor(alert_unverified=True):
    cfg = NginxMonitorConfig(
        enabled=True, alert_unverified_web_hit_200=alert_unverified, rce_correlation_enabled=False,
    )
    mon = NginxMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)
    async def fake_meta(domain, source):
        return "", {"domain": domain or "example.com"}
    mon._build_web_attack_metadata = fake_meta
    return mon, published


def set_verdict(mon, verdict, evidence=None, content_type=None):
    async def fake_classify(domain, path):
        return verdict, evidence, content_type
    mon._classify_response = fake_classify


PASSWD_EVIDENCE = _SuccessEvidence(
    evidence_type="PASSWD_FILE_DISCLOSURE",
    indicators=["baris root format /etc/passwd (root:x:0:0:)"],
    score=2, verification_status=200, verification_response_size=1024,
)


async def run_hit(mon, *, ip="9.9.9.9", path="/.env", category=EventCategory.WEB_ATTACK_LFI, status=200):
    await mon._verify_and_publish_hit_impl(
        ip, path, "GET", status, "example.com", category, 0.9, SOURCE,
    )


async def main():
    mon, pub = make_monitor()
    set_verdict(mon, "confirmed", PASSWD_EVIDENCE)
    await run_hit(mon)
    assert len(pub) == 1, pub
    assert pub[0].category == CONFIRMED_BREACH_CATEGORY, pub[0].category
    assert pub[0].severity == Severity.CRITICAL, pub[0].severity
    assert pub[0].metadata["classification"] == "CONFIRMED_SUCCESS", pub[0].metadata
    assert pub[0].metadata["success"] is True
    assert pub[0].metadata["evidence_type"] == "PASSWD_FILE_DISCLOSURE"
    assert "CONFIRMED_SUCCESS" in pub[0].message
    print("Scenario 1 (200 + content evidence -> CONFIRMED_SUCCESS / WEB_ATTACK_SUCCESS / CRITICAL) PASSED")

    mon, pub = make_monitor()
    set_verdict(mon, "false_positive")
    await run_hit(mon)
    assert len(pub) == 1, "an unverified 200 must still be published, not dropped"
    ev = pub[0]
    assert ev.category == EventCategory.WEB_ATTACK_LFI, ev.category
    assert ev.category != CONFIRMED_BREACH_CATEGORY, "no evidence must never reach #confirmed-breach"
    assert ev.severity == Severity.MEDIUM, ev.severity
    assert ev.metadata["classification"] == "SUSPICIOUS", ev.metadata
    assert ev.metadata["success"] is False
    assert ev.metadata["evidence_type"] is None
    assert ev.metadata.get("needs_manual_review") is True, ev.metadata
    assert ev.metadata.get("unverified_hit") is True, ev.metadata
    assert ev.metadata.get("verification_verdict") == "false_positive", ev.metadata
    assert "cek manual" in ev.message.lower(), ev.message
    assert ev.status_code == 200
    print("Scenario 2 (200 without evidence -> SUSPICIOUS on its own category, NOT confirmed-breach) PASSED")

    mon, pub = make_monitor()
    set_verdict(mon, "fetch_failed")
    await run_hit(mon)
    assert len(pub) == 1 and pub[0].category == EventCategory.WEB_ATTACK_LFI, pub
    assert pub[0].metadata["classification"] == "SUSPICIOUS"
    assert pub[0].metadata.get("verification_verdict") == "fetch_failed"
    print("Scenario 3 (fetch_failed 200 -> SUSPICIOUS, not suppressed, not confirmed) PASSED")

    mon, pub = make_monitor(alert_unverified=False)
    set_verdict(mon, "false_positive")
    await run_hit(mon)
    assert pub == [], "with alert_unverified_web_hit_200=false, a benign 200 is suppressed as before"
    mon2, pub2 = make_monitor(alert_unverified=False)
    set_verdict(mon2, "confirmed", PASSWD_EVIDENCE)
    await run_hit(mon2)
    assert len(pub2) == 1 and pub2[0].severity == Severity.CRITICAL
    print("Scenario 4 (toggle off -> benign 200 suppressed again; confirmed hit always delivered) PASSED")

    mon, pub = make_monitor()
    set_verdict(mon, "false_positive")
    for _ in range(5):
        await run_hit(mon, ip="7.7.7.7", path="/wp-config.php", category=EventCategory.WEB_ATTACK_LFI)
    assert len(pub) == 1, f"5 identical benign 200s must collapse to 1 alert, got {len(pub)}"
    print("Scenario 5 (repeated benign 200s deduped -> single alert, channel not flooded) PASSED")

    from discord_integration.webhook import _INCIDENT_ELIGIBLE_CATEGORIES
    assert EventCategory.WEB_ATTACK_SUCCESS in _INCIDENT_ELIGIBLE_CATEGORIES, (
        "WEB_ATTACK_SUCCESS must bypass the severity floor or the INFO 'cek manual' alerts "
        "would be dropped before delivery"
    )
    print("Scenario 6 (WEB_ATTACK_SUCCESS bypasses the MEDIUM floor -> INFO alerts still delivered) PASSED")

    print("\nALL WEB_ATTACK_SUCCESS ROUTING TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
