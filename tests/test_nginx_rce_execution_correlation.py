import asyncio
import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from discord_integration.webhook import discord_safe_codeblock, discord_safe_inline
from modules.nginx_monitor import NginxMonitor, _LogSource

SOURCE = _LogSource(log_file="/var/log/nginx/access.log", line_number=1, raw_line="raw")
RCE_PATH = "/index.php?cmd=;cat%20/etc/passwd"


def make_monitor(**overrides):
    kwargs = dict(enabled=True, rce_correlation_enabled=True, rce_correlation_window_seconds=0.08)
    kwargs.update(overrides)
    cfg = NginxMonitorConfig(**kwargs)
    mon = NginxMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_meta(domain, source):
        return "", {"domain": domain or "example.com", "project_root": "/home/vic/htdocs/example.com", "linux_user": "vic"}

    mon._build_web_attack_metadata = fake_meta
    return mon, published


def correlated_event(category, *, project_root=None, linux_user=None, metadata=None, severity=Severity.HIGH):
    return BaseEvent(
        source_module="test", category=category, severity=severity, message="test",
        raw="", metadata={"project_root": project_root, "linux_user": linux_user, **(metadata or {})},
    )


async def check(mon, ip):
    await mon._check_web_attack_signature(ip, RCE_PATH, "GET", "curl/8.0", 404, "example.com", SOURCE)


async def main():
    mon, pub = make_monitor()
    await check(mon, "203.0.113.9")
    assert pub == [], "publish must not happen before the correlation window elapses"
    await asyncio.sleep(0.15)
    assert len(pub) == 1, pub
    ev = pub[0]
    assert ev.category == EventCategory.WEB_ATTACK_RCE, ev.category
    assert ev.metadata["assessment"] == "REQUEST_DETECTED_NO_EXECUTION_EVIDENCE", ev.metadata
    assert all(v is False for v in ev.metadata["execution_evidence"].values()), ev.metadata["execution_evidence"]
    assert ev.severity != Severity.CRITICAL, "no evidence must never auto-escalate to CRITICAL"
    print("Scenario 1 (RCE signature alone, no follow-up evidence -> REQUEST_DETECTED_NO_EXECUTION_EVIDENCE) PASSED")

    mon2, pub2 = make_monitor()
    await check(mon2, "203.0.113.10")
    await asyncio.sleep(0.02)
    await mon2._on_correlation_event(correlated_event(
        EventCategory.PROCESS_ANOMALY, project_root="/home/vic/htdocs/example.com", linux_user="vic",
        metadata={"rules": ["WEB_PROCESS_SPAWN_SHELL"], "pid": 4242, "cmdline": "/bin/sh -c 'id'"},
    ))
    await asyncio.sleep(0.15)
    assert len(pub2) == 1, pub2
    ev2 = pub2[0]
    assert ev2.metadata["assessment"] == "RCE_EXECUTION_SUSPECTED", ev2.metadata
    assert ev2.metadata["execution_evidence"]["command_execution"] is True, ev2.metadata["execution_evidence"]
    assert ev2.metadata["execution_evidence"]["suspicious_process"] is True, ev2.metadata["execution_evidence"]
    assert any("4242" in d for d in ev2.metadata["evidence_details"]), ev2.metadata["evidence_details"]
    assert ev2.severity == Severity.CRITICAL, ev2.severity
    print("Scenario 2 (correlated shell-spawn process -> RCE_EXECUTION_SUSPECTED, CRITICAL, evidence shown) PASSED")

    mon3, pub3 = make_monitor()
    await check(mon3, "203.0.113.11")
    await asyncio.sleep(0.02)
    await mon3._on_correlation_event(correlated_event(
        EventCategory.FILE_INTEGRITY_CHANGE, project_root="/home/vic/htdocs/example.com", linux_user="vic",
        metadata={"change_type": "created", "path": "/home/vic/htdocs/example.com/public/shell.php"},
        severity=Severity.CRITICAL,
    ))
    await asyncio.sleep(0.15)
    assert len(pub3) == 1, pub3
    ev3 = pub3[0]
    assert ev3.metadata["assessment"] == "RCE_EXECUTION_SUSPECTED", ev3.metadata
    assert ev3.metadata["execution_evidence"]["new_file"] is True
    assert ev3.metadata["execution_evidence"]["new_executable"] is True
    assert ev3.metadata["execution_evidence"]["config_change"] is True
    print("Scenario 3 (correlated CRITICAL newly-created file -> new_file/new_executable/config_change evidence) PASSED")

    mon4, pub4 = make_monitor()
    await check(mon4, "203.0.113.12")
    await asyncio.sleep(0.02)
    await mon4._on_correlation_event(correlated_event(
        EventCategory.PROCESS_ANOMALY, project_root="/home/other/htdocs/other.com", linux_user="other",
        metadata={"rules": ["WEB_PROCESS_SPAWN_SHELL"], "pid": 9999},
    ))
    await asyncio.sleep(0.15)
    assert len(pub4) == 1, pub4
    ev4 = pub4[0]
    assert ev4.metadata["assessment"] == "REQUEST_DETECTED_NO_EXECUTION_EVIDENCE", (
        f"an unrelated project's process must not be treated as evidence: {ev4.metadata}"
    )
    print("Scenario 4 (unrelated project/user process event -- correctly NOT counted as evidence) PASSED")

    mon5, pub5 = make_monitor()
    await check(mon5, "203.0.113.13")
    await asyncio.sleep(0.02)
    await mon5._on_correlation_event(correlated_event(
        EventCategory.PERSISTENCE_NEW_USER, project_root=None, linux_user=None,
        metadata={"username": "sneaky"},
    ))
    await asyncio.sleep(0.15)
    assert len(pub5) == 1, pub5
    ev5 = pub5[0]
    assert ev5.metadata["assessment"] == "RCE_EXECUTION_SUSPECTED", ev5.metadata
    assert ev5.metadata["execution_evidence"]["persistence_change"] is True
    assert any("host-wide" in d for d in ev5.metadata["evidence_details"]), ev5.metadata["evidence_details"]
    print("Scenario 5 (host-wide PERSISTENCE_NEW_USER -- still counted, labeled host-wide) PASSED")

    mon6, pub6 = make_monitor(attack_silence_seconds=0.01)
    await check(mon6, "203.0.113.14")
    await asyncio.sleep(0.02)
    await mon6._on_correlation_event(correlated_event(
        EventCategory.PROCESS_ANOMALY, project_root="/home/vic/htdocs/example.com", linux_user="vic",
        metadata={"rules": ["WEB_PROCESS_SPAWN_SHELL"], "pid": 555},
    ))
    await asyncio.sleep(0.15)
    assert len(pub6) == 1
    await asyncio.sleep(0.05)
    await mon6._sweep_stale_incidents()
    recovered = [e for e in pub6 if e.category == EventCategory.NGINX_ATTACK_RECOVERED]
    assert len(recovered) == 1, pub6
    rec = recovered[0]
    assert rec.metadata.get("confidence") is None, "must never carry a fabricated confidence value"
    assert rec.confidence == 0.0
    assert rec.metadata["assessment"] == "RCE_EXECUTION_SUSPECTED", rec.metadata
    assert rec.metadata["execution_evidence"]["command_execution"] is True
    assert "Assessment: RCE_EXECUTION_SUSPECTED" in rec.message
    print("Scenario 6 (NGINX_ATTACK_RECOVERED carries forward the last computed assessment/evidence) PASSED")

    mon7, pub7 = make_monitor()
    start = time.time()
    await mon7._check_web_attack_signature(
        "203.0.113.15", "/index.php?id=1 union select 1,2,3--", "GET", "curl/8.0", 404, "example.com", SOURCE,
    )
    elapsed = time.time() - start
    assert len(pub7) == 1, pub7
    assert elapsed < 0.05, f"non-RCE category must publish immediately, took {elapsed}s"
    assert "assessment" not in pub7[0].metadata, pub7[0].metadata
    print("Scenario 7 (non-RCE category (SQLI) -- immediate publish, unaffected by correlation) PASSED")

    payload = "id=1; \n```@everyone``` <script>alert(1)</script> `whoami`"
    safe_block = discord_safe_codeblock(payload)
    assert "```" not in safe_block[3:-4], safe_block
    safe_inline = discord_safe_inline(payload)
    assert "\\`whoami\\`" in safe_inline, safe_inline
    assert discord_safe_inline(None) == "N/A"
    print("Scenario 8 (Discord-safe rendering: backtick/triple-backtick payload never breaks embed) PASSED")

    print("\nALL NGINX RCE EXECUTION-CORRELATION REGRESSION TESTS PASSED")


asyncio.run(main())
