import asyncio
import os
import sys
from types import SimpleNamespace

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import ProcessAnomalyDetectorConfig
from core.datatypes import EventCategory
from core.event_bus import EventBus
from core.project_registry import build_project_registry
import modules.process_anomaly_detector as pad
from modules.process_anomaly_detector import (
    ProcessAnomalyDetector, ProcessSnapshot, detect_cross_project_reference, evaluate_rules,
)


class _FakeSelfHealth:
    def should_run(self, capability: str) -> bool:
        return False


def snap(pid, cmdline, project, uid=1000, exe="/usr/bin/cat"):
    return ProcessSnapshot(
        pid=pid, ppid=1, uid=uid, gid=uid, exe=exe, cwd=f"/home/{project}/htdocs/site" if project else None,
        cmdline=cmdline, username=project, start_time=0.0, project=project, network_active=False,
        start_time_ticks=1000 + pid,
    )


def make_detector(**overrides):
    cfg = ProcessAnomalyDetectorConfig(enabled=True, learning_mode=False, **overrides)
    det = ProcessAnomalyDetector(EventBus(), cfg)
    published = []
    det.publish = lambda ev: published.append(ev)
    return det, published


def cross_project_events(published):
    return [e for e in published if e.category == EventCategory.CROSS_PROJECT_PROCESS]


def _snapshot(**overrides):
    base = dict(
        domain="site-a.com", linux_user="newus", project_path="/home/newus/htdocs/site-a.com",
        document_root="/home/newus/htdocs/site-a.com/dist", nginx_vhost="site-a.com.conf",
        website_type="Node.js", runtime="node", php_version=None, node_version="20", python_version=None,
        port="3000", pm2_process_name="site-a", project_status="RUNNING", reverse_proxy="127.0.0.1:3000",
        ssl_enabled=True,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


async def main():
    pad.get_self_health_monitor = lambda: _FakeSelfHealth()
    loop = asyncio.get_running_loop()

    def rule_snap(exe, uid, cwd=None, cmdline="x"):
        return ProcessSnapshot(
            pid=1, ppid=1, uid=uid, gid=uid, exe=exe, cwd=cwd, cmdline=cmdline,
            username=str(uid), start_time=0.0, project=None, network_active=False,
        )

    weights = {"WEB_RUNTIME_PRIVILEGE_ESCALATION": 90}
    results = evaluate_rules(rule_snap("/bin/sh", 0), rule_snap("/usr/bin/node", 1000), set(), weights)
    assert "WEB_RUNTIME_PRIVILEGE_ESCALATION" in [r for r, _, _ in results]
    print("Test 1 (web runtime spawning a root child triggers WEB_RUNTIME_PRIVILEGE_ESCALATION) PASSED")

    results2 = evaluate_rules(rule_snap("/usr/bin/otherapp", 1002), rule_snap("/usr/bin/someapp", 1001), set(), weights)
    assert "WEB_RUNTIME_PRIVILEGE_ESCALATION" not in [r for r, _, _ in results2]
    print("Test 2 (ordinary non-web, non-root uid switch does not trigger it) PASSED")

    results3 = evaluate_rules(rule_snap("/bin/sh", 0), rule_snap("/usr/bin/node", 0), set(), weights)
    assert "WEB_RUNTIME_PRIVILEGE_ESCALATION" not in [r for r, _, _ in results3]
    print("Test 3 (web parent already root -> no escalation flagged) PASSED")

    ignore = set(ProcessAnomalyDetectorConfig().cross_project_ignore_users)
    assert detect_cross_project_reference(snap(1, "cat /home/newus-other/.env", "newus"), ignore) == "newus-other"
    assert detect_cross_project_reference(snap(2, "cat /home/newus/htdocs/site/f.txt", "newus"), ignore) is None
    assert detect_cross_project_reference(snap(3, "cat /home/newus-other/.env", "newus", uid=0), ignore) is None
    assert detect_cross_project_reference(snap(4, "cat /home/cloudpanel/logs.txt", "newus"), ignore) is None
    assert detect_cross_project_reference(snap(5, "cat /home/newus/.env", "cloudpanel"), ignore) is None
    assert detect_cross_project_reference(snap(6, "", "newus"), ignore) is None
    assert detect_cross_project_reference(snap(7, "cat /home/newus-other/.env", None), ignore) is None
    print("Test 4 (detect_cross_project_reference: foreign ref, own ref, root, ignore-list, missing data) PASSED")

    det, pub = make_detector()
    pad.list_pids = lambda: {3001}
    pad.read_starttime_ticks = lambda pid: 1000 + pid
    pad.read_process_snapshot = lambda pid: snap(pid, "cat /home/newus-other/.env", "newus")
    await det._scan_cycle()
    events = cross_project_events(pub)
    assert len(events) == 1, events
    assert events[0].metadata["own_project"] == "newus"
    assert events[0].metadata["referenced_project"] == "newus-other"
    print("Test 5 (cross-project alert published end-to-end via _scan_cycle) PASSED")

    await det._scan_cycle()
    assert len(cross_project_events(pub)) == 1, "must not duplicate the alert for the same still-running process"
    print("Test 6 (no duplicate alert across repeated cycles) PASSED")

    det2, pub2 = make_detector()
    pad.list_pids = lambda: {3002}
    pad.read_starttime_ticks = lambda pid: 1000 + pid
    pad.read_process_snapshot = lambda pid: snap(pid, "cat /home/newus/htdocs/site/a.txt", "newus")
    await det2._scan_cycle()
    assert cross_project_events(pub2) == []
    print("Test 7 (own-project file reference -- no alert) PASSED")

    det3, pub3 = make_detector()
    pad.list_pids = lambda: {3003}
    pad.read_starttime_ticks = lambda pid: 1000 + pid
    pad.read_process_snapshot = lambda pid: snap(pid, "cat /home/newus-other/.env", "newus", uid=0)
    await det3._scan_cycle()
    assert cross_project_events(pub3) == []
    print("Test 8 (root uid excluded from cross-project detection) PASSED")

    det4, pub4 = make_detector(cross_project_ignore_users=["cloudpanel", "clp", "backupuser"])
    pad.list_pids = lambda: {3004}
    pad.read_starttime_ticks = lambda pid: 1000 + pid
    pad.read_process_snapshot = lambda pid: snap(pid, "cat /home/backupuser/dumps/db.sql", "newus")
    await det4._scan_cycle()
    assert cross_project_events(pub4) == []
    print("Test 9 (operator-configured cross_project_ignore_users entry is honored) PASSED")

    det5, pub5 = make_detector()
    registry = build_project_registry([
        _snapshot(domain="site-a.com", linux_user="newus"),
        _snapshot(domain="evil-target.com", linux_user="newus-other", website_type="PHP", runtime="php"),
    ])
    det5.attach_project_registry_source(lambda: registry)
    pad.list_pids = lambda: {3005}
    pad.read_starttime_ticks = lambda pid: 1000 + pid
    pad.read_process_snapshot = lambda pid: snap(pid, "cat /home/newus-other/.env", "newus")
    await det5._scan_cycle()
    events5 = cross_project_events(pub5)
    assert len(events5) == 1
    assert events5[0].metadata.get("own_domain") == "site-a.com"
    assert events5[0].metadata.get("referenced_domain") == "evil-target.com"
    print("Test 10 (attach_project_registry_source enriches the alert with domain names) PASSED")

    det6, pub6 = make_detector()
    pad.list_pids = lambda: {3006}
    pad.read_starttime_ticks = lambda pid: 1000 + pid
    pad.read_process_snapshot = lambda pid: snap(pid, "cat /home/newus-other/.env", "newus")
    await det6._scan_cycle()
    events6 = cross_project_events(pub6)
    assert len(events6) == 1
    assert "own_domain" not in events6[0].metadata
    print("Test 11 (no registry attached -> alert still fires without domain enrichment) PASSED")

    print("\nALL CROSS-PROJECT + PRIVILEGE ESCALATION REGRESSION TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(), timeout=60))
