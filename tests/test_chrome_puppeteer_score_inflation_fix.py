import asyncio
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import ProcessAnomalyDetectorConfig
from core.event_bus import EventBus
import modules.process_anomaly_detector as pad_mod
from modules.process_anomaly_detector import ProcessAnomalyDetector, ProcessSnapshot


class FakeProcTable:
    def __init__(self):
        self.snapshots = {}

    def add(self, pid, ppid, uid, exe, cwd, cmdline, username="newus"):
        now = time.time()
        self.snapshots[pid] = ProcessSnapshot(
            pid=pid, ppid=ppid, uid=uid, gid=uid, exe=exe, cwd=cwd, cmdline=cmdline,
            username=username, start_time=now, project=None, network_active=False,
            start_time_ticks=pid * 10,
        )

    def list_pids(self):
        return set(self.snapshots.keys())

    def read_process_snapshot(self, pid):
        return self.snapshots.get(pid)

    def read_starttime_ticks(self, pid):
        snap = self.snapshots.get(pid)
        return snap.start_time_ticks if snap else None


def install(table):
    pad_mod.list_pids = table.list_pids
    pad_mod.read_process_snapshot = table.read_process_snapshot
    pad_mod.read_starttime_ticks = table.read_starttime_ticks


async def main():
    real = (pad_mod.list_pids, pad_mod.read_process_snapshot, pad_mod.read_starttime_ticks)
    try:
        await run_scenarios()
    finally:
        pad_mod.list_pids, pad_mod.read_process_snapshot, pad_mod.read_starttime_ticks = real


async def run_scenarios():
    d = tempfile.mkdtemp()
    cfg = ProcessAnomalyDetectorConfig(
        enabled=True, learning_mode=False, tier_publish_threshold=30, tier_discord_threshold=80,
        baseline_state_path=os.path.join(d, "pad.json"),
        fingerprint_baseline_state_path=os.path.join(d, "fp.json"),
    )
    bus = EventBus()
    events = []

    async def collector(e):
        events.append(e)

    sub = await bus.subscribe("c", collector, categories=None)
    mon = ProcessAnomalyDetector(bus, cfg)
    mon._learning_started_at = time.time()

    table = FakeProcTable()
    install(table)

    table.add(500, ppid=1, uid=1000, exe="/usr/bin/node", cwd="/home/newus/project",
               cmdline="node server.js", username="newus")
    await mon._scan_cycle()
    await sub.queue.join()
    assert events == [], "initial baseline must stay silent"
    events.clear()

    chrome_exe = "/home/newus/.cache/puppeteer/chrome/linux-121.0.6167.85/chrome-linux64/chrome"
    table.add(600, ppid=500, uid=1000, exe=chrome_exe, cwd="/home/newus/project",
               cmdline=f"{chrome_exe} --headless --disable-gpu --no-sandbox "
                        "--user-data-dir=/tmp/puppeteer_dev_chrome_profile-abc123",
               username="newus")
    for i, pid in enumerate([601, 602, 603, 604, 605, 606]):
        table.add(pid, ppid=600, uid=1000, exe=chrome_exe, cwd="/home/newus/project",
                   cmdline=f"{chrome_exe} --type=renderer --field-trial-handle={pid},r{i},flags",
                   username="newus")
    await mon._scan_cycle()
    await sub.queue.join()
    assert events == [], (
        f"a fully-trusted Puppeteer/Chrome tree (1 parent + 6 children) must not alert at all, "
        f"got {[(e.metadata.get('pid'), e.metadata.get('rules')) for e in events]}"
    )
    print("Scenario 1 (trusted Chrome parent + 6 volatile-cmdline children -- zero alerts) PASSED")
    events.clear()

    table.add(700, ppid=1, uid=1000, exe="/home/newus/.hidden/evil", cwd="/home/newus/project",
               cmdline="/home/newus/.hidden/evil --serve", username="newus")
    for i, pid in enumerate([701, 702, 703, 704, 705, 706]):
        table.add(pid, ppid=700, uid=1000, exe="/home/newus/.hidden/evil", cwd="/home/newus/project",
                   cmdline=f"/home/newus/.hidden/evil --worker={i}", username="newus")
    await mon._scan_cycle()
    await sub.queue.join()
    parent_events = [e for e in events if e.metadata.get("pid") == 700]
    assert len(parent_events) >= 1, "a genuinely escalating untrusted tree must still alert"
    assert len(parent_events) <= 3, (
        f"parent republish must be capped at 3 (one per severity tier), got {len(parent_events)}"
    )
    severities = [e.severity.value for e in parent_events]
    assert len(severities) == len(set(severities)), (
        f"parent must never be republished twice at the SAME severity tier: {severities}"
    )
    assert parent_events[-1].metadata["confidence"] == 90, parent_events[-1].metadata
    print(
        f"Scenario 2 (untrusted parent + 6 children -- {len(parent_events)} republish(es) "
        f"across tiers {severities}, capped and deduped, not one per child) PASSED"
    )

    events.clear()

    for old_pid in (600, 601, 602, 603, 604, 605, 606, 700, 701, 702, 703, 704, 705, 706):
        table.snapshots.pop(old_pid, None)
    await mon._scan_cycle()
    await sub.queue.join()
    events.clear()

    chrome_exe2 = "/home/newus/.cache/puppeteer/chrome/linux-121.0.6167.85/chrome-linux64/chrome"
    table.add(700, ppid=500, uid=1000, exe=chrome_exe2, cwd="/home/newus/project",
               cmdline=f"{chrome_exe2} --headless --disable-gpu --no-sandbox "
                        "--user-data-dir=/tmp/puppeteer_dev_chrome_profile-restart999",
               username="newus")
    table.add(701, ppid=700, uid=1000, exe=chrome_exe2, cwd="/home/newus/project",
               cmdline=f"{chrome_exe2} --type=renderer --field-trial-handle=999,r9,newflags",
               username="newus")
    await mon._scan_cycle()
    await sub.queue.join()
    assert events == [], (
        f"trusted Chrome reusing a formerly-untrusted-process's PID after restart, with a "
        f"brand-new fingerprint, must still be zero alerts -- trust bypass must not depend on "
        f"PID continuity, got {[(e.metadata.get('pid'), e.metadata.get('rules')) for e in events]}"
    )
    print("Scenario 3 (Chrome restart + PID reuse + fingerprint baru pada trusted profile -- tetap zero alert) PASSED")

    print("\nALL CHROME/PUPPETEER SCORE-INFLATION FIX REGRESSION TESTS PASSED")


asyncio.run(main())
