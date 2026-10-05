import asyncio
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import ProcessAnomalyDetectorConfig
from core.datatypes import EventCategory
from core.event_bus import EventBus
from core.process_fingerprint import compute_fingerprint
import modules.process_anomaly_detector as pad_mod
from modules.process_anomaly_detector import ProcessAnomalyDetector, ProcessSnapshot


class FakeProcTable:
    def __init__(self):
        self.snapshots = {}

    def add(self, pid, ppid, uid, exe, cwd, cmdline, username="newus", start_time=None, start_time_ticks=None):
        now = time.time()
        self.snapshots[pid] = ProcessSnapshot(
            pid=pid, ppid=ppid, uid=uid, gid=uid, exe=exe, cwd=cwd, cmdline=cmdline,
            username=username, start_time=start_time if start_time is not None else now,
            project=None, network_active=False,
            start_time_ticks=start_time_ticks if start_time_ticks is not None else pid * 10,
        )

    def remove(self, pid):
        self.snapshots.pop(pid, None)

    def list_pids(self):
        return set(self.snapshots.keys())

    def read_process_snapshot(self, pid):
        return self.snapshots.get(pid)

    def read_starttime_ticks(self, pid):
        snap = self.snapshots.get(pid)
        return snap.start_time_ticks if snap else None


def install_fake_table(table: FakeProcTable):
    pad_mod.list_pids = table.list_pids
    pad_mod.read_process_snapshot = table.read_process_snapshot
    pad_mod.read_starttime_ticks = table.read_starttime_ticks


async def main():
    real_list_pids = pad_mod.list_pids
    real_read_snapshot = pad_mod.read_process_snapshot
    real_read_ticks = pad_mod.read_starttime_ticks
    try:
        await run_scenarios()
    finally:
        pad_mod.list_pids = real_list_pids
        pad_mod.read_process_snapshot = real_read_snapshot
        pad_mod.read_starttime_ticks = real_read_ticks


async def run_scenarios():
    d = tempfile.mkdtemp()
    cfg = ProcessAnomalyDetectorConfig(
        enabled=True, learning_mode=False, tier_publish_threshold=10,
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
    table.add(100, ppid=1, uid=1000, exe="/usr/bin/customtool", cwd="/home/newus/project", cmdline="customtool --serve")
    install_fake_table(table)

    assert mon._fingerprint_baseline_is_initial is True
    await mon._scan_cycle()
    await sub.queue.join()
    assert events == [], f"initial baseline must publish zero events: {[e.metadata for e in events]}"
    assert mon._fingerprint_baseline_is_initial is False
    assert len(mon._fingerprint_baseline) == 1
    print("Scenario 1 (initial process baseline: zero alerts, baseline populated silently) PASSED")

    table.add(200, ppid=1, uid=1000, exe="/usr/bin/anothertool", cwd="/home/newus/project2", cmdline="anothertool run")
    await mon._scan_cycle()
    await sub.queue.join()
    new_fp_events = [e for e in events if "NEW_PROCESS_FINGERPRINT" in e.metadata.get("rules", [])]
    assert len(new_fp_events) == 1, f"expected exactly one NEW_PROCESS_FINGERPRINT event: {new_fp_events}"
    scenario4_metadata = new_fp_events[0].metadata
    assert scenario4_metadata["pid"] == 200
    assert len(mon._fingerprint_baseline) == 2
    print("Scenario 4 (genuinely new process fingerprint after baseline established -> event) PASSED")
    events.clear()

    table.remove(200)
    table.add(300, ppid=1, uid=1000, exe="/usr/bin/anothertool", cwd="/home/newus/project2", cmdline="anothertool run")
    await mon._scan_cycle()
    await sub.queue.join()
    restart_fp_events = [e for e in events if "NEW_PROCESS_FINGERPRINT" in e.metadata.get("rules", [])]
    assert restart_fp_events == [], f"same fingerprint under a new PID must not re-alert: {restart_fp_events}"
    assert len(mon._fingerprint_baseline) == 2, "restart with an identical fingerprint must not grow the baseline"
    print("Scenario 3 (PID changed but fingerprint identical -- no re-alert, restart-stable) PASSED")
    events.clear()

    table.remove(100)
    table.remove(300)
    await mon._scan_cycle()
    table.add(101, ppid=1, uid=1000, exe="/usr/bin/customtool", cwd="/home/newus/project", cmdline="customtool --serve")
    table.add(301, ppid=1, uid=1000, exe="/usr/bin/anothertool", cwd="/home/newus/project2", cmdline="anothertool run")
    await mon._scan_cycle()
    await sub.queue.join()
    reboot_fp_events = [e for e in events if "NEW_PROCESS_FINGERPRINT" in e.metadata.get("rules", [])]
    assert reboot_fp_events == [], f"reboot with identical fingerprints must not storm: {reboot_fp_events}"
    print("Scenario 14 (simulated reboot, same fingerprints reappear under new PIDs -- no storm) PASSED")

    fp_before_restart = dict(mon._fingerprint_baseline)
    mon2 = ProcessAnomalyDetector(EventBus(), cfg)
    from modules.process_anomaly_detector import load_fingerprint_baseline as _load_fp
    mon2._fingerprint_baseline = _load_fp(cfg.fingerprint_baseline_state_path)
    mon2._fingerprint_baseline_is_initial = not mon2._fingerprint_baseline
    assert len(mon2._fingerprint_baseline) == len(fp_before_restart) == 2
    assert mon2._fingerprint_baseline_is_initial is False, "restart with a non-empty persisted baseline must not re-enter INITIAL_BASELINE"
    print("Scenario 13 (RTSA restart: fresh instance loads persisted baseline from disk) PASSED")

    assert scenario4_metadata["user"] == "newus", scenario4_metadata
    assert scenario4_metadata["exe"] == "/usr/bin/anothertool", scenario4_metadata
    assert scenario4_metadata["cwd"] == "/home/newus/project2", scenario4_metadata
    assert scenario4_metadata["ppid"] == 1, scenario4_metadata
    assert scenario4_metadata["cmdline"] == "anothertool run", scenario4_metadata
    assert "process_fingerprint" in scenario4_metadata and scenario4_metadata["process_fingerprint"], scenario4_metadata
    print("Scenario 18-22 (alert carries project/user/executable/cwd/parent context) PASSED")

    for field_name in (
        "uid", "exe_basename", "parent_fingerprint", "parent_uid",
        "cpu_percent", "memory_percent", "listening_ports",
    ):
        assert field_name in scenario4_metadata, f"{field_name} missing from PROCESS_ANOMALY metadata"
    assert scenario4_metadata["uid"] == 1000, scenario4_metadata
    assert scenario4_metadata["exe_basename"] == "anothertool", scenario4_metadata
    print("Scenario 18-22b (alert juga membawa uid/exe_basename/parent_fingerprint/cpu-mem) PASSED")

    base = dict(
        exe="/usr/bin/node", uid=1000, username="newus", cmdline="node server.js",
        cwd="/home/newus/project", parent_fingerprint=None, parent_exe="/usr/lib/systemd/systemd",
    )
    fp_a = compute_fingerprint(**base)
    fp_a_again = compute_fingerprint(**base)
    assert fp_a.fingerprint == fp_a_again.fingerprint, "identical inputs must produce identical fingerprints"

    fp_diff_path = compute_fingerprint(**{**base, "exe": "/home/attacker/.hidden/node"})
    assert fp_diff_path.fingerprint != fp_a.fingerprint
    assert fp_diff_path.exe_basename == fp_a.exe_basename == "node"
    print("Scenario 5 (same basename 'node', different path -- different fingerprint) PASSED")

    fp_diff_user = compute_fingerprint(**{**base, "uid": 0, "username": "root"})
    assert fp_diff_user.fingerprint != fp_a.fingerprint
    print("Scenario 6 (same binary, different Linux user -- different fingerprint/context) PASSED")

    fp_diff_parent = compute_fingerprint(**{**base, "parent_exe": "/bin/bash", "cwd": "/tmp"})
    assert fp_diff_parent.fingerprint != fp_a.fingerprint
    print("Scenario 7 (same binary, different parent/cwd context -- different fingerprint) PASSED")

    fp_case17_normal = compute_fingerprint(
        exe="/usr/bin/node", uid=1000, username="newus", cmdline="node server.js",
        cwd="/home/newus/project", parent_fingerprint=None, parent_exe="/usr/lib/systemd/systemd",
    )
    fp_case17_suspicious = compute_fingerprint(
        exe="/usr/bin/node", uid=0, username="root", cmdline="node server.js",
        cwd="/tmp", parent_fingerprint=None, parent_exe=None,
    )
    assert fp_case17_normal.fingerprint != fp_case17_suspicious.fingerprint, (
        "CASE 17: same executable but drastically different context (root/tmp/no known parent) "
        "must not be silently trusted as 'the same fingerprint we've always seen'"
    )
    print("Scenario 17 (CASE 17 worked example: context change -> different fingerprint, no bypass) PASSED")

    print("\nALL PROCESS FINGERPRINT BASELINE REGRESSION TESTS PASSED")


asyncio.run(main())
