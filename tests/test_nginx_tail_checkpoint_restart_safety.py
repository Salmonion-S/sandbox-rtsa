import asyncio
import os
import shutil
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig
from core.event_bus import EventBus
from modules.nginx_monitor import (
    NginxMonitor, _TailCheckpoint, _read_text_lines_segment, _resync_to_next_line_boundary,
    _RE_ACCESS,
)

BASE = os.path.join(tempfile.gettempdir(), "rtsa_nginx_tail_checkpoint_test")


def access_line(n, ip="203.0.113.7"):
    return f'{ip} - - [01/Jan/2026:00:00:0{n} +0000] "GET /page{n} HTTP/1.1" 200 100 "-" "curl/8.0"'


def make_monitor(log_path, **overrides):
    cfg = NginxMonitorConfig(
        enabled=True, access_log_path=log_path, auto_discover_vhost_logs=False,
        tail_checkpoint_max_catchup_bytes=overrides.pop("tail_checkpoint_max_catchup_bytes", 20_000_000),
        **overrides,
    )
    return NginxMonitor(EventBus(), cfg)


async def main():
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)

    p1 = os.path.join(BASE, "seg1.log")
    with open(p1, "w") as f:
        f.write(access_line(1) + "\n" + access_line(2) + "\n" + access_line(3) + "\n")
    lines, consumed = _read_text_lines_segment(p1, 0, 1_000_000)
    assert len(lines) == 3, lines
    assert lines[0] == access_line(1) and lines[2] == access_line(3)
    assert consumed == os.path.getsize(p1)
    more_lines, more_consumed = _read_text_lines_segment(p1, consumed, 1_000_000)
    assert more_lines == [] and more_consumed == consumed
    print("Test 1 (_read_text_lines_segment reads exactly the complete lines present) PASSED")

    p2 = os.path.join(BASE, "seg2.log")
    with open(p2, "w") as f:
        f.write(access_line(1) + "\n" + access_line(2) + "\n")
        f.write('203.0.113.9 - - [01/Jan/2026:00:00:09 +0000] "GET /partial')
    lines2, consumed2 = _read_text_lines_segment(p2, 0, 1_000_000)
    assert len(lines2) == 2, lines2
    expected_consumed = len(access_line(1)) + 1 + len(access_line(2)) + 1
    assert consumed2 == expected_consumed, (consumed2, expected_consumed)
    print("Test 2 (a partial trailing line at EOF is never returned or consumed) PASSED")

    p3 = os.path.join(BASE, "seg3.log")
    with open(p3, "w") as f:
        f.write(access_line(1) + "\n" + access_line(2) + "\n" + access_line(3) + "\n")
    mid_of_line2 = len(access_line(1)) + 1 + 5
    resynced = _resync_to_next_line_boundary(p3, mid_of_line2)
    expected = len(access_line(1)) + 1 + len(access_line(2)) + 1
    assert resynced == expected, (resynced, expected)
    lines3, _c3 = _read_text_lines_segment(p3, resynced, 1_000_000)
    assert lines3 == [access_line(3)], lines3
    print("Test 3 (_resync_to_next_line_boundary lands exactly on the next line start) PASSED")

    log_path = os.path.join(BASE, "resume.log")
    with open(log_path, "w") as f:
        f.write(access_line(1) + "\n" + access_line(2) + "\n")
    inode = os.stat(log_path).st_ino
    offset_after_2 = os.path.getsize(log_path)
    with open(log_path, "a") as f:
        f.write(access_line(3) + "\n" + access_line(4) + "\n")

    mon = make_monitor(log_path)
    replayed = []

    async def handler(line, path, line_no):
        replayed.append(line)

    checkpoint = _TailCheckpoint(inode=inode, offset=offset_after_2)
    await mon._catch_up_tail_from_checkpoint(log_path, handler, checkpoint)
    assert replayed == [access_line(3), access_line(4)], replayed
    final_cp = mon._tail_checkpoints[log_path]
    assert final_cp.inode == inode
    assert final_cp.offset == os.path.getsize(log_path)
    print("Test 4 (plain restart resume replays exactly the lines written during downtime) PASSED")

    log_path_r = os.path.join(BASE, "rotated.log")
    with open(log_path_r, "w") as f:
        f.write(access_line(1) + "\n" + access_line(2) + "\n" + access_line(3) + "\n")
    old_inode = os.stat(log_path_r).st_ino
    offset_after_1 = len(access_line(1)) + 1
    os.rename(log_path_r, log_path_r + ".1")
    with open(log_path_r, "w") as f:
        f.write(access_line(4) + "\n" + access_line(5) + "\n")
    new_inode = os.stat(log_path_r).st_ino
    assert new_inode != old_inode

    mon_r = make_monitor(log_path_r)
    replayed_r = []

    async def handler_r(line, path, line_no):
        replayed_r.append(line)

    checkpoint_r = _TailCheckpoint(inode=old_inode, offset=offset_after_1)
    await mon_r._catch_up_tail_from_checkpoint(log_path_r, handler_r, checkpoint_r)
    assert replayed_r == [access_line(2), access_line(3), access_line(4), access_line(5)], replayed_r
    final_cp_r = mon_r._tail_checkpoints[log_path_r]
    assert final_cp_r.inode == new_inode
    assert final_cp_r.offset == os.path.getsize(log_path_r)
    print("Test 5 (rotation during downtime: unread tail of old file + all of new file replayed) PASSED")

    log_path_t = os.path.join(BASE, "truncated.log")
    with open(log_path_t, "w") as f:
        f.write(access_line(1) + "\n" + access_line(2) + "\n" + access_line(3) + "\n")
    inode_t = os.stat(log_path_t).st_ino
    stale_offset = os.path.getsize(log_path_t)
    with open(log_path_t, "w") as f:
        f.write(access_line(9) + "\n")
    assert os.stat(log_path_t).st_ino == inode_t

    mon_t = make_monitor(log_path_t)
    replayed_t = []

    async def handler_t(line, path, line_no):
        replayed_t.append(line)

    checkpoint_t = _TailCheckpoint(inode=inode_t, offset=stale_offset)
    await mon_t._catch_up_tail_from_checkpoint(log_path_t, handler_t, checkpoint_t)
    assert replayed_t == [access_line(9)], replayed_t
    print("Test 6 (truncation during downtime: reads from 0 instead of a stale past-EOF offset) PASSED")

    log_path_b = os.path.join(BASE, "big_gap.log")
    total_lines = 200
    with open(log_path_b, "w") as f:
        for i in range(total_lines):
            f.write(access_line(i % 10) + "\n")
    inode_b = os.stat(log_path_b).st_ino
    one_line_len = len(access_line(0)) + 1
    tiny_budget = one_line_len * 10

    mon_b = make_monitor(log_path_b, tail_checkpoint_max_catchup_bytes=tiny_budget)
    warnings = []
    mon_b.logger.warning = lambda *a, **k: warnings.append((a, k))
    replayed_b = []

    async def handler_b(line, path, line_no):
        replayed_b.append(line)

    checkpoint_b = _TailCheckpoint(inode=inode_b, offset=0)
    await mon_b._catch_up_tail_from_checkpoint(log_path_b, handler_b, checkpoint_b)
    assert len(replayed_b) < total_lines, (
        f"a downtime gap exceeding the configured budget must not be fully replayed: "
        f"{len(replayed_b)} of {total_lines}"
    )
    assert len(warnings) >= 1, "exceeding the catch-up budget must be disclosed via a warning log, not silent"
    for line in replayed_b:
        assert _RE_ACCESS.match(line), f"catch-up must never hand a garbled/partial line to the handler: {line!r}"
    final_cp_b = mon_b._tail_checkpoints[log_path_b]
    assert final_cp_b.offset <= os.path.getsize(log_path_b)
    print("Test 7 (budget-exceeded gap: partial replay, disclosed via warning, no garbled lines) PASSED")

    log_path_e2e = os.path.join(BASE, "e2e.log")
    with open(log_path_e2e, "w") as f:
        f.write(access_line(1) + "\n")

    mon_e2e = make_monitor(log_path_e2e)
    seen = []

    async def e2e_handler(line, path, line_no):
        seen.append(line)

    task1 = asyncio.create_task(mon_e2e._tail_file(log_path_e2e, e2e_handler))
    await asyncio.sleep(0.2)
    assert seen == [], (
        f"first-ever run (no checkpoint) must never replay pre-existing content, "
        f"matching every other baseline in this codebase: {seen}"
    )
    with open(log_path_e2e, "a") as f:
        f.write(access_line(2) + "\n")
    await asyncio.sleep(0.6)
    assert seen == [access_line(2)], f"live tailing while running must be unaffected: {seen}"

    task1.cancel()
    await asyncio.gather(task1, return_exceptions=True)
    cp_after_stop = mon_e2e._tail_checkpoints[log_path_e2e]
    assert cp_after_stop.offset == os.path.getsize(log_path_e2e)
    print("Test 8 (first run: no historical replay, live tailing works, checkpoint tracked) PASSED")

    with open(log_path_e2e, "a") as f:
        f.write(access_line(3) + "\n" + access_line(4) + "\n")

    mon_e2e2 = make_monitor(log_path_e2e)
    mon_e2e2._tail_checkpoints[log_path_e2e] = cp_after_stop
    seen2 = []

    async def e2e_handler2(line, path, line_no):
        seen2.append(line)

    task2 = asyncio.create_task(mon_e2e2._tail_file(log_path_e2e, e2e_handler2))
    await asyncio.sleep(0.3)
    assert seen2 == [access_line(3), access_line(4)], (
        f"a simulated restart with a carried-over checkpoint must replay exactly the lines "
        f"written during the 'downtime' between task1 stopping and task2 starting: {seen2}"
    )
    with open(log_path_e2e, "a") as f:
        f.write(access_line(5) + "\n")
    await asyncio.sleep(0.6)
    assert seen2 == [access_line(3), access_line(4), access_line(5)], (
        f"live tailing must resume normally after catch-up completes: {seen2}"
    )
    task2.cancel()
    await asyncio.gather(task2, return_exceptions=True)
    print("Test 9 (restart with carried-over checkpoint: catch-up then seamless live resume) PASSED")

    log_path_off = os.path.join(BASE, "off.log")
    with open(log_path_off, "w") as f:
        f.write(access_line(1) + "\n")
    mon_off = make_monitor(log_path_off, tail_checkpoint_enabled=False)
    seen_off = []

    async def off_handler(line, path, line_no):
        seen_off.append(line)

    task_off = asyncio.create_task(mon_off._tail_file(log_path_off, off_handler))
    await asyncio.sleep(0.2)
    with open(log_path_off, "a") as f:
        f.write(access_line(2) + "\n")
    await asyncio.sleep(0.6)
    assert seen_off == [access_line(2)]
    assert mon_off._tail_checkpoints == {}, (
        "tail_checkpoint_enabled=False must behave exactly as before this change -- no "
        "checkpoint state tracked at all"
    )
    task_off.cancel()
    await asyncio.gather(task_off, return_exceptions=True)
    print("Test 10 (tail_checkpoint_enabled=False: unchanged pre-existing behavior) PASSED")

    print("\nALL NGINX TAIL CHECKPOINT RESTART-SAFETY TESTS PASSED")


asyncio.run(main())
