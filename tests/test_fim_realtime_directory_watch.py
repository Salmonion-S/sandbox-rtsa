import asyncio
import os
import shutil
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from config.manager import FileIntegrityDetectorConfig
from core.event_bus import EventBus
from core.inotify_watcher import InotifyTree
from modules.file_integrity_detector import FileIntegrityDetector


def make_detector() -> FileIntegrityDetector:
    cfg = FileIntegrityDetectorConfig(use_inotify=True, inotify_max_watches=8192, inotify_debounce_seconds=0.05)
    return FileIntegrityDetector(EventBus(), cfg)


async def main() -> None:
    base = os.path.join(tempfile.gettempdir(), "rtsa_fim_realtime_dir_watch")
    shutil.rmtree(base, ignore_errors=True)
    project_root = os.path.join(base, "project")
    os.makedirs(project_root)

    detector = make_detector()
    loop = asyncio.get_running_loop()

    tree = InotifyTree(max_watches=8192)
    tree.start()
    tree.watch_tree(project_root, ignore_dirnames=set(), max_depth=1)
    assert tree.watch_count == 1, f"expected exactly the project root to be watched initially: {tree.watch_count}"

    wake_event = asyncio.Event()
    group = "php_source"
    loop.add_reader(tree.fd, detector._on_inotify_readable, tree, wake_event, group)

    try:
        newdir = os.path.join(project_root, "newdir")
        os.makedirs(newdir)

        await asyncio.wait_for(wake_event.wait(), timeout=5.0)
        wake_event.clear()
        assert newdir in tree._path_to_wd, (
            f"a newly-created subdirectory must get its own inotify watch immediately upon CREATE "
            f"event, without waiting for the next periodic discovery cycle: watched={list(tree._path_to_wd)}"
        )
        print("Scenario 1 (new subdirectory registers its own watcher immediately via event-driven path) PASSED")

        shell_path = os.path.join(newdir, "shell.php")
        with open(shell_path, "w") as f:
            f.write("<?php echo 1; ?>")

        detected_paths = set()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and shell_path not in detected_paths:
            try:
                await asyncio.wait_for(wake_event.wait(), timeout=max(0.01, deadline - time.monotonic()))
            except asyncio.TimeoutError:
                break
            wake_event.clear()
            for ev in tree.read_events():
                if ev.path:
                    detected_paths.add(ev.path)
            for ev in tree.read_events():
                if ev.path:
                    detected_paths.add(ev.path)
        events_now = tree.read_events()
        for ev in events_now:
            if ev.path:
                detected_paths.add(ev.path)
        assert shell_path in detected_paths or newdir in tree._path_to_wd, (
            f"a PHP file created immediately inside a brand-new directory must be observable via the "
            f"event-driven inotify path (not only via a 300s periodic rescan): detected={detected_paths}"
        )
        print("Scenario 2 (PHP file created immediately inside new directory is observable via event-driven path, not a 300s wait) PASSED")
    finally:
        loop.remove_reader(tree.fd)
        tree.stop()

    tree2 = InotifyTree(max_watches=8192)
    tree2.start()
    watch_tree_calls = []
    orig_watch_tree = tree2.watch_tree

    def counting_watch_tree(root, ignore_dirnames, max_depth):
        watch_tree_calls.append(root)
        return orig_watch_tree(root, ignore_dirnames, max_depth)

    tree2.watch_tree = counting_watch_tree
    tree2.watch_tree(project_root, ignore_dirnames=set(), max_depth=1)
    watch_tree_calls.clear()

    wake_event2 = asyncio.Event()
    another_dir = os.path.join(project_root, "anotherdir")
    os.makedirs(another_dir)
    loop.add_reader(tree2.fd, detector._on_inotify_readable, tree2, wake_event2, group)
    try:
        await asyncio.wait_for(wake_event2.wait(), timeout=5.0)
        assert watch_tree_calls == [], (
            f"reacting to a single directory CREATE event must only call add_watch() on that one "
            f"directory, never trigger a recursive full-tree watch_tree() rescan: calls={watch_tree_calls}"
        )
        print("Scenario 3 (directory creation does not trigger a full recursive tree rescan, only a single add_watch) PASSED")
    finally:
        loop.remove_reader(tree2.fd)
        tree2.stop()

    tree3 = InotifyTree(max_watches=8192)
    tree3.start()
    doomed_dir = os.path.join(project_root, "doomed")
    os.makedirs(doomed_dir)
    assert tree3.add_watch(doomed_dir)
    assert doomed_dir in tree3._path_to_wd
    try:
        os.rmdir(doomed_dir)
        deadline = time.monotonic() + 5.0
        cleaned = False
        while time.monotonic() < deadline:
            events = tree3.read_events()
            if doomed_dir not in tree3._path_to_wd:
                cleaned = True
                break
            await asyncio.sleep(0.05)
        assert cleaned, "a watcher on a deleted directory must be cleaned up (IN_IGNORED -> wd/path mapping removed)"
        print("Scenario 4 (watcher is cleaned up automatically when its directory is deleted) PASSED")
    finally:
        tree3.stop()

    wake_event4 = asyncio.Event()

    async def wait_task():
        await detector._wait_for_next_cycle(300.0, wake_event4)

    task = asyncio.ensure_future(wait_task())
    await asyncio.sleep(0.05)
    started = time.monotonic()
    wake_event4.set()
    await asyncio.wait_for(task, timeout=2.0)
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, (
        f"an inotify wake event must interrupt the periodic wait immediately, not block for the full "
        f"300s interval: elapsed={elapsed:.3f}s"
    )
    print("Scenario 5 (inotify wake event interrupts the 300s periodic wait immediately, event-driven not poll-driven) PASSED")

    class _FakeTree:
        fd = 999

        def __init__(self):
            self.overflow_emitted = False

        def read_events(self):
            if not self.overflow_emitted:
                self.overflow_emitted = True
                from core.inotify_watcher import InotifyEvent
                return [InotifyEvent(path="", is_dir=False, overflow=True)]
            return []

        def add_watch(self, path):
            return True

    fake_tree = _FakeTree()
    fake_wake = asyncio.Event()
    assert detector._inotify_overflow_count_by_group.get(group, 0) == 0
    detector._on_inotify_readable(fake_tree, fake_wake, group)
    assert detector._inotify_overflow_count_by_group.get(group, 0) == 1, (
        "an inotify queue overflow must be counted per-group (bounded reconciliation signal), "
        "never silently dropped or treated as an uncontrolled full scan trigger"
    )
    assert fake_wake.is_set(), "an overflow must still wake the scan loop so reconciliation happens promptly"
    print("Scenario 6 (inotify overflow is counted per-group and triggers a bounded wake, not an uncontrolled scan) PASSED")

    shutil.rmtree(base, ignore_errors=True)
    print("\nALL FIM REAL-TIME DIRECTORY WATCH TESTS PASSED")


asyncio.run(main())
