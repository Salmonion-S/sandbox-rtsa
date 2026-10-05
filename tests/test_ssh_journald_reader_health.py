import asyncio
import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import SSHMonitorConfig
from core.event_bus import EventBus
from modules.ssh_monitor import SSHMonitor


class _FakeStdout:
    def __init__(self, lines):
        self._lines = list(lines)

    async def readline(self):
        if self._lines:
            return self._lines.pop(0)
        return b""


class _FakeProc:
    def __init__(self, lines):
        self.stdout = _FakeStdout(lines)

    def kill(self):
        pass

    async def wait(self):
        return None


async def main() -> None:
    mon = SSHMonitor(EventBus(), SSHMonitorConfig(enabled=True))
    mon._process_line = lambda line: None

    call_count = {"n": 0}

    async def fake_create_subprocess_exec(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _FakeProc([b"line one\n", b"line two\n"])
        raise asyncio.CancelledError()

    original_create = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = fake_create_subprocess_exec
    original_sleep = asyncio.sleep
    slept_for = []

    async def fake_sleep(seconds):
        slept_for.append(seconds)
        if len(slept_for) >= 1:
            raise asyncio.CancelledError()

    asyncio.sleep = fake_sleep
    try:
        try:
            await mon._stream_journald()
        except asyncio.CancelledError:
            pass
    finally:
        asyncio.create_subprocess_exec = original_create
        asyncio.sleep = original_sleep

    assert mon._journald_reader_last_line_at is not None, (
        "processing real lines from the journalctl stream must update the reader's "
        "last-line-seen timestamp, so a stalled/dead reader is externally observable"
    )
    assert mon._journald_reader_restarts == 1, (
        f"a clean EOF (journalctl exiting without raising an exception) must still be counted "
        f"as a restart AND must back off before retrying -- immediately looping back into "
        f"create_subprocess_exec with no sleep would be a busy-restart-loop, got restarts="
        f"{mon._journald_reader_restarts}, slept_for={slept_for}"
    )
    assert slept_for and slept_for[0] == 5, (
        f"the clean-EOF path must sleep before retrying, not spin immediately, got {slept_for}"
    )
    print(
        "Scenario 1 (clean EOF from journalctl is counted as a restart AND backed off, "
        "never a tight busy-restart-loop; last-line timestamp is externally observable) PASSED"
    )

    print("\nALL SSH JOURNALD READER HEALTH TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
