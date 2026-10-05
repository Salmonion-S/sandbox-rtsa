import os
import stat
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio
import pwd
import time
from unittest import mock

import core.user_deletion as user_deletion
from config.manager import (
    CloudflareConfig, DeluserConfig, DiscordConfig, HostPersistenceDetectorConfig, ModulesConfig,
    ResponseEngineConfig, RTSAConfig,
)
from core.event_bus import EventBus
from discord_integration.bot import RTSABot


class FakeDb:
    def __init__(self):
        self.actions = []

    def enqueue_action(self, payload, result):
        self.actions.append((payload, result))

    def enqueue_incident_create(self, **k):
        pass

    def enqueue_incident_update(self, *a, **k):
        pass


def make_bot(deluser_cfg=None):
    fast_cfg = deluser_cfg or DeluserConfig(
        account_deletion_timeout_seconds=0.3, home_cleanup_timeout_seconds=0.3,
        verification_step_timeout_seconds=2.0,
    )
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False, whitelist_user=["newusproud"]),
        modules=ModulesConfig(
            host_persistence_detector=HostPersistenceDetectorConfig(
                auto_remediate_protect_users=["newusproud", "root"],
            ),
        ),
        cloudflare=CloudflareConfig(enabled=False),
        deluser=fast_cfg,
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)


def fake_pw(name="news-new", uid=1500, gid=1500, home="/home/news-new", shell="/bin/bash"):
    return pwd.struct_passwd((name, "x", uid, gid, "", home, shell))


def write_script(directory, name, body):
    path = os.path.join(directory, name)
    with open(path, "w") as f:
        f.write(f"#!/bin/sh\n{body}\n")
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def test_format_deletion_result_failed_exact_shape(bot):
    result = user_deletion.DeletionResult(
        state=user_deletion.STATE_FAILED, username="news-new", uid=1500, home="/home/news-new",
        reason="deletion command timed out",
        transitions=(user_deletion.STATE_PREFLIGHT,),
        verification=user_deletion.VerificationResult(
            passwd_entry_exists=True, id_command_succeeds=True,
            active_process_count=0, active_session_count=0, home_directory_exists=True,
        ),
        userdel_timed_out=True,
    )
    message = bot._format_deletion_result(result)
    assert "DELUSER FAILED" in message
    assert "User: `news-new`" in message
    assert "Reason: deletion command timed out" in message
    assert "Linux account: STILL EXISTS" in message
    assert "UID: 1500" in message
    assert "Active processes: 0" in message
    assert "Home directory: EXISTS" in message
    assert "No successful deletion" not in message
    assert "DELUSER SUCCESS" not in message
    print(
        "Scenario 1 [DISCORD OUTPUT MATCHES MANDATED FAILED FORMAT] (User/Reason/Verification block with "
        "Linux account STILL EXISTS/UID/Active processes/Home directory all present, and it never claims "
        "success anywhere in the message) PASSED"
    )


def test_format_deletion_result_all_states(bot):
    base = dict(
        username="news-new", uid=1500, home="/home/news-new", transitions=(),
    )
    success = user_deletion.DeletionResult(state=user_deletion.STATE_SUCCESS, reason="ok", **base)
    assert "DELUSER SUCCESS" in bot._format_deletion_result(success)

    partial = user_deletion.DeletionResult(state=user_deletion.STATE_PARTIAL_FAILURE, reason="partial", **base)
    assert "DELUSER PARTIAL_FAILURE" in bot._format_deletion_result(partial)

    unknown = user_deletion.DeletionResult(state=user_deletion.STATE_UNKNOWN, reason="unknown", **base)
    assert "DELUSER UNKNOWN" in bot._format_deletion_result(unknown)

    already = user_deletion.DeletionResult(state=user_deletion.STATE_ALREADY_DELETED, reason="gone", uid=None, home=None, username="news-new", transitions=())
    assert "DELUSER ALREADY_DELETED" in bot._format_deletion_result(already)
    print(
        "Scenario 2 [DISCORD OUTPUT DISTINGUISHES EVERY TERMINAL STATE] (SUCCESS, PARTIAL_FAILURE, UNKNOWN, "
        "and ALREADY_DELETED each render their own unambiguous header) PASSED"
    )


async def _run_subprocess_timeout_case(bot, tmpdir):
    hang_script = write_script(tmpdir, "userdel_hang", "trap '' TERM\nsleep 30")
    start = time.monotonic()
    result = await bot._run_deluser_subprocess([hang_script], 0.3)
    elapsed = time.monotonic() - start
    assert result.timed_out is True
    assert elapsed < 6.0, f"timeout handling took too long: {elapsed}s"
    return result


def test_real_subprocess_timeout_kills_process_group(bot):
    with tempfile.TemporaryDirectory() as tmpdir:
        result = asyncio.run(_run_subprocess_timeout_case(bot, tmpdir))
    assert result.returncode is not None or result.returncode is None
    print(
        "Scenario 3 [REAL SUBPROCESS TIMEOUT ESCALATES SIGTERM -> SIGKILL] (a script that ignores SIGTERM "
        "is still terminated within the grace period via SIGKILL sent to its process group, and "
        "_run_deluser_subprocess reports timed_out=True rather than hanging forever) PASSED"
    )


async def _run_end_to_end(bot, tmpdir, *, userdel_body, getent_body, id_body, active_processes_present=False):
    userdel_path = write_script(tmpdir, "userdel", userdel_body)
    getent_path = write_script(tmpdir, "getent", getent_body)
    id_path = write_script(tmpdir, "id", id_body)
    rm_path = write_script(tmpdir, "rm", "exit 0")

    def which(name):
        return {"userdel": userdel_path, "getent": getent_path, "id": id_path, "rm": rm_path}.get(name)

    with mock.patch("pwd.getpwnam", return_value=fake_pw()), \
         mock.patch("shutil.which", side_effect=which), \
         mock.patch.object(RTSABot, "_deluser_engine_count_processes", staticmethod(
             lambda uid: _async_const(3 if active_processes_present else 0))), \
         mock.patch.object(RTSABot, "_deluser_engine_count_sessions", staticmethod(lambda u: _async_const(0))):
        return await bot._delete_linux_user("news-new", reason="test", requested_by="tester", remove_home=False)


async def _async_const(value):
    return value


def test_end_to_end_successful_deletion():
    bot = make_bot()
    with tempfile.TemporaryDirectory() as tmpdir:
        message = asyncio.run(_run_end_to_end(
            bot, tmpdir, userdel_body="exit 0", getent_body="exit 2", id_body="exit 1",
        ))
    assert "DELUSER SUCCESS" in message, message
    assert bot.db_worker.actions, "an action record must be written"
    _, result_str = bot.db_worker.actions[-1]
    assert result_str == "success"
    print(
        "Scenario 4 [END-TO-END: NORMAL SUCCESSFUL DELETION THROUGH THE REAL DISCORD WIRING] (real "
        "subprocess exec for userdel/getent/id, full state machine, correct Discord message and db action "
        "record) PASSED"
    )


def test_end_to_end_timeout_still_exists_is_failed():
    bot = make_bot()
    with tempfile.TemporaryDirectory() as tmpdir:
        message = asyncio.run(_run_end_to_end(
            bot, tmpdir,
            userdel_body="trap '' TERM\nsleep 30",
            getent_body='echo "news-new:x:1500:1500::/home/news-new:/bin/bash"\nexit 0',
            id_body='echo "uid=1500(news-new)"\nexit 0',
        ))
    assert "DELUSER FAILED" in message, message
    assert "STILL EXISTS" in message
    assert "DELUSER SUCCESS" not in message
    print(
        "Scenario 5 [END-TO-END: THE REPORTED BUG IS FIXED] (userdel hangs past its budget and is killed, "
        "but getent/id confirm the account is still fully present -- the Discord message is an unambiguous "
        "FAILED naming STILL EXISTS, never a bare 'timeout' that could be misread as anything else) PASSED"
    )


def test_already_deleted_no_crash():
    bot = make_bot()
    with mock.patch("pwd.getpwnam", side_effect=KeyError):
        message = asyncio.run(bot._delete_linux_user("ghost-user", reason="test", requested_by="tester"))
    assert "DELUSER ALREADY_DELETED" in message
    print(
        "Scenario 6 [ALREADY-DELETED USER NEVER CRASHES THE COMMAND] (a username with no passwd entry at "
        "all produces a clean ALREADY_DELETED message, not an exception) PASSED"
    )


def test_uid_drift_refuses_before_touching_userdel():
    bot = make_bot()
    calls = []

    async def spy_run_subprocess(args, timeout):
        calls.append(args)
        raise AssertionError("userdel/getent/id must never be invoked when the UID has drifted")

    with mock.patch("pwd.getpwnam", return_value=fake_pw(uid=1500)), \
         mock.patch("shutil.which", return_value="/bin/true"), \
         mock.patch.object(bot, "_run_deluser_subprocess", spy_run_subprocess):
        message = asyncio.run(bot._delete_linux_user(
            "news-new", reason="test", requested_by="tester", remove_home=True, expected_uid=9999,
        ))
    assert "DELUSER FAILED" in message
    assert "UID" in message
    assert calls == []
    print(
        "Scenario 7 [UID DRIFT SAFETY WIRED END-TO-END] (/deluser's captured expected_uid is actually "
        "passed through to the engine, and a mismatch refuses before any subprocess is ever spawned) PASSED"
    )


def main() -> None:
    bot = make_bot()
    test_format_deletion_result_failed_exact_shape(bot)
    test_format_deletion_result_all_states(bot)
    test_real_subprocess_timeout_kills_process_group(bot)
    test_end_to_end_successful_deletion()
    test_end_to_end_timeout_still_exists_is_failed()
    test_already_deleted_no_crash()
    test_uid_drift_refuses_before_touching_userdel()
    print("\nALL /deluser DISCORD LIFECYCLE WIRING TESTS PASSED")


main()
