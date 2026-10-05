import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio

import core.user_deletion as ud


class FakeSystem:

    def __init__(self, *, pw_entry=None, active_processes=0, active_sessions=0, home_exists=True):
        self.pw_entry = pw_entry
        self.active_processes = active_processes
        self.active_sessions = active_sessions
        self.home_exists = home_exists
        self.subprocess_calls = []
        self.userdel_result = ud.SubprocessResult(returncode=0, stdout="", stderr="", timed_out=False)
        self.getent_result = ud.SubprocessResult(returncode=2, stdout="", stderr="", timed_out=False)
        self.id_result = ud.SubprocessResult(returncode=1, stdout="", stderr="not found", timed_out=False)
        self.rm_result = ud.SubprocessResult(returncode=0, stdout="", stderr="", timed_out=False)
        self.getent_raises = False
        self.id_raises = False
        self.home_after_rm = False

    async def getpw_fn(self, username):
        return self.pw_entry

    async def count_processes_fn(self, uid):
        return self.active_processes

    async def count_sessions_fn(self, username):
        return self.active_sessions

    async def home_exists_fn(self, home):
        return self.home_exists

    async def run_subprocess_fn(self, args, timeout):
        self.subprocess_calls.append((tuple(args), timeout))
        if args[0] == "userdel":
            return self.userdel_result
        if args[0] == "getent":
            if self.getent_raises:
                raise RuntimeError("getent kaboom")
            return self.getent_result
        if args[0] == "id":
            if self.id_raises:
                raise RuntimeError("id kaboom")
            return self.id_result
        if args[0] == "rm":
            self.home_exists = self.home_after_rm
            return self.rm_result
        raise AssertionError(f"unexpected subprocess call: {args}")

    def kwargs(self, **overrides):
        base = dict(
            getpw_fn=self.getpw_fn, count_processes_fn=self.count_processes_fn,
            count_sessions_fn=self.count_sessions_fn, home_exists_fn=self.home_exists_fn,
            run_subprocess_fn=self.run_subprocess_fn,
            userdel_bin="userdel", getent_bin="getent", id_bin="id", rm_bin="rm",
        )
        base.update(overrides)
        return base


def pw(name="news-new", uid=1500, gid=1500, home="/home/news-new", shell="/bin/bash"):
    return ud.PwEntry(name=name, uid=uid, gid=gid, home=home, shell=shell)


async def _run(sys_, **kw):
    return await ud.delete_linux_user("news-new", remove_home=kw.pop("remove_home", False),
                                       budgets=kw.pop("budgets", ud.DeletionBudgets()), **sys_.kwargs(**kw))


async def main() -> None:
    sys_ = FakeSystem(pw_entry=pw())
    result = await _run(sys_)
    assert result.state == ud.STATE_SUCCESS, result
    assert result.verification.confirmed_gone
    assert any(c[0][0] == "userdel" for c in sys_.subprocess_calls)
    assert not any(c[0][0] == "rm" for c in sys_.subprocess_calls), "rm must never run when remove_home=False"
    print("Scenario A [NORMAL SUCCESSFUL DELETION, HOME NOT REQUESTED] (userdel runs once, verification "
          "confirms gone, rm is never invoked) PASSED")

    sys_ = FakeSystem(pw_entry=pw(), home_exists=True)
    sys_.home_after_rm = False
    result = await _run(sys_, remove_home=True)
    assert result.state == ud.STATE_SUCCESS, result
    assert result.home_removed is True
    assert any(c[0][0] == "rm" for c in sys_.subprocess_calls)
    print("Scenario B [NORMAL SUCCESSFUL DELETION WITH HOME REMOVAL] (userdel then rm both run, both "
          "verified, SUCCESS with home_removed=True) PASSED")

    sys_ = FakeSystem(pw_entry=pw())
    sys_.userdel_result = ud.SubprocessResult(returncode=None, stdout="", stderr="", timed_out=True)
    sys_.getent_result = ud.SubprocessResult(returncode=2, stdout="", stderr="", timed_out=False)
    sys_.id_result = ud.SubprocessResult(returncode=1, stdout="", stderr="no such user", timed_out=False)
    result = await _run(sys_)
    assert result.state == ud.STATE_SUCCESS, result
    assert result.userdel_timed_out is True
    assert "timeout" in result.reason.lower() and "terhapus" in result.reason.lower()
    print("Scenario C [USERDEL TIMEOUT BUT ACCOUNT ACTUALLY DELETED] (a bare subprocess timeout must never "
          "be reported as failure when verification proves the account is gone -- this is the exact "
          "false-negative the original bug report was about) PASSED")

    sys_ = FakeSystem(pw_entry=pw())
    sys_.userdel_result = ud.SubprocessResult(returncode=None, stdout="", stderr="", timed_out=True)
    sys_.getent_result = ud.SubprocessResult(
        returncode=0, stdout="news-new:x:1500:1500::/home/news-new:/bin/bash\n", stderr="", timed_out=False,
    )
    sys_.id_result = ud.SubprocessResult(returncode=0, stdout="uid=1500(news-new)\n", stderr="", timed_out=False)
    result = await _run(sys_)
    assert result.state == ud.STATE_FAILED, result
    assert result.userdel_timed_out is True
    assert result.verification.confirmed_present
    assert "MASIH ADA" in result.reason or "masih ada" in result.reason.lower()
    print("Scenario D [USERDEL TIMEOUT AND ACCOUNT STILL EXISTS] (the exact reported bug: a timeout must "
          "never be reported as a generic/ambiguous result when verification proves the account is still "
          "fully present -- this must be an unambiguous FAILED) PASSED")

    sys_ = FakeSystem(pw_entry=pw())
    sys_.userdel_result = ud.SubprocessResult(
        returncode=1, stdout="", stderr="userdel: user news-new is currently used by process 4821", timed_out=False,
    )
    sys_.getent_result = ud.SubprocessResult(
        returncode=0, stdout="news-new:x:1500:1500::/home/news-new:/bin/bash\n", stderr="", timed_out=False,
    )
    sys_.id_result = ud.SubprocessResult(returncode=0, stdout="uid=1500(news-new)\n", stderr="", timed_out=False)
    result = await _run(sys_)
    assert result.state == ud.STATE_FAILED, result
    assert result.userdel_timed_out is False
    assert "4821" in result.reason
    print("Scenario E [DELETION FAILS (NON-TIMEOUT) WITH ACCOUNT STILL PRESENT] (a clean non-zero userdel "
          "exit is also verified, not blindly trusted -- FAILED with the real stderr reason surfaced) PASSED")

    sys_ = FakeSystem(pw_entry=None)
    result = await _run(sys_)
    assert result.state == ud.STATE_ALREADY_DELETED, result
    assert sys_.subprocess_calls == [], "no subprocess should ever run for an account that never existed"
    print("Scenario F [ALREADY DELETED / NOT FOUND -- IDEMPOTENT, NO CRASH] (getpw returns None -> "
          "ALREADY_DELETED immediately, zero subprocess calls, no exception) PASSED")

    sys_ = FakeSystem(pw_entry=pw())
    sys_.getent_raises = True
    sys_.id_raises = True
    result = await _run(sys_)
    assert result.state == ud.STATE_UNKNOWN, result
    assert len(result.verification.errors) >= 2
    print("Scenario G [VERIFICATION COMMANDS BOTH FAIL -- UNKNOWN, NEVER A GUESS] (getent and id both "
          "error out -- RTSA reports UNKNOWN rather than fabricating SUCCESS or FAILED from no evidence) PASSED")

    sys_ = FakeSystem(pw_entry=pw(), home_exists=False)
    sys_.getent_result = ud.SubprocessResult(returncode=2, stdout="", stderr="", timed_out=False)
    sys_.id_raises = True
    result = await _run(sys_)
    assert result.state == ud.STATE_UNKNOWN, result
    print("Scenario H [PARTIAL VERIFICATION EVIDENCE -- NEVER A FALSE SUCCESS] (getent alone says gone but "
          "id could not be checked at all -- one confirming signal is not enough to declare SUCCESS, "
          "correctly falls back to UNKNOWN) PASSED")

    sys_ = FakeSystem(pw_entry=pw(), active_processes=3, active_sessions=0)
    result = await _run(sys_)
    assert result.state == ud.STATE_FAILED, result
    assert "clearproses" in result.reason
    assert sys_.subprocess_calls == [], "userdel must never run while active processes are still present"
    print("Scenario I [ACTIVE PROCESSES BLOCK DELETION -- /clearproses REQUIREMENT PRESERVED] "
          "(defence-in-depth re-check inside the engine itself refuses before ever invoking userdel) PASSED")

    sys_ = FakeSystem(pw_entry=pw(), active_processes=0, active_sessions=2)
    result = await _run(sys_)
    assert result.state == ud.STATE_FAILED, result
    assert "clearproses" in result.reason
    assert sys_.subprocess_calls == []
    print("Scenario J [ACTIVE SESSIONS ALSO BLOCK DELETION] (a logged-in session with zero background "
          "processes still refuses deletion, same as active processes) PASSED")

    sys_ = FakeSystem(pw_entry=pw(), home_exists=True)
    sys_.home_after_rm = True
    result = await _run(sys_, remove_home=True)
    assert result.state == ud.STATE_PARTIAL_FAILURE, result
    assert result.home_removed is False
    assert result.verification.home_directory_exists is True
    print("Scenario K [ACCOUNT DELETED BUT HOME DIRECTORY CLEANUP INCOMPLETE -- PARTIAL_FAILURE] "
          "(the security-critical account deletion succeeded and is verified, but the home directory rm "
          "did not finish in time -- reported as PARTIAL_FAILURE, never a bare FAILED or a bare SUCCESS) PASSED")

    sys_ = FakeSystem(pw_entry=pw(uid=1500))
    result = await _run(sys_, expected_uid=1600)
    assert result.state == ud.STATE_FAILED, result
    assert "UID" in result.reason
    assert sys_.subprocess_calls == [], "userdel must never run when the UID drifted since validation"
    print("Scenario L [UID DRIFT BETWEEN VALIDATION AND EXECUTION REFUSES] (the account may have been "
          "recreated with a different UID between /deluser's confirmation and execution -- the engine "
          "refuses outright rather than deleting whatever now sits at that username) PASSED")

    sys_ = FakeSystem(pw_entry=None)
    try:
        result = await _run(sys_, expected_uid=1500)
    except Exception as exc:
        raise AssertionError(f"delete_linux_user must never raise, got {exc!r}")
    assert result.state == ud.STATE_ALREADY_DELETED, result
    print("Scenario M [IDEMPOTENT RE-RUN NEVER CRASHES] (calling delete_linux_user again for an account "
          "that is already gone -- even with an expected_uid set -- returns cleanly, never raises) PASSED")

    budgets = ud.DeletionBudgets(
        account_deletion_seconds=17.0, home_cleanup_seconds=42.0, verification_step_seconds=3.0,
    )
    sys_ = FakeSystem(pw_entry=pw(), home_exists=True)
    sys_.home_after_rm = False
    await _run(sys_, remove_home=True, budgets=budgets)
    timeouts_by_cmd = {c[0][0]: c[1] for c in sys_.subprocess_calls}
    assert timeouts_by_cmd["userdel"] == 17.0
    assert timeouts_by_cmd["getent"] == 3.0
    assert timeouts_by_cmd["id"] == 3.0
    assert timeouts_by_cmd["rm"] == 42.0
    print("Scenario N [SEPARATE TIME BUDGETS PROPAGATE CORRECTLY] (account deletion, verification, and "
          "home cleanup each carry their own configured timeout down to the actual subprocess call -- "
          "never one shared global timeout) PASSED")

    assert ud._safe_rm_args("rm", "/") is None
    assert ud._safe_rm_args("rm", "/root") is None
    assert ud._safe_rm_args("rm", "/home") is None
    assert ud._safe_rm_args("rm", "") is None
    assert ud._safe_rm_args("rm", "relative/path") is None
    assert ud._safe_rm_args("rm", "/home/news-new") == ["rm", "-rf", "--", "/home/news-new"]
    print("Scenario O [HOME DIRECTORY RM SAFETY GUARD] (rm -rf is refused outright against root-level or "
          "non-absolute paths regardless of what a corrupted passwd entry might claim) PASSED")

    sys_ = FakeSystem(pw_entry=pw(), home_exists=True)
    sys_.home_after_rm = True
    result = await _run(sys_, remove_home=True)
    assert result.transitions == (
        ud.STATE_PREFLIGHT, ud.STATE_CLEARING, ud.STATE_DELETING, ud.STATE_VERIFYING,
        ud.STATE_DELETING, ud.STATE_VERIFYING,
    ), result.transitions
    print("Scenario P [EXPLICIT STATE TRANSITIONS RECORDED] (a full remove_home run walks PREFLIGHT -> "
          "CLEARING -> DELETING -> VERIFYING -> DELETING (home cleanup) -> VERIFYING, fully traceable) PASSED")

    print("\nALL USER DELETION ENGINE (core/user_deletion.py) TESTS PASSED")


asyncio.run(main())
