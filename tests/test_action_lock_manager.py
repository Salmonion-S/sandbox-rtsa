import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.action_lock import ActionLockManager, ActionStatus


async def main():
    mgr = ActionLockManager(ttl_seconds=1.0, running_stale_seconds=2.0, max_entries=5)

    acquired, existing = mgr.try_acquire(action="kill_process", target="process:100", event_id="e1", requested_by="alice")
    assert acquired and existing is None
    print("Scenario 1 (first acquisition on a fresh target succeeds) PASSED")

    acquired2, existing2 = mgr.try_acquire(action="kill_process", target="process:100", event_id="e1", requested_by="bob")
    assert not acquired2
    assert existing2.status == ActionStatus.RUNNING
    print("Scenario 2 (concurrent acquisition on the SAME target while RUNNING is rejected) PASSED")

    acquired3, _existing3 = mgr.try_acquire(action="kill_process", target="process:200", event_id="e2", requested_by="alice")
    assert acquired3, "an unrelated target must never be blocked by a different target's lock"
    print("Scenario 3 (unrelated target is never blocked) PASSED")

    mgr.complete(action="kill_process", target="process:100", success=True, result_summary="killed")
    acquired4, existing4 = mgr.try_acquire(action="kill_process", target="process:100", event_id="e3", requested_by="carol")
    assert not acquired4
    assert existing4.status == ActionStatus.SUCCESS
    assert existing4.result_summary == "killed"
    print("Scenario 4 (SUCCESS within the dedup window blocks re-execution, returns cached result) PASSED")

    await asyncio.sleep(1.1)
    acquired5, existing5 = mgr.try_acquire(action="kill_process", target="process:100", event_id="e4", requested_by="dave")
    assert acquired5, "a SUCCESS record older than the TTL must allow a fresh attempt"
    assert existing5 is None
    print("Scenario 5 (SUCCESS beyond the TTL window expires, allowing a fresh attempt) PASSED")

    mgr.complete(action="kill_process", target="process:100", success=False, result_summary="permission denied")
    acquired6, existing6 = mgr.try_acquire(action="kill_process", target="process:100", event_id="e5", requested_by="alice")
    assert acquired6, "a FAILED action must allow an immediate retry, not leave a permanent lock"
    print("Scenario 6 (FAILED action does not leave a permanent lock, retry allowed immediately) PASSED")

    mgr2 = ActionLockManager(ttl_seconds=100.0, running_stale_seconds=0.5, max_entries=5)
    mgr2.try_acquire(action="pm2stop", target="pm2:deploy:myapp", event_id="e6", requested_by="alice")
    await asyncio.sleep(0.6)
    acquired7, existing7 = mgr2.try_acquire(action="pm2stop", target="pm2:deploy:myapp", event_id="e7", requested_by="bob")
    assert acquired7, "a RUNNING action stuck far longer than running_stale_seconds (crash/hang) must eventually expire"
    print("Scenario 7 (a stuck RUNNING record eventually expires -- crash recovery) PASSED")

    mgr3 = ActionLockManager(ttl_seconds=100.0, running_stale_seconds=100.0, max_entries=3)
    for i in range(5):
        mgr3.try_acquire(action="killport", target=f"port:tcp:0.0.0.0:{8000+i}", event_id=f"e{i}", requested_by="alice")
    assert len(mgr3) <= 3, f"the idempotency cache must stay bounded, got {len(mgr3)}"
    print("Scenario 8 (idempotency cache stays bounded under max_entries, oldest evicted) PASSED")

    mgr4 = ActionLockManager()
    key1 = ActionLockManager.make_key("block_port", "port:tcp:0.0.0.0:8080")
    key2 = ActionLockManager.make_key("kill_process", "port:tcp:0.0.0.0:8080")
    assert key1 != key2, "the same target under a DIFFERENT action must be an independent key"
    a1, _ = mgr4.try_acquire(action="block_port", target="port:tcp:0.0.0.0:8080", event_id="e8", requested_by="alice")
    a2, _ = mgr4.try_acquire(action="kill_process", target="port:tcp:0.0.0.0:8080", event_id="e9", requested_by="alice")
    assert a1 and a2, "action identity includes both action AND target -- different actions on the same target are independent"
    print("Scenario 9 (action identity = action + target, not target alone) PASSED")

    print("\nALL ACTION LOCK MANAGER TESTS PASSED")


asyncio.run(main())
