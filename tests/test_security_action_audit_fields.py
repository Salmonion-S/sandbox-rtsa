import os
import re
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import dataclasses

from core.datatypes import ActionType, RemediationAction


def main():
    action = RemediationAction(
        action_type=ActionType.BAN_IP, target="1.2.3.4", reason="test", requested_by="tester",
    )
    assert action.previous_state is None
    assert action.resulting_state is None
    print("Test 1 (RemediationAction default previous_state/resulting_state -- None, backward compatible) PASSED")

    action2 = RemediationAction(
        action_type=ActionType.BAN_IP, target="1.2.3.4", reason="test", requested_by="tester",
        previous_state="NOT_BANNED", resulting_state="BAN_VERIFIED",
    )
    payload = dataclasses.asdict(action2)
    assert payload["previous_state"] == "NOT_BANNED"
    assert payload["resulting_state"] == "BAN_VERIFIED"
    print("Test 2 (RemediationAction explicit previous/resulting_state survive dataclasses.asdict) PASSED")

    with open(os.path.join(_REPO_ROOT, "discord_integration", "bot.py"), "r", encoding="utf-8") as f:
        bot_source = f.read()

    audit_log_def = re.search(
        r"def _audit_log\(\s*self,.*?\)\s*->\s*None:", bot_source, re.DOTALL,
    )
    assert audit_log_def is not None, "_audit_log() definition not found"
    assert "previous_state" in audit_log_def.group(0) and "resulting_state" in audit_log_def.group(0), (
        "_audit_log() must accept previous_state/resulting_state kwargs"
    )
    print("Test 3 (_audit_log() signature carries previous_state/resulting_state kwargs) PASSED")

    assert bot_source.count("previous_state=") >= 6, (
        "expected previous_state= to be populated at least once for each of the six named "
        "commands (/banip x2, /clearproses, /deluser x2, /pm2startup, /ignoredm+/monit x2)"
    )
    print("Test 4 (previous_state= is populated at the named-command audit call sites) PASSED")

    assert "previous_state=\"PRESENT\", resulting_state=result.state" in bot_source, (
        "/deluser main branch must record PRESENT -> result.state"
    )
    assert "previous_state=\"ABSENT\", resulting_state=user_deletion.STATE_ALREADY_DELETED" in bot_source, (
        "/deluser already-deleted branch must record ABSENT -> ALREADY_DELETED"
    )
    print("Test 5 (/deluser records previous_state distinctly for PRESENT vs ABSENT accounts) PASSED")

    print("\nALL SECURITY ACTION AUDIT FIELD REGRESSION TESTS PASSED")


if __name__ == "__main__":
    main()
