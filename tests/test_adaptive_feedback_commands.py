import asyncio
import os
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.adaptive_feedback as af
from config.manager import (
    CloudflareConfig, DatabaseConfig, DiscordConfig, ModulesConfig, ResponseEngineConfig,
    RTSAConfig, TceConfig,
)
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from database.sqlite_pool import SQLiteWriteWorker
from discord_integration.bot import RTSABot, _VALID_INCIDENT_ID


class FakeDb:
    def __init__(self):
        self.actions = []
        self.feedback_calls = []
        self.weight_change_calls = []

    def enqueue_action(self, *a, **k):
        self.actions.append((a, k))

    def enqueue_incident_create(self, **k):
        pass

    def enqueue_incident_update(self, *a, **k):
        pass

    def enqueue_adaptive_feedback(self, **k):
        self.feedback_calls.append(k)

    def enqueue_adaptive_weight_change(self, **k):
        self.weight_change_calls.append(k)


_DEFAULT_TEST_ADAPTIVE_CFG = af.AdaptiveFeedbackConfig(
    enabled=True, collect_feedback=True, aggregate_feedback=True, apply_weights=False,
)


def make_bot(db_path: str, db: FakeDb, adaptive_cfg: af.AdaptiveFeedbackConfig = None) -> RTSABot:
    cfg = RTSAConfig(
        database=DatabaseConfig(path=db_path),
        response_engine=ResponseEngineConfig(detection_only=False),
        cloudflare=CloudflareConfig(enabled=False),
        modules=ModulesConfig(tce=TceConfig(
            adaptive_detection=adaptive_cfg if adaptive_cfg is not None else _DEFAULT_TEST_ADAPTIVE_CFG,
        )),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=db, supervisor=None)


async def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "rtsa.db")
        writer = SQLiteWriteWorker(db_path=db_path, flush_interval_seconds=0.05)
        await writer.start()

        correlated_event = BaseEvent(
            source_module="tce", category=EventCategory.CORRELATED_THREAT, severity=Severity.HIGH,
            message="Threat: Possible Webshell", event_id="inc-cmd-multi",
            metadata={
                "label": "Possible Webshell", "confidence": 78, "correlation_id": "inc-cmd-multi",
                "project": "example.com",
                "score_breakdown": [
                    {"kind": "Webshell Signature", "weight": 50, "occurrences": 1, "detail": "a", "event_id": "e1"},
                    {"kind": "Process anomaly", "weight": 15, "occurrences": 1, "detail": "b", "event_id": "e2"},
                ],
            },
        )
        writer.enqueue_event(correlated_event)
        await asyncio.sleep(0.3)
        await writer.stop()

        db = FakeDb()
        bot = make_bot(db_path, db)

        assert not af.is_valid_verdict("MAYBE")
        assert af.is_valid_verdict("TRUE_POSITIVE")
        assert not _VALID_INCIDENT_ID.match("foo; rm -rf /")
        assert not _VALID_INCIDENT_ID.match("../../etc/passwd")
        assert not _VALID_INCIDENT_ID.match("a" * 200)
        assert _VALID_INCIDENT_ID.match("inc-cmd-multi")
        print(
            "Test 1 [INCIDENT ID / VERDICT VALIDATION] (shell-metacharacter, path-traversal, and "
            "oversized incident IDs are all rejected by the same regex gate real Discord input passes "
            "through before any resolution happens; a bogus verdict string is rejected too) PASSED"
        )

        result = await bot._record_feedback(
            "inc-cmd-multi", af.VERDICT_TRUE_POSITIVE, requested_by="tester", notes="looks bad",
        )
        assert result.startswith("✅"), result
        assert len(db.feedback_calls) == 2, db.feedback_calls
        recorded_kinds = {c["kind"] for c in db.feedback_calls}
        assert recorded_kinds == {"Webshell Signature", "Process anomaly"}
        for c in db.feedback_calls:
            assert c["verdict"] == af.VERDICT_TRUE_POSITIVE
            assert c["source"] == "feedback_command"
            assert c["incident_id"] == "inc-cmd-multi"
            assert c["correlation_id"] == "inc-cmd-multi"
            assert c["project"] == "example.com"
        print(
            "Test 2 [/feedback RESOLVES AND RECORDS ALL CONTRIBUTING KINDS] (/feedback on a correlated "
            "incident writes one adaptive_feedback row per contributing detector kind, all carrying the "
            "same explicit verdict, correlation_id, and project scope) PASSED"
        )

        db.feedback_calls.clear()
        not_found = await bot._record_feedback(
            "does-not-exist-at-all", af.VERDICT_FALSE_POSITIVE, requested_by="tester", notes=None,
        )
        assert not_found.startswith("❌"), not_found
        assert db.feedback_calls == []
        print(
            "Test 3 [/feedback ON UNKNOWN INCIDENT WRITES NOTHING] (an incident_id with no matching "
            "event record produces a clean failure message and zero adaptive_feedback rows) PASSED"
        )

        db.feedback_calls.clear()
        await bot._record_incident_action_feedback("inc-cmd-multi", af.ACTION_BAN, "operator1")
        assert len(db.feedback_calls) == 2
        for c in db.feedback_calls:
            assert c["verdict"] == af.VERDICT_UNKNOWN, (
                f"BAN button must never record a TRUE_POSITIVE verdict automatically, got {c['verdict']}"
            )
            assert c["action"] == af.ACTION_BAN
            assert c["source"] == "button_action"
        print(
            "Test 4 [BAN BUTTON NEVER MEANS TRUE_POSITIVE] (clicking Ban on an incident records "
            "context-only feedback rows with verdict=UNKNOWN and action=BAN -- never an automatic "
            "TRUE_POSITIVE verdict that would train the adaptive model) PASSED"
        )

        db.feedback_calls.clear()
        await bot._record_incident_action_feedback("inc-cmd-multi", af.ACTION_IGNORE, "operator2")
        assert len(db.feedback_calls) == 2
        for c in db.feedback_calls:
            assert c["verdict"] == af.VERDICT_UNKNOWN, (
                f"IGNORE button must never record a FALSE_POSITIVE verdict automatically, got {c['verdict']}"
            )
            assert c["action"] == af.ACTION_IGNORE
            assert c["source"] == "button_action"
        print(
            "Test 5 [IGNORE BUTTON NEVER MEANS FALSE_POSITIVE] (clicking Ignore records context-only "
            "feedback rows with verdict=UNKNOWN and action=IGNORE -- never an automatic FALSE_POSITIVE "
            "verdict) PASSED"
        )

        for verdict in (af.VERDICT_UNKNOWN, af.VERDICT_INCONCLUSIVE):
            store = af.AdaptiveWeightStore()
            cfg = af.AdaptiveFeedbackConfig(
                enabled=True, collect_feedback=True, aggregate_feedback=True, apply_weights=True,
                enforce_acknowledgement=af.REQUIRED_ACKNOWLEDGEMENT, min_samples=1,
            )
            change = af.apply_verdict(
                store, kind="Webshell Signature", project="example.com", server="host1",
                verdict=verdict, config=cfg,
            )
            assert change is None, f"{verdict} must never produce a weight change record"
        print(
            "Test 6 [UNKNOWN/INCONCLUSIVE NEVER REACH THE WEIGHT STORE] (even if a context-only "
            "button-action row somehow got fed into aggregation, UNKNOWN and INCONCLUSIVE verdicts "
            "produce no weight_change record at all -- double protection alongside Tests 4/5) PASSED"
        )

        explanation = await bot._explain_incident("inc-cmd-multi")
        assert "ADAPTIVE DETECTION STATUS" in explanation
        assert "Enabled: Yes" in explanation
        assert "Feedback Collection: Yes" in explanation
        assert "Aggregation: Yes" in explanation
        assert "Apply To Production: No" in explanation
        assert "STATIC WEIGHT" in explanation
        assert "Webshell Signature: 50" in explanation
        assert "Process anomaly: 15" in explanation
        assert "ADAPTIVE CANDIDATE" in explanation
        assert "CURRENT PRODUCTION WEIGHT" in explanation
        assert "Incident Score" in explanation and "78" in explanation
        assert "Tier" in explanation and "Possible Webshell" in explanation
        assert "Production Status" in explanation and af.STATUS_STATIC_ONLY in explanation
        assert "Production Score Modified" in explanation and "No" in explanation
        assert "apply_weights is false" in explanation
        print(
            "Test 7 [/explain RENDERS FULL STATIC/CANDIDATE/PRODUCTION BREAKDOWN] (with apply_weights "
            "false -- the normal continuous-collection posture -- /explain shows static weights, "
            "candidate state, incident score/tier, and an explicit 'Production Score Modified: No' with "
            "the reason spelled out -- a full debugging/audit tool, not a bare weight lookup) PASSED"
        )

        not_found_explain = await bot._explain_incident("nonexistent-incident-id")
        assert not_found_explain.startswith("❌")
        print(
            "Test 8 [/explain ON UNKNOWN INCIDENT FAILS CLEANLY] (no traceback, no bogus zeroed-out "
            "breakdown -- a clear not-found message) PASSED"
        )

        disabled_db = FakeDb()
        disabled_bot = make_bot(db_path, disabled_db, af.AdaptiveFeedbackConfig(enabled=False))
        disabled_explain = await disabled_bot._explain_incident("inc-cmd-multi")
        assert "Enabled: No" in disabled_explain
        assert "nonaktif" in disabled_explain.lower()
        disabled_feedback = await disabled_bot._record_feedback(
            "inc-cmd-multi", af.VERDICT_TRUE_POSITIVE, requested_by="tester", notes=None,
        )
        assert disabled_feedback.startswith("❌")
        assert disabled_db.feedback_calls == []
        await disabled_bot._record_incident_action_feedback("inc-cmd-multi", af.ACTION_BAN, "operator1")
        assert disabled_db.feedback_calls == [], "enabled=false must also suppress context-only button feedback"
        print(
            "Test 9 [ENABLED=FALSE SAFELY DISABLES THE WHOLE SUBSYSTEM] (/explain, /feedback, and the "
            "Ban/Ignore context recorder all fail gracefully with a clear disabled-state message and "
            "write zero rows -- never a crash) PASSED"
        )

        no_collect_db = FakeDb()
        no_collect_bot = make_bot(
            db_path, no_collect_db,
            af.AdaptiveFeedbackConfig(enabled=True, collect_feedback=False, aggregate_feedback=True, apply_weights=False),
        )
        no_collect_result = await no_collect_bot._record_feedback(
            "inc-cmd-multi", af.VERDICT_TRUE_POSITIVE, requested_by="tester", notes=None,
        )
        assert no_collect_result.startswith("❌")
        assert no_collect_db.feedback_calls == []
        await no_collect_bot._record_incident_action_feedback("inc-cmd-multi", af.ACTION_BAN, "operator1")
        assert no_collect_db.feedback_calls == []
        print(
            "Test 10 [COLLECT_FEEDBACK=FALSE BLOCKS /feedback AND BUTTON CONTEXT RECORDING] (enabled=True "
            "but collect_feedback=False means /feedback returns a clear disabled message and the "
            "Ban/Ignore context recorder silently records nothing, with zero rows written) PASSED"
        )

        ack_db = FakeDb()
        ack_bot = make_bot(
            db_path, ack_db,
            af.AdaptiveFeedbackConfig(
                enabled=True, collect_feedback=True, aggregate_feedback=True, apply_weights=True,
                enforce_acknowledgement="",
            ),
        )
        ack_explanation = await ack_bot._explain_incident("inc-cmd-multi")
        assert "Acknowledgement Valid: No" in ack_explanation
        assert "Production Status" in ack_explanation and af.STATUS_STATIC_ONLY in ack_explanation
        assert "Production Score Modified" in ack_explanation and "No" in ack_explanation
        assert "acknowledgement" in ack_explanation.lower()
        print(
            "Test 11 [APPLY_WEIGHTS=TRUE + MISSING ACKNOWLEDGEMENT EXPOSED VIA /explain] (production "
            "scoring falls back to static weights and /explain names the missing/invalid acknowledgement "
            "as the exact reason -- no crash, no silent enforcement) PASSED"
        )

    print("\nALL ADAPTIVE FEEDBACK DISCORD COMMAND TESTS PASSED")


asyncio.run(main())
