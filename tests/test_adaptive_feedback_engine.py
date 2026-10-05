import asyncio
import dataclasses
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.adaptive_feedback as af
from config.manager import TceConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from database.sqlite_pool import SQLiteWriteWorker
import modules.threat_correlation_engine as tce


def _classify(source_module, category, **kw):
    ev = tce.CorrelationCandidateEvent(
        event_id=kw.pop("event_id", "e1"), timestamp=0.0, category=category, severity="MEDIUM",
        message="m", source_module=source_module, **kw,
    )
    return ev


async def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "rtsa.db")
        worker = SQLiteWriteWorker(db_path=db_path, flush_interval_seconds=0.05)
        await worker.start()

        cfg = TceConfig()

        ev = _classify("webshell_detector", "FILE_INTEGRITY_CHANGE", project="siteA")
        classified = tce.classify_event(
            ev, cfg, adaptive_store=None,
            adaptive_config=af.AdaptiveFeedbackConfig(
                enabled=True, collect_feedback=True, aggregate_feedback=True, apply_weights=True,
                enforce_acknowledgement=af.REQUIRED_ACKNOWLEDGEMENT,
            ),
            server_scope="host1",
        )
        assert classified.kind == "Webshell Signature"
        assert classified.weight == 50
        classified2 = tce.classify_event(ev, cfg)
        assert classified2.weight == 50
        print(
            "Test 1 [SQLITE / STORE UNAVAILABLE NEVER BLOCKS TCE SCORING] (classify_event with a None "
            "adaptive_store, or no adaptive params at all, scores normally using the static base weight, "
            "identical to before adaptive wiring existed) PASSED"
        )

        store = af.AdaptiveWeightStore()
        adaptive_cfg_observe = af.AdaptiveFeedbackConfig(
            enabled=True, collect_feedback=True, aggregate_feedback=True, apply_weights=False, min_samples=1,
        )
        af.apply_verdict(
            store, kind="Webshell Signature", project="siteA", server="host1",
            verdict=af.VERDICT_TRUE_POSITIVE, config=adaptive_cfg_observe, now=time.time(),
        )
        lookup = af.get_weight(store, kind="Webshell Signature", project="siteA", server="host1", base_weight=50, config=adaptive_cfg_observe)
        assert lookup.multiplier != 1.0, "sanity: the store really did learn something"
        classified_observe = tce.classify_event(
            ev, cfg, adaptive_store=store, adaptive_config=adaptive_cfg_observe, server_scope="host1",
        )
        assert classified_observe.weight == 50, "apply_weights=False must never change the applied weight"
        print(
            "Test 2 [APPLY_WEIGHTS=FALSE NEVER ALTERS PRODUCTION SCORE] (even though the adaptive store "
            "has already learned a non-default multiplier for this exact kind/scope, classify_event's "
            "applied weight with apply_weights=False is unchanged from the static base weight) PASSED"
        )

        adaptive_cfg_enforce = af.AdaptiveFeedbackConfig(
            enabled=True, collect_feedback=True, aggregate_feedback=True, apply_weights=True,
            enforce_acknowledgement=af.REQUIRED_ACKNOWLEDGEMENT, min_samples=1,
        )
        store2 = af.AdaptiveWeightStore()
        af.apply_verdict(
            store2, kind="Webshell Signature", project="siteA", server="host1",
            verdict=af.VERDICT_TRUE_POSITIVE, config=adaptive_cfg_enforce, now=time.time(),
        )
        classified_enforce = tce.classify_event(
            ev, cfg, adaptive_store=store2, adaptive_config=adaptive_cfg_enforce, server_scope="host1",
        )
        assert classified_enforce.weight != 50, "apply_weights=True with a valid acknowledgement must apply the learned adaptive multiplier"
        print(
            "Test 3 [APPLY_WEIGHTS=TRUE + VALID ACKNOWLEDGEMENT APPLIES THE LEARNED MULTIPLIER] (positive "
            "control -- proves the injection point genuinely changes production weight when apply_weights "
            "is true and acknowledged, so Test 2's no-change result is a real guarantee and not a "
            "broken/no-op code path) PASSED"
        )

        adaptive_cfg_unacked = af.AdaptiveFeedbackConfig(
            enabled=True, collect_feedback=True, aggregate_feedback=True, apply_weights=True,
            enforce_acknowledgement="", min_samples=1,
        )
        store3 = af.AdaptiveWeightStore()
        af.apply_verdict(
            store3, kind="Webshell Signature", project="siteA", server="host1",
            verdict=af.VERDICT_TRUE_POSITIVE, config=adaptive_cfg_unacked, now=time.time(),
        )
        classified_unacked = tce.classify_event(
            ev, cfg, adaptive_store=store3, adaptive_config=adaptive_cfg_unacked, server_scope="host1",
        )
        assert classified_unacked.weight == 50, "apply_weights=True without a valid acknowledgement must fall back to the static weight"
        assert adaptive_cfg_unacked.should_apply_weights is False
        assert adaptive_cfg_unacked.production_status == af.STATUS_STATIC_ONLY
        assert "acknowledgement" in adaptive_cfg_unacked.production_status_reason.lower()
        print(
            "Test 3b [APPLY_WEIGHTS=TRUE + MISSING ACKNOWLEDGEMENT FALLS BACK TO STATIC WEIGHT] (a learned "
            "multiplier exists and apply_weights is true, but enforce_acknowledgement is missing/invalid, "
            "so classify_event still scores with the static base weight and production_status_reason "
            "names the missing acknowledgement) PASSED"
        )

        correlated_event = BaseEvent(
            source_module="tce", category=EventCategory.CORRELATED_THREAT, severity=Severity.HIGH,
            message="Threat: Possible Webshell", event_id="inc-multi",
            metadata={
                "label": "Possible Webshell", "confidence": 78, "correlation_id": "inc-multi",
                "project": "example.com",
                "score_breakdown": [
                    {"kind": "Webshell Signature", "weight": 50, "occurrences": 1, "detail": "a", "event_id": "e1"},
                    {"kind": "Process anomaly", "weight": 15, "occurrences": 1, "detail": "b", "event_id": "e2"},
                    {"kind": "Outbound anomaly", "weight": 13, "occurrences": 2, "detail": "c", "event_id": "e3"},
                ],
            },
        )
        worker.enqueue_event(correlated_event)
        await asyncio.sleep(0.3)

        resolved = tce.resolve_incident_contributors(db_path, "inc-multi", cfg, server_scope="host1")
        assert resolved is not None
        assert resolved.is_correlated is True
        assert {c.kind for c in resolved.contributors} == {"Webshell Signature", "Process anomaly", "Outbound anomaly"}
        assert resolved.total_score == 78
        assert resolved.tier == "Possible Webshell"
        assert resolved.project == "example.com"
        print(
            "Test 4 [CORRELATED INCIDENT RESOLVES ALL CONTRIBUTING KINDS] (an incident backed by a "
            "3-detector CORRELATED_THREAT event resolves to all 3 contributing kinds, not just one, "
            "with the incident's own stored score/tier/project carried through) PASSED"
        )

        single_event = BaseEvent(
            source_module="webshell_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
            severity=Severity.HIGH, message="single alert", event_id="inc-single",
            metadata={"project": "solo.com"},
        )
        worker.enqueue_event(single_event)
        await asyncio.sleep(0.3)
        resolved_single = tce.resolve_incident_contributors(db_path, "inc-single", cfg, server_scope="host1")
        assert resolved_single is not None
        assert resolved_single.is_correlated is False
        assert len(resolved_single.contributors) == 1
        assert resolved_single.contributors[0].kind == "Webshell Signature"
        print(
            "Test 5 [SINGLE-EVENT INCIDENT RESOLVES TO ONE CONTRIBUTOR] (an incident that never went "
            "through TCE correlation still resolves via classify_event() on the raw event itself -- "
            "feedback is never limited to correlation_id-bearing incidents only) PASSED"
        )

        assert tce.resolve_incident_contributors(db_path, "does-not-exist", cfg, server_scope="host1") is None
        print(
            "Test 6 [UNKNOWN INCIDENT ID RESOLVES SAFELY TO NONE] (a nonexistent incident_id returns "
            "None instead of raising, letting callers report a clean 'not found' message) PASSED"
        )

        adaptive_cfg_rt = af.AdaptiveFeedbackConfig(
            enabled=True, collect_feedback=True, aggregate_feedback=True, apply_weights=True,
            enforce_acknowledgement=af.REQUIRED_ACKNOWLEDGEMENT, min_samples=1,
        )
        for kind in ("Webshell Signature", "Process anomaly", "Outbound anomaly"):
            worker.enqueue_adaptive_feedback(
                incident_id="inc-multi", correlation_id="inc-multi", kind=kind,
                scope_key="project:example.com", project="example.com", server="host1",
                verdict=af.VERDICT_TRUE_POSITIVE, action=None, source="feedback_command",
                requested_by="tester", notes="round trip test",
            )
        await asyncio.sleep(0.3)

        rows = tce.fetch_adaptive_feedback_since(db_path, 0)
        assert len(rows) == 3

        cfg_rt = dataclasses.replace(cfg, adaptive_detection=adaptive_cfg_rt)
        engine = tce.ThreatCorrelationEngine(EventBus(), cfg_rt)
        engine.attach_db_worker(worker)

        changes = engine._apply_pending_feedback(rows)
        assert len(changes) == 3
        for change in changes:
            worker.enqueue_adaptive_weight_change(
                kind=change.kind, scope_key=change.scope_key, old_multiplier=change.old_multiplier,
                new_multiplier=change.new_multiplier, delta=change.delta, sample_count=change.sample_count,
                verdict=change.verdict, reason=change.reason,
            )
        await asyncio.sleep(0.3)

        state = tce.explain_kind_state(
            db_path, kind="Webshell Signature", base_weight=50, project="example.com", server="host1",
            config=adaptive_cfg_rt,
        )
        assert state.has_candidate is True
        assert state.candidate_multiplier > 1.0
        assert state.fallback_level == "project"
        assert state.sample_count == 1
        assert state.last_changed_at is not None
        assert state.production_weight(adaptive_cfg_rt) == state.candidate_weight, (
            "apply_weights=True + valid acknowledgement must route production_weight through the candidate"
        )
        adaptive_cfg_rt_unacked = dataclasses.replace(adaptive_cfg_rt, enforce_acknowledgement="")
        assert state.production_weight(adaptive_cfg_rt_unacked) == float(state.base_weight), (
            "an invalid acknowledgement must route production_weight back to the static base weight"
        )
        print(
            "Test 7 [FULL ROUND TRIP: FEEDBACK -> AGGREGATION -> WEIGHT HISTORY -> EXPLAIN] (three raw "
            "feedback rows are turned into three audited weight_history rows by the same aggregation "
            "logic TCE runs periodically, explain_kind_state reads back the resulting candidate "
            "multiplier/scope/sample count correctly, and production_weight() correctly gates on "
            "apply_weights + acknowledgement) PASSED"
        )

        adaptive_cfg_fb = af.AdaptiveFeedbackConfig(
            enabled=True, collect_feedback=True, aggregate_feedback=True, apply_weights=True,
            enforce_acknowledgement=af.REQUIRED_ACKNOWLEDGEMENT, min_samples=1,
        )
        worker.enqueue_adaptive_weight_change(
            kind="Reverse Shell", scope_key="server:host1", old_multiplier=1.0, new_multiplier=1.1,
            delta=0.1, sample_count=1, verdict="TRUE_POSITIVE", reason="server-level test",
        )
        await asyncio.sleep(0.3)
        state_fb = tce.explain_kind_state(
            db_path, kind="Reverse Shell", base_weight=50, project="unrelated-project", server="host1",
            config=adaptive_cfg_fb,
        )
        assert state_fb.fallback_level == "server"
        assert state_fb.candidate_multiplier == 1.1
        state_default = tce.explain_kind_state(
            db_path, kind="Reverse Shell", base_weight=50, project=None, server=None, config=adaptive_cfg_fb,
        )
        assert state_default.fallback_level == "default"
        assert state_default.has_candidate is False
        assert state_default.candidate_multiplier == 1.0
        print(
            "Test 8 [EXPLAIN SCOPE FALLBACK PROJECT -> SERVER -> GLOBAL] (a kind with only server-level "
            "history is found via fallback for an unrelated project on the same server, and falls all "
            "the way to the untouched default when neither project nor server match anything) PASSED"
        )

        adaptive_cfg_no_aggregation = af.AdaptiveFeedbackConfig(
            enabled=True, collect_feedback=True, aggregate_feedback=False, apply_weights=True,
            enforce_acknowledgement=af.REQUIRED_ACKNOWLEDGEMENT, min_samples=1,
        )
        state_still_readable = tce.explain_kind_state(
            db_path, kind="Reverse Shell", base_weight=50, project="unrelated-project", server="host1",
            config=adaptive_cfg_no_aggregation,
        )
        assert state_still_readable.has_candidate is True
        assert state_still_readable.candidate_multiplier == 1.1, "existing weight_history stays fully readable even with aggregate_feedback=False"
        no_new_change = af.apply_verdict(
            af.AdaptiveWeightStore(), kind="Reverse Shell", project="unrelated-project", server="host1",
            verdict=af.VERDICT_TRUE_POSITIVE, config=adaptive_cfg_no_aggregation, now=time.time(),
        )
        assert no_new_change is None, "aggregate_feedback=False must block any new aggregation"
        print(
            "Test 9 [AGGREGATE_FEEDBACK=FALSE PRESERVES READABLE HISTORY WITHOUT NEW AGGREGATION] "
            "(existing weight_history rows remain fully visible through explain_kind_state, but "
            "apply_verdict refuses to create any new weight change while aggregate_feedback is false) PASSED"
        )

        await worker.stop()

    print("\nALL ADAPTIVE FEEDBACK ENGINE (TCE integration) TESTS PASSED")


asyncio.run(main())
