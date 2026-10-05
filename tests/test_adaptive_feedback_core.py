import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.adaptive_feedback import (
    REQUIRED_ACKNOWLEDGEMENT, AdaptiveFeedbackConfig, AdaptiveWeightStore,
    VERDICT_BENIGN, VERDICT_FALSE_POSITIVE, VERDICT_INCONCLUSIVE, VERDICT_TRUE_POSITIVE,
    VERDICT_UNKNOWN, apply_verdict, get_weight,
)


def main() -> None:
    cfg = AdaptiveFeedbackConfig(
        enabled=True, collect_feedback=True, aggregate_feedback=True, apply_weights=True,
        enforce_acknowledgement=REQUIRED_ACKNOWLEDGEMENT, min_samples=3, max_weight_delta_per_period=0.06,
        weight_min=0.5, weight_max=1.5, default_multiplier=1.0,
        history_decay_half_life_days=30.0, aggregation_interval_seconds=300.0,
    )

    store = AdaptiveWeightStore()
    now = 1_000_000.0
    for _ in range(10):
        result = apply_verdict(
            store, kind="Process anomaly", project="siteA", server="host1",
            verdict=VERDICT_UNKNOWN, config=cfg, now=now,
        )
        assert result is None
    lookup = get_weight(store, kind="Process anomaly", project="siteA", server="host1", base_weight=15, config=cfg, now=now)
    assert lookup.multiplier == cfg.default_multiplier
    assert lookup.sample_count == 0
    print("Test 1 [UNKNOWN NEVER MODIFIES WEIGHT] (10 UNKNOWN verdicts leave multiplier at default and record zero samples) PASSED")

    store = AdaptiveWeightStore()
    for _ in range(10):
        result = apply_verdict(
            store, kind="Process anomaly", project="siteA", server="host1",
            verdict=VERDICT_INCONCLUSIVE, config=cfg, now=now,
        )
        assert result is None
    lookup = get_weight(store, kind="Process anomaly", project="siteA", server="host1", base_weight=15, config=cfg, now=now)
    assert lookup.multiplier == cfg.default_multiplier
    assert lookup.sample_count == 0
    print("Test 2 [INCONCLUSIVE NEVER MODIFIES WEIGHT] (10 INCONCLUSIVE verdicts leave multiplier at default and record zero samples) PASSED")

    store = AdaptiveWeightStore()
    for i in range(cfg.min_samples - 1):
        result = apply_verdict(
            store, kind="Webshell Signature", project="siteA", server="host1",
            verdict=VERDICT_TRUE_POSITIVE, config=cfg, now=now,
        )
        assert result is None, f"adjustment must not apply before min_samples (iteration {i})"
    result = apply_verdict(
        store, kind="Webshell Signature", project="siteA", server="host1",
        verdict=VERDICT_TRUE_POSITIVE, config=cfg, now=now,
    )
    assert result is not None, "the min_samples-th verdict must finally apply an adjustment"
    assert result.sample_count == cfg.min_samples
    print(
        "Test 3 [MIN SAMPLES GATES ADJUSTMENT] (no weight movement for the first min_samples-1 "
        "verdicts; the min_samples-th verdict is the first to move the multiplier) PASSED"
    )

    store = AdaptiveWeightStore()
    t = now
    for _ in range(200):
        apply_verdict(
            store, kind="Webshell Signature", project="siteA", server="host1",
            verdict=VERDICT_TRUE_POSITIVE, config=cfg, now=t,
        )
        t += cfg.aggregation_interval_seconds + 1
    lookup = get_weight(store, kind="Webshell Signature", project="siteA", server="host1", base_weight=50, config=cfg, now=t)
    assert lookup.multiplier <= cfg.weight_max, f"multiplier {lookup.multiplier} exceeded weight_max"
    assert lookup.multiplier == cfg.weight_max
    print("Test 4 [WEIGHT CANNOT EXCEED MAX] (repeated TRUE_POSITIVE across many periods clamps at weight_max) PASSED")

    store = AdaptiveWeightStore()
    t = now
    for _ in range(200):
        apply_verdict(
            store, kind="Process anomaly", project="siteA", server="host1",
            verdict=VERDICT_FALSE_POSITIVE, config=cfg, now=t,
        )
        t += cfg.aggregation_interval_seconds + 1
    lookup = get_weight(store, kind="Process anomaly", project="siteA", server="host1", base_weight=15, config=cfg, now=t)
    assert lookup.multiplier >= cfg.weight_min, f"multiplier {lookup.multiplier} went below weight_min"
    assert lookup.multiplier == cfg.weight_min
    print("Test 5 [WEIGHT CANNOT GO BELOW MIN] (repeated FALSE_POSITIVE across many periods clamps at weight_min, never suppressed to zero) PASSED")

    store = AdaptiveWeightStore()
    t = now
    for _ in range(50):
        apply_verdict(
            store, kind="Webshell Signature", project="siteA", server="host1",
            verdict=VERDICT_TRUE_POSITIVE, config=cfg, now=t,
        )
        t += cfg.aggregation_interval_seconds + 1
    project_lookup = get_weight(store, kind="Webshell Signature", project="siteA", server="host1", base_weight=50, config=cfg, now=t)
    global_lookup = get_weight(store, kind="Webshell Signature", project=None, server=None, base_weight=50, config=cfg, now=t)
    assert project_lookup.multiplier != cfg.default_multiplier, "project scope should have learned something"
    assert global_lookup.multiplier == cfg.default_multiplier, "global scope must remain untouched by project-only feedback"
    print("Test 6 [PROJECT SCOPE NEVER MUTATES GLOBAL SCOPE] (feedback scoped to project siteA leaves the global-scope multiplier at default) PASSED")

    store = AdaptiveWeightStore()
    t = now
    for _ in range(50):
        apply_verdict(
            store, kind="Reverse Shell", project=None, server="host1",
            verdict=VERDICT_TRUE_POSITIVE, config=cfg, now=t,
        )
        t += cfg.aggregation_interval_seconds + 1
    unrelated_project_lookup = get_weight(
        store, kind="Reverse Shell", project="some-other-project", server="host1", base_weight=50, config=cfg, now=t,
    )
    assert unrelated_project_lookup.fallback_level == "server"
    assert unrelated_project_lookup.multiplier != cfg.default_multiplier
    no_scope_lookup = get_weight(store, kind="Reverse Shell", project=None, server=None, base_weight=50, config=cfg, now=t)
    assert no_scope_lookup.fallback_level == "default"
    assert no_scope_lookup.multiplier == cfg.default_multiplier
    print(
        "Test 7 [FALLBACK PROJECT -> SERVER -> GLOBAL] (a project with no history for this kind falls "
        "back to the server-level multiplier; with no server match either, falls back to the untouched "
        "global default) PASSED"
    )

    lookup = get_weight(None, kind="Webshell Signature", project="siteA", server="host1", base_weight=50, config=cfg, now=now)
    assert lookup.multiplier == cfg.default_multiplier
    assert lookup.effective_weight == 50.0
    assert lookup.fallback_level == "default"
    print(
        "Test 8 [CACHE MISS / UNAVAILABLE STORE FALLS BACK SAFELY] (a None store -- e.g. never hydrated "
        "because of a persistence failure -- returns the safe default multiplier 1.0 without raising) PASSED"
    )

    store = AdaptiveWeightStore()
    for _ in range(3):
        apply_verdict(
            store, kind="Webshell Signature", project="siteA", server="host1",
            verdict=VERDICT_TRUE_POSITIVE, config=cfg, now=now,
        )
    baseline = get_weight(store, kind="Webshell Signature", project="siteA", server="host1", base_weight=50, config=cfg, now=now)
    for i in range(200):
        apply_verdict(
            store, kind="Webshell Signature", project="siteA", server="host1",
            verdict=VERDICT_TRUE_POSITIVE, config=cfg, now=now + i * 0.01,
        )
    after_flood = get_weight(store, kind="Webshell Signature", project="siteA", server="host1", base_weight=50, config=cfg, now=now + 2.0)
    total_period_delta = abs(after_flood.multiplier - baseline.multiplier)
    assert total_period_delta <= cfg.max_weight_delta_per_period + 1e-9, (
        f"period cap bypassed: moved {total_period_delta} within a single aggregation period"
    )
    print(
        "Test 9 [PER-PERIOD CAP CANNOT BE BYPASSED BY REPEATED FEEDBACK] (200 TRUE_POSITIVE verdicts "
        "fired within one aggregation period move the multiplier by at most max_weight_delta_per_period "
        "total, not 200x the per-sample step) PASSED"
    )

    store = AdaptiveWeightStore()
    disabled_cfg = AdaptiveFeedbackConfig(enabled=False, collect_feedback=True, aggregate_feedback=True, apply_weights=False)
    result = apply_verdict(
        store, kind="Webshell Signature", project="siteA", server="host1",
        verdict=VERDICT_TRUE_POSITIVE, config=disabled_cfg, now=now,
    )
    assert result is None
    assert store.get("Webshell Signature", "project:siteA") is None
    print("Test 10 [DISABLED ENGINE NEVER TOUCHES THE WEIGHT STORE] (adaptive_detection.enabled=false means apply_verdict is a pure no-op) PASSED")

    store = AdaptiveWeightStore()
    for _ in range(3):
        apply_verdict(
            store, kind="Process anomaly", project="siteA", server="host1",
            verdict=VERDICT_BENIGN, config=cfg, now=now,
        )
    lookup = get_weight(store, kind="Process anomaly", project="siteA", server="host1", base_weight=15, config=cfg, now=now)
    assert lookup.multiplier < cfg.default_multiplier
    print(
        "Test 11 [BENIGN NUDGES RELIABILITY DOWN] (BENIGN verdicts -- activity happened but was not "
        "malicious -- push the multiplier below default, same direction as FALSE_POSITIVE but weaker) PASSED"
    )

    store = AdaptiveWeightStore()
    aggregation_off_cfg = AdaptiveFeedbackConfig(
        enabled=True, collect_feedback=True, aggregate_feedback=False, apply_weights=False,
        min_samples=3, max_weight_delta_per_period=0.06, weight_min=0.5, weight_max=1.5,
        default_multiplier=1.0, history_decay_half_life_days=30.0, aggregation_interval_seconds=300.0,
    )
    for _ in range(10):
        result = apply_verdict(
            store, kind="Webshell Signature", project="siteA", server="host1",
            verdict=VERDICT_TRUE_POSITIVE, config=aggregation_off_cfg, now=now,
        )
        assert result is None
    assert store.get("Webshell Signature", "project:siteA") is None
    print(
        "Test 12 [AGGREGATE_FEEDBACK=FALSE DISABLES AGGREGATION EVEN WHEN ENABLED] (enabled=True but "
        "aggregate_feedback=False means apply_verdict remains a pure no-op) PASSED"
    )

    print("\nALL ADAPTIVE FEEDBACK CORE (core/adaptive_feedback.py) TESTS PASSED")


main()
