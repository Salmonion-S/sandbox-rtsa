import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import (
    ConfigManager, ConfigValidationError, RTSAConfig, _build_dataclass,
    _migrate_legacy_adaptive_detection_config,
)
from core.adaptive_feedback import REQUIRED_ACKNOWLEDGEMENT


def _migrated(raw):
    _migrate_legacy_adaptive_detection_config(raw)
    return _build_dataclass(RTSAConfig, raw)


def _assert_no_adaptive_detection_errors(cfg):
    try:
        ConfigManager._validate_semantics(cfg)
    except ConfigValidationError as exc:
        assert "adaptive_detection" not in str(exc), (
            f"adaptive_detection config must not be the source of a validation error here: {exc}"
        )


def main() -> None:
    cfg_default = _build_dataclass(RTSAConfig, {})
    adaptive = cfg_default.adaptive_detection
    assert adaptive.enabled is False
    assert adaptive.collect_feedback is True
    assert adaptive.aggregate_feedback is True
    assert adaptive.apply_weights is False
    assert adaptive.should_apply_weights is False
    print("Scenario A [LIBRARY DEFAULT IS SAFE] (with no adaptive_detection section at all, enabled=False -- the subsystem never runs unless explicitly turned on) PASSED")

    raw_enforce = {"adaptive_detection": {"enabled": True, "mode": "enforce"}}
    cfg_enforce = _migrated(raw_enforce)
    assert cfg_enforce.adaptive_detection.collect_feedback is True
    assert cfg_enforce.adaptive_detection.aggregate_feedback is True
    assert cfg_enforce.adaptive_detection.apply_weights is True
    print("Scenario B [LEGACY mode=enforce MIGRATES TO apply_weights=True] (an old-style config file with mode=enforce still loads safely, mapped onto collect_feedback=True, aggregate_feedback=True, apply_weights=True) PASSED")

    raw_observe = {"adaptive_detection": {"enabled": True, "mode": "observe_only"}}
    cfg_observe = _migrated(raw_observe)
    assert cfg_observe.adaptive_detection.collect_feedback is True
    assert cfg_observe.adaptive_detection.aggregate_feedback is True
    assert cfg_observe.adaptive_detection.apply_weights is False
    print("Scenario C [LEGACY mode=observe_only MIGRATES TO apply_weights=False] (an old-style observe_only config maps onto collect_feedback=True, aggregate_feedback=True, apply_weights=False -- the exact new 'safe continuous collection' posture) PASSED")

    raw_explicit_wins = {
        "adaptive_detection": {"enabled": True, "mode": "enforce", "apply_weights": False},
    }
    cfg_explicit_wins = _migrated(raw_explicit_wins)
    assert cfg_explicit_wins.adaptive_detection.apply_weights is False, (
        "an explicit new-style field present alongside a legacy mode must always win over the legacy mapping"
    )
    print("Scenario D [EXPLICIT NEW FIELDS ALWAYS WIN OVER LEGACY mode] (mode=enforce is present, but an explicit apply_weights=False in the same file overrides the legacy-derived value) PASSED")

    raw_bogus_mode = {"adaptive_detection": {"enabled": True, "mode": "totally-not-a-real-mode"}}
    cfg_bogus = _migrated(raw_bogus_mode)
    assert cfg_bogus.adaptive_detection.collect_feedback is True
    assert cfg_bogus.adaptive_detection.aggregate_feedback is True
    assert cfg_bogus.adaptive_detection.apply_weights is False
    print("Scenario E [UNRECOGNIZED LEGACY mode VALUE IS IGNORED SAFELY] (an unknown mode string never crashes config load -- it is ignored and the dataclass defaults are used) PASSED")

    raw_target_shape = {
        "discord": {"enabled": False},
        "adaptive_detection": {
            "enabled": True, "collect_feedback": True, "aggregate_feedback": True,
            "apply_weights": False, "min_samples": 5, "max_weight_delta_per_period": 0.05,
            "weight_min": 0.5, "weight_max": 1.5, "history_decay_half_life_days": 30,
            "aggregation_interval_seconds": 300,
        },
    }
    cfg_target = _build_dataclass(RTSAConfig, raw_target_shape)
    assert cfg_target.adaptive_detection.enabled is True
    assert cfg_target.adaptive_detection.collect_feedback is True
    assert cfg_target.adaptive_detection.aggregate_feedback is True
    assert cfg_target.adaptive_detection.apply_weights is False
    assert cfg_target.adaptive_detection.should_apply_weights is False
    _assert_no_adaptive_detection_errors(cfg_target)
    print("Scenario F [TARGET SHAPE LOADS AND VALIDATES CLEANLY] (the exact deployment-recommended config -- enabled=true, apply_weights=false -- loads, has should_apply_weights=False, and its adaptive_detection section passes semantic validation cleanly) PASSED")

    raw_apply_no_ack = {
        "discord": {"enabled": False},
        "adaptive_detection": {"enabled": True, "apply_weights": True},
    }
    cfg_apply_no_ack = _build_dataclass(RTSAConfig, raw_apply_no_ack)
    _assert_no_adaptive_detection_errors(cfg_apply_no_ack)
    assert cfg_apply_no_ack.adaptive_detection.should_apply_weights is False, (
        "apply_weights=True without a valid enforce_acknowledgement must never actually apply weights"
    )
    print("Scenario G [apply_weights=TRUE WITHOUT ACKNOWLEDGEMENT NEVER RAISES, NEVER ENFORCES] (RTSA must not refuse to start over a missing acknowledgement -- validate_semantics only warns, and should_apply_weights stays False) PASSED")

    raw_apply_with_ack = {
        "discord": {"enabled": False},
        "adaptive_detection": {
            "enabled": True, "apply_weights": True, "enforce_acknowledgement": REQUIRED_ACKNOWLEDGEMENT,
        },
    }
    cfg_apply_with_ack = _build_dataclass(RTSAConfig, raw_apply_with_ack)
    _assert_no_adaptive_detection_errors(cfg_apply_with_ack)
    assert cfg_apply_with_ack.adaptive_detection.should_apply_weights is True
    print("Scenario H [apply_weights=TRUE + VALID ACKNOWLEDGEMENT ENABLES should_apply_weights] (a fully deliberate opt-in -- apply_weights=true and the exact required acknowledgement string -- is the only path that makes should_apply_weights True) PASSED")

    raw_bad_bounds = {"adaptive_detection": {"enabled": True, "min_samples": 0}}
    cfg_bad_bounds = _build_dataclass(RTSAConfig, raw_bad_bounds)
    try:
        ConfigManager._validate_semantics(cfg_bad_bounds)
        raise AssertionError("min_samples=0 must still be a hard validation error")
    except ConfigValidationError as exc:
        assert "min_samples" in str(exc)
    print("Scenario I [NUMERIC BOUND VALIDATION UNCHANGED] (min_samples/weight bounds/interval validation from before the refactor are still hard errors that block startup) PASSED")

    print("\nALL ADAPTIVE DETECTION CONFIGURATION MIGRATION TESTS PASSED")


main()
