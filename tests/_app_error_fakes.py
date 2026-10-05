from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.manager import ApplicationErrorTrackerConfig
from core.app_error_engine import AppErrorEngine
from core.app_error_model import AppErrorEvent, compute_fingerprint
from core.pipeline_metrics import APP_ERROR_COUNTERS, APP_ERROR_GAUGES, APP_ERROR_LATENCIES, PipelineMetrics

T0 = 1_800_000_000.0
SERVER = "srv2"
_SEQ = [0]


class Clock:
    def __init__(self, t: float = T0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> float:
        self.t += seconds
        return self.t


def config(**sections: Any) -> ApplicationErrorTrackerConfig:
    return ApplicationErrorTrackerConfig(enabled=True, **sections)


def make_engine(cfg: Optional[ApplicationErrorTrackerConfig] = None, clock: Optional[Clock] = None):
    clock = clock or Clock()
    metrics = PipelineMetrics(APP_ERROR_COUNTERS, APP_ERROR_GAUGES, APP_ERROR_LATENCIES)
    engine = AppErrorEngine(cfg or config(), clock=clock, metrics=metrics, server=SERVER)
    return engine, clock, metrics


def make_event(
    clock: Clock, project: str = "disdik", error_type: str = "TypeError", message: str = "Cannot read properties of undefined", error_class: str = "EXCEPTION",
    count: int = 1, source_log: str = "/home/u/logs/err.log", timing: str = "REALTIME", event_time: Optional[float] = None, domain: Optional[str] = None,
    route: str = "", status: Optional[int] = None, service: str = "api", frames: Optional[List[str]] = None, **extra: Any,
) -> AppErrorEvent:
    _SEQ[0] += 1
    when = clock.t if event_time is None else event_time
    return AppErrorEvent(
        event_id=extra.pop("event_id", f"ev{_SEQ[0]}"), event_time=when, observed_at=clock.t, processed_at=clock.t, server=SERVER, project=project,
        error_type=error_type, error_message=message, fingerprint=compute_fingerprint(project, service, error_type, message, frames or []),
        error_class=error_class, domain=domain if domain is not None else f"{project}.example.com", service=service, count=count, source_log=source_log,
        http_path=route, http_status=status, timing_status=timing, **extra,
    )


def kinds(notes) -> List[str]:
    return [n.kind for n in notes]


def run_events(engine: AppErrorEngine, events) -> List[Any]:
    notes: List[Any] = []
    for event in events:
        notes.extend(engine.ingest(event).notifications)
    return notes


def counters(metrics: PipelineMetrics) -> Dict[str, int]:
    return metrics.snapshot()["counters"]
