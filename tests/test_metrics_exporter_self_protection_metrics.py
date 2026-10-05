import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.event_bus import EventBus
from core.metrics_exporter import MetricsExporter
from core.module_profiler import ModuleProfiler


class FakeDb:
    stats = {"written": 0, "dropped": 0, "queue_size": 0}


class FakeSupervisor:
    stats = {}


def main():
    ModuleProfiler._registry.clear()
    profiler = ModuleProfiler("test_probe_module")
    profiler.record_event(published=7, processed=5)
    profiler.record_subprocess(3)
    profiler.record_error()

    exporter = MetricsExporter(EventBus(), FakeDb(), FakeSupervisor())
    rendered = exporter._render()

    assert 'rtsa_module_events_published_total{module="test_probe_module"} 7' in rendered, rendered
    assert 'rtsa_module_events_processed_total{module="test_probe_module"} 5' in rendered, rendered
    assert 'rtsa_module_subprocess_total{module="test_probe_module"} 3' in rendered, rendered
    assert 'rtsa_module_errors_total{module="test_probe_module"} 1' in rendered, rendered
    print("Test 1 (per-module events/subprocess/error counters exposed, FIM events/sec derivable) PASSED")

    assert "rtsa_process_cpu_percent" in rendered, "CPU percent metric must be exposed (section 28)"
    assert "rtsa_process_memory_percent" in rendered, "RSS memory percent metric must be exposed (section 28)"
    print("Test 2 (CPU/RSS memory percent gauges exposed) PASSED")

    ModuleProfiler._registry.clear()
    print("\nALL SELF-PROTECTION METRICS TESTS PASSED")


main()
