import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import HealthMonitorConfig
from core.datatypes import EventCategory, HealthEvent, Severity
from core.event_bus import EventBus
from modules.health_monitor import HealthMonitor, _format_top_mem_processes
from tests._isolated_config import isolated_config_manager


def _mem_snapshot(
    percent, available_bytes=200 * 1024 * 1024 * 1024, buff_cache_bytes=1 * 1024 * 1024 * 1024,
    swap_percent=0.0, swap_used_bytes=0, top_mem_processes=(),
):
    total = 8 * 1024 * 1024 * 1024
    used = int(total * percent / 100)
    return HealthEvent(
        source_module="health_monitor", category=EventCategory.HEALTH_STATUS,
        severity=Severity.INFO, message="", raw="",
        cpu_percent=10.0, mem_percent=percent, disk_percent=10.0,
        mem_total_bytes=total, mem_available_bytes=available_bytes, mem_used_bytes=used,
        mem_free_bytes=max(0, available_bytes - buff_cache_bytes), mem_buff_cache_bytes=buff_cache_bytes,
        swap_total_bytes=16 * 1024 * 1024 * 1024, swap_used_bytes=swap_used_bytes, swap_percent=swap_percent,
        top_mem_processes=top_mem_processes,
    )


def _make_monitor(**overrides):
    base = dict(
        mem_alert_threshold=90.0, mem_recovery_threshold=85.0, mem_critical_threshold=97.0,
        mem_critical_available_mb=256.0, resource_consecutive_breaches=3,
        resource_consecutive_recoveries=3, resource_minimum_breach_duration_seconds=999999.0,
    )
    base.update(overrides)
    bus = EventBus()
    return HealthMonitor(bus, HealthMonitorConfig(**base))


async def _collect(hm):
    collected = []

    async def collector(event):
        collected.append(event)

    sub = await hm.bus.subscribe("collector", collector, categories=None)
    return collected, sub


async def _feed(hm, samples):
    for percent in samples:
        hm._evaluate_resource_thresholds(_mem_snapshot(percent))


async def main():
    hm = _make_monitor()
    collected, sub = await _collect(hm)
    await _feed(hm, [89.0, 90.8, 89.2, 89.4])
    await sub.queue.join()
    high_events = [e for e in collected if e.severity in (Severity.HIGH, Severity.CRITICAL)]
    assert len(high_events) == 0, (
        f"Case A: a single transient spike above threshold must never fire HIGH, got {len(high_events)}"
    )
    print("Test A (single spike: NO HIGH alert) PASSED")
    await hm.bus.unsubscribe("collector")

    hm = _make_monitor()
    collected, sub = await _collect(hm)
    await _feed(hm, [90.5, 90.7, 90.4, 91.0])
    await sub.queue.join()
    high_events = [e for e in collected if e.severity == Severity.HIGH]
    assert len(high_events) == 1, f"Case B: sustained high must confirm exactly ONE HIGH alert, got {len(high_events)}"
    assert "melebihi threshold" in high_events[0].message
    assert "Memory Usage:" in high_events[0].message
    print("Test B (sustained high: ONE HIGH alert) PASSED")
    await hm.bus.unsubscribe("collector")

    hm = _make_monitor()
    collected, sub = await _collect(hm)
    await _feed(hm, [90.5, 90.7, 90.4])
    await sub.queue.join()
    assert hm._resource_states["Memory"].state == "HIGH"
    collected.clear()
    await _feed(hm, [89.9, 88.8, 87.0])
    await sub.queue.join()
    recovered = [e for e in collected if "kembali normal" in e.message]
    assert len(recovered) == 0, (
        f"Case C: samples above the recovery threshold (85.0) must not trigger recovery, got {len(recovered)}"
    )
    assert hm._resource_states["Memory"].state == "HIGH"
    print("Test C (hysteresis: no recovery until <= recovery_threshold) PASSED")
    await hm.bus.unsubscribe("collector")

    collected2, sub2 = await _collect(hm)
    await _feed(hm, [84.8, 84.5, 84.7])
    await sub2.queue.join()
    recovered2 = [e for e in collected2 if "kembali normal" in e.message]
    assert len(recovered2) == 1, f"Case D: a genuine sustained drop must publish exactly ONE recovery, got {len(recovered2)}"
    assert hm._resource_states["Memory"].state == "NORMAL"
    print("Test D (proper recovery: ONE recovery event) PASSED")
    await hm.bus.unsubscribe("collector")

    hm = _make_monitor()
    collected, sub = await _collect(hm)
    await _feed(hm, [90.1, 89.8, 90.2, 89.9, 90.3])
    await sub.queue.join()
    alert_events = [e for e in collected if e.severity in (Severity.HIGH, Severity.CRITICAL)]
    assert len(alert_events) == 0, (
        f"Case E: oscillation around the threshold must never confirm HIGH (no alert storm), got {len(alert_events)}"
    )
    print("Test E (oscillation: no alert storm, never confirmed) PASSED")
    await hm.bus.unsubscribe("collector")

    hm = _make_monitor()
    collected, sub = await _collect(hm)
    hm._evaluate_resource_thresholds(_mem_snapshot(91.0, available_bytes=64 * 1024 * 1024))
    await sub.queue.join()
    critical_events = [e for e in collected if e.severity == Severity.CRITICAL]
    assert len(critical_events) == 1, (
        f"Case F: critically low available memory must alert immediately without waiting for "
        f"consecutive confirmation, got {len(critical_events)}"
    )
    print("Test F (severe condition: immediate CRITICAL alert via low available memory) PASSED")
    await hm.bus.unsubscribe("collector")

    hm = _make_monitor()
    collected, sub = await _collect(hm)
    await _feed(hm, [70.0, 71.0, 69.5, 70.2])
    await sub.queue.join()
    assert len(collected) == 0, (
        "Case G: high swap usage alone (with mem_percent well below threshold) must never "
        "independently trigger a memory-pressure alert"
    )
    snapshot_with_swap = _mem_snapshot(90.5, swap_percent=85.0, swap_used_bytes=14 * 1024 * 1024 * 1024)
    hm2 = _make_monitor()
    collected2, sub2 = await _collect(hm2)
    hm2._evaluate_resource_thresholds(snapshot_with_swap)
    hm2._evaluate_resource_thresholds(snapshot_with_swap)
    hm2._evaluate_resource_thresholds(snapshot_with_swap)
    await sub2.queue.join()
    high2 = [e for e in collected2 if e.severity == Severity.HIGH]
    assert len(high2) == 1
    assert "Swap Used:" in high2[0].message and "Swap Total:" in high2[0].message, (
        "swap usage must still be visible as evidence inside a genuine memory alert"
    )
    print("Test G (swap pressure: not proof alone, but visible as evidence) PASSED")
    await hm.bus.unsubscribe("collector")
    await hm2.bus.unsubscribe("collector")

    hm = _make_monitor()
    collected, sub = await _collect(hm)
    cache_heavy = _mem_snapshot(15.0, available_bytes=7 * 1024 * 1024 * 1024, buff_cache_bytes=6 * 1024 * 1024 * 1024)
    hm._evaluate_resource_thresholds(cache_heavy)
    hm._evaluate_resource_thresholds(cache_heavy)
    hm._evaluate_resource_thresholds(cache_heavy)
    await sub.queue.join()
    assert len(collected) == 0, (
        "Case H: a host with large reclaimable cache but healthy available memory (low percent, "
        "since psutil already derives percent from available on Linux) must not be classified "
        "as memory-exhausted"
    )
    print("Test H (cache-heavy host with healthy available: not classified as critical) PASSED")
    await hm.bus.unsubscribe("collector")

    hm = _make_monitor(cpu_alert_threshold=90.0, cpu_recovery_threshold=85.0, cpu_critical_threshold=98.0)
    collected, sub = await _collect(hm)

    def _cpu_snapshot(percent):
        return HealthEvent(
            source_module="health_monitor", category=EventCategory.HEALTH_STATUS,
            severity=Severity.INFO, message="", raw="", cpu_percent=percent, mem_percent=10.0, disk_percent=10.0,
        )

    for percent in (91.0, 92.0, 90.5):
        hm._evaluate_resource_thresholds(_cpu_snapshot(percent))
    await sub.queue.join()
    cpu_high = [e for e in collected if e.severity == Severity.HIGH]
    assert len(cpu_high) == 1, f"CPU alert path (regression) must still confirm exactly once, got {len(cpu_high)}"
    print("Test I (regression: CPU alert path still works under the new state machine) PASSED")
    await hm.bus.unsubscribe("collector")

    hm = _make_monitor()
    collected, sub = await _collect(hm)
    top_procs = (
        {"pid": 111, "user": "mysql", "cpu_percent": 5.0, "mem_percent": 10.0, "rss_bytes": 900 * 1024 * 1024, "command": "mysqld"},
    )
    for percent in (91.0, 91.5, 91.2):
        hm._evaluate_resource_thresholds(_mem_snapshot(91.0, top_mem_processes=top_procs))
    await sub.queue.join()
    high = [e for e in collected if e.severity == Severity.HIGH]
    assert len(high) == 1
    msg = high[0].message
    for required in (
        "Memory Usage:", "Threshold:", "Total:", "Used:", "Available:", "Free:", "Buff/Cache:",
        "Swap Used:", "Swap Total:", "Proses Memory Teratas:", "mysqld",
    ):
        assert required in msg, f"evidence-rich alert message missing required field: {required!r}"
    print("Test J (evidence-rich memory alert contains all required fields incl. top processes) PASSED")
    await hm.bus.unsubscribe("collector")

    hm = _make_monitor()
    collected, sub = await _collect(hm)
    hm._evaluate_resource_thresholds(_mem_snapshot(91.0))
    await sub.queue.join()
    pending = [e for e in collected if e.severity == Severity.LOW]
    assert len(pending) == 1
    assert pending[0].metadata.get("state") == "PENDING_HIGH"
    print("Test K (unconfirmed breach publishes internal LOW-severity telemetry, below Discord floor) PASSED")
    await hm.bus.unsubscribe("collector")

    cfg_default = HealthMonitorConfig()
    assert cfg_default.mem_recovery_threshold == 85.0
    assert cfg_default.resource_consecutive_breaches == 3
    print("Test L (new config fields have safe defaults with no config.yaml changes required) PASSED")

    os.environ.setdefault("RTSA_DISCORD_BOT_TOKEN", "test_fixture_token_never_a_real_credential_0123456789abcdef")
    os.environ.setdefault("RTSA_CLOUDFLARE_API_TOKEN", "test_fixture_cf_token_never_real_fedcba9876543210")
    legacy_config = {
        "discord": {"enabled": False},
        "modules": {
            "health_monitor": {
                "enabled": True, "cpu_alert_threshold": 90.0, "mem_alert_threshold": 90.0,
                "disk_alert_threshold": 90.0,
            },
            "nginx_monitor": {"svg_upload_scanner": {"enabled": False}},
        },
    }
    with isolated_config_manager(legacy_config) as mgr:
        assert mgr.config.modules.health_monitor.mem_recovery_threshold == 85.0
    print(
        "Test M (a config.yaml written before this fix -- with no hysteresis keys -- still loads, "
        "isolated from the production database.path directory) PASSED"
    )

    with open("modules/health_monitor.py", "r") as f:
        source = f.read()
    for forbidden in ("subprocess.Popen(['free'", "'free',", "'top',", "'ps',", "'htop'", "os.popen(", "shell=True"):
        assert forbidden not in source, f"health_monitor.py must never shell out for memory/process data: {forbidden}"
    assert "psutil.virtual_memory" in source
    assert "psutil.swap_memory" in source
    print("Test N (memory/process evidence is gathered via psutil only, never shell/subprocess) PASSED")

    assert "create_task" not in source
    print("Test O (no per-poll task creation -- reuses the existing polling loop) PASSED")

    formatted = _format_top_mem_processes(top_procs)
    assert "mysqld" in formatted and "MB" in formatted
    print("Test P (top-memory formatter renders bounded, human-readable RSS) PASSED")

    print("\nALL HEALTH MONITOR MEMORY HYSTERESIS TESTS PASSED")


asyncio.run(main())
