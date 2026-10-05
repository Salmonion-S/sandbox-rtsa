import asyncio, inspect, os, sqlite3, sys, tempfile, time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from pathlib import Path

from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.incident_engine import IncidentEngine, IncidentEngineConfig, _MAX_EVIDENCE_ENTRIES
from database.sqlite_pool import SQLiteWriteWorker

BASE = os.path.join(tempfile.gettempdir(), "rtsa_audit_hardening")

async def main():
    import shutil
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)

    db = f"{BASE}/durability.db"
    w = SQLiteWriteWorker(db_path=db, batch_size=200, flush_interval_seconds=1.0, retention_days=0)
    await w.start()
    N = 1000
    for i in range(N):
        w.enqueue_event(BaseEvent(source_module="t", category=EventCategory.SYSTEM,
                                  severity=Severity.INFO, message=f"e{i}", raw=""))
    await w.stop()
    conn = sqlite3.connect(db)
    persisted = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    assert persisted == N, f"shutdown lost {N - persisted} accepted events (was a real data-loss bug)"
    print(f"Scenario 1 (SQLite shutdown durability: {N} enqueued -> {persisted} persisted, zero loss) PASSED")

    src = inspect.getsource(SQLiteWriteWorker.stop)
    assert "wait_for(self._worker_task" in src, (
        "stop() must await the drain loop's own completion so the final batch is written"
    )
    assert "self._queue.join()" not in src, (
        "stop() must not gate shutdown on queue.join(): task_done() fires before the write"
    )
    print("Scenario 2 (stop() awaits the drain loop instead of cancelling on a queue.join() signal) PASSED")

    from config.manager import SSHMonitorConfig
    from modules.ssh_monitor import SSHMonitor
    mon = SSHMonitor(EventBus(), SSHMonitorConfig(enabled=True))
    mon.publish = lambda e: None
    done_flags = []

    async def enrichment(tag):
        await asyncio.sleep(0.3)
        done_flags.append(tag)

    baseline = set(asyncio.all_tasks())
    for i in range(4):
        mon._spawn_background(enrichment(i))
    await mon.teardown()
    assert len(done_flags) == 4, f"teardown abandoned in-flight enrichment tasks: {done_flags}"
    stray = [t for t in asyncio.all_tasks()
             if t not in baseline and t is not asyncio.current_task() and not t.done()]
    assert not stray, f"ssh_monitor leaked background tasks past teardown: {stray}"
    print("Scenario 3 (ssh_monitor.teardown drains all in-flight enrichment tasks, zero leaked) PASSED")

    jsrc = inspect.getsource(SSHMonitor._journald_available)
    assert "create_subprocess_exec" not in jsrc, "PATH lookup must not spawn a subprocess"
    assert "shutil.which" in jsrc
    print("Scenario 4 (ssh_monitor._journald_available uses a PATH lookup, no untimed subprocess) PASSED")

    eng = IncidentEngine(IncidentEngineConfig())
    for i in range(20_000):
        eng.report("attack:198.51.100.7:SCAN", "198.51.100.7", kind="SCAN",
                   evidence=f"GET /wp-content/{i}/x.php?v={i}")
    inc = eng.get("attack:198.51.100.7:SCAN")
    assert len(inc.evidence) <= _MAX_EVIDENCE_ENTRIES, len(inc.evidence)
    assert inc.check_count == 20_000, inc.check_count
    assert len(inc.evidence[-20:]) == 20, "consumers slice evidence[-20:] and must still get 20"
    assert inc.evidence[-1].endswith("v=19999"), "most recent evidence must be the retained end"
    print(f"Scenario 5 (evidence bounded at {len(inc.evidence)}/{_MAX_EVIDENCE_ENTRIES} after 20k-request scan, "
          f"check_count still exact, consumer slice intact) PASSED")

    def bench(n):
        e = IncidentEngine(IncidentEngineConfig())
        t0 = time.monotonic()
        for i in range(n):
            e.report("k", "r", kind="SCAN", evidence=f"GET /p/{i}")
        return time.monotonic() - t0

    bench(2000)
    t_small, t_large = bench(5_000), bench(50_000)
    per_small, per_large = t_small / 5_000, t_large / 50_000
    assert per_large < per_small * 3, (
        f"per-request cost grew {per_large / per_small:.1f}x for 10x input -- still super-linear"
    )
    print(f"Scenario 6 (scan cost stays linear: {per_large / per_small:.2f}x per-request for 10x input, "
          f"not the ~10x of the quadratic scan) PASSED")

    from discord_integration.bot import _resolve_vhost_conf_path
    conf_dir = Path("/etc/nginx/sites-enabled")
    escapes = ["../sites-available/x", "../../etc/systemd/system/x", "/etc/passwd", "..", ".",
               "a/../../etc/x", "foo/bar", "", "..%2f..%2fetc", "\\..\\..\\etc"]
    for bad in escapes:
        assert _resolve_vhost_conf_path(conf_dir, bad) is None, f"must refuse {bad!r}"
    for good in ["example.com", "api.example.com", "localhost", "my_vhost", "a-b.example.co.uk"]:
        assert _resolve_vhost_conf_path(conf_dir, good) == conf_dir / f"{good}.conf", good
    print(f"Scenario 7 ({len(escapes)} traversal shapes refused, 5 legitimate vhost names accepted) PASSED")

    bus = EventBus()
    got_all, got_filtered = [], []
    await bus.subscribe("all", lambda e: _collect(got_all, e), categories=None)
    await bus.subscribe("filtered", lambda e: _collect(got_filtered, e),
                        categories=[EventCategory.SSH_AUTH])
    for cat in (EventCategory.SSH_AUTH, EventCategory.SYSTEM, EventCategory.SSH_AUTH):
        bus.publish_nowait(BaseEvent(source_module="t", category=cat,
                                     severity=Severity.INFO, message="m", raw=""))
    await asyncio.sleep(0.15)
    await bus.shutdown()
    assert len(got_all) == 3, f"catch-all subscriber must receive every event: {len(got_all)}"
    assert len(got_filtered) == 2, f"filtered subscriber must receive only its category: {len(got_filtered)}"
    assert all(e.category == EventCategory.SSH_AUTH for e in got_filtered)
    assert not hasattr(bus, "_by_category_index"), "dead write-only index should be gone"
    print("Scenario 8 (EventBus routing correct after removing the dead category index: 3 all / 2 filtered) PASSED")

    import main as rtsa_main
    bsrc = inspect.getsource(rtsa_main.RTSAEngine._run_discord_bot)
    assert "_DISCORD_STABLE_SESSION_SECONDS" in bsrc, (
        "reconnect loop must reset backoff after a stable session instead of ratcheting to max forever"
    )
    assert rtsa_main._DISCORD_BASE_BACKOFF_SECONDS < rtsa_main._DISCORD_MAX_BACKOFF_SECONDS
    print("Scenario 9 (Discord reconnect backoff resets after a stable session, no permanent max-backoff) PASSED")

    print("\nALL AUDIT HARDENING REGRESSION TESTS PASSED")

async def _collect(sink, event):
    sink.append(event)

asyncio.run(asyncio.wait_for(main(), timeout=300))
