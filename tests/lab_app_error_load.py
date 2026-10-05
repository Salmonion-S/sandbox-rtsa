from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _app_error_fakes import config
from config.manager import (
    AppErrorBudgetConfig, AppErrorCollectionConfig, AppErrorLogSourceConfig, AppErrorStorageConfig, DiscordConfig, OutboundBackpressureConfig,
)
from core.datatypes import EventCategory
from core.event_bus import EventBus
from core.pipeline_metrics import get_app_error_metrics
from database.sqlite_pool import SQLiteWriteWorker
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.application_error_tracker import ApplicationErrorTracker

PRODUCER = r"""
import json, os, sys, time
path, rate, seconds, projects, variants = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
handle = open(path, "a", buffering=1 << 16)
start = time.time()
sent = 0
tick = 0.05
while True:
    elapsed = time.time() - start
    if elapsed >= seconds:
        break
    due = int(elapsed * rate) - sent
    for i in range(max(0, due)):
        n = sent + i
        err = {"type": "TypeError", "message": "Cannot read properties of undefined (reading 'f%d') request %d" % (n % variants, n), "stack": "TypeError: x\n    at handler%d (/app/src/h%d.js:%d:1)" % (n % variants, n % variants, n % 90 + 1)}
        handle.write(json.dumps({"level": 50, "time": int(time.time() * 1000), "msg": "request failed", "err": err, "req": {"method": "GET", "url": "/api/items/%d" % n}}) + "\n")
    sent += max(0, due)
    handle.flush()
    time.sleep(tick)
handle.close()
print(sent)
"""


class FakeMessage:
    _next = 1

    def __init__(self, channel):
        FakeMessage._next += 1
        self.id = FakeMessage._next
        self.channel = channel

    async def edit(self, content=None, embeds=None, view=None):
        return None


class FakeChannel:
    id = 999111

    def __init__(self):
        self.sent = []

    async def send(self, content=None, embeds=None, view=None):
        self.sent.append(embeds[0].to_dict()["title"] if hasattr(embeds[0], "to_dict") else "")
        return FakeMessage(self)

    async def fetch_message(self, message_id):
        return FakeMessage(self)


class FakeBot:
    def __init__(self, channel):
        self.channel = channel

    def is_ready(self):
        return True

    def get_channel(self, cid):
        return self.channel


def rss_mb() -> float:
    with open("/proc/self/status") as handle:
        for line in handle:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024.0
    return 0.0


async def run_rate(rate: int, seconds: float, projects: int, variants: int, label: str, collection: AppErrorCollectionConfig) -> dict:
    tmp = tempfile.mkdtemp(prefix="rtsa-app-load-")
    db_path = os.path.join(tmp, "rtsa.db")
    worker = SQLiteWriteWorker(db_path, flush_interval_seconds=0.5)
    await worker.start()
    bus = EventBus()
    await worker.attach_to_bus(bus)
    channel = FakeChannel()
    dispatcher = DiscordWebhookDispatcher(bus, DiscordConfig(alert_channel_id=999111, outbound=OutboundBackpressureConfig(dedup_window_seconds=60.0)))
    dispatcher.set_bot(FakeBot(channel))
    await dispatcher.start()
    delays = []

    async def capture(event):
        if event.category in (EventCategory.APPLICATION_ERROR, EventCategory.APPLICATION_ERROR_DIGEST):
            delays.append(time.time() - event.timestamp)

    await bus.subscribe("lab_capture", capture, categories=[EventCategory.APPLICATION_ERROR, EventCategory.APPLICATION_ERROR_DIGEST])
    sources = []
    logs = []
    for p in range(projects):
        path = os.path.join(tmp, f"p{p}.log")
        open(path, "w").close()
        logs.append(path)
        sources.append(AppErrorLogSourceConfig(path=path, project=f"project{p:03d}", domain=f"project{p:03d}.example.com", service="api", format="json"))
    cfg = config(collection=collection, storage=AppErrorStorageConfig(state_path=os.path.join(tmp, "state.json")), notifications=AppErrorBudgetConfig())
    tracker = ApplicationErrorTracker(bus, cfg)
    tracker.attach_db_worker(worker)
    for source in sources:
        tracker.register_source(source)
    loop = asyncio.get_running_loop()
    tracker.start(loop)
    await asyncio.sleep(1.5)
    metrics = get_app_error_metrics()
    base = metrics.snapshot()
    base_rss = rss_mb()
    cpu0, wall0 = time.process_time(), time.time()
    producers = [
        subprocess.Popen([sys.executable, "-c", PRODUCER, path, str(max(1, rate // projects) if rate >= projects else 1), str(seconds), "1", str(variants)], stdout=subprocess.PIPE)
        for path in (logs if rate >= projects else logs[:max(1, rate)])
    ]
    max_queue = 0
    peak_rss = base_rss
    while time.time() - wall0 < seconds + 1:
        await asyncio.sleep(0.5)
        max_queue = max(max_queue, len(tracker._queue))
        peak_rss = max(peak_rss, rss_mb())
    produced = sum(int(p.communicate()[0].decode().strip() or 0) for p in producers)
    drain_deadline = time.time() + 30
    while time.time() < drain_deadline:
        await asyncio.sleep(0.5)
        counted = metrics.snapshot()["counters"]["application_errors_total"] - base["counters"]["application_errors_total"]
        if counted >= produced or all(os.path.getsize(p) <= tracker._sources[p].offset for p in logs if p in tracker._sources):
            break
        max_queue = max(max_queue, len(tracker._queue))
    cpu1, wall1 = time.process_time(), time.time()
    await asyncio.sleep(1.0)
    snap = metrics.snapshot()
    counted = snap["counters"]["application_errors_total"] - base["counters"]["application_errors_total"]
    latency_now = snap["latency"].get("application_event_processing_latency", {})
    latency_base = base["latency"].get("application_event_processing_latency", {})
    latency = {"count": latency_now.get("count", 0) - latency_base.get("count", 0), "sum": latency_now.get("sum", 0.0) - latency_base.get("sum", 0.0), "max": latency_now.get("max", 0.0)}
    stats = worker.stats
    await tracker.stop()
    await asyncio.sleep(1.0)
    await worker.stop()
    conn = sqlite3.connect(db_path)
    events_rows = conn.execute("SELECT count(*) FROM events WHERE category LIKE 'APPLICATION_ERROR%'").fetchone()[0]
    incident_rows = conn.execute("SELECT count(*) FROM app_error_incidents").fetchone()[0]
    digest_rows = conn.execute("SELECT count(*) FROM app_error_digests").fetchone()[0]
    conn.close()
    await bus.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)
    delta = {k: snap["counters"][k] - base["counters"][k] for k in snap["counters"]}
    delays.sort()
    return {
        "label": label, "target_rate": rate, "seconds": seconds, "projects": projects, "produced_lines": produced, "errors_counted": counted,
        "cpu_percent_of_one_core": round((cpu1 - cpu0) / max(0.001, wall1 - wall0) * 100, 1), "rss_before_mb": round(base_rss, 1), "rss_peak_mb": round(peak_rss, 1),
        "sqlite_avg_flush_ms": stats["avg_flush_time_ms"], "sqlite_max_flush_ms": stats["max_flush_time_ms"], "sqlite_queue_dropped": stats["dropped"],
        "bus_delivery_p50_ms": round(delays[len(delays) // 2] * 1000, 1) if delays else None, "bus_delivery_max_ms": round(delays[-1] * 1000, 1) if delays else None,
        "max_engine_queue_depth": max_queue, "processing_latency_avg_s": round(latency.get("sum", 0) / latency["count"], 3) if latency.get("count") else None,
        "processing_latency_max_s": round(latency.get("max", 0.0), 3) if latency else None, "incidents": incident_rows, "stored_event_rows": events_rows, "digest_rows": digest_rows,
        "notifications_sent": delta["application_notification_sent_total"], "notifications_suppressed": delta["application_notification_suppressed_total"],
        "digests": delta["application_digest_total"], "discord_messages": len(channel.sent), "events_dropped": delta["application_event_dropped_total"],
        "storms": delta["application_error_storms_total"],
    }


async def main() -> None:
    seconds = float(os.environ.get("LAB_SECONDS", "12"))
    default = AppErrorCollectionConfig()
    fast = AppErrorCollectionConfig(poll_interval_seconds=1.0, max_bytes_per_cycle=32 * 1024 * 1024, max_bytes_per_file_per_cycle=8 * 1024 * 1024, event_queue_max=50000, batch_size=2000)
    results = []
    for rate in (10, 100, 1000, 10000):
        for label, collection in (("default-config", default), ("high-throughput-config", fast)):
            if rate < 1000 and label == "high-throughput-config":
                continue
            result = await run_rate(rate, seconds, 50, 12, label, collection)
            results.append(result)
            print(json.dumps(result), flush=True)
    print("DONE")


if __name__ == "__main__":
    asyncio.run(main())
