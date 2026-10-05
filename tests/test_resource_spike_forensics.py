import asyncio
import gc
import os
import resource
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import discord_integration.webhook as webhook_module
from config.manager import (
    DiscordConfig, NginxMonitorConfig, SSHMonitorConfig, WebsiteMonitorConfig,
)
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.self_health import DEGRADED, EMERGENCY, NORMAL, OVERLOADED, get_self_health_monitor
from core.website_check import WebsiteCheckResult
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.nginx_monitor import NginxMonitor, _LogSource
from modules.ssh_monitor import SSHMonitor
from modules.website_monitor import WebsiteMonitor

_PRODUCTION_TASK_SITES = {
    ("modules/base.py", "loop.create_task"),
    ("core/event_bus.py", "loop.create_task"),
    ("core/supervisor.py", "loop.create_task"),
    ("main.py", "asyncio.create_task"),
    ("discord_integration/bot.py", "asyncio.create_task"),
    ("discord_integration/webhook.py", "asyncio.create_task"),
    ("discord_integration/lb_bgp_ports.py", "loop.create_task"),
    ("core/lb_validation.py", "ensure_future"),
    ("modules/injection_detector.py", "asyncio.create_task"),
    ("modules/nginx_monitor.py", "asyncio.create_task"),
    ("modules/ssh_monitor.py", "asyncio.create_task"),
    ("modules/ssh_monitor.py", "loop.create_task"),
    ("modules/threat_correlation_engine.py", "asyncio.create_task"),
}

_TASK_SITE_BOUNDS = {
    "modules/base.py": "one long-lived task per module instance, cancelled in stop()",
    "core/event_bus.py": "one long-lived task per subscriber, cancelled on shutdown",
    "core/supervisor.py": "one long-lived watcher task per supervised entry",
    "main.py": "two named singleton tasks created once per process",
    "discord_integration/bot.py": (
        "one long-lived ban-expiry loop (Auto SSL / auto_vhost repair tasks are tracked in bounded sets, "
        "serialised by a lock, gated by per-domain cooldown and attempt caps, and cancelled in close())"
    ),
    "discord_integration/webhook.py": "one long-lived outbound flush loop",
    "core/lb_validation.py": (
        "operator-run CLI probe only (never imported by the engine): per-request tasks bounded by a semaphore of "
        "rate x timeout + 4, rate capped at 20/s, duration capped at 900 s and MAX_SAMPLES, all awaited before it returns"
    ),
    "discord_integration/lb_bgp_ports.py": (
        "at most two long-lived run_periodic tasks per process (controller tick, optional router observer poll), "
        "created once in start() only when bgp_ecmp is enabled, each with a per-run timeout, cancelled in stop()"
    ),
    "modules/injection_detector.py": "one long-lived sweep loop",
    "modules/nginx_monitor.py": "per-event tasks capped by max_pending_verify_tasks",
    "modules/ssh_monitor.py": (
        "one cleanup loop plus per-event tasks capped by max_pending_background_tasks, plus sshd -T "
        "verification tasks capped at 4 concurrent and claimed at most once per effective-config context"
    ),
    "modules/threat_correlation_engine.py": (
        "one long-lived adaptive-feedback aggregation loop, cancelled in run()'s finally block "
        "alongside the module's own shutdown"
    ),
}


def open_fd_count():
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


def rss_kb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def force_health_state(state):
    monitor = get_self_health_monitor()
    monitor._state = state
    return monitor


def scan_task_creation_sites():
    found = {}
    for root, dirs, files in os.walk(_REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in {".git", "tests", "benchmarks", "validation", "__pycache__", "docs"}]
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, _REPO_ROOT)
            with open(path) as f:
                for line_number, line in enumerate(f, 1):
                    for token in ("asyncio.create_task", "loop.create_task", "ensure_future"):
                        if token in line:
                            found.setdefault((rel, token), []).append(line_number)
    return found


def make_website_monitor(**overrides):
    overrides.setdefault("enabled", True)
    overrides.setdefault("auto_discover", False)
    monitor = WebsiteMonitor(EventBus(), WebsiteMonitorConfig(**overrides))
    monitor._nginx_locally_up = None
    return monitor


def rce_kwargs(ip="203.0.113.7"):
    return dict(
        publish_category=EventCategory.WEB_ATTACK_RCE,
        correlation_category=EventCategory.WEB_ATTACK_RCE,
        severity=Severity.HIGH, message="simulated rce attempt",
        source=_LogSource(log_file="/var/log/nginx/x.log", line_number=1, raw_line="raw"),
        ip=ip, request_path="/?cmd=id", matched_signature="rce", confidence=90.0,
        status=200, cp_metadata={}, extra_metadata={}, is_whitelisted=False, request_time=0.0,
    )


async def cancel_all(tasks):
    pending = [t for t in tasks if not t.done()]
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


async def main() -> None:
    sites = scan_task_creation_sites()
    assert set(sites) == _PRODUCTION_TASK_SITES, (
        f"the set of task-creation sites in production code changed. Every site must have a stated "
        f"lifetime bound before it ships, because an unbounded one is a resource spike waiting to "
        f"happen.\nadded: {sorted(set(sites) - _PRODUCTION_TASK_SITES)}\n"
        f"removed: {sorted(_PRODUCTION_TASK_SITES - set(sites))}"
    )
    for module_path, _token in sorted(sites):
        assert module_path in _TASK_SITE_BOUNDS, f"{module_path} has no documented task bound"
    print(
        f"Test 1 [TASK CREATION AUDIT] ({len(sites)} task-creation sites across "
        f"{len(_TASK_SITE_BOUNDS)} production modules, every one with a stated lifetime bound: "
        f"long-lived singletons or per-event tasks under an explicit cap) PASSED"
    )

    nginx = NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True))
    published = []
    nginx.publish = lambda event: published.append(event)
    force_health_state(NORMAL)
    for index in range(500):
        await nginx._publish_web_attack(**rce_kwargs(ip=f"203.0.113.{index % 250}"))
    pending = len(nginx._verify_tasks)
    cap = nginx.config.max_pending_verify_tasks
    assert pending <= cap, (
        f"REGRESSION GUARD: 500 RCE-class attacks must not create more than "
        f"max_pending_verify_tasks={cap} concurrent correlation tasks. Each one holds its full "
        f"alert payload while sleeping rce_correlation_window_seconds, so an unbounded count is a "
        f"direct memory and scheduler spike under an attack burst. Got {pending} pending tasks."
    )
    assert len(published) == 500 - pending, (
        f"every attack over the cap must still be published immediately rather than dropped, "
        f"expected {500 - pending} immediate publishes got {len(published)}"
    )
    skipped_assessments = [
        e for e in published if e.metadata.get("assessment") == "RCE_CORRELATION_SKIPPED"
    ]
    assert len(skipped_assessments) == len(published) and published, (
        f"an alert published without its correlation window must say so honestly instead of "
        f"implying no execution was found, got {len(skipped_assessments)} of {len(published)}"
    )
    assert all(e.severity == Severity.HIGH for e in skipped_assessments), (
        "skipping correlation must not downgrade the alert severity"
    )
    health = await nginx.health()
    assert health["rce_correlation_skipped_total"] == len(published), (
        f"the skip must be counted for observability, got {health['rce_correlation_skipped_total']}"
    )
    await cancel_all(nginx._verify_tasks)
    print(
        f"Test 2 [RCE CORRELATION TASK BOUND] (500 RCE-class attacks produce at most {cap} "
        f"concurrent correlation tasks, was {500} unbounded before the fix; the {len(published)} "
        f"over the cap are still published immediately at HIGH severity, labelled "
        f"RCE_CORRELATION_SKIPPED rather than silently dropped or downgraded) PASSED"
    )

    for state, divisor in ((NORMAL, 1), (DEGRADED, 2), (OVERLOADED, 4), (EMERGENCY, 10)):
        probe = NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True))
        probe.publish = lambda event: None
        force_health_state(state)
        expected = max(1, probe.config.max_pending_verify_tasks // divisor)
        assert probe._effective_max_pending_verify_tasks() == expected, (
            f"self-health state {state} must tighten the pending-task cap to {expected}"
        )
        for index in range(200):
            await probe._publish_web_attack(**rce_kwargs(ip=f"198.51.100.{index % 250}"))
        assert len(probe._verify_tasks) <= expected, (
            f"under {state} the pending correlation tasks must stay at or under {expected}, got "
            f"{len(probe._verify_tasks)}"
        )
        await cancel_all(probe._verify_tasks)
    force_health_state(NORMAL)
    print(
        f"Test 3 [ADAPTIVE TASK CAP] (the pending-task cap actually tightens with self-health state "
        f"-- NORMAL {NginxMonitorConfig().max_pending_verify_tasks}, DEGRADED "
        f"{NginxMonitorConfig().max_pending_verify_tasks // 2}, OVERLOADED "
        f"{NginxMonitorConfig().max_pending_verify_tasks // 4}, EMERGENCY "
        f"{NginxMonitorConfig().max_pending_verify_tasks // 10}, and 200 attacks per state never "
        f"exceed it) PASSED"
    )

    ssh = SSHMonitor(EventBus(), SSHMonitorConfig(enabled=True))
    ssh.publish = lambda event: None
    ssh_cap = ssh.config.max_pending_background_tasks

    async def never_finishes():
        await asyncio.Event().wait()

    for _ in range(ssh_cap + 200):
        if len(ssh._background_tasks) < ssh_cap:
            ssh._spawn_background(never_finishes())
    assert len(ssh._background_tasks) <= ssh_cap, (
        f"ssh_monitor background enrichment must stay under max_pending_background_tasks="
        f"{ssh_cap}, got {len(ssh._background_tasks)}"
    )
    await cancel_all(ssh._background_tasks)
    print(
        f"Test 4 [SSH ENRICHMENT BOUND] (the GeoIP enrichment task pool is capped at {ssh_cap} and "
        f"the call site checks the cap before spawning, so a login flood cannot grow the task set "
        f"without limit) PASSED"
    )

    baseline_tasks = len(asyncio.all_tasks())
    gc.collect()
    baseline_fds = open_fd_count()
    baseline_objects = len(gc.get_objects())
    cycle_samples = []
    leak_monitor = make_website_monitor(
        domains=[f"leak{i}.example.com" for i in range(10)], down_confirmation_checks=1,
    )
    leak_monitor.publish = lambda event: None

    async def fake_check(domain):
        leak_monitor._current_active_checks += 1
        try:
            await asyncio.sleep(0)
            await leak_monitor._evaluate(domain, WebsiteCheckResult(
                domain, "https", "ok", status_code=200, provider="network", response_time_ms=1.0,
            ))
        finally:
            leak_monitor._current_active_checks -= 1

    leak_monitor._check_one_domain = fake_check
    for cycle in range(1, 101):
        await leak_monitor._poll_once()
        if cycle in (10, 50, 100):
            gc.collect()
            cycle_samples.append((cycle, len(asyncio.all_tasks()), open_fd_count(), len(gc.get_objects())))
    for cycle, tasks, fds, objects in cycle_samples:
        assert tasks <= baseline_tasks + 2, (
            f"after {cycle} poll cycles the live task count must not grow (baseline "
            f"{baseline_tasks}), got {tasks} -- a per-cycle task leak is a direct spike source"
        )
        assert baseline_fds < 0 or fds <= baseline_fds + 2, (
            f"after {cycle} poll cycles the open file descriptor count must not grow (baseline "
            f"{baseline_fds}), got {fds}"
        )
        assert objects <= baseline_objects * 1.5 + 5000, (
            f"after {cycle} poll cycles the tracked object count grew from {baseline_objects} to "
            f"{objects}, which indicates per-cycle state accumulating instead of being reused"
        )
    assert len(leak_monitor._states) == 10, (
        f"per-domain state must stay one entry per monitored domain across 100 cycles, got "
        f"{len(leak_monitor._states)}"
    )
    print(
        f"Test 5 [CYCLE LEAK] (100 website poll cycles over 10 domains: tasks "
        f"{baseline_tasks}->{cycle_samples[-1][1]}, fds {baseline_fds}->{cycle_samples[-1][2]}, "
        f"gc objects {baseline_objects}->{cycle_samples[-1][3]}, per-domain state entries "
        f"{len(leak_monitor._states)} -- nothing accumulates per cycle) PASSED"
    )

    concurrency_results = []
    for domain_count in (20, 100, 500):
        for state, attr in (
            (NORMAL, "max_concurrent_checks"),
            (DEGRADED, "degraded_max_concurrent_checks"),
            (EMERGENCY, "critical_max_concurrent_checks"),
        ):
            force_health_state(state)
            monitor = make_website_monitor(
                domains=[f"d{i}.example.com" for i in range(domain_count)],
                max_concurrent_checks=20, degraded_max_concurrent_checks=4,
                critical_max_concurrent_checks=1,
            )
            monitor.publish = lambda event: None
            await monitor._maybe_refresh_discovery()
            peak = {"value": 0}
            inflight = {"value": 0}

            async def counting_check(_domain, peak=peak, inflight=inflight):
                inflight["value"] += 1
                peak["value"] = max(peak["value"], inflight["value"])
                await asyncio.sleep(0)
                inflight["value"] -= 1

            monitor._check_one_domain = counting_check
            await monitor._poll_once()
            expected = min(getattr(monitor.config, attr), domain_count)
            assert peak["value"] <= expected, (
                f"with {domain_count} domains under {state} the measured peak in-flight checks must "
                f"not exceed {expected}, got {peak['value']} -- the governor state variable is not "
                f"enough, the actual concurrency has to be limited"
            )
            assert peak["value"] == expected, (
                f"with {domain_count} domains under {state} the monitor must actually use its full "
                f"allowance of {expected} concurrent checks, measured {peak['value']}"
            )
            concurrency_results.append((domain_count, state, peak["value"]))
    force_health_state(NORMAL)
    print(
        f"Test 6 [EFFECTIVE CONCURRENCY] (measured peak simultaneous website checks, not just the "
        f"configured value: " +
        ", ".join(f"{n} domains/{s}={p}" for n, s, p in concurrency_results) +
        ") PASSED"
    )

    bus = EventBus()
    small_queue = 32
    received = []

    async def slow_consumer(event):
        await asyncio.sleep(0.01)
        received.append(event)

    subscriber = await bus.subscribe("slow", slow_consumer, max_queue_size=small_queue)
    published_count = small_queue * 20
    for index in range(published_count):
        bus.publish_nowait(BaseEvent(
            source_module="load", category=EventCategory.AUDIT_NETWORK, severity=Severity.INFO,
            message=f"event {index}", raw="", metadata={},
        ))
    queue_size = subscriber.queue.qsize()
    dropped = subscriber.dropped_count
    assert queue_size <= small_queue, (
        f"a subscriber queue must never exceed its declared maxsize {small_queue}, got {queue_size} "
        f"-- an unbounded queue turns a burst into unbounded memory"
    )
    assert dropped == published_count - queue_size - subscriber.delivered_count, (
        f"every event must be accounted for as queued, delivered or dropped: published "
        f"{published_count}, queued {queue_size}, delivered {subscriber.delivered_count}, dropped "
        f"{dropped}"
    )
    assert dropped > 0, "the overflow must be explicitly dropped and counted, not buffered"
    await bus.shutdown()
    print(
        f"Test 7 [EVENT BUS BOUND] (publishing {published_count} events into a queue of maxsize "
        f"{small_queue} leaves the queue at {queue_size} with {dropped} explicitly dropped and "
        f"counted, and every published event is accounted for) PASSED"
    )

    discord_cfg = DiscordConfig(enabled=True, alert_channel_id=1)
    dispatcher = DiscordWebhookDispatcher(EventBus(), discord_cfg)
    backlog_cap = webhook_module._MAX_PENDING_QUEUE_SIZE
    object.__setattr__(discord_cfg.outbound, "aggregation_min_count", 10_000)
    object.__setattr__(discord_cfg.outbound, "critical_aggregation_min_count", 10_000)
    for index in range(backlog_cap * 3):
        severity = Severity.CRITICAL if index % 100 == 0 else Severity.INFO
        dispatcher._enqueue_pending(
            {"content": f"payload {index}"},
            BaseEvent(
                source_module="load", category=EventCategory.AUDIT_NETWORK, severity=severity,
                message=f"event {index}", raw="", metadata={},
            ),
            1, "alert",
        )
    backlog = len(dispatcher._pending_heap)
    retained_critical = len([
        entry for entry in dispatcher._pending_heap if entry[2].severity == Severity.CRITICAL
    ])
    assert backlog <= backlog_cap, (
        f"the Discord retry backlog must stay at or under {backlog_cap}, got {backlog} -- an "
        f"unbounded backlog grows without limit whenever Discord is unreachable"
    )
    assert retained_critical == backlog_cap * 3 // 100, (
        f"eviction under backlog pressure must drop the lowest-severity entries first so no "
        f"CRITICAL alert is lost, expected all {backlog_cap * 3 // 100} retained, got "
        f"{retained_critical}"
    )
    print(
        f"Test 8 [DISCORD BACKLOG BOUND] ({backlog_cap * 3} sends queued while the transport is "
        f"unavailable leave {backlog} entries pending, capped at {backlog_cap}, and all "
        f"{retained_critical} CRITICAL alerts survive because eviction drops the lowest severity "
        f"first) PASSED"
    )

    burst_nginx = NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True))
    burst_nginx.publish = lambda event: None
    scan_cap = burst_nginx.config.scan_batch_max_active
    for index in range(scan_cap * 5):
        burst_nginx._record_scan_attempt(
            f"192.0.2.{index % 256}", f"/probe-{index}", f"d{index}.example.com", 40.0,
            _LogSource(log_file="/var/log/nginx/x.log", line_number=index, raw_line="raw"),
        )
    assert len(burst_nginx._scan_batches) <= scan_cap, (
        f"scan batches must stay at or under scan_batch_max_active={scan_cap}, got "
        f"{len(burst_nginx._scan_batches)}"
    )
    assert burst_nginx._scan_batches_overflow_total > 0, (
        "overflow beyond the scan-batch cap must be counted rather than silently discarded"
    )
    for state in burst_nginx._scan_batches.values():
        task = state.get("task")
        if task is not None:
            task.cancel()
    print(
        f"Test 9 [SCAN BATCH BOUND] (a {scan_cap * 5}-request scan storm leaves "
        f"{len(burst_nginx._scan_batches)} tracked batches, capped at {scan_cap}, with "
        f"{burst_nginx._scan_batches_overflow_total} overflow events counted) PASSED"
    )

    rss_before = rss_kb()
    memory_monitor = make_website_monitor(
        domains=[f"mem{i}.example.com" for i in range(50)], down_confirmation_checks=1,
    )
    memory_monitor.publish = lambda event: None

    async def memory_check(domain):
        await memory_monitor._evaluate(domain, WebsiteCheckResult(
            domain, "https", "connection_refused", provider="network", error_detail="refused",
        ))

    memory_monitor._check_one_domain = memory_check
    for _ in range(100):
        await memory_monitor._poll_once()
    gc.collect()
    rss_after = rss_kb()
    growth_kb = rss_after - rss_before
    assert growth_kb < 60_000, (
        f"100 poll cycles over 50 permanently-down domains grew peak RSS by {growth_kb} KB, which "
        f"indicates per-cycle retention rather than bounded incident state"
    )
    open_incidents = len(memory_monitor._incident_engine._incidents)
    assert open_incidents == 50, (
        f"a permanently-down fleet must hold exactly one incident per domain across 100 cycles, "
        f"got {open_incidents}"
    )
    print(
        f"Test 10 [MEMORY GROWTH] (100 cycles over 50 permanently-down domains: peak RSS grew "
        f"{growth_kb} KB and the incident engine holds exactly {open_incidents} incidents -- one "
        f"per domain, not one per check) PASSED"
    )

    render_nginx = NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True))
    rendered_events = []
    render_nginx.publish = lambda event: rendered_events.append(event)
    force_health_state(NORMAL)
    for _ in range(render_nginx.config.max_pending_verify_tasks + 1):
        await render_nginx._publish_web_attack(**rce_kwargs())
    await cancel_all(render_nginx._verify_tasks)
    skipped_event = rendered_events[0]
    render_dispatcher = DiscordWebhookDispatcher(
        EventBus(), DiscordConfig(enabled=True, alert_channel_id=1),
    )
    payload = render_dispatcher._build_payload(skipped_event)
    assessment_fields = [
        field for embed in payload.get("embeds", []) for field in embed.get("fields", [])
        if field.get("name") == "Assessment"
    ]
    assert assessment_fields, "the alert must carry a rendered Assessment field"
    rendered = assessment_fields[0]["value"]
    assert "RCE_CORRELATION_SKIPPED" in rendered, (
        f"the Discord embed must state that correlation was skipped, got {rendered!r}"
    )
    assert skipped_event.metadata["assessment_reason"] in rendered, (
        f"the caveat explaining that a skipped correlation is not evidence of no execution must "
        f"reach the reader, not just sit in metadata. Rendered: {rendered!r}"
    )
    print(
        f"Test 11 [HONEST DEGRADATION RENDERING] (an alert whose correlation window was skipped "
        f"under load renders both RCE_CORRELATION_SKIPPED and the caveat that this is not evidence "
        f"of no execution, so a bare status line cannot be mistaken for a clean result) PASSED"
    )

    print("\nALL RESOURCE SPIKE FORENSICS TESTS PASSED")


asyncio.run(main())
