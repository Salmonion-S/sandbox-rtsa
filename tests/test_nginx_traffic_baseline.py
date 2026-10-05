import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig, TrafficBaselineConfig
from core.bounded_cache import BoundedLRUSet
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from modules.nginx_monitor import (
    CONFIRMED_EXPLOITATION, HIGH_ATTACK_TRAFFIC, NORMAL_TRAFFIC, SUSPICIOUS_TRAFFIC_BURST,
    TRAFFIC_SPIKE, NginxMonitor, _VhostTrafficState, _VhostTrafficWindow,
)

DOMAIN = "example.com"


def make_monitor(**tb_overrides):
    defaults = dict(
        window_seconds=1.0, min_windows_before_active=3, absolute_rps_threshold=10.0,
        spike_multiplier=3.0, attack_multiplier=5.0, suspicious_ratio_burst=0.15,
        suspicious_ratio_attack=0.30, min_suspicious_count=5, unique_ip_threshold=5,
        sustained_windows_required=3, cooldown_seconds=300.0, max_tracked_paths=20,
        max_tracked_vhosts=500, max_tracked_ips_per_window=5000,
    )
    defaults.update(tb_overrides)
    tb = TrafficBaselineConfig(**defaults)
    cfg = NginxMonitorConfig(enabled=True, traffic_baseline=tb)
    mon = NginxMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_cloudpanel_context(domain):
        return "", {"domain": domain or "unknown"}

    mon._cloudpanel_context = fake_cloudpanel_context
    return mon, published


def feed_window(mon, domain, *, requests, suspicious=0, unique_ips=1, status=200, category="WEB_ATTACK_SCAN"):
    ip_pool = [f"203.0.113.{i % 250}" for i in range(unique_ips)]
    for i in range(requests):
        is_susp = i < suspicious
        mon._track_traffic_baseline(
            domain, f"/path{i % 5}", status, ip_pool[i % len(ip_pool)],
            is_suspicious=is_susp, attack_category=category if is_susp else None,
        )


async def finalize(mon, domain, now):
    state = mon._vhost_traffic_state.get(domain)
    win = state.current
    state.current = None
    await mon._finalize_traffic_window(domain, state, win, now, mon.config.traffic_baseline)
    return state


async def warm_up_baseline(mon, domain, *, windows=3, rps=2, start=1000.0):
    now = start
    for _ in range(windows):
        feed_window(mon, domain, requests=rps, unique_ips=2)
        now += 1.0
        await finalize(mon, domain, now)
    return now


async def main() -> None:
    mon, published = make_monitor()
    now = 1000.0
    feed_window(mon, DOMAIN, requests=500, suspicious=400, unique_ips=50)
    now += 1.0
    state = await finalize(mon, DOMAIN, now)
    assert state.last_classification == NORMAL_TRAFFIC, (
        f"a cold-start window (no baseline yet) must never classify above NORMAL_TRAFFIC: {state.last_classification}"
    )
    assert not published, "cold start must never alert"
    print("Scenario 1 (cold start never classifies/alerts regardless of volume) PASSED")

    mon, published = make_monitor()
    now = await warm_up_baseline(mon, DOMAIN, windows=5, rps=2)
    feed_window(mon, DOMAIN, requests=200, suspicious=150, unique_ips=30)
    now += 1.0
    state = await finalize(mon, DOMAIN, now)
    assert state.last_classification == HIGH_ATTACK_TRAFFIC, f"volume/ratio should qualify: {state.last_classification}"
    assert not published, "a single HIGH_ATTACK_TRAFFIC window (not yet sustained) must never alert"
    assert state.consecutive_high_attack_windows == 1
    print("Scenario 2 (single-window spike qualifies but does not yet alert -- sustained duration required) PASSED")

    for _ in range(2):
        feed_window(mon, DOMAIN, requests=200, suspicious=150, unique_ips=30)
        now += 1.0
        state = await finalize(mon, DOMAIN, now)
    assert len(published) == 1, f"sustained HIGH_ATTACK_TRAFFIC must alert exactly once: {len(published)}"
    ev = published[0]
    assert ev.category == EventCategory.NGINX_RATE_ANOMALY
    assert ev.severity == Severity.HIGH
    meta = ev.metadata
    for key in (
        "current_rps", "baseline_rps", "multiplier", "suspicious_rps", "unique_ips",
        "top_suspicious_paths", "status_4xx", "status_5xx", "attack_categories",
        "duration_seconds", "confidence", "recommendation", "classification",
    ):
        assert key in meta, f"missing required section-53 field: {key}"
    assert meta["classification"] == HIGH_ATTACK_TRAFFIC
    assert "Cloudflare" in meta["recommendation"] and "manually" in meta["recommendation"].lower()
    assert meta["domain"] == DOMAIN
    print("Scenario 3 (sustained HIGH_ATTACK_TRAFFIC alerts exactly once with full section-53 field set) PASSED")

    feed_window(mon, DOMAIN, requests=200, suspicious=150, unique_ips=30)
    now += 1.0
    await finalize(mon, DOMAIN, now)
    assert len(published) == 1, "a repeat HIGH_ATTACK_TRAFFIC window within cooldown must not re-alert"
    print("Scenario 4 (cooldown prevents repeat alert for the same sustained attack) PASSED")

    baseline_before = mon._vhost_traffic_state.get(DOMAIN).baseline_rps
    feed_window(mon, DOMAIN, requests=200, suspicious=150, unique_ips=30)
    now += 1.0
    state = await finalize(mon, DOMAIN, now)
    assert state.baseline_rps == baseline_before, (
        f"baseline must be frozen during a sustained attack window: {baseline_before} -> {state.baseline_rps}"
    )
    print("Scenario 5 (baseline frozen during HIGH_ATTACK_TRAFFIC, never poisoned by attack traffic) PASSED")

    mon2, published2 = make_monitor()
    now2 = await warm_up_baseline(mon2, DOMAIN, windows=5, rps=2)
    feed_window(mon2, DOMAIN, requests=50, suspicious=0, unique_ips=2)
    now2 += 1.0
    state2 = await finalize(mon2, DOMAIN, now2)
    assert state2.last_classification == TRAFFIC_SPIKE, state2.last_classification
    assert not published2, "TRAFFIC_SPIKE (volume only, no suspicious evidence) must never alert"
    print("Scenario 6 (pure volume spike with zero suspicious evidence classifies TRAFFIC_SPIKE, never alerts) PASSED")

    mon3, published3 = make_monitor()
    now3 = await warm_up_baseline(mon3, DOMAIN, windows=5, rps=2)
    feed_window(mon3, DOMAIN, requests=20, suspicious=6, unique_ips=2)
    now3 += 1.0
    state3 = await finalize(mon3, DOMAIN, now3)
    assert state3.last_classification == SUSPICIOUS_TRAFFIC_BURST, state3.last_classification
    assert not published3, "SUSPICIOUS_TRAFFIC_BURST below the HIGH_ATTACK_TRAFFIC threshold must stay internal"
    print("Scenario 7 (suspicious burst below attack threshold classifies SUSPICIOUS_TRAFFIC_BURST, stays internal) PASSED")

    mon4, published4 = make_monitor()
    now4 = await warm_up_baseline(mon4, DOMAIN, windows=5, rps=2)
    feed_window(mon4, DOMAIN, requests=5, unique_ips=2)
    mon4._mark_confirmed_exploitation(DOMAIN)
    now4 += 1.0
    state4 = await finalize(mon4, DOMAIN, now4)
    assert state4.last_classification == CONFIRMED_EXPLOITATION, state4.last_classification
    assert not published4, "the traffic-baseline system must never duplicate the existing WEB_ATTACK_SUCCESS alert"
    baseline_before4 = state4.baseline_rps
    feed_window(mon4, DOMAIN, requests=5, unique_ips=2)
    mon4._mark_confirmed_exploitation(DOMAIN)
    now4 += 1.0
    state4 = await finalize(mon4, DOMAIN, now4)
    assert state4.baseline_rps == baseline_before4, "baseline must also be frozen during CONFIRMED_EXPLOITATION"
    print("Scenario 8 (CONFIRMED_EXPLOITATION reflected internally, never double-alerts, freezes baseline) PASSED")

    mon5, _ = make_monitor()
    mon5.config = NginxMonitorConfig(
        enabled=True, whitelisted_ips=["203.0.113.99"], traffic_baseline=mon5.config.traffic_baseline,
    )
    mon5._whitelisted_networks = mon5._parse_whitelisted_networks(["203.0.113.99"])

    async def fake_status_anomaly(*args, **kwargs):
        return None

    async def fake_web_attack_signature(*args, **kwargs):
        return None

    async def fake_injection(*args, **kwargs):
        return None

    async def fake_svg(*args, **kwargs):
        return None

    async def fake_redirect(*args, **kwargs):
        return None

    mon5._check_status_anomaly = fake_status_anomaly
    mon5._check_web_attack_signature = fake_web_attack_signature
    mon5._check_injection_techniques = fake_injection
    mon5._check_svg_upload = fake_svg
    mon5._track_redirect_chain = fake_redirect

    line = (
        '203.0.113.99 - - [19/Aug/2026:12:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 100 '
        '"-" "sqlmap/1.7" "example.com"'
    )
    await mon5._process_access_line(line, "/var/log/nginx/access.log", 1, domain="example.com")
    win5 = mon5._vhost_traffic_state.get("example.com").current
    assert win5.request_count == 1
    assert win5.suspicious_count == 0, "whitelisted IP's request must never count as suspicious in the baseline"
    print("Scenario 9 (whitelisted IP traffic tracked but never counted as suspicious) PASSED")

    mon6, _ = make_monitor(max_tracked_vhosts=2)
    for d in ("a.example.com", "b.example.com", "c.example.com"):
        mon6._track_traffic_baseline(d, "/", 200, "203.0.113.1", is_suspicious=False)
    assert len(mon6._vhost_traffic_state) <= 2, "vhost tracking must stay bounded by max_tracked_vhosts"
    items = mon6._vhost_traffic_state.items()
    assert isinstance(items, tuple)
    print("Scenario 10 (per-vhost state tracking is bounded, items() usable for periodic sweep) PASSED")

    print("\nALL NGINX TRAFFIC BASELINE TESTS PASSED")


asyncio.run(main())
