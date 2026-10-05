import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig, ScanBurstRecommendationConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from modules.nginx_monitor import NginxMonitor

DOMAIN = "example.com"
LOG_FILE = "/var/log/nginx/example.com.access.log"


def make_monitor(**sb_overrides):
    defaults = dict(
        enabled=True, scan_window_seconds=60.0, scan_count_threshold=10,
        cooldown_seconds=1800.0, max_tracked_vhosts=500,
        minimum_unique_paths_for_enumeration=3, minimum_unique_ips_for_distributed=5,
        dominant_source_ratio=0.6, minimum_confidence_for_cloudflare_recommendation="HIGH",
    )
    defaults.update(sb_overrides)
    sb = ScanBurstRecommendationConfig(**defaults)
    cfg = NginxMonitorConfig(enabled=True, scan_burst_recommendation=sb)
    mon = NginxMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_cloudpanel_context(domain):
        return "", {"domain": domain or "unknown"}

    mon._cloudpanel_context = fake_cloudpanel_context
    return mon, published


_line_counter = {"n": 0}


def _next_line() -> int:
    _line_counter["n"] += 1
    return _line_counter["n"]


async def _feed(mon, domain, count, *, ip="203.0.113.5", paths=("/.env",), method="GET", status=404, ua=""):
    for i in range(count):
        await mon._track_scan_burst(
            domain, True, ip=ip, path=paths[i % len(paths)], method=method, status=status, ua=ua,
            category="WEB_ATTACK_SCAN", log_file=LOG_FILE, line_number=_next_line(),
        )


async def main() -> None:
    mon, published = make_monitor()
    await _feed(mon, DOMAIN, 9, ip="203.0.113.5", paths=("/.env", "/.git/config", "/wp-login.php"))
    assert not published, "9 scan hits (below the 10-count threshold) must not alert yet"
    await _feed(mon, DOMAIN, 1, ip="203.0.113.5", paths=("/.env",))
    assert len(published) == 1, f"the 10th scan hit within the window must cross the threshold and alert: {published}"
    ev = published[0]
    assert ev.category == EventCategory.NGINX_RATE_ANOMALY
    assert ev.severity == Severity.HIGH
    assert ev.metadata["detector"] == "scan_burst_recommendation"
    assert ev.metadata["scan_count"] == 10
    assert ev.metadata["scan_count_threshold"] == 10
    assert ev.metadata["confidence_label"] == "HIGH"
    assert ev.metadata["cloudflare_action_recommended"] is True
    assert "Cloudflare" in ev.metadata["recommendation"] and "manually" in ev.metadata["recommendation"].lower()
    assert ev.metadata["domain"] == DOMAIN
    assert ev.metadata["top_source_ip"] == "203.0.113.5"
    assert "Rekomendasi" not in ev.message, (
        "the recommendation text must live only in the dedicated Recommendation field, "
        f"never baked into the human-readable message too: {ev.message!r}"
    )
    print(
        "Scenario 1 (single-source sequential enumeration across >=3 distinct suspicious paths "
        "crosses threshold -> HIGH confidence, Cloudflare recommended, recommendation not duplicated in message) PASSED"
    )

    published.clear()
    await _feed(mon, DOMAIN, 10, ip="203.0.113.5", paths=("/.env", "/.git/config", "/wp-login.php"))
    assert not published, "a repeat crossing within the cooldown window must not re-alert"
    print("Scenario 2 (cooldown prevents repeat alert for the same vhost) PASSED")

    mon2, published2 = make_monitor()
    for _ in range(50):
        await mon2._track_scan_burst(DOMAIN, False, log_file=LOG_FILE, line_number=_next_line())
    assert not published2, "non-suspicious requests must never count toward the scan-burst threshold"
    print("Scenario 3 (non-suspicious requests never count toward the threshold) PASSED")

    mon3, published3 = make_monitor(enabled=False)
    await _feed(mon3, DOMAIN, 50, ip="203.0.113.5", paths=("/.env", "/.git/config", "/wp-login.php"))
    assert not published3, "scan_burst_recommendation.enabled=false must fully disable this mode"
    assert len(mon3._scan_burst_windows) == 0, "disabled mode must not even track state"
    print("Scenario 4 (enabled=false fully disables tracking and alerting -- the 'turn off' switch) PASSED")

    mon4, published4 = make_monitor(scan_count_threshold=3, scan_window_seconds=0.2)
    await _feed(mon4, DOMAIN, 3, ip="203.0.113.5", paths=("/.env", "/.git/config", "/wp-login.php"))
    assert len(published4) == 1
    await asyncio.sleep(0.25)
    published4.clear()
    await _feed(mon4, DOMAIN, 2, ip="203.0.113.5", paths=("/.env", "/.git/config"))
    assert not published4, "scan hits that age out of scan_window_seconds must not count toward a later threshold crossing"
    print("Scenario 5 (scan_window_seconds correctly expires old hits, a short window doesn't linger) PASSED")

    mon5, published5 = make_monitor()
    await _feed(mon5, "a.example.com", 15, ip="203.0.113.6", paths=("/.env", "/.git/config", "/wp-login.php"))
    await _feed(mon5, "b.example.com", 15, ip="203.0.113.7", paths=("/.env", "/.git/config", "/wp-login.php"))
    assert len(published5) == 2, f"tracking must be independent per-vhost: {len(published5)}"
    domains_alerted = {ev.metadata["domain"] for ev in published5}
    assert domains_alerted == {"a.example.com", "b.example.com"}
    print("Scenario 6 (scan-burst tracking is independent per vhost, both cross threshold and alert) PASSED")

    mon6, published6 = make_monitor()
    await _feed(mon6, DOMAIN, 10, ip="203.0.113.8", paths=("/api/data",))
    assert len(published6) == 1
    ev6 = published6[0]
    assert ev6.metadata["confidence_label"] in ("LOW", "MEDIUM"), (
        f"repeated hits on a single path with no enumeration/distribution evidence must never "
        f"reach HIGH purely from request count, got {ev6.metadata['confidence_label']}"
    )
    assert ev6.metadata["cloudflare_action_recommended"] is False
    assert "Suspicious scanning activity detected" in ev6.metadata["recommendation"]
    print(
        "Scenario 7 (repeated hits on one path from one source, no enumeration evidence -- "
        "reproduces the reported false positive shape -- stays LOW/MEDIUM, no Cloudflare recommendation) PASSED"
    )

    mon7, published7 = make_monitor(minimum_unique_ips_for_distributed=5)
    sensitive_paths = ("/.env", "/.git/config", "/wp-login.php")
    for i in range(10):
        await mon7._track_scan_burst(
            DOMAIN, True, ip=f"198.51.100.{i}", path=sensitive_paths[i % len(sensitive_paths)],
            method="GET", status=404, ua="", category="WEB_ATTACK_SCAN",
            log_file=LOG_FILE, line_number=_next_line(),
        )
    assert len(published7) == 1
    ev7 = published7[0]
    assert ev7.metadata["unique_ips"] == 10
    assert ev7.metadata["distributed_scanning"] is True
    assert ev7.metadata["confidence_label"] in ("HIGH", "CRITICAL"), (
        f"10 distinct IPs collectively probing multiple sensitive paths is classic distributed scanning: {ev7.metadata}"
    )
    print("Scenario 8 (distributed scanning from many distinct IPs across multiple sensitive paths is classified as such) PASSED")

    mon7b, published7b = make_monitor(minimum_unique_ips_for_distributed=5)
    for i in range(10):
        await mon7b._track_scan_burst(
            DOMAIN, True, ip=f"198.51.100.{100 + i}", path="/.env", method="GET", status=404, ua="",
            category="WEB_ATTACK_SCAN", log_file=LOG_FILE, line_number=_next_line(),
        )
    assert len(published7b) == 1
    assert published7b[0].metadata["confidence_label"] not in ("HIGH", "CRITICAL"), (
        f"many IPs hitting one single path one time each, with no path-diversity evidence, "
        f"must not alone reach HIGH: {published7b[0].metadata}"
    )
    print("Scenario 8b (many distinct IPs against a single shared path, no path diversity -- stays below HIGH) PASSED")

    mon8, published8 = make_monitor()
    await _feed(mon8, DOMAIN, 10, ip="", paths=("/.env", "/.git/config", "/wp-login.php"))
    assert len(published8) == 1
    ev8 = published8[0]
    assert ev8.metadata["confidence_label"] == "LOW", (
        f"missing source IP attribution must force LOW confidence, never HIGH/CRITICAL: {ev8.metadata}"
    )
    assert ev8.metadata["cloudflare_action_recommended"] is False
    assert "UNAVAILABLE" in ev8.metadata["source_attribution_status"]
    print("Scenario 9 (source IP unavailable -- 'N/A' -- never escalates to a confident classification) PASSED")

    mon9, published9 = make_monitor(scan_count_threshold=5)
    base_line = _next_line()
    for _ in range(2000):
        await mon9._track_scan_burst(
            DOMAIN, True, ip="203.0.113.9", path="/.env", method="GET", status=404, ua="",
            category="WEB_ATTACK_SCAN", log_file=LOG_FILE, line_number=base_line,
        )
    state = mon9._scan_burst_windows.get(DOMAIN)
    assert len(state.events) == 1, (
        f"2000 duplicate-processing attempts of the SAME log line must never be counted more than "
        f"once, got {len(state.events)} tracked events"
    )
    assert not published9, "a single deduplicated hit must never itself cross a threshold of 5"
    print("Scenario 10 (2000 duplicate-processing attempts of the same log line collapse to 1 observation) PASSED")

    mon10, published10 = make_monitor(scan_count_threshold=2000, minimum_unique_paths_for_enumeration=3)
    await _feed(
        mon10, DOMAIN, 2000, ip="203.0.113.10",
        paths=("/.env", "/.git/config", "/wp-login.php", "/.aws/credentials"),
    )
    assert len(published10) == 1
    assert published10[0].metadata["scan_count"] == 2000, (
        f"2000 genuinely distinct log lines must produce 2000 observations, not fewer: "
        f"{published10[0].metadata['scan_count']}"
    )
    print("Scenario 11 (2000 unique log lines -> 2000 distinct observations, dedup never drops real traffic) PASSED")

    print("\nALL NGINX SCAN-BURST RECOMMENDATION TESTS PASSED")


asyncio.run(main())
