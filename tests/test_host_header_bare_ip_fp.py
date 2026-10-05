import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig
from core.datatypes import EventCategory
from core.event_bus import EventBus
from core.injection_signatures import classify_request, detect_host_header_anomaly
from modules.nginx_monitor import NginxMonitor

LOG_FILE = "/var/log/nginx/access.log"


def make_monitor(**overrides):
    cfg = NginxMonitorConfig(enabled=True, alert_on_scan_attempts=True, php_stack_present=False, **overrides)
    mon = NginxMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def access_line(ip, path, status=200, method="GET", ua="Mozilla/5.0", host="rmepro.com", xfh=None):
    line = f'{ip} - - [01/Jan/2026:00:00:00 +0000] "{method} {path} HTTP/1.1" {status} 100 "-" "{ua}" "{host}"'
    if xfh is not None:
        line += f' "{xfh}"'
    return line


async def run_line(mon, *a, **kw):
    await mon._process_access_line(access_line(*a, **kw), LOG_FILE, 1, domain=kw.get("host", "rmepro.com"))


def attacks(pub):
    return [e for e in pub if e.category.value.startswith("WEB_ATTACK")]


async def main():
    assert detect_host_header_anomaly("2402:8780:1014:ba62:81c4:38bf:d27e:a6a0", "") is None
    assert detect_host_header_anomaly("2401:e320:6eb:bb10:89dd:755a:290c:e1c4", "") is None
    assert detect_host_header_anomaly("203.0.113.7", "") is None
    assert detect_host_header_anomaly("rmepro.com", "") is None
    print("Test 1 (bare IPv4/IPv6 host values -- no anomaly) PASSED")

    assert detect_host_header_anomaly("[2402:8780:1014:ba62::1]:443", "") is None
    assert detect_host_header_anomaly("[2402:8780:1014:ba62::1]", "") is None
    print("Test 2 (bracketed IPv6, with/without port -- still no anomaly, unaffected by fix) PASSED")

    assert detect_host_header_anomaly("rmepro.com\r\nX-Injected: evil", "") == "host_header_crlf"
    assert detect_host_header_anomaly("rmepro.com, evil.com", "") == "host_header_duplicated"
    assert detect_host_header_anomaly("evil:1:2:3", "") == "host_header_malformed"
    assert detect_host_header_anomaly("not a host!!", "") == "host_header_malformed"
    assert detect_host_header_anomaly("rmepro.com", "evil.com") == "host_header_xfh_conflict"
    print("Test 3 (CRLF / non-IP duplicate / non-IP garbage / XFH conflict -- all still detected) PASSED")

    assert detect_host_header_anomaly("203.0.113.7, 198.51.100.9", "") is None
    print("Test 4 (multi-IP XFF-shaped chain -- still no anomaly, pre-existing behavior preserved) PASSED")

    assert detect_host_header_anomaly("-", "") is None
    assert detect_host_header_anomaly("", "") is None
    print("Test 4b (nginx's \"-\" empty-field placeholder -- no anomaly, same as a truly empty value) PASSED")

    result = classify_request(
        "GET", "/_next/image?url=%2Fassets%2Fimages%2Fbg-cta.png&w=1920&q=75",
        host_header="2402:8780:1014:ba62:81c4:38bf:d27e:a6a0",
    )
    assert result.top_category is None, f"the reported FP shape must not classify as an attack: {result}"
    print("Test 5 (classify_request: reported /_next/image FP shape -> no match) PASSED")

    result_dash = classify_request(
        "OPTIONS", "/api/article/detail/jasa-pembuatan-dashboard-monitoring-bisnis-real-time",
        host_header="-",
    )
    assert result_dash.top_category is None, f"a logged '-' host field must not classify as an attack: {result_dash}"
    print("Test 5b (classify_request: reported OPTIONS '-' host FP shape -> no match) PASSED")

    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.30", "/_next/image?url=%2Fassets%2Fimages%2Fbg-cta.png&w=1920&q=75",
                   host="2402:8780:1014:ba62:81c4:38bf:d27e:a6a0")
    assert attacks(pub) == [], f"/_next/image with a bare-IPv6 host log field must not alert: {pub}"
    print("Test 6 (end-to-end: /_next/image with bare-IPv6 host field -- no WEB_ATTACK_*) PASSED")

    mon, pub = make_monitor()
    for _ in range(5):
        await run_line(mon, "2401:e320:6eb:bb10:89dd:755a:290c:e1c4",
                       "/socket.io/?EIO=4&transport=polling&t=72c3dcpy",
                       host="2401:e320:6eb:bb10:89dd:755a:290c:e1c4")
    assert attacks(pub) == [], (
        f"repeated /socket.io/ polling with a bare-IPv6 host log field must never alert (matches the "
        f"production report's repeated Host Header Injection flood): {pub}"
    )
    print("Test 7 (end-to-end: repeated /socket.io/ polling with bare-IPv6 host field -- no flood of alerts) PASSED")

    mon, pub = make_monitor()
    await run_line(mon, "17.22.245.71", "/api/article/detail/jasa-pembuatan-dashboard-monitoring-bisnis-real-time",
                   method="OPTIONS", status=204, host="-")
    assert attacks(pub) == [], f"an OPTIONS preflight with a logged '-' host field must not alert: {pub}"
    print("Test 7b (end-to-end: OPTIONS preflight with '-' host field -- no WEB_ATTACK_*) PASSED")

    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.31", "/dashboard", host="rmepro.com", xfh="evil.com")
    assert any(e.category == EventCategory.WEB_ATTACK_PROTOCOL_ABUSE for e in pub), (
        f"a real Host/X-Forwarded-Host conflict must still alert after this fix: {pub}"
    )
    print("Test 8 (end-to-end: genuine Host/XFH conflict on an ordinary page -- still alerts) PASSED")

    mon, pub = make_monitor()
    await mon._process_access_line(
        '203.0.113.32 - - [01/Jan/2026:00:00:00 +0000] "GET /dashboard HTTP/1.1" '
        '200 100 "-" "Mozilla/5.0" "rmepro.com\r\nX-Injected: evil"',
        LOG_FILE, 1, domain="rmepro.com",
    )
    for state in mon._scan_batches.values():
        state["task"].cancel()
    assert any(e.category == EventCategory.WEB_ATTACK_PROTOCOL_ABUSE for e in pub), (
        f"a genuine CRLF-injected Host header must still alert after this fix: {pub}"
    )
    print("Test 9 (end-to-end: genuine CRLF-injected Host header -- still alerts) PASSED")

    print("\nALL BARE-IP / '-' PLACEHOLDER HOST-HEADER FALSE-POSITIVE REGRESSION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
