import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig
from core.datatypes import EventCategory
from core.event_bus import EventBus
from core.injection_signatures import classify_request
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


def _cleanup(mon):
    return None


async def run_line(mon, *a, **kw):
    await mon._process_access_line(access_line(*a, **kw), LOG_FILE, 1, domain=kw.get("host", "rmepro.com"))
    _cleanup(mon)


async def main():

    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.10", "/socket.io/?EIO=4&transport=polling&t=NxK2--",
                   xfh="app.rmepro.com")
    assert not any(e.category == EventCategory.WEB_ATTACK_PROTOCOL_ABUSE for e in pub), (
        f"GET /socket.io/ polling with a proxy-chain Host/XFH mismatch must not alert: {pub}"
    )
    print("Scenario A (GET /socket.io/?EIO=4&transport=polling normal -> no WEB_ATTACK_PROTOCOL_ABUSE) PASSED")

    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.11", "/socket.io/?EIO=4&transport=polling&t=NxK2--",
                   method="POST", xfh="app.rmepro.com")
    assert pub == [], f"POST /socket.io/ polling normal traffic must not alert at all: {pub}"
    print("Scenario B (POST /socket.io/?EIO=4&transport=polling normal -> no alert) PASSED")

    mon, pub = make_monitor()
    for method in ("GET", "POST"):
        await run_line(mon, "203.0.113.12", "/socket.io/?EIO=4&transport=polling&t=NxK2&sid=Xg8CvVzz",
                       method=method, xfh="app.rmepro.com")
    assert pub == [], f"Socket.IO session-continuation (sid=) traffic must not alert: {pub}"
    print("Scenario C (Socket.IO with sid= session continuation, GET+POST -> no alert) PASSED")

    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.13", "/socket.io/?EIO=4&transport=websocket&sid=xyz789",
                   xfh="app.rmepro.com")
    assert pub == [], f"Socket.IO websocket-transport traffic must not alert: {pub}"
    print("Scenario C2 (Socket.IO transport=websocket -> no alert) PASSED")


    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.14", "/socket.io/?EIO=4&transport=websocket&sid=abc123",
                   status=101, xfh="app.rmepro.com")
    assert pub == [], f"HTTP 101 WebSocket upgrade must never alert: {pub}"
    print("Scenario D (HTTP 101 Socket.IO WebSocket upgrade -> no WEB_ATTACK_PROTOCOL_ABUSE) PASSED")


    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.15", "/sitemap.xml", status=403)
    assert not any(e.category.value.startswith("WEB_ATTACK") for e in pub), (
        f"/sitemap.xml must never be classified as WEB_ATTACK_*: {pub}"
    )
    print("Scenario E (/sitemap.xml -> ignored, no WEB_ATTACK_*) PASSED")

    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.16",
                   "/_next/image?url=%2Fassets%2Fimages%2Flogo-ae.png&w=256&q=75", status=403)
    assert not any(e.category.value.startswith("WEB_ATTACK") for e in pub), (
        f"/_next/image with any query must never be classified as WEB_ATTACK_*: {pub}"
    )
    print("Scenario F (/_next/image?url=...&w=...&q=... -> ignored regardless of query) PASSED")

    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.17", "/wp-admin/install.php?step=1", status=403)
    assert not any(e.category.value.startswith("WEB_ATTACK") for e in pub), (
        f"/wp-admin/install.php?step=1 must never be classified as WEB_ATTACK_*: {pub}"
    )
    print("Scenario G (/wp-admin/install.php?step=1 -> ignored) PASSED")

    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.18", "/aplikasi-klinik-di-lampung?_rsc=teg37", status=403)
    assert not any(e.category.value.startswith("WEB_ATTACK") for e in pub), (
        f"the reported _rsc= path must never be classified as WEB_ATTACK_*: {pub}"
    )
    mon2, pub2 = make_monitor()
    await run_line(mon2, "203.0.113.19", "/a-totally-different-page-slug?_rsc=zzz999", status=403)
    assert not any(e.category.value.startswith("WEB_ATTACK") for e in pub2), (
        f"_rsc= must generalize to any path, not just the one reported example: {pub2}"
    )
    print("Scenario H (/aplikasi-klinik-di-lampung?_rsc=... ignored, generalizes to other slugs) PASSED")


    mon, pub = make_monitor()
    await run_line(
        mon, "203.0.113.20",
        "/socket.io/?EIO=4&transport=polling&sid=1'%20UNION%20SELECT%20password%20FROM%20users--",
        status=400,
    )
    assert any(e.category == EventCategory.WEB_ATTACK_SQLI for e in pub), (
        f"a real SQLi payload through socket.io must still be detected: {pub}"
    )
    print("Scenario I1 (real SQLi payload smuggled through socket.io -- still detected) PASSED")

    mon, pub = make_monitor()
    await mon._process_access_line(
        '203.0.113.21 - - [01/Jan/2026:00:00:00 +0000] "GET /socket.io/?EIO=4&transport=polling HTTP/1.1" '
        '200 100 "-" "Mozilla/5.0" "rmepro.com\r\nX-Injected: evil"',
        LOG_FILE, 1, domain="rmepro.com",
    )
    _cleanup(mon)
    assert any(e.category == EventCategory.WEB_ATTACK_PROTOCOL_ABUSE for e in pub), (
        f"a genuine CRLF-injected Host header on a socket.io path must still alert: {pub}"
    )
    print("Scenario I2 (real CRLF-injected Host header on socket.io path -- still detected) PASSED")

    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.22", "/dashboard", xfh="evil.com")
    assert any(e.category == EventCategory.WEB_ATTACK_PROTOCOL_ABUSE for e in pub), (
        f"Host/X-Forwarded-Host conflict on an ordinary page must still alert: {pub}"
    )
    print("Scenario I3 (Host/XFH conflict on an ordinary, non-exempt page -- still detected) PASSED")

    default_result = classify_request(
        "GET", "/socket.io/?EIO=4&transport=polling", host_header="rmepro.com",
        x_forwarded_host="app.rmepro.com",
    )
    assert default_result.top_technique == "Host Header Injection", (
        "without opting in, classify_request must not silently exempt socket.io-shaped paths"
    )
    print("Scenario I4 (classify_request defaults to full detection unless is_realtime_protocol_path=True) PASSED")


    mon, pub = make_monitor(whitelisted_ips=["110.137.38.197"])
    await run_line(mon, "110.137.38.197", "/wp-login.php", status=403, host="rmepro.com")
    assert len(pub) == 1, f"110.137.38.197 must still produce a raw/forensic event: {pub}"
    assert pub[0].metadata.get("notify_discord") is False, (
        f"110.137.38.197's event must be marked notify_discord=False: {pub[0].metadata}"
    )
    import yaml
    raw = yaml.safe_load(open("config/config.yaml"))
    shipped_ips = raw["modules"]["nginx_monitor"]["whitelisted_ips"]
    assert "110.137.38.197" in shipped_ips, shipped_ips
    for existing_ip in ("2a02:4780:59:a503::1", "110.137.39.186", "147.93.81.81", "2a02:4780:59:cd6::1"):
        assert existing_ip in shipped_ips, f"existing whitelist entry {existing_ip} must be preserved: {shipped_ips}"
    assert raw["modules"]["nginx_monitor"]["scan_aggregation_window_seconds"] == 30.0
    print(
        "Scenario J (110.137.38.197 whitelisted: event still recorded with notify_discord=False, "
        "not suppressed entirely; existing 4 IPs preserved; window stays 30.0) PASSED"
    )


    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.23", "/_next/image-evil.php?x=1", status=403)
    assert not mon._is_benign_request_path("/_next/image-evil.php?x=1"), (
        "a lookalike path must not be swept in by the /_next/image prefix boundary check"
    )
    print("Scenario K (a /_next/image lookalike path is not matched by the prefix boundary check) PASSED")

    mon, pub = make_monitor()
    await run_line(mon, "203.0.113.24", "/socket.io", xfh="app.rmepro.com")
    assert pub == [], f"bare /socket.io (no trailing slash) must also be recognized: {pub}"
    print("Scenario L (bare /socket.io with no trailing slash is recognized) PASSED")

    print("\nALL SOCKET.IO / IGNORE-PATTERN FALSE-POSITIVE TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
