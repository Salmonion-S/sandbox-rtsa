import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig
from core.datatypes import EventCategory
from core.event_bus import EventBus
from modules.nginx_monitor import NginxMonitor


def make_monitor(**overrides):
    mon = NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True, **overrides))
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def log_line(path, status, ip="203.0.113.7", ua="Mozilla/5.0", host="rmepro.com"):
    return f'{ip} - - [01/Jan/2026:00:00:00 +0000] "GET {path} HTTP/1.1" {status} 100 "-" "{ua}" "{host}"'


async def main():
    mon, _ = make_monitor()

    benign = [
        "/", "/robots.txt", "/favicon.ico", "/assets/images/logo-rme.png",
        "/sitemap.xml", "/assets/app.9f3c.css", "/_next/static/chunk.js",
        "/fonts/inter.woff2", "/?utm_source=fb&utm_campaign=launch",
    ]
    for p in benign:
        assert mon._is_benign_request_path(p) is True, f"{p!r} should be benign"
    print(f"Scenario 1 ({len(benign)} well-known/static paths recognised as benign) PASSED")

    must_inspect = [
        "/logo.png/../../etc/passwd", "/assets/../../../etc/passwd",
        "/logo.png?id=1'OR'1'='1", "/x.png\x00.php", "/api?q=<script>alert(1)</script>",
        "/index.php", "/.env", "/wp-config.php", "/admin/login.action",
        "/..%2f..%2fetc/passwd",
    ]
    for p in must_inspect:
        assert mon._is_benign_request_path(p) is False, f"{p!r} must NOT be treated as benign"
    print(f"Scenario 2 ({len(must_inspect)} traversal/encoded/attack paths still inspected, not allowlisted) PASSED")

    mon3, pub3 = make_monitor()
    for p in ("/robots.txt", "/", "/assets/images/logo-rme.png"):
        await mon3._process_access_line(log_line(p, 403), "/var/log/nginx/access.log", 1, domain="rmepro.com")
    assert pub3 == [], f"benign 403s must publish nothing, got {[e.category.value for e in pub3]}"
    print("Scenario 3 (403 on /robots.txt, /, logo -> zero NGINX_RATE_ANOMALY alerts) PASSED")

    mon4, pub4 = make_monitor()
    await mon4._process_access_line(log_line("/wp-login.php", 403), "/var/log/nginx/access.log", 1, domain="rmepro.com")
    assert any(e.category == EventCategory.NGINX_RATE_ANOMALY for e in pub4), (
        f"a 403 on a non-benign path must still alert, got {[e.category.value for e in pub4]}"
    )
    print("Scenario 4 (403 on /wp-login.php -> NGINX_RATE_ANOMALY still fires) PASSED")

    mon5, pub5 = make_monitor(alert_on_scan_attempts=True)
    await mon5._process_access_line(
        log_line("/static/x.js/../../../../etc/passwd", 200), "/var/log/nginx/access.log", 1, domain="rmepro.com",
    )
    assert mon5._is_benign_request_path("/static/x.js/../../../../etc/passwd") is False
    print("Scenario 5 (a .js path carrying traversal is inspected, not allowlisted) PASSED")

    mon6, _ = make_monitor(ignore_static_asset_requests=False)
    assert mon6._is_benign_request_path("/robots.txt") is True, "explicit list still applies"
    assert mon6._is_benign_request_path("/assets/images/logo-rme.png") is False, (
        "with static auto-benign off, a plain asset is inspected again"
    )
    print("Scenario 6 (ignore_static_asset_requests=false -> exact list kept, static assets inspected) PASSED")

    import yaml
    raw = yaml.safe_load(open("config/config.yaml"))
    shipped = raw["modules"]["nginx_monitor"]["benign_request_paths"]
    assert "/" in shipped and "/robots.txt" in shipped, shipped
    print("Scenario 7 (config.yaml ships benign_request_paths incl. / and /robots.txt) PASSED")

    print("\nALL BENIGN PATH ALLOWLIST TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
