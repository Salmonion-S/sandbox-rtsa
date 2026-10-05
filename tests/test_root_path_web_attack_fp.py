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
    mon = NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True, **overrides))
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def access_line(path, status=200, method="GET", ip="203.0.113.7", ua="Mozilla/5.0", host="rmepro.com", xfh=None):
    line = f'{ip} - - [01/Jan/2026:00:00:00 +0000] "{method} {path} HTTP/1.1" {status} 100 "-" "{ua}"'
    if host is not None:
        line += f' "{host}"'
    if xfh is not None:
        line += f' "{xfh}"'
    return line


def protocol_abuse(pub):
    return [e for e in pub if e.category == EventCategory.WEB_ATTACK_PROTOCOL_ABUSE]


async def main():
    mon0, _ = make_monitor()
    root_true = ["/", "/?foo=bar", "/?a=1&b=2", "/?utm_source=fb"]
    root_false = ["/foo", "/foo/", "//", "/?x=<script>", "/?a=1;b=2", "/x", "/?x=' OR '1'='1"]
    for p in root_true:
        assert mon0._is_exempt_root_request(p) is True, f"{p!r} must be exempt (exact root)"
    for p in root_false:
        assert mon0._is_exempt_root_request(p) is False, f"{p!r} must NOT be exempt"
    print(f"Scenario 1 ({len(root_true)} exact-root shapes exempt, {len(root_false)} non-root/dangerous shapes not) PASSED")

    for kw in (
        {},
        {"host": "rmepro.com, evil.com"},
        {"host": "rmepro.com", "xfh": "attacker.example"},
        {"host": "a:b:c"},
        {"host": "rmepro.com\r\nX-Injected: evil"},
        {"ua": "kube-probe/1.28"},
        {"ua": "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)"},
        {"host": None},
    ):
        mon, pub = make_monitor()
        await mon._process_access_line(access_line("/", **kw), LOG_FILE, 1, domain="rmepro.com")
        assert protocol_abuse(pub) == [], f"GET / with {kw} must never alert WEB_ATTACK_PROTOCOL_ABUSE: {pub}"
    print("Scenario 2 (GET / with clean/benign/duplicated/malformed/CRLF/XFH-conflict Host, and health-check UAs -- zero alerts) PASSED")

    for method in ("POST", "HEAD", "OPTIONS"):
        mon, pub = make_monitor()
        await mon._process_access_line(
            access_line("/", method=method, host="rmepro.com, evil.com"), LOG_FILE, 1, domain="rmepro.com",
        )
        assert protocol_abuse(pub) == [], f"{method} / with a duplicated Host must not alert: {pub}"
    print("Scenario 3 (POST/HEAD/OPTIONS / with a duplicated Host header -- zero alerts) PASSED")

    mon, pub = make_monitor()
    await mon._process_access_line(
        access_line("/?normal=query", host="rmepro.com, evil.com"), LOG_FILE, 1, domain="rmepro.com",
    )
    assert protocol_abuse(pub) == [], f"/?normal=query with a duplicated Host must not alert: {pub}"
    print("Scenario 4 (/?normal=query with a duplicated Host header -- zero alerts) PASSED")

    for path in ("/dashboard", "/api", "/x"):
        mon, pub = make_monitor()
        await mon._process_access_line(
            access_line(path, host="rmepro.com, evil.com"), LOG_FILE, 1, domain="rmepro.com",
        )
        assert len(protocol_abuse(pub)) == 1, f"a duplicated Host header on {path!r} must still alert: {pub}"
    print("Scenario 5 (duplicated Host header on /dashboard, /api, /x -- still alerts, exemption is exact-root only) PASSED")

    for path in ("/dashboard", "/api"):
        mon, pub = make_monitor()
        await mon._process_access_line(
            access_line(path, host="rmepro.com", xfh="evil.com"), LOG_FILE, 1, domain="rmepro.com",
        )
        assert len(protocol_abuse(pub)) == 1, f"Host/XFH conflict on {path!r} must still alert: {pub}"
    print("Scenario 5b (Host/X-Forwarded-Host conflict on /dashboard, /api -- still alerts) PASSED")

    mon, pub = make_monitor()
    await mon._process_access_line(
        access_line("/?x=<script>alert(1)</script>", status=404, host="rmepro.com, evil.com"),
        LOG_FILE, 1, domain="rmepro.com",
    )
    cats = {e.category for e in pub}
    assert EventCategory.WEB_ATTACK_XSS in cats, f"an XSS payload in the query on '/' must still be caught: {pub}"
    assert EventCategory.WEB_ATTACK_PROTOCOL_ABUSE in cats, (
        f"a dangerous query voids the root exemption, so the duplicated Host must also still alert: {pub}"
    )
    print("Scenario 6 (XSS payload smuggled via '/?<script>...' with a duplicated Host -- BOTH XSS and the Host anomaly still fire) PASSED")

    attack_paths = [
        "/../../../etc/passwd", "/etc/passwd", "/wp-admin/install.php", "/shell.php",
        "/admin/login.action", "/.env", "/wp-login.php",
    ]
    mon, pub = make_monitor(php_stack_present=True, alert_on_scan_attempts=True)
    for path in attack_paths:
        await mon._process_access_line(
            access_line(path, status=404), LOG_FILE, 1, domain="rmepro.com",
        )
    assert pub, f"previously-detected attack paths must still be flagged by at least one rule: {pub}"
    print(f"Scenario 7 ({len(attack_paths)} known attack paths still produce alerts -- exemption is not a broad bypass) PASSED")

    default_still_fires = classify_request(
        "GET", "/", host_header="example.com", x_forwarded_host="evil.com",
    )
    assert default_still_fires.top_technique == "Host Header Injection", (
        "classify_request must not silently exempt '/' unless is_root_path=True is passed explicitly"
    )
    exempted = classify_request(
        "GET", "/", host_header="example.com", x_forwarded_host="evil.com", is_root_path=True,
    )
    assert exempted.top_category is None, f"is_root_path=True must suppress the Host/XFH-conflict finding: {exempted}"
    print("Scenario 8 (classify_request: is_root_path is opt-in, defaults to full detection) PASSED")

    print("\nALL ROOT-PATH WEB_ATTACK FALSE-POSITIVE REGRESSION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
