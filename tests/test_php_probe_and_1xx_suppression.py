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

    mon, pub = make_monitor(php_stack_present=False, alert_on_scan_attempts=True)
    await mon._process_access_line(
        log_line("/wp-admin/install.php?step=1", 403), "/var/log/nginx/access.log", 1, domain="rmepro.com",
    )
    web_attacks = [e for e in pub if e.category.value.startswith("WEB_ATTACK")]
    assert web_attacks == [], f"php_stack_present=False must not raise any WEB_ATTACK_* for install.php, got {web_attacks}"
    print("Scenario 1 (wp-admin/install.php?step=1 -> zero WEB_ATTACK_* alerts) PASSED")

    mon_default, pub_default = make_monitor(alert_on_scan_attempts=True)
    assert NginxMonitorConfig().php_stack_present is True, "default must be True (PHP assumed present) unless configured off"
    await mon_default._process_access_line(
        log_line("/wp-login.php", 403), "/var/log/nginx/access.log", 1, domain="rmepro.com",
    )
    assert mon_default._scan_batches, (
        f"default config (php_stack_present=True) must still record wp-login.php as a scan attempt, "
        f"got batches={mon_default._scan_batches} publishes={[e.category.value for e in pub_default]}"
    )
    print("Scenario 2 (php_stack_present=True (default) -> wp-login.php still flagged as before) PASSED")

    mon3, pub3 = make_monitor(php_stack_present=False, alert_on_scan_attempts=True)
    for p in ("/xmlrpc.php", "/WP-LOGIN.PHP", "/setup.php?x=1"):
        await mon3._process_access_line(log_line(p, 403), "/var/log/nginx/access.log", 1, domain="rmepro.com")
    web_attacks3 = [e for e in pub3 if e.category.value.startswith("WEB_ATTACK")]
    assert web_attacks3 == [], f"every .php-suffixed probe must be suppressed, got {web_attacks3}"
    print("Scenario 3 (xmlrpc.php, uppercase WP-LOGIN.PHP, setup.php -> all suppressed) PASSED")

    mon4, pub4 = make_monitor(php_stack_present=False, alert_on_scan_attempts=True)
    await mon4._process_access_line(
        log_line("/api/users?id=1'%20OR%20'1'='1", 403), "/var/log/nginx/access.log", 1, domain="rmepro.com",
    )
    assert any(e.category.value.startswith("WEB_ATTACK") for e in pub4), (
        f"a non-.php attack path must still be detected, got {[e.category.value for e in pub4]}"
    )
    print("Scenario 4 (SQLi on a non-.php API path -> still detected, suppression is scoped to .php only) PASSED")

    mon5, pub5 = make_monitor(php_stack_present=False)
    await mon5._process_access_line(
        log_line("/wp-admin/install.php?step=1", 403), "/var/log/nginx/access.log", 1, domain="rmepro.com",
    )
    assert any(e.category == EventCategory.NGINX_RATE_ANOMALY for e in pub5), (
        "php_stack_present must not affect NGINX_RATE_ANOMALY -- that is a separate concern/channel"
    )
    print("Scenario 5 (php_stack_present leaves NGINX_RATE_ANOMALY untouched -- different alert category) PASSED")

    import yaml
    raw = yaml.safe_load(open("config/config.yaml"))
    assert raw["modules"]["nginx_monitor"]["php_stack_present"] is False
    print("Scenario 6 (config.yaml ships php_stack_present=false for this fleet) PASSED")


    mon7, pub7 = make_monitor(alert_on_scan_attempts=True)
    await mon7._process_access_line(
        log_line("/ws?x=<script>alert(1)</script>", 101), "/var/log/nginx/access.log", 1, domain="rmepro.com",
    )
    assert pub7 == [], f"status=101 must never produce any alert, got {[e.category.value for e in pub7]}"
    print("Scenario 7 (HTTP 101 on an attack-shaped path -> zero alerts, protocol handshake ignored) PASSED")

    mon8, pub8 = make_monitor(alert_on_scan_attempts=True)
    await mon8._process_access_line(
        log_line("/ws?x=<script>alert(1)</script>", 403), "/var/log/nginx/access.log", 1, domain="rmepro.com",
    )
    assert any(e.category == EventCategory.WEB_ATTACK_XSS for e in pub8), (
        f"the same path at a real status code must still be caught, got {[e.category.value for e in pub8]}"
    )
    print("Scenario 8 (same path at HTTP 403 -> still detected; the skip is 1xx-specific) PASSED")

    mon9, pub9 = make_monitor(alert_on_scan_attempts=True)
    await mon9._process_access_line(
        log_line("/.env", 100), "/var/log/nginx/access.log", 1, domain="rmepro.com",
    )
    assert pub9 == [], f"any 1xx status must be skipped entirely, got {[e.category.value for e in pub9]}"
    print("Scenario 9 (HTTP 100 Continue -> also skipped, the rule covers the whole 1xx class) PASSED")

    mon10, pub10 = make_monitor()
    await mon10._process_access_line(
        log_line("/robots.txt", 101), "/var/log/nginx/access.log", 1, domain="rmepro.com",
    )
    assert pub10 == [], f"1xx must short-circuit before status-anomaly checks too, got {pub10}"
    print("Scenario 10 (1xx short-circuits before status-anomaly/rate-anomaly checks as well) PASSED")

    print("\nALL PHP-PROBE AND 1xx SUPPRESSION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
