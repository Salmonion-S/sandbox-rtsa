import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from pathlib import Path

import yaml

from config.manager import ConfigManager, NginxMonitorConfig
from core.datatypes import EventCategory
from core.event_bus import EventBus
from modules.nginx_monitor import NginxMonitor, _detect_svg_upload_filename

LOG_FILE = "/var/log/nginx/access.log"


def make_monitor(**overrides):
    mon = NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True, **overrides))
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def access_line(method, path, status=200, ip="203.0.113.7", ua="Mozilla/5.0", host="rmepro.com"):
    return f'{ip} - - [01/Jan/2026:00:00:00 +0000] "{method} {path} HTTP/1.1" {status} 100 "-" "{ua}" "{host}"'


def svg_events(pub):
    return [e for e in pub if e.category == EventCategory.WEB_ATTACK_SVG_UPLOAD]


async def main():
    assert _detect_svg_upload_filename("GET", "/assets/logo.svg") is None
    assert _detect_svg_upload_filename("HEAD", "/uploads/test.svg") is None
    assert _detect_svg_upload_filename("GET", "/_next/image?url=/assets/logo.svg") is None
    assert _detect_svg_upload_filename("POST", "/uploads/test.svg") == "test.svg"
    assert _detect_svg_upload_filename("POST", "/api/upload/MALICIOUS.SVG") == "MALICIOUS.SVG"
    assert _detect_svg_upload_filename("POST", "/api/upload?filename=malicious.svg") == "malicious.svg"
    assert _detect_svg_upload_filename("POST", "/api/upload?file=x/malicious.svg") == "malicious.svg"
    assert _detect_svg_upload_filename("POST", "/uploads/test.jpg") is None
    assert _detect_svg_upload_filename("POST", "/api/upload") is None
    assert _detect_svg_upload_filename("POST", "/contact") is None
    assert _detect_svg_upload_filename("POST", "/api/upload?ref=/assets/logo.svg") is None, (
        "a query key outside the small exact upload-metadata set must not trigger"
    )
    assert _detect_svg_upload_filename("POST", "/.svg") is None, "a bare '.svg' is not a real filename"
    print("Scenario 1 (unit-level filename-detection boundary: 11 shapes) PASSED")

    mon, pub = make_monitor()
    await mon._process_access_line(access_line("GET", "/assets/logo.svg"), LOG_FILE, 1, domain="rmepro.com")
    assert svg_events(pub) == [], f"GET /assets/logo.svg must never trigger POST_SVG_UPLOAD: {pub}"
    print("Scenario A (GET /assets/logo.svg -- no alert) PASSED")

    mon, pub = make_monitor()
    await mon._process_access_line(
        access_line("GET", "/_next/image?url=/assets/logo.svg"), LOG_FILE, 1, domain="rmepro.com",
    )
    assert svg_events(pub) == [], f"Next.js image proxy referencing an .svg must never alert: {pub}"
    print("Scenario B (GET /_next/image?url=/assets/logo.svg -- no alert) PASSED")

    for path, expected_filename in (
        ("/uploads/test.svg", "test.svg"),
        ("/api/upload/malicious.svg", "malicious.svg"),
        ("/api/upload?filename=malicious.svg", "malicious.svg"),
    ):
        mon, pub = make_monitor()
        await mon._process_access_line(access_line("POST", path), LOG_FILE, 1, domain="rmepro.com")
        events = svg_events(pub)
        assert len(events) == 1, f"POST {path} must trigger exactly one POST_SVG_UPLOAD alert: {pub}"
        ev = events[0]
        assert ev.matched_signature == "POST_SVG_UPLOAD", ev.matched_signature
        assert ev.metadata["filename"] == expected_filename, ev.metadata
        assert ev.domain == "rmepro.com"
        assert ev.source_ip == "203.0.113.7"
        assert ev.metadata["content_type"].startswith("Tidak tersedia"), (
            "Content-Type must be honestly reported as unavailable, never fabricated"
        )
    print("Scenario C (3 POST shapes with an access-log-provable .svg filename -- POST_SVG_UPLOAD alert, full evidence) PASSED")

    mon, pub = make_monitor()
    await mon._process_access_line(access_line("POST", "/uploads/test.jpg"), LOG_FILE, 1, domain="rmepro.com")
    assert svg_events(pub) == [], f"a non-.svg upload must never trigger this rule: {pub}"
    print("Scenario D (POST /uploads/test.jpg -- no alert) PASSED")

    mon, pub = make_monitor()
    await mon._process_access_line(access_line("POST", "/api/upload"), LOG_FILE, 1, domain="rmepro.com")
    assert svg_events(pub) == [], f"a POST with no filename signal must never trigger this rule: {pub}"
    print("Scenario E (POST /api/upload, no filename signal -- no alert) PASSED")

    mon, pub = make_monitor()
    await mon._process_access_line(access_line("POST", "/upload"), LOG_FILE, 1, domain="rmepro.com")
    assert svg_events(pub) == [], (
        "documented limitation: a filename living only inside a multipart body is "
        f"structurally invisible to a standard nginx access log line: {pub}"
    )
    print("Scenario LIMITATION (POST /upload, .svg filename only in an unreachable multipart "
          "body -- correctly produces no alert, not a fabricated one) PASSED")

    mon, pub = make_monitor()
    await mon._process_access_line(access_line("POST", "/uploads/malicious.svg"), LOG_FILE, 1, domain="rmepro.com")
    ev = svg_events(pub)[0]
    raw = yaml.safe_load(open("config/config.yaml"))
    config_manager = ConfigManager.__new__(ConfigManager)
    config_manager._config_path = Path("config/config.yaml")
    config_manager._merge_external_config_files(raw)
    mapped_channel = raw["discord"]["category_channels"]["WEB_ATTACK_SVG_UPLOAD"]
    assert mapped_channel == 1529424819618316369, mapped_channel
    print("Scenario F (config.yaml routes WEB_ATTACK_SVG_UPLOAD to confirmed branch 1529424819618316369) PASSED")

    from discord_integration.webhook import _BAN_ELIGIBLE_CATEGORIES, _INCIDENT_ELIGIBLE_CATEGORIES
    assert EventCategory.WEB_ATTACK_SVG_UPLOAD not in _BAN_ELIGIBLE_CATEGORIES, (
        "POST_SVG_UPLOAD must never show a Ban/Kill button -- detection + evidence only"
    )
    assert EventCategory.WEB_ATTACK_SVG_UPLOAD in _INCIDENT_ELIGIBLE_CATEGORIES, (
        "POST_SVG_UPLOAD must still be reliably delivered and incident-tracked"
    )
    print("Scenario G (WEB_ATTACK_SVG_UPLOAD: incident-tracked and reliably delivered, but no ban button) PASSED")

    mon, pub = make_monitor(alert_on_scan_attempts=True)
    await mon._process_access_line(
        access_line("GET", "/../../../etc/passwd", status=404), LOG_FILE, 1, domain="rmepro.com",
    )
    assert pub, "existing path-traversal detection must be completely unaffected"
    print("Scenario H (pre-existing path-traversal detection unaffected -- no rules removed) PASSED")

    print("\nALL POST_SVG_UPLOAD REGRESSION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
