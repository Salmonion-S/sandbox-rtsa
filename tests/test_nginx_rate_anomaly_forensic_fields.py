import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import DiscordConfig
from core.datatypes import EventCategory, NginxEvent, Severity
from core.event_bus import EventBus
from discord_integration.webhook import DiscordWebhookDispatcher


def field_map(payload):
    return {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}


def main() -> None:
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())

    traffic_event = NginxEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY,
        severity=Severity.HIGH, message="HIGH_ATTACK_TRAFFIC terdeteksi", raw="",
        domain="victim.example.com",
        metadata={
            "domain": "victim.example.com", "classification": "HIGH_ATTACK_TRAFFIC",
            "current_rps": 2000.0, "baseline_rps": 250.0, "multiplier": 8.0,
            "suspicious_ratio": 0.42, "unique_ips": 340, "duration_seconds": 60.0,
            "status_4xx": 900, "status_5xx": 12,
            "top_suspicious_paths": ["/wp-login.php", "/.env", "/xmlrpc.php"],
            "attack_categories": {"WEB_ATTACK_SCAN": 800, "WEB_ATTACK_SQLI": 50},
            "recommendation": "Consider enabling Cloudflare Under Attack Mode manually.",
        },
    )
    payload = dispatcher._build_payload(traffic_event)
    fields = field_map(payload)
    assert fields["Requests/sec"] == "2000.0"
    assert fields["Baseline"] == "250.0 req/s"
    assert fields["Ratio"] == "8.0x baseline"
    assert fields["Unique Source IPs"] == "340"
    assert fields["Suspicious Request %"] == "42%"
    assert "4xx: 900" in fields["Status Distribution"] and "5xx: 12" in fields["Status Distribution"]
    assert "/wp-login.php" in fields["Top Suspicious Paths"]
    assert "WEB_ATTACK_SCAN: 800" in fields["Attack Categories"]
    assert fields["Recommendation"] != "N/A"
    print("Scenario 1 (HIGH_ATTACK_TRAFFIC event: full traffic-baseline forensic fields rendered) PASSED")

    scan_burst_event = NginxEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY,
        severity=Severity.HIGH, message="Aktivitas scanning tinggi terdeteksi", raw="",
        domain="victim.example.com",
        metadata={
            "domain": "victim.example.com", "detector": "scan_burst_recommendation",
            "scan_count": 1500, "scan_window_seconds": 120.0, "scan_count_threshold": 200,
            "recommendation": "Consider enabling Cloudflare Under Attack Mode manually.",
        },
    )
    payload2 = dispatcher._build_payload(scan_burst_event)
    fields2 = field_map(payload2)
    assert fields2["Scan Request Count"] == "1500"
    assert "2" in fields2["Scan Window"] or "min" in fields2["Scan Window"].lower()
    print("Scenario 2 (scan-burst recommendation event: scan count/window rendered) PASSED")

    rate_event = NginxEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY,
        severity=Severity.MEDIUM, message="Response rate-limit/forbidden 429", raw="",
        source_ip="203.0.113.9", request_path="/login", status_code=429, domain="victim.example.com",
        metadata={"domain": "victim.example.com", "check_count": 7, "incident_key": "rate:203.0.113.9"},
    )
    payload3 = dispatcher._build_payload(rate_event)
    fields3 = field_map(payload3)
    assert fields3["Request Count"] == "7"
    assert fields3["Source IP"] == "203.0.113.9"
    print("Scenario 3 (per-IP rate-limit event: check_count/source IP rendered, falls back to event.source_ip) PASSED")

    sparse_event = NginxEvent(
        source_module="nginx_monitor", category=EventCategory.NGINX_RATE_ANOMALY,
        severity=Severity.MEDIUM, message="test", raw="", metadata={},
    )
    payload4 = dispatcher._build_payload(sparse_event)
    assert payload4["embeds"][0]["fields"]
    print("Scenario 4 (missing metadata does not crash, degrades to N/A) PASSED")

    print("\nALL NGINX_RATE_ANOMALY FORENSIC FIELD TESTS PASSED")


main()
