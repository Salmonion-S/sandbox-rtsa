import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.datatypes import EventCategory
from core.injection_signatures import classify_request
from modules.injection_detector import _ATTACK_SIGNAL_CATEGORIES, _SUBSCRIBED_CATEGORIES

MALICIOUS = [
    ("loopback via http", "/?url=http://127.0.0.1:6379/"),
    ("loopback via localhost", "/fetch?target=http://localhost:8080/admin"),
    ("IPv6 loopback bracketed", "/proxy?dest=http://[::1]:9200/_cluster/health"),
    ("private 10.x range", "/webhook?callback=http://10.0.0.5/internal-api"),
    ("private 172.16-31.x range", "/import?src=http://172.16.5.4/config"),
    ("private 192.168.x range", "/render?url=http://192.168.1.1/router-admin"),
    ("link-local/cloud metadata IP", "/?feed=http://169.254.169.254/latest/meta-data/"),
    ("GCP metadata hostname", "/?url=http://metadata.google.internal/computeMetadata/v1/"),
    ("Azure metadata IP", "/?url=http://100.100.100.200/metadata/instance"),
    ("gopher scheme to internal redis", "/?target=gopher://127.0.0.1:6379/_INFO"),
]

BENIGN = [
    ("legitimate public URL", "/?url=https://example.com/image.png"),
    ("legitimate public API callback", "/webhook?callback=https://api.stripe.com/v1/events"),
    ("public CDN asset", "/?src=https://cdn.example.net/assets/logo.svg"),
    ("bare IP-shaped text with no scheme", "/search?q=10.0.0.5+subnetting+tutorial"),
    ("bare 'localhost' word with no scheme", "/docs/what-is-localhost-explained"),
]


def main() -> None:
    for label, path in MALICIOUS:
        r = classify_request("GET", path)
        assert r.top_category == EventCategory.WEB_ATTACK_SSRF, (
            f"{label} ({path}): must be WEB_ATTACK_SSRF, got {r.top_category} / {r.rules}"
        )
        assert "ssrf_internal_target" in r.rules, f"{label} ({path}): must fire ssrf_internal_target, got {r.rules}"
    print(f"Scenario 1 ({len(MALICIOUS)} SSRF-shaped payloads targeting internal/loopback/metadata: all classified WEB_ATTACK_SSRF) PASSED")

    for label, path in BENIGN:
        r = classify_request("GET", path)
        assert r.top_category != EventCategory.WEB_ATTACK_SSRF, (
            f"{label} ({path}): false positive -- classified as {r.top_category} / {r.rules}"
        )
    print(f"Scenario 2 ({len(BENIGN)} legitimate public URLs / bare mentions: zero false positives) PASSED")

    assert EventCategory.WEB_ATTACK_SSRF in _ATTACK_SIGNAL_CATEGORIES, (
        "WEB_ATTACK_SSRF must be a watched probing category so it can be corroborated/confirmed, "
        "matching every other WEB_ATTACK_* probe category"
    )
    assert EventCategory.WEB_ATTACK_SSRF in _SUBSCRIBED_CATEGORIES
    print("Scenario 3 (WEB_ATTACK_SSRF participates in the confirm-via-corroboration pipeline, like SSTI/XXE/etc) PASSED")

    print("\nALL SSRF DETECTION TESTS PASSED")


main()
