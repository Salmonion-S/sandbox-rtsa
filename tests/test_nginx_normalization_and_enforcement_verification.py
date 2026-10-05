import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import modules.nginx_monitor as nm
from config.manager import NginxMonitorConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from core.injection_signatures import iterative_decode

LOG_FILE = "/var/log/nginx/access.log"


def make_monitor(**overrides):
    overrides.setdefault("rce_correlation_enabled", False)
    mon = nm.NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True, **overrides))
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def access_line(path, status=200, method="GET", ip="35.196.132.85", ua="Mozilla/5.0", host="rmepro.com"):
    return f'{ip} - - [01/Jan/2026:00:00:00 +0000] "{method} {path} HTTP/1.1" {status} 100 "-" "{ua}" "{host}"'


def sqli_events(pub):
    return [e for e in pub if e.category == EventCategory.WEB_ATTACK_SQLI]


async def main_async() -> None:
    print("=== P6.1: bounded double-decode catches a double-percent-encoded SQLi payload the single-decode path missed ===")
    double_encoded_payload = "/?id=1%2527%2520OR%2520%25271%2527%253D%25271"
    mon, pub = make_monitor()
    await mon._process_access_line(
        access_line(double_encoded_payload, status=403), LOG_FILE, 1, domain="rmepro.com",
    )
    assert sqli_events(pub), (
        f"a double-percent-encoded classic SQLi tautology ('OR '1'='1) must still be detected via "
        f"bounded double-decode fallback matching, not silently bypassed: {pub}"
    )
    print("  double-percent-encoded SQLi payload detected via bounded decode fallback")

    print("\n=== P6.2: single-decoded (normal) SQLi payloads still detected without regression (no double-decode needed) ===")
    mon, pub = make_monitor()
    await mon._process_access_line(
        access_line("/?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--", status=403),
        LOG_FILE, 1, domain="rmepro.com",
    )
    assert sqli_events(pub), f"a plain single-encoded SQLi payload must still match on the cheap first pass: {pub}"
    print("  plain SQLi payload still detected on first pass (no behavior regression)")

    print("\n=== P6.3: benign traffic (including harmless percent-encoded content) never false-positives after the decode fallback ===")
    mon, pub = make_monitor()
    benign_paths = [
        "/search?q=how%2520to%2520cook%2520pasta",
        "/download?file=report%2520final.pdf",
        "/?a=1&b=2&c=3",
    ]
    for p in benign_paths:
        await mon._process_access_line(access_line(p, status=200), LOG_FILE, 1, domain="rmepro.com")
    assert sqli_events(pub) == [], f"benign double-encoded traffic must never trigger a false SQLi finding: {pub}"
    print(f"  {len(benign_paths)} benign (including double-percent-encoded) requests -- zero false positives")

    print("\n=== P6.4: iterative_decode is exported publicly from core.injection_signatures and applies bounded NFKC normalization ===")
    assert iterative_decode("caf%C3%A9") == "café"
    fullwidth = "ｓｅｌｅｃｔ"
    normalized = iterative_decode(fullwidth)
    assert normalized == "select", f"NFKC normalization must fold fullwidth evasion characters to ASCII: {normalized!r}"
    print("  iterative_decode() is public, bounded (max 3 rounds), and NFKC-normalizes fullwidth/compatibility characters")

    print("\n=== P7.1: a Cloudflare-edge-only status code (520) during live verification is classified ENFORCEMENT_UNVERIFIED, never asserted as BLOCKED BY NGINX ===")
    mon, pub = make_monitor(alert_unverified_web_hit_200=True, response_validation_enabled=True)

    async def fake_fetch(domain, path):
        return 520, "text/html", "<html><body>Cloudflare error 520: Web server is returning an unknown error</body></html>"

    mon._fetch = fake_fetch
    verdict, evidence, content_type = await mon._classify_response("rmepro.com", "/wp-config.php.bak")
    assert verdict == "enforcement_unverified", f"a 520 (Cloudflare-only status) must classify as enforcement_unverified, got {verdict!r}"
    assert evidence is None, "a Cloudflare edge error page must never be treated as confirmed-exploit evidence"
    print("  _classify_response() returns verdict='enforcement_unverified' for a live-fetch 520, with no fabricated evidence")

    print("\n=== P7.2: end-to-end -- the rendered Discord message for an enforcement_unverified hit is honest, never claims a specific blocking layer ===")
    mon2, pub2 = make_monitor(alert_unverified_web_hit_200=True, response_validation_enabled=True)
    mon2._fetch = fake_fetch
    await mon2._process_access_line(
        access_line("/?f=php://filter/convert.base64-encode/resource=index.php", status=200),
        LOG_FILE, 1, domain="rmepro.com",
    )
    await asyncio.sleep(0.05)
    for task in list(mon2._verify_tasks):
        await task
    matching = [e for e in pub2 if e.metadata.get("verification_verdict") == "enforcement_unverified"]
    assert matching, f"expected at least one published event with verification_verdict=enforcement_unverified: {[e.metadata for e in pub2]}"
    ev = matching[0]
    assert "ENFORCEMENT_UNVERIFIED" in ev.message, ev.message
    assert "tidak bisa dipastikan" in ev.message.lower(), (
        f"the message must explicitly hedge that the enforcement layer could not be determined, "
        f"rather than silently asserting one: {ev.message}"
    )
    assert "JANGAN diasumsikan" in ev.message, (
        f"message must explicitly warn against assuming 'BLOCKED BY NGINX' from this ambiguous "
        f"status, not merely omit the claim: {ev.message}"
    )
    assert ev.metadata.get("success") is False, "an enforcement_unverified hit must never be marked as a confirmed success"
    print("  end-to-end: enforcement_unverified hit renders an honest message, never fabricates 'BLOCKED BY NGINX'")

    print("\nALL NGINX NORMALIZATION + ENFORCEMENT VERIFICATION TESTS PASSED")


asyncio.run(main_async())
