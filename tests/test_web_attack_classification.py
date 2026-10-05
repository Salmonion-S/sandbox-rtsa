import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from core.injection_signatures import classify_request
from modules.nginx_monitor import (
    NginxMonitor, _LogSource, _classify_attack_outcome, _detect_success_evidence,
    _score_path_traversal,
)

SOURCE = _LogSource(log_file="/var/log/nginx/access.log", line_number=1, raw_line="raw")
TRAVERSAL = "/?file=../../../../etc/passwd"

PASSWD_BODY = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)
NEXTJS_FALLBACK_BODY = (
    '<!doctype html><html><head><title>Beranda</title></head><body>'
    '<div id="__next"></div><script id="__NEXT_DATA__" type="application/json">{}</script>'
    '</body></html>'
)
ENV_BODY = "APP_KEY=base64:abcdef\nDB_PASSWORD=hunter2\n<?php echo 1; ?>"


def make_monitor(**overrides):
    kwargs = dict(enabled=True, rce_correlation_enabled=False)
    kwargs.update(overrides)
    mon = NginxMonitor(EventBus(), NginxMonitorConfig(**kwargs))
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_meta(domain, source):
        return "", {"domain": domain or "example.com"}

    mon._build_web_attack_metadata = fake_meta
    return mon, published


def set_response(mon, status, content_type, body):
    async def fake_fetch(domain, path):
        return status, content_type, body
    mon._fetch = fake_fetch

    async def no_baseline(domain):
        return None
    mon._get_vhost_baseline = no_baseline


async def run_signature(mon, status, *, path=TRAVERSAL, ua="curl/8.0", size=19936):
    await mon._check_web_attack_signature(
        "203.0.113.7", path, "GET", ua, status, "example.com", SOURCE, response_size=size,
    )
    await asyncio.sleep(0)


async def main():
    mon, pub = make_monitor()
    await run_signature(mon, 404)
    assert len(pub) == 1, pub
    assert pub[0].metadata["classification"] == "ATTEMPT", pub[0].metadata
    assert pub[0].category == EventCategory.WEB_ATTACK_PATH_TRAVERSAL, pub[0].category
    assert pub[0].metadata["success"] is False
    assert pub[0].metadata["response_size"] == 19936
    print("Scenario 1 (PATH_TRAVERSAL + 404 -> ATTEMPT) PASSED")

    mon, pub = make_monitor()
    await run_signature(mon, 403)
    assert pub[0].metadata["classification"] == "BLOCKED", pub[0].metadata
    print("Scenario 2 (PATH_TRAVERSAL + 403 -> BLOCKED) PASSED")

    mon, pub = make_monitor()
    set_response(mon, 200, "text/plain", "harga produk: 19936")
    await run_signature(mon, 200)
    assert len(pub) == 1, pub
    ev = pub[0]
    assert ev.metadata["classification"] == "SUSPICIOUS", ev.metadata
    assert ev.category != EventCategory.WEB_ATTACK_SUCCESS, "200 alone must never be a confirmed breach"
    assert ev.category == EventCategory.WEB_ATTACK_PATH_TRAVERSAL
    assert ev.metadata["success"] is False
    assert ev.metadata["evidence_type"] is None
    assert ev.severity == Severity.MEDIUM
    print("Scenario 3 (PATH_TRAVERSAL + 200 tanpa evidence -> SUSPICIOUS, bukan WEB_ATTACK_SUCCESS) PASSED")

    mon, pub = make_monitor()
    set_response(mon, 200, "text/html; charset=utf-8", NEXTJS_FALLBACK_BODY)
    await run_signature(mon, 200)
    assert pub[0].metadata["classification"] == "SUSPICIOUS", pub[0].metadata
    assert pub[0].metadata["verification_verdict"] == "false_positive"
    print("Scenario 4/11 (PATH_TRAVERSAL + 200 dengan fallback Next.js -> SUSPICIOUS) PASSED")

    mon, pub = make_monitor()
    set_response(mon, 200, "text/plain", PASSWD_BODY)
    await run_signature(mon, 200)
    ev = pub[0]
    assert ev.metadata["classification"] == "CONFIRMED_SUCCESS", ev.metadata
    assert ev.category == EventCategory.WEB_ATTACK_SUCCESS
    assert ev.severity == Severity.CRITICAL
    assert ev.metadata["evidence_type"] == "PASSWD_FILE_DISCLOSURE"
    assert ev.metadata["success"] is True
    print("Scenario 5 (PATH_TRAVERSAL + 200 + bukti /etc/passwd -> CONFIRMED_SUCCESS) PASSED")

    mon, pub = make_monitor()
    set_response(mon, 200, "text/plain", ENV_BODY)
    await run_signature(mon, 200, path="/download?file=../../.aws/credentials")
    ev = pub[0]
    assert ev.metadata["classification"] == "CONFIRMED_SUCCESS", ev.metadata
    rendered = " ".join(ev.metadata["matched_indicators"]) + ev.message + str(ev.metadata)
    assert "hunter2" not in rendered, "a secret value must never leave the verification function"
    assert "base64:abcdef" not in rendered, "a secret value must never leave the verification function"
    print("Scenario 6 (credential evidence -> CONFIRMED_SUCCESS, nilai secret ter-redaksi) PASSED")

    for status in (301, 302, 307, 308):
        mon, pub = make_monitor()
        await run_signature(mon, status)
        assert pub[0].metadata["classification"] == "ATTEMPT", (status, pub[0].metadata)
        assert pub[0].category != EventCategory.WEB_ATTACK_SUCCESS
    print("Scenario 7 (PATH_TRAVERSAL + 301/302/307/308 -> ATTEMPT, bukan bukti eksekusi) PASSED")

    mon, pub = make_monitor()
    await run_signature(mon, 444)
    assert pub[0].metadata["classification"] == "BLOCKED", pub[0].metadata
    print("Scenario 8 (HTTP 444 -> BLOCKED) PASSED")

    double_encoded = "/x?p=%252e%252e%252fetc%252fpasswd&cmd=%253Bid"
    result = classify_request("GET", double_encoded)
    assert "double_url_encoding" in result.encoding_evasion, result
    assert result.top_category is not None, result
    print("Scenario 9 (double-encoded traversal/CMDi tetap terdeteksi) PASSED")

    mon, pub = make_monitor()
    await run_signature(mon, 200, path="/download?file=laporan-2026.pdf")
    assert pub == [], f"legitimate file query must not fire any signature: {pub}"
    print("Scenario 10 (legitimate file query -> tidak ada alert) PASSED")

    uas = [
        "Mozilla/5.0 (compatible; Google-Extended)",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "curl/8.0",
        "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0",
    ]
    scores = {ua: _score_path_traversal("/x?p=../../secret", 404, ua) for ua in uas}
    assert len(set(scores.values())) == 1, f"UA must not change the score: {scores}"

    outcomes = []
    for ua in uas:
        mon, pub = make_monitor()
        await run_signature(mon, 404, ua=ua)
        outcomes.append((len(pub), pub[0].metadata["classification"], pub[0].severity))
    assert len(set(outcomes)) == 1, f"detection outcome must be identical across UAs: {outcomes}"
    print("Scenario 12 (Google-Extended/Googlebot/curl/browser UA -> hasil deteksi identik) PASSED")

    malicious = ["/x?c=;id", "/x?c=|id", "/x?c=$(whoami)", "/x?c=`id`"]
    for path in malicious:
        mon, pub = make_monitor()
        await run_signature(mon, 404, path=path)
        assert pub, f"structural shell injection must be detected: {path}"
    for encoded, decoded in (("/x?c=%3Bid", "/x?c=;id"), ("/x?c=%7Cid", "/x?c=|id")):
        mon, pub = make_monitor()
        await run_signature(mon, 404, path=decoded)
        assert pub, f"decoded form must be detected: {decoded}"
        assert classify_request("GET", encoded).top_category is not None, encoded
    benign = [
        "/api/tools?name=curl", "/blog?tag=bash", "/search?q=whoami",
        "/p?a=1&b=2&c=3", "/docs?section=echo", "/u?id=42&sort=name",
    ]
    for path in benign:
        mon, pub = make_monitor()
        await run_signature(mon, 404, path=path)
        assert pub == [], f"a bare keyword/ampersand as a normal parameter must not fire: {path} -> {pub}"
    print("Scenario 34 (RCE structural terdeteksi; keyword & '&' biasa tidak false positive) PASSED")

    assert _detect_success_evidence("lihat daftar user: daemon:x:1:1:", min_score=2) is None
    assert _detect_success_evidence("<?php echo 'contoh kode'; ?>", min_score=2) is None
    assert _detect_success_evidence(PASSWD_BODY, min_score=2) is not None
    assert _detect_success_evidence(ENV_BODY, min_score=2) is not None
    assert _detect_success_evidence("DB_PASSWORD=hunter2\n", min_score=2) is not None
    assert _detect_success_evidence("Cara mengatur db_password di aplikasi Anda", min_score=2) is None
    assert _classify_attack_outcome(200, None) == "SUSPICIOUS"
    assert _classify_attack_outcome(500, None) == "ATTEMPT"
    assert _classify_attack_outcome(401, None) == "BLOCKED"
    print("Evidence scoring (satu indikator lemah != bukti; kombinasi indikator = bukti) PASSED")

    print("\nALL WEB ATTACK CLASSIFICATION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
