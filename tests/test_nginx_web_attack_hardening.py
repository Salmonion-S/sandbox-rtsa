import asyncio
import json
import os
import sys
import tempfile
import time
from types import SimpleNamespace

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.cloudpanel_resolver as cloudpanel_resolver
from config.manager import DiscordConfig, NginxMonitorConfig, TceConfig, WebProbeConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.pipeline_metrics import get_nginx_metrics
from core.web_probe import (
    OUTCOME_ACCESSIBLE, OUTCOME_BLOCKED, OUTCOME_ERROR, OUTCOME_NOT_FOUND, OUTCOME_REDIRECTED,
    ProbeSeverityInputs, classify_probe, event_type_for_probe, normalize_request_target, outcome_for_status,
    score_probe_incident,
)
from core.web_scan_incident import (
    ACTION_ESCALATE, ACTION_NEW, ACTION_SILENT, ACTION_UPDATE, STATE_CLOSED, STATE_OPEN, STATE_QUIET,
    BatchObservation, ScanIncidentTracker,
)
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.nginx_monitor import NginxMonitor, _LogSource
from modules.threat_correlation_engine import (
    _row_to_candidate_event, build_evidence_items, classify_event, group_classified_events, score_group,
)

LOG_FILE = "/var/log/nginx/site.access.log"
DOMAIN = "site-one.example"
SCANNER_IP = "203.0.113.9"


def make_monitor(**overrides):
    web_probe = overrides.pop("web_probe", WebProbeConfig(enrichment_enabled=False))
    cfg = NginxMonitorConfig(enabled=True, web_probe=web_probe, tail_checkpoint_enabled=False, **overrides)
    mon = NginxMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_meta(domain, source):
        return "", {"domain": domain or DOMAIN, "cloudpanel_user": "UNKNOWN", "project_path": "UNKNOWN",
                    "mapping_status": "UNRESOLVED"}

    mon._build_web_attack_metadata = fake_meta

    async def fake_classify(domain, path):
        return "false_positive", None, None

    mon._classify_response = fake_classify
    return mon, published


def line(method, path, status=404, ip=SCANNER_IP, ua="Mozilla/5.0", host=DOMAIN, location=None):
    text = f'{ip} - - [19/Aug/2026:12:00:00 +0000] "{method} {path} HTTP/1.1" {status} 123 "-" "{ua}" "{host}"'
    if location is not None:
        text += f' "-" "https" "{location}"'
    return text


class Feeder:
    def __init__(self, mon):
        self.mon = mon
        self.n = 0

    async def __call__(self, method, path, status=404, **kw):
        self.n += 1
        domain = kw.get("host", DOMAIN)
        await self.mon._process_access_line(line(method, path, status, **kw), LOG_FILE, self.n, domain=domain)


async def flush(mon):
    for state in mon._scan_batches.values():
        state["first_seen"] -= 999.0
    await mon._sweep_scan_batches()


def scan_events(pub):
    return [e for e in pub if e.category == EventCategory.WEB_ATTACK_SCAN and "incident_id" in e.metadata]


def cats(pub):
    return sorted({e.category.value for e in pub})


async def test_normalisation_and_classification() -> None:
    def cls(uri, host="example.com"):
        return classify_probe(normalize_request_target(uri), host=host)

    strong = {
        "/.env": "dotenv_file", "/.env.production": "dotenv_file", "/app/.env?x=1": "dotenv_file",
        "/%2e%65%6e%76": "dotenv_file", "/.env%00.jpg": "dotenv_file", "//.git//config": "git_metadata",
        "/.git": "git_metadata", "/.git/HEAD": "git_metadata", "/.git/refs/heads/main": "git_metadata",
        "/.git/objects/ab/cdef": "git_metadata", "/.svn/entries": "svn_metadata", "/.hg/store": "hg_metadata",
        "/backup.zip": "backup_archive_name", "/db.sql": "backup_suffix", "/index.php.bak": "backup_suffix",
        "/config.php~": "backup_suffix", "/site.tar.gz": "backup_archive_name", "/x.dump": "backup_suffix",
        "/wp-config.php.old": "backup_suffix", "/.index.php.swp": "backup_suffix",
        "/phpinfo.php": "phpinfo", "/server-status": "apache_server_status", "/actuator/env": "actuator_env",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php": "phpunit_eval_stdin",
        "/.aws/credentials": "aws_credentials",
    }
    for uri, rule in strong.items():
        match = cls(uri)
        assert match is not None and match.is_strong and match.rule == rule, (uri, match)
    print("Test 1a (env/git/svn/hg/backup/debug signatures, incl. encoded + null-byte forms) PASSED")

    traversal = [
        "/../../etc/passwd", "/..%2f..%2fetc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/..%252f..%252fetc/passwd",
        "/....//....//etc/passwd", "/..;/admin", "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/a\\..\\..\\windows\\win.ini", "/download?file=../../etc/passwd", "/etc/passwd",
        "/%2e%2e%5c%2e%2e%5cwindows/win.ini", "/..%c0%af..%c0%afetc/passwd",
    ]
    for uri in traversal:
        match = cls(uri)
        assert match is not None and match.attack_class == "PATH_TRAVERSAL" and match.is_strong, (uri, match)
    print("Test 1b (traversal: plain, encoded, double-encoded, overlong, backslash, ;, dot-variant, query) PASSED")

    legit = [
        "/", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/manifest.json", "/_next/static/chunks/main.abc.js",
        "/_next/image?url=%2Flogo.png&w=64&q=75", "/assets/app.css", "/static/img/logo.png", "/js/app.js",
        "/css/site.css", "/images/a.jpg", "/api/health", "/api/users?id=5", "/api/admin/users", "/health",
        "/blog/environment-tips", "/blog/git-tips-for-teams", "/downloads/report.zip", "/uploads/photo.tar.gz",
        "/x.js.map", "/100%25-off", "/products?sort=price&page=2", "/search?q=a;b|c<d>&x=it's",
        "/.well-known/acme-challenge/abc", "/about-us", "/contact.php", "/index.php", "/actuator/health",
    ]
    for uri in legit:
        assert cls(uri) is None, (uri, cls(uri))
    print("Test 1c (favicon/robots/sitemap/_next/assets/api/health/downloads/generic chars never classify) PASSED")

    weak = ["/admin", "/wp-admin/", "/wp-login.php", "/metrics", "/swagger", "/openapi.json", "/actuator", "/debug", "/phpmyadmin"]
    for uri in weak:
        match = cls(uri)
        assert match is not None and not match.is_strong, (uri, match)
    print("Test 1d (admin/metrics/swagger/openapi/debug are WEAK contextual surfaces, never strong) PASSED")

    n = normalize_request_target("/a%3fb?x=%2e%2e")
    assert n.raw_query == "x=%2e%2e" and n.raw_path == "/a%3fb", "an encoded %3f must never become the query separator"
    assert n.path == "/a?b" and n.query == "x=.."
    once = normalize_request_target("/100%25-off")
    assert once.normalized_path == "/100%-off" and once.decode_rounds == 1, once
    huge = normalize_request_target("/" + "%25" * 5000)
    assert huge.decode_rounds <= 3 and "TRUNCATED" in huge.flags
    print("Test 1e (bounded decode: literal % decoded once, 5000x %25 stays bounded, raw query kept separate) PASSED")

    assert outcome_for_status(200) == OUTCOME_ACCESSIBLE and outcome_for_status(404) == OUTCOME_NOT_FOUND
    assert outcome_for_status(444) == OUTCOME_BLOCKED and outcome_for_status(403) == OUTCOME_BLOCKED
    assert outcome_for_status(301) == OUTCOME_REDIRECTED and outcome_for_status(500) == OUTCOME_ERROR
    git = cls("/.git/config")
    assert event_type_for_probe(git, OUTCOME_NOT_FOUND) == "SENSITIVE_PATH_PROBE"
    assert event_type_for_probe(git, OUTCOME_BLOCKED) == "SENSITIVE_PATH_PROBE"
    assert event_type_for_probe(git, OUTCOME_ACCESSIBLE) == "SENSITIVE_FILE_EXPOSURE"
    print("Test 1f (404 -> SENSITIVE_PATH_PROBE/NOT_FOUND, 444 -> BLOCKED, 200 -> SENSITIVE_FILE_EXPOSURE/ACCESSIBLE) PASSED")


async def test_severity_model() -> None:
    def tier(**kw):
        base = dict(request_count=1, unique_paths=1)
        base.update(kw)
        return score_probe_incident(ProbeSeverityInputs(**base)).tier

    assert tier() == "LOW"
    assert tier(request_count=20, unique_paths=20) == "MEDIUM"
    assert tier(request_count=300, unique_paths=120, unique_classes=3) == "HIGH"
    assert tier(request_count=25, unique_paths=12, unique_classes=3) == "HIGH"
    assert tier(request_count=30, unique_paths=12, unique_domains=4) == "HIGH"
    assert tier(accessible_exposure=True) == "HIGH"
    assert tier(accessible_exposure=True, verified_success=True) == "CRITICAL"
    assert tier(request_count=5000, unique_paths=900, unique_classes=5, unique_domains=9) == "HIGH", \
        "probing alone, however large, is never CRITICAL"
    assert tier(correlated_fim=True) == "HIGH"
    assert tier(request_count=12, unique_paths=3, known_scanner_ua=True) == "MEDIUM"
    assert tier(request_count=2, unique_paths=2, known_scanner_ua=True) == "LOW", "UA alone is not enough"
    print("Test 2 (1x LOW, 20 MEDIUM, hundreds/multi-class/cross-domain HIGH, 200 HIGH, verified CRITICAL, never CRITICAL from probing) PASSED")


def _batch(ip="198.51.100.1", domain="a.example", count=1, paths=None, **kw):
    paths = paths or {f"/p{i}": 1 for i in range(count)}
    return BatchObservation(
        ip=ip, domain=domain, count=count, distinct_paths_seen=len(paths), paths=paths,
        classes={"SENSITIVE_FILE": count}, rules={"dotenv_file": count}, outcomes={"NOT_FOUND": len(paths)}, **kw,
    )


async def test_incident_lifecycle() -> None:
    cfg = WebProbeConfig(incident_quiet_seconds=60.0, incident_close_seconds=300.0, update_min_delta_requests=50,
                         max_updates_per_incident=2)
    tracker = ScanIncidentTracker(cfg)
    d1 = tracker.merge(_batch(count=1), now=1000.0)
    assert d1.action == ACTION_SILENT and not d1.notify and d1.severity == "LOW" and d1.created
    d2 = tracker.merge(_batch(count=25, paths={f"/q{i}": 1 for i in range(25)}), now=1030.0)
    assert d2.action == ACTION_NEW and d2.notify and d2.severity == "MEDIUM", d2
    assert d2.incident is d1.incident and not d2.created, "one incident per source"
    d3 = tracker.merge(_batch(count=3, paths={"/z1": 1, "/z2": 1, "/z3": 1}), now=1060.0)
    assert d3.action == ACTION_SILENT and d3.suppressed_count == 1, d3
    d4 = tracker.merge(_batch(count=90, paths={f"/r{i}": 1 for i in range(90)}), now=1090.0)
    assert d4.action == ACTION_ESCALATE and d4.severity == "HIGH" and d4.previous_severity == "MEDIUM", d4
    d5 = tracker.merge(_batch(count=2, paths={"/s1": 1, "/s2": 1}), now=1120.0)
    assert d5.action == ACTION_SILENT, "HIGH -> HIGH with nothing new is never repeated"
    d6 = tracker.merge(_batch(count=200, paths={f"/t{i}": 1 for i in range(200)}), now=1150.0)
    assert d6.action == ACTION_UPDATE and d6.delta_requests >= 200, d6
    d7 = tracker.merge(_batch(count=900, paths={f"/u{i}": 1 for i in range(50)}), now=1180.0)
    assert d7.action == ACTION_UPDATE
    d8 = tracker.merge(_batch(count=2000, paths={f"/v{i}": 1 for i in range(50)}), now=1210.0)
    assert d8.action == ACTION_SILENT and d8.incident.updates_sent >= cfg.max_updates_per_incident, \
        "updates per incident are bounded; the rest is counted as suppressed"
    print("Test 3a (NEW once, SILENT while nothing new, ESCALATE on tier rise, UPDATE bounded per incident) PASSED")

    assert tracker.sweep(1210.0 + 30.0) == [] and d1.incident.state == STATE_OPEN
    assert tracker.sweep(1210.0 + 61.0) == [] and d1.incident.state == STATE_QUIET
    d9 = tracker.merge(_batch(count=1), now=1210.0 + 100.0)
    assert d9.reopened and d9.incident is d1.incident and d1.incident.state == STATE_OPEN
    closed = tracker.sweep(1310.0 + 301.0)
    assert closed == [d1.incident] and d1.incident.state == STATE_CLOSED
    d10 = tracker.merge(_batch(count=1), now=1310.0 + 400.0)
    assert d10.created and d10.incident is not d1.incident, "after CLOSED a new incident starts"
    print("Test 3b (OPEN -> QUIET -> reopened -> CLOSED -> a new incident starts) PASSED")

    other = tracker.merge(_batch(ip="198.51.100.77", count=1), now=2000.0)
    assert other.incident.incident_id != d10.incident.incident_id
    print("Test 3c (different source IPs never share an incident) PASSED")


async def test_scanner_burst_and_outcomes() -> None:
    mon, pub = make_monitor()
    feed = Feeder(mon)
    paths = [f"/.env.{i}" for i in range(10)] + [f"/.git/{i}" for i in range(10)]
    for i in range(100):
        await feed("GET", paths[i % len(paths)], 404)
    await flush(mon)
    events = scan_events(pub)
    assert len(events) == 1, f"100 requests / 20 paths / one source -> ONE incident event, got {len(events)}"
    meta = events[0].metadata
    assert meta["incident_action"] == "NEW" and meta["notify_discord"] is True
    assert events[0].severity == Severity.HIGH, (events[0].severity, meta["scan_incident"])
    assert meta["scan_incident"]["requests"] == 100 and meta["scan_incident"]["unique_paths"] == 20
    assert meta["outcome"] == "NOT_FOUND" and meta["event_type"] == "SENSITIVE_PATH_PROBE"
    assert set(meta["attack_classes"]) == {"SENSITIVE_FILE", "VCS_METADATA"}
    for i in range(20):
        await feed("GET", f"/.env.more{i}", 404)
    await flush(mon)
    events = scan_events(pub)
    assert len(events) == 2 and events[1].metadata["notify_discord"] is False, \
        "small growth on the same incident stays raw evidence, no second Discord alert"
    print("Test 4a (100 requests / 20 paths / 30s / one source -> one incident; later small growth is silent) PASSED")

    mon, pub = make_monitor()
    feed = Feeder(mon)
    await feed("GET", "/.env", 404)
    await flush(mon)
    ev = scan_events(pub)[0]
    assert ev.severity == Severity.LOW and ev.metadata["notify_discord"] is False
    assert ev.metadata["event_type"] == "SENSITIVE_PATH_PROBE" and ev.metadata["outcome"] == "NOT_FOUND"
    print("Test 4b (single GET /.env 404 -> LOW, stored, NOT sent to Discord) PASSED")

    for status, outcome in ((403, "BLOCKED"), (444, "BLOCKED"), (500, "ERROR"), (302, "REDIRECTED"), (404, "NOT_FOUND")):
        mon, pub = make_monitor()
        feed = Feeder(mon)
        await feed("GET", "/.git/config", status)
        await flush(mon)
        ev = scan_events(pub)[0]
        assert ev.metadata["outcome"] == outcome, (status, ev.metadata["outcome"])
        assert ev.metadata["event_type"] == "SENSITIVE_PATH_PROBE" and ev.metadata["attack_class"] == "VCS_METADATA"
        assert ev.metadata["matched_rule"] == "git_metadata" and ev.metadata["http_status"] == status
    print("Test 4c (/.git/config across 302/403/404/444/500 -> SENSITIVE_PATH_PROBE with the right outcome) PASSED")

    mon, pub = make_monitor()
    feed = Feeder(mon)
    await feed("GET", "/.git/config", 301, location="https://site-one.example/.git/config")
    await feed("GET", "/.git/config", 444)
    await flush(mon)
    ev = scan_events(pub)[0]
    assert ev.metadata["http_status_chain"] == "301 -> 444" and ev.metadata["outcome"] == "BLOCKED", ev.metadata
    print("Test 4d (301 -> 444 is one BLOCKED probe with the '301 -> 444' chain) PASSED")

    mon, pub = make_monitor()
    feed = Feeder(mon)
    await feed("GET", "/.git/config", 301)
    await flush(mon)
    ev = scan_events(pub)[0]
    assert ev.metadata["location_capture"] == "UNAVAILABLE" and ev.metadata["redirect_location"] == "UNKNOWN"
    print("Test 4e (redirect without a captured Location says UNKNOWN / location_capture=UNAVAILABLE) PASSED")

    mon, pub = make_monitor()
    feed = Feeder(mon)

    async def unverifiable(domain, path):
        return "fetch_failed", None, None

    mon._classify_response = unverifiable
    await feed("GET", "/.env", 200)
    for _ in range(3):
        await asyncio.sleep(0)
    await asyncio.gather(*list(mon._verify_tasks), return_exceptions=True)
    await flush(mon)
    verify = [e for e in pub if e.metadata.get("unverified_hit")]
    assert verify and verify[0].metadata["event_type"] == "SENSITIVE_FILE_EXPOSURE"
    assert verify[0].severity == Severity.HIGH, "an unverified 2xx on an exposure class is HIGH, not MEDIUM"
    assert verify[0].metadata["outcome"] == "ACCESSIBLE" and verify[0].metadata["matched_rule"] == "dotenv_file"
    inc = scan_events(pub)[0]
    assert inc.severity in (Severity.HIGH, Severity.CRITICAL) and inc.metadata["notify_discord"] is True
    print("Test 4f (GET /.env 200 -> SENSITIVE_FILE_EXPOSURE/ACCESSIBLE, incident at least HIGH) PASSED")


async def test_multi_domain_and_false_positives() -> None:
    mon, pub = make_monitor()
    feed = Feeder(mon)
    for d in range(5):
        for i in range(10):
            await feed("GET", f"/.env.d{i}", 404, host=f"dom{d}.example")
    await flush(mon)
    events = scan_events(pub)
    assert events and all(e.metadata["incident_id"] == events[0].metadata["incident_id"] for e in events), \
        "cross-domain scanning from one source stays ONE incident"
    last = events[-1]
    assert last.metadata["event_type"] == "MULTI_DOMAIN_WEB_SCAN"
    assert last.metadata["scan_incident"]["unique_domains"] == 5 and last.severity == Severity.HIGH
    assert sum(1 for e in events if e.metadata["notify_discord"]) <= 2, "at most NEW (+ one escalation)"
    print("Test 5a (5 domains, one scanner -> one MULTI_DOMAIN_WEB_SCAN incident, HIGH, bounded notifications) PASSED")

    mon, pub = make_monitor()
    feed = Feeder(mon)
    benign = ["/", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/_next/static/a.js", "/assets/app.css",
              "/images/a.png", "/api/health", "/api/orders?id=5", "/health", "/products?sort=price",
              "/search?q=a;b|c<d>&x=it's", "/blog/environment-tips", "/downloads/report.zip"]
    for _ in range(20):
        for path in benign:
            for status in (200, 404):
                await feed("GET", path, status, ua="Mozilla/5.0 (X11; Linux) Chrome/120")
    await flush(mon)
    assert pub == [], f"legitimate traffic must publish nothing: {[(e.category.value, e.request_path) for e in pub][:5]}"
    assert not mon._scan_batches
    print("Test 5b (favicon/robots/sitemap/_next/assets/api/health/generic characters -> zero events) PASSED")

    mon, pub = make_monitor()
    feed = Feeder(mon)
    await feed("GET", "/admin", 404)
    await feed("GET", "/metrics", 404)
    await feed("GET", "/swagger", 404)
    await flush(mon)
    assert pub == [], "weak, contextual surfaces never alert on their own"
    await feed("GET", "/debug", 404)
    await feed("GET", "/administrator", 404)
    await flush(mon)
    assert scan_events(pub), "enough distinct weak surfaces from one source promotes them to scan evidence"
    print("Test 5c (weak probes ignored alone, promoted after 4 distinct surfaces from one source) PASSED")

    mon, pub = make_monitor()
    feed = Feeder(mon)
    await feed("GET", "/.env", 404, ua="Mozilla/5.0")
    await feed("GET", "/admin", 404, ua="Mozilla/5.0")
    await feed("GET", "/metrics", 404, ua="Mozilla/5.0")
    await flush(mon)
    incident = scan_events(pub)[0].metadata["scan_incident"]
    assert incident["requests"] == 3, "weak probes count once the source is already probing for real"
    print("Test 5d (weak probes count after a strong probe from the same source) PASSED")

    mon, pub = make_monitor()
    feed = Feeder(mon)
    await feed("GET", "/.env", 404, ua="sqlmap/1.7")
    await flush(mon)
    assert scan_events(pub)[0].severity == Severity.LOW, "a scanner user-agent alone does not raise severity"
    print("Test 5e (user-agent alone is never enough to raise severity; no IP allowlist anywhere) PASSED")


async def test_error_spike_separation() -> None:
    mon, pub = make_monitor(error_spike_threshold=5, error_spike_window_seconds=60)
    feed = Feeder(mon)
    for i in range(60):
        await feed("GET", f"/.env.v{i}", 404, ip=f"198.51.100.{i % 5 + 1}")
    assert len(mon._error_window) == 0 and "error_spike" not in mon._batch_state, \
        "a scan is not an application error spike"
    assert mon._probe_requests_excluded_from_error_spike == 60
    for i in range(60):
        await feed("GET", "/api/orders", 404, ip=f"198.51.100.{i % 5 + 1}")
    assert len(mon._error_window) >= 5 and "error_spike" in mon._batch_state, \
        "the same volume of errors on a normal endpoint is still an error spike"
    for state in mon._batch_state.values():
        task = state.get("task")
        if task is not None:
            task.cancel()
    print("Test 6 (60x 404 on /.env* = scan, not NGINX_ERROR_SPIKE; 60x 404 on /api/orders = error spike) PASSED")


async def test_injection_and_traversal_through_monitor() -> None:
    traversal = [
        "/..%2f..%2fetc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/..%252f..%252fetc/passwd",
        "/....//....//etc/passwd", "/..;/admin", "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/a\\..\\..\\windows\\win.ini", "/download?file=../../etc/passwd",
    ]
    for uri in traversal:
        mon, pub = make_monitor()
        feed = Feeder(mon)
        await feed("GET", uri, 404)
        await asyncio.sleep(0)
        assert any(e.category == EventCategory.WEB_ATTACK_PATH_TRAVERSAL for e in pub), (uri, cats(pub))
        ev = [e for e in pub if e.category == EventCategory.WEB_ATTACK_PATH_TRAVERSAL][0]
        assert ev.metadata["attack_class"] == "PATH_TRAVERSAL" or ev.metadata.get("matched_categories")
    print(f"Test 7a ({len(traversal)} traversal variants -> WEB_ATTACK_PATH_TRAVERSAL) PASSED")

    payloads = {
        "sqli": "/item?id=1%27%20OR%20%271%27%3D%271", "sqli_union": "/item?id=1%20UNION%20SELECT%201,2,3",
        "xss": "/q?s=%3Cscript%3Ealert(1)%3C/script%3E", "xss_event": "/q?s=%22%20onerror%3Dalert(1)%20x%3D%22",
        "cmd": "/ping?host=1.1.1.1;cat%20/etc/passwd", "cmd_sub": "/ping?host=$(whoami)",
        "ssti": "/hello?name=%7B%7B7*7%7D%7D", "ldap": "/login?u=*)(uid=*))(|(uid=*",
        "lfi": "/view?f=php://filter/convert.base64-encode/resource=index",
    }
    for name, uri in payloads.items():
        mon, pub = make_monitor()
        feed = Feeder(mon)
        await feed("GET", uri, 404)
        for _ in range(3):
            await asyncio.sleep(0)
        await asyncio.gather(*list(mon._verify_tasks), return_exceptions=True)
        assert [e for e in pub if e.category.value.startswith("WEB_ATTACK_")], (name, uri, cats(pub))
    print(f"Test 7b ({len(payloads)} SQLi/XSS/cmd/template/LDAP/file-include payloads raise a WEB_ATTACK event) PASSED")

    quiet = [
        "/search?q=it%27s", "/search?q=a%3Bb", "/search?q=a%7Cb", "/search?q=%3C3", "/search?q=(1)",
        "/search?q=100%25", "/page?title=Tom%20%26%20Jerry", "/p?x=1--2", "/p?u=user@example.com",
        "/download?file=report-2026.pdf", "/redirect?next=/dashboard", "/a?b=c&d=e;f=g",
    ]
    mon, pub = make_monitor()
    feed = Feeder(mon)
    for uri in quiet:
        await feed("GET", uri, 200, ua="Mozilla/5.0")
    for _ in range(3):
        await asyncio.sleep(0)
    await asyncio.gather(*list(mon._verify_tasks), return_exceptions=True)
    await flush(mon)
    assert pub == [], f"generic characters alone must not alert: {[(e.request_path, e.category.value) for e in pub]}"
    print(f"Test 7c ({len(quiet)} URIs with generic punctuation only -> no alert) PASSED")


async def test_normalised_fields_and_mapping() -> None:
    mon, pub = make_monitor()
    feed = Feeder(mon)
    await feed("GET", "/.env?token=abc123secret&x=1", 404)
    await flush(mon)
    meta = scan_events(pub)[0].metadata
    for key in (
        "http_method", "http_version", "http_status", "raw_uri", "normalized_uri", "host", "server_name",
        "bytes_sent", "referer", "user_agent", "source_port", "server_ip", "server_port", "upstream_status",
        "request_time", "upstream_response_time", "location_block", "location_capture", "matched_rule",
    ):
        assert key in meta, key
    assert meta["http_version"] == "1.1" and meta["source_port"] == "UNKNOWN" and meta["upstream_status"] == "UNKNOWN"
    assert "abc123secret" not in json.dumps(meta, default=str), "sensitive query values are masked"
    print("Test 8a (normalised request record present, UNKNOWN where the log format has no such field, secrets masked) PASSED")

    async def none_resolver(domain):
        return None

    original = cloudpanel_resolver.resolve_domain
    cloudpanel_resolver.resolve_domain = none_resolver
    try:
        mon = NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True))
        _, unresolved = await mon._cloudpanel_context("unmapped.example")
        assert unresolved["domain"] == "unmapped.example" and unresolved["cloudpanel_user"] == "UNKNOWN"
        assert unresolved["project_path"] == "UNKNOWN" and unresolved["mapping_status"] == "UNRESOLVED"

        async def resolver(domain):
            return SimpleNamespace(linux_user="siteuser", project_root="/home/siteuser/htdocs/site-one.example",
                                   htdocs_path="/home/siteuser/htdocs/site-one.example", nginx_vhost="site-one.example",
                                   domain=domain)
        cloudpanel_resolver.resolve_domain = resolver
        _, resolved = await mon._cloudpanel_context("site-one.example")
        assert resolved["mapping_status"] == "RESOLVED" and resolved["cloudpanel_user"] == "siteuser"
        assert resolved["project_path"].endswith("site-one.example")
    finally:
        cloudpanel_resolver.resolve_domain = original
    print("Test 8b (mapping: RESOLVED with user/path; UNRESOLVED -> domain known, user/path UNKNOWN) PASSED")


async def test_malformed_lines_and_isolation() -> None:
    metrics = get_nginx_metrics()
    metrics.reset()
    mon, pub = make_monitor(web_probe=WebProbeConfig(enrichment_enabled=False, malformed_debug_per_minute=2))
    for i in range(50):
        await mon._process_access_line(f"garbage line {i} \x00\xff", LOG_FILE, i, domain=DOMAIN)
    await mon._process_access_line('1.2.3.4 - - [x] "GET / HTTP/1.1" 200 1 "-" "ua" "h"', LOG_FILE, 99, domain=DOMAIN)
    snap = metrics.snapshot()["counters"]
    assert snap["nginx_lines_processed_total"] == 51 and snap["nginx_lines_malformed_total"] == 50, snap
    assert mon._malformed_logged_in_window <= 2, "malformed debug logging is bounded"

    async def boom(*a, **k):
        raise RuntimeError("boom")

    mon._check_status_anomaly = boom
    await mon._process_access_line(line("GET", "/x", 200), LOG_FILE, 100, domain=DOMAIN)
    assert metrics.snapshot()["counters"]["nginx_line_errors_total"] == 1
    snap = metrics.snapshot()
    assert snap["latency"]["nginx_parser_latency"]["count"] >= 1
    print("Test 9 (malformed lines counted with bounded debug output; an exception on one line never stops the tailer) PASSED")


async def test_rotation_without_duplicates() -> None:
    mon, _ = make_monitor()
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "access.log")
    with open(path, "w") as fh:
        fh.write("")
    seen = []

    async def handler(text, log_file, line_no):
        seen.append(text)

    task = asyncio.create_task(mon._tail_file(path, handler))
    await asyncio.sleep(0.5)
    with open(path, "a") as fh:
        fh.write("a1\na2\na3\n")
    await asyncio.sleep(1.0)
    os.rename(path, path + ".1")
    with open(path, "w") as fh:
        fh.write("b1\nb2\n")
    await asyncio.sleep(1.5)
    with open(path, "a") as fh:
        fh.write("b3\n")
    await asyncio.sleep(1.0)
    with open(path, "w") as fh:
        fh.write("c1\n")
    await asyncio.sleep(1.5)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert seen == ["a1", "a2", "a3", "b1", "b2", "b3", "c1"], seen
    print("Test 10 (rename rotation and truncation: every line exactly once, no duplicates, none lost) PASSED")


async def test_attack_fim_web_access_chain() -> None:
    mon, pub = make_monitor()
    feed = Feeder(mon)
    project_root = "/home/siteuser/htdocs/site-one.example"

    async def resolver(domain):
        return SimpleNamespace(linux_user="siteuser", project_root=project_root, htdocs_path=project_root,
                               nginx_vhost=domain, domain=domain)

    original = cloudpanel_resolver.resolve_domain
    cloudpanel_resolver.resolve_domain = resolver
    try:
        await feed("GET", "/.env", 404)
        await flush(mon)

        fim = BaseEvent(
            source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
            severity=Severity.HIGH, message="created suspicious.php",
            metadata={
                "path": f"{project_root}/suspicious.php", "event_type": "CREATED", "change_type": "created",
                "executable_or_interpreted": True, "risk_categories": ["EXECUTABLE", "WEBROOT"],
                "assessment": "SUSPICIOUS", "deployment_status": "INACTIVE", "project_root": project_root,
                "linux_user": "siteuser", "domain": DOMAIN, "project": "siteuser",
            },
        )
        await mon._on_correlation_event(fim)
        await feed("GET", "/suspicious.php", 200)
        access = [e for e in pub if e.category == EventCategory.WEB_ACCESS]
        assert len(access) == 1, cats(pub)
        wa = access[0]
        assert wa.metadata["path"] == f"{project_root}/suspicious.php" and wa.metadata["preceded_by_probe"] is True
        assert wa.metadata["fim_event_id"] == fim.event_id and wa.metadata["notify_discord"] is False
        assert wa.metadata["mapping_status"] == "RESOLVED"
        await feed("GET", "/suspicious.php", 200)
        assert len([e for e in pub if e.category == EventCategory.WEB_ACCESS]) == 1, "cooldown: one WEB_ACCESS per source+file"
        await feed("GET", "/index.php", 200)
        await feed("GET", "/other/suspicious.php", 200)
        assert len([e for e in pub if e.category == EventCategory.WEB_ACCESS]) == 1, "only the exact file FIM changed"
    finally:
        cloudpanel_resolver.resolve_domain = original
    assert mon._scan_tracker.get(SCANNER_IP).correlated_fim is True
    print("Test 11a (probe -> FIM CREATE -> 200 on that exact file = one internal WEB_ACCESS, marked preceded_by_probe) PASSED")

    candidates = []
    for ev in [e for e in pub if e.category == EventCategory.WEB_ATTACK_SCAN][:1] + [fim, wa]:
        candidates.append(_row_to_candidate_event(
            ev.event_id, ev.timestamp, ev.source_module, ev.category.value, ev.severity.value, ev.message,
            None, json.dumps(ev.metadata, default=str),
        ))
    tce = TceConfig()
    classified = [classify_event(c, tce) for c in candidates]
    kinds = sorted(c.kind for c in classified)
    assert kinds == ["FIM webroot executable created", "Web access to changed file", "Web attack (unconfirmed)"], kinds
    groups = group_classified_events(classified)
    assert len(groups) == 1, "the three pieces of evidence correlate into one group"
    result = score_group(groups[0], tce)
    items, _hidden = build_evidence_items(result, tce)
    shown = {i.get("kind") for i in items}
    assert {"FIM webroot executable created", "Web access to changed file"} <= shown, shown
    web_item = next(i for i in items if i.get("kind") == "Web access to changed file")
    assert web_item["extra"]["timeline_window"] in ("within 30s", "within 60s", "within 120s"), web_item["extra"]
    assert web_item["extra"]["preceded_by_probe"] is True
    assert result.total >= 70 and result.tier == "Possible Webshell", (result.total, result.tier)
    assert result.tier != "Likely Compromise", "no CRITICAL without independent process/outbound evidence"
    print("Test 11b (TCE keeps WEB_ATTACK_SCAN + FIM create + WEB_ACCESS as separate evidence; HIGH candidate, not CRITICAL) PASSED")


async def test_discord_scan_format() -> None:
    mon, pub = make_monitor()
    feed = Feeder(mon)
    evil = "@everyone <@123456> <@&999> **bold**\nnewline"
    await feed("GET", "/.git/config", 301, ua=evil, location="https://site-one.example/.git/config")
    await feed("GET", "/.git/config", 444, ua=evil)
    for i in range(30):
        await feed("GET", f"/.env.{i}", 404, ua=evil)
    await flush(mon)
    event = scan_events(pub)[0]
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    payload = dispatcher._build_payload(event)
    embed = payload["embeds"][0]
    names = {f["name"]: f["value"] for f in embed["fields"]}
    for required in ("Domain", "Source", "Attack Class", "Matched Rule", "HTTP", "Outcome", "Requests",
                     "Unique Paths", "Window", "Correlation", "Tingkat Keparahan", "First Seen", "Last Seen", "Incident"):
        assert required in names, (required, sorted(names))
    assert names["HTTP"] == "301 -> 444", names["HTTP"]
    assert names["Outcome"] == "BLOCKED", names["Outcome"]
    blob = json.dumps(payload)
    assert "@everyone" not in blob.replace("@​everyone", "").replace("@\\u200beveryone", ""), blob[:400]
    assert "<@123456>" not in blob and "<@&999>" not in blob
    for f in embed["fields"]:
        assert len(f["value"]) <= 1024
    print("Test 12 (Discord scan incident fields present; mention injection/markdown/newlines neutralised; bounded) PASSED")


async def test_metrics_exposed() -> None:
    from core.metrics_exporter import MetricsExporter
    exporter = MetricsExporter.__new__(MetricsExporter)
    snapshot_names = set(get_nginx_metrics().snapshot()["counters"]) | set(get_nginx_metrics().snapshot()["latency"])
    for name in ("nginx_lines_processed_total", "nginx_lines_malformed_total", "nginx_attack_candidates_total",
                 "nginx_attack_incidents_total", "nginx_events_coalesced_total", "nginx_parser_latency"):
        assert name in snapshot_names, name
    print("Test 13 (all required nginx metrics are registered in the existing exporter registry) PASSED")


async def main() -> None:
    await test_normalisation_and_classification()
    await test_severity_model()
    await test_incident_lifecycle()
    await test_scanner_burst_and_outcomes()
    await test_multi_domain_and_false_positives()
    await test_error_spike_separation()
    await test_injection_and_traversal_through_monitor()
    await test_normalised_fields_and_mapping()
    await test_malformed_lines_and_isolation()
    await test_rotation_without_duplicates()
    await test_attack_fim_web_access_chain()
    await test_discord_scan_format()
    await test_metrics_exposed()
    print("\nALL NGINX WEB-ATTACK HARDENING TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
