import asyncio
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import discord_integration.bot as bot
import modules.nginx_monitor as nm
from config.manager import (
    CloudflareConfig, DiscordConfig, ModulesConfig, NginxMonitorConfig, ResponseEngineConfig, RTSAConfig,
)
from core.datatypes import EventCategory
from config.manager import ResourceGovernorConfig
from core.cpu_governor import configure_cpu_governor
from core.event_bus import EventBus
from core.injection_signatures import classify_request
from discord_integration.bot import RTSABot, _hardening_rule_names_present

LOG_FILE = "/var/log/nginx/access.log"

MALICIOUS = [
    ("backtick + echo (reported bug shape)", "/?host=%60echo+GSCAN_CMDI%60"),
    ("backtick + whoami", "/?cmd=%60whoami%60"),
    ("backtick + id", "/?x=%60id%60"),
    ("$(whoami)", "/?x=$(whoami)"),
    ("$(id)", "/?x=$(id)"),
    ("semicolon + id, literal", "/?x=;id"),
    ("pipe + id, literal", "/?x=|id"),
    ("pipe + id, percent-encoded", "/?x=%7Cid"),
    ("semicolon + id, percent-encoded", "/?x=%3Bid"),
    ("semicolon + id, double percent-encoded", "/?x=%253Bid"),
    ("pipe + id, double percent-encoded", "/?x=%257Cid"),
]

BENIGN = [
    ("bare 'curl' query value", "/?q=curl"),
    ("bare 'wget' query value", "/?q=wget"),
    ("bare 'bash' query value", "/search?keyword=bash"),
    ("bare 'echo' query value", "/artikel?query=echo"),
    ("bare 'whoami' query value", "/?q=whoami"),
    ("bare 'id' query value", "/?q=id"),
    ("download-tool-name param", "/page?tool=download"),
    ("legitimate download URL param", "/page?url=https://example.com/file"),
    ("multi-param query with '&'", "/?a=1&b=2&c=3"),
    ("filename mentioning curl", "/download?file=curl-installer.sh"),
    ("search query mentioning bash tutorial", "/search?q=how+to+use+bash+scripting"),
]


def main_sync():
    print("=== A. classify_request() (core/injection_signatures.py) ===")
    for label, path in MALICIOUS:
        r = classify_request("GET", path)
        assert r.top_category == EventCategory.WEB_ATTACK_RCE, f"{label} ({path}): must be WEB_ATTACK_RCE, got {r.top_category} / {r.rules}"
        assert r.confidence >= 55, f"{label} ({path}): confidence too low ({r.confidence}) for a clear RCE payload"
    print(f"  {len(MALICIOUS)} malicious payloads -- all classified WEB_ATTACK_RCE with confidence >= 55")

    for label, path in BENIGN:
        r = classify_request("GET", path)
        assert r.top_category != EventCategory.WEB_ATTACK_RCE, f"{label} ({path}): false positive -- classified as {r.top_category} / {r.rules}"
    print(f"  {len(BENIGN)} benign requests -- zero classified as WEB_ATTACK_RCE")

    print("\n=== B. nginx_monitor.py local RCE regex (single-decode, real-time log path) ===")
    import urllib.parse
    rce_pattern = next(p for c, p, _ in nm._WEB_ATTACK_SIGNATURES if c == EventCategory.WEB_ATTACK_RCE)
    single_decode_cases = [(l, p) for l, p in MALICIOUS if "double percent-encoded" not in l]
    for label, path in single_decode_cases:
        decoded = urllib.parse.unquote(path)
        assert rce_pattern.search(decoded), f"{label} ({path}): nginx_monitor RCE regex must match {decoded!r}"
    print(
        f"  {len(single_decode_cases)} malicious payloads -- all matched by the single-decode local regex "
        f"(double-encoding needs classify_request's iterative decode, covered in section A instead)"
    )
    for label, path in BENIGN:
        decoded = urllib.parse.unquote(path)
        assert not rce_pattern.search(decoded), f"{label} ({path}): false positive on nginx_monitor RCE regex, decoded={decoded!r}"
    print(f"  {len(BENIGN)} benign requests -- zero false positives")

    print("\n=== C. Nginx rce_command_injection_block ($request_uri ~* structural simulation) ===")
    marker = bot._RCE_COMMAND_INJECTION_BLOCK_MARKER
    inner = marker[len('if ($request_uri ~* "'):-len('")')]
    nginx_pattern = re.compile(inner, re.IGNORECASE)
    for label, path in MALICIOUS:
        if "double percent-encoded" in label:
            continue
        assert nginx_pattern.search(path), f"{label} ({path}): Nginx rule must match the raw \\$request_uri {path!r}"
    print(f"  {len(MALICIOUS) - 2} malicious payloads (single-encoded/literal, matches Nginx's undecoded $request_uri) -- all matched")
    for label, path in BENIGN:
        assert not nginx_pattern.search(path), f"{label} ({path}): Nginx rule false positive on {path!r}"
    print(f"  {len(BENIGN)} benign requests -- zero false positives, '&' alone never blocked")

    built = bot._build_rce_command_injection_block("    ")
    assert marker in built, "the marker constant must be a literal substring of what the builder inserts (idempotency depends on this)"
    print("  marker/builder content consistent (idempotency-safe)")


def make_monitor(**overrides):
    overrides.setdefault("rce_correlation_enabled", False)
    mon = nm.NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True, **overrides))
    published = []
    mon.publish = lambda ev: published.append(ev)
    return mon, published


def access_line(path, status=200, method="GET", ip="35.196.132.85", ua="Mozilla/5.0", host="rmepro.com"):
    return f'{ip} - - [01/Jan/2026:00:00:00 +0000] "{method} {path} HTTP/1.1" {status} 100 "-" "{ua}" "{host}"'


def rce_events(pub):
    return [e for e in pub if e.category == EventCategory.WEB_ATTACK_RCE]


async def main_async():
    print("\n=== D. End-to-end NginxMonitor._process_access_line, incl. the exact reported bug shape ===")
    mon, pub = make_monitor()
    await mon._process_access_line(
        access_line("/?host=%60echo+GSCAN_CMDI%60", status=200, ua="Discordbot/2.0"),
        LOG_FILE, 1, domain="rmepro.com",
    )
    assert rce_events(pub), f"the exact reported payload must still alert end-to-end: {pub}"
    print("  reported bug shape (Discordbot UA, HTTP 200) -- WEB_ATTACK_RCE published as expected")

    print("\n=== E. User-Agent never gates detection (never a whitelist basis) ===")
    for ua_label, ua in (
        ("Googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
        ("Discordbot", "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"),
        ("ordinary browser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
    ):
        mon, pub = make_monitor()
        await mon._process_access_line(access_line("/?x=;id", status=403, ua=ua), LOG_FILE, 1, domain="rmepro.com")
        assert rce_events(pub), f"{ua_label} UA must not suppress a real CMDi payload: {pub}"

        mon, pub = make_monitor()
        await mon._process_access_line(access_line("/?q=curl", status=200, ua=ua), LOG_FILE, 1, domain="rmepro.com")
        assert rce_events(pub) == [], f"{ua_label} UA + benign payload must not manufacture an RCE finding: {pub}"
    print("  3 UA variants (Googlebot/Discordbot/browser) x malicious+benign -- detection outcome identical regardless of UA")

    print("\n=== F. /sofix applies the structural rule, nginx -t passes, idempotent re-run ===")
    base = os.path.join(tempfile.gettempdir(), "rtsa_rce_hardening_regression")
    shutil.rmtree(base, ignore_errors=True)
    conf_dir = Path(base) / "sites-enabled"
    conf_dir.mkdir(parents=True)
    sofix_dir = Path(base) / "backups" / "sofix"
    nginx_dir = Path(base) / "backups" / "nginx"
    conf_file = conf_dir / "plainapp.id.conf"
    conf_file.write_text(
        "server {\n    listen 443 ssl http2;\n    server_name plainapp.id;\n"
        "    root /home/plainapp/htdocs/plainapp.id;\n"
        "    location / {\n        proxy_pass http://127.0.0.1:4012;\n    }\n}\n",
        encoding="utf-8",
    )

    class FakeDb:
        def enqueue_action(self, *a, **k): pass
        def enqueue_incident_create(self, **k): pass
        def enqueue_incident_update(self, *a, **k): pass

    class _Proc:
        returncode = 0
        async def communicate(self): return (b"ok", b"")
        def kill(self): pass
        async def wait(self): pass

    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(
            detection_only=False, nginx_backup_directory=str(nginx_dir), sofix_backup_directory=str(sofix_dir),
        ),
        modules=ModulesConfig(nginx_monitor=NginxMonitorConfig(conf_directory=str(conf_dir))),
        cloudflare=CloudflareConfig(enabled=False),
    )
    sofix_bot = RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)

    orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec

    async def fake_exec(*a, **k):
        return _Proc()

    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    shutil.which = lambda n: f"/usr/bin/{n}"
    asyncio.create_subprocess_exec = fake_exec
    try:
        result = await sofix_bot._sofix("plainapp.id", requested_by="tester")
        assert "Hardening diterapkan" in result, result
        assert "rce_command_injection_block" in result, result
        assert "nginx -t` passed" in result, result

        text = conf_file.read_text(encoding="utf-8")
        assert "rce_command_injection_block" not in text
        assert "cat|wget|curl|nc|bash|sh|id|whoami" in text, "structural command-name group must be in the written config"
        assert "GSCAN_CMDI" not in text, "no scanner-marker literal should be baked into the rule -- it's structural now"
        assert "rce_command_injection_block" in _hardening_rule_names_present(text)

        result2 = await sofix_bot._sofix("plainapp.id", requested_by="tester")
        assert "sudah memenuhi semua standar hardening" in result2, (
            f"second /sofix run must be a no-op (idempotent), got: {result2}"
        )
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        shutil.rmtree(base, ignore_errors=True)
    print("  /sofix wrote the structural rce_command_injection_block rule, nginx -t passed, second run was a no-op")

    print("\nALL RCE/CMDi STRUCTURAL HARDENING REGRESSION TESTS PASSED")


main_sync()
asyncio.run(asyncio.wait_for(main_async(), timeout=60))
