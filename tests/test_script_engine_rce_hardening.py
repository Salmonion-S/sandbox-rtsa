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

REPORTED_PAYLOAD = (
    "/${newjavax.script.ScriptEngineManager().getEngineByName('nashorn')."
    "eval('catconfluence.cfg.xml')}/"
)

MALICIOUS = [
    ("reported Nashorn ScriptEngineManager probe (exact shape)", REPORTED_PAYLOAD),
    ("percent-encoded braces variant", REPORTED_PAYLOAD.replace("${", "%24%7B").replace("}", "%7D")),
    ("GraalJS engine variant", "/${new GraalJSScriptEngine().eval('id')}/"),
    ("getEngineByExtension variant", "/?x=${engineManager.getEngineByExtension('js').eval(payload)}"),
    ("no braces, plain query param", "/api?q=ScriptEngineManager().getEngineByName('js').eval('whoami')"),
]

BENIGN = [
    ("blog text mentioning ScriptEngineManager, no eval call", "/blog/java-scripting-scriptenginemanager-tutorial"),
    ("bare eval( with no script-engine context", "/?q=eval(1+1)"),
    ("legitimate query about nashorn horses", "/search?q=nashorn+horse+breed"),
    ("getEngineByName far from any eval call", "/?x=" + "getEngineByName('js')" + "A" * 300 + "eval("),
]


def main_sync():
    print("=== A. classify_request() (core/injection_signatures.py) ===")
    for label, path in MALICIOUS:
        r = classify_request("GET", path)
        assert r.top_category == EventCategory.WEB_ATTACK_RCE, (
            f"{label} ({path}): must be WEB_ATTACK_RCE, got {r.top_category} / {r.rules}"
        )
        assert "script_engine_manager_eval" in r.rules, f"{label} ({path}): must fire the new dedicated rule, got {r.rules}"
    print(f"  {len(MALICIOUS)} script-engine RCE variants -- all classified WEB_ATTACK_RCE via script_engine_manager_eval")

    for label, path in BENIGN:
        r = classify_request("GET", path)
        assert "script_engine_manager_eval" not in r.rules, (
            f"{label} ({path}): false positive on the new script-engine signature -- rules={r.rules}"
        )
    print(f"  {len(BENIGN)} benign/unrelated requests -- zero false positives on script_engine_manager_eval")

    print("\n=== B. Nginx script_engine_rce_block ($request_uri ~* structural simulation) ===")
    marker = bot._SCRIPT_ENGINE_RCE_BLOCK_MARKER
    inner = marker[len('if ($request_uri ~* "'):-len('")')]
    nginx_pattern = re.compile(inner, re.IGNORECASE)
    for label, path in MALICIOUS:
        assert nginx_pattern.search(path), f"{label} ({path}): Nginx rule must match the raw $request_uri {path!r}"
    print(f"  {len(MALICIOUS)} malicious payloads -- all matched by the raw-$request_uri Nginx rule")
    for label, path in BENIGN:
        assert not nginx_pattern.search(path), f"{label} ({path}): Nginx rule false positive on {path!r}"
    print(f"  {len(BENIGN)} benign requests -- zero false positives")

    built = bot._build_script_engine_rce_block("    ")
    assert marker in built, "the marker constant must be a literal substring of what the builder inserts (idempotency depends on this)"
    print("  marker/builder content consistent (idempotency-safe)")

    try:
        re.compile(inner)
    except re.error as exc:
        raise AssertionError(f"generated Nginx regex is not even a valid regex: {exc}")
    print("  generated regex compiles cleanly (structurally valid, safely escaped)")


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
    print("\n=== C. End-to-end NginxMonitor._process_access_line, exact reported Nashorn shape ===")
    mon, pub = make_monitor()
    await mon._process_access_line(
        access_line(REPORTED_PAYLOAD, status=308, ua="Mozilla/5.0 (Linux; Android 10; K)"),
        LOG_FILE, 1, domain="simpangbabat.simpuskes.com",
    )
    assert rce_events(pub), f"the exact reported Nashorn payload must alert end-to-end: {pub}"
    print("  reported bug shape (HTTP 308, mobile UA) -- WEB_ATTACK_RCE published as expected")

    print("\n=== D. /sofix applies the structural rule, nginx -t passes, idempotent re-run ===")
    base = os.path.join(tempfile.gettempdir(), "rtsa_script_engine_rce_hardening_regression")
    shutil.rmtree(base, ignore_errors=True)
    conf_dir = Path(base) / "sites-enabled"
    conf_dir.mkdir(parents=True)
    sofix_dir = Path(base) / "backups" / "sofix"
    nginx_dir = Path(base) / "backups" / "nginx"
    conf_file = conf_dir / "simpangbabat.simpuskes.com.conf"
    conf_file.write_text(
        "server {\n    listen 443 ssl http2;\n    server_name simpangbabat.simpuskes.com;\n"
        "    root /home/simpuskes-simpangbabat/htdocs/simpangbabat.simpuskes.com;\n"
        "    location / {\n        proxy_pass http://127.0.0.1:4013;\n    }\n}\n",
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
        result = await sofix_bot._sofix("simpangbabat.simpuskes.com", requested_by="tester")
        assert "Hardening diterapkan" in result, result
        assert "script_engine_rce_block" in result, result
        assert "nginx -t` passed" in result, result

        text = conf_file.read_text(encoding="utf-8")
        assert "ScriptEngineManager" in text, "structural script-engine rule must be in the written config"
        assert "script_engine_rce_block" in _hardening_rule_names_present(text)

        result2 = await sofix_bot._sofix("simpangbabat.simpuskes.com", requested_by="tester")
        assert "sudah memenuhi semua standar hardening" in result2, (
            f"second /sofix run must be a no-op (idempotent), got: {result2}"
        )
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        shutil.rmtree(base, ignore_errors=True)
    print("  /sofix wrote the structural script_engine_rce_block rule, nginx -t passed, second run was a no-op")

    print("\nALL SCRIPT-ENGINE (JSR223/Nashorn/GraalJS) RCE HARDENING REGRESSION TESTS PASSED")


main_sync()
asyncio.run(asyncio.wait_for(main_async(), timeout=60))
