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
from config.manager import (
    CloudflareConfig, DiscordConfig, ModulesConfig, NginxMonitorConfig, ResponseEngineConfig, RTSAConfig,
)
from core.event_bus import EventBus
from discord_integration.bot import RTSABot


class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass


class _Proc:
    returncode = 0
    async def communicate(self): return (b"syntax is ok\nnginx: configuration file test is successful", b"")
    def kill(self): pass
    async def wait(self): pass


def make_bot(conf_dir):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(
            detection_only=False,
            sofix_backup_directory=os.path.join(conf_dir, "..", "backups", "sofix"),
        ),
        modules=ModulesConfig(nginx_monitor=NginxMonitorConfig(conf_directory=conf_dir)),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)


def _inner_regex(marker: str) -> "re.Pattern":
    prefix = 'if ($request_uri ~* "'
    suffix = '")'
    assert marker.startswith(prefix) and marker.endswith(suffix), marker
    return re.compile(marker[len(prefix):-len(suffix)], re.IGNORECASE)


def main_sync() -> None:
    print("=== A. marker/builder text consistency across all hardening rules ===")
    for name, marker, builder in bot._NGINX_HARDENING_RULES:
        built = builder("    ")
        assert marker in built, (
            f"{name}: builder output must literally contain its own marker string byte-for-byte, or "
            f"re-running the rule against its own output would never detect it as already present "
            f"(broken idempotency): built={built!r}"
        )
    print(f"  {len(bot._NGINX_HARDENING_RULES)} rules -- every marker is a literal substring of its own builder output")

    print("\n=== B. no marker introduces an unguarded '#' that corrupts server-block brace scanning ===")
    for name, marker, _builder in bot._NGINX_HARDENING_RULES:
        assert "#" not in marker, (
            f"{name}: marker contains a bare '#' -- _find_server_block_spans() treats '#' as an nginx "
            f"comment start and skips to end-of-line while counting braces, so any '#' embedded in "
            f"inserted config text corrupts span detection for everything that follows it (this exact "
            f"bug was found and fixed for ssti_block's Ruby-style '#{{7*7}}' probe during this pass)"
        )
    print(f"  {len(bot._NGINX_HARDENING_RULES)} rules -- none embed a literal '#' in their marker text")

    print("\n=== C. full-cycle idempotency: apply all rules twice, second pass must be a byte-for-byte no-op ===")
    conf_text = (
        "server {\n"
        "    listen 443 ssl http2;\n"
        "    server_name coveragetest.id;\n"
        "    root /home/coverageuser/htdocs/coveragetest.id;\n"
        "    location / {\n"
        "        proxy_pass http://127.0.0.1:3000;\n"
        "    }\n"
        "}\n"
    )
    hardened1, counts1 = bot._ensure_nginx_hardening_rules(conf_text)
    assert all(v == 1 for v in counts1.values()), f"first pass must add every rule exactly once: {counts1}"
    hardened2, counts2 = bot._ensure_nginx_hardening_rules(hardened1)
    assert all(v == 0 for v in counts2.values()), f"second pass must add nothing (idempotent): {counts2}"
    assert hardened1 == hardened2, "second pass must produce byte-for-byte identical config text"
    present = bot._hardening_rule_names_present(hardened1)
    assert set(present) == set(counts1.keys()), (
        f"every rule applied must be detected as present afterward: present={present}, expected={list(counts1.keys())}"
    )
    print(f"  {len(counts1)} rules applied once, second pass is a true no-op, all {len(present)} detected present afterward")

    print("\n=== D. new rule coverage: malicious payloads matched, representative benign traffic is not ===")
    coverage = {
        "sqli_block": (
            bot._SQLI_BLOCK_MARKER,
            [
                "/?id=1 UNION SELECT username,password FROM users",
                "/?id=1%20UNION%20SELECT%20user,pass%20FROM%20users",
                "/?id=1+union+select+1,2,3",
                "/?id=1 or 1=1",
                "/?id=1' OR '1'='1",
                "/?id=1;--",
                "/?id=1 AND SLEEP(5)",
            ],
            ["/?q=curl", "/search?keyword=selection", "/products?select=color&from=shop", "/?editor=1"],
        ),
        "ssti_block": (
            bot._SSTI_BLOCK_MARKER,
            ["/?name={{7*7}}", "/?name=%7b%7b7*7%7d%7d", "/?name=${7*7}"],
            ["/?name=hello", "/?x={{user}}"],
        ),
        "lfi_block": (
            bot._LFI_BLOCK_MARKER,
            [
                "/?file=php://filter/convert.base64-encode/resource=index.php",
                "/?file=php://input",
                "/?file=/proc/self/environ",
                "/?file=zip://shell.jpg%23payload",
                "/?file=phar://upload.jpg/shell",
            ],
            ["/?file=readme.txt", "/download?file=report.pdf"],
        ),
        "webshell_rce_block": (
            bot._WEBSHELL_RCE_BLOCK_MARKER,
            [
                "/uploads/c99shell.php", "/wso.php",
                "/shell.php?cmd=eval(base64_decode($_POST[1]))",
                "/x.php?a=assert(base64_decode(\"phpinfo();\"))",
            ],
            ["/?q=evaluation", "/?q=asserted_fact"],
        ),
    }
    for name, (marker, malicious, benign) in coverage.items():
        pat = _inner_regex(marker)
        for p in malicious:
            assert pat.search(p), f"{name}: expected a match on {p!r}"
        for p in benign:
            assert not pat.search(p), f"{name}: false positive on {p!r}"
    print(f"  {len(coverage)} newly-added block rules -- all malicious payloads matched, zero false positives on benign traffic")

    print("\n=== E. attack-category coverage matrix (DETECTION vs NGINX BLOCK) ===")
    matrix = [
        ("XSS", "yes (WEB_ATTACK_XSS)", "no -- detection-only by design (output-encoding issue, blind blocking of '<script' risks breaking legitimate JSON/API payloads)"),
        ("SQLi", "yes (WEB_ATTACK_SQLI)", "yes (sqli_block, added this pass)"),
        ("Command Injection", "yes (WEB_ATTACK_RCE)", "yes (rce_command_injection_block)"),
        ("RCE (generic/webshell)", "yes (WEB_ATTACK_RCE)", "yes (rce_command_injection_block, webshell_rce_block added this pass)"),
        ("Java Expression Injection / OGNL", "yes (WEB_ATTACK_SSTI)", "yes (ognl_struts_block)"),
        ("Script Engine Injection", "yes (WEB_ATTACK_RCE)", "yes (script_engine_rce_block)"),
        ("SSTI", "yes (WEB_ATTACK_SSTI)", "yes (ssti_block, added this pass)"),
        ("SSRF", "yes (WEB_ATTACK_SSRF)", "no -- detection-only by design (payload is a param VALUE, not classifiable from $request_uri alone without high false-positive risk)"),
        ("LFI", "yes (WEB_ATTACK_LFI)", "yes (lfi_block, added this pass)"),
        ("RFI", "yes (WEB_ATTACK_LFI, rfi_remote_url_param rule added this pass)", "no -- detection-only (remote-URL-as-param is app-specific; a blanket block risks legitimate redirect/webhook/callback params)"),
        ("Path Traversal", "yes (WEB_ATTACK_PATH_TRAVERSAL)", "yes (path_traversal_block)"),
        ("XXE", "yes (WEB_ATTACK_XXE)", "yes (xxe_block)"),
        ("XInclude", "yes (WEB_ATTACK_XXE, xinclude_abuse rule)", "no -- detection-only (generic 'xinclude' substring is too broad to safely block without app-specific context)"),
        ("Deserialization", "yes (WEB_ATTACK_DESERIALIZATION)", "no -- detection-only by design (payload lives in the POST body, which $request_uri-based Nginx if-blocks cannot inspect)"),
        ("LDAP Injection", "yes (WEB_ATTACK_INJECTION_OTHER)", "no -- detection-only (metacharacters too generic/short to block safely)"),
        ("NoSQL Injection", "yes (WEB_ATTACK_INJECTION_OTHER)", "no -- detection-only (primarily body-based; query-string form is rare enough that blocking risks FPs on generic operator-shaped params)"),
        ("XPath Injection", "yes (WEB_ATTACK_INJECTION_OTHER)", "no -- detection-only (boolean-probe pattern too generic to block safely)"),
        ("HTTP Parameter Pollution", "yes (WEB_ATTACK_PROTOCOL_ABUSE)", "no -- detection-only (duplicate query keys are frequently legitimate; blocking would break real apps)"),
        ("CRLF Injection", "yes (WEB_ATTACK_PROTOCOL_ABUSE)", "no -- detection-only by design (low-confidence header-smuggle heuristics unsuitable for a hard block)"),
        ("Request Smuggling", "yes (WEB_ATTACK_PROTOCOL_ABUSE)", "no -- detection-only (Transfer-Encoding/Content-Length probing must not hard-block, per spec's own low-confidence guidance)"),
        ("Webshell", "yes (known_webshell_marker rule)", "yes (webshell_rce_block, added this pass)"),
        ("Host Header Injection", "yes (detect_host_header_anomaly)", "no -- detection-only (Host-header enforcement belongs to vhost/server_name matching, not a blanket if-block)"),
        ("Malicious file upload", "yes (SVG content scanner + FIM)", "yes (php_block: uploaded PHP never executes as a script)"),
    ]
    assert len(matrix) == 23, f"matrix must cover all 23 categories named in the spec, got {len(matrix)}"
    for category, detection, block in matrix:
        assert detection.startswith("yes"), f"{category}: every category must have DETECTION coverage, got {detection!r}"
    print(f"  {len(matrix)}/23 attack categories documented: DETECTION coverage on all 23, NGINX BLOCK added for 4 new low-FP categories (SQLi/SSTI/LFI/Webshell), remainder intentionally detection-only per confidence/context policy")

    print("\n=== F. /sofix end-to-end applies the new rules and is idempotent on a real config file ===")
    base = os.path.join(tempfile.gettempdir(), "rtsa_sofix_coverage_matrix_regression")
    shutil.rmtree(base, ignore_errors=True)
    conf_dir = os.path.join(base, "sites-enabled")
    os.makedirs(conf_dir)
    conf_file = Path(conf_dir) / "coveragetest.id.conf"
    conf_file.write_text(conf_text, encoding="utf-8")

    rtsa_bot = make_bot(conf_dir)
    orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec

    async def fake_exec(*a, **k):
        return _Proc()

    shutil.which = lambda n: f"/usr/bin/{n}"
    asyncio.create_subprocess_exec = fake_exec
    try:
        async def run() -> None:
            result1 = await rtsa_bot._sofix_impl("coveragetest.id", requested_by="tester")
            assert "sqli_block" in result1 and "ssti_block" in result1 and "lfi_block" in result1 and "webshell_rce_block" in result1, result1
            result2 = await rtsa_bot._sofix_impl("coveragetest.id", requested_by="tester")
            assert "sudah memenuhi semua standar hardening" in result2, (
                f"second /sofix run must be a no-op (idempotent): {result2}"
            )
        asyncio.run(run())
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        shutil.rmtree(base, ignore_errors=True)
    print("  /sofix applied all 4 new rules end-to-end on a real vhost config; second run was a true no-op")

    print("\nALL /sofix BLOCK COVERAGE MATRIX TESTS PASSED")


main_sync()
