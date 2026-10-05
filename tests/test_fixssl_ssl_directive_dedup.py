import asyncio
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import (
    CloudflareConfig, DiscordConfig, ModulesConfig, NginxMonitorConfig, ResourceGovernorConfig, ResponseEngineConfig, RTSAConfig,
)
from core.cpu_governor import configure_cpu_governor
from core.event_bus import EventBus
from discord_integration.bot import RTSABot, _dedupe_identical_ssl_path_directives


def _block(*lines: str) -> str:
    body = "\n".join(lines)
    return f"server {{\n{body}\n}}\n"


def main() -> None:
    text = _block(
        "    listen 443 ssl http2;",
        "    server_name example.com;",
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
        "    root /home/exampleuser/htdocs/example.com;",
    )
    out, removed = _dedupe_identical_ssl_path_directives(text)
    assert removed == 1
    assert out.count("ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;") == 1
    assert "listen 443 ssl http2;" in out
    assert "root /home/exampleuser/htdocs/example.com;" in out
    print("Test 1 (exact-duplicate ssl_certificate collapses to one) PASSED")

    text = _block(
        "    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;",
        "    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;",
    )
    out, removed = _dedupe_identical_ssl_path_directives(text)
    assert removed == 1
    assert out.count("ssl_certificate_key") == 1
    print("Test 2 (exact-duplicate ssl_certificate_key collapses to one) PASSED")

    text = _block(
        "    ssl_certificate      /etc/letsencrypt/live/example.com/fullchain.pem;",
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
    )
    out, removed = _dedupe_identical_ssl_path_directives(text)
    assert removed == 1
    assert out.count("ssl_certificate") == 1
    print("Test 3 (whitespace-different duplicate still recognized) PASSED")

    text = _block(
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
        "    ssl_certificate /etc/letsencrypt/live/old.example.com/fullchain.pem;",
    )
    out, removed = _dedupe_identical_ssl_path_directives(text)
    assert removed == 0
    assert out == text
    assert out.count("ssl_certificate") == 2
    print("Test 4 (different-argument duplicate is preserved, not guessed) PASSED")

    text = _block(
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
    )
    once, removed_once = _dedupe_identical_ssl_path_directives(text)
    twice, removed_twice = _dedupe_identical_ssl_path_directives(once)
    assert removed_once == 2
    assert removed_twice == 0
    assert once == twice
    print("Test 5 (idempotent across repeated invocations) PASSED")

    text = _block(
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
        "    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;",
        "    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;",
        "    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;",
    )
    out, removed = _dedupe_identical_ssl_path_directives(text)
    assert removed == 2
    assert out.count("ssl_certificate ") == 1
    assert out.count("ssl_certificate_key") == 1
    assert out.count("ssl_trusted_certificate") == 1
    print("Test 6 (multiple directive families deduped independently) PASSED")

    text = (
        _block(
            "    server_name a.example.com;",
            "    ssl_certificate /etc/letsencrypt/live/a.example.com/fullchain.pem;",
            "    ssl_certificate /etc/letsencrypt/live/a.example.com/fullchain.pem;",
        )
        + "\n"
        + _block(
            "    server_name b.example.com;",
            "    ssl_certificate /etc/letsencrypt/live/b.example.com/fullchain.pem;",
        )
    )
    out, removed = _dedupe_identical_ssl_path_directives(text)
    assert removed == 1
    assert out.count("a.example.com/fullchain.pem") == 1
    assert out.count("b.example.com/fullchain.pem") == 1
    assert "server_name b.example.com;" in out
    print("Test 7 (per-block scoping does not cross server block boundaries) PASSED")

    text = _block(
        "    # managed by /fixssl",
        "    listen 443 ssl http2;",
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
        "    add_header X-Frame-Options SAMEORIGIN;",
    )
    out, removed = _dedupe_identical_ssl_path_directives(text)
    assert removed == 1
    assert "# managed by /fixssl" in out
    assert "listen 443 ssl http2;" in out
    assert "add_header X-Frame-Options SAMEORIGIN;" in out
    assert out.count("ssl_certificate ") == 1
    print("Test 8 (unrelated directives/comments preserved verbatim) PASSED")

    for directive, arg in (
        ("ssl_certificate", "/etc/letsencrypt/live/x.com/fullchain.pem"),
        ("ssl_certificate_key", "/etc/letsencrypt/live/x.com/privkey.pem"),
        ("ssl_trusted_certificate", "/etc/letsencrypt/live/x.com/chain.pem"),
        ("ssl_client_certificate", "/etc/nginx/ssl/client-ca.pem"),
        ("ssl_dhparam", "/etc/nginx/dhparam.pem"),
    ):
        text = _block(f"    {directive} {arg};", f"    {directive} {arg};")
        out, removed = _dedupe_identical_ssl_path_directives(text)
        assert removed == 1, f"{directive} was not deduped"
        assert out.count(directive) == 1
    print("Test 9 (all five in-scope directives individually recognized) PASSED")

    text = _block(
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
        "    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;",
    )
    out, removed = _dedupe_identical_ssl_path_directives(text)
    assert removed == 0
    assert out == text
    print("Test 10 (no duplicates -> no-op, byte-identical) PASSED")

    text = _block(
        "    location /api/ {",
        "        proxy_pass http://127.0.0.1:3000;",
        "    }",
        "    location /ws/ {",
        "        proxy_pass http://127.0.0.1:3000;",
        "    }",
    )
    out, removed = _dedupe_identical_ssl_path_directives(text)
    assert removed == 0
    assert out == text
    assert out.count("proxy_pass http://127.0.0.1:3000;") == 2
    print("Test 11 (proxy_pass left untouched -- out of scope by design) PASSED")

    text = _block(*([
        "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;"
    ] * 4))
    out, removed = _dedupe_identical_ssl_path_directives(text)
    assert removed == 3
    assert out.count("ssl_certificate ") == 1
    print("Test 12 (4x repeat collapses to exactly 1) PASSED")

    print("All test_fixssl_ssl_directive_dedup tests PASSED")


class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass


class _Proc:
    returncode = 0
    async def communicate(self): return (b"Certificate not yet due for renewal", b"")
    def kill(self): pass
    async def wait(self): pass


def make_bot(conf_dir: str) -> RTSABot:
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(
            detection_only=False,
            nginx_backup_directory=os.path.join(conf_dir, "..", "backups", "nginx"),
            sofix_backup_directory=os.path.join(conf_dir, "..", "backups", "sofix"),
        ),
        modules=ModulesConfig(nginx_monitor=NginxMonitorConfig(conf_directory=conf_dir)),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)


async def integration_main() -> None:
    base = os.path.join(tempfile.gettempdir(), "rtsa_fixssl_dedup_regression")
    shutil.rmtree(base, ignore_errors=True)
    conf_dir = os.path.join(base, "sites-enabled")
    os.makedirs(conf_dir)

    domain = "dupessl.example.com"
    conf_file = Path(conf_dir) / f"{domain}.conf"
    conf_file.write_text(
        "server {\n"
        "    listen 443 ssl http2;\n"
        f"    server_name {domain};\n"
        f"    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;\n"
        f"    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;\n"
        f"    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;\n"
        f"    root /home/dupessluser/htdocs/{domain};\n"
        "}\n",
        encoding="utf-8",
    )

    bot = make_bot(conf_dir)

    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
    orig_gethostbyname = socket.gethostbyname

    async def fake_exec(*a, **k):
        return _Proc()

    async def fake_check_ssl(domain, port=443, timeout=5.0):
        return True, "valid, berlaku sampai Jan 01 00:00:00 2027 GMT (120d left)"

    shutil.which = lambda n: f"/usr/bin/{n}"
    asyncio.create_subprocess_exec = fake_exec
    socket.gethostbyname = lambda host: "203.0.113.60"
    bot._check_ssl = fake_check_ssl

    try:
        result = await bot._fixssl(domain, requested_by="tester")
        assert "✅ `nginx -t` passed" in result, result
        assert "✅ Nginx reloaded" in result, result

        text_after = conf_file.read_text(encoding="utf-8")
        assert text_after.count(f"ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;") == 1, (
            f"duplicate ssl_certificate line was not collapsed by a real /fixssl run:\n{text_after}"
        )
        assert text_after.count("ssl_certificate_key") == 1
        assert f"server_name {domain};" in text_after
        assert f"root /home/dupessluser/htdocs/{domain};" in text_after
        assert "directive SSL" in result and "duplikat persis" in result, (
            f"/fixssl result should report the duplicate-SSL-directive cleanup step:\n{result}"
        )
        print("Integration test (a real /fixssl run collapses an on-disk duplicate ssl_certificate) PASSED")

        result2 = await bot._fixssl(domain, requested_by="tester")
        text_after_2 = conf_file.read_text(encoding="utf-8")
        assert text_after_2 == text_after, "a second /fixssl run must not further mutate an already-clean config"
        assert "duplikat persis" not in result2, (
            f"second run must not re-report a duplicate-directive cleanup once none remain:\n{result2}"
        )
        print("Integration test (second /fixssl run is a clean idempotent no-op for this step) PASSED")
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        socket.gethostbyname = orig_gethostbyname
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
    asyncio.run(integration_main())
    print("\nALL test_fixssl_ssl_directive_dedup TESTS PASSED")
