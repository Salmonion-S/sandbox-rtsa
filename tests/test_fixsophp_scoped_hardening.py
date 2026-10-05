import asyncio
import os
import shutil
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import tempfile
from pathlib import Path

from config.manager import (
    CloudflareConfig, DiscordConfig, ModulesConfig, NginxMonitorConfig, ResponseEngineConfig, RTSAConfig,
)
from config.manager import ResourceGovernorConfig
from core.cpu_governor import configure_cpu_governor
from core.event_bus import EventBus
from discord_integration.bot import RTSABot

BASE = os.path.join(tempfile.gettempdir(), "rtsa_fixsophp_test")

STATIC_VHOST = """\
server {
    listen 443 ssl http2;
    server_name plainapp.id;
    root /home/plainapp/htdocs/plainapp.id;
    location / {
        proxy_pass http://127.0.0.1:4012;
    }
}
"""

PHP_VHOST = """\
server {
    listen 443 ssl http2;
    server_name phpapp.id;
    root /home/phpapp/htdocs/phpapp.id;
    location ~ \\.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
}
"""


class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass


class _Proc:
    returncode = 0
    async def communicate(self): return (b"ok", b"")
    def kill(self): pass
    async def wait(self): pass


def make_bot(conf_dir, sofix_dir, nginx_dir):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(
            detection_only=False,
            nginx_backup_directory=str(nginx_dir),
            sofix_backup_directory=str(sofix_dir),
        ),
        modules=ModulesConfig(nginx_monitor=NginxMonitorConfig(conf_directory=str(conf_dir))),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)


def install_fakes():
    orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
    async def fake_exec(*a, **k): return _Proc()
    shutil.which = lambda n: f"/usr/bin/{n}"
    asyncio.create_subprocess_exec = fake_exec
    def restore():
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
    return restore


async def main():
    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    shutil.rmtree(BASE, ignore_errors=True)

    conf_dir = Path(BASE) / "s1" / "sites-enabled"; conf_dir.mkdir(parents=True)
    sofix_dir = Path(BASE) / "s1" / "backups" / "sofix"
    conf_file = conf_dir / "plainapp.id.conf"
    conf_file.write_text(STATIC_VHOST, encoding="utf-8")

    bot = make_bot(conf_dir, sofix_dir, Path(BASE) / "s1" / "backups" / "nginx")
    restore = install_fakes()
    try:
        result = await bot._fixsophp("plainapp.id", requested_by="tester")
    finally:
        restore()

    assert "Hardening diterapkan" in result, result
    new_text = conf_file.read_text(encoding="utf-8")
    assert r"location ~ \.php" in new_text, f"php_block rule must be applied: {new_text}"
    assert "location ^~ /@fs/" not in new_text, (
        f"/fixsophp must apply ONLY the php_block rule, not the full /sofix suite: {new_text}"
    )
    assert "/@fs/" not in new_text
    assert "cat%20" not in new_text
    print("Scenario 1 (/fixsophp applies ONLY php_block, not the other 7 /sofix rules) PASSED")

    conf_dir2 = Path(BASE) / "s2" / "sites-enabled"; conf_dir2.mkdir(parents=True)
    sofix_dir2 = Path(BASE) / "s2" / "backups" / "sofix"
    conf_file2 = conf_dir2 / "phpapp.id.conf"
    conf_file2.write_text(PHP_VHOST, encoding="utf-8")
    bot2 = make_bot(conf_dir2, sofix_dir2, Path(BASE) / "s2" / "backups" / "nginx")
    restore = install_fakes()
    try:
        result2 = await bot2._fixsophp("phpapp.id", requested_by="tester")
    finally:
        restore()
    assert "sudah memenuhi semua standar hardening" in result2, (
        f"a genuinely PHP-serving vhost must never get the php_block rule (would break the site): {result2}"
    )
    assert conf_file2.read_text(encoding="utf-8") == PHP_VHOST, "a PHP vhost's config must stay untouched"
    print("Scenario 2 (/fixsophp never blocks PHP execution on a domain that actually serves PHP) PASSED")

    conf_dir3 = Path(BASE) / "s3" / "sites-enabled"; conf_dir3.mkdir(parents=True)
    sofix_dir3 = Path(BASE) / "s3" / "backups" / "sofix"
    conf_file3 = conf_dir3 / "plainapp.id.conf"
    conf_file3.write_text(STATIC_VHOST, encoding="utf-8")
    bot3 = make_bot(conf_dir3, sofix_dir3, Path(BASE) / "s3" / "backups" / "nginx")
    restore = install_fakes()
    try:
        result3 = await bot3._sofix("plainapp.id", requested_by="tester")
    finally:
        restore()
    new_text3 = conf_file3.read_text(encoding="utf-8")
    assert r"location ~ \.php" in new_text3 and "location ^~ /@fs/" in new_text3, (
        f"/sofix (unscoped) must still apply the full 8-rule suite -- no regression from adding "
        f"rule scoping: {new_text3}"
    )
    print("Scenario 3 (/sofix unscoped still applies the full hardening suite, unaffected by scoping) PASSED")

    print("\nALL /fixsophp SCOPED HARDENING TESTS PASSED")


asyncio.run(main())
