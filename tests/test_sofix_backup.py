import asyncio
import os
import shutil
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import tempfile
from pathlib import Path

import yaml

from config.manager import (
    CloudflareConfig, ConfigManager, ConfigValidationError, DiscordConfig, ModulesConfig,
    NginxMonitorConfig, ResourceGovernorConfig, ResponseEngineConfig, RTSAConfig,
)
from core.cpu_governor import configure_cpu_governor
from core.event_bus import EventBus
from discord_integration.bot import RTSABot

BASE = os.path.join(tempfile.gettempdir(), "rtsa_sofix_backup_test")

VHOST = """\
server {
    listen 443 ssl http2;
    server_name plainapp.id;
    root /home/plainapp/htdocs/plainapp.id;
    location / {
        proxy_pass http://127.0.0.1:4012;
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
    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
    async def fake_exec(*a, **k): return _Proc()
    shutil.which = lambda n: f"/usr/bin/{n}"
    asyncio.create_subprocess_exec = fake_exec
    def restore():
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
    return restore

async def main():
    shutil.rmtree(BASE, ignore_errors=True)

    conf_dir = Path(BASE) / "s1" / "sites-enabled"; conf_dir.mkdir(parents=True)
    sofix_dir = Path(BASE) / "s1" / "backups" / "sofix"
    nginx_dir = Path(BASE) / "s1" / "backups" / "nginx"
    conf_file = conf_dir / "plainapp.id.conf"
    conf_file.write_text(VHOST, encoding="utf-8")

    bot = make_bot(conf_dir, sofix_dir, nginx_dir)
    restore = install_fakes()
    try:
        result = await bot._sofix("plainapp.id", requested_by="tester")
    finally:
        restore()

    assert "Hardening diterapkan" in result, result
    backups = list(sofix_dir.glob("plainapp.id.conf.rtsa-backup-*"))
    assert len(backups) == 1, f"expected exactly one backup in the sofix dir, got {backups}"
    assert backups[0].read_text(encoding="utf-8") == VHOST, (
        "backup must contain the ORIGINAL config -- if it matches the rewritten file, the "
        "copy was taken after the modification and is useless for rollback"
    )
    assert conf_file.read_text(encoding="utf-8") != VHOST, "the live config should have been hardened"
    print(f"Scenario 1 (backup written to {sofix_dir.name}/ and holds the pre-change bytes) PASSED")

    assert not nginx_dir.exists() or not list(nginx_dir.glob("*")), (
        f"/sofix must not write into the /fixssl backup directory, found {list(nginx_dir.glob('*'))}"
    )
    assert str(sofix_dir) in result, f"the reported backup path must be the sofix one: {result}"
    print("Scenario 2 (/sofix backups kept out of the /fixssl backup directory, path reported to operator) PASSED")

    conf_dir3 = Path(BASE) / "s3" / "sites-enabled"; conf_dir3.mkdir(parents=True)
    blocker = Path(BASE) / "s3" / "backups"
    blocker.parent.mkdir(parents=True, exist_ok=True)
    blocker.write_text("not a directory")
    sofix3 = blocker / "sofix"
    conf3 = conf_dir3 / "plainapp.id.conf"
    conf3.write_text(VHOST, encoding="utf-8")
    bot3 = make_bot(conf_dir3, sofix3, Path(BASE) / "s3" / "nginx-backups")
    restore = install_fakes()
    try:
        result3 = await bot3._sofix("plainapp.id", requested_by="tester")
    finally:
        restore()
    assert "Gagal membuat backup" in result3, result3
    assert conf3.read_text(encoding="utf-8") == VHOST, (
        "config must be byte-identical when the backup could not be taken"
    )
    print("Scenario 3 (unwritable backup dir -> /sofix aborts, live config byte-identical) PASSED")

    conf_dir4 = Path(BASE) / "s4" / "sites-enabled"; conf_dir4.mkdir(parents=True)
    sofix4 = Path(BASE) / "s4" / "backups" / "sofix"
    conf4 = conf_dir4 / "a.example.com.conf"
    conf4.write_text(VHOST, encoding="utf-8")
    bot4 = make_bot(conf_dir4, sofix4, Path(BASE) / "s4" / "backups" / "nginx")
    restore = install_fakes()
    try:
        await bot4._sofix("a.example.com", requested_by="tester")
        conf4.write_text(VHOST, encoding="utf-8")
        await bot4._sofix("a.example.com", requested_by="tester")
    finally:
        restore()
    backups4 = sorted(sofix4.glob("a.example.com.conf.rtsa-backup-*"))
    assert len(backups4) == 2, f"each run must leave its own backup, got {backups4}"
    assert all(b.read_text(encoding="utf-8") == VHOST for b in backups4)
    print(f"Scenario 4 ({len(backups4)} separate timestamped backups after 2 runs, none overwritten) PASSED")

    bad = RTSAConfig(
        response_engine=ResponseEngineConfig(
            sofix_backup_directory="/etc/nginx/sites-enabled/backups",
            nginx_backup_directory="/opt/security/rtsa/backups/nginx",
        ),
        modules=ModulesConfig(nginx_monitor=NginxMonitorConfig(conf_directory="/etc/nginx/sites-enabled")),
    )
    try:
        ConfigManager._validate_semantics(bad)
        raise AssertionError("a sofix backup dir inside the nginx conf dir must be rejected")
    except ConfigValidationError as exc:
        assert "sofix_backup_directory" in str(exc), str(exc)
    ok = RTSAConfig(
        response_engine=ResponseEngineConfig(
            sofix_backup_directory="/opt/security/rtsa/backups/sofix",
            nginx_backup_directory="/opt/security/rtsa/backups/nginx",
        ),
        modules=ModulesConfig(nginx_monitor=NginxMonitorConfig(conf_directory="/etc/nginx/sites-enabled")),
    )
    try:
        ConfigManager._validate_semantics(ok)
    except ConfigValidationError as exc:
        assert "backup_directory" not in str(exc), f"a correct backup dir must not be flagged: {exc}"
    print("Scenario 5 (config validation refuses a sofix backup dir inside the nginx conf dir) PASSED")

    raw = yaml.safe_load(open("config/config.yaml"))
    shipped = raw["response_engine"]["sofix_backup_directory"]
    assert shipped.rstrip("/").endswith("/sofix"), shipped
    assert shipped != raw["response_engine"]["nginx_backup_directory"], "must be a separate directory"
    assert ResponseEngineConfig().sofix_backup_directory.rstrip("/").endswith("/sofix")
    print(f"Scenario 6 (config.yaml ships sofix_backup_directory={shipped}, distinct from the /fixssl one) PASSED")

    shutil.rmtree(BASE, ignore_errors=True)
    print("\nALL /sofix BACKUP TESTS PASSED")

asyncio.run(asyncio.wait_for(main(), timeout=120))
