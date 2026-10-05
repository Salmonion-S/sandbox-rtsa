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

import core.cloudpanel_resolver as cloudpanel_resolver
from config.manager import (
    CloudflareConfig, DiscordConfig, ModulesConfig, NginxMonitorConfig, ResponseEngineConfig, RTSAConfig,
)
from core.cloudpanel_resolver import CloudPanelAsset
from core.event_bus import EventBus
from discord_integration.bot import ActionStatus, RTSABot


class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass


class _Proc:
    returncode = 0
    async def communicate(self): return (b"Congratulations! Certificate obtained.", b"")
    def kill(self): pass
    async def wait(self): pass


def make_bot(conf_dir):
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


async def main() -> None:
    base = os.path.join(tempfile.gettempdir(), "rtsa_fixsslphp_regression")
    shutil.rmtree(base, ignore_errors=True)
    conf_dir = os.path.join(base, "sites-enabled")
    os.makedirs(conf_dir)

    php_conf = Path(conf_dir) / "phpproject.id.conf"
    php_conf.write_text(
        "server {\n    listen 443 ssl http2;\n    server_name phpproject.id;\n"
        "    ssl_certificate /etc/letsencrypt/live/phpproject.id/fullchain.pem;\n"
        "    root /home/phpuser/htdocs/phpproject.id;\n"
        "    location ~ \\.php$ {\n        fastcgi_pass unix:/run/php/php8.2-fpm-phpuser.sock;\n"
        "        fastcgi_index index.php;\n    }\n}\n",
        encoding="utf-8",
    )

    node_conf = Path(conf_dir) / "nodeproject.id.conf"
    node_conf.write_text(
        "server {\n    listen 443 ssl http2;\n    server_name nodeproject.id;\n"
        "    root /home/nodeuser/htdocs/nodeproject.id;\n"
        "    location / {\n        proxy_pass http://127.0.0.1:4021;\n    }\n}\n",
        encoding="utf-8",
    )

    bot = make_bot(conf_dir)

    orig_which, orig_exec = shutil.which, asyncio.create_subprocess_exec
    orig_resolve_domain = cloudpanel_resolver.resolve_domain
    orig_gethostbyname = socket.gethostbyname

    async def fake_exec(*a, **k):
        return _Proc()

    async def fake_resolve_domain(domain):
        if domain == "phpproject.id":
            return CloudPanelAsset(
                domain="phpproject.id", linux_user="phpuser",
                project_root="/home/phpuser", htdocs_path="/home/phpuser/htdocs/phpproject.id",
                nginx_vhost=str(php_conf), pm2_user=None, discovered_at=0.0,
            )
        return None

    shutil.which = lambda n: f"/usr/bin/{n}"
    asyncio.create_subprocess_exec = fake_exec
    cloudpanel_resolver.resolve_domain = fake_resolve_domain
    socket.gethostbyname = lambda host: "203.0.113.50"

    async def fake_check_ssl(domain, port=443, timeout=5.0):
        return True, "valid, berlaku sampai Jan 01 00:00:00 2027 GMT (120d left)"

    bot._check_ssl = fake_check_ssl

    try:
        result = await bot._fixsslphp("phpproject.id", requested_by="tester")
        assert "Project: phpuser" in result, result
        assert "PHP Runtime: PHP-FPM" in result, result
        assert "PHP-FPM: unix:/run/php/php8.2-fpm-phpuser.sock" in result, result
        assert "Certificate:" in result and "fullchain.pem" in result, result
        assert "Certificate Expiry (sebelum):" in result, result
        assert "Old Config Fingerprint:" in result, result
        assert "New Config Fingerprint:" in result, result
        assert "Hardening diterapkan" in result or "nginx -t` passed" in result, result
        print("Scenario 1 (/fixsslphp on a PHP project: full field set, delegates to /fixssl engine) PASSED")

        text_after = php_conf.read_text(encoding="utf-8")
        assert "location ~ \\.php(?:/|$)" not in text_after, (
            "/fixsslphp must never apply a blanket PHP-block rule to a genuine PHP project"
        )
        print("Scenario 2 (/fixsslphp never applies a global PHP-block rule to a real PHP project) PASSED")

        result_node = await bot._fixsslphp("nodeproject.id", requested_by="tester")
        assert "tidak terdeteksi sebagai project PHP" in result_node, result_node
        node_text_after = node_conf.read_text(encoding="utf-8")
        node_text_before = (
            "server {\n    listen 443 ssl http2;\n    server_name nodeproject.id;\n"
            "    root /home/nodeuser/htdocs/nodeproject.id;\n"
            "    location / {\n        proxy_pass http://127.0.0.1:4021;\n    }\n}\n"
        )
        assert node_text_after == node_text_before, "a non-PHP vhost must never be touched by /fixsslphp"
        print("Scenario 3 (/fixsslphp refuses a non-PHP (Node.js) vhost, file untouched) PASSED")

        results = await asyncio.gather(
            bot._fixsslphp("phpproject.id", requested_by="alice"),
            bot._fixssl("phpproject.id", requested_by="bob"),
        )
        blocked_count = sum(1 for r in results if "sedang diproses oleh operasi nginx lain" in r)
        assert blocked_count == 1, (
            f"/fixsslphp and /fixssl on the same domain must share one domain-level lock "
            f"(one proceeds, one is rejected): {results}"
        )
        print("Scenario 4 (/fixsslphp and /fixssl share the same domain lock -- no concurrent double-run) PASSED")

        bot2 = make_bot(conf_dir)
        bot2.rtsa_config = RTSAConfig(
            response_engine=ResponseEngineConfig(detection_only=True),
            modules=ModulesConfig(nginx_monitor=NginxMonitorConfig(conf_directory=conf_dir)),
            cloudflare=CloudflareConfig(enabled=False),
        )
        result_blocked = await bot2._fixsslphp("phpproject.id", requested_by="tester")
        assert "detection" in result_blocked.lower() or "❌" in result_blocked or "🔒" in result_blocked, result_blocked
        print("Scenario 5 (detection-only mode blocks /fixsslphp from making any change) PASSED")
    finally:
        shutil.which, asyncio.create_subprocess_exec = orig_which, orig_exec
        cloudpanel_resolver.resolve_domain = orig_resolve_domain
        socket.gethostbyname = orig_gethostbyname
        shutil.rmtree(base, ignore_errors=True)

    print("\nALL /fixsslphp TESTS PASSED")


asyncio.run(main())
