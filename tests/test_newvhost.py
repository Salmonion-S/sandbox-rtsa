from __future__ import annotations

import asyncio
import os
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import discord

from config.manager import (
    AutoVhostConfig, CloudflareConfig, ConfigManager, ConfigValidationError, DiscordConfig, ModulesConfig,
    ResponseEngineConfig, RTSAConfig, WebsiteMonitorConfig,
)
from core import vhost_recovery as vr
from core.auto_ssl import CertbotLineage, CertificateFacts, RecheckOutcome
from core.datatypes import ActionType, BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.nginx_vhost_inspect import find_vhost_blocks
from core.website_check import WebsiteCheckResult
import modules.website_monitor as website_monitor_module
from discord_integration.bot import RTSABot
from modules.website_monitor import WebsiteMonitor

DOMAIN = "shop.example.com"
USER = "shopuser"
NOW = time.time()
DAY = 86400.0


def facts(days: float, domain: str = DOMAIN) -> CertificateFacts:
    return CertificateFacts(domain, "Let's Encrypt (R3)", NOW - 30 * DAY, NOW + days * DAY, (domain,), source="certificate-file")


class Env:
    def __init__(self, tmp: str) -> None:
        self.tmp = tmp
        self.enabled = os.path.join(tmp, "nginx", "sites-enabled")
        self.available = os.path.join(tmp, "nginx", "sites-available")
        self.confd = os.path.join(tmp, "nginx", "conf.d")
        self.home = os.path.join(tmp, "home")
        self.php = os.path.join(tmp, "php")
        self.ssl = os.path.join(tmp, "ssl")
        for directory in (self.enabled, self.confd, self.home, os.path.join(self.php, "8.2", "fpm", "pool.d"), self.ssl):
            os.makedirs(directory, exist_ok=True)
        Path(self.tmp, "nginx", "fastcgi_params").write_text("fastcgi_param X y;\n")
        self.cfg = AutoVhostConfig(
            sites_available_directory=self.available, sites_enabled_directory=self.enabled, home_root=self.home,
            php_fpm_pool_glob=os.path.join(self.php, "*", "fpm", "pool.d", "*.conf"),
            ssl_certificate_directories=[self.ssl],
        )

    def project(self, user: str = USER, domain: str = DOMAIN, files: Optional[Dict[str, str]] = None) -> str:
        root = os.path.join(self.home, user, "htdocs", domain)
        os.makedirs(root, exist_ok=True)
        for name, content in (files or {}).items():
            path = os.path.join(root, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            Path(path).write_text(content)
        return root

    def pool(self, user: str = USER, listen: str = "/run/php/php8.2-fpm-shop.sock", version: str = "8.2", name: Optional[str] = None) -> None:
        directory = os.path.join(self.php, version, "fpm", "pool.d")
        os.makedirs(directory, exist_ok=True)
        Path(directory, f"{name or user}.conf").write_text(f"[{user}]\nuser = {user}\ngroup = {user}\nlisten = {listen}\n")

    def snapshot(self) -> Dict[str, Tuple[str, Any]]:
        state: Dict[str, Tuple[str, Any]] = {}
        for base in (self.enabled, self.available, self.confd):
            if not os.path.isdir(base):
                continue
            for name in sorted(os.listdir(base)):
                path = os.path.join(base, name)
                if os.path.islink(path):
                    state[path] = ("link", os.readlink(path))
                else:
                    st = os.stat(path)
                    state[path] = ("file", (Path(path).read_bytes(), st.st_ino, st.st_mtime_ns))
        return state


def asset_for(env: Env, user: str = USER, domain: str = DOMAIN) -> Any:
    return SimpleNamespace(
        domain=domain, linux_user=user, project_root=os.path.join(env.home, user),
        htdocs_path=os.path.join(env.home, user, "htdocs", domain), pm2_user=user, nginx_vhost=None,
    )


class FakePorts(vr.VhostPorts):
    def __init__(self, env: Env) -> None:
        self.env = env
        self.asset: Optional[Any] = asset_for(env)
        self.pm2: Optional[List[Dict[str, Any]]] = None
        self.listening: Dict[int, List[int]] = {}
        self.lineages: List[CertbotLineage] = []
        self.cert_facts: Dict[str, Optional[CertificateFacts]] = {}
        self.live_tests: List[Tuple[bool, str]] = [(True, "ok")]
        self.live_test_calls = 0
        self.candidate_result: Tuple[bool, str] = (True, "ok")
        self.candidate_seen: List[str] = []
        self.reload_results: List[Tuple[bool, str]] = [(True, "reloaded")]
        self.reload_calls = 0
        self.active: Optional[bool] = True
        self.verify_result: Tuple[bool, str, Optional[float]] = (True, "HTTP HTTP 200 OK, 40 ms", 40.0)
        self.recheck = RecheckOutcome(healthy=True, last_probe_ok=True)
        self.recheck_calls = 0
        self.mutations = True
        self.audits: List[Dict[str, Any]] = []
        self.attributions: List[List[str]] = []
        self.hardening_fn = lambda text: text
        self.test_hook = None

    async def resolve_asset(self, domain): return self.asset

    async def find_references(self, domain):
        blocks = []
        for directory in (self.env.enabled, self.env.confd):
            blocks.extend(find_vhost_blocks(directory, domain))
        return blocks

    def pm2_processes(self, user): return self.pm2
    def listening_ports(self, pid): return self.listening.get(pid, [])
    async def certbot_lineages(self, domain): return (True, list(self.lineages), "")
    async def certificate_file_facts(self, path): return self.cert_facts.get(path)

    async def nginx_test(self):
        index = min(self.live_test_calls, len(self.live_tests) - 1)
        self.live_test_calls += 1
        if self.test_hook:
            await self.test_hook()
        return self.live_tests[index]

    async def nginx_test_candidate(self, candidate_path):
        self.candidate_seen.append(candidate_path)
        assert os.path.basename(candidate_path).startswith("."), "the candidate must be a hidden temp file nginx globs never include"
        assert os.path.exists(candidate_path)
        return self.candidate_result

    async def nginx_reload(self, requested_by):
        index = min(self.reload_calls, len(self.reload_results) - 1)
        self.reload_calls += 1
        return self.reload_results[index]

    async def nginx_active(self): return self.active
    async def verify_website(self, domain, expect_https): return self.verify_result

    async def recheck_website(self, domain):
        self.recheck_calls += 1
        return self.recheck

    def mutations_allowed(self): return self.mutations
    def hardening(self, text): return self.hardening_fn(text)
    def record_attribution(self, paths): self.attributions.append(list(paths))
    def audit(self, record): self.audits.append(record)
    def now(self): return NOW


async def run_vhost(env: Env, ports: FakePorts, *, dry_run: bool = False, reload: bool = False, auto: bool = False,
                    domain: str = DOMAIN):
    discovery = await vr.discover(domain, env.cfg, ports)
    outcome = await vr.apply(discovery, env.cfg, ports, requested_by="tester", dry_run=dry_run, reload=reload, auto=auto)
    return discovery, outcome


def vhost_text(domain: str = DOMAIN) -> str:
    return f"server {{\n  listen 80;\n  server_name {domain};\n  root /var/www/x;\n}}\n"


async def test_1_existing_valid_vhost_not_overwritten() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        target = os.path.join(env.enabled, f"{DOMAIN}.conf")
        Path(target).write_text(vhost_text())
        before = env.snapshot()
        ports = FakePorts(env)
        discovery, outcome = await run_vhost(env, ports, reload=True)
        assert discovery.action == vr.ACTION_NO_CHANGE and outcome.ok and outcome.no_change
        assert env.snapshot() == before, "an existing valid vhost must be byte-for-byte untouched"
        assert ports.live_test_calls == 0 and ports.reload_calls == 0
        title, kind, fields = vr.format_result(discovery, outcome, domain=DOMAIN)
        assert kind == "info" and "ALREADY PRESENT" in title
    print("Test 1 (existing valid vhost -> no overwrite, no nginx call, reported as already present) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        Path(env.enabled, f"{DOMAIN}.conf").write_text("server { listen 80; server_name other.example.com; }\n")
        before = env.snapshot()
        discovery, outcome = await run_vhost(env, FakePorts(env))
        assert not outcome.ok and discovery.stop_code == vr.STOP_EXISTING_CONFIG_CONFLICT
        assert env.snapshot() == before
    print("Test 1b (a file with our name that defines another domain -> refused, never overwritten) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        Path(env.confd, "legacy.conf").write_text(vhost_text())
        before = env.snapshot()
        discovery, outcome = await run_vhost(env, FakePorts(env))
        assert not outcome.ok and discovery.stop_code == vr.STOP_EXISTING_CONFIG_CONFLICT
        assert "legacy.conf" in discovery.stop_reason and env.snapshot() == before
    print("Test 1c (domain already defined elsewhere in the nginx tree -> no duplicate vhost created) PASSED")


async def test_2_symlink_recreated() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        os.makedirs(env.available)
        available = os.path.join(env.available, f"{DOMAIN}.conf")
        Path(available).write_text(vhost_text())
        os.symlink(available, os.path.join(env.enabled, "other.example.com.conf"))
        Path(env.available, "other.example.com.conf").write_text(vhost_text("other.example.com"))
        before_available = Path(available).read_bytes()
        ports = FakePorts(env)
        discovery, outcome = await run_vhost(env, ports)
        link = os.path.join(env.enabled, f"{DOMAIN}.conf")
        assert discovery.action == vr.ACTION_RECREATE_SYMLINK and outcome.ok, outcome
        assert os.path.islink(link) and os.readlink(link) == available, "the symlink convention must be kept (no copy)"
        assert Path(available).read_bytes() == before_available, "the existing config is validated, not regenerated"
        assert outcome.nginx_test == "PASS" and outcome.reload == "NOT PERFORMED" and ports.reload_calls == 0
        assert not ports.candidate_seen, "no config is generated when the existing one is reused"
    print("Test 2 (sites-available present, sites-enabled missing -> symlink recreated, nginx -t, no reload by default) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        os.makedirs(env.available)
        available = os.path.join(env.available, f"{DOMAIN}.conf")
        Path(available).write_text(vhost_text())
        os.symlink(os.path.join(env.available, "gone.conf"), os.path.join(env.enabled, f"{DOMAIN}.conf"))
        ports = FakePorts(env)
        discovery, outcome = await run_vhost(env, ports, reload=True)
        assert outcome.ok and outcome.reload == "SUCCESS" and ports.reload_calls == 1
        assert os.readlink(os.path.join(env.enabled, f"{DOMAIN}.conf")) == available
        assert outcome.website.startswith("VERIFIED") and ports.recheck_calls == 1
    print("Test 2b (dangling link replaced, graceful reload, website verified, monitor lifecycle re-check) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        os.makedirs(env.available)
        available = os.path.join(env.available, f"{DOMAIN}.conf")
        Path(available).write_text(vhost_text())
        ports = FakePorts(env)
        ports.live_tests = [(False, "nginx: [emerg] boom")]
        discovery, outcome = await run_vhost(env, ports, reload=True)
        assert not outcome.ok and outcome.stage == vr.STAGE_NGINX_TEST and ports.reload_calls == 0
        assert not os.path.lexists(os.path.join(env.enabled, f"{DOMAIN}.conf")), "the link must be removed again"
        assert Path(available).read_text() == vhost_text()
        assert outcome.rollback.startswith("SUCCESS") or outcome.rollback.startswith("FAILED")
    print("Test 2c (symlink recreated but nginx -t fails -> link removed, no reload, available file untouched) PASSED")


async def test_3_php_reconstruct() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        root = env.project(files={"public/index.php": "<?php", "artisan": "", "composer.json": "{}"})
        env.pool()
        env.pool(user="someoneelse", listen="/run/php/php8.2-fpm-other.sock", version="8.2")
        os.makedirs(os.path.join(env.home, USER, "logs", "nginx"))
        ports = FakePorts(env)
        hardening = RTSABot._harden_vhost_text
        ports.hardening_fn = hardening
        other = os.path.join(env.enabled, "other.example.com.conf")
        Path(other).write_text("server { listen [::]:80; listen 80; server_name other.example.com; }\n")
        before_other = Path(other).stat().st_ino, Path(other).read_bytes()
        discovery, outcome = await run_vhost(env, ports)
        assert outcome.ok, outcome
        assert discovery.project_type == vr.TYPE_PHP and discovery.document_root == os.path.join(root, "public")
        target = os.path.join(env.enabled, f"{DOMAIN}.conf")
        text = Path(target).read_text()
        assert "fastcgi_pass unix:/run/php/php8.2-fpm-shop.sock;" in text, "the socket comes from the user's own pool"
        assert "other.sock" not in text
        assert f"root {os.path.join(root, 'public')};" in text and "try_files $uri $uri/ /index.php?$query_string;" in text
        assert f"include {os.path.join(tmp, 'nginx')}/fastcgi_params;" in text
        assert "listen [::]:80;" in text, "IPv6 listen follows the convention already used by this server"
        assert f"access_log {os.path.join(env.home, USER, 'logs', 'nginx')}/access.log;" in text
        assert "hidden" in text.lower() or "/\\." in text or "\\.(" in text or "deny all" in text, "existing hardening policy applied"
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o644
        assert sorted(os.listdir(env.enabled)) == sorted(["other.example.com.conf", f"{DOMAIN}.conf"]), "no temp leftovers"
        assert (Path(other).stat().st_ino, Path(other).read_bytes()) == before_other
        assert ports.attributions and target in ports.attributions[0], "FIM attribution recorded for the new file"
    print("Test 3 (both missing + PHP/Laravel -> reconstructed from the user's own PHP-FPM pool, hardening applied, atomic install) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.php": "<?php"})
        ports = FakePorts(env)
        discovery, outcome = await run_vhost(env, ports)
        assert not outcome.ok and discovery.stop_code == vr.STOP_PHP_FPM_POOL_NOT_FOUND
        assert os.listdir(env.enabled) == [], "no pool -> no config, and no pool is ever created"
        assert not any(os.scandir(os.path.join(env.php, "8.2", "fpm", "pool.d")))
    print("Test 3b (no PHP-FPM pool for the user -> STOP, nothing written, no pool created) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.php": "<?php"})
        env.pool()
        env.pool(listen="/run/php/php8.3-fpm-shop.sock", version="8.3")
        discovery, outcome = await run_vhost(env, FakePorts(env))
        assert discovery.stop_code == vr.STOP_PHP_FPM_POOL_AMBIGUOUS and not outcome.ok
    print("Test 3c (two PHP-FPM pools for one user -> ambiguous, STOP) PASSED")


async def test_4_node_pm2() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        root = env.project(files={"package.json": "{}"})
        ports = FakePorts(env)
        ports.pm2 = [{"name": "app", "pid": 777, "pm2_env": {"pm_cwd": root, "PORT": "4321", "status": "online"}}]
        ports.listening = {777: [4321]}
        discovery, outcome = await run_vhost(env, ports)
        assert outcome.ok and discovery.project_type == vr.TYPE_NODE and discovery.node_port == 4321
        text = Path(os.path.join(env.enabled, f"{DOMAIN}.conf")).read_text()
        assert "proxy_pass http://127.0.0.1:4321;" in text and "3000" not in text, "the port is detected, never assumed"
        assert 'proxy_set_header Upgrade $http_upgrade;' in text and "root " not in text
    print("Test 4 (both missing + Node/PM2 -> upstream port taken from the running process, not hardcoded) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        root = env.project(files={"package.json": "{}", "ecosystem.config.js": "module.exports={apps:[{name:'a',env:{PORT: 5055}}]}"})
        discovery, outcome = await run_vhost(env, FakePorts(env))
        assert outcome.ok and discovery.node_port == 5055 and "ecosystem" in discovery.node_evidence
    print("Test 4b (no running process but an ecosystem config with PORT -> that port) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        root = env.project(files={"package.json": "{}"})
        ports = FakePorts(env)
        ports.pm2 = [
            {"name": "web", "pid": 1, "pm2_env": {"pm_cwd": root, "PORT": "3001"}},
            {"name": "api", "pid": 2, "pm2_env": {"pm_cwd": root, "PORT": "3002"}},
        ]
        discovery, outcome = await run_vhost(env, ports)
        assert not outcome.ok and discovery.stop_code == vr.STOP_PROJECT_TYPE_UNKNOWN
        assert os.listdir(env.enabled) == []
    print("Test 4c (two apps / two ports -> PROJECT_TYPE_UNKNOWN, no destructive guess) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"package.json": "{}"})
        discovery, outcome = await run_vhost(env, FakePorts(env))
        assert discovery.stop_code == vr.STOP_PROJECT_TYPE_UNKNOWN and "package.json present" in discovery.stop_reason
    print("Test 4d (package.json but nothing runs it -> PROJECT_TYPE_UNKNOWN) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        root = env.project(files={"package.json": "{}", "index.php": "<?php"})
        ports = FakePorts(env)
        ports.pm2 = [{"name": "app", "pid": 1, "pm2_env": {"pm_cwd": root, "PORT": "3001"}}]
        discovery, _ = await run_vhost(env, ports)
        assert discovery.stop_code == vr.STOP_PROJECT_TYPE_UNKNOWN and "both" in discovery.stop_reason
    print("Test 4e (Node evidence AND PHP entry point -> refuses to guess) PASSED")


async def test_5_static() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        root = env.project(files={"package.json": "{}", "dist/index.html": "x", "src/main.js": ""})
        discovery, outcome = await run_vhost(env, FakePorts(env))
        assert outcome.ok and discovery.project_type == vr.TYPE_STATIC and discovery.document_root == os.path.join(root, "dist")
        text = Path(os.path.join(env.enabled, f"{DOMAIN}.conf")).read_text()
        assert f"root {os.path.join(root, 'dist')};" in text and "fastcgi" not in text and "proxy_pass" not in text
    print("Test 5 (static project with dist/ -> document root is the real dist directory) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        root = env.project(files={"index.html": "x"})
        discovery, _ = await run_vhost(env, FakePorts(env))
        assert discovery.document_root == root
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        root = env.project(files={"build/index.html": "x"})
        discovery, _ = await run_vhost(env, FakePorts(env))
        assert discovery.document_root == os.path.join(root, "build")
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"dist/index.html": "x", "build/index.html": "y"})
        discovery, outcome = await run_vhost(env, FakePorts(env))
        assert discovery.stop_code == vr.STOP_PROJECT_TYPE_UNKNOWN and not outcome.ok
    print("Test 5b (root index.html / build/ used as they are; dist AND build -> ambiguous STOP) PASSED")


async def test_6_multiple_candidates() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(user="alpha", files={"index.html": "x"})
        env.project(user="beta", files={"index.html": "x"})
        ports = FakePorts(env)
        ports.asset = None
        before = env.snapshot()
        discovery, outcome = await run_vhost(env, ports)
        assert discovery.stop_code == vr.STOP_MULTIPLE_PROJECT_CANDIDATES and not outcome.ok
        assert "alpha" in discovery.stop_reason and "beta" in discovery.stop_reason
        assert env.snapshot() == before and os.listdir(env.enabled) == []
        title, kind, fields = vr.format_result(discovery, outcome, domain=DOMAIN)
        assert kind == "failure" and dict(fields)["Stage"] == "discovery" and "MULTIPLE_PROJECT_CANDIDATES" in dict(fields)["Reason"]
    print("Test 6 (same domain under two Linux users -> MULTIPLE_PROJECT_CANDIDATES, STOP, nothing written) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        ports = FakePorts(env)
        ports.asset = None
        discovery, outcome = await run_vhost(env, ports)
        assert discovery.stop_code == vr.STOP_PROJECT_NOT_FOUND
    print("Test 6b (no project anywhere -> PROJECT_NOT_FOUND, STOP) PASSED")


async def test_7_nginx_test_failure_rollback() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        ports.live_tests = [(False, "nginx: [emerg] unexpected token=abc123secret"), (True, "ok")]
        before = env.snapshot()
        discovery, outcome = await run_vhost(env, ports, reload=True)
        assert not outcome.ok and outcome.stage == vr.STAGE_NGINX_TEST and ports.reload_calls == 0
        assert outcome.rollback.startswith("SUCCESS"), outcome.rollback
        assert env.snapshot() == before, "rollback must leave the nginx tree exactly as it was"
        assert "abc123secret" not in outcome.nginx_test
        title, kind, fields = vr.format_result(discovery, outcome, domain=DOMAIN)
        assert title == "RTSA — NEW VHOST FAILED" and dict(fields)["Rollback"].startswith("SUCCESS")
        assert dict(fields)["Stage"] == "nginx-test"
    print("Test 7 (nginx -t fails after install -> files removed, no reload, rollback SUCCESS, tree identical) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        ports.candidate_result = (False, "nginx: [emerg] invalid parameter")
        discovery, outcome = await run_vhost(env, ports)
        assert not outcome.ok and outcome.stage == vr.STAGE_NGINX_TEST
        assert os.listdir(env.enabled) == [], "a candidate that fails validation is deleted and never installed"
        assert ports.live_test_calls == 0
    print("Test 7b (candidate fails pre-validation -> temp file deleted, nothing installed) PASSED")


async def test_8_reload_failure_rollback() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        ports.reload_results = [(False, "reload failed")]
        before = env.snapshot()
        discovery, outcome = await run_vhost(env, ports, reload=True)
        assert not outcome.ok and outcome.stage == vr.STAGE_RELOAD and outcome.reload == "FAILED"
        assert outcome.rollback.startswith("SUCCESS") and env.snapshot() == before
        assert ports.reload_calls == 1, "a failed reload is never retried in a loop"
    print("Test 8 (reload fails -> vhost removed again, single reload attempt, tree identical) PASSED")


async def test_9_verification_failure_no_false_recovery() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        ports.verify_result = (False, "HTTP HTTP 502 Bad Gateway", 120.0)
        ports.reload_results = [(True, "ok"), (True, "reloaded previous")]
        before = env.snapshot()
        discovery, outcome = await run_vhost(env, ports, reload=True)
        assert not outcome.ok and outcome.stage == vr.STAGE_VERIFICATION
        assert ports.recheck_calls == 0 and not outcome.recovered_via_monitor, "no recovery claim for an unhealthy site"
        assert "NOT HEALTHY" in outcome.website
        assert outcome.rollback.startswith("SUCCESS") and "previous config reloaded" in outcome.rollback
        assert ports.reload_calls == 2, "the previous valid config is reloaded after the rollback"
        assert env.snapshot() == before
    print("Test 9 (website unhealthy after reload -> rollback + previous config reloaded, no recovery claimed) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        ports.active = False
        discovery, outcome = await run_vhost(env, ports, reload=True)
        assert not outcome.ok and outcome.stage == vr.STAGE_VERIFICATION and ports.recheck_calls == 0
    print("Test 9b (nginx inactive after reload -> verification failure, no recovery claim) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        discovery, outcome = await run_vhost(env, ports, reload=True)
        assert outcome.ok and outcome.recovered_via_monitor and ports.recheck_calls == 1
        title, kind, fields = vr.format_result(discovery, outcome, domain=DOMAIN)
        data = dict(fields)
        assert title == "RTSA — NEW VHOST CREATED" and kind == "success"
        for key, expected in (("Enabled", "YES"), ("nginx -t", "PASS"), ("Reload", "SUCCESS")):
            assert data[key] == expected, (key, data[key])
        assert data["Website"].startswith("VERIFIED") and data["Linux User"] == USER and data["Project Type"] == "STATIC"
    print("Test 9c (healthy after reload -> success format per spec; recovery comes from the monitor lifecycle re-check) PASSED")


async def test_10_invalid_domains_rejected() -> None:
    bad = [
        "../../etc/passwd", "shop.example.com/../../etc", "shop.example.com; rm -rf /", "$(id).example.com",
        "*.example.com", "1.2.3.4", "https://shop.example.com", "shop.example.com:8080", "localhost", "a b.com",
        "shop..example.com", "-bad.example.com", "sh\nop.example.com", "", "   ", "shop_x.example.com", "x" * 300 + ".com",
        "/etc/nginx/nginx.conf", "..", "shop.example.com\\..\\x",
    ]
    for value in bad:
        domain, error = vr.validate_vhost_domain(value)
        assert domain is None and error, f"{value!r} must be rejected"
        parsed, _d, _r, args_error = vr.parse_newvhost_args(value)
        assert parsed is None and args_error, f"{value!r} must be rejected by the command parser"
    assert vr.validate_vhost_domain("Shop.Example.COM.")[0] == DOMAIN
    assert vr.parse_newvhost_args(f"{DOMAIN} --dry-run") == (DOMAIN, True, False, None)
    assert vr.parse_newvhost_args(f"--reload {DOMAIN}") == (DOMAIN, False, True, None)
    print(f"Test 10 ({len(bad)} hostile/invalid inputs incl. ../../etc/passwd rejected; --dry-run/--reload parsed) PASSED")


def _make_bot(env: Env, *, detection_only: bool = False, auto_enabled: bool = False):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=detection_only), modules=ModulesConfig(),
        cloudflare=CloudflareConfig(enabled=False),
        auto_vhost=AutoVhostConfig(**{**env.cfg.__dict__, "enabled": auto_enabled}),
    )

    class FakeDb:
        def __init__(self): self.actions = []
        def enqueue_action(self, action, result="pending"): self.actions.append((action, result))
        def enqueue_incident_create(self, **_k): pass

    bot = RTSABot(DiscordConfig(enabled=True, admin_role_ids=[10], critical_command_role_ids=[20]), cfg, EventBus(),
                  db_worker=FakeDb(), supervisor=None)
    return bot


class _Role:
    def __init__(self, role_id): self.id = role_id


class _Resp:
    def __init__(self): self.sent = []; self.deferred = False
    async def send_message(self, content=None, **_k): self.sent.append(content)
    async def defer(self, ephemeral=True): self.deferred = True


class _Follow:
    def __init__(self): self.sent = []
    async def send(self, content=None, *, embed=None, ephemeral=True, **_k): self.sent.append(embed)


def _interaction(role_ids):
    member = mock.Mock(spec=discord.Member)
    member.roles = [_Role(r) for r in role_ids]
    member.__str__ = mock.Mock(return_value="tester#1")
    return SimpleNamespace(user=member, response=_Resp(), followup=_Follow())


async def test_11_single_flight_and_command_gate() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        bot = _make_bot(env)
        ports = FakePorts(env)
        bot._vhost_ports = ports
        gate = asyncio.Event()
        entered = asyncio.Event()

        async def slow():
            entered.set()
            await gate.wait()

        ports.test_hook = slow
        first = asyncio.create_task(bot._newvhost_run(DOMAIN, dry_run=False, reload=False, requested_by="a"))
        await entered.wait()
        _domain, _disc, second = await bot._newvhost_run(DOMAIN, dry_run=False, reload=False, requested_by="b")
        assert not second.ok and vr.STOP_BUSY in second.reason, second
        assert len(ports.audits) == 0, "the refused duplicate must not touch anything"
        gate.set()
        _d, _disc, done = await first
        assert done.ok
        installed = [n for n in os.listdir(env.enabled)]
        assert installed == [f"{DOMAIN}.conf"]
    print("Test 11 (two concurrent /newvhost for one domain -> exactly one runs, the other is refused as busy) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        bot = _make_bot(env)
        bot._vhost_ports = FakePorts(env)
        callback = bot.tree.get_command("newvhost").callback

        stranger = _interaction([999])
        await callback(stranger, DOMAIN, False, False)
        assert "Tidak memiliki izin" in stranger.response.sent[0] and os.listdir(env.enabled) == []
        admin_only = _interaction([10])
        await callback(admin_only, DOMAIN, False, False)
        assert "Tidak memiliki izin" in admin_only.response.sent[0] and os.listdir(env.enabled) == []

        traversal = _interaction([20])
        await callback(traversal, "../../etc/passwd", False, False)
        embed = traversal.followup.sent[0]
        assert embed.title == "RTSA — NEW VHOST FAILED" and "INVALID_DOMAIN" in " ".join(f.value for f in embed.fields)
        assert os.listdir(env.enabled) == []

        dry = _interaction([20])
        await callback(dry, f"{DOMAIN} --dry-run", False, False)
        dry_embed = dry.followup.sent[0]
        assert "DRY RUN" in dry_embed.title and os.listdir(env.enabled) == []
        names = [f.name for f in dry_embed.fields]
        for expected in ("Domain", "Project", "Linux User", "Document Root", "Project Type", "PHP-FPM", "Node/PM2", "Port",
                         "Existing Vhost", "SSL State", "Proposed Config Path", "Proposed Template", "Nginx Test"):
            assert expected in names, expected
        assert "server_name" in dry_embed.description

        real = _interaction([20])
        await callback(real, DOMAIN, False, False)
        assert real.followup.sent[0].title == "RTSA — NEW VHOST CREATED" and os.listdir(env.enabled) == [f"{DOMAIN}.conf"]
        audits = bot._vhost_ports.audits
        assert len(audits) == 3, "rejected input, dry-run and the real run are all audited"
        assert [a["ok"] for a in audits] == [False, True, True] and audits[1]["dry_run"] is True
        for record in audits:
            assert record["operator"] == "tester#1" and record["server"]
        assert audits[2]["generated_path"] == os.path.join(env.enabled, f"{DOMAIN}.conf")
        assert audits[2]["owner"] == USER and audits[2]["template"] == "static-http" and audits[2]["nginx_test"] == "PASS"
        assert audits[2]["reload"] == "NOT PERFORMED" and audits[2]["rollback"] == "NOT NEEDED"

        from discord_integration.vhost_ports import BotVhostPorts
        BotVhostPorts(bot).audit(audits[2])
        action, result = bot.db_worker.actions[-1]
        assert action["action_type"] in (ActionType.NEWVHOST, ActionType.NEWVHOST.value) and result == "SUCCESS"
        assert action["target"] == DOMAIN and "generated_path" in action["reason"]
    print("Test 11b (command RBAC critical-only, traversal rejected, dry-run embed has every required field, audited) PASSED")


async def test_12_unrelated_vhosts_untouched() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        os.makedirs(env.available)
        for name in ("a.example.com", "b.example.com"):
            Path(env.available, f"{name}.conf").write_text(vhost_text(name))
            os.symlink(os.path.join(env.available, f"{name}.conf"), os.path.join(env.enabled, f"{name}.conf"))
        Path(env.confd, "custom.conf").write_text("upstream x { server 127.0.0.1:9; }\n")
        Path(env.tmp, "nginx", "nginx.conf").write_text("events{}\n")
        env.project(files={"index.html": "x"})
        before = env.snapshot()
        nginx_conf_before = Path(env.tmp, "nginx", "nginx.conf").read_bytes()
        discovery, outcome = await run_vhost(env, FakePorts(env), reload=True)
        assert outcome.ok and discovery.layout == vr.LAYOUT_SYMLINK
        after = env.snapshot()
        new_paths = set(after) - set(before)
        assert new_paths == {os.path.join(env.available, f"{DOMAIN}.conf"), os.path.join(env.enabled, f"{DOMAIN}.conf")}
        for path, value in before.items():
            assert after[path] == value, f"{path} changed"
        assert Path(env.tmp, "nginx", "nginx.conf").read_bytes() == nginx_conf_before
        assert os.readlink(os.path.join(env.enabled, f"{DOMAIN}.conf")) == os.path.join(env.available, f"{DOMAIN}.conf")
    print("Test 12 (unrelated vhosts, conf.d and nginx.conf untouched; symlink convention detected and followed) PASSED")

    source = Path(_REPO_ROOT, "core", "vhost_recovery.py").read_text() + Path(_REPO_ROOT, "discord_integration", "vhost_ports.py").read_text()
    for forbidden in ("shell=True", "create_subprocess_shell", "os.system", "shutil.rmtree", "os.rmdir", '"restart"', "'restart'"):
        assert forbidden not in source, f"{forbidden} must never appear in the /newvhost implementation"
    print("Test 12b (source audit: no shell, no rmtree, no nginx restart anywhere in /newvhost) PASSED")


async def test_13_cloudpanel_compat() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        discovery, outcome = await run_vhost(env, ports)
        assert discovery.cloudpanel_managed and discovery.project.source == "cloudpanel" and discovery.project.linux_user == USER
        text = Path(os.path.join(env.enabled, f"{DOMAIN}.conf")).read_text()
        assert "access_log" not in text, "no log directive is emitted for a log directory that does not exist"
        assert discovery.layout == vr.LAYOUT_DIRECT, "CloudPanel writes plain files into sites-enabled: no symlink convention imposed"
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        logs = os.path.join(env.home, USER, "logs", "nginx")
        os.makedirs(logs)
        discovery, outcome = await run_vhost(env, FakePorts(env))
        text = Path(os.path.join(env.enabled, f"{DOMAIN}.conf")).read_text()
        assert f"access_log {logs}/access.log;" in text and f"error_log {logs}/error.log;" in text
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        ports.asset = None
        discovery, outcome = await run_vhost(env, ports)
        assert outcome.ok and not discovery.cloudpanel_managed and discovery.project.source == "filesystem"
    print("Test 13 (CloudPanel project: owner/root from inventory, CloudPanel log layout, direct sites-enabled file; non-CloudPanel fallback works) PASSED")


async def test_14_missing_ssl_no_broken_directives() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        ghost = CertbotLineage("shop", (DOMAIN,), "/etc/letsencrypt/live/shop/fullchain.pem", None, None, "/etc/letsencrypt/live/shop/privkey.pem")
        ports.lineages = [ghost]
        discovery, outcome = await run_vhost(env, ports)
        text = Path(os.path.join(env.enabled, f"{DOMAIN}.conf")).read_text()
        assert outcome.ok and discovery.ssl is None
        for directive in ("ssl_certificate", "listen 443", "ssl_protocols"):
            assert directive not in text, f"{directive} must not be emitted without a real certificate"
        assert "listen 80;" in text and discovery.template_name == "static-http"
        assert "/fixssl" in dict(vr.format_result(discovery, outcome, domain=DOMAIN)[2])["SSL"]
    print("Test 14 (certificate paths that do not exist -> HTTP-safe config, zero ssl directives) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        crt, key = os.path.join(env.ssl, f"{DOMAIN}.crt"), os.path.join(env.ssl, f"{DOMAIN}.key")
        Path(crt).write_text("crt")
        Path(key).write_text("key")
        for label, cert_facts in (("expired", facts(-2)), ("other-name", facts(30, "other.example.org")), ("unreadable", None)):
            ports = FakePorts(env)
            ports.cert_facts = {crt: cert_facts}
            discovery = await vr.discover(DOMAIN, env.cfg, ports)
            assert discovery.ssl is None and discovery.ssl_note, label
    print("Test 14b (expired / wrong-name / unreadable certificate -> never mapped, HTTP-safe with a reason) PASSED")


async def test_15_valid_ssl_mapping_preserved() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        crt, key = os.path.join(env.ssl, f"{DOMAIN}.crt"), os.path.join(env.ssl, f"{DOMAIN}.key")
        Path(crt).write_text("crt")
        Path(key).write_text("key")
        ports = FakePorts(env)
        ports.cert_facts = {crt: facts(60)}
        discovery, outcome = await run_vhost(env, ports)
        text = Path(os.path.join(env.enabled, f"{DOMAIN}.conf")).read_text()
        assert outcome.ok and discovery.ssl and discovery.template_name == "static-https"
        assert f"ssl_certificate {crt};" in text and f"ssl_certificate_key {key};" in text
        assert "listen 443 ssl;" in text and "return 301 https://$host$request_uri;" in text
        assert ".well-known/acme-challenge" in text, "HTTP-01 renewals keep working"
    print("Test 15 (valid certificate + key -> HTTPS server with the real paths, HTTP->HTTPS redirect, ACME location) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        live = os.path.join(tmp, "le", "shop")
        os.makedirs(live)
        cert, key = os.path.join(live, "fullchain.pem"), os.path.join(live, "privkey.pem")
        Path(cert).write_text("c")
        Path(key).write_text("k")
        ports = FakePorts(env)
        ports.lineages = [CertbotLineage("shop", (DOMAIN, f"www.{DOMAIN}"), cert, None, None, key)]
        ports.cert_facts = {cert: facts(60)}
        discovery, outcome = await run_vhost(env, ports)
        text = Path(os.path.join(env.enabled, f"{DOMAIN}.conf")).read_text()
        assert f"ssl_certificate {cert};" in text and discovery.ssl.source == "certbot lineage shop"
    print("Test 15b (Certbot lineage covering the domain -> its own fullchain/privkey paths are mapped) PASSED")

    if shutil.which("openssl"):
        from discord_integration.vhost_ports import BotVhostPorts

        with tempfile.TemporaryDirectory() as tmp:
            env = Env(tmp)
            import subprocess
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{tmp}/k.pem", "-out", f"{tmp}/c.pem",
                            "-days", "30", "-subj", f"/CN={DOMAIN}", "-addext", f"subjectAltName=DNS:{DOMAIN}"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            bot = _make_bot(env)
            real_facts = await BotVhostPorts(bot).certificate_file_facts(f"{tmp}/c.pem")
            assert real_facts is not None and real_facts.covers(DOMAIN) and not real_facts.expired(time.time())
            assert await BotVhostPorts(bot).certificate_file_facts(f"{tmp}/missing.pem") is None
        print("Test 15c (real openssl reads a certificate FILE for validity/coverage; a missing file -> None) PASSED")


async def test_16_dry_run_writes_nothing_and_safety_rails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        before = env.snapshot()
        listing_before = sorted(os.listdir(env.enabled)), sorted(os.listdir(env.tmp))
        ports = FakePorts(env)
        discovery, outcome = await run_vhost(env, ports, dry_run=True, reload=True)
        assert outcome.ok and outcome.dry_run and env.snapshot() == before
        assert (sorted(os.listdir(env.enabled)), sorted(os.listdir(env.tmp))) == listing_before
        assert not ports.candidate_seen and ports.reload_calls == 0 and not ports.attributions
        assert "server_name shop.example.com;" in outcome.preview and outcome.template == "static-http"
        assert outcome.written_path == os.path.join(env.enabled, f"{DOMAIN}.conf")
    print("Test 16 (dry-run: identical tree, no candidate, no reload, no attribution, preview shown) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        ports.mutations = False
        discovery, outcome = await run_vhost(env, ports)
        assert not outcome.ok and vr.STOP_DETECTION_ONLY in outcome.reason and os.listdir(env.enabled) == []
    print("Test 16b (detection-only mode -> nothing is written) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        discovery = await vr.discover(DOMAIN, env.cfg, ports)
        Path(env.enabled, f"{DOMAIN}.conf").write_text("someone else's config\n")

        outcome = await vr.apply(discovery, env.cfg, ports, requested_by="t")
        assert not outcome.ok and outcome.stage == vr.STAGE_CONFIG_GENERATION
        assert Path(env.enabled, f"{DOMAIN}.conf").read_text() == "someone else's config\n"
        assert sorted(os.listdir(env.enabled)) == [f"{DOMAIN}.conf"], "temp file cleaned up after losing the race"
    print("Test 16c (a config appears between discovery and install -> never overwritten, temp file removed) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "real.conf")
        Path(target).write_text("x")
        try:
            vr._replace_symlink(os.path.join(tmp, "avail.conf"), target)
        except FileExistsError:
            pass
        else:
            raise AssertionError("a real file must never be replaced by a symlink")
        assert Path(target).read_text() == "x"
    print("Test 16d (symlink replacement refuses real files and live links) PASSED")


async def test_17_auto_vhost() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        ports = FakePorts(env)
        ports.asset = None
        discovery, outcome = await run_vhost(env, ports, auto=True)
        assert not outcome.ok and vr.STOP_NOT_AUTO_ELIGIBLE in outcome.reason and os.listdir(env.enabled) == []
        ports = FakePorts(env)
        discovery, outcome = await run_vhost(env, ports, auto=True)
        assert outcome.ok and outcome.reload == "NOT PERFORMED"
    print("Test 17 (auto mode requires CloudPanel-confirmed ownership; default is create-without-reload) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        env.project(files={"index.html": "x"})
        assert AutoVhostConfig().enabled is False and AutoVhostConfig().reload_after_create is False
        bot = _make_bot(env, auto_enabled=False)
        bot._vhost_ports = FakePorts(env)
        event = BaseEvent(source_module="website_monitor", category=EventCategory.NGINX_VHOST_MISSING, severity=Severity.HIGH,
                          message="x", metadata={"domain": DOMAIN, "domains": [DOMAIN]})
        await bot._on_vhost_missing_for_auto_vhost(event)
        assert not bot._auto_vhost_tasks and os.listdir(env.enabled) == [], "auto_vhost is off by default: alert only"

        bot = _make_bot(env, auto_enabled=True)
        bot._vhost_ports = FakePorts(env)
        published: List[BaseEvent] = []
        bot.bus.publish_nowait = published.append
        await bot._on_vhost_missing_for_auto_vhost(event)
        await asyncio.gather(*list(bot._auto_vhost_tasks))
        assert os.listdir(env.enabled) == [f"{DOMAIN}.conf"]
        assert published and published[0].category == EventCategory.CONFIG_CHANGE and "NEW VHOST CREATED" in published[0].message
        await bot._on_vhost_missing_for_auto_vhost(event)
        assert not bot._auto_vhost_tasks or all(t.done() for t in bot._auto_vhost_tasks)
        assert len(published) == 1, "cooldown: the same domain is not retried inside auto_cooldown_seconds"

        detection = _make_bot(env, detection_only=True, auto_enabled=True)
        await detection._on_vhost_missing_for_auto_vhost(event)
        assert not detection._auto_vhost_tasks
    print("Test 17b (auto_vhost off -> alert only; on -> one guarded create, cooldown, detection-only respected) PASSED")


async def test_18_website_monitor_vhost_missing() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        conf = os.path.join(tmp, "nginx", "sites-enabled")
        os.makedirs(conf)
        bus = EventBus()
        collected: List[BaseEvent] = []

        async def collector(event): collected.append(event)

        sub = await bus.subscribe("collector", collector, categories=None)
        cfg = WebsiteMonitorConfig(enabled=True, incident_mode=True, down_confirmation_checks=2, recovery_confirmation_checks=2,
                                   transient_retry_enabled=False, conf_directory=conf)
        asset = SimpleNamespace(domain=DOMAIN, linux_user=USER, project_root="/home/x", htdocs_path="/home/x/htdocs/d",
                                pm2_user=USER, nginx_vhost=None)

        async def fake_resolve(domain): return asset if domain == DOMAIN else None

        original = website_monitor_module.cloudpanel_resolver.resolve_domain
        original_find = website_monitor_module.find_vhost_blocks
        scans = []

        def counting_find(directory, domain):
            scans.append(directory)
            return original_find(directory, domain)

        website_monitor_module.cloudpanel_resolver.resolve_domain = fake_resolve
        website_monitor_module.find_vhost_blocks = counting_find
        try:
            def res(status, condition="cloudflare_down"):
                return WebsiteCheckResult(DOMAIN, "https", condition, status, f"HTTP {status}", 50.0, provider="cloudflare")

            wm = WebsiteMonitor(bus, cfg)
            for _ in range(3):
                await wm._evaluate(DOMAIN, res(526))
            await sub.queue.join()
            missing = [e for e in collected if e.category == EventCategory.NGINX_VHOST_MISSING]
            assert len(missing) == 1 and not [e for e in collected if e.category == EventCategory.WEBSITE_DOWN]
            event = missing[0]
            assert event.metadata["root_cause"] == "VHOST_MISSING" and event.metadata["root_cause_confidence"] == "CONFIRMED"
            assert f"/newvhost {DOMAIN} --dry-run" in event.message and event.message.startswith("NGINX_VHOST_MISSING")
            assert len(scans) <= 2, f"the vhost check is cached per domain, not repeated per probe ({len(scans)} directory reads)"

            Path(conf, f"{DOMAIN}.conf").write_text(vhost_text())
            wm._states[DOMAIN].vhost_checked_at = 0.0
            collected.clear()
            await wm._evaluate(DOMAIN, res(200, "ok"))
            await wm._evaluate(DOMAIN, res(200, "ok"))
            await sub.queue.join()
            recovered = [e for e in collected if e.category == EventCategory.WEBSITE_RECOVERED]
            assert len(recovered) == 1 and recovered[0].metadata["root_cause"] == "VHOST_MISSING"
            print("Test 18 (confirmed-down domain with a project but no vhost -> VHOST_MISSING + NGINX_VHOST_MISSING with /newvhost action; existing lifecycle recovers it) PASSED")

            collected.clear()
            wm2 = WebsiteMonitor(bus, cfg)
            for _ in range(3):
                await wm2._evaluate(DOMAIN, res(526))
            await sub.queue.join()
            assert [e.metadata["root_cause"] for e in collected if e.category == EventCategory.WEBSITE_DOWN] == ["SSL_INVALID"], (
                "with a vhost present the SSL classification is unchanged"
            )

            collected.clear()
            wm3 = WebsiteMonitor(bus, cfg)
            os.unlink(os.path.join(conf, f"{DOMAIN}.conf"))
            for _ in range(2):
                await wm3._evaluate(DOMAIN, res(None, "dns_failure"))
            await sub.queue.join()
            assert [e.metadata["root_cause"] for e in collected if e.category == EventCategory.WEBSITE_DOWN] == ["DNS_FAILURE"]

            collected.clear()
            wm4 = WebsiteMonitor(bus, cfg)
            for _ in range(2):
                await wm4._evaluate("nomap.example.com", WebsiteCheckResult("nomap.example.com", "https", "cloudflare_down", 526, "HTTP 526"))
            await sub.queue.join()
            assert [e.metadata["root_cause"] for e in collected if e.category == EventCategory.WEBSITE_DOWN] == ["SSL_INVALID"], (
                "no project on this host -> ownership unknown -> never classified as a missing vhost"
            )
        finally:
            website_monitor_module.cloudpanel_resolver.resolve_domain = original
            website_monitor_module.find_vhost_blocks = original_find
            await bus.unsubscribe("collector")
    print("Test 18b (strong causes (DNS) and unowned domains are never overridden with VHOST_MISSING) PASSED")


async def test_19_config_defaults() -> None:
    cfg = AutoVhostConfig()
    assert cfg.enabled is False
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "c.yaml")
        Path(path).write_text("auto_vhost:\n  sites_enabled_directory: relative/dir\n")
        try:
            ConfigManager(path)
        except ConfigValidationError as exc:
            assert "sites_enabled_directory" in str(exc)
        else:
            raise AssertionError("relative directories must be rejected")
        Path(path).write_text("auto_vhost:\n  cloudpanel_regeneration_command: ['sh', '-c', 'x']\n")
        try:
            ConfigManager(path)
        except ConfigValidationError as exc:
            assert "shell" in str(exc)
        else:
            raise AssertionError("shell interpreters must be rejected")
    print("Test 19 (auto_vhost defaults to disabled; relative paths and shell commands rejected by config validation) PASSED")


async def main() -> None:
    await test_1_existing_valid_vhost_not_overwritten()
    await test_2_symlink_recreated()
    await test_3_php_reconstruct()
    await test_4_node_pm2()
    await test_5_static()
    await test_6_multiple_candidates()
    await test_7_nginx_test_failure_rollback()
    await test_8_reload_failure_rollback()
    await test_9_verification_failure_no_false_recovery()
    await test_10_invalid_domains_rejected()
    await test_11_single_flight_and_command_gate()
    await test_12_unrelated_vhosts_untouched()
    await test_13_cloudpanel_compat()
    await test_14_missing_ssl_no_broken_directives()
    await test_15_valid_ssl_mapping_preserved()
    await test_16_dry_run_writes_nothing_and_safety_rails()
    await test_17_auto_vhost()
    await test_18_website_monitor_vhost_missing()
    await test_19_config_defaults()
    print("\nALL NEWVHOST TESTS PASSED")


asyncio.run(main())
