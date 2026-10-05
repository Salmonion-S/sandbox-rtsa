from __future__ import annotations

import asyncio
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import AutoSslConfig, CloudflareConfig, DiscordConfig, ModulesConfig, ResponseEngineConfig, RTSAConfig
from core.auto_ssl import (
    PROBE_HANDSHAKE_FAILED, PROBE_OK, PROBE_REFUSED, VERDICT_CERT_EXPIRED, VERDICT_CERT_VALID,
    VERDICT_DOMAIN_MISMATCH, VERDICT_NO_TLS_LISTENER, VERDICT_TLS_CONFIG_PROBLEM, BackupHandle,
    classify_origin_probe, probe_origin_with_facts,
)
from core.change_attribution import AUTO_SSL
from core.event_bus import EventBus
from core.nginx_vhost_inspect import distinct_vhost_files, find_vhost_blocks, server_name_matches
from discord_integration.auto_ssl_ports import BotAutoSslPorts, conf_directories_for, _minimal_env
from discord_integration.bot import RTSABot

DOMAIN = "shop.example.com"

CA_CNF = """[ca]
default_ca = CA_default
[CA_default]
database = index.txt
new_certs_dir = .
serial = serial
default_md = sha256
policy = policy_any
unique_subject = no
[policy_any]
commonName = supplied
organizationName = optional
[req]
distinguished_name = dn
prompt = no
[dn]
CN = {cn}
O = Test CA
[v3]
subjectAltName = DNS:{cn}
"""


def _run(*args: str, cwd: str) -> None:
    subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_cert(directory: str, name: str, cn: str, *, start: str, end: str) -> tuple[str, str]:
    work = os.path.join(directory, name)
    os.makedirs(work)
    with open(os.path.join(work, "ca.cnf"), "w") as handle:
        handle.write(CA_CNF.format(cn=cn))
    Path(work, "index.txt").touch()
    Path(work, "serial").write_text("01\n")
    _run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "r.csr",
         "-config", "ca.cnf", cwd=work)
    _run("openssl", "ca", "-batch", "-selfsign", "-keyfile", "k.pem", "-in", "r.csr", "-out", "c.pem",
         "-startdate", start, "-enddate", end, "-config", "ca.cnf", "-extensions", "v3", "-notext", cwd=work)
    return os.path.join(work, "c.pem"), os.path.join(work, "k.pem")


class TlsServer:
    def __init__(self, cert: str, key: str) -> None:
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with self.ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    def close(self) -> None:
        self._stop = True
        self.thread.join(timeout=2)
        self.sock.close()


class GarbageServer:
    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.recv(64)
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            except OSError:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self._stop = True
        self.thread.join(timeout=2)
        self.sock.close()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def make_bot(tmp: str) -> RTSABot:
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False, nginx_backup_directory=os.path.join(tmp, "backups")),
        modules=ModulesConfig(), cloudflare=CloudflareConfig(enabled=False),
        auto_ssl=AutoSslConfig(state_path=os.path.join(tmp, "state.json")),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=mock.Mock(), supervisor=None)


async def test_real_tls_probe() -> None:
    if shutil.which("openssl") is None:
        print("Test 1-5 SKIPPED (openssl CLI not available)")
        return
    with tempfile.TemporaryDirectory() as tmp:
        valid_cert, valid_key = make_cert(tmp, "valid", DOMAIN, start="20240101000000Z", end="20990101000000Z")
        expired_cert, expired_key = make_cert(tmp, "expired", DOMAIN, start="20200101000000Z", end="20200102000000Z")
        other_cert, other_key = make_cert(tmp, "other", "other.example.org", start="20240101000000Z", end="20990101000000Z")
        now = time.time()

        server = TlsServer(valid_cert, valid_key)
        try:
            result = await probe_origin_with_facts(DOMAIN, hosts=("127.0.0.1",), port=server.port, timeout=5.0)
        finally:
            server.close()
        assert result.outcome == PROBE_OK and result.facts is not None, result
        assert result.facts.subject_cn == DOMAIN and DOMAIN in result.facts.sans
        assert result.facts.issuer and "Test CA" in result.facts.issuer, result.facts.issuer
        assert result.chain_trusted is False, "self-signed test CA is not in the system trust store"
        assert classify_origin_probe(result, DOMAIN, now).code == VERDICT_CERT_VALID
    print("Test 1 (real TLS handshake: certificate facts parsed via openssl, valid cert -> CERT_VALID) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        expired_cert, expired_key = make_cert(tmp, "expired", DOMAIN, start="20200101000000Z", end="20200102000000Z")
        server = TlsServer(expired_cert, expired_key)
        try:
            result = await probe_origin_with_facts(DOMAIN, hosts=("127.0.0.1",), port=server.port, timeout=5.0)
        finally:
            server.close()
        assert result.outcome == PROBE_OK and result.facts is not None
        verdict = classify_origin_probe(result, DOMAIN, time.time())
        assert verdict.code == VERDICT_CERT_EXPIRED, verdict
        assert result.facts.days_left(time.time()) < 0
    print("Test 2 (an EXPIRED certificate is still readable and classified CERT_EXPIRED, not 'handshake failed') PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        other_cert, other_key = make_cert(tmp, "other", "other.example.org", start="20240101000000Z", end="20990101000000Z")
        server = TlsServer(other_cert, other_key)
        try:
            result = await probe_origin_with_facts(DOMAIN, hosts=("127.0.0.1",), port=server.port, timeout=5.0)
        finally:
            server.close()
        assert classify_origin_probe(result, DOMAIN, time.time()).code == VERDICT_DOMAIN_MISMATCH
    print("Test 3 (certificate for a different name -> CERT_DOMAIN_MISMATCH, not renewable) PASSED")

    refused = await probe_origin_with_facts(DOMAIN, hosts=("127.0.0.1",), port=_free_port(), timeout=2.0)
    assert refused.outcome == PROBE_REFUSED
    assert classify_origin_probe(refused, DOMAIN, time.time()).code == VERDICT_NO_TLS_LISTENER
    print("Test 4 (nothing listening -> NO_TLS_LISTENER) PASSED")

    garbage = GarbageServer()
    try:
        result = await probe_origin_with_facts(DOMAIN, hosts=("127.0.0.1",), port=garbage.port, timeout=2.0)
    finally:
        garbage.close()
    assert result.outcome == PROBE_HANDSHAKE_FAILED
    assert classify_origin_probe(result, DOMAIN, time.time()).code == VERDICT_TLS_CONFIG_PROBLEM
    print("Test 5 (listener that does not speak TLS -> TLS_CONFIG_PROBLEM) PASSED")


async def test_run_command_safety() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bot = make_bot(tmp)
        ports = BotAutoSslPorts(bot)

        with mock.patch.dict(os.environ, {"RTSA_DISCORD_BOT_TOKEN": "TOPSECRET-DISCORD", "RTSA_CLOUDFLARE_API_TOKEN": "TOPSECRET-CF"}):
            result = await ports.run_command([shutil.which("env") or "/usr/bin/env"], 10.0)
        assert result.returncode == 0
        assert "TOPSECRET" not in result.output, "child processes must not inherit RTSA's own secrets"
        assert "PATH=" in result.output
        assert "PATH" in _minimal_env()
        print("Test 6 (child process environment is minimal: RTSA Discord/Cloudflare tokens are never inherited) PASSED")

        started = time.monotonic()
        timed_out = await ports.run_command([sys.executable, "-c", "import time; time.sleep(30)"], 0.5)
        assert timed_out.timed_out is True and timed_out.returncode is None
        assert time.monotonic() - started < 5.0
        print("Test 7 (command timeout -> child killed, bounded, timed_out reported) PASSED")

        missing = await ports.run_command(["/nonexistent/certbot-binary", "renew"], 5.0)
        assert missing.missing_binary is True and missing.returncode is None
        print("Test 8 (missing binary -> clean CommandResult, no exception) PASSED")

        redacted = await ports.run_command(
            [sys.executable, "-c", "print('token=abcd1234efgh Authorization: Bearer SUPERSECRETBEARER123')"], 5.0,
        )
        assert "abcd1234efgh" not in redacted.output and "SUPERSECRETBEARER123" not in redacted.output
        print("Test 9 (tool output is sanitised before it can reach Discord/logs/audit) PASSED")

        pid_file = os.path.join(tmp, "child.pid")
        code = f"import os,time; open({pid_file!r},'w').write(str(os.getpid())); time.sleep(60)"
        task = asyncio.create_task(ports.run_command([sys.executable, "-c", code], 60.0))
        for _ in range(100):
            if os.path.exists(pid_file) and Path(pid_file).read_text():
                break
            await asyncio.sleep(0.05)
        child_pid = int(Path(pid_file).read_text())
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await asyncio.sleep(0.2)
        try:
            os.kill(child_pid, 0)
            alive = True
        except ProcessLookupError:
            alive = False
        assert not alive, "cancelling the repair must kill its child process, never orphan it"
        print("Test 10 (cancellation -> child process killed, CancelledError propagated) PASSED")

        source = Path(_REPO_ROOT, "discord_integration", "auto_ssl_ports.py").read_text()
        assert "shell=True" not in source and "os.system" not in source and "create_subprocess_shell" not in source
        print("Test 11 (no shell execution path exists in the Auto SSL ports) PASSED")


async def test_vhost_inspection_and_backup() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        nginx = os.path.join(tmp, "nginx")
        enabled = os.path.join(nginx, "sites-enabled")
        available = os.path.join(nginx, "sites-available")
        confd = os.path.join(nginx, "conf.d")
        for directory in (enabled, available, confd):
            os.makedirs(directory)
        Path(enabled, f"{DOMAIN}.conf").write_text(f"""
# server_name commented.example.com;
server {{
  listen 80;
  listen [::]:80;
  server_name {DOMAIN} www.{DOMAIN};
  return 301 https://$host$request_uri;
}}
server {{
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name www.{DOMAIN} {DOMAIN};
  ssl_certificate /etc/letsencrypt/live/{DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/{DOMAIN}/privkey.pem;
  root /home/shopuser/htdocs/{DOMAIN};
  location / {{ proxy_pass http://127.0.0.1:3111/; }}
}}
""")
        Path(available, "linked.example.com.conf").write_text(
            "server { listen 443 ssl; server_name linked.example.com; ssl_certificate /x/f.pem; fastcgi_pass unix:/run/php/php8.2-fpm-x.sock; }\n"
        )
        os.symlink(os.path.join(available, "linked.example.com.conf"), os.path.join(enabled, "linked.example.com.conf"))
        outside = os.path.join(tmp, "outside.conf")
        Path(outside).write_text("server { server_name evil.example.com; listen 443 ssl; }\n")
        os.symlink(outside, os.path.join(enabled, "evil.example.com.conf"))
        Path(confd, "wild.conf").write_text("server { listen 443 ssl; server_name *.wild.example.com; }\n")

        blocks = find_vhost_blocks(enabled, DOMAIN)
        assert len(blocks) == 2 and len(distinct_vhost_files(blocks)) == 1
        tls_block = next(b for b in blocks if b.has_ssl_listen)
        assert tls_block.ssl_certificate == f"/etc/letsencrypt/live/{DOMAIN}/fullchain.pem"
        assert tls_block.proxy_pass == "http://127.0.0.1:3111/" and tls_block.root.endswith(DOMAIN)
        assert not any(b.has_ssl_listen for b in blocks if b is not tls_block)
        print("Test 12 (vhost inspection: 80+443 blocks, server_name list, ssl_certificate, proxy_pass, comments ignored) PASSED")

        linked = find_vhost_blocks(enabled, "linked.example.com")
        assert len(linked) == 1 and linked[0].fastcgi_pass == "unix:/run/php/php8.2-fpm-x.sock"
        assert linked[0].path.endswith("sites-enabled/linked.example.com.conf")
        assert "sites-available" in linked[0].real_path
        assert find_vhost_blocks(enabled, "evil.example.com") == [], (
            "a symlink escaping the nginx tree must never be read"
        )
        assert find_vhost_blocks(enabled, "nothing.example.com") == []
        print("Test 13 (symlinked vhosts followed inside the nginx tree; symlink escaping it ignored; missing domain -> empty) PASSED")

        assert server_name_matches("*.wild.example.com", "a.wild.example.com")
        assert not server_name_matches("*.wild.example.com", "wild.example.com")
        assert not server_name_matches("~^(www\\.)?x\\.com$", "x.com") and not server_name_matches("_", "x.com")
        assert conf_directories_for(enabled) == [enabled, confd]
        print("Test 14 (server_name matching: wildcard/regex/default handled; conf.d sibling scanned too) PASSED")

        bot = make_bot(tmp)
        ports = BotAutoSslPorts(bot)
        attributions = []
        bot._record_change_attribution = lambda entries, source, who: attributions.append((entries, source, who))
        target = os.path.join(enabled, f"{DOMAIN}.conf")
        os.chmod(target, 0o640)
        original = Path(target).read_bytes()
        handle = await ports.backup_file(target)
        assert isinstance(handle, BackupHandle) and handle.digest and handle.backup_path
        assert Path(handle.backup_path).read_bytes() == original
        assert stat.S_IMODE(os.stat(handle.backup_path).st_mode) == 0o600
        assert attributions and attributions[0][1] == AUTO_SSL, "vhost changes must be attributed to Auto SSL (FIM ledger)"
        Path(target).write_text("server { broken }")
        assert await ports.file_digest(target) != handle.digest
        assert await ports.restore_file(handle) is None
        assert Path(target).read_bytes() == original and await ports.file_digest(target) == handle.digest
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o640, "restore must preserve the vhost file mode"
        print("Test 15 (vhost backup/restore: digest, 0600 backup, FIM attribution, atomic restore preserves mode) PASSED")

        gone = await ports.backup_file(os.path.join(tmp, "missing.conf"))
        assert gone.digest is None and gone.original_bytes is None
        assert await ports.restore_file(gone) == "no backup content available"
        print("Test 16 (backup of a missing file degrades cleanly; restore without content refuses instead of writing) PASSED")


async def main() -> None:
    await test_real_tls_probe()
    await test_run_command_safety()
    await test_vhost_inspection_and_backup()
    print("\nALL AUTO SSL REAL-IO TESTS PASSED")


asyncio.run(main())
