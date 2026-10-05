from __future__ import annotations

import asyncio
import os
import socket
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from core.auto_ssl import PROBE_OK, PROBE_REFUSED, CertificateFacts, OriginTlsProbe
from core.datatypes import EventCategory
from core.nginx_vhost_inspect import VhostServerBlock
from core.website_check import WebsiteCheckResult
from core.website_diagnosis import (
    APPLICATION_CRASH_LOOP, APPLICATION_HTTP_ERROR, APPLICATION_PORT_NOT_LISTENING, BACKEND_TIMEOUT, CONFIRMED,
    CLOUDFLARE_ORIGIN_MISMATCH, LIKELY, NETWORK_PATH_UNVERIFIED, NGINX_CONFIG_INVALID, NGINX_NOT_ACTIVE, PHP_FPM_DOWN,
    PM2_NOT_RUNNING, POSSIBLE, UNKNOWN_ROOT_CAUSE, UPSTREAM_CONNECTION_REFUSED, VHOST_CONFIGURATION_MISMATCH,
    VHOST_MISSING, DefaultDiagnosisPorts, DiagnosisInputs, DiagnosisPorts, DnsSnapshot, TcpProbe,
    build_still_down_event, run_diagnosis_chain, TCP_MISSING_SOCKET, TCP_OK, TCP_REFUSED, TCP_TIMEOUT, TCP_ERROR,
)

DOMAIN = "www.example.com"
LOCAL_IP = "203.0.113.10"
CF_EDGE = "104.16.0.1"
NOW = time.time()


def good_probe() -> OriginTlsProbe:
    facts = CertificateFacts(DOMAIN, "Let's Encrypt (R3)", NOW - 86400, NOW + 60 * 86400, (DOMAIN,))
    return OriginTlsProbe(PROBE_OK, host="127.0.0.1", facts=facts, chain_trusted=True)


def block(*, proxy: Optional[str] = "http://127.0.0.1:3000", fastcgi: Optional[str] = None, ssl: bool = True,
          cert: Optional[str] = None) -> VhostServerBlock:
    return VhostServerBlock(
        path="/etc/nginx/sites-enabled/www.example.com.conf", real_path="/etc/nginx/sites-enabled/www.example.com.conf",
        server_names=(DOMAIN,), listens=("443 ssl",) if ssl else ("80",), has_ssl_listen=ssl,
        ssl_certificate=cert, ssl_certificate_key=None, proxy_pass=proxy, fastcgi_pass=fastcgi, root=None, includes=(),
    )


class FakePorts(DiagnosisPorts):
    def __init__(self) -> None:
        self.dns = DnsSnapshot(a=(LOCAL_IP,))
        self.local = [LOCAL_IP]
        self.cf_records: Optional[List[str]] = None
        self.active: Optional[bool] = True
        self.test = (True, "syntax is ok")
        self.blocks: List[VhostServerBlock] = [block()]
        self.tcp = TcpProbe(TCP_OK)
        self.tcp_targets: List[str] = []
        self.pm2: Optional[List[Dict[str, Any]]] = None
        self.origin = good_probe()
        self.local_status: Optional[int] = None
        self.log_tail: Optional[str] = None

    async def resolve_dns(self, domain): return self.dns
    def local_addresses(self): return list(self.local)
    async def cloudflare_origin_records(self, domain): return self.cf_records
    async def nginx_active(self): return self.active
    async def nginx_test(self): return self.test
    async def find_vhosts(self, domain): return list(self.blocks)

    async def tcp_probe(self, target):
        self.tcp_targets.append(target)
        return self.tcp

    def pm2_processes(self, user): return self.pm2
    async def probe_origin(self, domain): return self.origin
    async def local_http_status(self, domain): return self.local_status
    async def tail_log(self, path, asset): return self.log_tail


def asset() -> Any:
    return SimpleNamespace(linux_user="site", pm2_user="site", htdocs_path=f"/home/site/htdocs/{DOMAIN}", project_root="/home/site")


def inputs(*, with_asset: bool = True, pm2_state: str = "UNKNOWN", expected: Tuple[str, ...] = (),
           result: Optional[WebsiteCheckResult] = None, nginx_up: Optional[bool] = True) -> DiagnosisInputs:
    return DiagnosisInputs(
        domain=DOMAIN, ssl_state="RECOVERED / VALID",
        last_result=result or WebsiteCheckResult(DOMAIN, "https", "http_down", 502, "HTTP 502 Bad Gateway"),
        asset=asset() if with_asset else None, pm2_state=pm2_state, nginx_locally_up=nginx_up,
        conf_directories=["/etc/nginx/sites-enabled"], expected_origin_ips=expected,
    )


def pm2_proc(name: str = "backend-example", status: str = "online", restarts: int = 0, uptime_s: float = 3600.0) -> Dict[str, Any]:
    return {"name": name, "pid": 123, "pm2_env": {
        "status": status, "restart_time": restarts, "pm_uptime": (time.time() - uptime_s) * 1000,
        "pm_err_log_path": "/home/site/.pm2/logs/backend-error.log",
    }}


def codes(report) -> List[Tuple[str, str]]:
    return [(f.code, f.confidence) for f in report.findings]


async def test_pm2_not_running_matches_spec_sample() -> None:
    ports = FakePorts()
    ports.pm2 = [pm2_proc(status="stopped")]
    ports.tcp = TcpProbe(TCP_REFUSED, "connection refused")
    report = await run_diagnosis_chain(inputs(pm2_state="CONFIRMED_DOWN"), ports)
    assert codes(report) == [(PM2_NOT_RUNNING, CONFIRMED)], codes(report)
    event = build_still_down_event(report)
    text = event.message
    assert event.category == EventCategory.WEBSITE_STILL_DOWN
    for expected in (
        "WEBSITE_STILL_DOWN", "SSL:\nRECOVERED / VALID", "Website:\nSTILL DOWN (HTTP 502 Bad Gateway)",
        "Confirmed Root Cause:\nPM2_NOT_RUNNING [CONFIRMED]", "PM2 app backend-example status=stopped",
        "Expected Port: 3000", "Listening: NO", "Cloudflare Origin: MATCH", "NGINX: ACTIVE", "NGINX Config: PASS",
        "VHost: PRESENT", "SSL: VALID", "Recommended Action:", "Start/recover the PM2 application",
    ):
        assert expected in text, f"missing {expected!r} in:\n{text}"
    assert event.metadata["root_cause"] == PM2_NOT_RUNNING and event.metadata["root_cause_confidence"] == CONFIRMED
    print("Test 1 (PM2 stopped -> WEBSITE_STILL_DOWN in the specified format, CONFIRMED PM2_NOT_RUNNING) PASSED")


async def test_cloudflare_origin_mismatch_evidence_levels() -> None:
    ports = FakePorts()
    ports.dns = DnsSnapshot(a=("198.51.100.9",), aaaa=("2606:4700::1111",))
    report = await run_diagnosis_chain(inputs(expected=(LOCAL_IP,)), ports)
    finding = next(f for f in report.findings if f.code == CLOUDFLARE_ORIGIN_MISMATCH)
    assert finding.confidence == CONFIRMED, "operator-configured expected origin + records elsewhere is CONFIRMED"
    evidence = "\n".join(finding.evidence)
    assert f"Expected Origin: {LOCAL_IP}" in evidence and "DNS A: 198.51.100.9" in evidence
    assert "DNS AAAA: 2606:4700::1111" in evidence
    assert dict(report.checks)["Cloudflare Origin"] == "MISMATCH"
    text = build_still_down_event(report).message
    assert "Confirmed Root Cause:\nCLOUDFLARE_ORIGIN_MISMATCH [CONFIRMED]" in text
    print("Test 2 (direct DNS points elsewhere + configured expected origin -> CONFIRMED CLOUDFLARE_ORIGIN_MISMATCH with A/AAAA evidence) PASSED")

    ports = FakePorts()
    ports.dns = DnsSnapshot(a=(CF_EDGE,))
    ports.cf_records = ["198.51.100.9"]
    report = await run_diagnosis_chain(inputs(), ports)
    finding = next(f for f in report.findings if f.code == CLOUDFLARE_ORIGIN_MISMATCH)
    assert finding.confidence == POSSIBLE, "interface-derived expectation cannot prove a mismatch (NAT / elastic IP)"
    assert any("NAT" in line for line in finding.evidence)
    assert dict(report.checks)["Cloudflare Proxied"] == "YES"
    text = build_still_down_event(report).message
    assert "Possible Root Cause:" in text and "Likely Root Cause" not in text and "Confirmed Root Cause" not in text
    print("Test 3 (proxied domain, Cloudflare API record elsewhere, interface-only expectation -> POSSIBLE, never overstated) PASSED")

    ports = FakePorts()
    ports.dns = DnsSnapshot(a=(CF_EDGE,))
    ports.cf_records = None
    report = await run_diagnosis_chain(inputs(), ports)
    assert not any(f.code == CLOUDFLARE_ORIGIN_MISMATCH for f in report.findings), (
        "Cloudflare edge IPs must never be compared against this server's IP"
    )
    assert dict(report.checks)["Cloudflare Origin"].startswith("UNKNOWN")
    print("Test 4 (proxied domain, origin record unreadable -> UNKNOWN, no false mismatch from edge IPs) PASSED")

    ports = FakePorts()
    ports.dns = DnsSnapshot(a=(LOCAL_IP, "198.51.100.9"))
    report = await run_diagnosis_chain(inputs(), ports)
    finding = next(f for f in report.findings if f.code == CLOUDFLARE_ORIGIN_MISMATCH)
    assert finding.confidence == LIKELY and any("198.51.100.9" in line for line in finding.evidence)
    print("Test 5 (one record is this server, another points elsewhere -> LIKELY stale/secondary origin) PASSED")

    ports = FakePorts()
    ports.dns = DnsSnapshot(a=("198.51.100.9",))
    ports.pm2 = [pm2_proc(status="stopped")]
    ports.tcp = TcpProbe(TCP_REFUSED)
    report = await run_diagnosis_chain(inputs(pm2_state="CONFIRMED_DOWN"), ports)
    assert report.primary is not None and report.primary.code == PM2_NOT_RUNNING, (
        "a CONFIRMED finding outranks an earlier POSSIBLE one"
    )
    print("Test 6 (POSSIBLE origin mismatch does not hide a CONFIRMED PM2 finding) PASSED")


async def test_nginx_and_vhost() -> None:
    ports = FakePorts()
    ports.blocks = []
    report = await run_diagnosis_chain(inputs(), ports)
    assert (VHOST_MISSING, CONFIRMED) in codes(report) and dict(report.checks)["VHost"] == "MISSING"
    assert any("htdocs" in line for f in report.findings if f.code == VHOST_MISSING for line in f.evidence)
    text = build_still_down_event(report).message
    assert "/newvhost" in text
    report = await run_diagnosis_chain(inputs(with_asset=False), ports)
    assert (VHOST_MISSING, LIKELY) in codes(report), "without a project on this host the vhost gap is only LIKELY"
    print("Test 7 (no vhost: CONFIRMED when the project exists on this host, LIKELY otherwise; action = /newvhost) PASSED")

    ports = FakePorts()
    ports.blocks = [block(ssl=False)]
    ports.origin = OriginTlsProbe(PROBE_REFUSED)
    report = await run_diagnosis_chain(inputs(), ports)
    assert (VHOST_CONFIGURATION_MISMATCH, CONFIRMED) in codes(report)
    assert any("no `listen ... ssl`" in line for f in report.findings if f.code == VHOST_CONFIGURATION_MISMATCH for line in f.evidence)
    print("Test 8 (vhost without a TLS listener -> CONFIRMED VHOST_CONFIGURATION_MISMATCH) PASSED")

    ports = FakePorts()
    other = CertificateFacts("other.example.org", "X", NOW - 1, NOW + 86400, ("other.example.org",))
    ports.origin = OriginTlsProbe(PROBE_OK, facts=other)
    report = await run_diagnosis_chain(inputs(), ports)
    mismatch = next(f for f in report.findings if f.code == VHOST_CONFIGURATION_MISMATCH)
    assert any("SNI" in line for line in mismatch.evidence)
    print("Test 9 (SNI answered with a certificate for another name -> VHOST_CONFIGURATION_MISMATCH) PASSED")

    ports = FakePorts()
    ports.active = False
    ports.test = (False, "nginx: [emerg] unknown directive token=abc123secret")
    report = await run_diagnosis_chain(inputs(nginx_up=None), ports)
    assert (NGINX_NOT_ACTIVE, CONFIRMED) in codes(report) and (NGINX_CONFIG_INVALID, CONFIRMED) in codes(report)
    assert dict(report.checks)["NGINX"] == "INACTIVE" and dict(report.checks)["NGINX Config"] == "FAIL"
    assert "abc123secret" not in build_still_down_event(report).message
    print("Test 10 (nginx inactive + nginx -t failing -> both CONFIRMED, secrets in nginx output redacted) PASSED")


async def test_backend_and_pm2() -> None:
    ports = FakePorts()
    ports.pm2 = [pm2_proc(status="online")]
    ports.tcp = TcpProbe(TCP_REFUSED, "connection refused")
    report = await run_diagnosis_chain(inputs(pm2_state="CONFIRMED_UP"), ports)
    assert codes(report) == [(APPLICATION_PORT_NOT_LISTENING, CONFIRMED)], codes(report)
    assert "Listening: NO" in "\n".join(report.findings[0].evidence)
    assert dict(report.checks)["PM2"] == "ONLINE"
    print("Test 11 (PM2 online but nothing listens on the proxied port -> CONFIRMED APPLICATION_PORT_NOT_LISTENING) PASSED")

    ports = FakePorts()
    ports.pm2 = [pm2_proc(status="online", restarts=14, uptime_s=8.0)]
    ports.tcp = TcpProbe(TCP_OK)
    report = await run_diagnosis_chain(inputs(pm2_state="CONFIRMED_UP"), ports)
    assert (APPLICATION_CRASH_LOOP, LIKELY) in codes(report)
    print("Test 12 (many restarts + tiny uptime -> LIKELY APPLICATION_CRASH_LOOP, not CONFIRMED) PASSED")

    ports = FakePorts()
    ports.pm2 = None
    ports.tcp = TcpProbe(TCP_REFUSED)
    report = await run_diagnosis_chain(inputs(pm2_state="UNKNOWN"), ports)
    assert (UPSTREAM_CONNECTION_REFUSED, CONFIRMED) in codes(report)
    assert dict(report.checks)["PM2"] == "UNKNOWN"
    print("Test 13 (PM2 state unknown but upstream refuses -> UPSTREAM_CONNECTION_REFUSED, PM2 not guessed) PASSED")

    ports = FakePorts()
    ports.tcp = TcpProbe(TCP_TIMEOUT, "connect timeout")
    report = await run_diagnosis_chain(inputs(with_asset=False), ports)
    assert (BACKEND_TIMEOUT, LIKELY) in codes(report)
    print("Test 14 (upstream connect timeout -> LIKELY BACKEND_TIMEOUT) PASSED")

    ports = FakePorts()
    ports.blocks = [block(proxy=None, fastcgi="unix:/run/php/php8.2-fpm-site.sock")]
    ports.tcp = TcpProbe(TCP_MISSING_SOCKET, "socket does not exist")
    report = await run_diagnosis_chain(inputs(), ports)
    assert (PHP_FPM_DOWN, CONFIRMED) in codes(report) and ports.tcp_targets == ["unix:/run/php/php8.2-fpm-site.sock"]
    print("Test 15 (fastcgi_pass socket missing -> CONFIRMED PHP_FPM_DOWN; socket path comes from the vhost, not a guess) PASSED")

    ports = FakePorts()
    ports.blocks = [block(proxy="http://198.51.100.77:8080")]
    report = await run_diagnosis_chain(inputs(), ports)
    assert ports.tcp_targets == [], "a non-local upstream must never be probed by RTSA"
    assert "NOT PROBED" in dict(report.checks)["Upstream"]
    ports = FakePorts()
    ports.blocks = [block(proxy="http://$backend_host")]
    report = await run_diagnosis_chain(inputs(), ports)
    assert ports.tcp_targets == [] and "NOT PROBED" in dict(report.checks)["Upstream"]
    print("Test 16 (non-local / variable upstreams are reported as NOT PROBED, never connected to) PASSED")


async def test_application_and_network_levels() -> None:
    ports = FakePorts()
    ports.local_status = 500
    ports.log_tail = "TypeError: boom | token=[REDACTED]"
    ports.pm2 = [pm2_proc(status="online")]
    report = await run_diagnosis_chain(inputs(pm2_state="CONFIRMED_UP"), ports)
    assert (APPLICATION_HTTP_ERROR, CONFIRMED) in codes(report)
    assert any("Recent error log" in line for f in report.findings for line in f.evidence)
    print("Test 17 (SSL/NGINX/PM2/port all fine but local request is HTTP 500 -> CONFIRMED APPLICATION_HTTP_ERROR + log evidence) PASSED")

    ports = FakePorts()
    ports.local_status = 200
    report = await run_diagnosis_chain(inputs(), ports)
    assert codes(report) == [(NETWORK_PATH_UNVERIFIED, POSSIBLE)], codes(report)
    text = build_still_down_event(report).message
    assert "No firewall / routing evidence was collected" in text and "Possible Root Cause" in text
    assert "Confirmed Root Cause" not in text and "Likely Root Cause" not in text
    print("Test 18 (everything healthy locally, external probe fails -> POSSIBLE network path, firewall NOT concluded) PASSED")

    ports = FakePorts()
    ports.local_status = None
    report = await run_diagnosis_chain(inputs(result=WebsiteCheckResult(DOMAIN, "https", "ok", 200)), ports)
    assert report.findings == [] and report.primary is None
    event = build_still_down_event(report)
    assert "UNKNOWN (no evidence collected)" in event.message
    assert "Likely Root Cause" not in event.message and "Confirmed Root Cause" not in event.message
    assert event.metadata["root_cause"] == UNKNOWN_ROOT_CAUSE
    print("Test 19 (no evidence -> 'UNKNOWN (no evidence collected)', never a made-up 'likely root cause') PASSED")


async def test_default_ports_real_io() -> None:
    ports = DefaultDiagnosisPorts(conf_directories=[], nginx_test=lambda: asyncio.sleep(0, result=(True, "ok")))

    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        assert (await ports.tcp_probe(f"127.0.0.1:{port}")).outcome == TCP_OK
    finally:
        server.close()
        await server.wait_closed()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    assert (await ports.tcp_probe(f"127.0.0.1:{closed_port}")).outcome == TCP_REFUSED
    with tempfile.TemporaryDirectory() as tmp:
        sock_path = os.path.join(tmp, "php.sock")
        assert (await ports.tcp_probe(f"unix:{sock_path}")).outcome == TCP_MISSING_SOCKET
        unix_server = await asyncio.start_unix_server(lambda r, w: w.close(), sock_path)
        try:
            assert (await ports.tcp_probe(f"unix:{sock_path}")).outcome == TCP_OK
        finally:
            unix_server.close()
            await unix_server.wait_closed()
        regular = os.path.join(tmp, "regular.file")
        Path(regular).write_text("x")
        assert (await ports.tcp_probe(f"unix:{regular}")).outcome == TCP_ERROR
    print("Test 20 (real TCP/unix-socket probes: OK / REFUSED / MISSING_SOCKET / not-a-socket) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        project = os.path.join(tmp, "home", "site")
        os.makedirs(os.path.join(project, ".pm2", "logs"))
        log = os.path.join(project, ".pm2", "logs", "err.log")
        Path(log).write_text("start\n" + "\n".join(f"line {i} password=hunter2 ok" for i in range(20)))
        outside = os.path.join(tmp, "outside.log")
        Path(outside).write_text("secret outside content")
        asset_obj = SimpleNamespace(project_root=project)
        tail = await ports.tail_log(log, asset_obj)
        assert tail and "hunter2" not in tail and "line 19" in tail and "line 10" not in tail
        assert await ports.tail_log(outside, asset_obj) is None, "log reads are confined to the project's home"
        os.symlink(outside, os.path.join(project, "link.log"))
        assert await ports.tail_log(os.path.join(project, "link.log"), asset_obj) is None
        assert await ports.tail_log(log, None) is None
    print("Test 21 (app log tail: last lines only, secrets redacted, confined to the project home, symlink escape refused) PASSED")

    dns = await ports.resolve_dns("localhost")
    assert "127.0.0.1" in dns.a or "::1" in dns.aaaa
    missing = await ports.resolve_dns("does-not-exist.invalid")
    assert not missing.a and not missing.aaaa and missing.error
    print("Test 22 (DNS snapshot splits A/AAAA; resolution failure is reported, not raised) PASSED")


async def main() -> None:
    await test_pm2_not_running_matches_spec_sample()
    await test_cloudflare_origin_mismatch_evidence_levels()
    await test_nginx_and_vhost()
    await test_backend_and_pm2()
    await test_application_and_network_levels()
    await test_default_ports_real_io()
    print("\nALL WEBSITE DIAGNOSIS TESTS PASSED")


asyncio.run(main())
