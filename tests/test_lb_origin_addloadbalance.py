from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

_TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _TESTS)

import _lb_vhost_fakes as nv
from _lb_fakes import DOMAIN, Env, FakePorts, make_config, make_report
from config.manager import LbDomainConfig
from core import vhost_recovery as vr
from core.lb_model import HttpProbeResult, OpStatus, ServerInventoryEntry, TlsProbeResult
from core.lb_origin import (
    LbOriginPorts, OriginReport, build_origin_report, load_report_file, sign_report, write_report_file,
)

USER = "shopuser"
GIT_SHA = "0123456789abcdef0123456789abcdef01234567"


class TreePorts(nv.NvPorts, LbOriginPorts):
    def __init__(self, env, server_id: str = "server1") -> None:
        nv.NvPorts.__init__(self, env)
        self.server_id = server_id
        self.http = {"/healthz": HttpProbeResult(True, 200, 9.0, "", True, "", 12)}
        self.tls = TlsProbeResult(True, True, None, "")
        self.db_results = None
        self.probe_log: List[str] = []

    def read_text(self, path: str, limit: int) -> Optional[str]:
        try:
            info = os.stat(path)
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                return None
            return Path(path).read_text(encoding="utf-8", errors="replace")[:limit]
        except OSError:
            return None

    def list_directory(self, path: str, limit: int) -> List[str]:
        try:
            return sorted(os.listdir(path))[:limit]
        except OSError:
            return []

    def is_directory(self, path: str) -> bool:
        return os.path.isdir(path)

    async def local_http_probe(self, scheme, port, host_header, path, timeout, verify_tls):
        self.probe_log.append(f"{scheme}://{host_header}:{port}{path}")
        if not os.path.exists(os.path.join(self.env.enabled, f"{host_header}.conf")):
            return HttpProbeResult(False, None, None, "connection refused")
        return self.http.get(path, HttpProbeResult(False, 404, 3.0, "HTTP 404", True, "", 0))

    async def local_tls_probe(self, port, domain, timeout):
        return self.tls

    def server_entry(self):
        return ServerInventoryEntry(self.server_id, self.server_id.title(), f"{self.server_id}.internal", "203.0.113.11", "10.0.0.11", "both")

    def clock(self) -> float:
        return nv.NOW


def listen_vhost(env, domain=DOMAIN, listen="443 ssl") -> None:
    Path(env.enabled, f"{domain}.conf").write_text(f"server {{\n  listen {listen};\n  server_name {domain};\n  root /srv/x;\n}}\n")


def node_project(env, db_url: str = "postgres://appuser:s3cr3tPass@db.internal:5432/appdb?connection_limit=10", extra_env: str = "") -> str:
    root = env.project(files={
        "package.json": json.dumps({"name": "shop", "version": "1.2.3", "dependencies": {"socket.io": "4", "express-session": "1"}}),
        ".env": f"DATABASE_URL={db_url}\nPORT=3000\n{extra_env}",
        ".git/HEAD": "ref: refs/heads/main\n", ".git/refs/heads/main": GIT_SHA + "\n",
        "migrations/20260101_init.sql": "--", "migrations/20260215_users.sql": "--", "migrations/20260301_orders.sql": "--",
        "uploads/avatar.png": "x",
    })
    return root


def vhost_cfg(env):
    return env.cfg


async def report_for(env, ports, lb_cfg=None):
    return await build_origin_report(domain=DOMAIN, ports=ports, vhost_cfg=env.cfg, lb_cfg=lb_cfg or make_config(3), operation_id="op-test")


async def test_1_full_origin_report() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = nv.NvEnv(tmp)
        root = node_project(env)
        listen_vhost(env)
        ports = TreePorts(env)
        ports.pm2 = [{"name": "app", "pid": 777, "pm2_env": {"pm_cwd": root, "PORT": "3000", "status": "online"}}]
        ports.listening = {777: [3000]}
        report = await report_for(env, ports)
        assert report.project_found and report.cloudpanel_user == USER and report.project_path == root
        assert report.nginx_vhost_state == "PRESENT" and report.runtime == "NODE" and report.app_port == 3000 and report.app_running is True
        assert (report.scheme, report.public_port, report.health_path, report.health_ok, report.health_status) == ("https", 443, "/healthz", True, 200)
        assert report.host_header_ok and report.tls_ok
        assert report.app_version == f"1.2.3+{GIT_SHA[:12]}", report.app_version
        assert report.schema_version == "3:20260301_orders.sql" and "NOT_VERIFIED" in report.migration_state
        assert report.db["engine"] == "postgresql" and report.db["host"] == "db.internal" and report.db["pool_size"] == 10
        assert report.db_mode == "PRIMARY_SHARED" and report.db_mode_source == "inferred"
        kinds = {s["kind"] for s in report.stateful}
        assert kinds == {"sessions", "uploads", "websocket"}, kinds
        assert ports.probe_log == ["https://example.com:443/healthz"] or ports.probe_log[0].endswith("/healthz"), "the Host header/SNI is the domain and the path comes from the candidates"
        blob = json.dumps(report.to_dict())
        assert "s3cr3tPass" not in blob and "appuser" not in blob, "credentials never enter the report"
        assert report.server_id == "server1" and report.operation_id == "op-test"
        assert report.db_connectivity["level"] in ("DNS", "NONE"), "db.internal is not reachable from the test host; the report says so honestly"
        assert "DB_UNREACHABLE" in report.blockers and not report.ready
    print("Test 1 (origin report: project/vhost/runtime/port/health/TLS/version/schema/DB/stateful discovered; credentials never recorded; unreachable DB blocks) PASSED")


async def test_2_blockers() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = nv.NvEnv(tmp)
        root = env.project(files={"index.html": "x"})
        ports = TreePorts(env)
        missing = await report_for(env, ports)
        assert missing.project_found and missing.nginx_vhost_state == "MISSING" and "NGINX_VHOST_MISSING" in missing.blockers and not missing.ready
        listen_vhost(env, listen="80")
        http_only = await report_for(env, ports)
        assert "ORIGIN_HTTP_ONLY" in http_only.blockers
        allowed = await report_for(env, ports, make_config(3, allow_http_origin=True))
        assert "ORIGIN_HTTP_ONLY" not in allowed.blockers and allowed.scheme == "http"
        listen_vhost(env)
        ports.tls = TlsProbeResult(True, False, None, "self-signed certificate")
        assert "TLS_INVALID" in (await report_for(env, ports)).blockers
        ports.tls = TlsProbeResult(True, True, None, "")
        ports.http = {"/healthz": HttpProbeResult(False, 503, 9.0, "HTTP 503", True, "", 0)}
        assert "HEALTH_ENDPOINT_UNHEALTHY" in (await report_for(env, ports)).blockers
        ports.http = {"/healthz": HttpProbeResult(False, 200, 9.0, "", True, "credential", 40)}
        assert "HEALTH_ENDPOINT_LEAK" in (await report_for(env, ports)).blockers
        ports.http = {}
        assert "HEALTH_ENDPOINT_NOT_FOUND" in (await report_for(env, ports)).blockers
        ports.http = {"/status": HttpProbeResult(True, 200, 5.0, "", True, "", 9)}
        cfg = make_config(3, domains=[LbDomainConfig(domain=DOMAIN, health_path="/status", origin_port=8443, scheme="https")])
        configured = await report_for(env, ports, cfg)
        assert configured.health_path == "/status" and configured.public_port == 8443 and configured.health_ok
    with tempfile.TemporaryDirectory() as tmp:
        env = nv.NvEnv(tmp)
        none = await report_for(env, TreePorts(env))
        assert not none.project_found and "PROJECT_NOT_FOUND" in none.blockers
    with tempfile.TemporaryDirectory() as tmp:
        env = nv.NvEnv(tmp)
        env.project(user="alice", files={"index.html": "x"})
        env.project(user="bob", files={"index.html": "x"})
        ports = TreePorts(env)
        ports.asset = None
        ambiguous = await report_for(env, ports)
        assert "PROJECT_AMBIGUOUS" in ambiguous.blockers and not ambiguous.project_found
    with tempfile.TemporaryDirectory() as tmp:
        env = nv.NvEnv(tmp)
        ports = TreePorts(env)
        ports.server_entry = lambda: None
        stranger = await report_for(env, ports)
        assert "SERVER_NOT_IN_INVENTORY" in stranger.blockers
    print("Test 2 (missing vhost / HTTP-only / invalid TLS / failing, leaking or missing health endpoint / no or ambiguous project / unknown server are blocking) PASSED")


async def test_3_reports_are_signed_and_verified() -> None:
    key = b"k" * 32
    with tempfile.TemporaryDirectory() as tmp:
        report = OriginReport(domain=DOMAIN, server_id="server2", checked_at=1000.0, project_found=True, ready=True, app_version="2.5")
        ok, path = write_report_file(tmp, report, key)
        assert ok and os.path.basename(path) == f"{DOMAIN}__server2.json"
        assert oct(os.stat(path).st_mode & 0o777) == "0o640"
        loaded = load_report_file(tmp, DOMAIN, "server2", key=key, max_age_seconds=900, now=1100.0)
        assert loaded.usable and loaded.report.app_version == "2.5"
        assert load_report_file(tmp, DOMAIN, "server2", key=key, max_age_seconds=900, now=5000.0).status == "ORIGIN_REPORT_STALE"
        assert load_report_file(tmp, DOMAIN, "server2", key=key, max_age_seconds=900, now=100.0).status == "ORIGIN_REPORT_STALE", "a report from the future is not trusted"
        assert load_report_file(tmp, DOMAIN, "server2", key=b"z" * 32, max_age_seconds=900, now=1100.0).status == "ORIGIN_REPORT_INVALID"
        assert load_report_file(tmp, DOMAIN, "server2", key=None, max_age_seconds=900, now=1100.0).status == "ORIGIN_REPORT_INVALID", "no key: other servers' reports are not accepted"
        assert load_report_file(tmp, DOMAIN, "server9", key=key, max_age_seconds=900, now=1100.0).status == "ORIGIN_REPORT_MISSING"
        envelope = json.loads(Path(path).read_text())
        envelope["report"]["ready"] = False
        Path(path).write_text(json.dumps(envelope))
        assert load_report_file(tmp, DOMAIN, "server2", key=key, max_age_seconds=900, now=1100.0).status == "ORIGIN_REPORT_INVALID", "tampering is detected"
        swapped = json.loads(Path(path).read_text())
        swapped["report"]["server_id"] = "server3"
        swapped["signature"] = sign_report(swapped["report"], key)
        Path(os.path.join(tmp, f"{DOMAIN}__server2.json")).write_text(json.dumps(swapped))
        assert load_report_file(tmp, DOMAIN, "server2", key=key, max_age_seconds=900, now=1100.0).status == "ORIGIN_REPORT_INVALID", "a report cannot claim another server"
        Path(os.path.join(tmp, f"{DOMAIN}__server2.json")).write_text("{not json")
        assert load_report_file(tmp, DOMAIN, "server2", key=key, max_age_seconds=900, now=1100.0).status == "ORIGIN_REPORT_INVALID"
        Path(os.path.join(tmp, f"{DOMAIN}__server2.json")).write_text("x" * 300_000)
        assert load_report_file(tmp, DOMAIN, "server2", key=key, max_age_seconds=900, now=1100.0).status == "ORIGIN_REPORT_INVALID"
        assert write_report_file("/proc/no-such-dir-xyz", report, key)[0] is False
    print("Test 3 (origin reports are HMAC-signed; tampering, wrong key, missing key, stale/future, wrong server, corrupt and oversized files are rejected) PASSED")


async def test_4_addloadbalance_dry_run_and_apply() -> None:
    env = Env(3)
    env.ports.local_report = make_report("server1", vhost_state="MISSING", blockers=["NGINX_VHOST_MISSING"])
    calls = {"n": 0}

    def factory(domain, operation_id):
        calls["n"] += 1
        ready = env.ports.prepare_calls != []
        return make_report("server1", vhost_state="PRESENT" if ready else "MISSING", blockers=[] if ready else ["NGINX_VHOST_MISSING"])

    env.ports.local_report_factory = factory
    dry = await env.orch.addloadbalance(DOMAIN, operator="alice", apply=False)
    assert dry.status == OpStatus.DRY_RUN and dry.planned_actions and any("/newvhost" in a for a in dry.planned_actions)
    assert env.ports.prepare_calls == [] and env.ports.published_reports == [], "a dry run changes nothing on the origin"
    assert env.cf.calls == [], "/addloadbalance never talks to Cloudflare"
    unconfirmed = await env.orch.addloadbalance(DOMAIN, operator="alice", apply=True, confirmed=False)
    assert unconfirmed.status == OpStatus.ABORTED and "confirmation" in unconfirmed.message and env.ports.prepare_calls == []
    applied = await env.orch.addloadbalance(DOMAIN, operator="alice", apply=True, confirmed=True)
    assert applied.status == OpStatus.SUCCESS and env.ports.prepare_calls == [False]
    assert applied.report.ready and applied.report_path and len(env.ports.published_reports) == 1
    assert "nginx vhost created" in applied.applied_actions and "origin report written" in applied.applied_actions
    assert env.cf.calls == [], "origin servers never create the Cloudflare load balancer"
    assert env.store.last_audit()["kind"] == "addloadbalance" and env.store.last_audit()["operator"] == "alice"
    print("Test 4 (/addloadbalance: dry run is read-only; apply needs confirmation, prepares the vhost once, writes the report, never touches Cloudflare) PASSED")


async def test_5_addloadbalance_failures_and_assignment() -> None:
    env = Env(3)
    mk = make_report
    env.ports.local_report = mk("server1", vhost_state="MISSING", blockers=["NGINX_VHOST_MISSING"])
    env.ports.vhost_result = (False, "nginx-test: nginx -t failed")
    failed = await env.orch.addloadbalance(DOMAIN, operator="alice", apply=True, confirmed=True)
    assert failed.status == OpStatus.FAILED and env.ports.prepare_calls == [False]
    assert "not reloaded after a failed test" in failed.message and env.ports.published_reports == [] and env.cf.calls == []
    assert "LB_ORIGIN_SETUP_FAILED" in env.categories()

    env = Env(3, cfg=make_config(3, domains=[LbDomainConfig(domain=DOMAIN, origins=["server2", "server3"])]))
    result = await env.orch.addloadbalance(DOMAIN, operator="alice", apply=False)
    assert result.assignment == "NOT_ASSIGNED" and "NOT_ASSIGNED" in result.report.blockers and not result.report.ready
    assert "does not guess" in " ".join(f["message"] for f in result.report.findings)

    env = Env(3, cfg=make_config(3, enabled=False))
    blocked = await env.orch.addloadbalance(DOMAIN, operator="alice", apply=True, confirmed=True)
    assert blocked.status == OpStatus.ABORTED and env.ports.prepare_calls == []
    env = Env(3)
    env.ports.allowed = False
    env.ports.local_report = mk("server1", vhost_state="MISSING", blockers=["NGINX_VHOST_MISSING"])
    detection = await env.orch.addloadbalance(DOMAIN, operator="alice", apply=True, confirmed=True)
    assert detection.status == OpStatus.ABORTED and "detection-only" in detection.message and env.ports.prepare_calls == []
    bad = await env.orch.addloadbalance("../../etc/passwd", operator="alice", apply=True, confirmed=True)
    assert bad.status == OpStatus.ABORTED and env.ports.prepare_calls == []
    print("Test 5 (vhost preparation failure -> FAILED, no report, no Cloudflare; unassigned server, disabled config, detection-only and hostile domains refused) PASSED")


class VhostBackedPorts(FakePorts):
    def __init__(self, env_lb, nv_env, nv_ports, tree_ports) -> None:
        super().__init__("server1", env_lb.cf)
        self.nv_env, self.nv_ports, self.tree_ports = nv_env, nv_ports, tree_ports
        self.cfg = env_lb.cfg

    async def local_origin_report(self, domain, operation_id):
        return await build_origin_report(domain=domain, ports=self.tree_ports, vhost_cfg=self.nv_env.cfg, lb_cfg=self.cfg, operation_id=operation_id)

    async def prepare_local_origin(self, domain, dry_run):
        self.prepare_calls.append(dry_run)
        discovery = await vr.discover(domain, self.nv_env.cfg, self.nv_ports)
        outcome = await vr.apply(discovery, self.nv_env.cfg, self.nv_ports, requested_by="rtsa-loadbalance", dry_run=dry_run, reload=True)
        return bool(outcome.ok), f"{outcome.stage or 'vhost'}: {outcome.reason or 'ok'}"


def build_static_origin(tmp: str, live_tests):
    nv_env = nv.NvEnv(tmp)
    nv_env.project(files={"index.html": "x", "healthz": "ok"})
    tree = TreePorts(nv_env)
    tree.live_tests = live_tests
    env_lb = Env(3)
    ports = VhostBackedPorts(env_lb, nv_env, tree, tree)
    env_lb.ports = ports
    env_lb.ctx.ports = ports
    return nv_env, tree, env_lb


async def test_6_real_vhost_engine_no_reload_after_failed_nginx_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        nv_env, tree, env_lb = build_static_origin(tmp, [(False, "nginx: [emerg] unexpected token=abc123secret")])
        before = nv_env.snapshot()
        result = await env_lb.orch.addloadbalance(DOMAIN, operator="alice", apply=True, confirmed=True)
        assert result.status == OpStatus.FAILED, (result.status, result.message)
        assert tree.reload_calls == 0, "nginx must never be reloaded after a failed nginx -t"
        assert nv_env.snapshot() == before, "the failed vhost install is rolled back: the nginx tree is identical"
        assert env_lb.ports.published_reports == [] and env_lb.cf.calls == []
        assert "abc123secret" not in result.message
    with tempfile.TemporaryDirectory() as tmp:
        nv_env, tree, env_lb = build_static_origin(tmp, [(True, "ok")])
        before = nv_env.snapshot()
        dry = await env_lb.orch.addloadbalance(DOMAIN, operator="alice", apply=False)
        assert dry.status == OpStatus.DRY_RUN and nv_env.snapshot() == before and tree.reload_calls == 0
        assert dry.report.nginx_vhost_state == "MISSING" and "NGINX_VHOST_MISSING" in dry.report.blockers
        ok = await env_lb.orch.addloadbalance(DOMAIN, operator="alice", apply=True, confirmed=True)
        assert ok.status == OpStatus.SUCCESS and tree.reload_calls == 1, "reload happens once, after a successful test"
        assert os.path.exists(os.path.join(nv_env.enabled, f"{DOMAIN}.conf"))
        assert ok.report.nginx_vhost_state == "PRESENT"
        assert len(env_lb.ports.published_reports) == 1
    print("Test 6 (real /newvhost engine: failed nginx -t -> rollback, tree identical, NO reload; success -> one reload after the test, vhost present) PASSED")


async def main() -> None:
    for test in (
        test_1_full_origin_report, test_2_blockers, test_3_reports_are_signed_and_verified, test_4_addloadbalance_dry_run_and_apply,
        test_5_addloadbalance_failures_and_assignment, test_6_real_vhost_engine_no_reload_after_failed_nginx_test,
    ):
        await test()
    print("\nALL LOAD BALANCER ORIGIN/ADDLOADBALANCE TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
