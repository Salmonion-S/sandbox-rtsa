from __future__ import annotations

import asyncio
import copy
import json
import os
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.manager import (
    LbDomainConfig, LbSafetyConfig, LbServerConfig, LbVerifyConfig, LoadBalancingConfig,
)
from core.lb_context import LbContext
from core.lb_model import HttpProbeResult, ProbeResult, TlsProbeResult
from core.lb_orchestrator import LoadBalancerOrchestrator
from core.lb_origin import OriginReport, ReportLoad
from core.lb_ports import LbPorts
from core.lb_state import LbStateStore
from core.lb_status import LoadBalancerMonitor
from core.pipeline_metrics import PipelineMetrics, LB_COUNTERS, LB_GAUGES, LB_LATENCIES
from discord_integration.cloudflare import CfResult

DOMAIN = "example.com"
ZONE_ID = "zone-1"
ACCOUNT_ID = "acct-1"


class SimulatedCrash(BaseException):
    pass


def ok(data: Any) -> CfResult:
    return CfResult(True, 200, json.loads(json.dumps(data)), "", 0.001)


def fail(message: str, status: int = 500) -> CfResult:
    return CfResult(False, status, None, message, 0.001)


class FakeCloudflare:
    def __init__(self) -> None:
        self.zones = {DOMAIN: {"id": ZONE_ID, "name": DOMAIN}}
        self.dns: List[Dict[str, Any]] = []
        self.monitors: Dict[str, Dict[str, Any]] = {}
        self.pools: Dict[str, Dict[str, Any]] = {}
        self.lbs: Dict[str, Dict[str, Any]] = {}
        self.calls: List[Tuple[str, tuple]] = []
        self.fail_methods: Dict[str, str] = {}
        self.fail_after: Dict[str, int] = {}
        self.crash_after: Dict[str, int] = {}
        self.unhealthy_addresses: set = set()
        self.unreachable_health = False
        self._counter = 0
        self.call_counts: Dict[str, int] = {}
        self.history: List[Tuple[str, Dict[str, Any]]] = []

    def _record(self, method: str, body: Dict[str, Any]) -> None:
        self.history.append((method, copy.deepcopy(body)))

    def enabled_addresses_ever(self) -> set:
        seen = set()
        for method, body in self.history:
            if method in ("create_lb_pool", "update_lb_pool"):
                for origin in body.get("origins", []):
                    if origin.get("enabled"):
                        seen.add(origin["address"])
        return seen

    def _id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter}"

    def _gate(self, method: str) -> Optional[CfResult]:
        self.calls.append((method, ()))
        self.call_counts[method] = self.call_counts.get(method, 0) + 1
        if method in self.crash_after and self.call_counts[method] > self.crash_after[method]:
            raise SimulatedCrash(method)
        if method in self.fail_methods:
            return fail(self.fail_methods[method])
        if method in self.fail_after and self.call_counts[method] > self.fail_after[method]:
            return fail(f"injected failure in {method}")
        return None

    def count(self, prefix: str) -> int:
        return sum(1 for m, _ in self.calls if m.startswith(prefix))

    def mutations(self) -> List[str]:
        return [m for m, _ in self.calls if m.split("_")[0] in ("create", "update", "delete")]

    async def resolve_single_zone_for_domain(self, domain: str) -> Optional[Dict[str, str]]:
        self.calls.append(("resolve_single_zone_for_domain", ()))
        for name, zone in self.zones.items():
            if domain == name or domain.endswith("." + name):
                return dict(zone)
        return None

    async def get_zone_details(self, zone_id: str) -> CfResult:
        gate = self._gate("get_zone_details")
        return gate or ok({"id": zone_id, "account": {"id": ACCOUNT_ID}})

    async def list_dns_records_named(self, zone_id: str, name: str) -> CfResult:
        gate = self._gate("list_dns_records_named")
        return gate or ok([r for r in self.dns if r["name"] == name])

    async def list_lb_monitors(self, account_id: str) -> CfResult:
        gate = self._gate("list_lb_monitors")
        return gate or ok(list(self.monitors.values()))

    async def get_lb_monitor(self, account_id: str, monitor_id: str) -> CfResult:
        gate = self._gate("get_lb_monitor")
        if gate:
            return gate
        return ok(self.monitors[monitor_id]) if monitor_id in self.monitors else fail("not found", 404)

    async def create_lb_monitor(self, account_id: str, body: Dict[str, Any]) -> CfResult:
        gate = self._gate("create_lb_monitor")
        self._record("create_lb_monitor", body)
        if gate:
            return gate
        item = {**copy.deepcopy(body), "id": self._id("mon")}
        self.monitors[item["id"]] = item
        return ok(item)

    async def update_lb_monitor(self, account_id: str, monitor_id: str, body: Dict[str, Any]) -> CfResult:
        gate = self._gate("update_lb_monitor")
        self._record("update_lb_monitor", body)
        if gate:
            return gate
        if monitor_id not in self.monitors:
            return fail("not found", 404)
        self.monitors[monitor_id].update(copy.deepcopy(body))
        return ok(self.monitors[monitor_id])

    async def delete_lb_monitor(self, account_id: str, monitor_id: str) -> CfResult:
        gate = self._gate("delete_lb_monitor")
        if gate:
            return gate
        if monitor_id not in self.monitors:
            return fail("not found", 404)
        if any(p.get("monitor") == monitor_id for p in self.pools.values()):
            return fail("monitor is in use")
        del self.monitors[monitor_id]
        return ok({"id": monitor_id})

    async def list_lb_pools(self, account_id: str) -> CfResult:
        gate = self._gate("list_lb_pools")
        return gate or ok(list(self.pools.values()))

    async def get_lb_pool(self, account_id: str, pool_id: str) -> CfResult:
        gate = self._gate("get_lb_pool")
        if gate:
            return gate
        return ok(self.pools[pool_id]) if pool_id in self.pools else fail("not found", 404)

    async def create_lb_pool(self, account_id: str, body: Dict[str, Any]) -> CfResult:
        gate = self._gate("create_lb_pool")
        self._record("create_lb_pool", body)
        if gate:
            return gate
        if any(p["name"] == body["name"] for p in self.pools.values()):
            return fail("pool name already exists")
        item = {**copy.deepcopy(body), "id": self._id("pool")}
        self.pools[item["id"]] = item
        return ok(item)

    async def update_lb_pool(self, account_id: str, pool_id: str, body: Dict[str, Any]) -> CfResult:
        gate = self._gate("update_lb_pool")
        self._record("update_lb_pool", body)
        if gate:
            return gate
        if pool_id not in self.pools:
            return fail("not found", 404)
        self.pools[pool_id].update(copy.deepcopy(body))
        return ok(self.pools[pool_id])

    async def delete_lb_pool(self, account_id: str, pool_id: str) -> CfResult:
        gate = self._gate("delete_lb_pool")
        if gate:
            return gate
        if pool_id not in self.pools:
            return fail("not found", 404)
        if any(pool_id in lb.get("default_pools", []) for lb in self.lbs.values()):
            return fail("pool is referenced by a load balancer")
        del self.pools[pool_id]
        return ok({"id": pool_id})

    async def get_lb_pool_health(self, account_id: str, pool_id: str) -> CfResult:
        gate = self._gate("get_lb_pool_health")
        if gate:
            return gate
        if self.unreachable_health:
            return fail("health unavailable")
        pool = self.pools.get(pool_id)
        if pool is None:
            return fail("not found", 404)
        pops: Dict[str, Any] = {}
        for pop in ("LAX", "AMS", "SIN"):
            entries = []
            for origin in pool.get("origins", []):
                if not origin.get("enabled"):
                    continue
                healthy = origin["address"] not in self.unhealthy_addresses
                entries.append({origin["name"]: {
                    "healthy": healthy, "rtt": "42.5ms" if healthy else "", "response_code": 200 if healthy else 502,
                    "failure_reason": "No failures" if healthy else "UPSTREAM_TIMEOUT",
                }})
            pops[pop] = {"healthy": True, "origins": entries}
        return ok({"pool_id": pool_id, "pop_health": pops})

    async def list_load_balancers(self, zone_id: str) -> CfResult:
        gate = self._gate("list_load_balancers")
        return gate or ok(list(self.lbs.values()))

    async def get_load_balancer(self, zone_id: str, lb_id: str) -> CfResult:
        gate = self._gate("get_load_balancer")
        if gate:
            return gate
        return ok(self.lbs[lb_id]) if lb_id in self.lbs else fail("not found", 404)

    async def create_load_balancer(self, zone_id: str, body: Dict[str, Any]) -> CfResult:
        gate = self._gate("create_load_balancer")
        self._record("create_load_balancer", body)
        if gate:
            return gate
        if any(r["name"] == body["name"] for r in self.dns):
            return fail("a DNS record with that name already exists")
        item = {**copy.deepcopy(body), "id": self._id("lb")}
        self.lbs[item["id"]] = item
        return ok(item)

    async def update_load_balancer(self, zone_id: str, lb_id: str, body: Dict[str, Any]) -> CfResult:
        gate = self._gate("update_load_balancer")
        self._record("update_load_balancer", body)
        if gate:
            return gate
        if lb_id not in self.lbs:
            return fail("not found", 404)
        self.lbs[lb_id].update(copy.deepcopy(body))
        return ok(self.lbs[lb_id])

    async def delete_load_balancer(self, zone_id: str, lb_id: str) -> CfResult:
        gate = self._gate("delete_load_balancer")
        if gate:
            return gate
        if lb_id not in self.lbs:
            return fail("not found", 404)
        del self.lbs[lb_id]
        return ok({"id": lb_id})


class FakePorts(LbPorts):
    def __init__(self, server_id: str = "server1", cloudflare: Optional[FakeCloudflare] = None) -> None:
        self._server_id = server_id
        self.cloudflare = cloudflare
        self.down: set = set()
        self.http_status: Dict[str, int] = {}
        self.http_leak: Dict[str, str] = {}
        self.tls_untrusted: set = set()
        self.reports: Dict[str, ReportLoad] = {}
        self.local_report: Optional[OriginReport] = None
        self.local_report_factory = None
        self.vhost_result: Tuple[bool, str] = (True, "vhost created")
        self.prepare_calls: List[bool] = []
        self.dns_answers: List[str] = ["104.16.0.1"]
        self.public_ok = True
        self.public_calls = 0
        self.tcp_calls = 0
        self.http_calls = 0
        self.events: List[Any] = []
        self.audits: List[Dict[str, Any]] = []
        self.published_reports: List[OriginReport] = []
        self.sleeps: List[float] = []
        self.traffic: Optional[Dict[str, int]] = None
        self.allowed = True
        self.clock = 1_700_000_000.0
        self.mono = 1000.0
        self.report_publish_ok = True

    def local_server_id(self) -> str:
        return self._server_id

    def local_server_name(self) -> str:
        return self._server_id.title()

    async def tcp_probe(self, address: str, port: int, timeout: float) -> ProbeResult:
        self.tcp_calls += 1
        if address in self.down:
            return ProbeResult(False, None, "connection refused")
        return ProbeResult(True, 3.0, "")

    async def tls_probe(self, address: str, port: int, domain: str, timeout: float) -> TlsProbeResult:
        if address in self.tls_untrusted:
            return TlsProbeResult(True, False, None, "self-signed certificate")
        return TlsProbeResult(True, True, self.clock + 86400 * 60, "")

    async def http_probe(self, address, port, scheme, host_header, path, timeout, verify_tls) -> HttpProbeResult:
        self.http_calls += 1
        if address in self.down:
            return HttpProbeResult(False, None, None, "connection refused")
        status = self.http_status.get(address, 200)
        return HttpProbeResult(200 <= status < 300 and not self.http_leak.get(address), status, 12.0, "" if status < 400 else f"HTTP {status}", True, self.http_leak.get(address, ""), 20)

    async def public_probe(self, domain: str, path: str, timeout: float) -> HttpProbeResult:
        self.public_calls += 1
        if self.public_ok:
            return HttpProbeResult(True, 200, 30.0, "", True, "", 20)
        return HttpProbeResult(False, 522, 5000.0, "origin timeout", True, "", 0)

    async def resolve_dns(self, domain: str, timeout: float) -> List[str]:
        return list(self.dns_answers)

    async def local_origin_report(self, domain: str, operation_id: str) -> OriginReport:
        if self.local_report_factory is not None:
            return self.local_report_factory(domain, operation_id)
        if self.local_report is not None:
            return self.local_report
        return make_report(self._server_id)

    async def load_origin_report(self, domain: str, server_id: str) -> ReportLoad:
        return self.reports.get(server_id) or ReportLoad("ORIGIN_REPORT_MISSING", detail=f"no report file for {server_id}")

    def publish_origin_report(self, report: OriginReport) -> Tuple[bool, str]:
        if not self.report_publish_ok:
            return False, "could not write report"
        self.published_reports.append(report)
        return True, f"/reports/{report.domain}__{report.server_id}.json"

    async def prepare_local_origin(self, domain: str, dry_run: bool) -> Tuple[bool, str]:
        self.prepare_calls.append(dry_run)
        return self.vhost_result

    async def observed_traffic(self, domain: str) -> Optional[Dict[str, int]]:
        return self.traffic

    def mutations_allowed(self) -> bool:
        return self.allowed

    def publish(self, event: Any) -> None:
        self.events.append(event)

    def audit(self, record: Dict[str, Any]) -> None:
        self.audits.append(record)

    def now(self) -> float:
        return self.clock

    def monotonic(self) -> float:
        return self.mono

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.mono += seconds
        self.clock += seconds
        await asyncio.sleep(0)


def make_report(
    server_id: str, *, domain: str = DOMAIN, app_version: str = "2.5.0+abc123456789", schema_version: str = "42:2026_09_01_add_users",
    db_mode: str = "PRIMARY_SHARED", db_host: str = "db.internal", db_level: str = "PROTOCOL", scheme: str = "https", port: int = 443,
    health_path: str = "/healthz", blockers: Optional[List[str]] = None, stateful: Optional[List[Dict[str, Any]]] = None,
    checked_at: float = 1_700_000_000.0, pool_size: int = 0, vhost_state: str = "PRESENT", findings: Optional[List[Dict[str, Any]]] = None,
) -> OriginReport:
    facts = {
        "engine": "postgresql", "host": db_host, "port": 5432, "name": "app", "user_present": True, "password_present": True,
        "tls_required": None, "pool_size": pool_size, "read_replica_configured": False, "locality": "PRIVATE", "source": "DATABASE_URL",
        "target_fingerprint": "fp-" + db_host,
    }
    report = OriginReport(
        domain=domain, server_id=server_id, server_name=server_id.title(), hostname=f"{server_id}.internal", public_ip="", private_ip="",
        role="origin", checked_at=checked_at, project_found=True, project_path=f"/home/{server_id}user/htdocs/{domain}", cloudpanel_user=f"{server_id}user",
        nginx_vhost_state=vhost_state, runtime="NODE", app_port=3000, public_port=port, scheme=scheme, health_path=health_path, health_ok=True,
        health_status=200, health_latency_ms=10.0, app_running=True, host_header_ok=True, tls_ok=True, app_version=app_version,
        schema_version=schema_version, migration_state="code head", db=facts, db_mode=db_mode, db_mode_source="declared", db_mode_reason="declared",
        db_connectivity={"origin_id": server_id, "level": db_level, "dns_ok": True, "tcp_ok": True, "protocol_ok": True, "latency_ms": 2.0, "reason": "ok", "checked_at": checked_at},
        stateful=stateful or [], findings=findings or [], blockers=blockers or [], ready=not blockers,
    )
    if blockers and not findings:
        report.findings = [{"code": code, "severity": "CRITICAL", "message": f"{code} on {server_id}", "origin_id": server_id, "blocking": True} for code in blockers]
    return report


def make_config(
    n: int = 3, *, orchestrator: str = "server1", enabled: bool = True, domains: Optional[List[LbDomainConfig]] = None,
    min_healthy: int = 1, drain_wait: float = 5.0, allow_http_origin: bool = False, allow_insecure_tls: bool = False,
    require_origin_report: bool = True, **overrides: Any,
) -> LoadBalancingConfig:
    servers = [
        LbServerConfig(server_id=f"server{i}", name=f"Server{i}", public_ip=f"203.0.113.{10 + i}", private_ip=f"10.0.0.{10 + i}", role="both" if i == 1 else "origin")
        for i in range(1, n + 1)
    ]
    return LoadBalancingConfig(
        enabled=enabled, orchestrator_server_id=orchestrator, servers=servers, domains=domains or [], max_origins=16,
        safety=LbSafetyConfig(
            minimum_healthy_origins=min_healthy, drain_wait_seconds=drain_wait, allow_http_origin=allow_http_origin,
            allow_insecure_tls=allow_insecure_tls, require_origin_report=require_origin_report,
        ),
        verify=LbVerifyConfig(pool_health_timeout_seconds=30.0, pool_health_poll_seconds=5.0, data_plane_retries=2, data_plane_spacing_seconds=1.0, probe_timeout_seconds=2.0),
        status_cache_ttl_seconds=30.0, **overrides,
    )


def origin_ips(n: int) -> str:
    return " ".join(f"203.0.113.{10 + i}" for i in range(1, n + 1))


def fresh_metrics() -> PipelineMetrics:
    return PipelineMetrics(LB_COUNTERS, LB_GAUGES, LB_LATENCIES)


class Env:
    def __init__(self, n: int = 3, *, server_id: str = "server1", cfg: Optional[LoadBalancingConfig] = None, state_dir: Optional[str] = None,
                 with_reports: bool = True, cloudflare: Optional[FakeCloudflare] = "auto", metrics: Optional[PipelineMetrics] = None,
                 **cfg_overrides: Any) -> None:
        self.dir = state_dir or tempfile.mkdtemp(prefix="rtsa-lb-test-")
        self.n = n
        self.cf = FakeCloudflare() if cloudflare == "auto" else cloudflare
        self.ports = FakePorts(server_id, self.cf)
        self.cfg = cfg or make_config(n, **cfg_overrides)
        self.metrics = metrics or fresh_metrics()
        self.store = LbStateStore(os.path.join(self.dir, "lb_state.json"), clock=self.ports.now)
        self.ctx = LbContext(self.cfg, self.store, self.ports, metrics=self.metrics)
        self.monitor = LoadBalancerMonitor(self.ctx)
        self.orch = LoadBalancerOrchestrator(self.ctx, self.monitor)
        if with_reports:
            for i in range(1, n + 1):
                sid = f"server{i}"
                if sid != server_id:
                    self.ports.reports[sid] = ReportLoad("OK", make_report(sid))

    def rebuild(self) -> "Env":
        clone = Env.__new__(Env)
        clone.dir, clone.n, clone.cf, clone.ports, clone.cfg = self.dir, self.n, self.cf, self.ports, self.cfg
        clone.metrics = fresh_metrics()
        clone.store = LbStateStore(os.path.join(self.dir, "lb_state.json"), clock=self.ports.now)
        clone.ctx = LbContext(self.cfg, clone.store, self.ports, metrics=clone.metrics)
        clone.monitor = LoadBalancerMonitor(clone.ctx)
        clone.orch = LoadBalancerOrchestrator(clone.ctx, clone.monitor)
        return clone

    def categories(self) -> List[str]:
        return [e.category.value for e in self.ports.events]
