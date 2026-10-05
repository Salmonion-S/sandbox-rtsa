import os
import sys
from dataclasses import replace
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import (
    BgpAttestationConfig, BgpConvergenceConfig, BgpDrainConfig, BgpEcmpConfig, BgpHealthConfig, BgpNodeConfig,
    BgpPeerConfig, BgpServiceConfig, BgpSpeakerConfig,
)
from core.lb_alerts import LbAlertLifecycle
from core.lb_bgp_controller import BgpPorts, NodeController
from core.lb_bgp_model import EcmpObservation, HealthLayer, LayerResult, PeerState, Provenance
from core.lb_bgp_speaker import BgpSpeaker, PeerSnapshot, RouterObserver, SpeakerCapability, SpeakerResult
from core.lb_bgp_state import BgpStateStore
from core.pipeline_metrics import PipelineMetrics, LB_COUNTERS, LB_GAUGES, LB_LATENCIES

DOMAIN = "example.com"
VIP = "203.0.113.10"
PREFIX = "203.0.113.10/32"
PEER_ADDRESS = "10.0.0.1"


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.t = start

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class FakeRouter:
    def __init__(self, clock: FakeClock, hold_seconds: float = 9.0, bfd_seconds: Optional[float] = None) -> None:
        self.clock = clock
        self.hold = hold_seconds
        self.bfd = bfd_seconds
        self.routes: Dict[str, Dict[str, Any]] = {}

    def register(self, node: str) -> None:
        self.routes.setdefault(node, {"advertised": False, "alive": True, "died_at": None, "session": True})

    def set_advertised(self, node: str, value: bool) -> None:
        self.routes[node]["advertised"] = value

    def kill(self, node: str) -> None:
        self.routes[node]["alive"] = False
        self.routes[node]["died_at"] = self.clock.t

    def revive(self, node: str) -> None:
        self.routes[node]["alive"] = True
        self.routes[node]["died_at"] = None

    def paths(self) -> List[str]:
        out = []
        detection = self.bfd if self.bfd is not None else self.hold
        for node, state in self.routes.items():
            if not state["advertised"] or not state["session"]:
                continue
            if not state["alive"] and self.clock.t - state["died_at"] >= detection:
                continue
            out.append(node)
        return sorted(out)

    def distribute(self, flows: int) -> Dict[str, int]:
        paths = self.paths()
        counts = {node: 0 for node in paths}
        if not paths:
            return counts
        for flow in range(flows):
            counts[paths[(flow * 2654435761 >> 7) % len(paths)]] += 1
        return counts


class FakeSpeaker(BgpSpeaker):
    def __init__(self, clock: FakeClock, router: FakeRouter, node: str, *, peer_asn: int = 65000) -> None:
        self.clock = clock
        self.router = router
        self.node = node
        self.session_up = True
        self.originate = False
        self.visible_after: Optional[float] = None
        self.visibility_delay = 0.0
        self.announce_calls = 0
        self.withdraw_calls = 0
        self.fail_announce = False
        self.fail_withdraw = False
        self.available = True
        self.unreachable = False
        self.local_asn: Optional[int] = 65001
        self.unexpected: List[str] = []
        self.queries = 0
        router.register(node)

    def _visible(self) -> bool:
        return self.visible_after is None or self.clock.t >= self.visible_after

    async def capability(self) -> SpeakerCapability:
        return SpeakerCapability(self.available, self.available, "FRRouting fake", self.local_asn if self.available else None,
                                 "" if self.available else "vtysh binary not found")

    async def peers(self, *, force: bool = False) -> PeerSnapshot:
        self.queries += 1
        if self.unreachable:
            return PeerSnapshot({}, [], None, None, False, "bgpd is not running", self.clock.t)
        state = "Established" if self.session_up else "Active"
        peer = PeerState("rtr", PEER_ADDRESS, state)
        return PeerSnapshot({"rtr": peer}, list(self.unexpected), self.local_asn, "1.1.1.1", True, "", self.clock.t)

    async def originated(self, prefix: str) -> Optional[bool]:
        self.queries += 1
        if self.unreachable:
            return None
        if self.originate:
            return True
        if self.visible_after is not None and not self._visible():
            return True
        return False

    async def advertised_peers(self, prefix: str) -> Optional[List[str]]:
        self.queries += 1
        if self.unreachable:
            return None
        if not self.session_up:
            return []
        if self.originate:
            return [PEER_ADDRESS]
        if self.visible_after is not None and not self._visible():
            return [PEER_ADDRESS]
        return []

    async def announce(self, prefix: str) -> SpeakerResult:
        self.announce_calls += 1
        if self.fail_announce:
            return SpeakerResult(False, False, "vtysh failed")
        self.originate = True
        self.visible_after = None
        self.router.set_advertised(self.node, True)
        return SpeakerResult(True, True, "applied", ["network " + prefix])

    async def withdraw(self, prefix: str) -> SpeakerResult:
        self.withdraw_calls += 1
        if self.fail_withdraw:
            return SpeakerResult(False, False, "vtysh failed")
        self.originate = False
        self.visible_after = self.clock.t + self.visibility_delay if self.visibility_delay else None
        self.router.set_advertised(self.node, False)
        return SpeakerResult(True, True, "applied", ["no network " + prefix])


class FakeObserver(RouterObserver):
    def __init__(self, router: FakeRouter) -> None:
        self.router = router

    async def observe(self, prefix: str) -> EcmpObservation:
        paths = self.router.paths()
        return EcmpObservation(prefix, [f"10.0.0.{i + 10}" for i, _ in enumerate(paths)], len(paths), "FAKE_ROUTER", "kernel", self.router.clock.t)


class FakePorts(BgpPorts):
    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.layer_state: Dict[HealthLayer, Optional[bool]] = {layer: True for layer in HealthLayer}
        self.vip = True
        self.connections: Optional[int] = 0
        self.events: List[Any] = []
        self.audits: List[Dict[str, Any]] = []
        self.allow_mutations = True
        self.key: Optional[bytes] = b"k" * 32
        self.probe_error = False
        self.probes = 0
        self.vip_added = 0

    def now(self) -> float:
        return self.clock.t

    def monotonic(self) -> float:
        return self.clock.t

    async def sleep(self, seconds: float) -> None:
        self.clock.advance(seconds)

    async def probe_layers(self, service, node):
        self.probes += 1
        if self.probe_error:
            raise RuntimeError("boom")
        return {
            layer: LayerResult(layer, ok, Provenance.LOCAL_PROBE, "" if ok else f"{layer.value} unavailable", self.clock.t)
            for layer, ok in self.layer_state.items()
        }

    async def active_connections(self, service):
        return self.connections

    def vip_present(self, vip: str):
        return self.vip

    async def ensure_vip(self, vip: str, present: bool):
        self.vip = present
        self.vip_added += 1
        return True, "ok"

    def mutations_allowed(self) -> bool:
        return self.allow_mutations

    def publish(self, event) -> None:
        self.events.append(event)

    def audit(self, record) -> None:
        self.audits.append(record)

    def report_key(self):
        return self.key

    def set(self, layer: HealthLayer, ok: Optional[bool]) -> None:
        self.layer_state[layer] = ok


def make_metrics() -> PipelineMetrics:
    return PipelineMetrics(LB_COUNTERS, LB_GAUGES, LB_LATENCIES)


def make_cfg(tmpdir: str, nodes: int = 3, **overrides: Any) -> BgpEcmpConfig:
    node_cfgs = [BgpNodeConfig(f"node{i + 1}", f"server_{i + 1}", f"10.0.1.{i + 1}") for i in range(nodes)]
    service = BgpServiceConfig(domain=DOMAIN, vip=VIP, prefix=PREFIX, port=443, health_path="/healthz", nodes=node_cfgs)
    health = BgpHealthConfig(
        probe_interval_seconds=2.0, probe_timeout_seconds=1.0, down_threshold=3, up_threshold=3, min_healthy_seconds=6.0,
        cooldown_seconds=10.0, max_transitions_per_window=4, transition_window_seconds=600.0, flap_hold_seconds=120.0,
    )
    base = BgpEcmpConfig(
        enabled=True, apply_enabled=True, state_path=os.path.join(tmpdir, "state.json"),
        node_reports_dir=os.path.join(tmpdir, "reports"), node_report_interval_seconds=30.0,
        speaker=BgpSpeakerConfig(local_asn=65001, state_cache_seconds=1.0),
        peers=[BgpPeerConfig("rtr", PEER_ADDRESS, 65000)], health=health,
        drain=BgpDrainConfig(wait_seconds=10.0, max_wait_seconds=60.0, connections_threshold=0, poll_seconds=2.0),
        convergence=BgpConvergenceConfig(slow_threshold_seconds=15.0, verify_timeout_seconds=10.0, verify_poll_seconds=0.5),
        services=[service],
    )
    return replace(base, **overrides)


class Node:
    def __init__(self, cfg: BgpEcmpConfig, node_cfg: BgpNodeConfig, clock: FakeClock, router: FakeRouter, tmpdir: str,
                 *, store: Optional[BgpStateStore] = None) -> None:
        self.cfg = cfg
        self.clock = clock
        self.ports = FakePorts(clock)
        self.speaker = FakeSpeaker(clock, router, node_cfg.node_id)
        self.metrics = make_metrics()
        self.alerts = LbAlertLifecycle(self.ports.publish, self.metrics)
        self.store = store or BgpStateStore(os.path.join(tmpdir, f"state_{node_cfg.node_id}.json"), clock=clock.now)
        self.controller = NodeController(
            cfg, cfg.services[0], node_cfg, ports=self.ports, speaker=self.speaker, alerts=self.alerts, store=self.store,
            metrics=self.metrics,
        )

    def categories(self) -> List[str]:
        return [e.category.value for e in self.ports.events]


async def run_ticks(nodes: List[Node], seconds: float, interval: float = 2.0) -> None:
    steps = int(seconds / interval)
    for _ in range(steps):
        for node in nodes:
            await node.controller.tick()
        nodes[0].clock.advance(interval)


from core.lb_bgp_feasibility import FeasibilityPorts


class FakeFeasibilityPorts(FeasibilityPorts):
    def __init__(self, clock: Optional[FakeClock] = None) -> None:
        self.clock = clock or FakeClock()
        self.binaries: Dict[str, str] = {}
        self.sysctls: Dict[str, str] = {"net.ipv4.conf.all.rp_filter": "2", "net.ipv4.fib_multipath_hash_policy": "1"}
        self.addresses: List[str] = ["10.0.1.1"]
        self.listening: List[Tuple[str, int, str]] = []
        self.dns: List[str] = []

    def which(self, name: str) -> Optional[str]:
        return self.binaries.get(name)

    def read_sysctl(self, key: str) -> Optional[str]:
        return self.sysctls.get(key)

    def local_addresses(self) -> List[str]:
        return list(self.addresses)

    def listeners(self) -> List[Tuple[str, int, str]]:
        return list(self.listening)

    async def resolve_dns(self, domain: str, timeout: float) -> List[str]:
        return list(self.dns)

    def now(self) -> float:
        return self.clock.t


ALL_ATTESTATIONS = [
    BgpAttestationConfig("upstream_bgp_permitted", True, "provider ticket PRV-1: BGP enabled for AS65001"),
    BgpAttestationConfig("asn_available", True, "RIR record AS65001"),
    BgpAttestationConfig("prefix_announceable", True, "BYOIP LOA for 9.9.9.0/24"),
    BgpAttestationConfig("multi_origin_allowed", True, "provider ticket PRV-2: multi-origin allowed"),
    BgpAttestationConfig("provider_antispoof_ok", True, "provider ticket PRV-3: anti-spoofing exempt for the VIP"),
    BgpAttestationConfig("router_ecmp_enabled", True, "network change NET-77: maximum-paths 8"),
]


from core.lb_bgp_orchestrator import BgpOrchestrator
from core.lb_bgp_state import NodeStateReport, write_node_report
from core.lb_bgp_status import BgpStatusService
from core.lb_state import DomainLocks


class World:
    def __init__(self, tmp: str, nodes: int = 3, *, local: str = "server_1", apply_enabled: bool = True, attest: bool = True,
                 observer: bool = True, vip: str = "9.9.9.10", prefix: str = "9.9.9.10/32", key: Optional[bytes] = b"k" * 32,
                 cloudflare_domains: Optional[List[str]] = None) -> None:
        self.tmp = tmp
        self.clock = FakeClock()
        self.router = FakeRouter(self.clock)
        cfg = make_cfg(tmp, nodes=nodes, apply_enabled=apply_enabled)
        service = BgpServiceConfig(
            domain=DOMAIN, vip=vip, prefix=prefix, port=443, health_path="/healthz", nodes=list(cfg.services[0].nodes),
        )
        self.cfg = replace(cfg, services=[service], attestations=list(ALL_ATTESTATIONS) if attest else [])
        self.local = local
        self.node = Node(self.cfg, next(n for n in service.nodes if n.server_identity == local), self.clock, self.router, tmp)
        self.node.ports.key = key
        self.controllers = {DOMAIN: self.node.controller}
        self.ports = self.node.ports
        self.feas = FakeFeasibilityPorts(self.clock)
        self.feas.addresses.append(vip)
        self.feas.listening = [("0.0.0.0", 443, "nginx")]
        self.observer = FakeObserver(self.router) if observer else None
        for n in service.nodes:
            self.router.register(n.node_id)
        from core.lb_bgp_speaker import NullRouterObserver

        self.metrics = self.node.metrics
        self.alerts = self.node.alerts
        self.status = BgpStatusService(
            self.cfg, ports=self.ports, controllers=self.controllers, observer=self.observer or NullRouterObserver(),
            alerts=self.alerts, metrics=self.metrics, report_max_age_seconds=300.0, cache_ttl_seconds=0.0,
            cloudflare=None, cloudflare_domains=cloudflare_domains or [],
        )
        self.locks = DomainLocks(clock=self.clock.now)
        self.orchestrator = BgpOrchestrator(
            self.cfg, LoadBalancingConfigStub(), ports=self.ports, feasibility_ports=self.feas, speaker=self.node.speaker,
            observer=self.observer or NullRouterObserver(), controllers=self.controllers, status=self.status,
            store=self.node.store, alerts=self.alerts, metrics=self.metrics, locks=self.locks,
            local_server_id=lambda: self.local, dns_timeout=1.0,
        )

    def write_report(self, node_id: str, *, state="ACTIVE", healthy=True, originated=True, mode="apply", age=0.0,
                     key: Optional[bytes] = None, connections=0, vip=None) -> None:
        report = NodeStateReport(
            domain=DOMAIN, node_id=node_id, server_identity="server_" + node_id[-1], vip=vip or self.cfg.services[0].vip,
            prefix=self.cfg.services[0].prefix, created_at=self.clock.t - age, state=state, mode=mode, healthy=healthy,
            peers=[{"peer_id": "rtr", "state": "Established"}], originated=originated,
            advertised_peers=[PEER_ADDRESS] if originated else [], connections=connections,
        )
        ok, detail = write_node_report(self.cfg.node_reports_dir, report, key if key is not None else self.ports.key)
        assert ok, detail


class LoadBalancingConfigStub:
    report_key_env_var = "RTSA_LB_REPORT_KEY"
