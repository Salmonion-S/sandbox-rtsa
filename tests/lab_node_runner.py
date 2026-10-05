import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import replace

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from config.manager import (
    BgpConvergenceConfig, BgpDrainConfig, BgpEcmpConfig, BgpHealthConfig, BgpNodeConfig, BgpPeerConfig, BgpServiceConfig,
    BgpSpeakerConfig,
)
from core.lb_alerts import LbAlertLifecycle
from core.lb_bgp_controller import BgpPorts, NodeController
from core.lb_bgp_model import HealthLayer, LayerResult, Provenance
from core.lb_bgp_speaker import FrrVtyshSpeaker, SubprocessRunner
from core.lb_bgp_state import BgpStateStore
from core.pipeline_metrics import LB_COUNTERS, LB_GAUGES, LB_LATENCIES, PipelineMetrics


class LabPorts(BgpPorts):
    def __init__(self, vip, port, out_dir, node):
        self.vip, self.port, self.out_dir, self.node = vip, port, out_dir, node
        self.events = open(os.path.join(out_dir, f"events_{node}.jsonl"), "a", buffering=1)

    async def _connect(self, timeout):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(self.vip, self.port), timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            return None, None, exc.__class__.__name__
        return reader, writer, ""

    async def probe_layers(self, service, node):
        now = time.time()
        reader, writer, why = await self._connect(1.0)
        results = {
            HealthLayer.NETWORK: LayerResult(HealthLayer.NETWORK, True, Provenance.LOCAL_PROBE, "", now),
            HealthLayer.NGINX: LayerResult(HealthLayer.NGINX, writer is not None, Provenance.LOCAL_PROBE, why, now),
            HealthLayer.VIP_LISTENER: LayerResult(HealthLayer.VIP_LISTENER, writer is not None, Provenance.LOCAL_PROBE, why, now),
            HealthLayer.BACKEND: LayerResult(HealthLayer.BACKEND, None, Provenance.CONFIG, "", now),
            HealthLayer.DATABASE: LayerResult(HealthLayer.DATABASE, None, Provenance.CONFIG, "", now),
        }
        ok, detail = False, why or "no response"
        if writer is not None:
            try:
                writer.write(b"GET /healthz HTTP/1.0\r\nHost: lab.example.com\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(200), 1.0)
                ok = data.startswith(b"HTTP/1.") and b" 200 " in data.split(b"\r\n", 1)[0]
                detail = "" if ok else data.split(b"\r\n", 1)[0].decode("ascii", "replace")
            except (OSError, asyncio.TimeoutError) as exc:
                detail = exc.__class__.__name__
            finally:
                writer.close()
        results[HealthLayer.APPLICATION] = LayerResult(HealthLayer.APPLICATION, ok, Provenance.LOCAL_PROBE, detail, now)
        return results

    async def active_connections(self, service):
        return 0

    def vip_present(self, vip):
        return True

    def publish(self, event):
        self.events.write(json.dumps({
            "t": time.time(), "category": event.category.value, "severity": event.severity.value, "message": event.message,
        }) + "\n")

    def audit(self, record):
        self.events.write(json.dumps({"t": time.time(), "audit": record}, default=str) + "\n")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--pathspace", required=True)
    parser.add_argument("--vip", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--asn", type=int, default=65001)
    parser.add_argument("--peer-asn", type=int, default=65000)
    parser.add_argument("--out", required=True)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--down", type=int, default=3)
    parser.add_argument("--up", type=int, default=3)
    parser.add_argument("--stable", type=float, default=2.0)
    parser.add_argument("--cooldown", type=float, default=3.0)
    parser.add_argument("--control", required=True)
    args = parser.parse_args()
    node = BgpNodeConfig(args.node, args.identity, "10.0.0.1")
    service = BgpServiceConfig(domain="lab.example.com", vip=args.vip, prefix=f"{args.vip}/32", port=args.port, scheme="http", nodes=[node])
    cfg = BgpEcmpConfig(
        enabled=True, apply_enabled=True, state_path=os.path.join(args.out, f"state_{args.node}.json"),
        node_reports_dir=os.path.join(args.out, "reports"), node_report_interval_seconds=5.0,
        speaker=BgpSpeakerConfig(vtysh_pathspace=args.pathspace, local_asn=args.asn, state_cache_seconds=1.0),
        peers=[BgpPeerConfig("rtr", args.peer, args.peer_asn)],
        health=BgpHealthConfig(
            probe_interval_seconds=args.interval, probe_timeout_seconds=1.0, down_threshold=args.down, up_threshold=args.up,
            min_healthy_seconds=args.stable, cooldown_seconds=args.cooldown, max_transitions_per_window=6,
            transition_window_seconds=300.0, flap_hold_seconds=30.0, backend="ignored", database="ignored",
        ),
        drain=BgpDrainConfig(wait_seconds=2.0, max_wait_seconds=30.0, connections_threshold=0, poll_seconds=1.0),
        convergence=BgpConvergenceConfig(slow_threshold_seconds=15.0, verify_timeout_seconds=15.0, verify_poll_seconds=0.1),
        services=[service],
    )
    ports = LabPorts(args.vip, args.port, args.out, args.node)
    metrics = PipelineMetrics(LB_COUNTERS, LB_GAUGES, LB_LATENCIES)
    speaker = FrrVtyshSpeaker(cfg.speaker, cfg.peers, SubprocessRunner())
    alerts = LbAlertLifecycle(ports.publish, metrics)
    store = BgpStateStore(cfg.state_path)
    controller = NodeController(cfg, service, node, ports=ports, speaker=speaker, alerts=alerts, store=store, metrics=metrics)
    await controller.start()
    await controller.request_enable("lab")
    last_state, last_conv = "", None
    while True:
        started = time.monotonic()
        await controller.tick()
        snap = controller.snapshot()
        if snap.state != last_state:
            ports.events.write(json.dumps({"t": time.time(), "state": snap.state, "reason": snap.reason, "withdraw_reason": snap.withdraw_reason, "serving": snap.serving}) + "\n")
            last_state = snap.state
        conv = json.dumps(snap.last_convergence, sort_keys=True)
        if conv != last_conv and snap.last_convergence.get("route_withdraw_started_at"):
            ports.events.write(json.dumps({"t": time.time(), "convergence": snap.last_convergence}) + "\n")
        last_conv = conv
        if os.path.exists(args.control):
            command = open(args.control).read().strip()
            os.remove(args.control)
            if command == "drain":
                await controller.request_drain("lab")
            elif command == "resume":
                await controller.request_resume("lab")
        await asyncio.sleep(max(0.0, args.interval - (time.monotonic() - started)))


if __name__ == "__main__":
    asyncio.run(main())
