from __future__ import annotations

import argparse
import asyncio
import json
import random
import resource
import time
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

LAB_STATE = "/var/lab-rtsa/projects.json"
NODE_KINDS = {"node-express", "next-ssr", "astro-ssr", "node-noisy", "gov-node", "node-hightraffic", "monolith"}
PY_KINDS = {"fastapi", "fastapi-db", "flask"}


class Stats:
    def __init__(self) -> None:
        self.phases: Dict[str, Dict[str, Any]] = {}

    def add(self, phase: str, status: int, latency: float, error: Optional[str] = None) -> None:
        p = self.phases.setdefault(phase, {"requests": 0, "statuses": {}, "errors": {}, "latencies": [], "started": time.time(), "ended": time.time()})
        p["requests"] += 1
        p["ended"] = time.time()
        if error:
            p["errors"][error] = p["errors"].get(error, 0) + 1
        else:
            key = str(status)
            p["statuses"][key] = p["statuses"].get(key, 0) + 1
            p["latencies"].append(latency)

    def summary(self) -> Dict[str, Any]:
        out = {}
        for name, p in self.phases.items():
            lat = sorted(p["latencies"])
            dur = max(p["ended"] - p["started"], 1e-6)

            def pct(q: float) -> Optional[float]:
                return round(lat[min(len(lat) - 1, int(q * len(lat)))] * 1000, 1) if lat else None

            ok = sum(v for k, v in p["statuses"].items() if k.startswith(("2", "3")))
            out[name] = {
                "requests": p["requests"], "duration_s": round(dur, 1), "rps": round(p["requests"] / dur, 1), "ok": ok,
                "http_5xx": sum(v for k, v in p["statuses"].items() if k.startswith("5")), "http_4xx": sum(v for k, v in p["statuses"].items() if k.startswith("4")),
                "transport_errors": sum(p["errors"].values()), "error_kinds": p["errors"], "statuses": p["statuses"],
                "p50_ms": pct(0.50), "p95_ms": pct(0.95), "p99_ms": pct(0.99), "max_ms": round(lat[-1] * 1000, 1) if lat else None,
            }
        return out


def load_targets() -> List[Dict[str, Any]]:
    with open(LAB_STATE, "r", encoding="utf-8") as handle:
        projects = json.load(handle)["projects"]
    targets = []
    for p in projects:
        weight = 12 if p["archetype"] == "node-hightraffic" else (4 if p["archetype"] == "gov-node" else 1)
        if p["archetype"].startswith("worker"):
            continue
        targets.append({"domain": p["domain"], "kind": p["archetype"], "weight": weight})
    return targets


def session_plan(kind: str, rng: random.Random) -> List[Tuple[str, str, Optional[bytes]]]:
    if kind in NODE_KINDS:
        uid = rng.randint(1, 5000)
        steps = [("GET", "/", None), ("GET", "/api/items", None), ("POST", "/api/login", b"{}"), ("GET", "/api/me", None), ("GET", f"/api/user/{uid}/profile", None)]
        roll = rng.random()
        if roll < 0.05:
            steps.append(("GET", "/api/report", None))
        elif roll < 0.10:
            steps.append(("GET", f"/api/slow?ms={rng.choice([100, 300, 800])}", None))
        elif roll < 0.13:
            steps.append(("POST", "/api/upload", b"x" * rng.choice([512, 4096, 65536])))
        elif roll < 0.20:
            steps.append(("GET", "/api/err", None))
        return steps
    if kind in PY_KINDS:
        uid = rng.randint(1, 5000)
        return [("GET", "/", None), ("GET", "/api/items", None), ("GET", f"/api/user/{uid}/profile", None), ("GET", "/api/err", None)]
    if kind.startswith("php"):
        return [("GET", "/", None), ("GET", "/api.php", None)]
    return [("GET", "/", None), ("GET", "/assets/app0.js", None), ("GET", "/assets/app1.js", None)]


async def user(uid: int, session: aiohttp.ClientSession, stats: Stats, targets: List[Dict[str, Any]], weights: List[int], state: Dict[str, Any], base: str) -> None:
    rng = random.Random(uid * 7919)
    while state["running"]:
        if uid >= state["active_users"]:
            await asyncio.sleep(0.5)
            continue
        target = rng.choices(targets, weights=weights)[0]
        headers = {"Host": target["domain"], "User-Agent": f"Mozilla/5.0 (lab-user-{uid})", "X-Forwarded-For": f"198.{18 + ((uid >> 16) & 1)}.{(uid >> 8) & 255}.{uid & 255}"}
        for method, path, body in session_plan(target["kind"], rng):
            if not state["running"]:
                return
            phase = state["phase"]
            started = time.monotonic()
            try:
                async with session.request(method, base + path, headers=headers, data=body, allow_redirects=False) as resp:
                    await resp.read()
                    stats.add(phase, resp.status, time.monotonic() - started)
            except asyncio.TimeoutError:
                stats.add(phase, 0, time.monotonic() - started, "timeout")
            except aiohttp.ClientError as exc:
                stats.add(phase, 0, time.monotonic() - started, type(exc).__name__)
            think = state["think"]
            if think > 0:
                await asyncio.sleep(rng.uniform(0.5 * think, 1.5 * think))


async def run(args: argparse.Namespace) -> Dict[str, Any]:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 65536), hard))
    targets = load_targets()
    weights = [t["weight"] for t in targets]
    stats = Stats()
    state = {"running": True, "active_users": 0, "phase": "ramp", "think": args.think}
    connector = aiohttp.TCPConnector(limit=0, force_close=False, ttl_dns_cache=300)
    timeout = aiohttp.ClientTimeout(total=args.request_timeout)
    timeline: List[Dict[str, Any]] = []
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [asyncio.ensure_future(user(i, session, stats, targets, weights, state, args.base)) for i in range(args.users)]
        phases = [
            ("ramp", args.ramp, None, args.think),
            ("sustained", args.sustained, args.users, args.think),
            ("burst", args.burst, args.users, 0.0),
            ("recovery", args.recovery, max(1, args.users // 10), args.think),
        ]
        for name, seconds, users, think in phases:
            state["phase"] = name
            state["think"] = think
            t0 = time.time()
            timeline.append({"phase": name, "start": t0, "seconds": seconds, "users": users if users is not None else f"0->{args.users}", "think_s": think})
            while time.time() - t0 < seconds:
                if users is None:
                    state["active_users"] = int(args.users * min(1.0, (time.time() - t0) / max(seconds, 1)))
                else:
                    state["active_users"] = users
                await asyncio.sleep(0.25)
            timeline[-1]["end"] = time.time()
        state["running"] = False
        await asyncio.wait(tasks, timeout=args.request_timeout + 5)
        for t in tasks:
            t.cancel()
    return {"users": args.users, "targets": len(targets), "timeline": timeline, "phases": stats.summary()}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=2000)
    parser.add_argument("--ramp", type=float, default=60)
    parser.add_argument("--sustained", type=float, default=180)
    parser.add_argument("--burst", type=float, default=30)
    parser.add_argument("--recovery", type=float, default=60)
    parser.add_argument("--think", type=float, default=2.0)
    parser.add_argument("--request-timeout", type=float, default=15.0)
    parser.add_argument("--base", default="http://127.0.0.1")
    parser.add_argument("--out", default="")
    args = parser.parse_args()
    result = asyncio.run(run(args))
    text = json.dumps(result, indent=1)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
    print(text)


if __name__ == "__main__":
    main()
