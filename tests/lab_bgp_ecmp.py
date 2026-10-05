import argparse
import glob
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time

_TESTS = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_TESTS)
LAB = "/tmp/rtsalab"
FRR = "/usr/lib/frr"
VIP = "203.0.113.10"
PORT = 8080
ROUTER_ASN = 65000
NODE_ASN = 65001
PYTHON = sys.executable


def run(argv, check=True, capture=True, timeout=60):
    result = subprocess.run(argv, capture_output=capture, text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(argv)} -> rc={result.returncode}: {result.stderr.strip()[:300]}")
    return result


def in_ns(name, *argv):
    return ["ip", "netns", "exec", name, *argv]


def prerequisites():
    missing = []
    if os.geteuid() != 0:
        missing.append("root")
    for binary in ("ip", "vtysh", "nft"):
        if not shutil.which(binary):
            missing.append(binary)
    for daemon in ("zebra", "bgpd", "bfdd"):
        if not os.path.exists(os.path.join(FRR, daemon)):
            missing.append(f"{FRR}/{daemon}")
    if not missing:
        probe = subprocess.run(["ip", "netns", "add", "rtsa_probe"], capture_output=True, text=True)
        if probe.returncode != 0:
            missing.append("network namespaces (" + probe.stderr.strip()[:80] + ")")
        else:
            subprocess.run(["ip", "netns", "del", "rtsa_probe"], capture_output=True)
    return missing


def cleanup(count):
    for name in ["cli", "rtr"] + [f"n{i}" for i in range(1, count + 1)]:
        pids = run(["ip", "netns", "pids", name], check=False).stdout.split()
        for pid in pids:
            subprocess.run(["kill", "-9", pid], capture_output=True)
        run(["ip", "netns", "del", name], check=False)
    for path in glob.glob("/etc/frr/rtr") + glob.glob("/etc/frr/n[0-9]*") + glob.glob("/var/run/frr/rtr") + glob.glob("/var/run/frr/n[0-9]*"):
        shutil.rmtree(path, ignore_errors=True)


def write(path, text):
    with open(path, "w") as handle:
        handle.write(text)


def frr_start(ns, bgpd_conf, bfd):
    conf_dir, run_dir = f"/etc/frr/{ns}", f"/var/run/frr/{ns}"
    os.makedirs(conf_dir, exist_ok=True)
    os.makedirs(run_dir, exist_ok=True)
    write(f"{conf_dir}/zebra.conf", f"hostname {ns}-zebra\nlog stdout\nno zebra nexthop kernel enable\n")
    write(f"{conf_dir}/bgpd.conf", bgpd_conf)
    write(f"{conf_dir}/vtysh.conf", "")
    if bfd:
        write(f"{conf_dir}/bfdd.conf", f"hostname {ns}-bfdd\nlog stdout\nbfd\n profile lab\n  detect-multiplier 3\n  receive-interval 300\n  transmit-interval 300\n exit\nexit\n")
    run(["chown", "-R", "frr:frr", conf_dir, run_dir])
    zserv = f"{run_dir}/zserv.api"
    run(in_ns(ns, f"{FRR}/zebra", "-d", "-N", ns, "-f", f"{conf_dir}/zebra.conf", "-i", f"{run_dir}/zebra.pid", "-z", zserv, "--log", f"file:/tmp/frr_{ns}.zebra.log"))
    if bfd:
        run(in_ns(ns, f"{FRR}/bfdd", "-d", "-N", ns, "-f", f"{conf_dir}/bfdd.conf", "-i", f"{run_dir}/bfdd.pid", "-z", zserv, "--log", f"file:/tmp/frr_{ns}.bfdd.log"))
    run(in_ns(ns, f"{FRR}/bgpd", "-d", "-N", ns, "-f", f"{conf_dir}/bgpd.conf", "-i", f"{run_dir}/bgpd.pid", "-z", zserv, "--log", f"file:/tmp/frr_{ns}.bgpd.log"))


def build(count, bfd):
    os.makedirs(LAB, exist_ok=True)
    os.makedirs(os.path.join(LAB, "flags"), exist_ok=True)
    for name in ["cli", "rtr"] + [f"n{i}" for i in range(1, count + 1)]:
        run(["ip", "netns", "add", name])
        run(in_ns(name, "ip", "link", "set", "lo", "up"))
    run(in_ns("rtr", "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.fib_multipath_hash_policy=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0"))
    run(["ip", "link", "add", "rtr-cli", "type", "veth", "peer", "name", "cli-rtr"])
    run(["ip", "link", "set", "rtr-cli", "netns", "rtr"])
    run(["ip", "link", "set", "cli-rtr", "netns", "cli"])
    run(in_ns("rtr", "ip", "addr", "add", "10.20.0.1/24", "dev", "rtr-cli"))
    run(in_ns("rtr", "ip", "link", "set", "rtr-cli", "up"))
    run(in_ns("cli", "ip", "addr", "add", "10.20.0.2/24", "dev", "cli-rtr"))
    run(in_ns("cli", "ip", "link", "set", "cli-rtr", "up"))
    run(in_ns("cli", "ip", "route", "add", "default", "via", "10.20.0.1"))
    for i in range(1, count + 1):
        run(["ip", "link", "add", f"rtr-n{i}", "type", "veth", "peer", "name", f"n{i}-rtr"])
        run(["ip", "link", "set", f"rtr-n{i}", "netns", "rtr"])
        run(["ip", "link", "set", f"n{i}-rtr", "netns", f"n{i}"])
        run(in_ns("rtr", "ip", "addr", "add", f"10.10.{i}.1/30", "dev", f"rtr-n{i}"))
        run(in_ns("rtr", "ip", "link", "set", f"rtr-n{i}", "up"))
        run(in_ns(f"n{i}", "ip", "addr", "add", f"10.10.{i}.2/30", "dev", f"n{i}-rtr"))
        run(in_ns(f"n{i}", "ip", "link", "set", f"n{i}-rtr", "up"))
        run(in_ns(f"n{i}", "ip", "route", "add", "default", "via", f"10.10.{i}.1"))
        run(in_ns(f"n{i}", "ip", "addr", "add", f"{VIP}/32", "dev", "lo"))
        run(in_ns(f"n{i}", "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0"))
    router = ["hostname rtr-bgpd", "log stdout", f"router bgp {ROUTER_ASN}", " bgp router-id 10.0.0.1", " no bgp ebgp-requires-policy"]
    for i in range(1, count + 1):
        router += [f" neighbor 10.10.{i}.2 remote-as {NODE_ASN}", f" neighbor 10.10.{i}.2 timers 3 9", f" neighbor 10.10.{i}.2 timers connect 3"]
        if bfd:
            router.append(f" neighbor 10.10.{i}.2 bfd profile lab")
    router += [" address-family ipv4 unicast", "  maximum-paths 8", " exit-address-family"]
    frr_start("rtr", "\n".join(router) + "\n", bfd)
    for i in range(1, count + 1):
        node = [
            f"hostname n{i}-bgpd", "log stdout", f"ip prefix-list RTSA_VIP seq 5 permit {VIP}/32", "ip prefix-list DENY_ALL seq 5 deny any",
            f"router bgp {NODE_ASN}", f" bgp router-id 10.10.{i}.2", " no bgp ebgp-requires-policy",
            f" neighbor 10.10.{i}.1 remote-as {ROUTER_ASN}", f" neighbor 10.10.{i}.1 timers 3 9", f" neighbor 10.10.{i}.1 timers connect 3",
        ]
        if bfd:
            node.append(f" neighbor 10.10.{i}.1 bfd profile lab")
        node += [" address-family ipv4 unicast", f"  neighbor 10.10.{i}.1 prefix-list RTSA_VIP out", f"  neighbor 10.10.{i}.1 prefix-list DENY_ALL in", " exit-address-family"]
        frr_start(f"n{i}", "\n".join(node) + "\n", bfd)


def start_services(count, interval):
    procs = []
    out = LAB
    for i in range(1, count + 1):
        name = f"n{i}"
        procs.append(subprocess.Popen(in_ns(name, PYTHON, os.path.join(_TESTS, "lab_node_http.py"), name, VIP, str(PORT), os.path.join(LAB, "flags")), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(0.8)
    for i in range(1, count + 1):
        name = f"n{i}"
        for stale in glob.glob(os.path.join(out, f"events_{name}.jsonl")) + glob.glob(os.path.join(out, f"state_{name}.json")):
            os.remove(stale)
        procs.append(subprocess.Popen(in_ns(
            name, PYTHON, os.path.join(_TESTS, "lab_node_runner.py"), "--node", name, "--identity", f"server_{i}", "--pathspace", name,
            "--vip", VIP, "--port", str(PORT), "--peer", f"10.10.{i}.1", "--out", out, "--interval", str(interval),
            "--control", os.path.join(out, f"control_{name}"),
        ), stdout=open(os.path.join(out, f"runner_{name}.log"), "w"), stderr=subprocess.STDOUT))
    return procs


def nexthops():
    result = run(in_ns("rtr", "ip", "-j", "route", "show", f"{VIP}/32"), check=False)
    try:
        data = json.loads(result.stdout or "[]")
    except ValueError:
        return -1
    if not data:
        return 0
    return len(data[0].get("nexthops", [])) or 1


class Poller(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.samples = []
        self.stop_flag = False

    def run(self):
        while not self.stop_flag:
            self.samples.append((time.time(), nexthops()))
            time.sleep(0.01)


def wait_for(predicate, timeout, step=0.1):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(step)
    return False


def events(node):
    path = os.path.join(LAB, f"events_{node}.jsonl")
    if not os.path.exists(path):
        return []
    rows = []
    for line in open(path):
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def node_state(node):
    states = [row for row in events(node) if "state" in row]
    return states[-1]["state"] if states else "UNKNOWN"


def all_active(count):
    return all(node_state(f"n{i}") == "ACTIVE" for i in range(1, count + 1)) and nexthops() == count


def loadgen(seconds, rate, out):
    return subprocess.Popen(in_ns("cli", PYTHON, os.path.join(_TESTS, "lab_loadgen.py"), "load", VIP, str(PORT), str(rate), str(seconds), out))


def analyse_client(path, t_inject):
    rows = []
    for line in open(path):
        parts = line.split()
        if len(parts) >= 2:
            rows.append((float(parts[0]), parts[1], parts[2] if len(parts) > 2 else ""))
    rows.sort()
    fails = [t for t, status, _n in rows if status == "fail"]
    after = [t for t in fails if t >= t_inject - 0.05]
    return {
        "requests": len(rows), "failures": len(fails), "failures_after_injection": len(after),
        "first_failure_after_s": round(after[0] - t_inject, 3) if after else None,
        "last_failure_after_s": round(after[-1] - t_inject, 3) if after else None,
        "failed_share_percent": round(100.0 * len(fails) / max(1, len(rows)), 2),
    }


def scenario(name, count, inject, restore, window, rate=40.0, settle=None):
    assert wait_for(lambda: all_active(count), 90.0), f"baseline not reached before {name}"
    time.sleep(1.0)
    poller = Poller()
    poller.start()
    out = os.path.join(LAB, f"load_{name}.txt")
    pre, post = 3.0, window
    generator = loadgen(pre + post, rate, out)
    time.sleep(pre)
    t_inject = time.time()
    inject()
    time.sleep(post)
    generator.wait(timeout=30)
    poller.stop_flag = True
    poller.join(timeout=2.0)
    removed = next((t for t, c in poller.samples if t >= t_inject and 0 <= c < count), None)
    restored = None
    result = {
        "scenario": name, "nodes": count, "ecmp_path_removed_after_s": round(removed - t_inject, 3) if removed else None,
        "min_paths_seen": min((c for t, c in poller.samples if t >= t_inject and c >= 0), default=None),
        "client": analyse_client(out, t_inject),
        "rtsa_events": {},
    }
    for i in range(1, count + 1):
        rows = [r for r in events(f"n{i}") if r.get("t", 0) >= t_inject - 0.5]
        if rows:
            result["rtsa_events"][f"node{i}"] = [
                {**{k: v for k, v in row.items() if k in ("category", "state", "reason", "withdraw_reason", "serving")}, "after_s": round(row["t"] - t_inject, 3)}
                for row in rows if "audit" not in row and "convergence" not in row
            ][:12]
            conv = [r["convergence"] for r in rows if "convergence" in r]
            if conv:
                c = conv[-1]
                base = {k: c.get(k) for k in ("failure_detected_at", "health_failed_at", "route_withdraw_started_at", "bgp_withdraw_observed_at")}
                result["rtsa_events"][f"node{i}_convergence_s"] = {
                    **{k: (round(v - t_inject, 3) if isinstance(v, (int, float)) else None) for k, v in base.items()},
                    "latencies": c.get("latencies"),
                }
    if restore is not None:
        t_restore = time.time()
        restore()
        regained = wait_for(lambda: all_active(count), 90.0, 0.05)
        restored = round(time.time() - t_restore, 3) if regained else None
        result["recovery_to_full_ecmp_s"] = restored
    return result


def inject_fail_flag(node):
    path = os.path.join(LAB, "flags", f"{node}.fail")
    return (lambda: write(path, "1")), (lambda: os.remove(path) if os.path.exists(path) else None)


def kill_http(node_ns):
    def go():
        for pid in run(["ip", "netns", "pids", node_ns], check=False).stdout.split():
            cmd = open(f"/proc/{pid}/cmdline", "rb").read().decode(errors="replace") if os.path.exists(f"/proc/{pid}/cmdline") else ""
            if "lab_node_http.py" in cmd:
                subprocess.run(["kill", "-9", pid], capture_output=True)
    return go


def start_http(node_ns, procs):
    def go():
        procs.append(subprocess.Popen(in_ns(node_ns, PYTHON, os.path.join(_TESTS, "lab_node_http.py"), node_ns, VIP, str(PORT), os.path.join(LAB, "flags")), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    return go


def drain_experiment(count, target):
    assert wait_for(lambda: all_active(count), 90.0)
    trigger = os.path.join(LAB, "drain_go")
    out = os.path.join(LAB, "held.json")
    for stale in (trigger, out):
        if os.path.exists(stale):
            os.remove(stale)
    holder = subprocess.Popen(in_ns("cli", PYTHON, os.path.join(_TESTS, "lab_loadgen.py"), "hold", VIP, str(PORT), "180", trigger, out))
    time.sleep(3.0)
    write(os.path.join(LAB, f"control_{target}"), "drain")
    wait_for(lambda: nexthops() == count - 1, 30.0, 0.05)
    time.sleep(2.0)
    write(trigger, "go")
    holder.wait(timeout=60)
    held = json.loads(open(out).read()) if os.path.exists(out) else {}
    wait_for(lambda: node_state(target) in ("WITHDRAWN",), 40.0)
    state = node_state(target)
    write(os.path.join(LAB, f"control_{target}"), "resume")
    resumed = wait_for(lambda: all_active(count), 90.0, 0.1)
    return {
        "scenario": "drain", "drained_node": f"node{target[1:]}", "state_after_drain": state, "held_connections_outcome_by_original_node": held,
        "resumed_to_full_ecmp": resumed,
    }


def distribution(count):
    result = run(in_ns("cli", PYTHON, os.path.join(_TESTS, "lab_loadgen.py"), "distribution", VIP, str(PORT), "600"), timeout=120)
    try:
        return json.loads(result.stdout.strip())
    except ValueError:
        return {"raw": result.stdout.strip()[:200]}


def environment(count, bfd, interval):
    version = run([os.path.join(FRR, "bgpd"), "--version"], check=False).stdout.splitlines()[0:1]
    return {
        "kernel": platform.release(), "python": platform.python_version(), "frr": version, "nodes": count,
        "topology": "client -> router(ECMP, FRR) -> N node namespaces, one shared VIP /32 on each node's loopback, eBGP",
        "bgp_timers": "keepalive 3s hold 9s connect-retry 3s", "bfd": "300ms x3" if bfd else "off",
        "ecmp": "maximum-paths 8, kernel fib_multipath_hash_policy=1 (L4 hash), zebra nexthop-groups disabled",
        "rtsa_health": f"probe every {interval}s, 3 failures to withdraw, 3 successes + 2s stability + 3s cooldown to advertise",
        "scope": "LAB ONLY: network namespaces on one host; this proves the mechanism and the RTSA controller, not any production network",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes", type=int, default=3)
    parser.add_argument("--bfd", action="store_true")
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--scenarios", default="distribution,app,server,bgpd,linkdown,silent,drain")
    parser.add_argument("--out", default=os.path.join(LAB, "evidence.json"))
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    missing = prerequisites()
    if missing:
        print("LAB SKIPPED: missing " + ", ".join(missing))
        return 0
    count = args.nodes
    cleanup(count)
    procs = []
    evidence = {"environment": environment(count, args.bfd, args.interval), "scenarios": []}
    try:
        build(count, args.bfd)
        procs = start_services(count, args.interval)
        print("lab built; waiting for every node to become ACTIVE through the RTSA controller ...")
        if not wait_for(lambda: all_active(count), 120.0):
            raise RuntimeError(f"baseline not reached: ECMP paths={nexthops()}, states={[node_state(f'n{i}') for i in range(1, count + 1)]}")
        evidence["baseline_ecmp_paths"] = nexthops()
        steps = args.scenarios.split(",")
        last = count
        for step in steps:
            print("scenario:", step)
            if step == "distribution":
                evidence["flow_distribution_600_connections"] = distribution(count)
            elif step == "app":
                inject, restore = inject_fail_flag(f"n{last}")
                evidence["scenarios"].append(scenario("application_failure_health_endpoint", count, inject, restore, 8.0))
            elif step == "server":
                evidence["scenarios"].append(scenario("web_server_process_dead", count, kill_http(f"n{last}"), start_http(f"n{last}", procs), 8.0))
            elif step == "bgpd":
                def stop_bgpd():
                    pid = open(f"/var/run/frr/n{last}/bgpd.pid").read().strip()
                    subprocess.run(["kill", "-9", pid], capture_output=True)

                def start_bgpd():
                    run(in_ns(f"n{last}", f"{FRR}/bgpd", "-d", "-N", f"n{last}", "-f", f"/etc/frr/n{last}/bgpd.conf", "-i", f"/var/run/frr/n{last}/bgpd.pid", "-z", f"/var/run/frr/n{last}/zserv.api", "--log", f"file:/tmp/frr_n{last}.bgpd.log"))

                evidence["scenarios"].append(scenario("bgp_daemon_killed", count, stop_bgpd, start_bgpd, 8.0))
            elif step == "linkdown":
                evidence["scenarios"].append(scenario(
                    "link_down_carrier_loss", count, lambda: run(in_ns(f"n{last}", "ip", "link", "set", f"n{last}-rtr", "down")),
                    lambda: (run(in_ns(f"n{last}", "ip", "link", "set", f"n{last}-rtr", "up")), run(in_ns(f"n{last}", "ip", "route", "replace", "default", "via", f"10.10.{last}.1"))), 10.0,
                ))
            elif step == "silent":
                def blackhole():
                    ns = f"n{last}"
                    run(in_ns(ns, "nft", "add", "table", "inet", "rtsalab"))
                    for chain, hook in (("i", "input"), ("o", "output")):
                        run(in_ns(ns, "nft", "add", "chain", "inet", "rtsalab", chain, "{", "type", "filter", "hook", hook, "priority", "0", ";", "policy", "drop", ";", "}"))
                    run(in_ns(ns, "nft", "insert", "rule", "inet", "rtsalab", "i", "iifname", "lo", "accept"))
                    run(in_ns(ns, "nft", "insert", "rule", "inet", "rtsalab", "o", "oifname", "lo", "accept"))

                evidence["scenarios"].append(scenario(
                    "silent_network_failure_no_carrier_loss", count, blackhole,
                    lambda: run(in_ns(f"n{last}", "nft", "delete", "table", "inet", "rtsalab")), 22.0,
                ))
            elif step == "drain":
                evidence["scenarios"].append(drain_experiment(count, f"n{last}"))
        evidence["rtsa_runner_errors"] = [open(p).read()[-400:] for p in glob.glob(os.path.join(LAB, "runner_*.log")) if "Traceback" in open(p).read()]
    finally:
        if not args.keep:
            for proc in procs:
                try:
                    proc.kill()
                except OSError:
                    pass
            cleanup(count)
    write(args.out, json.dumps(evidence, indent=2, default=str))
    print(json.dumps(evidence, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
