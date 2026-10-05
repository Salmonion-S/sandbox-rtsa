from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Dict

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
LAB_ROOT = "/var/lab-rtsa"
INSTALL = os.path.join(LAB_ROOT, "rtsa")
RUN_DIR = os.path.join(LAB_ROOT, "run")
LOG_DIR = os.path.join(LAB_ROOT, "logs")
ALERTS = os.path.join(RUN_DIR, "alerts.jsonl")
PID_FILE = os.path.join(RUN_DIR, "rtsa.pid")
SAMPLES = os.path.join(RUN_DIR, "rtsa_samples.jsonl")
CGROUP_NAME = "rtsa-lab-small"
LAB_GUILD = 4242
LAB_ADMIN_ROLE = 111
LAB_CRITICAL_ROLE = 222


def rewrite_paths(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: rewrite_paths(v) for k, v in node.items()}
    if isinstance(node, list):
        return [rewrite_paths(v) for v in node]
    if isinstance(node, str) and node.startswith("/opt/security/rtsa"):
        return INSTALL + node[len("/opt/security/rtsa"):]
    return node


def lab_config(profile: str) -> Dict[str, Any]:
    with open(os.path.join(REPO, "config", "config.yaml"), "r", encoding="utf-8") as handle:
        cfg = rewrite_paths(yaml.safe_load(handle))
    modules = cfg["modules"]
    for name, section in modules.items():
        if isinstance(section, dict) and "enabled" in section:
            section["enabled"] = True
    modules["ssh_monitor"]["auth_log_path"] = os.path.join(LOG_DIR, "auth.log")
    modules["audit_monitor"]["audit_log_path"] = os.path.join(LOG_DIR, "audit.log")
    modules.setdefault("tce", {})["events_db_path"] = cfg["database"]["path"]
    modules.setdefault("host_persistence_detector", {})["events_db_path"] = cfg["database"]["path"]
    cfg["response_engine"]["detection_only"] = True
    cfg["discord"].update({
        "enabled": True, "guild_id": LAB_GUILD, "admin_role_ids": [LAB_ADMIN_ROLE], "critical_command_role_ids": [LAB_CRITICAL_ROLE],
        "channel_config_file": "discord-server1.yaml", "bot_token_env_var": "RTSA_LAB_DISCORD_TOKEN",
    })
    for key in ("attack_mention_role_id", "ssh_login_mention_role_id", "website_down_mention_role_id"):
        if key in cfg["discord"]:
            cfg["discord"][key] = LAB_ADMIN_ROLE
    try:
        with open(os.path.join(LAB_ROOT, "projects.json"), "r", encoding="utf-8") as handle:
            projects = json.load(handle)["projects"]
    except (OSError, ValueError, KeyError):
        projects = []
    sources = [
        {"path": f"/home/{p['user']}/logs/app.log", "project": p["user"], "domain": p["domain"], "service": p["user"], "environment": "lab", "format": "auto"}
        for p in projects if not p["pm2"] and p["archetype"] not in ("static", "static-build")
    ]
    modules["application_error_tracker"].setdefault("collection", {})["structured_logs"] = sources
    cfg["metrics"] = {"enabled": True, "host": "127.0.0.1", "port": 6767}
    cfg["cloudflare"]["enabled"] = False
    if profile == "production-modules":
        with open(os.path.join(REPO, "config", "config.yaml"), "r", encoding="utf-8") as handle:
            original = yaml.safe_load(handle)
        for name, section in original["modules"].items():
            if isinstance(section, dict) and "enabled" in section:
                modules[name]["enabled"] = section["enabled"]
    return cfg


def cmd_install(args: argparse.Namespace) -> None:
    if os.path.isdir(INSTALL):
        shutil.rmtree(INSTALL)
    ignore = shutil.ignore_patterns(".git", "__pycache__", "validation", "*.pyc", "tests", "docs")
    shutil.copytree(REPO, INSTALL, ignore=ignore)
    for d in (RUN_DIR, LOG_DIR, os.path.join(INSTALL, "data"), os.path.join(INSTALL, "logs")):
        os.makedirs(d, exist_ok=True)
    for name in ("auth.log", "audit.log"):
        open(os.path.join(LOG_DIR, name), "a").close()
    with open(os.path.join(INSTALL, "config", "config.yaml"), "w", encoding="utf-8") as handle:
        yaml.safe_dump(lab_config(args.profile), handle, sort_keys=False)
    with open(os.path.join(REPO, "config", "discord-server1.yaml"), "r", encoding="utf-8") as handle:
        production_channels = yaml.safe_load(handle)
    categories = sorted((production_channels.get("category_channels") or {}).keys())
    lab_channels = {"alert_channel_id": 1, "category_channels": {name: 1000 + i for i, name in enumerate(categories)}}
    with open(os.path.join(INSTALL, "config", "discord-server1.yaml"), "w", encoding="utf-8") as handle:
        yaml.safe_dump(lab_channels, handle)
    with open(os.path.join(INSTALL, "config", "server.config.yaml"), "w", encoding="utf-8") as handle:
        handle.write("server_1: true\nserver_2: false\n")
    print(json.dumps({"install": INSTALL, "profile": args.profile, "detection_only": True}))


def join_cgroup(pid: int) -> None:
    for controller in ("memory", "cpuset"):
        path = f"/sys/fs/cgroup/{controller}/{CGROUP_NAME}"
        if os.path.isdir(path):
            with open(os.path.join(path, "cgroup.procs"), "w", encoding="utf-8") as handle:
                handle.write(str(pid))


def cmd_start(args: argparse.Namespace) -> None:
    os.makedirs(RUN_DIR, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("RTSA_")}
    env.update({"RTSA_LOCK_PATH": os.path.join(RUN_DIR, "rtsa.lock"), "RTSA_CONFIG_DIR": os.path.join(INSTALL, "config"), "RTSA_LAB_INSTALL": INSTALL, "RTSA_LAB_ALERTS": ALERTS, "RTSA_LAB_DISCORD_TOKEN": "lab0sandbox0offline0token", "PYTHONDONTWRITEBYTECODE": "1"})
    out = open(os.path.join(RUN_DIR, "rtsa_stdout.log"), "ab")
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "rtsa_lab_runner.py")], cwd=INSTALL, env=env, stdout=out, stderr=out, start_new_session=True)
    if args.cgroup:
        join_cgroup(proc.pid)
    with open(PID_FILE, "w", encoding="utf-8") as handle:
        handle.write(str(proc.pid))
    print(json.dumps({"pid": proc.pid, "cgroup": bool(args.cgroup)}))


def rtsa_pid() -> int:
    with open(PID_FILE, "r", encoding="utf-8") as handle:
        return int(handle.read().strip())


def cmd_stop(args: argparse.Namespace) -> None:
    try:
        pid = rtsa_pid()
    except (OSError, ValueError):
        print("not running")
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        print("not running")
        return
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            print(json.dumps({"stopped": pid, "seconds": round(args.timeout - (deadline - time.time()), 2)}))
            return
        time.sleep(0.2)
    os.kill(pid, signal.SIGKILL)
    print(json.dumps({"killed": pid}))


def proc_sample(pid: int, clk: int) -> Dict[str, Any]:
    with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
        fields = handle.read().rsplit(")", 1)[1].split()
    utime, stime = int(fields[11]), int(fields[12])
    threads = int(fields[17])
    status = {}
    with open(f"/proc/{pid}/status", "r", encoding="utf-8") as handle:
        for line in handle:
            if ":" in line:
                k, v = line.split(":", 1)
                status[k] = v.strip()
    fds = len(os.listdir(f"/proc/{pid}/fd"))
    children = 0
    try:
        with open(f"/proc/{pid}/task/{pid}/children", "r", encoding="utf-8") as handle:
            children = len(handle.read().split())
    except OSError:
        pass
    return {"cpu_s": (utime + stime) / clk, "rss_kb": int(status.get("VmRSS", "0 kB").split()[0]), "threads": threads, "fds": fds, "children": children}


def cmd_sample(args: argparse.Namespace) -> None:
    pid = rtsa_pid()
    clk = os.sysconf("SC_CLK_TCK")
    prev = None
    end = time.time() + args.seconds
    with open(args.out or SAMPLES, "a", encoding="utf-8") as out:
        while time.time() < end:
            try:
                s = proc_sample(pid, clk)
            except (OSError, ValueError):
                out.write(json.dumps({"t": time.time(), "dead": True}) + "\n")
                return
            now = time.time()
            if prev is not None:
                s["cpu_pct"] = round(100.0 * (s["cpu_s"] - prev[1]["cpu_s"]) / max(now - prev[0], 1e-6), 2)
            with open("/proc/loadavg", "r", encoding="utf-8") as handle:
                s["load1"] = float(handle.read().split()[0])
            s["t"] = now
            s["label"] = args.label
            out.write(json.dumps(s) + "\n")
            out.flush()
            prev = (now, s)
            time.sleep(args.interval)


def main() -> None:
    parser = argparse.ArgumentParser(prog="rtsa_lab")
    sub = parser.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("install")
    i.add_argument("--profile", choices=["all-modules", "production-modules"], default="all-modules")
    s = sub.add_parser("start")
    s.add_argument("--cgroup", action="store_true")
    t = sub.add_parser("stop")
    t.add_argument("--timeout", type=float, default=60.0)
    m = sub.add_parser("sample")
    m.add_argument("--seconds", type=float, default=60.0)
    m.add_argument("--interval", type=float, default=2.0)
    m.add_argument("--label", default="")
    m.add_argument("--out", default="")
    args = parser.parse_args()
    {"install": cmd_install, "start": cmd_start, "stop": cmd_stop, "sample": cmd_sample}[args.cmd](args)


if __name__ == "__main__":
    main()
