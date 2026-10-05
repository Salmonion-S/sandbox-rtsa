from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Any, Callable, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
LAB = "/var/lab-rtsa"
RUN = os.path.join(LAB, "run")
DATA = os.path.join(LAB, "rtsa", "data")
ALERTS = os.path.join(RUN, "alerts.jsonl")
STDOUT = os.path.join(RUN, "rtsa_stdout.log")
PID_FILE = os.path.join(RUN, "rtsa.pid")
OUT = os.path.join(REPO, "validation", "results", "failure")


def lab(*args: str) -> str:
    return subprocess.run([sys.executable, os.path.join(HERE, "rtsa_lab.py"), *args], capture_output=True, text=True, timeout=180).stdout.strip()


def pid() -> Optional[int]:
    try:
        with open(PID_FILE, "r", encoding="utf-8") as handle:
            value = int(handle.read().strip())
        os.kill(value, 0)
        return value
    except (OSError, ValueError):
        return None


def alerts_between(start: float, end: float) -> List[Dict[str, Any]]:
    rows = []
    try:
        with open(ALERTS, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if start <= row["t"] <= end and row["kind"] == "send":
                    rows.append(row)
    except OSError:
        pass
    return rows


def titles(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in rows:
        title = next((e.get("title") for e in r.get("embeds") or [] if e.get("title")), None) or (r.get("content") or "")[:60]
        out[title] = out.get(title, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def log_offset() -> int:
    try:
        return os.path.getsize(STDOUT)
    except OSError:
        return 0


def log_since(offset: int, needles: tuple = ("ERROR", "CRITICAL", "Traceback")) -> List[str]:
    try:
        with open(STDOUT, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            text = handle.read()
    except OSError:
        return []
    return [line[:240] for line in text.splitlines() if any(n in line for n in needles)][:40]


def wait_log(offset: int, needle: str, timeout: float) -> Optional[float]:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with open(STDOUT, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                if needle in handle.read():
                    return round(time.time() - start, 2)
        except OSError:
            pass
        time.sleep(0.5)
    return None


def wait_dead(p: int, timeout: float) -> Optional[float]:
    start = time.time()
    while time.time() - start < timeout:
        try:
            os.kill(p, 0)
        except OSError:
            return round(time.time() - start, 2)
        time.sleep(0.1)
    return None


def http(host: str, path: str) -> int:
    req = urllib.request.Request(f"http://127.0.0.1{path}", headers={"Host": host})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0


def db_check() -> Dict[str, Any]:
    try:
        conn = sqlite3.connect(f"file:{os.path.join(DATA, 'rtsa.db')}?mode=ro", uri=True, timeout=10)
        try:
            result = conn.execute("PRAGMA integrity_check").fetchone()[0]
            events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        finally:
            conn.close()
        return {"integrity": result, "events": events}
    except sqlite3.Error as exc:
        return {"integrity": f"error: {exc}"}


def state_files_valid() -> Dict[str, Any]:
    bad = []
    count = 0
    for name in os.listdir(DATA):
        if not name.endswith(".json"):
            continue
        count += 1
        try:
            with open(os.path.join(DATA, name), "r", encoding="utf-8") as handle:
                json.load(handle)
        except (OSError, ValueError) as exc:
            bad.append(f"{name}: {type(exc).__name__}")
    temps = [n for n in os.listdir(DATA) if ".tmp-" in n]
    return {"json_files": count, "invalid": bad, "leftover_temp_files": temps}


def start_rtsa() -> Dict[str, Any]:
    offset = log_offset()
    t0 = time.time()
    info = json.loads(lab("start", "--cgroup"))
    ready = wait_log(offset, "Remote access detector: siklus #1", 180)
    return {"pid": info.get("pid"), "seconds_to_first_scan_cycle": ready, "t0": t0, "offset": offset}


def f1_singleton() -> Dict[str, Any]:
    first = pid()
    env = {k: v for k, v in os.environ.items() if not k.startswith("RTSA_")}
    env.update({"RTSA_LOCK_PATH": os.path.join(RUN, "rtsa.lock"), "RTSA_CONFIG_DIR": os.path.join(LAB, "rtsa", "config"), "RTSA_LAB_INSTALL": os.path.join(LAB, "rtsa"),
                "RTSA_LAB_ALERTS": os.path.join(RUN, "alerts_second_instance.jsonl"), "RTSA_LAB_DISCORD_TOKEN": "lab0sandbox0offline0token"})
    t0 = time.time()
    proc = subprocess.run([sys.executable, os.path.join(HERE, "rtsa_lab_runner.py")], cwd=os.path.join(LAB, "rtsa"), env=env, capture_output=True, text=True, timeout=120)
    return {"first_pid": first, "second_exit_code": proc.returncode, "second_seconds": round(time.time() - t0, 2), "second_stderr": proc.stderr.strip()[-300:],
            "first_still_alive": pid() == first, "verdict": "PASS" if proc.returncode != 0 and pid() == first else "FAIL"}


def f2_graceful_restart() -> Dict[str, Any]:
    before = pid()
    offset = log_offset()
    t0 = time.time()
    os.kill(before, signal.SIGTERM)
    stop_s = wait_dead(before, 90)
    errors_on_stop = log_since(offset)
    started = start_rtsa()
    time.sleep(60)
    window = alerts_between(started["t0"], time.time())
    return {"stop_seconds": stop_s, "errors_during_stop": errors_on_stop, "restart": {k: v for k, v in started.items() if k != "offset"}, "alerts_first_60s_after_restart": titles(window),
            "state": state_files_valid(), "db": db_check(), "verdict": "PASS" if stop_s is not None and started["seconds_to_first_scan_cycle"] is not None else "FAIL"}


def f3_sigkill_under_load() -> Dict[str, Any]:
    load = subprocess.Popen(["taskset", "-c", "3", sys.executable, os.path.join(HERE, "loadgen.py"), "--users", "800", "--ramp", "10", "--sustained", "70", "--burst", "0", "--recovery", "0",
                             "--out", os.path.join(OUT, "f3_load.json")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(25)
    victim = pid()
    t_kill = time.time()
    os.kill(victim, signal.SIGKILL)
    wait_dead(victim, 10)
    after_kill = {"db": db_check(), "state": state_files_valid()}
    started = start_rtsa()
    load.wait(timeout=200)
    time.sleep(30)
    post = alerts_between(started["t0"], time.time())
    pre = alerts_between(t_kill - 120, t_kill)
    pre_titles = titles(pre)
    repeated = {k: v for k, v in titles(post).items() if k in pre_titles}
    return {"killed_pid": victim, "after_kill": after_kill, "restart": {k: v for k, v in started.items() if k != "offset"}, "alerts_before_kill_120s": pre_titles,
            "alerts_after_restart": titles(post), "titles_repeated_after_restart": repeated, "errors_after_restart": log_since(started["offset"]),
            "verdict": "PASS" if after_kill["db"].get("integrity") == "ok" and not after_kill["state"]["invalid"] and started["seconds_to_first_scan_cycle"] is not None else "FAIL"}


def f4_corrupt_state() -> Dict[str, Any]:
    victim = pid()
    os.kill(victim, signal.SIGTERM)
    wait_dead(victim, 90)
    corrupted = {}
    for name, payload in (("notification_gate_state.json", "{not json"), ("application_error_state.json", ""), ("process_fingerprint_baseline.json", "[1,2,3]"),
                          ("remote_access_baseline.json", "\x00\x00\x00"), ("cloudpanel_baseline.json", '{"version": 999, "projects": "nope"}')):
        path = os.path.join(DATA, name)
        if os.path.exists(path):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(payload)
            corrupted[name] = payload[:20]
    started = start_rtsa()
    time.sleep(60)
    alive = pid() is not None
    window = alerts_between(started["t0"], time.time())
    return {"corrupted": corrupted, "restart": {k: v for k, v in started.items() if k != "offset"}, "alive_after_60s": alive, "state_after": state_files_valid(),
            "alerts_first_60s": titles(window), "errors": log_since(started["offset"]), "verdict": "PASS" if alive and started["seconds_to_first_scan_cycle"] is not None else "FAIL"}


def f5_db_locked() -> Dict[str, Any]:
    offset = log_offset()
    conn = sqlite3.connect(os.path.join(DATA, "rtsa.db"), timeout=30, isolation_level=None)
    conn.execute("BEGIN EXCLUSIVE")
    t0 = time.time()
    for i in range(30):
        http("001.lab.test", f"/api/user/{7 * (i + 1)}/profile")
    time.sleep(30)
    conn.execute("COMMIT")
    conn.close()
    held = round(time.time() - t0, 1)
    time.sleep(30)
    errors = log_since(offset)
    return {"lock_held_s": held, "rtsa_alive": pid() is not None, "errors_logged": errors[:15], "error_count": len(errors), "db_after": db_check(),
            "verdict": "PASS" if pid() is not None else "FAIL"}


def f6_log_rotation() -> Dict[str, Any]:
    log = "/home/lab-001/logs/nginx/access.log"
    offset = log_offset()
    os.rename(log, log + ".1")
    subprocess.run(["nginx", "-s", "reopen"], capture_output=True, timeout=30)
    time.sleep(2)
    t0 = time.time()
    statuses = [http("001.lab.test", "/index.php?file=../../../../etc/passwd") for _ in range(3)]
    statuses += [http("001.lab.test", "/?q=1%20union%20select%20password%20from%20users--") for _ in range(3)]
    time.sleep(45)
    window = alerts_between(t0, time.time())
    detected = [t for t in titles(window) if "WEB_ATTACK" in t or "SCAN" in t or "TRAVERSAL" in t or "SQLI" in t or "LFI" in t]
    lines = sum(1 for _ in open(log, "r", encoding="utf-8", errors="replace")) if os.path.exists(log) else 0
    return {"rotated": log, "requests_statuses": statuses, "new_log_lines": lines, "alerts": titles(window), "web_attack_alerts": detected,
            "errors": log_since(offset), "verdict": "PASS" if detected else "FAIL"}


def f7_nginx_outage() -> Dict[str, Any]:
    offset = log_offset()
    with open("/run/nginx-lab.pid", "r", encoding="utf-8") as handle:
        master = int(handle.read().strip())
    t0 = time.time()
    subprocess.run(["nginx", "-s", "stop"], capture_output=True, timeout=30)
    wait_dead(master, 30)
    time.sleep(240)
    t_up = time.time()
    subprocess.run(["nginx"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    try:
        with open("/run/nginx-lab.pid", "r", encoding="utf-8") as handle:
            new_master = int(handle.read().strip())
        for controller in ("memory", "cpuset"):
            with open(f"/sys/fs/cgroup/{controller}/rtsa-lab-small/cgroup.procs", "w", encoding="utf-8") as handle:
                handle.write(str(new_master))
    except OSError:
        pass
    time.sleep(240)
    down = alerts_between(t0, t_up)
    up = alerts_between(t_up, time.time())
    return {"outage_s": round(t_up - t0, 1), "sites": 121, "alerts_during_outage": titles(down), "alert_count_during_outage": len(down),
            "alerts_after_recovery": titles(up), "alert_count_after_recovery": len(up), "errors": log_since(offset)[:10],
            "verdict": "PASS" if 0 < len(down) <= 20 else ("FAIL: no outage alert" if not down else "FAIL: alert storm")}


def lab_user_run(user: str, command: str) -> int:
    uid = int(subprocess.run(["id", "-u", user], capture_output=True, text=True).stdout)
    gid = int(subprocess.run(["id", "-g", user], capture_output=True, text=True).stdout)
    env = {"HOME": f"/home/{user}", "USER": user, "PATH": "/opt/node22/bin:/usr/bin:/bin", "PM2_HOME": f"/home/{user}/.pm2"}
    return subprocess.run(["setpriv", f"--reuid={uid}", f"--regid={gid}", "--init-groups", "--", "/bin/bash", "-c", command], env=env, capture_output=True, timeout=120).returncode


def f8_pm2_crash() -> Dict[str, Any]:
    offset = log_offset()
    t0 = time.time()
    rc_stop = lab_user_run("lab-002", "pm2 stop lab-002")
    out = subprocess.run(["pgrep", "-u", "lab-003", "-f", "server.js"], capture_output=True, text=True).stdout.split()
    for p in out:
        try:
            os.kill(int(p), signal.SIGKILL)
        except OSError:
            pass
    time.sleep(150)
    t_fix = time.time()
    rc_start = lab_user_run("lab-002", "pm2 start lab-002")
    time.sleep(120)
    down = alerts_between(t0, t_fix)
    up = alerts_between(t_fix, time.time())
    return {"pm2_stop_rc": rc_stop, "sigkilled_pm2_app_pids_lab003": out, "pm2_start_rc": rc_start, "alerts_while_down": titles(down), "alerts_after_restore": titles(up),
            "errors": log_since(offset)[:10], "verdict": "PASS" if down else "FAIL: no alert for stopped PM2 app"}


def f9_resource_storm() -> Dict[str, Any]:
    offset = log_offset()
    t0 = time.time()
    stop = threading.Event()

    def hammer() -> None:
        while not stop.is_set():
            http("hightraffic.lab.test", "/api/cpu?ms=1500")

    threads = [threading.Thread(target=hammer, daemon=True) for _ in range(12)]
    for t in threads:
        t.start()
    hog = subprocess.Popen(["setpriv", "--reuid=" + subprocess.run(["id", "-u", "lab-099"], capture_output=True, text=True).stdout.strip(), "--regid=" + subprocess.run(["id", "-g", "lab-099"], capture_output=True, text=True).stdout.strip(),
                            "--init-groups", "--", "/opt/node22/bin/node", "-e", "const a=[];const e=Date.now()+150000;while(Date.now()<e){a.push(Buffer.alloc(16*1024*1024,1));if(a.length>60)a.shift();for(let i=0;i<5e6;i++){}}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for controller in ("memory", "cpuset"):
        try:
            with open(f"/sys/fs/cgroup/{controller}/rtsa-lab-small/cgroup.procs", "w", encoding="utf-8") as handle:
                handle.write(str(hog.pid))
        except OSError:
            pass
    rtsa_pid = pid()
    samples = []
    clk = os.sysconf("SC_CLK_TCK")
    prev = None
    while time.time() - t0 < 160:
        try:
            with open(f"/proc/{rtsa_pid}/stat", "r", encoding="utf-8") as handle:
                fields = handle.read().rsplit(")", 1)[1].split()
            cpu = (int(fields[11]) + int(fields[12])) / clk
            now = time.time()
            if prev:
                samples.append(round(100 * (cpu - prev[1]) / (now - prev[0]), 1))
            prev = (now, cpu)
        except OSError:
            break
        time.sleep(2)
    stop.set()
    hog.kill()
    time.sleep(90)
    window = alerts_between(t0, time.time())
    return {"rtsa_cpu_pct_samples": samples, "rtsa_cpu_avg": round(sum(samples) / max(len(samples), 1), 1), "rtsa_alive": pid() is not None, "alerts": titles(window),
            "governor_deferrals": len([l for l in log_since(offset, ("ditunda", "deferred", "dilewati")) ]), "errors": log_since(offset)[:10],
            "verdict": "PASS" if pid() is not None else "FAIL"}


SCENARIOS: Dict[str, Callable[[], Dict[str, Any]]] = {
    "F1_singleton": f1_singleton, "F2_graceful_restart": f2_graceful_restart, "F3_sigkill_under_load": f3_sigkill_under_load, "F4_corrupt_state": f4_corrupt_state,
    "F5_db_locked": f5_db_locked, "F6_log_rotation": f6_log_rotation, "F7_nginx_outage_121_sites": f7_nginx_outage, "F8_pm2_crash": f8_pm2_crash,
    "F9_resource_storm": f9_resource_storm,
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    os.makedirs(OUT, exist_ok=True)
    names = [n for n in args.only.split(",") if n] or list(SCENARIOS)
    for name in names:
        if pid() is None:
            start_rtsa()
            time.sleep(30)
        t0 = time.time()
        try:
            result = SCENARIOS[name]()
        except Exception as exc:
            result = {"verdict": "ERROR", "error": f"{type(exc).__name__}: {exc}"}
        result["duration_s"] = round(time.time() - t0, 1)
        with open(os.path.join(OUT, f"{name}.json"), "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=1, default=str)
        print(f"{name}: {result.get('verdict')} ({result['duration_s']}s)", flush=True)


if __name__ == "__main__":
    main()
