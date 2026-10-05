from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import random
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

LAB_ROOT = "/var/lab-rtsa"
STATE = os.path.join(LAB_ROOT, "projects.json")
RUN_DIR = os.path.join(LAB_ROOT, "run")
GIT_DIR = os.path.join(LAB_ROOT, "git")
HOME_ROOT = "/home"
NGINX_CONF_DIR = "/etc/nginx/sites-enabled"
NODE_BIN = "/opt/node22/bin"
VENV = "/opt/lab/venv"
LAB_NODE_MODULES = "/opt/lab/node/node_modules"
DOMAIN_SUFFIX = "lab.test"
CGROUP_NAME = "rtsa-lab-small"
PERSONAS = {
    "lab-frontend": "static-build",
    "lab-backend": "node-noisy",
    "lab-php": "php-builtin",
    "lab-python": "fastapi-db",
    "lab-government": "gov-node",
    "lab-hightraffic": "node-hightraffic",
    "lab-worker": "worker-node",
}
ROTATION = (
    ("node-express", 40), ("php-builtin", 22), ("fastapi", 8), ("flask", 8), ("static", 14), ("next-ssr", 10), ("astro-ssr", 6), ("worker", 5), ("monolith", 5),
)
PM2_ARCHETYPES = {"node-express", "next-ssr", "astro-ssr", "node-noisy", "gov-node", "node-hightraffic", "monolith"}


@dataclass
class Project:
    user: str
    domain: str
    archetype: str
    port: int
    index: int
    pm2: bool = False
    vulnerable: bool = False
    error_rate: float = 0.0
    cpu_ms: int = 0
    flags: Dict[str, Any] = field(default_factory=dict)

    @property
    def home(self) -> str:
        return f"{HOME_ROOT}/{self.user}"

    @property
    def docroot(self) -> str:
        return f"{self.home}/htdocs/{self.domain}"


def run(argv: List[str], check: bool = True, **kwargs: Any) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=check, capture_output=True, text=True, **kwargs)


def user_env(user: str) -> Dict[str, str]:
    home = f"{HOME_ROOT}/{user}"
    return {
        "HOME": home, "USER": user, "LOGNAME": user, "PM2_HOME": f"{home}/.pm2", "NODE_PATH": LAB_NODE_MODULES,
        "PATH": f"{NODE_BIN}:{VENV}/bin:/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
    }


def spawn_as(user: str, argv: List[str], env: Dict[str, str], cwd: str, log: Optional[str] = None) -> int:
    info = pwd.getpwnam(user)
    full_env = {**user_env(user), **env}
    out = open(log, "ab") if log else subprocess.DEVNULL
    proc = subprocess.Popen(
        ["setpriv", f"--reuid={info.pw_uid}", f"--regid={info.pw_gid}", "--init-groups", "--"] + argv, cwd=cwd, env=full_env, stdout=out, stderr=out,
        stdin=subprocess.DEVNULL, start_new_session=True,
    )
    return proc.pid


def run_as(user: str, argv: List[str], env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None, timeout: float = 60.0) -> subprocess.CompletedProcess:
    info = pwd.getpwnam(user)
    full_env = {**user_env(user), **(env or {})}
    return subprocess.run(
        ["setpriv", f"--reuid={info.pw_uid}", f"--regid={info.pw_gid}", "--init-groups", "--"] + argv, cwd=cwd or info.pw_dir, env=full_env, capture_output=True, text=True,
        timeout=timeout, check=False,
    )


def plan(count: int, seed: int) -> List[Project]:
    rng = random.Random(seed)
    names = [f"lab-{i:03d}" for i in range(1, count - len(PERSONAS) + 1)]
    pool: List[str] = []
    for archetype, share in ROTATION:
        pool.extend([archetype] * share)
    while len(pool) < len(names):
        pool.append("node-express")
    rng.shuffle(pool)
    projects: List[Project] = []
    index = 0
    for user, archetype in PERSONAS.items():
        projects.append(make_project(user, archetype, index, rng))
        index += 1
    for user, archetype in zip(names, pool):
        projects.append(make_project(user, archetype, index, rng))
        index += 1
    return projects


def make_project(user: str, archetype: str, index: int, rng: random.Random) -> Project:
    port = 20000 + index
    domain = f"{user.replace('lab-', '')}.{DOMAIN_SUFFIX}"
    project = Project(user=user, domain=domain, archetype=archetype, port=port, index=index)
    project.pm2 = archetype in PM2_ARCHETYPES
    project.vulnerable = False
    if archetype in ("node-noisy",):
        project.error_rate = 0.25
    elif archetype == "gov-node":
        project.error_rate = 0.03
        project.cpu_ms = 8
    elif archetype in ("node-express", "fastapi", "flask"):
        project.error_rate = round(rng.choice([0.0, 0.0, 0.0, 0.01, 0.02, 0.05]), 2)
        project.cpu_ms = rng.choice([0, 0, 1, 2, 4])
    elif archetype == "node-hightraffic":
        project.cpu_ms = 1
    return project


NODE_SERVER = r"""
'use strict';
const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const NAME = process.env.LAB_NAME || 'lab';
const PORT = parseInt(process.env.PORT || '3000', 10);
const ERROR_RATE = parseFloat(process.env.ERROR_RATE || '0');
const CPU_MS = parseInt(process.env.CPU_MS || '0', 10);
const KIND = process.env.LAB_KIND || 'node-express';
const sessions = new Map();
let counter = 0;
function burn(ms) { const end = Date.now() + ms; let x = 0; while (Date.now() < end) { x += Math.sqrt(x + 1); } return x; }
function logError(err, req, userId) {
  const line = { level: 50, time: Date.now(), msg: 'request failed', service: NAME, err: { type: err.name || 'Error', message: err.message, stack: err.stack }, req: { method: req.method, url: req.url } };
  if (userId !== undefined) line.userId = String(userId);
  process.stderr.write(JSON.stringify(line) + '\n');
}
function redisCmd(args, cb) {
  const sock = net.createConnection({ host: '127.0.0.1', port: 6379 });
  let buf = '';
  sock.setTimeout(1500);
  sock.on('connect', () => { sock.write('*' + args.length + '\r\n' + args.map(a => '$' + Buffer.byteLength(String(a)) + '\r\n' + a + '\r\n').join('')); });
  sock.on('data', d => { buf += d; sock.end(); });
  sock.on('timeout', () => { sock.destroy(); cb(new Error('redis timeout')); });
  sock.on('error', e => cb(e));
  sock.on('close', () => cb(null, buf));
}
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  counter += 1;
  const send = (code, body, type) => { res.writeHead(code, { 'content-type': type || 'application/json' }); res.end(typeof body === 'string' ? body : JSON.stringify(body)); };
  try {
    if (CPU_MS > 0) burn(CPU_MS);
    if (url.pathname === '/healthz') return send(200, { ok: true, name: NAME });
    if (url.pathname === '/') return send(200, '<html><body><h1>' + NAME + '</h1><p>' + KIND + '</p></body></html>', 'text/html');
    if (url.pathname === '/api/items') return send(200, { items: Array.from({ length: 40 }, (_, i) => ({ id: i, name: NAME + '-' + i })) });
    if (url.pathname === '/api/slow') { const ms = Math.min(parseInt(url.searchParams.get('ms') || '200', 10), 5000); return setTimeout(() => send(200, { slept: ms }), ms); }
    if (url.pathname === '/api/cpu') { const ms = Math.min(parseInt(url.searchParams.get('ms') || '50', 10), 2000); burn(ms); return send(200, { burned: ms }); }
    if (url.pathname === '/api/db') {
      const key = 'lab:' + NAME + ':' + (counter % 50);
      return redisCmd(['INCR', key], (err, out) => { if (err) { logError(err, req); return send(503, { error: 'db unavailable' }); } return send(200, { key, reply: out.trim() }); });
    }
    if (url.pathname === '/api/err') { if (Math.random() < Math.max(ERROR_RATE, parseFloat(url.searchParams.get('rate') || '0'))) throw new Error('Cannot read properties of undefined (reading \'profile\')'); return send(200, { ok: true }); }
    const prof = url.pathname.match(/^\/api\/user\/(\d+)\/profile$/);
    if (prof) { const id = parseInt(prof[1], 10); if (id % 7 === 0) { const e = new TypeError('Cannot read properties of null (reading \'plan\')'); logError(e, req, id); return send(500, { error: 'profile failed' }); } return send(200, { id, plan: 'basic' }); }
    if (url.pathname === '/api/login' && req.method === 'POST') { const sid = Math.random().toString(36).slice(2); sessions.set(sid, Date.now()); res.setHeader('set-cookie', 'sid=' + sid); return send(200, { ok: true }); }
    if (url.pathname === '/api/me') { const sid = (req.headers.cookie || '').replace(/^.*sid=([^;]+).*$/, '$1'); return sessions.has(sid) ? send(200, { me: true }) : send(401, { me: false }); }
    if (url.pathname === '/api/upload' && req.method === 'POST') { const chunks = []; req.on('data', c => chunks.push(c)); return req.on('end', () => { const dir = path.join(__dirname, 'uploads'); fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, 'u' + counter + '.bin'), Buffer.concat(chunks)); send(201, { stored: true }); }); }
    if (url.pathname === '/api/report') { burn(Math.max(CPU_MS, 120)); return send(200, { rows: 1000 }); }
    return send(404, { error: 'not found' });
  } catch (err) {
    logError(err, req);
    return send(500, { error: 'internal' });
  }
});
server.keepAliveTimeout = 65000;
server.listen(PORT, '127.0.0.1', () => { process.stdout.write(JSON.stringify({ level: 30, msg: 'listening', service: NAME, port: PORT }) + '\n'); });
process.on('uncaughtException', e => { process.stderr.write('Uncaught ' + e.stack + '\n'); });
"""

WORKER_NODE = r"""
'use strict';
const net = require('net');
const NAME = process.env.LAB_NAME || 'worker';
const STOP_AFTER_S = parseInt(process.env.STOP_AFTER_S || '0', 10);
const started = Date.now();
let processed = 0;
function redis(args, cb) {
  const s = net.createConnection({ host: '127.0.0.1', port: 6379 });
  s.setTimeout(1500);
  s.on('connect', () => s.write('*' + args.length + '\r\n' + args.map(a => '$' + Buffer.byteLength(String(a)) + '\r\n' + a + '\r\n').join('')));
  s.on('data', d => { s.end(); });
  s.on('error', () => cb && cb(false));
  s.on('close', () => cb && cb(true));
}
const timer = setInterval(() => {
  if (STOP_AFTER_S && (Date.now() - started) / 1000 > STOP_AFTER_S) return;
  processed += 1;
  redis(['LPUSH', 'lab:' + NAME + ':done', String(processed)], ok => { if (!ok) process.stderr.write('Error: worker redis failure\n'); });
  if (processed % 20 === 0) process.stdout.write(JSON.stringify({ level: 30, msg: 'processed', service: NAME, n: processed }) + '\n');
}, 1000);
process.on('SIGTERM', () => { clearInterval(timer); process.exit(0); });
"""

FASTAPI_APP = r"""
import os, random, time, json, sys
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
NAME = os.environ.get("LAB_NAME", "lab")
ERROR_RATE = float(os.environ.get("ERROR_RATE", "0"))
CPU_MS = int(os.environ.get("CPU_MS", "0"))
app = FastAPI()

def burn(ms):
    end = time.time() + ms / 1000.0
    x = 0.0
    while time.time() < end:
        x += (x + 1) ** 0.5

def log_error(exc, request, user_id=None):
    line = {"level": 50, "time": int(time.time() * 1000), "msg": "request failed", "service": NAME, "err": {"type": type(exc).__name__, "message": str(exc)}, "req": {"method": request.method, "url": str(request.url.path)}}
    if user_id is not None:
        line["userId"] = str(user_id)
    sys.stderr.write(json.dumps(line) + "\n")
    sys.stderr.flush()

@app.middleware("http")
async def cpu(request: Request, call_next):
    if CPU_MS:
        burn(CPU_MS)
    return await call_next(request)

@app.get("/healthz")
async def healthz():
    return {"ok": True, "name": NAME}

@app.get("/", response_class=HTMLResponse)
async def index():
    return "<html><body><h1>%s</h1></body></html>" % NAME

@app.get("/api/items")
async def items():
    return {"items": [{"id": i, "name": "%s-%d" % (NAME, i)} for i in range(40)]}

@app.get("/api/err")
async def err(request: Request, rate: float = 0.0):
    if random.random() < max(ERROR_RATE, rate):
        exc = KeyError("profile")
        log_error(exc, request)
        return JSONResponse({"error": "internal"}, status_code=500)
    return {"ok": True}

@app.get("/api/user/{uid}/profile")
async def profile(uid: int, request: Request):
    if uid % 7 == 0:
        log_error(ValueError("plan is null"), request, uid)
        return JSONResponse({"error": "profile failed"}, status_code=500)
    return {"id": uid, "plan": "basic"}

@app.get("/api/cpu")
async def cpu_endpoint(ms: int = 50):
    burn(min(ms, 2000))
    return {"burned": ms}
"""

FLASK_APP = r"""
import os, random, time, json, sys
from flask import Flask, jsonify, request
NAME = os.environ.get("LAB_NAME", "lab")
ERROR_RATE = float(os.environ.get("ERROR_RATE", "0"))
CPU_MS = int(os.environ.get("CPU_MS", "0"))
app = Flask(__name__)

def burn(ms):
    end = time.time() + ms / 1000.0
    x = 0.0
    while time.time() < end:
        x += (x + 1) ** 0.5

def log_error(exc, user_id=None):
    line = {"level": 50, "time": int(time.time() * 1000), "msg": "request failed", "service": NAME, "err": {"type": type(exc).__name__, "message": str(exc)}, "req": {"method": request.method, "url": request.path}}
    if user_id is not None:
        line["userId"] = str(user_id)
    sys.stderr.write(json.dumps(line) + "\n")
    sys.stderr.flush()

@app.before_request
def before():
    if CPU_MS:
        burn(CPU_MS)

@app.route("/healthz")
def healthz():
    return jsonify(ok=True, name=NAME)

@app.route("/")
def index():
    return "<html><body><h1>%s</h1></body></html>" % NAME

@app.route("/api/items")
def items():
    return jsonify(items=[{"id": i, "name": "%s-%d" % (NAME, i)} for i in range(40)])

@app.route("/api/err")
def err():
    if random.random() < max(ERROR_RATE, float(request.args.get("rate", "0"))):
        log_error(KeyError("profile"))
        return jsonify(error="internal"), 500
    return jsonify(ok=True)

@app.route("/api/user/<int:uid>/profile")
def profile(uid):
    if uid % 7 == 0:
        log_error(ValueError("plan is null"), uid)
        return jsonify(error="profile failed"), 500
    return jsonify(id=uid, plan="basic")
"""

PHP_INDEX = """<?php
header('Content-Type: text/html');
echo '<html><body><h1>' . htmlspecialchars(getenv('LAB_NAME') ?: 'php') . '</h1></body></html>';
"""

PHP_API = """<?php
header('Content-Type: application/json');
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path === '/healthz') { echo json_encode(['ok' => true]); exit; }
if (strpos($path, '/api/items') === 0) { $items = []; for ($i = 0; $i < 40; $i++) { $items[] = ['id' => $i]; } echo json_encode(['items' => $items]); exit; }
if (strpos($path, '/api/err') === 0) { if (mt_rand() / mt_getrandmax() < (float)(getenv('ERROR_RATE') ?: 0)) { error_log('PHP Fatal error:  Uncaught Error: Call to a member function on null in ' . __FILE__ . ':9'); http_response_code(500); echo json_encode(['error' => 'internal']); exit; } echo json_encode(['ok' => true]); exit; }
http_response_code(404);
echo json_encode(['error' => 'not found']);
"""


BUILD_SCRIPT = r"""
'use strict';
const end = Date.now() + parseInt(process.env.BUILD_MS || '8000', 10);
const hog = [];
while (Date.now() < end) { hog.push(Buffer.alloc(1024 * 1024 * 20, 1)); if (hog.length > 12) hog.shift(); let x = 0; for (let i = 0; i < 2e6; i++) x += Math.sqrt(i); }
console.log('build complete');
"""


def write_file(path: str, content: str, uid: int, gid: int, mode: int = 0o644) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def nginx_vhost(project: Project) -> str:
    log_dir = f"{project.home}/logs/nginx"
    common = f"""server {{
    listen 80;
    server_name {project.domain};
    root {project.docroot};
    access_log {log_dir}/access.log;
    error_log {log_dir}/error.log;
    client_max_body_size 20m;
"""
    if project.archetype in ("static", "static-build"):
        return common + "    location / {\n        try_files $uri $uri/ /index.html;\n    }\n}\n"
    return common + f"""    location / {{
        proxy_pass http://127.0.0.1:{project.port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Connection "";
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
    }}
}}
"""


def build_project(project: Project) -> None:
    user = project.user
    try:
        info = pwd.getpwnam(user)
    except KeyError:
        run(["useradd", "-m", "-s", "/bin/bash", user])
        info = pwd.getpwnam(user)
    uid, gid = info.pw_uid, info.pw_gid
    os.chmod(project.home, 0o711)
    for sub in ("htdocs", "logs", "logs/nginx", ".ssh", ".pm2"):
        os.makedirs(os.path.join(project.home, sub), exist_ok=True)
    os.chmod(f"{project.home}/.ssh", 0o700)
    os.makedirs(project.docroot, exist_ok=True)
    kind = project.archetype
    env_secret = hashlib.sha256(f"{user}-secret".encode()).hexdigest()
    write_file(f"{project.docroot}/.env", f"DATABASE_URL=postgres://{user}:{env_secret[:16]}@127.0.0.1:5432/{user}\nSESSION_SECRET={env_secret}\nAPI_TOKEN=tok_{env_secret[16:40]}\n", uid, gid, 0o600)
    write_file(f"{project.home}/.ssh/id_ed25519", f"-----BEGIN OPENSSH PRIVATE KEY-----\nLAB-ONLY-PLACEHOLDER-{env_secret[:32]}\n-----END OPENSSH PRIVATE KEY-----\n", uid, gid, 0o600)
    if kind in ("static", "static-build"):
        write_file(f"{project.docroot}/index.html", f"<html><body><h1>{project.domain}</h1></body></html>\n", uid, gid)
        for n in range(3):
            write_file(f"{project.docroot}/assets/app{n}.js", f"console.log('{project.domain} {n}');\n", uid, gid)
        if kind == "static-build":
            write_file(f"{project.docroot}/build.js", BUILD_SCRIPT, uid, gid)
            write_file(f"{project.docroot}/package.json", json.dumps({"name": user, "scripts": {"build": "node build.js"}}), uid, gid)
    elif kind in ("fastapi", "fastapi-db"):
        write_file(f"{project.docroot}/main.py", FASTAPI_APP, uid, gid)
    elif kind == "flask":
        write_file(f"{project.docroot}/app.py", FLASK_APP, uid, gid)
    elif kind.startswith("php"):
        write_file(f"{project.docroot}/index.php", PHP_INDEX, uid, gid)
        write_file(f"{project.docroot}/api.php", PHP_API, uid, gid)
    elif kind.startswith("worker"):
        write_file(f"{project.docroot}/worker.js", WORKER_NODE, uid, gid)
    else:
        write_file(f"{project.docroot}/server.js", NODE_SERVER, uid, gid)
        write_file(f"{project.docroot}/package.json", json.dumps({"name": user, "version": "1.0.0", "main": "server.js", "scripts": {"start": "node server.js", "build": "node build.js"}}), uid, gid)
        write_file(f"{project.docroot}/build.js", BUILD_SCRIPT, uid, gid)
        if project.pm2:
            env = {"PORT": project.port, "LAB_NAME": user, "LAB_KIND": kind, "ERROR_RATE": project.error_rate, "CPU_MS": project.cpu_ms, "NODE_ENV": "production"}
            eco = "module.exports = { apps: [{ name: %s, script: 'server.js', cwd: %s, env: %s, max_memory_restart: '300M' }] };\n" % (json.dumps(user), json.dumps(project.docroot), json.dumps(env))
            write_file(f"{project.docroot}/ecosystem.config.js", eco, uid, gid)
    os.chmod(project.docroot, 0o755)
    run(["chown", "-R", f"{uid}:{gid}", f"{project.home}/htdocs", f"{project.home}/.ssh", f"{project.home}/.pm2"])
    write_file(f"{NGINX_CONF_DIR}/{project.domain}.conf", nginx_vhost(project), 0, 0, 0o644)
    for sub in ("logs", "logs/nginx"):
        os.chmod(os.path.join(project.home, sub), 0o755)
    bare = f"{GIT_DIR}/{user}.git"
    if not os.path.isdir(bare):
        run(["git", "init", "--bare", "-q", bare])
        run(["chown", "-R", f"{uid}:{gid}", bare])
    if not os.path.isdir(os.path.join(project.docroot, ".git")):
        run_as(user, ["git", "init", "-q", "-b", "main"], cwd=project.docroot)
        run_as(user, ["git", "config", "user.email", f"{user}@lab.test"], cwd=project.docroot)
        run_as(user, ["git", "config", "user.name", user], cwd=project.docroot)
        run_as(user, ["git", "add", "-A"], cwd=project.docroot)
        run_as(user, ["git", "commit", "-q", "-m", "initial"], cwd=project.docroot)
        run_as(user, ["git", "remote", "add", "origin", bare], cwd=project.docroot)
        run_as(user, ["git", "push", "-q", "-u", "origin", "main"], cwd=project.docroot)


def load_projects() -> List[Project]:
    with open(STATE, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return [Project(**p) for p in raw["projects"]]


def cmd_build(args: argparse.Namespace) -> None:
    os.makedirs(RUN_DIR, exist_ok=True)
    os.makedirs(GIT_DIR, exist_ok=True)
    os.makedirs(NGINX_CONF_DIR, exist_ok=True)
    for stale in ("default",):
        path = os.path.join(NGINX_CONF_DIR, stale)
        if os.path.exists(path):
            os.remove(path)
    with open("/etc/profile.d/lab-path.sh", "w", encoding="utf-8") as handle:
        handle.write(f'export PATH="{NODE_BIN}:{VENV}/bin:$PATH"\nexport NODE_PATH="{LAB_NODE_MODULES}"\n')
    projects = plan(args.projects, args.seed)
    for project in projects:
        build_project(project)
    hosts = "".join(f"127.0.0.1 {p.domain}\n" for p in projects)
    with open("/etc/hosts", "r", encoding="utf-8") as handle:
        existing = [l for l in handle.read().splitlines(True) if not l.rstrip().endswith(f".{DOMAIN_SUFFIX}")]
    with open("/etc/hosts", "w", encoding="utf-8") as handle:
        handle.write("".join(existing) + hosts)
    nginx_main = """user www-data;
worker_processes 2;
worker_rlimit_nofile 20000;
pid /run/nginx-lab.pid;
events { worker_connections 8192; multi_accept on; }
http {
    sendfile on;
    keepalive_timeout 65;
    keepalive_requests 10000;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    server { listen 80 default_server; server_name _; return 444; }
    include /etc/nginx/sites-enabled/*.conf;
}
"""
    with open("/etc/nginx/nginx.conf", "w", encoding="utf-8") as handle:
        handle.write(nginx_main)
    with open(STATE, "w", encoding="utf-8") as handle:
        json.dump({"seed": args.seed, "created": time.time(), "projects": [asdict(p) for p in projects]}, handle, indent=1)
    counts: Dict[str, int] = {}
    for p in projects:
        counts[p.archetype] = counts.get(p.archetype, 0) + 1
    print(json.dumps({"projects": len(projects), "archetypes": counts, "pm2_users": sum(1 for p in projects if p.pm2)}, indent=1))


def join_cgroup(pid: int, memory_bytes: int, cpus: str) -> None:
    for controller, settings in (("memory", {"memory.limit_in_bytes": str(memory_bytes), "memory.memsw.limit_in_bytes": None}), ("cpuset", {"cpuset.cpus": cpus, "cpuset.mems": "0"})):
        path = f"/sys/fs/cgroup/{controller}/{CGROUP_NAME}"
        os.makedirs(path, exist_ok=True)
        for key, value in settings.items():
            if value is None:
                continue
            try:
                with open(os.path.join(path, key), "w", encoding="utf-8") as handle:
                    handle.write(value)
            except OSError:
                pass
        with open(os.path.join(path, "cgroup.procs"), "w", encoding="utf-8") as handle:
            handle.write(str(pid))


def start_project(project: Project) -> Optional[int]:
    user = project.user
    kind = project.archetype
    logdir = f"{project.home}/logs"
    env = {"PORT": str(project.port), "LAB_NAME": user, "LAB_KIND": kind, "ERROR_RATE": str(project.error_rate), "CPU_MS": str(project.cpu_ms), "NODE_ENV": "production"}
    if kind in ("static", "static-build"):
        return None
    if project.pm2:
        result = run_as(user, ["pm2", "start", "ecosystem.config.js", "--update-env"], env=env, cwd=project.docroot, timeout=120)
        if result.returncode != 0:
            print(f"pm2 start failed for {user}: {result.stderr[:200]}", file=sys.stderr)
        run_as(user, ["pm2", "save", "--force"], cwd=project.docroot, timeout=60)
        return None
    if kind.startswith("php"):
        return spawn_as(user, ["php", "-S", f"127.0.0.1:{project.port}", "-t", project.docroot], env, project.docroot, f"{logdir}/app.log")
    if kind in ("fastapi", "fastapi-db"):
        return spawn_as(user, [f"{VENV}/bin/uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(project.port), "--log-level", "warning"], env, project.docroot, f"{logdir}/app.log")
    if kind == "flask":
        return spawn_as(user, [f"{VENV}/bin/gunicorn", "-b", f"127.0.0.1:{project.port}", "-w", "1", "--log-level", "warning", "app:app"], env, project.docroot, f"{logdir}/app.log")
    if kind.startswith("worker"):
        if user == "lab-worker":
            env["STOP_AFTER_S"] = "0"
        return spawn_as(user, [f"{NODE_BIN}/node", "worker.js"], env, project.docroot, f"{logdir}/app.log")
    return spawn_as(user, [f"{NODE_BIN}/node", "server.js"], env, project.docroot, f"{logdir}/app.log")


def nginx_running() -> bool:
    try:
        with open("/run/nginx-lab.pid", "r", encoding="utf-8") as handle:
            os.kill(int(handle.read().strip()), 0)
        return True
    except (OSError, ValueError):
        return False


def cmd_start(args: argparse.Namespace) -> None:
    projects = load_projects()
    if args.profile == "small":
        join_cgroup(os.getpid(), int(args.memory_gb * (1 << 30)), args.cpus)
    os.makedirs(RUN_DIR, exist_ok=True)
    if shutil.which("redis-server") and run(["redis-cli", "ping"], check=False).stdout.strip() != "PONG":
        subprocess.Popen(["redis-server", "--port", "6379", "--save", "", "--appendonly", "no", "--maxmemory", "256mb", "--daemonize", "yes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
    check = run(["nginx", "-t"], check=False)
    if check.returncode != 0:
        print(check.stderr, file=sys.stderr)
        sys.exit(2)
    if not nginx_running():
        if os.path.exists("/run/nginx-lab.pid"):
            os.remove("/run/nginx-lab.pid")
        subprocess.run(["nginx"], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    pids: Dict[str, int] = {}
    batch = max(1, args.batch)
    started = 0
    for project in projects:
        pid = start_project(project)
        if pid:
            pids[project.user] = pid
        started += 1
        if started % batch == 0:
            time.sleep(args.pause)
    with open(os.path.join(RUN_DIR, "pids.json"), "w", encoding="utf-8") as handle:
        json.dump(pids, handle)
    print(json.dumps({"started": started, "background_pids": len(pids)}))


def cmd_stop(args: argparse.Namespace) -> None:
    projects = load_projects()
    for project in projects:
        if project.pm2:
            run_as(project.user, ["pm2", "kill"], timeout=60)
    pid_file = os.path.join(RUN_DIR, "pids.json")
    if os.path.exists(pid_file):
        with open(pid_file, "r", encoding="utf-8") as handle:
            for pid in json.load(handle).values():
                try:
                    os.killpg(pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
    time.sleep(1)
    if nginx_running():
        run(["nginx", "-s", "quit"], check=False)
    print("stopped")


def cmd_status(args: argparse.Namespace) -> None:
    projects = load_projects()
    lab_users = {p.user for p in projects}
    uids = {pwd.getpwnam(u).pw_uid for u in lab_users}
    count = 0
    rss = 0
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            with open(f"/proc/{entry.name}/status", "r", encoding="utf-8") as handle:
                fields = dict(line.split(":", 1) for line in handle.read().splitlines() if ":" in line)
            if int(fields["Uid"].split()[0]) in uids:
                count += 1
                rss += int(fields.get("VmRSS", "0 kB").split()[0])
        except (OSError, ValueError, KeyError):
            continue
    healthy = 0
    sample = projects[: args.sample] if args.sample else projects
    for project in sample:
        if project.archetype in ("static", "static-build"):
            result = run(["curl", "-s", "-o", "/dev/null", "-m", "3", "-w", "%{http_code}", "-H", f"Host: {project.domain}", "http://127.0.0.1/"], check=False)
        elif project.archetype.startswith("worker"):
            continue
        else:
            result = run(["curl", "-s", "-o", "/dev/null", "-m", "3", "-w", "%{http_code}", "-H", f"Host: {project.domain}", "http://127.0.0.1/"], check=False)
        if result.stdout.strip().startswith("2"):
            healthy += 1
    print(json.dumps({"projects": len(projects), "lab_processes": count, "lab_rss_mb": round(rss / 1024.0, 1), "sampled_ok": healthy, "sampled": len(sample)}))


def cmd_destroy(args: argparse.Namespace) -> None:
    try:
        projects = load_projects()
    except OSError:
        projects = []
    cmd_stop(args) if projects else None
    for project in projects:
        run(["pkill", "-9", "-u", project.user], check=False)
        run(["userdel", "-r", "-f", project.user], check=False)
        path = f"{NGINX_CONF_DIR}/{project.domain}.conf"
        if os.path.exists(path):
            os.remove(path)
    shutil.rmtree(LAB_ROOT, ignore_errors=True)
    print("destroyed")


def main() -> None:
    parser = argparse.ArgumentParser(prog="labctl")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--projects", type=int, default=127)
    b.add_argument("--seed", type=int, default=2026)
    s = sub.add_parser("start")
    s.add_argument("--profile", choices=["small", "none"], default="small")
    s.add_argument("--memory-gb", type=float, default=8.0)
    s.add_argument("--cpus", default="0-2")
    s.add_argument("--batch", type=int, default=6)
    s.add_argument("--pause", type=float, default=1.0)
    sub.add_parser("stop")
    t = sub.add_parser("status")
    t.add_argument("--sample", type=int, default=0)
    sub.add_parser("destroy")
    args = parser.parse_args()
    {"build": cmd_build, "start": cmd_start, "stop": cmd_stop, "status": cmd_status, "destroy": cmd_destroy}[args.cmd](args)


if __name__ == "__main__":
    main()
