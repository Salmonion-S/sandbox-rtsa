from __future__ import annotations

import argparse
import asyncio
import dataclasses
import ipaddress
import json
import logging
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RESULTS = os.path.join(ROOT, "validation", "results")
CASE_DIR = os.path.join(RESULTS, "command_campaign")
LAB_STATE = "/var/lab-rtsa/projects.json"
sys.path.insert(0, ROOT)
sys.dont_write_bytecode = True

MARK = "rtsaZQ"
ADMIN_ROLE = 111
CRITICAL_ROLE = 222
OTHER_ROLE = 333
REQUESTER_ID = 1001
OTHER_ID = 2002
GUILD_ID = 4242
SECRETS = {
    "RTSA_DISCORD_BOT_TOKEN": "campaign-discord-token-0123456789abcdef",
    "RTSA_CLOUDFLARE_API_TOKEN": "campaign-cloudflare-token-0123456789abcdef",
    "RTSA_LB_REPORT_KEY": "campaign-lb-report-key-0123456789abcdef",
}
HOSTILE_STR = {
    "shell_semicolon": f"x;touch /tmp/{MARK}",
    "shell_subst": f"$(touch /tmp/{MARK})",
    "shell_backtick": f"`touch /tmp/{MARK}`",
    "shell_pipe": f"x|touch /tmp/{MARK}",
    "path_traversal": f"../../../../etc/{MARK}",
    "absolute_path": f"/etc/{MARK}",
    "option_injection": f"--{MARK}=1",
    "newline": f"ok\n{MARK}",
    "crlf": f"ok\r\n{MARK}: 1",
    "nul_byte": f"ok\x00{MARK}",
    "overlong": "a" * 4096 + MARK,
    "unicode_confusable": f"аpp‮{MARK}.lab.test",
    "glob": f"*{MARK}*",
    "space": f"ok {MARK}",
    "empty": "",
    "format_string": f"%s%n{{0.__class__}}{MARK}",
    "mention": f"@everyone {MARK}",
    "role_mention": f"<@&{111}> {MARK}",
}
HOSTILE_INT = {"negative": -1, "zero": 0, "too_large": 70000, "int64": 2 ** 63}
SHELLS = {"sh", "bash", "dash", "zsh", "ksh"}
READ_ONLY_VERBS = {
    "nginx": {"-t", "-T", "-V", "-v"},
    "systemctl": {"status", "is-active", "is-enabled", "is-failed", "show", "list-units", "list-unit-files", "cat", "list-timers"},
    "pm2": {"jlist", "list", "ls", "describe", "show", "prettylist", "logs", "ping", "info", "env", "--version", "-v"},
    "git": {"status", "log", "rev-parse", "diff", "show", "branch", "remote", "config", "ls-files", "rev-list", "describe", "for-each-ref", "fetch", "--version", "ls-remote"},
    "iptables": {"-L", "-S", "-nL", "--list", "-C"},
    "ip6tables": {"-L", "-S", "-nL", "--list", "-C"},
    "ipset": {"list", "test", "-L"},
    "nft": {"list"},
    "certbot": {"certificates"},
    "crontab": {"-l"},
    "fail2ban-client": {"status", "get", "ping"},
    "ufw": {"status"},
    "docker": {"ps", "inspect", "version", "info", "logs"},
}
MUTATING_VERBS = {
    "nginx": {"-s"},
    "systemctl": {"restart", "reload", "stop", "start", "enable", "disable", "mask", "unmask", "kill", "daemon-reload", "try-restart", "reload-or-restart"},
    "pm2": {"restart", "reload", "stop", "start", "delete", "del", "kill", "save", "startup", "unstartup", "resurrect", "flush", "update", "reset", "scale"},
    "git": {"pull", "checkout", "reset", "merge", "clean", "push", "stash", "rebase", "switch", "commit", "init", "clone"},
    "iptables": {"-A", "-I", "-D", "-F", "-X", "-N", "-R", "-P", "-Z", "--append", "--insert", "--delete", "--flush"},
    "ip6tables": {"-A", "-I", "-D", "-F", "-X", "-N", "-R", "-P", "-Z", "--append", "--insert", "--delete", "--flush"},
    "ipset": {"add", "del", "create", "destroy", "flush", "-A", "-D", "-N", "-X", "-F"},
    "nft": {"add", "delete", "flush", "insert", "replace"},
    "docker": {"stop", "restart", "rm", "kill", "start", "pause", "unpause"},
    "certbot": {"certonly", "renew", "install", "delete", "revoke", "run", "--nginx"},
    "crontab": {"-r", "-e"},
    "fail2ban-client": {"set", "unban", "reload", "stop", "start"},
    "ufw": {"allow", "deny", "delete", "enable", "disable", "reject", "limit"},
}
READ_ONLY_TOOLS = {
    "ss", "ps", "id", "getent", "df", "free", "uptime", "journalctl", "tail", "cat", "ls", "stat", "openssl", "dig", "host", "nslookup", "lsof", "who", "w", "last",
    "lastlog", "du", "find", "head", "readlink", "which", "node", "npm", "php", "php-fpm", "uname", "hostname", "whoami", "curl", "wget", "timeout", "nproc", "lscpu",
    "env", "printenv", "true", "date", "grep", "awk", "sed", "wc", "sort", "uniq", "netstat", "lsblk", "mount", "sha256sum", "md5sum", "file", "test", "[",
}
READ_ONLY_VERBS.update({"npm": {"--version", "-v", "ls", "list", "view", "config"}, "node": {"--version", "-v"}, "php": {"-v", "--version", "-m", "-i", "-l"}})
MUTATING_VERBS.update({"npm": {"run", "install", "ci", "build", "exec", "start", "update", "uninstall", "i", "rebuild"}, "node": set(), "php": set()})
for _tool in ("node", "npm", "php"):
    READ_ONLY_TOOLS.discard(_tool)


class Recorder:
    def __init__(self, sandbox: str) -> None:
        self.sandbox = os.path.realpath(sandbox)
        self.armed = False
        self.events: List[Dict[str, Any]] = []
        self.local = threading.local()

    def allowed(self, path: Any) -> bool:
        if isinstance(path, int):
            return True
        try:
            text = os.fsdecode(path)
        except (TypeError, ValueError):
            return False
        if text.startswith("file:"):
            text = text[5:].split("?", 1)[0]
        if text in ("/dev/null", ":memory:", ""):
            return True
        try:
            real = os.path.realpath(text)
        except (OSError, ValueError):
            return False
        return real == self.sandbox or real.startswith(self.sandbox + os.sep)

    def add(self, kind: str, blocked: bool, **detail: Any) -> None:
        clean = {k: _short(v) for k, v in detail.items()}
        self.events.append({"kind": kind, "blocked": blocked, "t": round(time.monotonic(), 4), **clean})


RECORDER: Optional[Recorder] = None


class CaptureHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        rec = RECORDER
        if rec is None or not rec.armed or record.levelno < logging.ERROR:
            return
        detail = record.getMessage()[:300]
        if record.exc_info and record.exc_info[1] is not None:
            exc = record.exc_info[1]
            tb = traceback.extract_tb(record.exc_info[2])
            where = next((f"{os.path.relpath(f.filename, ROOT)}:{f.lineno}" for f in reversed(tb) if f.filename.startswith(ROOT)), "?")
            detail += f" | {type(exc).__name__}: {str(exc)[:200]} @ {where}"
        rec.add("LOGGED_ERROR", False, logger=record.name, detail=detail)
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
PATH_EVENTS = {
    "os.remove": ("FS_DELETE", (0,)), "os.rmdir": ("FS_DELETE", (0,)), "shutil.rmtree": ("FS_DELETE", (0,)), "os.rename": ("FS_RENAME", (0, 1)),
    "os.mkdir": ("FS_MKDIR", (0,)), "os.chmod": ("FS_CHMOD", (0,)), "os.chown": ("FS_CHOWN", (0,)), "os.truncate": ("FS_WRITE", (0,)),
    "os.symlink": ("FS_LINK", (0, 1)), "os.link": ("FS_LINK", (0, 1)), "os.utime": ("FS_UTIME", (0,)), "os.setxattr": ("FS_XATTR", (0,)),
    "os.removexattr": ("FS_XATTR", (0,)), "shutil.copyfile": ("FS_WRITE", (1,)), "shutil.copymode": ("FS_CHMOD", (1,)), "shutil.copystat": ("FS_CHMOD", (1,)),
    "shutil.copytree": ("FS_WRITE", (1,)), "shutil.move": ("FS_RENAME", (0, 1)), "shutil.chown": ("FS_CHOWN", (0,)), "os.mknod": ("FS_WRITE", (0,)), "os.mkfifo": ("FS_WRITE", (0,)),
}


def _short(value: Any, limit: int = 600) -> Any:
    if isinstance(value, (bytes, bytearray)):
        value = os.fsdecode(bytes(value))
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + f"...(+{len(value) - limit})"
    if isinstance(value, (list, tuple)):
        return [_short(v, 300) for v in list(value)[:40]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _short(repr(value), limit)


def _loopback(host: Any) -> bool:
    if host in (None, "", "localhost", b"localhost"):
        return True
    try:
        return ipaddress.ip_address(os.fsdecode(host) if isinstance(host, bytes) else str(host)).is_loopback
    except ValueError:
        return False


def _is_ip(host: Any) -> bool:
    try:
        ipaddress.ip_address(os.fsdecode(host) if isinstance(host, bytes) else str(host))
        return True
    except ValueError:
        return False


def _resolve_dir_fd(path: Any, args: Tuple[Any, ...], index: int, event: str) -> Any:
    if not isinstance(path, (str, bytes)) or os.path.isabs(os.fsdecode(path)):
        return path
    if event == "os.rename":
        dir_fd = args[2 + index] if 2 + index < len(args) else None
    else:
        dir_fd = args[-1]
    if isinstance(dir_fd, int) and dir_fd >= 0:
        try:
            return os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), os.fsdecode(path))
        except OSError:
            return path
    return path


def _dir_fd_base() -> Optional[str]:
    frame = sys._getframe(2)
    while frame is not None:
        dir_fd = frame.f_locals.get("dir_fd") if frame.f_code.co_name == "_atomic_replace" else None
        if isinstance(dir_fd, int):
            try:
                return os.readlink(f"/proc/self/fd/{dir_fd}")
            except OSError:
                return None
        frame = frame.f_back
    return None


def audit_hook(event: str, args: Tuple[Any, ...]) -> None:
    rec = RECORDER
    if rec is None or not rec.armed or getattr(rec.local, "busy", False):
        return
    rec.local.busy = True
    try:
        _dispatch(rec, event, args)
    finally:
        rec.local.busy = False


def _dispatch(rec: Recorder, event: str, args: Tuple[Any, ...]) -> None:
    if event == "open":
        path, mode, flags = args
        if path is None or isinstance(path, int):
            return
        writing = bool(mode and any(c in mode for c in "wax+")) or bool(flags and flags & WRITE_FLAGS)
        text = os.fsdecode(path) if isinstance(path, (bytes, str)) else str(path)
        if not os.path.isabs(text):
            base = _dir_fd_base()
            if base:
                text = os.path.join(base, text)
                path = text
        if not writing:
            if MARK in text:
                rec.add("FS_READ_INPUT_PATH", False, path=text)
            return
        if rec.allowed(path):
            rec.add("FS_WRITE_SANDBOX", False, path=text)
            return
        rec.add("FS_WRITE", True, path=text)
        raise PermissionError(f"campaign sandbox: write to {text} blocked")
    if event in PATH_EVENTS:
        kind, positions = PATH_EVENTS[event]
        paths = [_resolve_dir_fd(args[i], args, i, event) for i in positions if i < len(args)]
        if all(rec.allowed(p) for p in paths):
            rec.add(kind + "_SANDBOX", False, paths=[str(p) for p in paths])
            return
        rec.add(kind, True, paths=[os.fsdecode(p) if isinstance(p, (str, bytes)) else str(p) for p in paths], event=event)
        raise PermissionError(f"campaign sandbox: {event} blocked")
    if event == "subprocess.Popen":
        executable, argv, cwd, env = args
        rec.add("SUBPROCESS_SYNC", True, argv=list(argv) if isinstance(argv, (list, tuple)) else [str(argv)], cwd=cwd)
        raise PermissionError("campaign sandbox: synchronous subprocess blocked")
    if event in ("os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty", "pty.spawn"):
        rec.add("PROCESS_SPAWN", True, event=event, args=list(args))
        raise PermissionError(f"campaign sandbox: {event} blocked")
    if event in ("os.kill", "os.killpg"):
        pid, sig = args
        if sig == 0:
            rec.add("SIGNAL_PROBE", False, pid=pid)
            return
        rec.add("KILL", True, pid=pid, sig=int(sig), event=event)
        raise PermissionError("campaign sandbox: signal blocked")
    if event == "signal.pthread_kill":
        if args[1] != 0:
            rec.add("KILL", True, thread=args[0], sig=int(args[1]), event=event)
            raise PermissionError("campaign sandbox: signal blocked")
        return
    if event == "socket.getaddrinfo":
        host = args[0]
        if _loopback(host) or _is_ip(host):
            return
        text = os.fsdecode(host) if isinstance(host, bytes) else str(host)
        if text.endswith(".lab.test"):
            rec.add("DNS_LAB", False, host=text)
            return
        rec.add("DNS", True, host=text, port=args[1])
        raise socket.gaierror(socket.EAI_NONAME, f"campaign sandbox: DNS lookup for {text} blocked")
    if event == "socket.connect":
        address = args[1]
        if isinstance(address, (str, bytes)):
            rec.add("NET_UNIX", True, path=os.fsdecode(address) if isinstance(address, bytes) else address)
            raise PermissionError("campaign sandbox: unix socket connect blocked")
        host = address[0] if isinstance(address, tuple) and address else address
        if _loopback(host):
            rec.add("NET_LOCAL", False, address=list(address) if isinstance(address, tuple) else address)
            return
        rec.add("NETWORK", True, address=list(address) if isinstance(address, tuple) else address)
        raise ConnectionRefusedError("campaign sandbox: network connect blocked")
    if event in ("socket.sendto", "socket.sendmsg"):
        address = args[-1]
        if isinstance(address, tuple) and address and not _loopback(address[0]):
            rec.add("NETWORK", True, address=list(address), event=event)
            raise PermissionError("campaign sandbox: datagram blocked")
        return
    if event == "socket.bind":
        address = args[1]
        host = address[0] if isinstance(address, tuple) and address else address
        rec.add("NET_BIND", not _loopback(host), address=list(address) if isinstance(address, tuple) else address)
        if not _loopback(host):
            raise PermissionError("campaign sandbox: bind blocked")
        return
    if event == "sqlite3.connect":
        database = args[0]
        if rec.allowed(database):
            return
        rec.add("DB_OPEN", True, database=str(database))
        raise PermissionError("campaign sandbox: sqlite outside sandbox blocked")
    if event in ("resource.setrlimit", "resource.prlimit", "os.chdir", "os.chroot"):
        rec.add("PROCESS_STATE", True, event=event, args=list(args))
        raise PermissionError(f"campaign sandbox: {event} blocked")
    if event in ("os.putenv", "os.unsetenv"):
        rec.add("ENV_MUTATION", False, event=event, key=args[0])
        return
    if event == "urllib.Request":
        rec.add("HTTP_REQUEST", False, url=args[0], method=args[3] if len(args) > 3 else None)


class FakeStream:
    async def readline(self) -> bytes:
        return b""

    async def read(self, n: int = -1) -> bytes:
        return b""

    def at_eof(self) -> bool:
        return True

    def write(self, data: bytes) -> None:
        return None

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


DISCOVERY_OUTPUT = "/opt/node22/bin/node\n---\n/opt/node22/bin/pm2\n---\n/opt/node22/bin/npm\n---\nv22.12.0\n---\n5.4.3\n"


HOST_STATE: Dict[str, Any] = {"rules": set(), "units": {}, "enabled": {}, "pm2": {}, "docker": {}}


def reset_host_state() -> None:
    HOST_STATE.update({"rules": set(), "units": {}, "enabled": {}, "pm2": {}, "docker": {}})


def _inner_argv(argv: List[str]) -> List[str]:
    exe = os.path.basename(argv[0]) if argv else ""
    if exe in SHELLS and "-c" in argv:
        idx = argv.index("-c")
        try:
            return shlex.split(argv[idx + 1]) if idx + 1 < len(argv) else []
        except ValueError:
            return []
    return argv


def fake_output(argv: List[str]) -> Tuple[int, str, str]:
    text = " ".join(argv)
    if "command -v node" in text:
        return 0, DISCOVERY_OUTPUT, ""
    inner = _inner_argv(argv)
    exe = os.path.basename(inner[0]) if inner else ""
    rest = inner[1:]
    if exe in ("iptables", "ip6tables"):
        flag = next((a for a in rest if a in ("-A", "-I", "-D", "-C", "--append", "--insert", "--delete", "--check")), None)
        spec = exe + " " + " ".join(a for a in rest if a not in ("-A", "-I", "-D", "-C", "--append", "--insert", "--delete", "--check", "-w"))
        if flag in ("-A", "-I", "--append", "--insert"):
            HOST_STATE["rules"].add(spec)
        elif flag in ("-D", "--delete"):
            HOST_STATE["rules"].discard(spec)
        elif flag in ("-C", "--check"):
            return (0, "", "") if spec in HOST_STATE["rules"] else (1, "", "iptables: Bad rule (does a matching rule exist in that chain?).")
        return 0, "", ""
    if exe == "ipset" and "test" in rest:
        return 1, "", ""
    if exe == "systemctl" and rest:
        verb = next((a for a in rest if not a.startswith("-")), "")
        unit = next((a for a in reversed(rest) if not a.startswith("-") and a != verb), "")
        while unit.endswith(".service.service"):
            unit = unit[: -len(".service")]
        if verb == "stop":
            HOST_STATE["units"][unit] = "inactive"
        elif verb in ("start", "restart", "try-restart", "reload-or-restart"):
            HOST_STATE["units"][unit] = "active"
        elif verb == "disable":
            HOST_STATE["enabled"][unit] = False
        elif verb == "enable":
            HOST_STATE["enabled"][unit] = True
        elif verb == "is-active":
            return (0, "active\n", "") if HOST_STATE["units"].get(unit, "active") == "active" else (3, "inactive\n", "")
        elif verb == "is-enabled":
            return (0, "enabled\n", "") if HOST_STATE["enabled"].get(unit, True) else (1, "disabled\n", "")
        return 0, "", ""
    if exe == "pm2" and rest:
        verb = rest[0]
        target = rest[1] if len(rest) > 1 else ""
        if verb == "jlist":
            apps = [{"name": n, "pid": 4300 + i if st == "online" else 0, "pm2_env": {"status": st, "restart_time": 1, "pm_uptime": 1700000000000}, "monit": {"memory": 1, "cpu": 0}}
                    for i, (n, st) in enumerate(sorted(HOST_STATE["pm2"].items()))]
            return 0, json.dumps(apps), ""
        if verb == "ping":
            return 0, "{ msg: 'pong' }\n", ""
        if verb == "stop":
            HOST_STATE["pm2"][target] = "stopped"
        elif verb in ("start", "restart", "reload"):
            HOST_STATE["pm2"][target] = "online"
        elif verb in ("delete", "del"):
            HOST_STATE["pm2"].pop(target, None)
        return 0, "", ""
    if exe == "docker" and rest:
        verb = rest[0]
        target = rest[-1]
        if verb == "stop":
            HOST_STATE["docker"][target] = False
        elif verb in ("restart", "start"):
            HOST_STATE["docker"][target] = True
        elif verb == "inspect":
            return 0, ("true" if HOST_STATE["docker"].get(target, True) else "false") + "\n", ""
        return 0, "", ""
    if exe == "node" and "--version" in rest:
        return 0, "v22.12.0\n", ""
    if exe == "git":
        if "--show-current" in rest or "--abbrev-ref" in rest:
            return 0, "main\n", ""
        if "get-url" in rest:
            return 0, "git@github.com:lab/app.git\n", ""
        if "rev-list" in rest:
            return 0, "0\t2\n", ""
        if "log" in rest:
            return 0, "abc1234 initial\n", ""
        return 0, "", ""
    if exe == "nginx" and "-t" in rest:
        return 0, "", "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful\n"
    return 0, "", ""


class FakeProc:
    def __init__(self, argv: Optional[List[str]] = None) -> None:
        rc, out, err = fake_output([str(a) for a in (argv or [])])
        self.returncode = rc
        self._out = out.encode()
        self._err = err.encode()
        self.pid = 4242424
        self.stdout = FakeStream()
        self.stderr = FakeStream()
        self.stdin = FakeStream()

    async def communicate(self, input: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        return self._out, self._err

    async def wait(self) -> int:
        return self.returncode

    def kill(self) -> None:
        return None

    def terminate(self) -> None:
        return None

    def send_signal(self, sig: int) -> None:
        return None


def install_subprocess_fakes() -> None:
    async def fake_exec(program: Any, *args: Any, **kwargs: Any) -> FakeProc:
        rec = RECORDER
        if rec is not None and rec.armed:
            rec.add("SUBPROCESS", False, argv=[str(program)] + [str(a) for a in args], cls=classify_subprocess([str(program)] + [str(a) for a in args]), user=kwargs.get("user"), cwd=kwargs.get("cwd"),
                    env_keys=sorted((kwargs.get("env") or {}).keys()) if kwargs.get("env") is not None else None)
        return FakeProc([str(program)] + [str(a) for a in args])

    async def fake_shell(cmd: Any, **kwargs: Any) -> FakeProc:
        rec = RECORDER
        if rec is not None and rec.armed:
            rec.add("SUBPROCESS_SHELL", False, command=str(cmd), user=kwargs.get("user"), cwd=kwargs.get("cwd"))
        return FakeProc(["/bin/sh", "-c", str(cmd)])

    asyncio.create_subprocess_exec = fake_exec
    asyncio.create_subprocess_shell = fake_shell
    asyncio.subprocess.create_subprocess_exec = fake_exec
    asyncio.subprocess.create_subprocess_shell = fake_shell


class FakeMessage:
    _next = 900000

    def __init__(self, recorder_list: List[Dict[str, Any]], channel: str) -> None:
        FakeMessage._next += 1
        self.id = FakeMessage._next
        self.embeds: List[Any] = []
        self.content = ""
        self._replies = recorder_list
        self._channel = channel

    async def edit(self, **kwargs: Any) -> "FakeMessage":
        self._replies.append(_reply_record("message.edit", kwargs))
        return self

    async def delete(self, **kwargs: Any) -> None:
        return None


def _embed_text(embed: Any) -> str:
    parts = [str(getattr(embed, "title", "") or ""), str(getattr(embed, "description", "") or "")]
    for field in getattr(embed, "fields", []) or []:
        parts.append(f"{field.name}: {field.value}")
    footer = getattr(embed, "footer", None)
    if footer is not None and getattr(footer, "text", None):
        parts.append(str(footer.text))
    return "\n".join(p for p in parts if p)


def _reply_record(channel: str, kwargs: Dict[str, Any], content: Any = None) -> Dict[str, Any]:
    text = [str(content)] if content is not None else []
    if kwargs.get("content") is not None:
        text.append(str(kwargs["content"]))
    embeds = list(kwargs.get("embeds") or [])
    if kwargs.get("embed") is not None:
        embeds.append(kwargs["embed"])
    for embed in embeds:
        text.append(_embed_text(embed))
    files = list(kwargs.get("files") or [])
    if kwargs.get("file") is not None:
        files.append(kwargs["file"])
    file_text = []
    for f in files:
        try:
            data = f.fp.getvalue() if hasattr(f.fp, "getvalue") else b""
            file_text.append(os.fsdecode(data[:200000]))
        except (AttributeError, ValueError):
            pass
    view = kwargs.get("view")
    return {
        "channel": channel, "text": "\n".join(text), "ephemeral": kwargs.get("ephemeral"), "files": [getattr(f, "filename", "?") for f in files],
        "file_text": "\n".join(file_text), "view": type(view).__name__ if view is not None else None, "view_obj": view,
        "allowed_mentions": repr(kwargs.get("allowed_mentions")) if "allowed_mentions" in kwargs else None, "t": time.monotonic(),
    }


class FakeResponse:
    def __init__(self, interaction: "FakeInteraction") -> None:
        self._i = interaction
        self._done = False

    def is_done(self) -> bool:
        return self._done

    def _mark(self, kind: str) -> None:
        if self._done:
            self._i.protocol.append(f"DOUBLE_RESPONSE:{kind}")
            import discord
            raise discord.InteractionResponded(self._i)
        self._done = True
        self._i.first_response_at = time.monotonic()

    async def send_message(self, content: Any = None, **kwargs: Any) -> None:
        self._mark("send_message")
        self._i.replies.append(_reply_record("response.send_message", kwargs, content))
        self._i.on_view(kwargs.get("view"))

    async def defer(self, **kwargs: Any) -> None:
        self._mark("defer")
        self._i.deferred = True

    async def edit_message(self, **kwargs: Any) -> None:
        self._mark("edit_message")
        self._i.replies.append(_reply_record("response.edit_message", kwargs))
        self._i.on_view(kwargs.get("view"))

    async def send_modal(self, modal: Any) -> None:
        self._mark("send_modal")
        self._i.replies.append({"channel": "response.send_modal", "text": type(modal).__name__, "view": None, "view_obj": None, "t": time.monotonic(), "files": [], "file_text": ""})


class FakeFollowup:
    def __init__(self, interaction: "FakeInteraction") -> None:
        self._i = interaction

    async def send(self, content: Any = None, **kwargs: Any) -> FakeMessage:
        if not self._i.response.is_done():
            self._i.protocol.append("FOLLOWUP_BEFORE_RESPONSE")
        self._i.replies.append(_reply_record("followup.send", kwargs, content))
        self._i.on_view(kwargs.get("view"))
        return FakeMessage(self._i.replies, "followup")


class FakeChannel:
    def __init__(self, interaction: "FakeInteraction") -> None:
        self._i = interaction
        self.id = 5151
        self.name = "campaign"

    async def send(self, content: Any = None, **kwargs: Any) -> FakeMessage:
        self._i.replies.append(_reply_record("channel.send", kwargs, content))
        self._i.on_view(kwargs.get("view"))
        return FakeMessage(self._i.replies, "channel")


class FakeInteraction:
    def __init__(self, client: Any, user: Any, *, custom_id: Optional[str] = None, message_id: Optional[int] = None, on_view: Any = None) -> None:
        import discord
        self.client = client
        self.user = user
        self.guild = mock.MagicMock()
        self.guild.id = GUILD_ID
        self.guild_id = GUILD_ID
        self.channel = FakeChannel(self)
        self.channel_id = self.channel.id
        self.replies: List[Dict[str, Any]] = []
        self.protocol: List[str] = []
        self.deferred = False
        self.first_response_at: Optional[float] = None
        self.started_at = time.monotonic()
        self.response = FakeResponse(self)
        self.followup = FakeFollowup(self)
        self.id = int(time.time() * 1000) % 10 ** 12
        self.locale = "en-US"
        self.command = mock.MagicMock()
        self.command.name = "campaign"
        if custom_id is not None:
            self.type = discord.InteractionType.component
            self.data = {"custom_id": custom_id, "component_type": 2}
            self.message = mock.MagicMock()
            self.message.id = message_id or 777000
            self.message.embeds = []
        else:
            self.type = discord.InteractionType.application_command
            self.data = {}
            self.message = None
        self._on_view = on_view

    def on_view(self, view: Any) -> None:
        if view is not None and self._on_view is not None:
            self._on_view(view, self)

    def is_expired(self) -> bool:
        return False

    async def edit_original_response(self, **kwargs: Any) -> FakeMessage:
        if not self.response.is_done():
            self.protocol.append("EDIT_BEFORE_RESPONSE")
        self.replies.append(_reply_record("edit_original_response", kwargs))
        self.on_view(kwargs.get("view"))
        return FakeMessage(self.replies, "original")

    async def original_response(self) -> FakeMessage:
        return FakeMessage(self.replies, "original")

    async def delete_original_response(self) -> None:
        return None


def make_member(roles: List[int], member_id: int, name: str) -> Any:
    import discord
    member = mock.MagicMock(spec=discord.Member)
    member.id = member_id
    role_objs = []
    for r in roles:
        role = mock.MagicMock()
        role.id = r
        role.name = f"role{r}"
        role_objs.append(role)
    member.roles = role_objs
    member.name = name
    member.display_name = name
    member.mention = f"<@{member_id}>"
    member.bot = False
    member.__str__.return_value = name
    return member


def make_dm_user(member_id: int) -> Any:
    import discord
    user = mock.MagicMock(spec=discord.User)
    user.id = member_id
    user.name = "dm-user"
    user.__str__.return_value = "dm-user"
    return user


def redirect_paths(obj: Any, sandbox: str, seen: Optional[set] = None) -> None:
    seen = seen if seen is not None else set()
    if id(obj) in seen or not dataclasses.is_dataclass(obj):
        return
    seen.add(id(obj))
    for field in dataclasses.fields(obj):
        value = getattr(obj, field.name)
        if isinstance(value, str) and value.startswith("/opt/security/rtsa"):
            object.__setattr__(obj, field.name, sandbox + value)
        elif dataclasses.is_dataclass(value):
            redirect_paths(value, sandbox, seen)
        elif isinstance(value, dict):
            for v in value.values():
                redirect_paths(v, sandbox, seen)


def make_rtsa_config(sandbox: str, detection_only: bool) -> Any:
    from config.manager import CloudflareConfig, RTSAConfig
    cfg = RTSAConfig(cloudflare=CloudflareConfig(enabled=False))
    redirect_paths(cfg, sandbox)
    object.__setattr__(cfg.response_engine, "detection_only", detection_only)
    os.makedirs(os.path.dirname(cfg.database.path), exist_ok=True)
    return cfg


def make_discord_config(roles_configured: bool) -> Any:
    from config.manager import DiscordConfig
    if not roles_configured:
        return DiscordConfig(enabled=True, guild_id=GUILD_ID, admin_role_ids=[], critical_command_role_ids=[])
    return DiscordConfig(enabled=True, guild_id=GUILD_ID, admin_role_ids=[ADMIN_ROLE], critical_command_role_ids=[CRITICAL_ROLE])


class DbProxy:
    def __init__(self, worker: Any) -> None:
        self._worker = worker

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._worker, name)
        if callable(target) and name.startswith("enqueue_"):
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                rec = RECORDER
                if rec is not None and rec.armed:
                    rec.add("DB_WRITE", False, method=name, args=[_short(a, 200) for a in args], kwargs={k: _short(v, 200) for k, v in kwargs.items()})
                return target(*args, **kwargs)
            return wrapper
        return target


def lab_fixture() -> Dict[str, Any]:
    try:
        with open(LAB_STATE, "r", encoding="utf-8") as handle:
            projects = json.load(handle)["projects"]
    except (OSError, ValueError, KeyError):
        projects = []
    node = next((p for p in projects if p["archetype"] == "node-express" and p["pm2"]), None)
    php = next((p for p in projects if p["archetype"].startswith("php")), None)
    victim = next((p for p in reversed(projects) if p["archetype"] == "static"), None)
    return {"node": node, "php": php, "victim": victim, "count": len(projects)}


def valid_values(fix: Dict[str, Any]) -> Dict[str, Any]:
    node = fix["node"] or {"user": "lab-001", "domain": "001.lab.test", "port": 20007}
    victim = fix["victim"] or node
    return {
        "domain": node["domain"], "api_domain": node["domain"], "ip": "203.0.113.50", "target": "203.0.113.50", "reason": "campaign", "severity": "HIGH",
        "event_id": "evt-campaign-ip", "incident_id": "evt-campaign-ip", "service": "nginx", "unit": "nginx", "access_key_id": "AKIACAMPAIGNEXAMPLE0",
        "secret_access_key": "c" * 40, "region": "ap-southeast-1", "old_token": "o" * 40, "new_token": "n" * 40,
        "old_webhook": "https://discord.com/api/webhooks/1/old-campaign-placeholder", "new_webhook": "https://discord.com/api/webhooks/2/new-campaign-placeholder",
        "origins": "10.10.0.11,10.10.0.12", "mode": "read", "username": victim["user"], "user_linux": node["user"], "owner": node["user"], "port": int(node["port"]),
        "app": node["user"], "application": node["user"], "github_repo": "lab/app", "branch": "main", "window": "24h", "jam": 6, "lines": 50,
        "outcome": "TRUE_POSITIVE", "notes": "campaign", "action": "status",
    }


def build_cases(command: Any, values: Dict[str, Any]) -> List[Dict[str, Any]]:
    params = list(getattr(command, "parameters", []))
    base: Dict[str, Any] = {}
    for p in params:
        if p.required:
            base[p.name] = values.get(p.name, "campaign")
    cases: List[Dict[str, Any]] = []
    for caller in ("no_roles_configured", "unauthorized", "dm_user", "admin_only", "critical", "critical_detection_only"):
        cases.append({"id": f"caller:{caller}", "caller": caller, "args": dict(base), "input_class": "valid", "policy": "requester_confirm"})
    cases.append({"id": "confirm:other_user_then_cancel", "caller": "critical", "args": dict(base), "input_class": "valid", "policy": "other_then_cancel"})
    cases.append({"id": "concurrency:x2", "caller": "critical", "args": dict(base), "input_class": "valid", "policy": "requester_confirm", "concurrent": 2})
    for p in params:
        kind = str(p.type).replace("AppCommandOptionType.", "")
        if kind == "string" and not getattr(p, "choices", None):
            for cls, payload in HOSTILE_STR.items():
                args = dict(base)
                args[p.name] = payload
                cases.append({"id": f"input:{p.name}:{cls}", "caller": "critical", "args": args, "input_class": cls, "param": p.name, "payload": payload, "policy": "requester_confirm"})
        elif kind == "string":
            for choice in p.choices:
                args = dict(base)
                args[p.name] = choice.value
                cases.append({"id": f"choice:{p.name}:{choice.value}", "caller": "critical", "args": args, "input_class": "valid_choice", "param": p.name, "policy": "requester_confirm"})
            args = dict(base)
            args[p.name] = f"bogus{MARK}"
            cases.append({"id": f"input:{p.name}:out_of_choices", "caller": "critical", "args": args, "input_class": "out_of_choices", "param": p.name, "payload": f"bogus{MARK}", "policy": "requester_confirm"})
        elif kind == "integer":
            for cls, payload in HOSTILE_INT.items():
                args = dict(base)
                args[p.name] = payload
                cases.append({"id": f"input:{p.name}:{cls}", "caller": "critical", "args": args, "input_class": cls, "param": p.name, "payload": payload, "policy": "requester_confirm"})
        elif kind == "boolean":
            for flag in (True, False):
                args = dict(base)
                args[p.name] = flag
                cases.append({"id": f"flag:{p.name}:{flag}", "caller": "critical", "args": args, "input_class": "valid_flag", "param": p.name, "policy": "requester_confirm"})
    return cases


CONFIRM_RE = re.compile(r"confirm|hapus|replace|lanjut|force|yes|apply|kill|ya\b", re.I)
CANCEL_RE = re.compile(r"cancel|batal", re.I)


class Case:
    def __init__(self, spec: Dict[str, Any], bot: Any, member: Any) -> None:
        self.spec = spec
        self.bot = bot
        self.member = member
        self.views: List[Tuple[Any, Any]] = []
        self.clicks: List[Dict[str, Any]] = []
        self.tasks: List[asyncio.Task] = []

    def on_view(self, view: Any, interaction: FakeInteraction) -> None:
        self.views.append((view, interaction))
        if not getattr(view, "children", None):
            return
        policy = self.spec.get("policy")
        confirm = next((c for c in view.children if getattr(c, "label", None) and CONFIRM_RE.search(c.label)), None)
        cancel = next((c for c in view.children if getattr(c, "label", None) and CANCEL_RE.search(c.label)), None)
        if confirm is None:
            return
        if policy == "requester_confirm":
            self.tasks.append(asyncio.ensure_future(self._click(view, confirm, self.member, "requester_confirm")))
        elif policy == "other_then_cancel":
            other = make_member([OTHER_ROLE], OTHER_ID, "other-user")
            self.tasks.append(asyncio.ensure_future(self._other_then_cancel(view, confirm, cancel, other)))

    async def _other_then_cancel(self, view: Any, confirm: Any, cancel: Any, other: Any) -> None:
        await self._click(view, confirm, other, "other_user_confirm")
        if cancel is not None and not view.is_finished():
            await self._click(view, cancel, self.member, "requester_cancel")
        elif not view.is_finished():
            view.stop()

    async def _click(self, view: Any, item: Any, user: Any, label: str) -> Dict[str, Any]:
        await asyncio.sleep(0.01)
        i = FakeInteraction(self.bot, user, custom_id=getattr(item, "custom_id", "x"), on_view=self.on_view)
        record: Dict[str, Any] = {"click": label, "view": type(view).__name__, "button": getattr(item, "label", None)}
        try:
            custom_id = getattr(item, "custom_id", None) or ""
            if custom_id.startswith("rtsa_action:"):
                record["routed"] = "on_interaction"
                await asyncio.wait_for(self.bot.on_interaction(i), timeout=20)
                first = i.replies[0]["text"] if i.replies else ""
                record["interaction_check"] = not bool(re.search(r"tidak (memiliki|punya) izin|tidak diotorisasi", first, re.I))
            else:
                allowed = await view.interaction_check(i)
                record["interaction_check"] = bool(allowed)
                if allowed:
                    await asyncio.wait_for(item.callback(i), timeout=20)
        except Exception as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"[:300]
        record["replies"] = [r["text"][:300] for r in i.replies]
        self.clicks.append(record)
        return record


def classify_subprocess(argv: List[str]) -> str:
    if not argv:
        return "UNKNOWN"
    exe = os.path.basename(argv[0])
    rest = argv[1:]
    if exe in ("sudo", "runuser", "setpriv", "nice", "ionice", "timeout", "env", "stdbuf"):
        tail = [a for a in rest if not a.startswith("-") and "=" not in a]
        if exe == "timeout" and tail:
            tail = tail[1:]
        idx = argv.index(tail[0]) if tail else len(argv)
        return classify_subprocess(argv[idx:])
    if exe in SHELLS:
        if "-c" in rest:
            idx = rest.index("-c")
            return classify_script(str(rest[idx + 1])) if idx + 1 < len(rest) else "MUTATE"
        return "MUTATE"
    if exe == "node" and len(rest) >= 2 and rest[0] == "-p" and "package.json" in rest[1] and ".version" in rest[1]:
        return "READ"
    if exe in READ_ONLY_VERBS:
        if any(a in MUTATING_VERBS.get(exe, ()) for a in rest):
            return "MUTATE"
        if any(a in READ_ONLY_VERBS[exe] for a in rest):
            return "READ"
        return "MUTATE"
    if exe in READ_ONLY_TOOLS:
        return "READ"
    return "MUTATE"


SHELL_BUILTINS = {"command", "echo", "printf", "cd", "export", "test", "[", "true", "false", "type", "set", "exec"}


def classify_script(script: str) -> str:
    worst = "READ"
    script = re.sub(r"\d?>&\d", " ", script)
    for inner in re.findall(r"\$\(([^()]*)\)", script):
        if classify_script(inner) != "READ":
            worst = "MUTATE"
    script = re.sub(r"\w+=\$\([^()]*\)", " ", script)
    for segment in re.split(r"[;&|\n]+", script):
        try:
            words = shlex.split(segment)
        except ValueError:
            return "MUTATE"
        while words and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
            words = words[1:]
        if not words:
            continue
        if words[0] in SHELL_BUILTINS and words[0] != "exec":
            continue
        if words[0] == "exec":
            words = words[1:]
        if classify_subprocess(words) != "READ":
            worst = "MUTATE"
    return worst


def shell_text(event: Dict[str, Any]) -> Optional[str]:
    if event["kind"] == "SUBPROCESS_SHELL":
        return event.get("command") or ""
    argv = event.get("argv") or []
    for i, a in enumerate(argv):
        if os.path.basename(str(a)) in SHELLS and "-c" in argv[i + 1:]:
            j = argv.index("-c", i + 1)
            return " ".join(str(x) for x in argv[j + 1:j + 2])
    return None


def analyse(spec: Dict[str, Any], events: List[Dict[str, Any]], replies: List[Dict[str, Any]]) -> Dict[str, Any]:
    payload = spec.get("payload")
    flags: List[str] = []
    side: Dict[str, int] = {}
    mutations: List[str] = []
    for e in events:
        side[e["kind"]] = side.get(e["kind"], 0) + 1
        if e["kind"] in ("SUBPROCESS", "SUBPROCESS_SYNC"):
            cls = e.get("cls") or classify_subprocess([str(a) for a in e.get("argv") or []])
            e["class"] = cls
            if cls in ("MUTATE", "SHELL"):
                mutations.append(" ".join(str(a) for a in (e.get("argv") or [])[:8]))
        elif e["kind"] == "SUBPROCESS_SHELL":
            e["class"] = classify_script(e.get("command", ""))
            if e["class"] != "READ":
                mutations.append(e.get("command", "")[:120])
        elif e["kind"] in ("FS_WRITE", "FS_DELETE", "FS_RENAME", "FS_CHMOD", "FS_CHOWN", "FS_LINK", "FS_MKDIR", "KILL", "NETWORK", "PROCESS_SPAWN", "PROCESS_STATE"):
            mutations.append(f"{e['kind']} {e.get('path') or e.get('paths') or e.get('pid') or e.get('address') or e.get('event')}")
    if isinstance(payload, str) and payload and MARK in payload:
        for e in events:
            text = shell_text(e) if e["kind"] in ("SUBPROCESS", "SUBPROCESS_SHELL") else None
            if text is not None and MARK in text:
                quoted = shlex.quote(payload) in text
                flags.append("SHELL_ARG_QUOTED" if quoted else "SHELL_INJECTION")
            if e["kind"] in ("SUBPROCESS", "SUBPROCESS_SYNC"):
                argv = [str(a) for a in e.get("argv") or []]
                for idx, a in enumerate(argv):
                    if MARK in a and a.startswith("-") and "--" not in argv[:idx]:
                        flags.append("OPTION_INJECTION")
                    elif MARK in a:
                        flags.append("PAYLOAD_IN_ARGV")
            for key in ("path", "paths"):
                value = e.get(key)
                values = value if isinstance(value, list) else [value]
                for v in values:
                    if isinstance(v, str) and MARK in v:
                        flags.append("PATH_FROM_INPUT_TRAVERSAL" if ("/../" in v or v.startswith("/etc/")) else "PATH_FROM_INPUT")
            if e["kind"] in ("DNS", "DNS_LAB", "NETWORK", "HTTP_REQUEST") and MARK in json.dumps(e):
                flags.append("NETWORK_FROM_INPUT")
            if e["kind"] == "DB_WRITE" and MARK in json.dumps(e):
                flags.append("STORED_INPUT")
        reply_text = "\n".join(r.get("text", "") for r in replies)
        if "@everyone" in payload and "@everyone" in reply_text:
            flags.append("EVERYONE_MENTION_ECHOED")
        if "<@&" in payload and "<@&" in reply_text:
            flags.append("ROLE_MENTION_ECHOED")
    reply_text = "\n".join(r.get("text", "") + "\n" + r.get("file_text", "") for r in replies)
    for value in SECRETS.values():
        if value in reply_text:
            flags.append("SECRET_IN_REPLY")
    for e in events:
        if e["kind"] in ("SUBPROCESS",) and e.get("user") not in (None, 0) and e.get("env_keys") is None:
            flags.append("PRIVDROP_WITHOUT_ENV")
    first = replies[0]["text"] if replies else ""
    denied = bool(re.search(r"tidak (memiliki|punya) izin|tidak diotorisasi|not authori[sz]ed|no permission", first, re.I))
    detection_blocked = "Detection Only" in reply_text
    return {"side_effects": side, "mutations": sorted(set(mutations))[:30], "flags": sorted(set(flags)), "denied": denied, "detection_only_reply": detection_blocked}


async def run_case(spec: Dict[str, Any], command: Any, sandbox: str, db: Any, timeout: float) -> Dict[str, Any]:
    from core.event_bus import EventBus
    from discord_integration.bot import RTSABot
    caller = spec["caller"]
    rtsa_cfg = make_rtsa_config(sandbox, detection_only=(caller == "critical_detection_only"))
    discord_cfg = make_discord_config(caller != "no_roles_configured")
    bot = RTSABot(discord_cfg, rtsa_cfg, EventBus(), db_worker=db, supervisor=None)
    if caller == "unauthorized":
        member = make_member([OTHER_ROLE], REQUESTER_ID, "unauthorized-user")
    elif caller == "dm_user":
        member = make_dm_user(REQUESTER_ID)
    elif caller == "admin_only":
        member = make_member([ADMIN_ROLE], REQUESTER_ID, "admin-user")
    else:
        member = make_member([ADMIN_ROLE, CRITICAL_ROLE], REQUESTER_ID, "critical-user")
    callback = bot.tree.get_command(command.name).callback
    case = Case(spec, bot, member)
    reset_host_state()
    interactions = [FakeInteraction(bot, member, on_view=case.on_view) for _ in range(spec.get("concurrent", 1))]
    before = set(asyncio.all_tasks())
    RECORDER.events = []
    RECORDER.armed = True
    started = time.monotonic()
    outcome = "OK"
    error = None
    try:
        await asyncio.wait_for(asyncio.gather(*(callback(i, **spec["args"]) for i in interactions)), timeout=timeout)
    except asyncio.TimeoutError:
        outcome = "TIMEOUT"
    except Exception as exc:
        outcome = "EXCEPTION"
        tb = traceback.extract_tb(exc.__traceback__)
        where = next((f"{os.path.relpath(f.filename, ROOT)}:{f.lineno}" for f in reversed(tb) if f.filename.startswith(ROOT)), "?")
        error = f"{type(exc).__name__}: {str(exc)[:240]} @ {where}"
    elapsed = time.monotonic() - started
    spawned = [t for t in asyncio.all_tasks() - before if not t.done()]
    if case.tasks or spawned:
        pending = [t for t in case.tasks + spawned if not t.done()]
        if pending:
            done, still = await asyncio.wait(pending, timeout=5)
    await cancel_spawned(before)
    RECORDER.armed = False
    events = list(RECORDER.events)
    replies = [r for i in interactions for r in i.replies]
    analysis = analyse(spec, events, replies)
    leaks = []
    for key, record in list(getattr(bot._action_lock, "_records", {}).items()) if hasattr(bot._action_lock, "_records") else []:
        if str(getattr(record, "status", "")).endswith("RUNNING"):
            leaks.append(key)
    if bot._nginx_domain_locks:
        leaks.append(f"nginx_domain_locks={sorted(bot._nginx_domain_locks)}")
    if bot._deluser_locks:
        leaks.append(f"deluser_locks={sorted(bot._deluser_locks)}")
    first_ack = [i.first_response_at - i.started_at for i in interactions if i.first_response_at is not None]
    protocol = sorted({p for i in interactions for p in i.protocol})
    if not all(i.first_response_at is not None for i in interactions):
        protocol.append("NO_RESPONSE")
    for v, _ in case.views:
        if not v.is_finished():
            v.stop()
    return {
        "id": spec["id"], "caller": caller, "input_class": spec["input_class"], "param": spec.get("param"), "outcome": outcome, "error": error,
        "elapsed_s": round(elapsed, 3), "first_ack_s": round(max(first_ack), 3) if first_ack else None, "protocol": protocol, "lock_leaks": leaks,
        "replies": [{"channel": r["channel"], "text": r["text"][:500], "view": r["view"], "ephemeral": r.get("ephemeral"), "files": r.get("files")} for r in replies[:8]],
        "views": sorted({type(v).__name__ for v, _ in case.views}), "clicks": case.clicks, "events": events[:60], "event_count": len(events),
        "logged_errors": [e["detail"] for e in events if e["kind"] == "LOGGED_ERROR"][:5], **analysis,
    }


async def component_sweep(command: Any, sandbox: str, db: Any, values: Dict[str, Any], timeout: float) -> List[Dict[str, Any]]:
    from core.event_bus import EventBus
    from discord_integration.bot import RTSABot
    out: List[Dict[str, Any]] = []
    params = {p.name: values.get(p.name, "campaign") for p in getattr(command, "parameters", []) if p.required}
    bot = RTSABot(make_discord_config(True), make_rtsa_config(sandbox, False), EventBus(), db_worker=db, supervisor=None)
    member = make_member([ADMIN_ROLE, CRITICAL_ROLE], REQUESTER_ID, "critical-user")
    spec = {"id": "sweep", "policy": "none"}
    case = Case(spec, bot, member)
    interaction = FakeInteraction(bot, member, on_view=case.on_view)
    before = set(asyncio.all_tasks())
    RECORDER.events = []
    RECORDER.armed = True
    task = asyncio.ensure_future(bot.tree.get_command(command.name).callback(interaction, **params))
    deadline = time.monotonic() + timeout
    while not task.done() and time.monotonic() < deadline:
        if case.views:
            await asyncio.sleep(0.3)
            break
        await asyncio.sleep(0.05)
    seen = set()
    for view, _ in list(case.views):
        name = type(view).__name__
        if view.is_finished() or name in seen or not getattr(view, "children", None):
            continue
        seen.add(name)
        for item in list(view.children):
            label = getattr(item, "label", None) or type(item).__name__
            for who, user in (("other_guild_member", make_member([OTHER_ROLE], OTHER_ID, "other-user")), ("requester", member)):
                RECORDER.events = []
                record = await case._click(view, item, user, who)
                await asyncio.sleep(0.05)
                events = list(RECORDER.events)
                mut = analyse({"id": "click"}, events, [])
                out.append({"view": name, "button": label, "clicker": who, "interaction_check": record.get("interaction_check"), "error": record.get("error"),
                            "replies": record.get("replies"), "side_effects": mut["side_effects"], "mutations": mut["mutations"]})
        if not view.is_finished():
            view.stop()
    if not task.done():
        try:
            await asyncio.wait_for(task, timeout=5)
        except BaseException:
            task.cancel()
    await cancel_spawned(before)
    RECORDER.armed = False
    return out


async def cancel_spawned(before: set) -> None:
    spawned = [t for t in asyncio.all_tasks() - before if not t.done() and t is not asyncio.current_task()]
    for t in spawned:
        t.cancel()
    if spawned:
        await asyncio.wait(spawned, timeout=5)


async def seed_db(db_path: str) -> None:
    from database.sqlite_pool import SQLiteWriteWorker
    writer = SQLiteWriteWorker(db_path=db_path, flush_interval_seconds=0.05)
    await writer.start()
    fix = lab_fixture()
    node = fix["node"] or {"user": "lab-001", "domain": "001.lab.test", "port": 20007}
    victim = fix["victim"] or node
    normal = {"pid": 4242001, "pid_create_time": 1.0, "port": int(node["port"]), "systemd_unit": "lab-campaign.service", "pm2_app_name": node["user"],
              "linux_user": node["user"], "docker_container_id": "c0ffee000001", "username": victim["user"]}
    protected = {"pid": 1, "pid_create_time": 0.0, "port": 22, "systemd_unit": "ssh.service", "pm2_app_name": "all", "linux_user": "root",
                 "docker_container_id": "c0ffee000002", "username": "root"}
    writer.enqueue_incident_create("evt-campaign-ip", "203.0.113.50", node["domain"], "WEB_ATTACK_RCE", "HIGH", "campaign", json.dumps(normal))
    writer.enqueue_incident_create("evt-campaign-protected", "198.51.100.7", node["domain"], "PORT_EXPOSURE", "HIGH", "campaign", json.dumps(protected))
    writer.enqueue_incident_create("evt-campaign-bare", None, None, "DDOS", "MEDIUM", "campaign", None)
    for action in ALERT_ACTIONS:
        writer.enqueue_incident_create(f"evt-{action}-ip", "203.0.113.50", node["domain"], "WEB_ATTACK_RCE", "HIGH", "campaign", json.dumps(normal))
        writer.enqueue_incident_create(f"evt-{action}-dronly", "203.0.113.51", node["domain"], "WEB_ATTACK_RCE", "HIGH", "campaign", json.dumps(normal))
        writer.enqueue_incident_create(f"evt-{action}-protected", "198.51.100.7", node["domain"], "PORT_EXPOSURE", "HIGH", "campaign", json.dumps(protected))
    await asyncio.sleep(0.8)
    await writer.stop()


async def worker_main(name: str, out_path: str, timeout: float) -> None:
    sandbox = tempfile.mkdtemp(prefix="rtsa_cmd_")
    os.makedirs(os.path.join(sandbox, "tmp"), exist_ok=True)
    tempfile.tempdir = os.path.join(sandbox, "tmp")
    os.environ["TMPDIR"] = tempfile.tempdir
    os.environ.update(SECRETS)
    root_logger = logging.getLogger()
    root_logger.handlers = [CaptureHandler()]
    root_logger.setLevel(logging.ERROR)
    from config.manager import ResourceGovernorConfig
    from core.cpu_governor import configure_cpu_governor
    from database.sqlite_pool import SQLiteWriteWorker
    from discord_integration.bot import RTSABot
    from core.event_bus import EventBus
    configure_cpu_governor(ResourceGovernorConfig(defer_when_system_busy=False))
    cfg = make_rtsa_config(sandbox, False)
    await seed_db(cfg.database.path)
    real_db = SQLiteWriteWorker(db_path=cfg.database.path, flush_interval_seconds=0.05)
    await real_db.start()
    db = DbProxy(real_db)
    global RECORDER
    RECORDER = Recorder(sandbox)
    install_subprocess_fakes()
    RTSABot.latency = property(lambda self: 0.042)
    sys.addaudithook(audit_hook)
    values = valid_values(lab_fixture())
    probe = RTSABot(make_discord_config(True), cfg, EventBus(), db_worker=db, supervisor=None)
    result: Dict[str, Any] = {"name": name, "sandbox": sandbox, "started": time.time()}
    if name == "__alerts__":
        result["alert_cases"] = await alert_campaign(sandbox, db, timeout)
    else:
        command = probe.tree.get_command(name)
        cases = build_cases(command, values)
        result["cases"] = []
        for spec in cases:
            result["cases"].append(await run_case(spec, command, sandbox, db, timeout))
        result["components"] = await component_sweep(command, sandbox, db, values, timeout)
    result["finished"] = time.time()
    await real_db.stop()
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=1, default=str)


ALERT_ACTIONS = (
    "ban", "ignore", "geoip", "rdns", "whois", "profile", "history", "timeline", "deluser", "kickssh", "killprocess", "killport", "blockport", "unblockport",
    "stopservice", "startservice", "restartservice", "disableservice", "enableservice", "pm2restartport", "pm2stopport", "pm2startport", "pm2deleteport",
    "dockerstop", "dockerrestart", "porthistory", "cekport", "fixcf_block", "recheck", "clearcp", "respm2", "fixssl",
)


async def alert_click(bot: Any, member: Any, custom_id: str, message_id: int, policy: str, timeout: float) -> Dict[str, Any]:
    spec = {"id": custom_id, "policy": policy}
    case = Case(spec, bot, member)
    interaction = FakeInteraction(bot, member, custom_id=custom_id, message_id=message_id, on_view=case.on_view)
    before = set(asyncio.all_tasks())
    RECORDER.events = []
    RECORDER.armed = True
    outcome, error = "OK", None
    try:
        await asyncio.wait_for(bot.on_interaction(interaction), timeout=timeout)
    except asyncio.TimeoutError:
        outcome = "TIMEOUT"
    except Exception as exc:
        outcome = "EXCEPTION"
        tb = traceback.extract_tb(exc.__traceback__)
        where = next((f"{os.path.relpath(f.filename, ROOT)}:{f.lineno}" for f in reversed(tb) if f.filename.startswith(ROOT)), "?")
        error = f"{type(exc).__name__}: {str(exc)[:240]} @ {where}"
    pending = [t for t in case.tasks if not t.done()]
    if pending:
        await asyncio.wait(pending, timeout=5)
    await asyncio.sleep(0.05)
    await cancel_spawned(before)
    RECORDER.armed = False
    events = list(RECORDER.events)
    analysis = analyse(spec, events, interaction.replies)
    for v, _ in case.views:
        if not v.is_finished():
            v.stop()
    return {"outcome": outcome, "error": error, "replies": [r["text"][:300] for r in interaction.replies[:4]], "clicks": case.clicks,
            "protocol": interaction.protocol + ([] if interaction.first_response_at is not None else ["NO_RESPONSE"]), "events": events[:40], **analysis}


async def alert_campaign(sandbox: str, db: Any, timeout: float) -> List[Dict[str, Any]]:
    from core.event_bus import EventBus
    from discord_integration.bot import RTSABot
    out: List[Dict[str, Any]] = []
    callers = {
        "unauthorized": make_member([OTHER_ROLE], REQUESTER_ID, "unauthorized-user"), "dm_user": make_dm_user(REQUESTER_ID),
        "admin_only": make_member([ADMIN_ROLE], REQUESTER_ID, "admin-user"), "critical": make_member([ADMIN_ROLE, CRITICAL_ROLE], REQUESTER_ID, "critical-user"),
    }
    message_id = 880000
    claims = os.path.join(sandbox, "alert_claims.json")
    for action in ALERT_ACTIONS:
        plan = [(f"evt-{action}-dronly", "critical", True)]
        plan += [(f"evt-{action}-ip", caller, False) for caller in ("unauthorized", "dm_user", "admin_only", "critical")]
        plan += [(f"evt-{action}-protected", "critical", False), ("evt-campaign-bare", "critical", False), ("evt-missing", "critical", False)]
        for event_id, caller, detection_only in plan:
            member = callers[caller]
            reset_host_state()
            message_id += 1
            target = f"rtsa_action:{action}:{event_id}"
            bot = RTSABot(make_discord_config(True), make_rtsa_config(sandbox, detection_only), EventBus(), db_worker=db, supervisor=None, claim_state_path=claims)
            record = await alert_click(bot, member, target, message_id, "requester_confirm", timeout)
            out.append({"action": action, "event_id": event_id, "caller": caller, "detection_only": detection_only, "phase": "first", **record})
            if caller != "critical" or detection_only or not (event_id.endswith("-ip") or event_id.endswith("-protected")):
                continue
            again = await alert_click(bot, member, target, message_id, "requester_confirm", timeout)
            out.append({"action": action, "event_id": event_id, "caller": caller, "detection_only": False, "phase": "replay_same_process", **again})
            restarted = RTSABot(make_discord_config(True), make_rtsa_config(sandbox, False), EventBus(), db_worker=db, supervisor=None, claim_state_path=claims)
            after = await alert_click(restarted, member, target, message_id, "requester_confirm", timeout)
            out.append({"action": action, "event_id": event_id, "caller": caller, "detection_only": False, "phase": "replay_after_restart", **after})
    bot = RTSABot(make_discord_config(True), make_rtsa_config(sandbox, False), EventBus(), db_worker=db, supervisor=None)
    critical = callers["critical"]
    for custom_id in ("rtsa_action:ban", "rtsa_action:ban:" + "../../" + MARK, "rtsa_action:" + "x" * 300 + ":evt", f"rtsa_action:nosuchaction:evt-campaign-ip", "rtsa_action:ban:evt-campaign-ip:extra"):
        message_id += 1
        record = await alert_click(bot, critical, custom_id, message_id, "requester_confirm", timeout)
        out.append({"action": "malformed", "event_id": custom_id[:80], "caller": "critical", "detection_only": False, "phase": "malformed", **record})
    return out


INTEGRITY_ROOTS = ("/etc/nginx", "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d", "/etc/crontab", "/etc/cron.d", "/etc/systemd/system", "/etc/hosts", "/etc/ssh", "/root/.ssh", "/home", "/opt")


def host_snapshot() -> Dict[str, Tuple[int, float]]:
    snap: Dict[str, Tuple[int, float]] = {}
    for root in INTEGRITY_ROOTS:
        if os.path.isfile(root):
            st = os.stat(root)
            snap[root] = (st.st_size, st.st_mtime)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".pm2", "logs", "uploads", "node_modules", ".git", ".npm", ".cache") and not os.path.join(dirpath, d).startswith(ROOT)]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                snap[path] = (st.st_size, st.st_mtime)
    return snap


def orchestrate(names: List[str], jobs: int, timeout: float) -> None:
    os.makedirs(CASE_DIR, exist_ok=True)
    before_snapshot = host_snapshot()
    queue = list(names)
    running: Dict[str, Tuple[subprocess.Popen, float]] = {}
    started = time.time()
    while queue or running:
        while queue and len(running) < jobs:
            name = queue.pop(0)
            out = os.path.join(CASE_DIR, f"{name.strip('_')}.json")
            log = open(os.path.join(CASE_DIR, f"{name.strip('_')}.log"), "w", encoding="utf-8")
            proc = subprocess.Popen([sys.executable, os.path.abspath(__file__), "--worker", name, "--out", out, "--timeout", str(timeout)], stdout=log, stderr=log, cwd=ROOT)
            running[name] = (proc, time.time())
        for name, (proc, t0) in list(running.items()):
            if proc.poll() is not None:
                print(f"{name}: rc={proc.returncode} {time.time() - t0:.1f}s", flush=True)
                del running[name]
            elif time.time() - t0 > 1800:
                proc.kill()
                print(f"{name}: KILLED after 1800s", flush=True)
                del running[name]
        time.sleep(0.2)
    after_snapshot = host_snapshot()
    changed = sorted(p for p in set(before_snapshot) | set(after_snapshot) if before_snapshot.get(p) != after_snapshot.get(p))
    with open(os.path.join(CASE_DIR, "_host_integrity.json"), "w", encoding="utf-8") as handle:
        json.dump({"roots": INTEGRITY_ROOTS, "files_checked": len(before_snapshot), "changed": changed[:200], "changed_count": len(changed)}, handle, indent=1)
    print(f"host integrity: {len(before_snapshot)} files checked, {len(changed)} changed {changed[:5]}", flush=True)
    print(f"campaign finished in {time.time() - started:.1f}s", flush=True)


def command_names() -> List[str]:
    from config.manager import CloudflareConfig, DiscordConfig, RTSAConfig
    from core.event_bus import EventBus
    from discord_integration.bot import RTSABot
    bot = RTSABot(DiscordConfig(enabled=True), RTSAConfig(cloudflare=CloudflareConfig(enabled=False)), EventBus(), db_worker=None, supervisor=None)
    return sorted(c.qualified_name for c in bot.tree.walk_commands())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker")
    parser.add_argument("--out")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--only", default="")
    parser.add_argument("--no-alerts", action="store_true")
    args = parser.parse_args()
    if args.worker:
        asyncio.run(worker_main(args.worker, args.out, args.timeout))
        return
    names = [n for n in args.only.split(",") if n] or command_names()
    if not args.no_alerts and not args.only:
        names = ["__alerts__"] + names
    orchestrate(names, args.jobs, args.timeout)


if __name__ == "__main__":
    main()
