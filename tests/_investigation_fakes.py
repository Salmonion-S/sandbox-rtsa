from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tempfile
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.manager import InvestigationConfig, InvestigationSshConfig
from core.investigation_ssh import build_ssh_report
from core.investigation_store import ReadOnlyStore
from database.sqlite_pool import _SCHEMA

NOW = 1_800_000_000.0
ROOT_ONLY = [{"name": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"}]


class EventDb:
    def __init__(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="rtsa-investigation-")
        self.path = os.path.join(self.dir, "rtsa.db")
        self.conn = sqlite3.connect(self.path)
        self.conn.executescript(_SCHEMA)
        self._seq = 0

    def add(self, ts: float, category: str, severity: str, meta: Dict[str, Any], message: str = "", module: str = "ssh_monitor") -> str:
        self._seq += 1
        event_id = f"ev{self._seq:06d}"
        self.conn.execute(
            "INSERT INTO events (event_id, timestamp, source_module, category, severity, message, raw, host, metadata) VALUES (?,?,?,?,?,?,?,?,?)",
            (event_id, ts, module, category, severity, message, "", "host", json.dumps(meta)),
        )
        return event_id

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.commit()
            self.conn.close()
        finally:
            shutil.rmtree(self.dir, ignore_errors=True)


def login(db: EventDb, ts: float, user: str, ip: str, sid: Optional[str], *, port: Optional[int] = 50000, ssh_port: int = 22, method: str = "publickey",
          fingerprint: Optional[str] = None, owner: Optional[str] = None, identity: Optional[str] = None, flags: Optional[List[str]] = None,
          timing: Optional[str] = None, pid: Optional[int] = 4000, source_key_mismatch: bool = False) -> str:
    meta: Dict[str, Any] = {
        "success": True, "username": user, "source_ip": ip, "auth_method": method, "ssh_port": ssh_port, "ssh_security_flags": flags or [],
    }
    if sid:
        meta["ssh_session_id"] = sid
    if port is not None:
        meta["source_port"] = port
    if fingerprint:
        meta["fingerprint"] = fingerprint
        meta["key_owner"] = owner or "UNKNOWN"
        meta["identity_status"] = identity or "TRUSTED"
        meta["key_source"] = f"/home/{user}/.ssh/authorized_keys"
    if timing:
        meta["event_timing_status"] = timing
    if pid is not None:
        meta["ssh_source_pid"] = pid
    if source_key_mismatch:
        meta["key_user_mismatch"] = True
    return db.add(ts, "SSH_AUTH", "LOW", meta, f"SSH login diterima untuk '{user}' dari {ip}")


def fail(db: EventDb, ts: float, ip: str, user: str = "admin", *, ssh_port: int = 22, status: str = "INVALID_USER") -> str:
    return db.add(ts, "SSH_AUTH", "INFO", {
        "success": False, "username": user, "source_ip": ip, "auth_method": "password", "ssh_port": ssh_port, "username_status": status,
    }, f"Percobaan login gagal {user} dari {ip}")


def logout(db: EventDb, ts: float, sid: Optional[str], user: str, ip: str, *, login_time: Optional[float], duration: Optional[float],
           classification: str = "NORMAL_SESSION_END", reason: str = "Disconnected", reliable: bool = True, state: str = "LOGGED_OUT", timing: Optional[str] = None) -> str:
    meta: Dict[str, Any] = {
        "success": True, "username": user, "source_ip": ip, "ssh_logout_classification": classification, "ssh_logout_state": state, "logout_reason": reason,
        "session_logout_time_reliable": reliable,
    }
    if sid:
        meta["ssh_session_id"] = sid
    if reliable:
        meta["session_logout_time"] = ts
    if login_time is not None:
        meta["session_login_time"] = login_time
    if duration is not None:
        meta["session_duration_seconds"] = duration
    if timing:
        meta["event_timing_status"] = timing
    return db.add(ts, "SSH_LOGOUT", "INFO", meta, f"SSH logout {user}")


def live_session(sid: str, user: str, ip: str, port: int, *, auth_time: float = NOW - 600, ssh_port: int = 22, method: str = "publickey",
                 fingerprint: Optional[str] = "SHA256:liveKEY", owner: Optional[str] = "alice@example.com", key_source: Optional[str] = "/home/deploy/.ssh/authorized_keys",
                 pid: Optional[int] = 4321) -> Dict[str, Any]:
    return {
        "session_id": sid, "user": user, "source_ip": ip, "source_port": port, "ssh_port": ssh_port, "auth_method": method, "key_fingerprint": fingerprint,
        "key_owner": owner, "key_source": key_source, "auth_time": auth_time, "last_seen": auth_time + 5, "logout_time": None, "duration": None, "status": "ACTIVE",
        "risk_context": {"flags": []}, "sshd_pid": pid, "correlation_confidence": "EXACT", "identity_status": "TRUSTED", "uid": 1001,
    }


def snapshot(sessions: Optional[List[Dict[str, Any]]] = None, keys: Optional[Dict[str, Any]] = None, **overrides: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "available": True, "taken_at": NOW, "server": "srv2", "hostname": "srv2", "ssh_ports": [22], "alert_on_login_failure": False, "brute_force_threshold": 5,
        "brute_force_window_seconds": 60.0, "correlation_window_seconds": 300.0, "correlation_min_failures": 3, "session_ttl_seconds": 86400.0,
        "sessions": sessions or [], "keys": keys, "key_monitor_enabled": keys is not None,
    }
    data.update(overrides)
    return data


def key_snapshot(users: Dict[str, Any], *, created_at: float = NOW - 30 * 86400.0, initialized: bool = True, additions: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "initialized": initialized, "created_at": created_at, "users": users, "additions": additions or {}, "new_key_window_seconds": 604800.0, "truncated": False,
        "key_count": sum(len(s["keys"]) for u in users.values() for s in u["sources"].values()), "health": {},
    }


def key_entry(*, first_seen: float, status: str = "NOT_REGISTERED", owner: str = "", algorithm: str = "ssh-ed25519", comment: str = "") -> Dict[str, Any]:
    return {
        "algorithm": algorithm, "comment": comment, "first_seen": first_seen, "last_seen": NOW - 60, "option_names": [], "registry_status": status, "owner_email": owner,
        "owner_label": "",
    }


def user_keys(user: str, keys: Dict[str, Dict[str, Any]], *, first_seen: float = NOW - 30 * 86400.0, command: Optional[str] = None, files: Optional[List[str]] = None) -> Dict[str, Any]:
    path = files[0] if files else f"/home/{user}/.ssh/authorized_keys"
    return {
        "uid": 1001, "home": f"/home/{user}", "first_seen": first_seen, "last_seen": NOW - 60,
        "config": {"authorized_keys_files": files or [".ssh/authorized_keys"], "command": command, "command_user": None, "pubkey_authentication": True,
                   "trusted_user_ca_keys": None, "revoked_keys": None, "uncertain": []},
        "command": None, "sources": {path: {"scope": "USER_HOME", "exists": True, "keys_known": True, "first_seen": first_seen, "last_seen": NOW - 60, "keys": keys}},
    }


def run_ssh(db_path: Optional[str], snap: Optional[Dict[str, Any]], *, window: float = 3600.0, now: float = NOW, cfg: Optional[InvestigationConfig] = None,
            accounts: Optional[List[Dict[str, Any]]] = None, sudoers: Any = None, store: Optional[ReadOnlyStore] = None) -> Dict[str, Any]:
    cfg = cfg or InvestigationConfig()
    own = store is None
    store = store or ReadOnlyStore(db_path or "/nonexistent/rtsa.db", time_budget_seconds=5.0)
    if own:
        store.open()
    try:
        return build_ssh_report(
            store, snap, cfg, window, now, passwd_provider=lambda: list(accounts if accounts is not None else ROOT_ONLY),
            sudoers_provider=sudoers or (lambda user, groups: "NO_ENTRY"),
        )
    finally:
        if own:
            store.close()


def config_with_uid0(*names: str) -> InvestigationConfig:
    return InvestigationConfig(ssh=InvestigationSshConfig(known_legitimate_uid0=list(names)))


import asyncio

from _app_error_fakes import Clock, make_engine, make_event
from core.app_error_model import hash_user_id
from database.sqlite_pool import SQLiteWriteWorker

SALT = b"investigation-test-salt-0123456789"


def with_users(event: Any, count: int, base: int = 0) -> Any:
    for index in range(count):
        event.add_user_hash(hash_user_id(SALT, f"user-{base + index}"))
    return event


class AppFlow:
    def __init__(self, db_dir: Optional[str] = None, cfg: Any = None, clock: Optional[Clock] = None) -> None:
        self.dir = db_dir or tempfile.mkdtemp(prefix="rtsa-investigation-app-")
        self.db_path = os.path.join(self.dir, "rtsa.db")
        self.worker = SQLiteWriteWorker(self.db_path, flush_interval_seconds=0.05)
        self.engine, self.clock, self.metrics = make_engine(cfg, clock)

    async def start(self) -> "AppFlow":
        await self.worker.start()
        return self

    async def settle(self, expected: int, timeout: float = 8.0) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while self.worker.stats["written"] < expected and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.1)

    async def persist(self) -> int:
        rows = self.engine.drain_dirty(10 ** 6)
        before = self.worker.stats["written"]
        for row in rows:
            assert self.worker.enqueue_app_error_incident(row)
        await self.settle(before + len(rows))
        return len(rows)

    def event(self, *, users: int = 0, user_base: int = 0, **kwargs: Any) -> Any:
        ev = make_event(self.clock, **kwargs)
        return with_users(ev, users, user_base) if users else ev

    async def stop(self) -> None:
        await self.worker.stop()

    def cleanup(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def run_top(db_path: str, window: float = 86400.0, now: float = 0.0, cfg: Optional[InvestigationConfig] = None, info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from core.investigation_app import build_top_issues
    with ReadOnlyStore(db_path) as store:
        return build_top_issues(store, cfg or InvestigationConfig(), window, now, info)


def run_impact(db_path: str, window: float = 86400.0, now: float = 0.0, cfg: Optional[InvestigationConfig] = None, info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from core.investigation_app import build_project_impact
    with ReadOnlyStore(db_path) as store:
        return build_project_impact(store, cfg or InvestigationConfig(), window, now, info)


def run_detail(db_path: str, reference: str, now: float, cfg: Optional[InvestigationConfig] = None, info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from core.investigation_app import build_incident_detail, build_issue_brief
    cfg = cfg or InvestigationConfig()
    with ReadOnlyStore(db_path) as store:
        detail = build_incident_detail(store, cfg, reference, now, info)
        if detail.get("found"):
            detail["brief"] = build_issue_brief(detail, cfg, server="srv2")
        return detail
