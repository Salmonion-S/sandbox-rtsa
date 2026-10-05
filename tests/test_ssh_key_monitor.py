import asyncio
import base64
import logging
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _ssh_logout_fakes import IP, LOGIN_AT, SSH_PORT, FrozenClock, accepted, by_cat, closed, fields_of, make_monitor
from config.manager import SSHKeyMonitorConfig
from core import ssh_key_baseline as kb
from core import ssh_key_monitor as km
from core.datatypes import EventCategory, Severity
from core.ssh_key_registry import STATUS_REVOKED, SshKeyRegistry
from core.ssh_key_sources import SshAccount, discover_effective_key_paths, parse_key_line
from core.sshd_effective_config import SshdConfigResolver

IS_ROOT = os.geteuid() == 0


def mk_key(n, comment="", options=""):
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + hashlib.sha256(f"key-{n}".encode()).digest()
    line = f"{options + ' ' if options else ''}ssh-ed25519 {base64.b64encode(blob).decode()}" + (f" {comment}" if comment else "")
    return line, parse_key_line(line).fingerprint


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class Lab:
    def __init__(self, sshd="", users=("alice",), state=True, registry=True, **cfg):
        self.root = tempfile.mkdtemp(prefix="rtsa_keys_")
        self.config_path = os.path.join(self.root, "sshd_config")
        self.write_sshd(sshd)
        self.homes = {}
        self.uid, self.gid = 1000, 1000
        for user in users:
            home = os.path.join(self.root, "home", user)
            os.makedirs(os.path.join(home, ".ssh"))
            self.homes[user] = home
        self.registry = SshKeyRegistry(os.path.join(self.root, "registry.json"))
        self.clock = Clock()
        self.events = []
        self.sessions = []
        self.ip_known = {}
        self.accounts = [SshAccount(u, self.uid + i, self.gid + i, h, "/bin/bash") for i, (u, h) in enumerate(self.homes.items())]
        self.state_path = os.path.join(self.root, "baseline.json") if state else ""
        options = dict(
            state_path=self.state_path, debounce_seconds=0.2, initial_delay_seconds=0.0, max_events_per_cycle=20,
            reconcile_interval_seconds=30.0,
        )
        options.update(cfg)
        self.cfg = SSHKeyMonitorConfig(**options)
        self.resolver = None
        self.monitor = self.make_monitor()

    def write_sshd(self, text):
        with open(self.config_path, "w") as handle:
            handle.write(text)

    def make_monitor(self, server="server1"):
        self.resolver = SshdConfigResolver(self.config_path, stat_ttl_seconds=0.0)
        return km.SshKeyMonitor(
            self.cfg, server_id=server, resolver=self.resolver, registry=self.registry, publish=self.events.append,
            active_sessions=lambda: list(self.sessions), ip_known=lambda user, ip: self.ip_known.get((user, ip)),
            clock=self.clock, accounts_provider=lambda: (list(self.accounts), False),
        )

    def path(self, user, name="authorized_keys"):
        return os.path.join(self.homes[user], ".ssh", name)

    def write(self, path, lines, mode=0o600):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write("\n".join(lines) + ("\n" if lines else ""))
        os.chmod(path, mode)

    async def baseline(self):
        events = await self.monitor.reconcile(None, "test-baseline")
        assert events == [] and self.monitor.baseline.initialized
        self.events.clear()

    async def cycle(self, users=None):
        before = len(self.events)
        await self.monitor.reconcile(None if users is None else set(users), "test")
        return self.events[before:]

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def types_of(events):
    return [e.change_types for e in events]


def run(coro):
    return asyncio.run(coro)


def test_1_authorized_keys_baseline_is_silent_then_addition_is_detected():
    async def go():
        lab = Lab()
        try:
            a, _ = mk_key(1, "alice@laptop")
            lab.write(lab.path("alice"), [a])
            await lab.baseline()
            assert lab.monitor.baseline.key_count() == 1
            b, fp_b = mk_key(2, "bob@phone")
            lab.write(lab.path("alice"), [a, b])
            events = await lab.cycle()
            assert len(events) == 1 and events[0].change_types == [kb.KEY_ADDED] and events[0].users == ["alice"]
            event = events[0]
            assert event.fingerprints == [fp_b] and event.keys[0]["algorithm"] == "ssh-ed25519" and event.keys[0]["comment"] == "bob@phone"
            assert event.classification == km.UNKNOWN_KEY_CHANGE and event.severity == "MEDIUM"
            assert event.source == lab.path("alice") and event.details[kb.KEY_ADDED]["source_stat"]["mode"] == "0600"
            assert "hacker" not in event.message.lower() and "hacker" not in " ".join(event.evidence).lower()
            assert not await lab.cycle()
        finally:
            lab.cleanup()
    run(go())
    print("Test 1 (authorized_keys: the initial baseline raises nothing, a new key is KEY_ADDED/UNKNOWN_KEY_CHANGE with algorithm, SHA256, comment, source, mode; an unchanged cycle is silent) PASSED")


def test_2_authorized_keys2_is_monitored_only_when_sshd_really_uses_it():
    async def go():
        for sshd, effective in (
            ("", True),
            ("AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n", True),
            ("AuthorizedKeysFile .ssh/authorized_keys\n", False),
        ):
            lab = Lab(sshd=sshd)
            try:
                a, _ = mk_key(1)
                lab.write(lab.path("alice"), [a])
                lab.write(lab.path("alice", "authorized_keys2"), [])
                await lab.baseline()
                sources = set(lab.monitor.baseline.users["alice"].sources)
                assert (lab.path("alice", "authorized_keys2") in sources) is effective, (sshd, sources)
                extra, fp = mk_key(9, "planted")
                lab.write(lab.path("alice", "authorized_keys2"), [extra])
                events = await lab.cycle()
                if effective:
                    assert len(events) == 1 and events[0].source == lab.path("alice", "authorized_keys2") and events[0].fingerprints == [fp]
                else:
                    assert events == [], "a file sshd does not read is not an authorized-key source"
                    health = lab.monitor.health()
                    assert health["inactive_candidate_sources"] == [{"user": "alice", "path": lab.path("alice", "authorized_keys2")}]
            finally:
                lab.cleanup()
    run(go())
    print("Test 2 (authorized_keys2: default and explicit config monitor it; AuthorizedKeysFile limited to authorized_keys does not, and the unused file is only listed as an inactive candidate) PASSED")


def test_3_multiple_authorized_keys_files_tokens_and_a_shared_global_file():
    async def go():
        shared = None
        lab = Lab(users=("alice", "bob"))
        try:
            shared = os.path.join(lab.root, "shared", "authorized_keys")
            peruser = os.path.join(lab.root, "keys", "%u")
            lab.write_sshd(
                f"AuthorizedKeysFile .ssh/authorized_keys %h/.ssh/authorized_keys2 {peruser} {shared} none\n"
            )
            a, _ = mk_key(1)
            lab.write(lab.path("alice"), [a])
            await lab.baseline()
            alice = lab.monitor.baseline.users["alice"]
            expected = {
                lab.path("alice"), lab.path("alice", "authorized_keys2"), os.path.join(lab.root, "keys", "alice"), shared,
            }
            assert set(alice.sources) == expected, set(alice.sources)
            assert {s.scope for s in alice.sources.values()} == {"USER_HOME", "USER_SPECIFIC", "GLOBAL"}
            k1, fp1 = mk_key(11, "carol")
            lab.write(os.path.join(lab.root, "keys", "alice"), [k1])
            events = await lab.cycle()
            assert [e.users for e in events] == [["alice"]] and events[0].scope == "USER_SPECIFIC"
            k2, fp2 = mk_key(12, "shared-admin")
            lab.write(shared, [k2])
            events = await lab.cycle()
            assert len(events) == 1 and events[0].users == ["alice", "bob"] and events[0].scope == "GLOBAL"
            assert set(events[0].change_types) == {kb.KEY_SOURCE_CREATED, kb.KEY_ADDED}
            assert events[0].primary == kb.KEY_SOURCE_CREATED
            assert events[0].classification == km.SUSPICIOUS_KEY_CHANGE
            assert any("global" in line for line in events[0].evidence)
        finally:
            lab.cleanup()
    run(go())
    print("Test 3 (several AuthorizedKeysFile entries with %h/%u tokens, 'none', a per-user path and one shared global file: every effective source is baselined, a shared change is ONE event for all users, GLOBAL scope is an aggravator) PASSED")


def test_4_creation_removal_replacement_and_option_change():
    async def go():
        lab = Lab()
        try:
            a, fp_a = mk_key(1, "alice@laptop")
            lab.write(lab.path("alice"), [a])
            await lab.baseline()
            b, fp_b = mk_key(2, "work@laptop")
            lab.write(lab.path("alice", "authorized_keys2"), [b])
            created = await lab.cycle()
            assert len(created) == 1 and created[0].primary == kb.KEY_SOURCE_CREATED and kb.KEY_ADDED in created[0].change_types
            assert created[0].classification == km.UNKNOWN_KEY_CHANGE, "a new file alone is not malicious"
            c, fp_c = mk_key(3, "alice@laptop")
            lab.write(lab.path("alice"), [c])
            replaced = await lab.cycle()
            assert len(replaced) == 1 and set(replaced[0].change_types) == {kb.KEY_ADDED, kb.KEY_REMOVED}
            assert replaced[0].details[kb.KEY_ADDED]["replacement_candidates"] == [{"old": fp_a, "new": fp_c, "basis": "same comment"}]
            lab.write(lab.path("alice"), [])
            removed = await lab.cycle()
            assert len(removed) == 1 and removed[0].primary == kb.KEY_REMOVED and removed[0].fingerprints == [fp_c]
            os.remove(lab.path("alice", "authorized_keys2"))
            deleted = await lab.cycle()
            assert len(deleted) == 1 and deleted[0].primary == kb.KEY_SOURCE_DELETED and deleted[0].fingerprints == [fp_b]
            d, fp_d = mk_key(4, "ci")
            lab.write(lab.path("alice"), [d])
            await lab.cycle()
            lab.write(lab.path("alice"), [d.replace("ssh-ed25519", 'command="/bin/sh -i",no-pty ssh-ed25519', 1)])
            changed = await lab.cycle()
            assert len(changed) == 1 and changed[0].primary == kb.KEY_CHANGED
            row = changed[0].details[kb.KEY_CHANGED]["keys"][0]
            assert row["forced_command_added"] is True and set(row["options_added"]) == {"command", "no-pty"}
            assert changed[0].classification == km.SUSPICIOUS_KEY_CHANGE
            lab.write(lab.path("alice"), [d.replace("ssh-ed25519", 'command="/bin/sh -i",no-pty ssh-ed25519', 1) + " renamed"])
            commented = await lab.cycle()
            assert commented[0].primary == kb.KEY_CHANGED and commented[0].details[kb.KEY_CHANGED]["keys"][0]["comment_changed"]
        finally:
            lab.cleanup()
    run(go())
    print("Test 4 (file creation, key removal, replacement with the same comment, file deletion and KEY_CHANGED for options/comment; a new file alone stays UNKNOWN, a forced command is SUSPICIOUS) PASSED")


def test_5_permission_and_ownership_changes_including_root_owned_files():
    async def go():
        lab = Lab()
        try:
            a, _ = mk_key(1)
            lab.write(lab.path("alice"), [a], mode=0o600)
            await lab.baseline()
            os.chmod(lab.path("alice"), 0o640)
            events = await lab.cycle()
            assert len(events) == 1 and events[0].primary == kb.PERMISSION_CHANGED
            assert events[0].details[kb.PERMISSION_CHANGED]["old_mode"] == "0600" and events[0].details[kb.PERMISSION_CHANGED]["new_mode"] == "0640"
            assert events[0].classification == km.UNKNOWN_KEY_CHANGE
            os.chmod(lab.path("alice"), 0o666)
            events = await lab.cycle()
            assert events[0].classification == km.SUSPICIOUS_KEY_CHANGE and events[0].details[kb.PERMISSION_CHANGED]["group_or_world_writable"] is True
            if IS_ROOT:
                os.chmod(lab.path("alice"), 0o600)
                await lab.cycle()
                os.chown(lab.path("alice"), 12345, 12345)
                events = await lab.cycle()
                assert len(events) == 1 and events[0].primary == kb.OWNERSHIP_CHANGED
                detail = events[0].details[kb.OWNERSHIP_CHANGED]
                assert detail["new_uid"] == 12345 and detail["old_uid"] == 0
                assert events[0].classification == km.SUSPICIOUS_KEY_CHANGE
                os.chown(lab.path("alice"), 0, 0)
                events = await lab.cycle()
                assert events[0].primary == kb.OWNERSHIP_CHANGED and events[0].classification == km.UNKNOWN_KEY_CHANGE
                b, _ = mk_key(2)
                lab.write(lab.path("alice"), [a, b])
                os.chown(lab.path("alice"), 0, 0)
                events = await lab.cycle()
                assert events and events[0].primary == kb.KEY_ADDED, "a change made by or as root is still detected"
        finally:
            lab.cleanup()
    run(go())
    print("Test 5 (mode change and ownership change are detected; world-writable or an unexpected owner is SUSPICIOUS; root-owned files and root edits are never ignored) PASSED")


def test_6_sshd_config_change_new_sources_and_authorized_keys_command_never_executed():
    async def go():
        lab = Lab(sshd="AuthorizedKeysFile .ssh/authorized_keys\n")
        try:
            a, _ = mk_key(1)
            lab.write(lab.path("alice"), [a])
            extra, fp_extra = mk_key(7, "already-there")
            lab.write(lab.path("alice", "authorized_keys2"), [extra])
            await lab.baseline()
            assert lab.path("alice", "authorized_keys2") not in lab.monitor.baseline.users["alice"].sources
            lab.write_sshd("AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n")
            lab.resolver.invalidate()
            lab.monitor.notify_config_changed()
            events = await lab.cycle()
            primaries = sorted(e.primary for e in events)
            assert primaries == sorted([kb.SSH_KEY_CONFIG_CHANGED, kb.KEY_ADDED]), primaries
            added = next(e for e in events if e.primary == kb.KEY_ADDED)
            assert added.details[kb.KEY_ADDED]["newly_effective"] is True and added.fingerprints == [fp_extra]
            config = next(e for e in events if e.primary == kb.SSH_KEY_CONFIG_CHANGED)
            assert config.details[kb.SSH_KEY_CONFIG_CHANGED]["delta"]["authorized_keys_files"]["added"] == [".ssh/authorized_keys2"]
            marker = os.path.join(lab.root, "command_ran")
            script = os.path.join(lab.root, "keys.sh")
            with open(script, "w") as handle:
                handle.write(f"#!/bin/sh\ntouch {marker}\n")
            os.chmod(script, 0o755)
            lab.write_sshd(f"AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\nAuthorizedKeysCommand {script} %u\nAuthorizedKeysCommandUser root\n")
            lab.resolver.invalidate()
            lab.monitor.notify_config_changed()
            events = await lab.cycle()
            assert len(events) == 1 and events[0].primary == kb.SSH_KEY_CONFIG_CHANGED
            assert events[0].classification == km.SUSPICIOUS_KEY_CHANGE and any("AuthorizedKeysCommand" in e for e in events[0].evidence)
            assert not os.path.exists(marker), "AuthorizedKeysCommand must never be executed"
            os.chmod(script, 0o777)
            events = await lab.cycle()
            assert events and events[0].primary == kb.SSH_KEY_CONFIG_CHANGED
            assert "command_binary_changed" in json.dumps(events[0].details, default=str)
            assert lab.monitor.baseline.users["alice"].config["command"].startswith(script)
        finally:
            lab.cleanup()
    run(go())
    print("Test 6 (effective sshd config change: a source that becomes effective is reported as SSH_KEY_CONFIG_CHANGED + KEY_ADDED(newly_effective), AuthorizedKeysCommand is audited and its binary tracked but never executed) PASSED")


def test_7_duplicate_file_events_collapse_into_one_reconciliation_and_one_alert():
    async def go():
        lab = Lab()
        try:
            a, _ = mk_key(1)
            lab.write(lab.path("alice"), [a])
            await lab.baseline()
            path = lab.path("alice")
            b, _ = mk_key(2)
            tmp = path + ".tmp"
            for index in range(5):
                lab.write(tmp, [a, b])
                os.replace(tmp, path)
            for _ in range(50):
                assert lab.monitor.notify_path(path, {"actor": "x", "process_name": "vim"})
            assert lab.monitor.deduplicated_total >= 49
            assert not lab.monitor.notify_path(os.path.join(lab.root, "unrelated.txt"))
            events = await lab.cycle(users={"alice"})
            assert len(events) == 1 and events[0].change_types == [kb.KEY_ADDED]
            assert events[0].actors["fim"]["process_name"] == "vim"
            assert not await lab.cycle(users={"alice"}) and not await lab.cycle()
            c, _ = mk_key(3)
            monitor_task = asyncio.create_task(lab.monitor.run())
            await asyncio.sleep(0.5)
            lab.write(path, [a, b, c])
            before = len(lab.events)
            for _ in range(20):
                lab.monitor.notify_path(path, {})
            await asyncio.sleep(1.0)
            lab.monitor.stop()
            await asyncio.wait_for(monitor_task, 5)
            assert len(lab.events) - before == 1, "twenty file events within the debounce window produce one alert"
        finally:
            lab.cleanup()
    run(go())
    print("Test 7 (atomic rewrites and 50+ duplicate FIM notifications fold into one reconciliation and exactly one alert; the event-driven loop debounces; unrelated paths are ignored) PASSED")


def test_8_login_with_a_new_key_correlates_and_raises_risk_by_evidence():
    async def go():
        lab = Lab()
        try:
            a, _ = mk_key(1)
            lab.write(lab.path("alice"), [a])
            await lab.baseline()
            b, fp_b = mk_key(2, "stranger")
            lab.clock.t += 100
            lab.write(lab.path("alice"), [a, b])
            added = (await lab.cycle())[0]
            assert added.classification == km.UNKNOWN_KEY_CHANGE
            assert f"alice|{fp_b}" in lab.monitor.baseline.additions
            lab.ip_known[("alice", "198.51.100.7")] = False
            lab.clock.t += 120
            event = lab.monitor.on_login(
                user="alice", fingerprint=fp_b, source_ip="198.51.100.7", source_port=50222, ssh_port=SSH_PORT, auth_method="publickey",
                event_time=lab.clock.t,
            )
            assert event is not None and event.classification == km.CORRELATED_SSH_INTRUSION and event.phase == km.PHASE_LOGIN
            assert event.severity == "CRITICAL", event.evidence
            assert event.login["source_ip"] == "198.51.100.7" and event.login["source_port"] == 50222 and event.login["ssh_port"] == SSH_PORT
            assert event.login["auth_method"] == "publickey" and 119 <= event.login["seconds_after_key_added"] <= 121
            assert any("IP belum pernah terlihat" in e for e in event.evidence) and any("detik sejak ditambahkan" in e for e in event.evidence)
            assert "hacker" not in event.message.lower()
            assert lab.monitor.on_login(user="alice", fingerprint=fp_b, source_ip="198.51.100.7", source_port=50223, ssh_port=SSH_PORT,
                                        auth_method="publickey", event_time=lab.clock.t + 5) is None, "same key + same IP: no second alert"
            other = lab.monitor.on_login(user="alice", fingerprint=fp_b, source_ip="203.0.113.9", source_port=40000, ssh_port=SSH_PORT,
                                         auth_method="publickey", event_time=lab.clock.t + 6)
            assert other is not None and other.login["source_ip"] == "203.0.113.9"
            ended = lab.monitor.on_logout(user="alice", fingerprint=fp_b, source_ip="198.51.100.7", source_port=50222, duration=300.0, event_time=lab.clock.t + 400)
            assert ended is not None and ended.phase == km.PHASE_SESSION_ENDED and ended.severity == "MEDIUM"
            assert lab.monitor.on_logout(user="alice", fingerprint=fp_b, source_ip="198.51.100.7", source_port=50222, duration=300.0, event_time=lab.clock.t + 401) is None
            assert lab.monitor.on_login(user="alice", fingerprint="SHA256:neverseen", source_ip=IP, source_port=1, ssh_port=1, auth_method="publickey", event_time=lab.clock.t) is None
        finally:
            lab.cleanup()
    run(go())
    print("Test 8 (a new unregistered key used to log in is CORRELATED_SSH_INTRUSION with IP/ports/method; risk rises from the evidence (new IP + fast use + no admin session); same IP is deduplicated; the session end is reported once) PASSED")


def test_9_unknown_key_never_used_stays_a_plain_change_and_expires():
    async def go():
        lab = Lab(new_key_window_seconds=3600.0)
        try:
            a, _ = mk_key(1)
            lab.write(lab.path("alice"), [a])
            await lab.baseline()
            b, fp_b = mk_key(2)
            lab.write(lab.path("alice"), [a, b])
            events = await lab.cycle()
            assert [e.classification for e in events] == [km.UNKNOWN_KEY_CHANGE] and not lab.monitor.correlated_total
            lab.clock.t += 7200
            assert lab.monitor.on_login(user="alice", fingerprint=fp_b, source_ip=IP, source_port=2, ssh_port=22, auth_method="publickey", event_time=lab.clock.t) is None
            assert f"alice|{fp_b}" not in lab.monitor.baseline.additions
            assert lab.monitor.on_login(user="alice", fingerprint=fp_b, source_ip=IP, source_port=2, ssh_port=22, auth_method="publickey", event_time=None) is None
        finally:
            lab.cleanup()
    run(go())
    print("Test 9 (a new key that is never used produces only UNKNOWN_KEY_CHANGE; after the window it is forgotten and a later login is not escalated) PASSED")


def test_10_known_admin_key_revoked_key_and_known_admin_ip_do_not_escalate_or_do_escalate():
    async def go():
        lab = Lab()
        try:
            a, _ = mk_key(1)
            lab.write(lab.path("alice"), [a])
            await lab.baseline()
            known, fp_known = mk_key(2, "admin@corp.example")
            assert lab.registry.register(fp_known, "admin@corp.example", "Admin", expected_linux_users=["alice"])[0]
            lab.write(lab.path("alice"), [a, known])
            events = await lab.cycle()
            assert [e.classification for e in events] == [km.KNOWN_ADMIN_CHANGE] and events[0].severity == "LOW"
            assert events[0].keys[0]["registry_status"] == "TRUSTED" and events[0].keys[0]["registry_owner"] == "admin@corp.example"
            assert lab.monitor.on_login(user="alice", fingerprint=fp_known, source_ip="198.51.100.1", source_port=1, ssh_port=22, auth_method="publickey", event_time=lab.clock.t + 1) is None
            revoked, fp_revoked = mk_key(3, "old@corp.example")
            assert lab.registry.register(fp_revoked, "old@corp.example", "Old", status=STATUS_REVOKED)[0]
            lab.write(lab.path("alice"), [a, known, revoked])
            events = await lab.cycle()
            assert events[0].classification == km.SUSPICIOUS_KEY_CHANGE and any("REVOKED" in e for e in events[0].evidence)
            lab.sessions.append({
                "user": "alice", "source_ip": "192.0.2.50", "source_port": 4000, "ssh_port": 22, "auth_method": "publickey",
                "fingerprint": fp_known, "session_id": "s1", "auth_time": lab.clock.t,
            })
            stranger, fp_stranger = mk_key(4, "colleague")
            lab.write(lab.path("alice"), [a, known, revoked, stranger])
            events = await lab.cycle()
            assert events[0].classification == km.UNKNOWN_KEY_CHANGE
            assert events[0].actors["resolution"] == "ACTIVE_SESSION_CANDIDATES" and events[0].actors["active_sessions"][0]["source_ip"] == "192.0.2.50"
            assert any("sesi admin" in e for e in events[0].evidence)
            from_admin = lab.monitor.on_login(user="alice", fingerprint=fp_stranger, source_ip="192.0.2.50", source_port=5000, ssh_port=22, auth_method="publickey", event_time=lab.clock.t + 30)
            assert from_admin is None, "the same IP as the admin session that was active when the key appeared is not escalated"
            from_elsewhere = lab.monitor.on_login(user="alice", fingerprint=fp_stranger, source_ip="198.18.0.5", source_port=5001, ssh_port=22, auth_method="publickey", event_time=lab.clock.t + 31)
            assert from_elsewhere is not None and from_elsewhere.severity in ("HIGH", "CRITICAL")
            lab.registry.register(fp_stranger, "colleague@corp.example", "Colleague", overwrite=True)
            assert lab.monitor.on_login(user="alice", fingerprint=fp_stranger, source_ip="198.18.0.99", source_port=5002, ssh_port=22, auth_method="publickey", event_time=lab.clock.t + 32) is None
        finally:
            lab.cleanup()
    run(go())
    print("Test 10 (a registered admin key is KNOWN_ADMIN_CHANGE/LOW and its login is normal; a REVOKED key is SUSPICIOUS; active-session actors are candidates only; the admin's own IP is not escalated; a key registered later is verified) PASSED")


def test_11_delayed_and_replayed_logins_are_judged_by_event_time():
    async def go():
        lab = Lab()
        try:
            a, _ = mk_key(1)
            lab.write(lab.path("alice"), [a])
            await lab.baseline()
            b, fp_b = mk_key(2)
            lab.clock.t += 1000
            added_at = lab.clock.t
            lab.write(lab.path("alice"), [a, b])
            await lab.cycle()
            lab.clock.t += 600
            replayed_old = lab.monitor.on_login(
                user="alice", fingerprint=fp_b, source_ip="198.51.100.2", source_port=1, ssh_port=22, auth_method="publickey",
                event_time=added_at - 500, timing_status="REPLAYED",
            )
            assert replayed_old is None, "a login that happened BEFORE the key was added (replayed journal) is not correlated"
            delayed = lab.monitor.on_login(
                user="alice", fingerprint=fp_b, source_ip="198.51.100.2", source_port=2, ssh_port=22, auth_method="publickey",
                event_time=added_at + 60, timing_status="DELAYED",
            )
            assert delayed is not None and delayed.login["delayed_login"] is True
            assert 59 <= delayed.login["seconds_after_key_added"] <= 61, "delta uses the login EVENT time, not processing time"
        finally:
            lab.cleanup()
    run(go())
    print("Test 11 (delayed/replayed login lines: a login whose event time precedes the key addition is never correlated; a delayed one is correlated by event time and flagged delayed_login) PASSED")


def test_12_baseline_persistence_restart_corruption_and_server_isolation():
    async def go():
        lab = Lab()
        try:
            a, _ = mk_key(1, "alice")
            lab.write(lab.path("alice"), [a])
            await lab.baseline()
            assert os.path.exists(lab.state_path) and stat.S_IMODE(os.stat(lab.state_path).st_mode) == 0o600
            raw = json.load(open(lab.state_path))
            assert raw["server"] == "server1" and raw["initialized"] is True
            source = raw["users"]["alice"]["sources"][lab.path("alice")]
            key = next(iter(source["keys"].values()))
            assert {"algorithm", "comment", "first_seen", "last_seen"} <= set(key) and source["owner"] and source["mode"] == 0o600 and "uid" in source
            b, fp_b = mk_key(2)
            lab.write(lab.path("alice"), [a, b])
            lab.events.clear()
            restarted = lab.make_monitor()
            restarted.baseline.load()
            events = await restarted.reconcile(None, "after-restart")
            assert len(events) == 1 and events[0].change_types == [kb.KEY_ADDED] and events[0].fingerprints == [fp_b], "a change made while RTSA was down is detected after restart"
            third = lab.make_monitor()
            third.baseline.load()
            assert await third.reconcile(None, "again") == []
            first_seen = third.baseline.users["alice"].sources[lab.path("alice")].keys[parse_key_line(a).fingerprint].first_seen
            assert first_seen <= lab.clock.t
            other = lab.make_monitor(server="server2")
            other.baseline.load()
            assert await other.reconcile(None, "other-server") == [] and other.baseline.rebuilt_reason == "server_mismatch"
            with open(lab.state_path, "w") as handle:
                handle.write("{not json")
            broken = lab.make_monitor()
            broken.baseline.load()
            lab.write(lab.path("alice"), [a])
            assert await broken.reconcile(None, "corrupt") == [] and broken.baseline.rebuilt_reason == "unreadable" and broken.baseline.initialized
        finally:
            lab.cleanup()
    run(go())
    print("Test 12 (persistent baseline per server+user+source+fingerprint with first_seen/last_seen/owner/mode, 0600; restart detects downtime changes; another server's or a corrupt baseline is rebuilt silently, never mixed) PASSED")


def test_13_unreadable_or_unstable_sources_never_become_false_removals_and_floods_are_capped():
    async def go():
        lab = Lab(users=tuple(f"u{i}" for i in range(30)), max_events_per_cycle=5)
        try:
            for user in lab.homes:
                lab.write(lab.path(user), [mk_key(hash(user) % 1000)[0]])
            await lab.baseline()
            victim = lab.path("u0")
            os.remove(victim)
            os.mkdir(victim)
            events = await lab.cycle(users={"u0"})
            assert events == [] and lab.monitor.unreadable_sources == 1
            assert lab.monitor.baseline.users["u0"].sources[victim].keys, "the baseline keys survive a source that cannot be read"
            os.rmdir(victim)
            lab.write(victim, [mk_key(hash("u0") % 1000)[0]])
            assert await lab.cycle(users={"u0"}) == []
            for index, user in enumerate(lab.homes):
                lab.write(lab.path(user), [mk_key(hash(user) % 1000)[0], mk_key(5000 + index)[0]])
            events = await lab.cycle()
            assert len(events) == 6 and events[-1].source == "multiple sources" and events[-1].details["additional_groups"] == 25
            assert lab.monitor.suppressed_total == 25
            assert not await lab.cycle(), "suppressed groups are baselined, not repeated"
        finally:
            lab.cleanup()
    run(go())
    print("Test 13 (an unreadable source keeps its baseline instead of reporting removals; 30 simultaneous changes become 5 alerts + one summary and are not repeated) PASSED")


def test_14_performance_and_memory_with_many_users():
    async def go():
        users = tuple(f"user{i}" for i in range(500))
        lab = Lab(users=users, max_users=2000)
        try:
            for index, user in enumerate(users):
                lab.write(lab.path(user), [mk_key(index * 3 + k)[0] for k in range(3)])
                lab.write(lab.path(user, "authorized_keys2"), [mk_key(100000 + index)[0]])
            started = time.time()
            await lab.baseline()
            first = time.time() - started
            assert lab.monitor.baseline.key_count() == 500 * 4 and lab.monitor.baseline.source_count() == 1000
            reads_after_baseline = lab.monitor.reader.reads
            started = time.time()
            assert not await lab.cycle()
            second = time.time() - started
            assert lab.monitor.reader.reads == reads_after_baseline, "unchanged files are never re-read (stat signature cache)"
            assert lab.monitor.reader.cache_hits >= 1000
            assert first < 20.0 and second < 10.0, (first, second)
            size = os.path.getsize(lab.state_path)
            assert size < 6_000_000, size
            lab.write(lab.path("user7"), [mk_key(7 * 3)[0], mk_key(999999)[0]])
            started = time.time()
            events = await lab.cycle(users={"user7"})
            partial = time.time() - started
            assert len(events) == 1 and partial < 1.0, partial
            import tracemalloc

            tracemalloc.start()
            await lab.cycle()
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            assert peak < 40_000_000, peak
            print(f"        500 users/1000 sources/2000 keys: baseline {first:.2f}s, unchanged cycle {second:.2f}s, one-user cycle {partial:.3f}s, state {size / 1024:.0f} KiB, peak {peak / 1e6:.1f} MB")
        finally:
            lab.cleanup()
    run(go())
    print("Test 14 (500 users x 2 sources: baseline and unchanged cycles are bounded, no file is re-read, a one-user reconcile is sub-second, state and peak memory stay small) PASSED")


def test_15_fim_and_persistence_discovery_use_the_effective_sources():
    lab = Lab(users=("alice", "bob"), sshd="AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n")
    try:
        resolver = SshdConfigResolver(lab.config_path, stat_ttl_seconds=0.0)

        class Entry:
            def __init__(self, name, home, uid=1000):
                self.pw_name, self.pw_dir, self.pw_uid, self.pw_gid, self.pw_shell = name, home, uid, uid, "/bin/bash"

        entries = [Entry("alice", lab.homes["alice"]), Entry("bob", lab.homes["bob"], 1001), Entry("daemon", "/usr/sbin", 1)]
        entries[2].pw_shell = "/usr/sbin/nologin"
        paths = discover_effective_key_paths(lab.config_path, resolver=resolver, passwd_entries=entries)
        assert lab.path("alice", "authorized_keys2") in paths and lab.path("bob") in paths
        assert all(cls == "ssh_authorized_keys" for cls in paths.values())
        lab.write_sshd("AuthorizedKeysFile .ssh/authorized_keys\n")
        resolver.invalidate()
        paths = discover_effective_key_paths(lab.config_path, resolver=resolver, passwd_entries=entries)
        assert lab.path("alice", "authorized_keys2") not in paths and lab.path("alice") in paths

        import modules.file_integrity_detector as fim
        import modules.host_persistence_detector as hp
        from config.manager import CriticalSystemWatchConfig, HostPersistenceDetectorConfig

        original_fim, original_hp = fim.discover_effective_key_paths, hp.discover_effective_key_paths
        wanted = lab.path("alice", "authorized_keys2")
        lab.write(wanted, [])
        try:
            fim.discover_effective_key_paths = lambda path: {wanted: "ssh_authorized_keys"}
            hp.discover_effective_key_paths = lambda path: {wanted: "ssh_authorized_keys"}
            critical = CriticalSystemWatchConfig(watched_system_files=[], watched_system_directories=[], cron_paths=[], systemd_unit_paths=[],
                                                 shell_profile_paths=[], shell_profile_globs=[], rc_paths=[], ssh_authorized_keys_glob=os.path.join(lab.root, "none", "*"),
                                                 ignore_path_substrings=[])
            assert fim.discover_critical_system_targets(critical) == {wanted: "ssh_authorized_keys"}
            disabled = CriticalSystemWatchConfig(watched_system_files=[], watched_system_directories=[], cron_paths=[], systemd_unit_paths=[],
                                                 shell_profile_paths=[], shell_profile_globs=[], rc_paths=[], ssh_authorized_keys_glob=os.path.join(lab.root, "none", "*"),
                                                 ignore_path_substrings=[], ssh_authorized_keys_effective_discovery=False)
            assert fim.discover_critical_system_targets(disabled) == {}
            persistence = HostPersistenceDetectorConfig(
                ssh_authorized_keys_glob=os.path.join(lab.root, "none", "*"), ssh_known_hosts_glob=os.path.join(lab.root, "none", "*"),
                ssh_root_authorized_keys_path="/nonexistent", ssh_root_known_hosts_path="/nonexistent", sshd_config_path="/nonexistent",
            )
            assert hp.discover_ssh_paths(persistence) == {wanted: "authorized_keys"}
            def boom(path):
                raise RuntimeError("resolver failure")
            fim.discover_effective_key_paths = boom
            logging.disable(logging.CRITICAL)
            try:
                assert fim.discover_critical_system_targets(critical) == {}, "a discovery error falls back to the glob instead of breaking FIM"
            finally:
                logging.disable(logging.NOTSET)
        finally:
            fim.discover_effective_key_paths, hp.discover_effective_key_paths = original_fim, original_hp
        detector = fim.FileIntegrityDetector.__new__(fim.FileIntegrityDetector)
        assert fim.FileIntegrityDetector._infer_critical_system_target_class.__code__.co_names.count("is_tracked_key_source") >= 1
        assert "authorized_keys2" in fim._HIGH_VALUE_FILENAMES
    finally:
        lab.cleanup()
    print("Test 15 (FIM and host-persistence discovery follow the effective AuthorizedKeysFile: authorized_keys2 only when sshd uses it, nologin accounts handled, glob fallback on errors, feature switchable) PASSED")


def test_16_ssh_monitor_integration_keeps_ssh_auth_and_adds_key_events():
    lab = Lab()
    try:
        a, _ = mk_key(1)
        lab.write(lab.path("alice"), [a])
        asyncio.run(lab.baseline())
        b, fp_b = mk_key(2, "stranger")
        lab.clock.t = LOGIN_AT - 300
        lab.write(lab.path("alice"), [a, b])
        mon, pub = make_monitor(meta_factory=lambda fingerprint, **extra: {
            "fingerprint": fingerprint, "key_type": "ED25519", "identity_status": "UNKNOWN_KEY", "key_owner": "UNKNOWN",
            "key_owner_basis": "UNKNOWN", "key_user_mismatch": None, "trusted_linux_user": True,
        }, trusted=("alice",))
        lab.monitor._publish = mon._publish_key_event
        lab.monitor._active_session_rows = mon._active_session_rows
        lab.monitor._active_sessions = mon._active_session_rows
        mon._key_monitor = lab.monitor
        asyncio.run(lab.cycle())
        pub_changes = by_cat(pub, EventCategory.SSH_KEY_CHANGE)
        assert len(pub_changes) == 1
        change = pub_changes[0]
        assert change.severity == Severity.MEDIUM and change.metadata["classification"] == km.UNKNOWN_KEY_CHANGE
        assert change.metadata["change_type"] == kb.KEY_ADDED and change.metadata["linux_users"] == ["alice"]
        assert change.metadata["key_source"] == lab.path("alice") and change.metadata["keys"][0]["fingerprint"] == fp_b
        fields = fields_of(change)
        assert fields["Klasifikasi"].replace("\\", "") == km.UNKNOWN_KEY_CHANGE and "ACTION" in fields and "Key" in fields and "Evidence" in fields
        assert "hacker" not in json.dumps(fields).lower()
        lab.clock.t = LOGIN_AT + 20
        with FrozenClock(LOGIN_AT + 30):
            mon._process_line(accepted(user="alice", ip="198.51.100.44", port=40123, fp=fp_b), event_time=LOGIN_AT, pid=7001)
        auth = by_cat(pub, EventCategory.SSH_AUTH)
        assert len(auth) == 1 and auth[0].metadata["fingerprint"] == fp_b, "SSH_AUTH is preserved"
        correlated = [e for e in by_cat(pub, EventCategory.SSH_KEY_CHANGE) if e.metadata["phase"] == km.PHASE_LOGIN]
        assert len(correlated) == 1
        event = correlated[0]
        assert event.metadata["classification"] == km.CORRELATED_SSH_INTRUSION and event.severity in (Severity.HIGH, Severity.CRITICAL)
        assert event.metadata["login"]["source_ip"] == "198.51.100.44" and event.metadata["login"]["source_port"] == 40123
        assert event.metadata["login"]["ssh_port"] == SSH_PORT and event.metadata["login"]["auth_method"] == "publickey"
        assert event.source_ip == "198.51.100.44" and event.metadata.get("notify_discord") is not False
        with FrozenClock(LOGIN_AT + 700):
            mon._process_line(closed(user="alice"), event_time=LOGIN_AT + 600, pid=7001)
        ended = [e for e in by_cat(pub, EventCategory.SSH_KEY_CHANGE) if e.metadata["phase"] == km.PHASE_SESSION_ENDED]
        assert len(ended) == 1
        with FrozenClock(LOGIN_AT + 900):
            mon._process_line(accepted(user="alice", ip="198.51.100.44", port=40999, fp=fp_b), event_time=LOGIN_AT + 800, pid=7002)
        assert len([e for e in by_cat(pub, EventCategory.SSH_KEY_CHANGE) if e.metadata["phase"] == km.PHASE_LOGIN]) == 1
        health = asyncio.run(mon.health())
        assert health["key_monitor"]["initialized"] is True and health["key_monitor"]["correlated_logins_total"] == 1
    finally:
        lab.cleanup()
    print("Test 16 (SSHMonitor integration: SSH_AUTH is unchanged, the change becomes one SSH_KEY_CHANGE with Discord fields, the first login with the new key is CORRELATED_SSH_INTRUSION with IP/ports/method, the logout is reported once, a repeat login is silent, health exposes the monitor) PASSED")


def test_17_fim_event_handler_routes_authorized_keys2_and_sshd_config():
    lab = Lab(sshd="AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n")
    try:
        a, _ = mk_key(1)
        lab.write(lab.path("alice"), [a])
        asyncio.run(lab.baseline())
        mon, pub = make_monitor()
        mon._key_monitor = lab.monitor
        mon.config = mon.config
        from core.datatypes import BaseEvent

        async def feed(path, **meta):
            await mon._on_authorized_keys_fim_event(BaseEvent("fim", EventCategory.FILE_INTEGRITY_CHANGE, Severity.HIGH, "changed", raw=path, metadata={"path": path, **meta}))

        asyncio.run(feed(lab.path("alice", "authorized_keys2"), actor="root", process_name="tee"))
        assert lab.monitor._pending_users == {"alice"} and "tee" in json.dumps(lab.monitor._fim_meta)
        asyncio.run(feed(os.path.join(lab.root, "elsewhere.txt")))
        assert lab.monitor._pending_users == {"alice"}
        lab.monitor._pending_users.clear()
        asyncio.run(feed(lab.config_path))
        assert lab.monitor._pending_full is True
    finally:
        lab.cleanup()
    print("Test 17 (the existing FIM-event subscription now routes authorized_keys2, any effective source and sshd_config to the key monitor with FIM actor evidence; unrelated paths are ignored) PASSED")


def test_18_hygiene_no_execution_no_filesystem_scan_and_bounded_state():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("ssh_key_sources.py", "ssh_key_baseline.py", "ssh_key_monitor.py"):
        source = open(os.path.join(root, "core", name)).read()
        for forbidden in ("subprocess", "os.system", "os.walk", "glob.glob", "shell=True", "Popen", "create_subprocess"):
            assert forbidden not in source, (name, forbidden)
    monitor_source = open(os.path.join(root, "core", "ssh_key_monitor.py")).read()
    assert "max(30.0" in monitor_source, "periodic reconciliation can never be faster than 30 s"
    from config.manager import SSHKeyMonitorConfig as Cfg

    assert Cfg().reconcile_interval_seconds >= 30 and Cfg().debounce_seconds >= 0.2
    lab = Lab(max_recent_additions=3)
    try:
        for index in range(10):
            lab.monitor.baseline.additions[f"u|{index}"] = {"first_seen": lab.clock.t + index}
        lab.monitor.baseline.trim_additions(lab.clock.t + 20, 3, 1e9)
        assert len(lab.monitor.baseline.additions) == 3
    finally:
        lab.cleanup()
    print("Test 18 (no process execution, no filesystem walk/glob in the key monitor; reconciliation floor 30 s; the correlation table is bounded) PASSED")


def main():
    test_1_authorized_keys_baseline_is_silent_then_addition_is_detected()
    test_2_authorized_keys2_is_monitored_only_when_sshd_really_uses_it()
    test_3_multiple_authorized_keys_files_tokens_and_a_shared_global_file()
    test_4_creation_removal_replacement_and_option_change()
    test_5_permission_and_ownership_changes_including_root_owned_files()
    test_6_sshd_config_change_new_sources_and_authorized_keys_command_never_executed()
    test_7_duplicate_file_events_collapse_into_one_reconciliation_and_one_alert()
    test_8_login_with_a_new_key_correlates_and_raises_risk_by_evidence()
    test_9_unknown_key_never_used_stays_a_plain_change_and_expires()
    test_10_known_admin_key_revoked_key_and_known_admin_ip_do_not_escalate_or_do_escalate()
    test_11_delayed_and_replayed_logins_are_judged_by_event_time()
    test_12_baseline_persistence_restart_corruption_and_server_isolation()
    test_13_unreadable_or_unstable_sources_never_become_false_removals_and_floods_are_capped()
    test_14_performance_and_memory_with_many_users()
    test_15_fim_and_persistence_discovery_use_the_effective_sources()
    test_16_ssh_monitor_integration_keeps_ssh_auth_and_adds_key_events()
    test_17_fim_event_handler_routes_authorized_keys2_and_sshd_config()
    test_18_hygiene_no_execution_no_filesystem_scan_and_bounded_state()
    print("\nALL SSH KEY MONITOR TESTS PASSED")


if __name__ == "__main__":
    main()
