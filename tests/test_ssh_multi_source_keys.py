from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import modules.ssh_monitor as ssh_monitor_module
from config.manager import DiscordConfig, SSHMonitorConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.ssh_key_registry import (
    IDENTITY_DISCOVERED, IDENTITY_UNKNOWN_KEY, IDENTITY_UNRESOLVED_EXTERNAL_PROVIDER, REGISTRATION_EXTERNAL_PROVIDER,
    REGISTRATION_MULTIPLE_SOURCES, REGISTRATION_NOT_FOUND, REGISTRATION_SINGLE_SOURCE, STATUS_TRUSTED, SshKeyRegistry,
)
from core.sshd_effective_config import (
    MatchContext, SCOPE_GLOBAL, SCOPE_USER_HOME, SCOPE_USER_SPECIFIC, SshdConfigResolver, evaluate_config,
    expand_authorized_keys_files, parse_sshd_config, parse_sshd_t_output,
)
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.ssh_monitor import SSHMonitor


def _wire(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def make_key(comment: str, seed: int) -> Tuple[str, str]:
    pub = bytes((seed + i) % 256 for i in range(32))
    wire = _wire(b"ssh-ed25519") + _wire(pub)
    b64 = base64.b64encode(wire).decode("ascii")
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii").rstrip("=")
    return f"ssh-ed25519 {b64} {comment}".rstrip(), fp


class FakePw:
    def __init__(self, pw_dir: str, pw_uid: int = 1500) -> None:
        self.pw_dir = pw_dir
        self.pw_uid = pw_uid
        self.pw_gid = pw_uid


class Env:
    def __init__(self, tmp: str, users: Optional[List[str]] = None) -> None:
        self.tmp = tmp
        self.etc = os.path.join(tmp, "etc")
        self.ssh = os.path.join(self.etc, "ssh")
        os.makedirs(os.path.join(self.ssh, "sshd_config.d"))
        os.makedirs(os.path.join(self.etc, "xdg"))
        self.config = os.path.join(self.ssh, "sshd_config")
        self.xdg = os.path.join(self.etc, "xdg", "authorized_keys")
        self.homes: Dict[str, str] = {}
        for user in users or ["newusproud"]:
            self.add_user(user)

    def add_user(self, user: str) -> str:
        home = os.path.join(self.tmp, "home", user)
        os.makedirs(os.path.join(home, ".ssh"), exist_ok=True)
        self.homes[user] = home
        return home

    def home_keys(self, user: str) -> str:
        return os.path.join(self.homes[user], ".ssh", "authorized_keys")

    def write(self, path: str, *lines: str) -> str:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        Path(path).write_text("\n".join(lines) + "\n")
        return path

    def sshd_config(self, text: str) -> None:
        Path(self.config).write_text(text)

    def monitor(self, *, use_sshd_t: bool = False) -> SSHMonitor:
        cfg = SSHMonitorConfig(
            enabled=True, geoip_lookup=False, ssh_key_registry_path=os.path.join(self.tmp, "registry.json"),
            ssh_key_registry_refresh_seconds=0.0, sshd_config_path=self.config, use_sshd_t=use_sshd_t,
            sshd_config_stat_ttl_seconds=0.0,
        )
        mon = SSHMonitor(EventBus(), cfg)
        mon.published = []
        mon.publish = lambda ev: mon.published.append(ev)
        resolver = mon._key_registry.resolver_for(self.config)
        resolver._group_lookup = lambda user: ()
        return mon

    def patch_pwd(self):
        real = ssh_monitor_module.pwd.getpwnam
        homes = self.homes

        def fake(name: str):
            if name not in homes:
                raise KeyError(name)
            return FakePw(homes[name], 1500 + sorted(homes).index(name))

        ssh_monitor_module.pwd.getpwnam = fake
        return real


def login(mon: SSHMonitor, user: str, fp: str, ip: str = "203.0.113.7") -> BaseEvent:
    before = len(mon.published)
    mon._process_line(f"Accepted publickey for {user} from {ip} port 5{abs(hash(ip + fp)) % 9000:04d} ssh2: ED25519 {fp}")
    events = [e for e in mon.published[before:] if e.category == EventCategory.SSH_AUTH]
    assert len(events) == 1, f"exactly one SSH_AUTH per login, got {len(events)}"
    return events[0]


def payload_fields(event: BaseEvent) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig(enabled=True, alert_channel_id=1), detection_only=False)
    payload = dispatcher._build_payload(event)
    embeds = payload["embeds"]
    return {f["name"]: f["value"] for f in embeds[0]["fields"]}, embeds


def test_a_single_source() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        line, fp = make_key("dev@example.com", 1)
        env.write(env.home_keys("newusproud"), line)
        env.sshd_config("PubkeyAuthentication yes\n")
        real = env.patch_pwd()
        try:
            mon = env.monitor()
            event = login(mon, "newusproud", fp)
        finally:
            ssh_monitor_module.pwd.getpwnam = real
        meta = event.metadata
        assert meta["key_registration"] == REGISTRATION_SINGLE_SOURCE and meta["key_source_count"] == 1
        assert meta["key_sources"] == [env.home_keys("newusproud")] and meta["key_source"] == env.home_keys("newusproud")
        assert meta["source_scope"] == SCOPE_USER_HOME
        fields, _ = payload_fields(event)
        assert fields["Key Registration"] == "SINGLE_SOURCE"
        assert fields["Key Sources"] == f"1. {env.home_keys('newusproud')}" and fields["Source Count"] == "1"
    print("Test A (single source -> SINGLE_SOURCE, one numbered source in the alert) PASSED")


def test_b_multiple_sources() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        line, fp = make_key("muhammadnurashiddiqi@gmail.com", 2)
        other, _ = make_key("other@example.com", 3)
        env.write(env.home_keys("newusproud"), line)
        env.write(env.xdg, other, line)
        env.sshd_config(f"AuthorizedKeysFile .ssh/authorized_keys {env.xdg}\n")
        real = env.patch_pwd()
        try:
            mon = env.monitor()
            event = login(mon, "newusproud", fp)
        finally:
            ssh_monitor_module.pwd.getpwnam = real
        meta = event.metadata
        assert meta["key_registration"] == REGISTRATION_MULTIPLE_SOURCES and meta["key_source_count"] == 2
        assert meta["key_sources"] == [env.home_keys("newusproud"), env.xdg], "the search does NOT stop at the first match"
        assert meta["key_source_scopes"] == [SCOPE_USER_HOME, SCOPE_GLOBAL] and meta["source_scope"] == "MIXED"
        assert meta["key_source"] == env.home_keys("newusproud")
        assert meta["identity_status"] == IDENTITY_DISCOVERED, "a known-location key with several sources is NOT automatically escalated"
        assert meta["risk"] == event.severity.value
        fields, embeds = payload_fields(event)
        assert fields["Key Registration"] == "MULTIPLE_SOURCES" and fields["Source Count"] == "2"
        assert fields["Key Sources"] == f"1. {env.home_keys('newusproud')}\n2. {env.xdg}"
        assert len(embeds) == 1
    print("Test B (same fingerprint in home + /etc/xdg-style global file -> MULTIPLE_SOURCES, source_count=2, all listed) PASSED")


def test_c_custom_authorized_keys_file() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        line, fp = make_key("custom@example.com", 4)
        custom = env.write(os.path.join(env.homes["newusproud"], ".keys", "newusproud.pub"), line)
        per_user = env.write(os.path.join(tmp, "srv", "keys", "newusproud"), line)
        env.sshd_config(f"AuthorizedKeysFile %h/.keys/%u.pub {tmp}/srv/keys/%u %z/bad\n")
        real = env.patch_pwd()
        try:
            mon = env.monitor()
            event = login(mon, "newusproud", fp)
        finally:
            ssh_monitor_module.pwd.getpwnam = real
        assert event.metadata["key_sources"] == [custom, per_user], "custom paths must appear; unknown %-tokens are dropped"
        assert event.metadata["key_source_scopes"] == [SCOPE_USER_HOME, SCOPE_USER_SPECIFIC]
    specs = expand_authorized_keys_files(
        [".ssh/authorized_keys", "/etc/xdg/authorized_keys", "%h/x/%%y", "/k/%U", "none", "/etc/../etc/xdg/authorized_keys", "%q"],
        "bob", 1234, "/home/bob",
    )
    assert [(s.path, s.scope) for s in specs] == [
        ("/home/bob/.ssh/authorized_keys", SCOPE_USER_HOME), ("/etc/xdg/authorized_keys", SCOPE_GLOBAL),
        ("/home/bob/x/%y", SCOPE_USER_HOME), ("/k/1234", SCOPE_USER_SPECIFIC),
    ], specs
    assert expand_authorized_keys_files(["none"], "bob", 1, "/home/bob") == []
    assert len(expand_authorized_keys_files([f"/k/{i}" for i in range(50)], "bob", 1, "/home/bob")) == 8, "bounded source count"
    print("Test C (custom AuthorizedKeysFile: %h/%u/%U/%% expanded, scopes classified, none/unknown tokens/dupes handled, bounded) PASSED")


def test_d_not_found() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        line, _ = make_key("someone@example.com", 5)
        _, missing_fp = make_key("nobody@example.com", 99)
        env.write(env.home_keys("newusproud"), line)
        env.sshd_config("")
        real = env.patch_pwd()
        try:
            mon = env.monitor()
            event = login(mon, "newusproud", missing_fp)
        finally:
            ssh_monitor_module.pwd.getpwnam = real
        assert event.metadata["key_registration"] == REGISTRATION_NOT_FOUND and event.metadata["key_source_count"] == 0
        assert event.metadata["identity_status"] == "NOT_REGISTERED" and event.metadata["key_owner"] == "UNKNOWN"
        fields, _ = payload_fields(event)
        assert fields["Key Registration"] == "NOT_FOUND"
        assert fields["Key Sources"] == "Tidak ditemukan pada configured AuthorizedKeysFile sources"
        assert "Source Count" not in fields
    print("Test D (fingerprint in no effective source and no provider -> NOT_FOUND with the specified text) PASSED")


def test_e_authorized_keys_command_never_executed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        marker = os.path.join(tmp, "EXECUTED")
        canary = os.path.join(tmp, "canary.sh")
        Path(canary).write_text(f"#!/bin/sh\ntouch {marker}\n")
        os.chmod(canary, 0o755)
        _, fp = make_key("remote@example.com", 6)
        env.write(env.home_keys("newusproud"), make_key("someone@example.com", 7)[0])
        env.sshd_config(
            f"AuthorizedKeysCommand {canary} %u --token=SUPERSECRET12345\nAuthorizedKeysCommandUser root\n"
        )
        calls: List[Any] = []
        real = env.patch_pwd()
        try:
            mon = env.monitor(use_sshd_t=False)
            mon._key_registry.resolver_for(env.config)._sshd_runner = lambda args, timeout: calls.append(args)
            event = login(mon, "newusproud", fp)
        finally:
            ssh_monitor_module.pwd.getpwnam = real
        meta = event.metadata
        assert meta["key_registration"] == REGISTRATION_EXTERNAL_PROVIDER and meta["external_provider"] is True
        assert meta["identity_status"] == IDENTITY_UNRESOLVED_EXTERNAL_PROVIDER
        assert meta["key_source"] == "AUTHORIZED_KEYS_COMMAND" and meta["key_sources"] == []
        assert "SUPERSECRET12345" not in meta["authorized_keys_command"] and canary in meta["authorized_keys_command"]
        assert meta["authorized_keys_command_user"] == "root"
        assert not os.path.exists(marker), "the AuthorizedKeysCommand must NEVER be executed for discovery"
        fields, _ = payload_fields(event)
        assert fields["Key Registration"] == "EXTERNAL_PROVIDER" and fields["Key Source"] == "AUTHORIZED_KEYS_COMMAND"
        assert fields["External Provider"] == "YES" and canary in fields["Command"]
        assert fields["Identity Status"] == "UNRESOLVED_EXTERNAL_PROVIDER"
        for args in calls:
            assert canary not in " ".join(args) and args[0] == "-T", "only `sshd -T` is ever run, never the provider command"
    print("Test E (AuthorizedKeysCommand: EXTERNAL_PROVIDER, sanitized command, UNRESOLVED_EXTERNAL_PROVIDER, provider NEVER executed) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        line, fp = make_key("both@example.com", 8)
        env.write(env.home_keys("newusproud"), line)
        env.sshd_config("AuthorizedKeysCommand /usr/local/bin/fetch %u\n")
        real = env.patch_pwd()
        try:
            event = login(env.monitor(), "newusproud", fp)
        finally:
            ssh_monitor_module.pwd.getpwnam = real
        assert event.metadata["key_registration"] == REGISTRATION_SINGLE_SOURCE and event.metadata["external_provider"] is True
        fields, _ = payload_fields(event)
        assert fields["External Provider"] == "YES" and "Key Sources" in fields
    print("Test E2 (key found in a file AND a provider exists -> file sources shown, provider flagged, no false NOT_FOUND) PASSED")


def test_f_one_alert_for_many_sources() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        line, fp = make_key("dup@example.com", 9)
        env.write(env.home_keys("newusproud"), line)
        env.write(env.xdg, line)
        extra = env.write(os.path.join(tmp, "etc", "extra_keys"), line)
        env.sshd_config(f"AuthorizedKeysFile .ssh/authorized_keys {env.xdg} {extra}\n")
        real = env.patch_pwd()
        try:
            mon = env.monitor()
            before = len(mon.published)
            mon._process_line(f"Accepted publickey for newusproud from 203.0.113.9 port 40000 ssh2: ED25519 {fp}")
            all_events = mon.published[before:]
        finally:
            ssh_monitor_module.pwd.getpwnam = real
        auth = [e for e in all_events if e.category == EventCategory.SSH_AUTH]
        assert len(auth) == 1 and auth[0].metadata["key_source_count"] == 3
        assert not [e for e in all_events if e.category != EventCategory.SSH_AUTH], "no per-source / follow-up alerts"
        _fields, embeds = payload_fields(auth[0])
        assert len(embeds) == 1
    print("Test F (same key in 3 locations -> still exactly 1 SSH_AUTH event and 1 Discord embed) PASSED")


def test_g_unknown_key_source_and_global_scope() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        planted, fp = make_key("planted-by-third-party@evil.example", 10)
        env.write(env.home_keys("newusproud"), make_key("legit@example.com", 11)[0])
        env.write(env.xdg, planted)
        env.sshd_config(f"AuthorizedKeysFile .ssh/authorized_keys {env.xdg}\n")
        real = env.patch_pwd()
        try:
            mon = env.monitor()
            event = login(mon, "newusproud", fp)
        finally:
            ssh_monitor_module.pwd.getpwnam = real
        meta = event.metadata
        assert meta["identity_status"] == IDENTITY_UNKNOWN_KEY
        assert meta["key_registration"] == REGISTRATION_SINGLE_SOURCE and meta["key_sources"] == [env.xdg]
        assert meta["key_owner"] == "UNKNOWN" and meta["key_owner_basis"] == "UNKNOWN"
        assert meta["key_comment"] == "planted-by-third-party@evil.example"
        assert meta["source_scope"] == SCOPE_GLOBAL and meta["current_user"] == "newusproud"
        assert meta["risk"] == event.severity.value, "risk comes from the existing severity/TCE policy, no second system"
        assert "file_owner" not in meta and "owner_uid" not in meta
        fields, _ = payload_fields(event)
        assert fields["Identity Status"] == "UNKNOWN_KEY" and fields["Key Owner"] == "UNKNOWN"
        assert fields["Key Comment"] == "planted-by-third-party@evil.example"
        assert fields["Key Sources"] == f"1. {env.xdg}" and fields["Source Scope"] == "GLOBAL"
        assert fields["Current User"] == "newusproud"
    print("Test G/J (third-party key in a GLOBAL source -> UNKNOWN_KEY, source path shown, scope GLOBAL + current user, owner UNKNOWN, file owner never used) PASSED")


def test_g2_registered_and_comment_owner() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        line, fp = make_key("Owner@Example.com", 12)
        others = [make_key(f"k{i}@example.com", 20 + i) for i in range(6)]
        env.write(env.home_keys("newusproud"), *[o[0] for o in others[:2]], line, *[o[0] for o in others[2:]])
        env.sshd_config("")
        real = env.patch_pwd()
        try:
            mon = env.monitor()
            event = login(mon, "newusproud", fp)
            meta = event.metadata
            assert meta["identity_status"] == IDENTITY_DISCOVERED and meta["key_owner_basis"] == "KEY_COMMENT"
            assert meta["registered_key_count"] == 7 and meta["current_key_index"] == 3
            assert len(meta["other_key_fingerprints"]) == 5 and meta["other_key_fingerprints_total"] == 6
            fields, _ = payload_fields(event)
            assert "BELUM terverifikasi" in fields["Key Owner"], "a key comment is metadata, never proof of ownership"
            assert fields["Registered Keys for User"] == "7" and fields["Current Login Key"] == "3 of 7"
            assert "+1 lainnya" in fields["Other Registered Key Fingerprints"]
            assert fp not in fields["Other Registered Key Fingerprints"]
            assert "private" not in " ".join(fields.values()).lower()

            mon._key_registry.register(fp, "real.owner@example.com", "Real Owner", status=STATUS_TRUSTED)
            event2 = login(mon, "newusproud", fp, ip="203.0.113.99")
            assert event2.metadata["key_owner"] == "real.owner@example.com" and event2.metadata["key_owner_basis"] == "REGISTRY"
            assert event2.metadata["identity_status"] == "TRUSTED"
        finally:
            ssh_monitor_module.pwd.getpwnam = real
    print("Test G2 (identity priority: registry > comment; comment shown as unverified; bounded key inventory '3 of 7') PASSED")


def test_h_fim_targeted_invalidation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp, ["alice", "bob", "carol"])
        a_line, a_fp = make_key("alice@example.com", 30)
        b_line, _ = make_key("bob@example.com", 31)
        c_line, _ = make_key("carol@example.com", 32)
        env.write(env.home_keys("alice"), a_line)
        env.write(env.home_keys("bob"), b_line)
        env.write(env.home_keys("carol"), c_line)
        env.write(env.xdg, make_key("shared@example.com", 33)[0])
        env.sshd_config(
            f"AuthorizedKeysFile .ssh/authorized_keys {env.xdg}\nMatch User carol\n    AuthorizedKeysFile .ssh/authorized_keys\n"
        )
        real = env.patch_pwd()
        try:
            mon = env.monitor()
            registry = mon._key_registry
            for user in ("alice", "bob", "carol"):
                registry.resolve_key_sources(user, env.homes[user], a_fp, sshd_config_path=env.config, uid=1)
            assert registry.file_read_count == 4, f"3 home files + 1 shared file read once, got {registry.file_read_count}"
            resolver = registry.resolver_for(env.config)
            parses = resolver.parse_count

            for user in ("alice", "bob", "carol"):
                registry.resolve_key_sources(user, env.homes[user], a_fp, sshd_config_path=env.config, uid=1)
            assert registry.file_read_count == 4 and resolver.parse_count == parses, "unchanged files are never re-read or re-parsed"

            assert sorted(registry.users_for_authorized_keys_path(env.xdg)) == ["alice", "bob"], "carol does not read the global file"
            planted, planted_fp = make_key("planted@evil.example", 34)
            Path(env.xdg).write_text(Path(env.xdg).read_text() + planted + "\n")
            event = BaseEvent(
                source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
                severity=Severity.MEDIUM, message="global authorized_keys changed", raw=env.xdg, metadata={"path": env.xdg},
            )
            asyncio.run(mon._on_authorized_keys_fim_event(event))
            assert registry.file_read_count == 5, "targeted refresh re-reads ONLY the changed file"
            assert registry.lookup_sources("alice", planted_fp) and registry.lookup_sources("bob", planted_fp)
            assert registry.lookup_sources("carol", planted_fp) == []
            assert registry.file_read_count == 5

            before = registry.file_read_count
            asyncio.run(mon._on_authorized_keys_fim_event(BaseEvent(
                source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
                severity=Severity.MEDIUM, message="x", raw="/tmp/unrelated", metadata={"path": "/tmp/unrelated"},
            )))
            assert registry.file_read_count == before, "an unrelated FIM event must not trigger any scan"

            asyncio.run(mon._on_authorized_keys_fim_event(BaseEvent(
                source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
                severity=Severity.MEDIUM, message="sshd_config changed", raw=env.config, metadata={"path": env.config},
            )))
            assert registry.file_read_count == before, "an sshd_config change must not rescan any key file"
            registry.resolve_key_sources("alice", env.homes["alice"], a_fp, sshd_config_path=env.config, uid=1)
            assert resolver.parse_count == parses + 1, "effective config is re-parsed lazily after the invalidation"
            assert registry.file_read_count == before, "unchanged key files stay cached across a config re-parse"
        finally:
            ssh_monitor_module.pwd.getpwnam = real
    print("Test H (FIM: global-file change refreshes only the users/file involved; unrelated events and sshd_config changes never rescan the filesystem) PASSED")


def test_i_match_user_and_address() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp, ["alice", "bob"])
        env.sshd_config(
            "AuthorizedKeysFile .ssh/authorized_keys\n"
            "Match User bob\n    AuthorizedKeysFile /etc/bob_keys/%u\n"
            "Match Address 10.0.0.0/8,!10.9.0.0/16\n    AuthorizedKeysFile /etc/office_keys\n"
            "Match Group admins User *,!bob\n    AuthorizedKeysFile /etc/admin_keys\n"
            "Match Host *.corp.example\n    AuthorizedKeysFile /etc/corp_keys\n"
        )
        parsed = parse_sshd_config(env.config)
        assert parsed.dimensions == {"user", "addr", "host"}

        def files(user: str, addr: Optional[str], groups: Tuple[str, ...] = (), host: Optional[str] = None):
            return evaluate_config(parsed, MatchContext(user, groups, addr, host)).authorized_keys_files

        assert files("alice", "192.0.2.5") == (".ssh/authorized_keys",)
        assert files("bob", "192.0.2.5") == ("/etc/bob_keys/%u",)
        assert files("alice", "10.1.2.3") == ("/etc/office_keys",)
        assert files("alice", "10.9.1.1") == (".ssh/authorized_keys",), "negated address pattern must not match"
        assert files("bob", "10.1.2.3") == ("/etc/bob_keys/%u",), "first matching Match block wins per keyword"
        assert files("carol", "192.0.2.5", ("admins",)) == ("/etc/admin_keys",)
        assert files("bob", "192.0.2.5", ("admins",)) == ("/etc/bob_keys/%u",)
        assert files("alice", "192.0.2.5", host="ws1.CORP.example") == ("/etc/corp_keys",)
        unknown_host = evaluate_config(parsed, MatchContext("alice", (), "192.0.2.5", None))
        assert "host" in unknown_host.uncertain and unknown_host.authorized_keys_files == (".ssh/authorized_keys",)

        line, fp = make_key("bob@example.com", 40)
        office_line, office_fp = make_key("office@example.com", 41)
        Path(tmp, "etc", "bob_keys").mkdir()
        bob_file = str(Path(tmp, "etc", "bob_keys", "bob"))
        Path(bob_file).write_text(line + "\n")
        env.sshd_config(
            f"AuthorizedKeysFile .ssh/authorized_keys\nMatch User bob\n    AuthorizedKeysFile {tmp}/etc/bob_keys/%u\n"
        )
        real = env.patch_pwd()
        try:
            mon = env.monitor()
            event = login(mon, "bob", fp)
            assert event.metadata["key_sources"] == [bob_file] and event.metadata["sshd_match_applied"] is True
            assert event.metadata["key_registration"] == REGISTRATION_SINGLE_SOURCE
            env.write(env.home_keys("alice"), line)
            alice_event = login(mon, "alice", fp)
            assert alice_event.metadata["key_registration"] == REGISTRATION_SINGLE_SOURCE
            assert alice_event.metadata["key_sources"] == [env.home_keys("alice")]
            assert alice_event.metadata["key_user_mismatch"] is False
        finally:
            ssh_monitor_module.pwd.getpwnam = real
    print("Test I (Match User/Address/Group/Host + negation + first-match precedence honoured; end-to-end effective source differs per user) PASSED")


def test_i2_include_and_sshd_t() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        Path(env.ssh, "sshd_config.d", "10-keys.conf").write_text("AuthorizedKeysFile /etc/dropin_keys\n")
        env.sshd_config(
            f"Include {env.ssh}/sshd_config.d/*.conf\nAuthorizedKeysFile .ssh/authorized_keys\n"
        )
        parsed = parse_sshd_config(env.config)
        assert evaluate_config(parsed, MatchContext("u")).authorized_keys_files == ("/etc/dropin_keys",), (
            "Include drop-ins are processed in place: first obtained value wins"
        )
        assert len(parsed.files) == 2

        resolver = SshdConfigResolver(env.config, stat_ttl_seconds=0.0)
        first = resolver.resolve("u")
        assert first.authorized_keys_files == ("/etc/dropin_keys",)
        Path(env.ssh, "sshd_config.d", "05-new.conf").write_text("AuthorizedKeysFile /etc/newer_keys\n")
        assert resolver.resolve("u").authorized_keys_files == ("/etc/newer_keys",), "a NEW drop-in file is noticed"
        assert resolver.is_config_path(str(Path(env.ssh, "sshd_config.d", "99-x.conf"))) and resolver.is_config_path(env.config)

        text = "port 22\nauthorizedkeysfile .ssh/authorized_keys /etc/xdg/authorized_keys\nauthorizedkeyscommand none\n" \
               "authorizedkeyscommanduser none\npubkeyauthentication yes\ntrustedusercakeys none\nrevokedkeys none\n"
        effective = parse_sshd_t_output(text)
        assert effective.authorized_keys_files == (".ssh/authorized_keys", "/etc/xdg/authorized_keys")
        assert effective.authorized_keys_command is None and effective.pubkey_authentication is True
        assert effective.source == "sshd -T"
        off = parse_sshd_t_output("pubkeyauthentication no\nauthorizedkeyscommand /x/y %u\ntrustedusercakeys /etc/ca.pub\n")
        assert off.pubkey_authentication is False and off.authorized_keys_command == "/x/y %u" and off.trusted_user_ca_keys == "/etc/ca.pub"

        env.sshd_config("AuthorizedKeysFile .ssh/authorized_keys\nMatch User bob\n  AuthorizedKeysFile /etc/bob\n")
        calls: List[Tuple[Any, float]] = []

        def runner(args, timeout):
            calls.append((list(args), timeout))
            return "authorizedkeysfile /etc/xdg/from_sshd_t\nauthorizedkeyscommand none\n"

        resolver2 = SshdConfigResolver(env.config, stat_ttl_seconds=0.0, sshd_runner=runner, group_lookup=lambda u: ())
        local = resolver2.resolve("bob", addr="203.0.113.5")
        assert local.authorized_keys_files == ("/etc/bob",) and local.source == "config-parse"
        assert resolver2.claim_verification("bob", "203.0.113.5", None) is True
        assert resolver2.claim_verification("bob", "203.0.113.5", None) is False, "verified at most once per context"
        verified = resolver2.verify_with_sshd_t("bob", "203.0.113.5", None)
        assert verified is not None and verified.authorized_keys_files == ("/etc/xdg/from_sshd_t",)
        assert calls and calls[0][0][:3] == ["-T", "-f", env.config] and "user=bob,addr=203.0.113.5" in calls[0][0][4]
        assert resolver2.resolve("bob", addr="203.0.113.5").source == "sshd -T", "the authoritative result replaces the parsed one"
        assert SshdConfigResolver(env.config).verify_with_sshd_t("bob", None, None) is None
    print("Test I2 (Include drop-ins first-wins + new drop-in noticed; sshd -T output parsed; authoritative sshd -T -C verification replaces the parser result once per context) PASSED")


def test_k_cache_and_performance() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        line, fp = make_key("busy@example.com", 50)
        env.write(env.home_keys("newusproud"), line)
        env.write(env.xdg, line)
        env.sshd_config(f"AuthorizedKeysFile .ssh/authorized_keys {env.xdg}\n")
        real = env.patch_pwd()
        try:
            mon = env.monitor(use_sshd_t=True)
            runner_calls: List[Any] = []
            mon._key_registry.resolver_for(env.config)._sshd_runner = lambda a, t: runner_calls.append(a)
            registry = mon._key_registry
            resolver = registry.resolver_for(env.config)

            async def burst() -> None:
                for index in range(100):
                    event = login(mon, "newusproud", fp, ip=f"198.51.100.{index % 250}")
                    assert event.metadata["key_source_count"] == 2
                await asyncio.sleep(0.05)

            asyncio.run(burst())
            assert registry.file_read_count == 2, f"100 rapid logins -> each key file read once, got {registry.file_read_count}"
            assert resolver.parse_count == 1 and resolver.evaluation_count == 1, (
                "no Match blocks -> a single effective-config evaluation serves every user and address"
            )
            assert len(runner_calls) <= 1, f"sshd -T verification runs at most once per context, got {len(runner_calls)}"

            planted, planted_fp = make_key("planted@evil.example", 51)
            with open(env.xdg, "a") as handle:
                handle.write(planted + "\n")
            event = login(mon, "newusproud", planted_fp)
            assert event.metadata["key_registration"] == REGISTRATION_SINGLE_SOURCE and event.metadata["key_sources"] == [env.xdg], (
                "a key planted seconds ago must be found on the very next login (stat-validated cache, no stale NOT_FOUND)"
            )
        finally:
            ssh_monitor_module.pwd.getpwnam = real

    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        huge = os.path.join(env.homes["newusproud"], ".ssh", "authorized_keys")
        with open(huge, "w") as handle:
            handle.write("x" * 3_000_000)
        registry = SshKeyRegistry(os.path.join(tmp, "r.json"), refresh_seconds=0.0)
        env.sshd_config("")
        result = registry.resolve_key_sources("newusproud", env.homes["newusproud"], "SHA256:" + "A" * 43, sshd_config_path=env.config)
        assert result.registration == REGISTRATION_NOT_FOUND, "oversized key files are skipped, never slurped"
    print("Test K (100 rapid logins -> 1 parse + 1 read per file + <=1 sshd -T; planted key visible on next login; oversized file ignored) PASSED")


def test_l_safety_no_writes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = Env(tmp)
        line, fp = make_key("safe@example.com", 60)
        env.write(env.home_keys("newusproud"), line)
        env.write(env.xdg, line)
        env.sshd_config(f"AuthorizedKeysFile .ssh/authorized_keys {env.xdg}\nAuthorizedKeysCommand /bin/false\n")
        tracked = [env.home_keys("newusproud"), env.xdg, env.config]
        before = {p: (Path(p).read_bytes(), os.stat(p).st_mtime_ns, stat.S_IMODE(os.stat(p).st_mode)) for p in tracked}
        real = env.patch_pwd()
        try:
            mon = env.monitor()
            login(mon, "newusproud", fp)
            asyncio.run(mon._on_authorized_keys_fim_event(BaseEvent(
                source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
                severity=Severity.MEDIUM, message="x", raw=env.xdg, metadata={"path": env.xdg},
            )))
        finally:
            ssh_monitor_module.pwd.getpwnam = real
        after = {p: (Path(p).read_bytes(), os.stat(p).st_mtime_ns, stat.S_IMODE(os.stat(p).st_mode)) for p in tracked}
        assert before == after, "discovery must never modify authorized_keys or sshd_config"

    source = Path(_REPO_ROOT, "core", "sshd_effective_config.py").read_text() + Path(_REPO_ROOT, "core", "ssh_key_registry.py").read_text()
    for forbidden in ("os.walk", "rglob", "find /", "shell=True", "os.system", "os.remove", "os.unlink", "chmod"):
        assert forbidden not in source, f"{forbidden} must not appear in SSH key discovery"
    monitor_source = Path(_REPO_ROOT, "modules", "ssh_monitor.py").read_text()
    assert "shell=True" not in monitor_source
    assert "authorized_keys_command" not in monitor_source.split("def _run_sshd")[1].split("def _resolve_key_sources")[0]
    print("Test L (read-only: no writes to keys/sshd_config, no filesystem walk/glob of home or /etc, no shell, provider command never run) PASSED")


def main() -> None:
    test_a_single_source()
    test_b_multiple_sources()
    test_c_custom_authorized_keys_file()
    test_d_not_found()
    test_e_authorized_keys_command_never_executed()
    test_f_one_alert_for_many_sources()
    test_g_unknown_key_source_and_global_scope()
    test_g2_registered_and_comment_owner()
    test_h_fim_targeted_invalidation()
    test_i_match_user_and_address()
    test_i2_include_and_sshd_t()
    test_k_cache_and_performance()
    test_l_safety_no_writes()
    print("\nALL SSH MULTI-SOURCE KEY DISCOVERY TESTS PASSED")


main()
