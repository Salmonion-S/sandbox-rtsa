from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.account_privilege as account_privilege
import core.ssh_key_registry as ssh_key_registry_module
from config.manager import DiscordConfig, SSHMonitorConfig
from core.analyzer import StatefulAnalyzer
from core.datatypes import BaseEvent, EventCategory, Severity, SSHEvent
from core.event_bus import EventBus
from core.ssh_key_registry import (
    IDENTITY_DISCOVERED, IDENTITY_NOT_REGISTERED, IDENTITY_REVOKED, IDENTITY_TRUSTED,
    STATUS_REVOKED, STATUS_TRUSTED, SshKeyRegistry,
    discover_key_from_line, fingerprint_from_pubkey_b64, parse_authorized_keys_line,
    resolve_authorized_keys_paths, resolve_key_identity,
)
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.ssh_monitor import SSHMonitor


def _ssh_wire_string(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def _make_pubkey_line(comment: str, seed: int = 0) -> tuple:
    pubkey_bytes = bytes((seed + i) % 256 for i in range(32))
    wire = _ssh_wire_string(b"ssh-ed25519") + _ssh_wire_string(pubkey_bytes)
    key_b64 = base64.b64encode(wire).decode("ascii")
    expected_fp = "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii").rstrip("=")
    line = f"ssh-ed25519 {key_b64} {comment}".rstrip()
    return line, key_b64, expected_fp


class _FakePwEntry:
    def __init__(self, pw_dir: str, pw_uid: int = 1500, pw_gid: int = 1500) -> None:
        self.pw_dir = pw_dir
        self.pw_uid = pw_uid
        self.pw_gid = pw_gid


def main() -> None:
    line, key_b64, expected_fp = _make_pubkey_line("someone@example.com")
    assert fingerprint_from_pubkey_b64(key_b64) == expected_fp
    result = discover_key_from_line(line)
    assert result is not None
    fp, key_type, comment = result
    assert fp == expected_fp and key_type == "ssh-ed25519" and comment == "someone@example.com"
    print("Test 1 (fingerprint computed from a hand-built SSH wire blob matches the independently-derived expected value) PASSED")

    _, _, unknown_fp = _make_pubkey_line("nobody@example.com", seed=99)
    with tempfile.TemporaryDirectory(prefix="rtsa-authkeys-") as tmp:
        registry = SshKeyRegistry(os.path.join(tmp, "registry.json"), refresh_seconds=0.0)
        result = resolve_key_identity(unknown_fp, "someuser", explicit_record=None, discovered=None)
        assert result.identity_status == IDENTITY_NOT_REGISTERED
        assert result.owner is None
    print("Test 2 (fingerprint absent from both registry and authorized_keys -> NOT_REGISTERED) PASSED")

    email_line, _, email_fp = _make_pubkey_line("m.tegar.irawan2008@gmail.com", seed=1)
    label_line, _, label_fp = _make_pubkey_line("deploy-key-prod", seed=2)
    malformed_lines = [
        "", "   ", "# this is a comment line", "not-a-valid-line-at-all",
        "ssh-rsa", "ssh-rsa   ",
        "totally-unsupported-keytype AAAAB3NzaC1yc2EA someone@example.com",
    ]
    for bad_line in malformed_lines:
        assert parse_authorized_keys_line(bad_line) is None, f"malformed line must not parse: {bad_line!r}"
    options_line = f'command="/usr/bin/rsync",no-port-forwarding {email_line}'
    parsed_with_options = parse_authorized_keys_line(options_line)
    assert parsed_with_options is not None and parsed_with_options[1] == email_line.split()[1]
    print("Test 3 (malformed/blank/comment lines rejected; options-prefixed line still parses the key) PASSED")

    email_result = discover_key_from_line(email_line)
    assert email_result is not None and email_result[2] == "m.tegar.irawan2008@gmail.com"
    label_result = discover_key_from_line(label_line)
    assert label_result is not None and label_result[2] == "deploy-key-prod"
    from core.ssh_key_registry import DiscoveredKey
    email_discovered = DiscoveredKey(fingerprint=email_fp, key_type="ssh-ed25519", comment="m.tegar.irawan2008@gmail.com", path="/home/x/.ssh/authorized_keys", linux_user="x")
    label_discovered = DiscoveredKey(fingerprint=label_fp, key_type="ssh-ed25519", comment="deploy-key-prod", path="/home/x/.ssh/authorized_keys", linux_user="x")
    assert email_discovered.comment_is_email is True
    assert label_discovered.comment_is_email is False
    print("Test 4 (email-shaped comment vs plain label comment correctly distinguished) PASSED")

    with tempfile.TemporaryDirectory(prefix="rtsa-authkeys-home-") as home:
        os.makedirs(os.path.join(home, ".ssh"), exist_ok=True)
        authorized_keys_path = os.path.join(home, ".ssh", "authorized_keys")
        with open(authorized_keys_path, "w") as f:
            f.write("\n".join([
                "# managed by ansible, do not edit",
                "",
                email_line,
                label_line,
                "totally-broken-line-should-be-skipped",
            ]) + "\n")

        registry = SshKeyRegistry(os.path.join(home, "registry.json"), refresh_seconds=0.0)
        registry.ensure_authorized_keys_scanned("newusproud", home, sshd_config_path="/nonexistent/sshd_config")
        discovered_email = registry.lookup_discovered("newusproud", email_fp)
        assert discovered_email is not None and discovered_email.path == authorized_keys_path
        result = resolve_key_identity(
            email_fp, "newusproud", explicit_record=None, discovered=discovered_email,
            authorized_for=registry.authorized_for_users(email_fp),
        )
        assert result.identity_status == IDENTITY_DISCOVERED
        assert result.owner == "m.tegar.irawan2008@gmail.com"
        assert result.key_source == authorized_keys_path
        print(
            "Test 5 (PRODUCTION CASE: key present in authorized_keys with an email comment, no explicit "
            "registry entry -> DISCOVERED with owner recovered, not NOT_REGISTERED/UNKNOWN) PASSED"
        )

        registry.register(email_fp, "explicit-owner@example.com", "Explicit Label", status=STATUS_TRUSTED)
        explicit_record = registry.lookup(email_fp)
        result2 = resolve_key_identity(
            email_fp, "newusproud", explicit_record=explicit_record, discovered=discovered_email,
            authorized_for=registry.authorized_for_users(email_fp),
        )
        assert result2.owner == "explicit-owner@example.com", "explicit registry owner must win over discovered comment"
        assert result2.owner_label == "Explicit Label"
        assert result2.identity_status == IDENTITY_TRUSTED
        print("Test 6 (matrix 5+6: explicit registry owner/label/TRUSTED status override the discovered comment) PASSED")

        registry.register(label_fp, "attacker@example.com", "Suspicious", status=STATUS_REVOKED, overwrite=True)
        revoked_explicit = registry.lookup(label_fp)
        discovered_label = registry.lookup_discovered("newusproud", label_fp)
        result3 = resolve_key_identity(
            label_fp, "newusproud", explicit_record=revoked_explicit, discovered=discovered_label,
            authorized_for=registry.authorized_for_users(label_fp),
        )
        assert result3.identity_status == IDENTITY_REVOKED, (
            "a REVOKED key still present in authorized_keys must never silently become TRUSTED/DISCOVERED"
        )
        print("Test 7 (matrix item 7: REVOKED key still present in authorized_keys stays REVOKED, never auto-restored) PASSED")

    with tempfile.TemporaryDirectory(prefix="rtsa-authkeys-multiuser-") as tmp:
        shared_line, _, shared_fp = _make_pubkey_line("shared-deploy-key", seed=7)
        home_a = os.path.join(tmp, "userA")
        home_b = os.path.join(tmp, "userB")
        for home in (home_a, home_b):
            os.makedirs(os.path.join(home, ".ssh"), exist_ok=True)
            with open(os.path.join(home, ".ssh", "authorized_keys"), "w") as f:
                f.write(shared_line + "\n")
        registry = SshKeyRegistry(os.path.join(tmp, "registry.json"), refresh_seconds=0.0)
        registry.ensure_authorized_keys_scanned("userA", home_a, sshd_config_path="/nonexistent")
        registry.ensure_authorized_keys_scanned("userB", home_b, sshd_config_path="/nonexistent")
        authorized_for = registry.authorized_for_users(shared_fp)
        users = sorted(u for u, _p in authorized_for)
        assert users == ["userA", "userB"], f"fingerprint must be tracked as authorized for BOTH users, got {users}"
        print("Test 8 (same fingerprint authorized for two different Linux users -- both tracked, no single owner silently chosen) PASSED")

        result_match = resolve_key_identity(
            shared_fp, "userA", explicit_record=None, discovered=registry.lookup_discovered("userA", shared_fp),
            authorized_for=authorized_for,
        )
        assert result_match.key_user_match is True
        print("Test 9 (matrix item 9: authenticated user matches an authorized_keys owner -> key_user_match True) PASSED")

        registry.register(
            shared_fp, "policy-owner@example.com", "Policy", expected_linux_users=["userA"], status=STATUS_TRUSTED,
        )
        explicit = registry.lookup(shared_fp)
        result_mismatch = resolve_key_identity(
            shared_fp, "userB", explicit_record=explicit, discovered=registry.lookup_discovered("userB", shared_fp),
            authorized_for=authorized_for,
        )
        assert result_mismatch.key_user_match is False, (
            "explicit registry declares this key for userA only -- authenticating as userB must be a mismatch"
        )
        print("Test 10 (matrix item 10: explicit expected_linux_users=[userA], login as userB -> key_user_match False) PASSED")

    with tempfile.TemporaryDirectory(prefix="rtsa-authkeys-refresh-") as home:
        os.makedirs(os.path.join(home, ".ssh"), exist_ok=True)
        ak_path = os.path.join(home, ".ssh", "authorized_keys")
        line1, _, fp1 = _make_pubkey_line("first-key", seed=11)
        with open(ak_path, "w") as f:
            f.write(line1 + "\n")

        registry = SshKeyRegistry(os.path.join(home, "registry.json"), refresh_seconds=300.0)
        registry.ensure_authorized_keys_scanned("refreshuser", home, sshd_config_path="/nonexistent")
        assert registry.lookup_discovered("refreshuser", fp1) is not None

        line2, _, fp2 = _make_pubkey_line("second-key", seed=12)
        import time as _time
        _time.sleep(0.01)
        with open(ak_path, "a") as f:
            f.write(line2 + "\n")
        os.utime(ak_path, None)

        registry.invalidate_authorized_keys_cache(ak_path)
        registry.ensure_authorized_keys_scanned("refreshuser", home, sshd_config_path="/nonexistent")
        assert registry.lookup_discovered("refreshuser", fp2) is not None, "newly-added key must be picked up after invalidation"
        print("Test 11 (matrix item 12+13: authorized_keys changes, FIM-style invalidation forces a fresh scan, new key discovered) PASSED")

        never_scanned = SshKeyRegistry(os.path.join(home, "registry2.json"), refresh_seconds=0.0)
        never_scanned.ensure_authorized_keys_scanned("ghostuser", "/nonexistent/home/ghostuser", sshd_config_path="/nonexistent")
        result_missing = resolve_key_identity(
            fp1, "ghostuser", explicit_record=None,
            discovered=never_scanned.lookup_discovered("ghostuser", fp1),
        )
        assert result_missing.identity_status in (IDENTITY_NOT_REGISTERED,), (
            f"a lookup against a missing/unreadable authorized_keys must never become TRUSTED, got {result_missing.identity_status}"
        )
        print("Test 12 (matrix item 14: missing/unreadable authorized_keys -> NOT_REGISTERED, never falsely TRUSTED) PASSED")

    paths = resolve_authorized_keys_paths("bob", "/home/bob", [".ssh/authorized_keys", "%h/.ssh/authorized_keys2"])
    assert paths == ["/home/bob/.ssh/authorized_keys", "/home/bob/.ssh/authorized_keys2"]
    print("Test 13 (AuthorizedKeysFile %h/%u token + relative path resolution) PASSED")

    with tempfile.TemporaryDirectory(prefix="rtsa-sshmon-authkeys-") as home:
        os.makedirs(os.path.join(home, ".ssh"), exist_ok=True)
        ak_path = os.path.join(home, ".ssh", "authorized_keys")
        prod_line, _, prod_fp = _make_pubkey_line("m.tegar.irawan2008@gmail.com", seed=42)
        with open(ak_path, "w") as f:
            f.write(prod_line + "\n")

        reg_path = os.path.join(home, "ssh_key_registry.json")
        cfg = SSHMonitorConfig(enabled=True, geoip_lookup=False, ssh_key_registry_path=reg_path, ssh_key_registry_refresh_seconds=0.0)
        mon = SSHMonitor(EventBus(), cfg)
        published = []
        mon.publish = lambda ev: published.append(ev)

        orig_getpwnam = account_privilege.pwd.getpwnam
        import modules.ssh_monitor as ssh_monitor_module
        orig_mon_getpwnam = ssh_monitor_module.pwd.getpwnam
        ssh_monitor_module.pwd.getpwnam = lambda name: _FakePwEntry(home)
        try:
            mon._process_line(
                f"Accepted publickey for newusproud from 103.105.82.10 port 64441 ssh2: ED25519 {prod_fp}"
            )

            assert len(published) == 1
            ev = published[0]
            assert ev.metadata["identity_status"] == IDENTITY_DISCOVERED, ev.metadata
            assert ev.metadata["key_owner"] == "m.tegar.irawan2008@gmail.com"
            assert ev.metadata["key_source"] == ak_path
            assert ev.metadata.get("key_user_mismatch") is False
            print(
                "Test 14 (END-TO-END PRODUCTION CASE: successful publickey login, key present in the user's "
                "own authorized_keys with an email comment, no explicit registry entry -- alert now shows "
                "DISCOVERED / correct owner / key source / Key User Match instead of NOT_REGISTERED/UNKNOWN) PASSED"
            )

            assert mon._key_registry.lookup_discovered("newusproud", prod_fp) is not None
            new_line, _, new_fp = _make_pubkey_line("second-person@example.com", seed=43)
            with open(ak_path, "a") as f:
                f.write(new_line + "\n")
            os.utime(ak_path, None)
            asyncio.run(mon._on_authorized_keys_fim_event(BaseEvent(
                source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
                severity=Severity.MEDIUM, message="authorized_keys changed", raw=ak_path,
                metadata={"path": ak_path},
            )))
            assert mon._key_registry.lookup_discovered("newusproud", new_fp) is not None, (
                "FIM change event on authorized_keys must invalidate the cache so the new key is discoverable"
            )
            print("Test 15 (FIM change event on authorized_keys invalidates the cache -- reuses FIM's existing watch, no second file watcher) PASSED")
        finally:
            ssh_monitor_module.pwd.getpwnam = orig_mon_getpwnam

    with tempfile.TemporaryDirectory(prefix="rtsa-sshmon-revoked-present-") as home:
        os.makedirs(os.path.join(home, ".ssh"), exist_ok=True)
        ak_path = os.path.join(home, ".ssh", "authorized_keys")
        harmless_line, _, harmless_fp = _make_pubkey_line("legit-key", seed=76)
        with open(ak_path, "w") as f:
            f.write(harmless_line + "\n")

        reg_path = os.path.join(home, "ssh_key_registry.json")
        cfg = SSHMonitorConfig(enabled=True, geoip_lookup=False, ssh_key_registry_path=reg_path, ssh_key_registry_refresh_seconds=0.0)
        mon = SSHMonitor(EventBus(), cfg)
        mon._key_registry.ensure_authorized_keys_scanned("newusproud", home, sshd_config_path="/nonexistent")

        revoked_line, _, revoked_fp = _make_pubkey_line("attacker@example.com", seed=77)
        with open(ak_path, "a") as f:
            f.write(revoked_line + "\n")
        os.utime(ak_path, None)
        mon._key_registry.register(revoked_fp, "attacker@example.com", "Suspicious", status=STATUS_REVOKED)
        published = []
        mon.publish = lambda ev: published.append(ev)

        import modules.ssh_monitor as ssh_monitor_module
        orig_mon_getpwnam = ssh_monitor_module.pwd.getpwnam
        ssh_monitor_module.pwd.getpwnam = lambda name: _FakePwEntry(home)
        try:
            asyncio.run(mon._on_authorized_keys_fim_event(BaseEvent(
                source_module="file_integrity_detector", category=EventCategory.FILE_INTEGRITY_CHANGE,
                severity=Severity.MEDIUM, message="authorized_keys changed", raw=ak_path,
                metadata={"path": ak_path},
            )))
        finally:
            ssh_monitor_module.pwd.getpwnam = orig_mon_getpwnam

        revoked_present = [e for e in published if e.category == EventCategory.SSH_REVOKED_KEY_PRESENT]
        assert len(revoked_present) == 1, published
        assert revoked_present[0].metadata["key_owner"] == "attacker@example.com"
        print("Test 16 (REVOKED key added to a previously-known user's authorized_keys -> SSH_REVOKED_KEY_PRESENT fires on the FIM change, no login required) PASSED")

    registry_source = open("core/ssh_key_registry.py").read()
    for marker in (
        "subprocess.run(", "subprocess.Popen(", "create_subprocess",
        "socket.getaddrinfo", "requests.get", "id_rsa", "id_ed25519", "PRIVATE KEY",
    ):
        assert marker not in registry_source, f"ssh_key_registry.py must never do {marker!r}"
    print("Test 17 (matrix 15+16+20: no private-key reads, no ssh-keygen subprocess spawn, no cross-server networking) PASSED")

    analyzer = StatefulAnalyzer(
        EventBus(), ssh_brute_force_threshold=2, ssh_brute_force_window_seconds=60,
        ssh_credential_stuffing_threshold=8, ssh_credential_stuffing_window_seconds=1800,
        ssh_credential_stuffing_min_distinct_ips=3,
    )
    captured = []

    async def _drive_analyzer():
        await analyzer.bus.subscribe("test-sink", lambda e: captured.append(e) or asyncio.sleep(0), categories=list(EventCategory))
        ts = 2_000_000.0
        for username in ("root", "admin"):
            await analyzer._on_event(SSHEvent(
                source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.MEDIUM,
                message="gagal", raw="", username=username, source_ip="45.10.20.30",
                auth_method="password", success=False, timestamp=ts,
                metadata={"username_status": "EXISTING_USER"},
            ))
        await analyzer._on_event(SSHEvent(
            source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.LOW,
            message="berhasil", raw="", username="root", source_ip="45.10.20.30",
            auth_method="publickey", success=True, timestamp=ts + 1,
            metadata={
                "fingerprint": "SHA256:" + "Z" * 43,
                "identity_status": IDENTITY_DISCOVERED, "key_owner": "someone@example.com",
            },
        ))

    asyncio.run(_drive_analyzer())
    brute_force = [e for e in captured if e.category == EventCategory.BRUTE_FORCE]
    red_zone = [e for e in captured if e.category == EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE]
    assert len(brute_force) == 1, "existing brute-force correlation must still fire"
    assert len(red_zone) == 1, "existing RED ZONE correlation must still fire"
    assert red_zone[0].metadata.get("identity_status") == IDENTITY_DISCOVERED
    print("Test 18 (matrix 17+18: existing BRUTE_FORCE and RED ZONE correlation both still function, now carrying identity context) PASSED")

    dispatcher = DiscordWebhookDispatcher(
        EventBus(), DiscordConfig(enabled=True, alert_channel_id=555000), detection_only=False,
    )
    auth_alert = SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.LOW,
        message="SSH login diterima untuk 'newusproud'", raw="",
        username="newusproud", source_ip="103.105.82.10", auth_method="publickey", success=True,
        metadata={
            "fingerprint": prod_fp, "key_type": "ssh-ed25519", "identity_status": IDENTITY_DISCOVERED,
            "key_owner": "m.tegar.irawan2008@gmail.com", "key_source": "/home/newusproud/.ssh/authorized_keys",
            "key_user_mismatch": False,
        },
    )
    payload = dispatcher._build_payload(auth_alert)
    fields = {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}
    assert fields["Identity Status"] == IDENTITY_DISCOVERED
    assert fields["Key Owner"] == "m.tegar.irawan2008@gmail.com"
    assert fields["Key Source"] == "/home/newusproud/.ssh/authorized_keys"
    assert fields["Key User Match"] == "YA"
    print("Test 19 (matrix item 19: Discord SSH_AUTH embed shows Identity Status DISCOVERED, Key Owner, Key Source, Key User Match) PASSED")

    revoked_present_alert = SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_REVOKED_KEY_PRESENT, severity=Severity.HIGH,
        message="revoked key present", raw="", username="newusproud", source_ip=None, auth_method=None, success=False,
        metadata={
            "fingerprint": "SHA256:" + "Y" * 43, "key_owner": "attacker@example.com",
            "owner_label": "Suspicious", "key_source": "/home/newusproud/.ssh/authorized_keys",
            "linux_user": "newusproud",
        },
    )
    revoked_payload = dispatcher._build_payload(revoked_present_alert)
    revoked_fields = {f["name"]: f["value"] for f in revoked_payload["embeds"][0]["fields"]}
    assert revoked_fields["Key Owner"] == "attacker@example.com"
    assert "REVOKED" in revoked_fields["ACTION"]
    print("Test 20 (SSH_REVOKED_KEY_PRESENT Discord embed shows key owner and explains it was not auto-restored) PASSED")

    print("\nALL SSH AUTHORIZED_KEYS CORRELATION TESTS PASSED")


main()
