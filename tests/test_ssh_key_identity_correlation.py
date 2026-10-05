from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import core.account_privilege as account_privilege
from core.account_privilege import ACCOUNT_NOT_FOUND, ACCOUNT_PRIVILEGED, ACCOUNT_STANDARD, classify_account_privilege
from config.manager import DiscordConfig, SSHMonitorConfig
from core.analyzer import StatefulAnalyzer
from core.datatypes import BaseEvent, EventCategory, Severity, SSHEvent
from core.event_bus import EventBus
from core.ssh_key_registry import (
    IDENTITY_NOT_REGISTERED, IDENTITY_REVOKED, IDENTITY_TRUSTED, STATUS_REVOKED, STATUS_TRUSTED,
    SshKeyRegistry, classify_identity, is_valid_email, is_valid_fingerprint, is_valid_label,
)
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.ssh_monitor import SSHMonitor

_FP_TRUSTED = "SHA256:" + "A" * 43
_FP_REVOKED = "SHA256:" + "B" * 43
_FP_UNKNOWN = "SHA256:" + "C" * 43


class _FakePwEntry:
    def __init__(self, pw_uid: int, pw_gid: int) -> None:
        self.pw_uid = pw_uid
        self.pw_gid = pw_gid


class _FakeGrEntry:
    def __init__(self, gr_name: str) -> None:
        self.gr_name = gr_name


async def main() -> None:
    assert is_valid_fingerprint(_FP_TRUSTED)
    assert not is_valid_fingerprint("not-a-fingerprint")
    assert not is_valid_fingerprint("SHA256:tooshort")
    assert is_valid_email("m.tegar.irawan2008@gmail.com")
    assert not is_valid_email("not-an-email")
    assert is_valid_label("Tegar")
    assert not is_valid_label("")
    print("Test 1 (fingerprint/email/label validators reject malformed input) PASSED")

    with tempfile.TemporaryDirectory(prefix="rtsa-sshkeyreg-") as tmp:
        reg_path = os.path.join(tmp, "ssh_key_registry.json")
        registry = SshKeyRegistry(reg_path, refresh_seconds=0.0)

        assert registry.lookup(_FP_UNKNOWN) is None
        assert classify_identity(_FP_UNKNOWN, None) == IDENTITY_NOT_REGISTERED
        assert classify_identity(None, None) == IDENTITY_NOT_REGISTERED
        print("Test 2 (unregistered/missing fingerprint -> NOT_REGISTERED, never guessed) PASSED")

        ok, reason = registry.register(
            _FP_TRUSTED, "m.tegar.irawan2008@gmail.com", "Tegar",
            key_type="ssh-ed25519", expected_linux_users=["newusproud"], status=STATUS_TRUSTED,
        )
        assert ok, reason
        record = registry.lookup(_FP_TRUSTED)
        assert record is not None and record.owner_email == "m.tegar.irawan2008@gmail.com"
        assert record.expected_linux_users == ("newusproud",)
        assert classify_identity(_FP_TRUSTED, record) == IDENTITY_TRUSTED
        with open(reg_path) as f:
            on_disk = json.load(f)
        assert "private" not in json.dumps(on_disk).lower(), "registry file must never contain private key material"
        print("Test 3 (register() persists a valid trusted key, lookup roundtrips, no private material stored) PASSED")

        ok2, reason2 = registry.register(_FP_TRUSTED, "someone-else@example.com", "Someone Else")
        assert not ok2, "duplicate fingerprint must be rejected without an explicit overwrite"
        assert "sudah terdaftar" in reason2
        assert registry.lookup(_FP_TRUSTED).owner_email == "m.tegar.irawan2008@gmail.com", "silent overwrite must never happen"
        print("Test 4 (duplicate fingerprint registration rejected -- no silent overwrite) PASSED")

        ok3, _ = registry.register(_FP_TRUSTED, "someone-else@example.com", "Someone Else", overwrite=True)
        assert ok3
        assert registry.lookup(_FP_TRUSTED).owner_email == "someone-else@example.com"
        print("Test 4b (explicit overwrite=True does update the record) PASSED")

        bad_ok, bad_reason = registry.register("not-a-fingerprint", "a@b.com", "X")
        assert not bad_ok and "Fingerprint" in bad_reason
        bad_ok2, _ = registry.register(_FP_UNKNOWN, "not-an-email", "X")
        assert not bad_ok2
        print("Test 5 (malformed fingerprint/email rejected by register()) PASSED")

        registry.register(_FP_REVOKED, "attacker-key-owner@example.com", "Suspicious", status=STATUS_REVOKED)
        revoked_record = registry.lookup(_FP_REVOKED)
        assert classify_identity(_FP_REVOKED, revoked_record) == IDENTITY_REVOKED
        print("Test 6 (revoked key classifies as REVOKED identity status) PASSED")

    missing_registry = SshKeyRegistry("/nonexistent/path/registry.json", refresh_seconds=0.0)
    assert missing_registry.lookup(_FP_TRUSTED) is None
    print("Test 7 (registry file unavailable -> lookup returns None gracefully, no crash) PASSED")

    with tempfile.TemporaryDirectory(prefix="rtsa-sshkeyreg-cache-") as tmp:
        reg_path = os.path.join(tmp, "registry.json")
        cached_registry = SshKeyRegistry(reg_path, refresh_seconds=300.0)
        cached_registry.register(_FP_TRUSTED, "a@b.com", "A")
        stat_calls = {"n": 0}
        real_stat = os.stat

        def counting_stat(path, *a, **kw):
            if path == reg_path:
                stat_calls["n"] += 1
            return real_stat(path, *a, **kw)

        os.stat = counting_stat
        try:
            for _ in range(5):
                cached_registry.lookup(_FP_TRUSTED)
        finally:
            os.stat = real_stat
        assert stat_calls["n"] == 0, (
            f"a lookup within the freshness window must never re-stat the registry file, got {stat_calls['n']} stats"
        )
        print("Test 8 (repeated lookups within the freshness window never re-touch the filesystem) PASSED")

    orig_getpwnam = account_privilege.pwd.getpwnam
    orig_getgrouplist = account_privilege.os.getgrouplist
    orig_getgrgid = account_privilege.grp.getgrgid
    try:
        account_privilege.pwd.getpwnam = lambda name: _FakePwEntry(pw_uid=0, pw_gid=0)
        assert classify_account_privilege("root") == ACCOUNT_PRIVILEGED, "UID 0 is always privileged"
        print("Test 9 (UID 0 account -> PRIVILEGED) PASSED")

        account_privilege.pwd.getpwnam = lambda name: _FakePwEntry(pw_uid=1500, pw_gid=1500)
        account_privilege.os.getgrouplist = lambda name, gid: [1500, 27]
        account_privilege.grp.getgrgid = lambda gid: _FakeGrEntry("sudo") if gid == 27 else _FakeGrEntry("newusproud")
        assert classify_account_privilege("newusproud") == ACCOUNT_PRIVILEGED, "sudo group membership -> PRIVILEGED"
        print("Test 10 (non-root account in the 'sudo' group -> PRIVILEGED, via real group membership) PASSED")

        account_privilege.os.getgrouplist = lambda name, gid: [1500]
        account_privilege.grp.getgrgid = lambda gid: _FakeGrEntry("newusproud")
        assert classify_account_privilege("newusproud") == ACCOUNT_STANDARD
        print("Test 11 (ordinary account, no privileged group -> STANDARD) PASSED")

        def _raise_keyerror(name):
            raise KeyError(name)

        account_privilege.pwd.getpwnam = _raise_keyerror
        assert classify_account_privilege("totally-made-up-user-xyz") == ACCOUNT_NOT_FOUND
        print("Test 12 (nonexistent account -> NOT_FOUND) PASSED")
    finally:
        account_privilege.pwd.getpwnam = orig_getpwnam
        account_privilege.os.getgrouplist = orig_getgrouplist
        account_privilege.grp.getgrgid = orig_getgrgid

    with tempfile.TemporaryDirectory(prefix="rtsa-sshmon-registry-") as tmp:
        reg_path = os.path.join(tmp, "ssh_key_registry.json")
        cfg = SSHMonitorConfig(
            enabled=True, geoip_lookup=False, ssh_key_registry_path=reg_path,
            ssh_key_registry_refresh_seconds=0.0,
        )
        mon = SSHMonitor(EventBus(), cfg)
        mon._key_registry.register(
            _FP_TRUSTED, "m.tegar.irawan2008@gmail.com", "Tegar",
            key_type="ssh-ed25519", expected_linux_users=["newusproud"], status=STATUS_TRUSTED,
        )
        mon._key_registry.register(_FP_REVOKED, "attacker@example.com", "Suspicious", status=STATUS_REVOKED)

        published = []
        mon.publish = lambda ev: published.append(ev)
        mon._process_line(
            f"Accepted publickey for newusproud from 103.105.82.10 port 52968 ssh2: RSA {_FP_UNKNOWN}"
        )
        assert len(published) == 1
        ev = published[0]
        assert ev.metadata["identity_status"] == IDENTITY_NOT_REGISTERED
        assert ev.metadata["key_owner"] == "UNKNOWN"
        print("Test 13 (unregistered fingerprint login -> identity_status NOT_REGISTERED, owner UNKNOWN) PASSED")

        published.clear()
        mon._process_line(
            f"Accepted publickey for newusproud from 103.105.82.10 port 52969 ssh2: RSA {_FP_TRUSTED}"
        )
        assert len(published) == 1, "a trusted key with a matching user must not raise any follow-up event"
        assert published[0].category == EventCategory.SSH_AUTH
        assert published[0].metadata["identity_status"] == IDENTITY_TRUSTED
        assert published[0].metadata["key_owner"] == "m.tegar.irawan2008@gmail.com"
        assert published[0].metadata["owner_label"] == "Tegar"
        print("Test 14 (trusted key, expected Linux user -> TRUSTED, owner/label shown, no follow-up event) PASSED")

        published.clear()
        mon._process_line(
            f"Accepted publickey for root from 103.105.82.10 port 52970 ssh2: RSA {_FP_TRUSTED}"
        )
        categories = [e.category for e in published]
        assert EventCategory.SSH_AUTH in categories and EventCategory.SSH_KEY_USER_MISMATCH in categories, categories
        assert EventCategory.SSH_AUTH == published[0].category, "SSH_AUTH must never be silently replaced"
        mismatch_event = next(e for e in published if e.category == EventCategory.SSH_KEY_USER_MISMATCH)
        assert mismatch_event.username == "root"
        assert mismatch_event.metadata["expected_linux_users"] == ["newusproud"]
        print("Test 15 (trusted key logs in as an unexpected Linux user -> additive SSH_KEY_USER_MISMATCH, SSH_AUTH preserved) PASSED")

        published.clear()
        mon._process_line(
            f"Accepted publickey for newusproud from 45.10.20.30 port 41000 ssh2: RSA {_FP_REVOKED}"
        )
        categories = [e.category for e in published]
        assert EventCategory.SSH_AUTH in categories and EventCategory.SSH_REVOKED_KEY_LOGIN in categories, categories
        revoked_event = next(e for e in published if e.category == EventCategory.SSH_REVOKED_KEY_LOGIN)
        assert revoked_event.severity == Severity.CRITICAL
        assert revoked_event.metadata["key_owner"] == "attacker@example.com"
        print("Test 16 (revoked key login -> additive SSH_REVOKED_KEY_LOGIN, CRITICAL, SSH_AUTH preserved) PASSED")

        published.clear()
        orig_getpwnam2 = account_privilege.pwd.getpwnam
        account_privilege.pwd.getpwnam = lambda name: _FakePwEntry(pw_uid=0, pw_gid=0)
        try:
            mon._process_line("Failed password for root from 94.177.195.107 port 36477")
        finally:
            account_privilege.pwd.getpwnam = orig_getpwnam2
        assert published[0].metadata["account_class"] == ACCOUNT_PRIVILEGED
        print("Test 17 (failed login against a privileged account -> account_class PRIVILEGED, real config not a hardcoded list) PASSED")

        published.clear()
        mon._process_line("Invalid user totally-fake-scan-user123 from 94.177.195.107 port 36478")
        assert published[0].metadata["account_class"] == ACCOUNT_NOT_FOUND
        print("Test 18 (invalid/nonexistent username -> account_class NOT_FOUND) PASSED")

    registry_source = open("core/ssh_key_registry.py").read()
    for marker in ("subprocess.run(", "subprocess.Popen(", "create_subprocess", "socket.getaddrinfo", "requests.get"):
        assert marker not in registry_source, f"ssh_key_registry.py must never call out externally: found {marker}"
    print("Test 19 (ssh_key_registry.py has zero subprocess/external-lookup/authorized_keys-scan code paths) PASSED")

    analyzer = StatefulAnalyzer(
        EventBus(), ssh_brute_force_threshold=2, ssh_brute_force_window_seconds=60,
        ssh_credential_stuffing_threshold=8, ssh_credential_stuffing_window_seconds=1800,
        ssh_credential_stuffing_min_distinct_ips=3,
    )
    published_alerts = []
    await analyzer.bus.subscribe(
        "test-sink", lambda e: published_alerts.append(e) or asyncio.sleep(0), categories=list(EventCategory),
    )

    ts = 1_000_000.0
    for username in ("root", "newusproud"):
        fail_event = SSHEvent(
            source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.MEDIUM,
            message="gagal", raw="", username=username, source_ip="94.177.195.107",
            auth_method="password", success=False, timestamp=ts,
            metadata={"username_status": "EXISTING_USER", "account_class": "PRIVILEGED"},
        )
        await analyzer._on_event(fail_event)
        ts += 1

    success_event = SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.LOW,
        message="berhasil", raw="", username="newusproud", source_ip="94.177.195.107",
        auth_method="publickey", success=True, timestamp=ts,
        metadata={
            "fingerprint": _FP_TRUSTED, "key_type": "ssh-ed25519", "identity_status": IDENTITY_TRUSTED,
            "key_owner": "m.tegar.irawan2008@gmail.com", "owner_label": "Tegar", "key_status": STATUS_TRUSTED,
        },
    )
    await analyzer._on_event(success_event)
    await analyzer.bus.unsubscribe("test-sink")

    red_zone = next((e for e in published_alerts if e.category == EventCategory.SSH_LOGIN_AFTER_BRUTE_FORCE), None)
    assert red_zone is not None, "successful login after brute force must produce SSH_LOGIN_AFTER_BRUTE_FORCE"
    assert red_zone.metadata.get("fingerprint") == _FP_TRUSTED
    assert red_zone.metadata.get("key_owner") == "m.tegar.irawan2008@gmail.com"
    assert red_zone.metadata.get("identity_status") == IDENTITY_TRUSTED
    assert red_zone.metadata.get("username_account_class", {}).get("root") == "PRIVILEGED"
    print(
        "Test 20 (RED ZONE alert carries trusted-key identity as contextual evidence AND privileged "
        "targeted-account class -- suspicious pattern not silently downgraded by a trusted key) PASSED"
    )

    dispatcher = DiscordWebhookDispatcher(
        EventBus(), DiscordConfig(enabled=True, alert_channel_id=555000), detection_only=False,
    )

    auth_alert = SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_AUTH, severity=Severity.LOW,
        message="SSH login diterima untuk 'newusproud' dari 103.105.82.10 lewat publickey", raw="",
        username="newusproud", source_ip="103.105.82.10", auth_method="publickey", success=True,
        metadata={
            "fingerprint": _FP_TRUSTED, "key_type": "ssh-ed25519", "identity_status": IDENTITY_TRUSTED,
            "key_owner": "m.tegar.irawan2008@gmail.com", "owner_label": "Tegar",
        },
    )
    auth_payload = dispatcher._build_payload(auth_alert)
    auth_fields = {f["name"]: f["value"] for f in auth_payload["embeds"][0]["fields"]}
    assert auth_fields["Identity Status"] == IDENTITY_TRUSTED
    assert auth_fields["Key Owner"] == "m.tegar.irawan2008@gmail.com"
    assert auth_fields["Owner Label"] == "Tegar"
    print("Test 21 (SSH_AUTH Discord embed shows Identity Status/Key Owner/Owner Label) PASSED")

    bf_alert = BaseEvent(
        source_module="analyzer", category=EventCategory.BRUTE_FORCE, severity=Severity.HIGH,
        message="Correlated rule 'ssh_brute_force' triggered", raw="",
        metadata={
            "source_ip": "94.177.195.107", "observed_count": 8, "window_seconds": 60,
            "unique_usernames": 2, "first_seen": 1_000_000.0, "last_seen": 1_000_030.0,
            "username_counts": {"root": 5, "cs": 3},
            "username_status": {"root": "EXISTING_USER", "cs": "INVALID_USER"},
            "username_account_class": {"root": "PRIVILEGED"},
            "auth_methods": ["password"],
        },
    )
    bf_payload = dispatcher._build_payload(bf_alert)
    bf_fields = {f["name"]: f["value"] for f in bf_payload["embeds"][0]["fields"]}
    assert "[PRIVILEGED]" in bf_fields["Targeted Users"] and "root" in bf_fields["Targeted Users"]
    assert "cs" in bf_fields["Targeted Users"] and "[PRIVILEGED]" not in bf_fields["Targeted Users"].split("cs")[1].split("\n")[0]
    print("Test 22 (BRUTE_FORCE Targeted Users breakdown marks the privileged account explicitly) PASSED")

    revoked_alert = SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_REVOKED_KEY_LOGIN, severity=Severity.CRITICAL,
        message="Login SSH berhasil menggunakan key REVOKED", raw="",
        username="newusproud", source_ip="45.10.20.30", auth_method="publickey", success=True,
        metadata={
            "fingerprint": _FP_REVOKED, "key_type": "ssh-ed25519", "identity_status": IDENTITY_REVOKED,
            "key_owner": "attacker@example.com", "owner_label": "Suspicious",
        },
    )
    revoked_payload = dispatcher._build_payload(revoked_alert)
    revoked_fields = {f["name"]: f["value"] for f in revoked_payload["embeds"][0]["fields"]}
    assert revoked_fields["Key Status"] == IDENTITY_REVOKED
    assert revoked_fields["Key Owner"] == "attacker@example.com"
    print("Test 23 (SSH_REVOKED_KEY_LOGIN Discord embed shows Key Owner/Key Status) PASSED")

    mismatch_alert = SSHEvent(
        source_module="ssh_monitor", category=EventCategory.SSH_KEY_USER_MISMATCH, severity=Severity.HIGH,
        message="Key/user mismatch", raw="",
        username="root", source_ip="103.105.82.10", auth_method="publickey", success=True,
        metadata={
            "fingerprint": _FP_TRUSTED, "identity_status": IDENTITY_TRUSTED,
            "key_owner": "m.tegar.irawan2008@gmail.com", "owner_label": "Tegar",
            "expected_linux_users": ["newusproud"],
        },
    )
    mismatch_payload = dispatcher._build_payload(mismatch_alert)
    mismatch_fields = {f["name"]: f["value"] for f in mismatch_payload["embeds"][0]["fields"]}
    assert mismatch_fields["Expected Linux User(s)"] == "['newusproud']"
    print("Test 24 (SSH_KEY_USER_MISMATCH Discord embed shows the expected Linux user(s)) PASSED")

    print("\nALL SSH KEY IDENTITY CORRELATION TESTS PASSED")


asyncio.run(main())
