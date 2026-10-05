import asyncio
import os
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import FileIntegrityDetectorConfig, NginxMonitorConfig
from core.change_attribution import (
    CONFIRMED as CA_CONFIRMED, SUSPICIOUS as CA_SUSPICIOUS, FIXSSL, SOFIX, attribute_change,
    load_recent_changes, record_changes,
)
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from core.file_identity import FileIdentity
from core.fim_risk_classifier import HIGH_RISK, LIKELY_LEGITIMATE, SUSPICIOUS, classify_risk
from modules.file_integrity_detector import FileIntegrityDetector
from modules.nginx_monitor import NginxMonitor, _LogSource

PROJECT = "/home/vic/htdocs/example.com"
SOURCE = _LogSource(log_file="/var/log/nginx/access.log", line_number=1, raw_line="raw")


def identity(path, sha, mode=0o644, inode=100):
    return FileIdentity(
        sha256=sha, mode=mode, uid=1000, gid=1000, size=10, mtime=time.time(),
        is_symlink=False, symlink_target=None, inode=inode,
    )


def make_fim(**overrides):
    cfg = FileIntegrityDetectorConfig(**overrides)
    det = FileIntegrityDetector(EventBus(), cfg)
    published = []
    det.publish = lambda ev: published.append(ev)
    return det, published


def evaluate(det, path, old, new, **kwargs):
    return det._evaluate_change(path, "php_source", old, new, **kwargs)


def make_monitor_for_ignore():
    mon = NginxMonitor(EventBus(), NginxMonitorConfig(enabled=True, rce_correlation_enabled=False))
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_meta(domain, source):
        return "", {"domain": "example.com"}

    mon._build_web_attack_metadata = fake_meta
    return mon, published


async def main():
    det, _pub = make_fim()

    created = evaluate(det, f"{PROJECT}/public/new.php", None, identity(f"{PROJECT}/public/new.php", "aaa"))
    assert created["change_type"] == "created", created
    assert created["sha256_old"] is None and created["sha256_new"] == "aaa"

    modified = evaluate(
        det, f"{PROJECT}/public/index.php",
        identity(f"{PROJECT}/public/index.php", "aaa"), identity(f"{PROJECT}/public/index.php", "bbb"),
    )
    assert modified["change_type"] == "modified", modified
    assert modified["sha256_old"] == "aaa" and modified["sha256_new"] == "bbb"

    deleted = evaluate(det, f"{PROJECT}/public/old.php", identity(f"{PROJECT}/public/old.php", "ccc"), None)
    assert deleted["change_type"] == "deleted", deleted
    assert deleted["sha256_old"] == "ccc" and deleted["sha256_new"] is None
    print("Scenario 19/20/21 (FIM create / modify / delete + old & new SHA256) PASSED")

    gone = evaluate(det, f"{PROJECT}/a.php", identity(f"{PROJECT}/a.php", "same", inode=77), None)
    appeared = evaluate(det, f"{PROJECT}/b.php", None, identity(f"{PROJECT}/b.php", "same", inode=77))
    merged = det._correlate_renames([gone, appeared])
    assert len(merged) == 1, merged
    assert merged[0]["change_type"] == "renamed", merged[0]
    assert merged[0]["renamed_from"] == f"{PROJECT}/a.php"
    print("Scenario 22 (FIM rename/move -> satu event 'renamed', bukan delete+create) PASSED")

    replaced_old = evaluate(det, f"{PROJECT}/c.php", identity(f"{PROJECT}/c.php", "x1", inode=1), None)
    replaced_new = evaluate(det, f"{PROJECT}/c.php.new", None, identity(f"{PROJECT}/c.php.new", "x1", inode=2))
    merged = det._correlate_renames([replaced_old, replaced_new])
    assert len(merged) == 2 and all(c.get("possible_rename") for c in merged), (
        "identical content on a DIFFERENT inode is only a possible rename (copy+delete looks identical): "
        "it stays DELETE + CREATE and both are flagged possible_rename=true"
    )
    assert {c["rename_evidence"] for c in merged} == {"HASH_MATCH_ONLY"}
    print("Scenario 23 (konten sama lintas inode -> tetap DELETE+CREATE dengan possible_rename=true, bukan RENAMED) PASSED")

    modified_generic = classify_risk(f"{PROJECT}/src/helper.php", "modified", PROJECT)
    assert modified_generic is not None, "a PHP change in a PHP project must be classified, not ignored"
    assert modified_generic.severity == Severity.MEDIUM, modified_generic
    assert modified_generic.assessment == SUSPICIOUS, modified_generic

    created_php = classify_risk(f"{PROJECT}/src/helper.php", "created", PROJECT)
    assert created_php.severity == Severity.HIGH, created_php
    assert created_php.assessment == HIGH_RISK

    auth_php = classify_risk(f"{PROJECT}/app/AuthController.php", "modified", PROJECT)
    assert auth_php.severity == Severity.HIGH, auth_php

    upload_php = classify_risk(f"{PROJECT}/public/uploads/shell.php", "created", PROJECT)
    assert upload_php.severity == Severity.CRITICAL, upload_php
    assert upload_php.assessment == HIGH_RISK
    print("Scenario 24/25 (PHP modify=SUSPICIOUS, new=HIGH_RISK, auth/upload-dir=lebih tinggi) PASSED")

    nginx_conf = classify_risk("/etc/nginx/sites-enabled/example.com.conf", "modified")
    assert nginx_conf.severity == Severity.HIGH, nginx_conf
    assert nginx_conf.assessment == HIGH_RISK
    assert classify_risk("/etc/systemd/system/evil.service", "created").severity == Severity.CRITICAL
    assert classify_risk("/etc/cron.d/backup", "modified").severity == Severity.CRITICAL
    assert classify_risk(f"{PROJECT}/public/uploads/.htaccess", "created").severity == Severity.HIGH
    print("Scenario 26 (nginx conf / systemd unit / cron / .htaccess terklasifikasi) PASSED")

    assert "possible_creator_pid" in modified and "creator" in modified
    assert modified["creator"] == "UNKNOWN", "no candidate found must render UNKNOWN, never guessed"
    print("Scenario 27 (process correlation: creator UNKNOWN kalau tidak ada kandidat) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ledger = os.path.join(tmp, "ledger.json")
        conf = "/etc/nginx/sites-enabled/example.com.conf"
        record_changes(ledger, [(conf, "new")], FIXSSL, requested_by="operator#1")
        recent = load_recent_changes(ledger, 900.0)
        result = attribute_change(recent, conf, "new")
        assert result is not None and result.status == CA_CONFIRMED, result
        assert result.record.source == FIXSSL
        assert result.record.operation_id, "an operation_id must be assigned"

        det2, _ = make_fim(change_ledger_path=ledger)
        attributed = det2._evaluate_change(
            conf, "system_file", identity(conf, "old"), identity(conf, "new"),
            recent_command_changes=recent,
        )
        assert attributed is not None, "an attributed change must still produce an audit event"
        assert attributed["change_source"] == FIXSSL, attributed
        assert attributed["assessment"] == LIKELY_LEGITIMATE, attributed
        assert attributed["attribution_status"] == CA_CONFIRMED, attributed
        assert attributed["severity"] == Severity.HIGH, (
            "attribution must NOT lower the severity -- it is context, not suppression"
        )
        print("Scenario 28 (/fixssl + FIM: hash cocok -> CONFIRMED/LIKELY_LEGITIMATE, event tetap terbit) PASSED")

        record_changes(ledger, [(conf, "expected-content-hash")], SOFIX, requested_by="operator#2")
        recent = load_recent_changes(ledger, 900.0)
        conflict = det2._evaluate_change(
            conf, "system_file", identity(conf, "old"), identity(conf, "attacker-actually-wrote-this"),
            recent_command_changes=recent,
        )
        assert conflict["change_source"] is None, (
            "a content mismatch must never legitimize the change via change_source"
        )
        assert conflict["attribution_status"] == CA_SUSPICIOUS, conflict
        assert conflict["assessment"] != LIKELY_LEGITIMATE, (
            f"content mismatch during a command's window must never read as legitimate: {conflict}"
        )
        print(
            "Scenario 28b (path+window cocok TAPI konten beda dari yang ditulis /sofix -> "
            "SUSPICIOUS, TIDAK PERNAH LIKELY_LEGITIMATE) PASSED"
        )

        readme = "/home/vic/htdocs/example.com/README.md"
        record_changes(ledger, [(readme, "expected-readme-hash")], SOFIX, requested_by="operator#3")
        recent_readme = load_recent_changes(ledger, 900.0)
        readme_conflict = det2._evaluate_change(
            readme, "php_source", identity(readme, "old"), identity(readme, "different-from-expected"),
            recent_command_changes=recent_readme,
        )
        assert readme_conflict["attribution_status"] == CA_SUSPICIOUS, readme_conflict
        assert readme_conflict["assessment"] != LIKELY_LEGITIMATE, readme_conflict
        assert "PERINGATAN ATRIBUSI" in (readme_conflict["risk_reason"] or ""), readme_conflict
        print(
            "Scenario 28c (file low-risk yang biasanya LIKELY_LEGITIMATE tetap di-floor ke "
            "SUSPICIOUS + catatan konflik saat konten tidak cocok) PASSED"
        )

        generic_path = f"{PROJECT}/data/generic.txt"
        assert classify_risk(generic_path, "modified", PROJECT) is None, (
            "test precondition: this path must not match any classify_risk rule"
        )
        record_changes(ledger, [(generic_path, "new")], FIXSSL, requested_by="operator#4")
        recent_generic = load_recent_changes(ledger, 900.0)
        generic_confirmed = det2._evaluate_change(
            generic_path, "uploads", identity(generic_path, "old"), identity(generic_path, "new"),
            recent_command_changes=recent_generic,
        )
        assert generic_confirmed["attribution_status"] == CA_CONFIRMED, generic_confirmed
        assert generic_confirmed["assessment"] == LIKELY_LEGITIMATE, (
            f"a CONFIRMED attribution must not be dropped just because no risk rule matched: "
            f"{generic_confirmed}"
        )
        print("Scenario 28d (CONFIRMED attribution tetap LIKELY_LEGITIMATE walau tidak ada rule classify_risk yang cocok) PASSED")

        other = "/etc/nginx/sites-enabled/other.com.conf"
        unattributed = det2._evaluate_change(
            other, "system_file", identity(other, "old"), identity(other, "new"),
            recent_command_changes=recent,
        )
        assert unattributed["change_source"] is None, unattributed
        assert unattributed["attribution_status"] is None, unattributed
        assert unattributed["assessment"] == HIGH_RISK, unattributed
        print("Scenario 29 (/sofix + FIM; file yang tidak disentuh RTSA tidak ikut ter-atribusi) PASSED")

        stale_ledger = os.path.join(tmp, "stale.json")
        record_changes(stale_ledger, [(conf, "new")], SOFIX, now=time.time() - 5000)
        assert load_recent_changes(stale_ledger, 900.0) == {}, "expired attribution must not apply"
        assert load_recent_changes(stale_ledger, 6000.0), "a wider window must still see it"
        print("Attribution window (record kedaluwarsa tidak lagi memberi label) PASSED")

    cfg = NginxMonitorConfig(enabled=True, rce_correlation_enabled=False, whitelisted_ips=["203.0.113.50"])
    mon = NginxMonitor(EventBus(), cfg)
    pub = []
    mon.publish = lambda ev: pub.append(ev)

    async def fake_meta(domain, source):
        return "", {"domain": "example.com"}

    mon._build_web_attack_metadata = fake_meta
    await mon._check_web_attack_signature(
        "203.0.113.50", "/x?c=;id", "GET", "curl/8.0", 404, "example.com", SOURCE,
        is_whitelisted=True, response_size=10,
    )
    assert len(pub) == 1, "a whitelisted IP must still produce a forensic event on the bus"
    assert pub[0].metadata["notify_discord"] is False, pub[0].metadata
    assert pub[0].metadata["classification"] == "ATTEMPT"
    print("Scenario 30 (whitelist -> event forensik tetap ada, hanya notify_discord=false) PASSED")

    assert mon._is_ip_whitelisted("203.0.113.50") is True
    assert mon._is_ip_whitelisted("198.51.100.9") is False
    mon.reload_config(NginxMonitorConfig(enabled=True, whitelisted_ips=["198.51.100.0/24"]))
    assert mon._is_ip_whitelisted("198.51.100.9") is True, "reload must apply the new whitelist"
    assert mon._is_ip_whitelisted("203.0.113.50") is False, "reload must drop the removed entry"
    print("Scenario 31 (/rtsareload benar-benar rebuild runtime whitelist) PASSED")

    mon2, pub2 = make_monitor_for_ignore()
    assert mon2._is_socketio_path("/socket.io/?EIO=4&transport=polling") is True
    assert mon2._is_socketio_path("/socket.io.evil/../../etc/passwd") is False
    assert mon2._is_benign_request_path("/_next/image?url=%2Fassets%2Flogo.png&w=640") is True
    assert mon2._is_benign_request_path("/sitemap.xml") is True
    assert mon2._is_benign_request_path("/") is True

    for ip, path in (
        ("203.0.113.91", "/_next/image?url=../../../etc/passwd"),
        ("203.0.113.92", "/socket.io/?EIO=4&q=' union select password from users--"),
        ("203.0.113.93", "/?file=../../../../etc/passwd"),
    ):
        pub2.clear()
        await mon2._check_web_attack_signature(
            ip, path, "GET", "curl/8.0", 404, "example.com", SOURCE, response_size=1,
        )
        assert pub2, f"an ignore pattern must never suppress attack detection: {path}"
    print("Scenario 32/33 (Socket.IO + Next.js asset ignore berlaku, tapi bukan detection bypass) PASSED")

    print("\nALL FIM / PHP / CHANGE-ATTRIBUTION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
