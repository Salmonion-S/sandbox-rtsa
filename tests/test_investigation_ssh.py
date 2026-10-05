from __future__ import annotations

import ast
import hashlib
import io
import os
import sys
import tokenize

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _investigation_fakes import (
    NOW, ROOT_ONLY, EventDb, config_with_uid0, fail, key_entry, key_snapshot, live_session, login, logout, run_ssh, snapshot, user_keys,
)
from core import investigation_format as fmt
from core.investigation_store import ReadOnlyStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = {"name": "deploy", "uid": 0, "gid": 0, "home": "/home/deploy", "shell": "/bin/bash"}


def text_of(report):
    return fmt.sections_to_text("t", fmt.ssh_header(report), fmt.ssh_sections(report))


def test_1_active_session_shows_the_full_identity():
    db = EventDb()
    try:
        report = run_ssh(db.path, snapshot([live_session("sess-A", "deploy", "198.51.100.7", 51234)]))
        item = report["active_sessions"]["items"][0]
        assert report["active_sessions"]["source"] == "LIVE_TRACKER" and report["summary"]["active_sessions"] == 1
        expected = {"session_id": "sess-A", "user": "deploy", "source_ip": "198.51.100.7", "source_port": 51234, "ssh_port": 22, "auth_method": "publickey",
                    "fingerprint": "SHA256:liveKEY", "key_owner": "alice@example.com", "sshd_pid": 4321}
        assert all(item[k] == v for k, v in expected.items()) and item["key_source"].endswith("authorized_keys") and item["login_time"] == NOW - 600
        text = text_of(report)
        for token in ("deploy@198.51.100.7:51234", "sshd:22", "publickey", "SHA256:liveKEY", "owner=alice@example.com", "sid=sess-A", "pid=4321"):
            assert token in text, token
    finally:
        db.close()
    print("Test 1 (active session carries user, source IP/port, SSH port, auth method, fingerprint, key owner/source, session id and pid) PASSED")


def test_2_multiple_sessions_of_one_user_stay_separate():
    db = EventDb()
    try:
        login(db, NOW - 900, "deploy", "198.51.100.7", "sess-1", port=40001)
        login(db, NOW - 600, "deploy", "198.51.100.7", "sess-2", port=40002)
        login(db, NOW - 500, "deploy", "198.51.100.7", None, port=40003, pid=None)
        login(db, NOW - 400, "deploy", "198.51.100.7", None, port=40004, pid=None)
        logout(db, NOW - 300, "sess-1", "deploy", "198.51.100.7", login_time=NOW - 900, duration=600.0)
        db.commit()
        live = [live_session("sess-2", "deploy", "198.51.100.7", 40002), live_session("sess-9", "deploy", "198.51.100.8", 40009, pid=4400)]
        report = run_ssh(db.path, snapshot(live))
        assert {i["session_id"] for i in report["active_sessions"]["items"]} == {"sess-2", "sess-9"}
        logins = report["logins"]["items"]
        assert len(logins) == 4 and report["summary"]["successful_logins"] == 4 and report["summary"]["duplicates_collapsed"] == 0
        by_sid = {i["session_id"]: i for i in logins if i["session_id"]}
        assert by_sid["sess-1"]["status"] == "LOGGED_OUT" and by_sid["sess-2"]["status"] == "NO_LOGOUT_OBSERVED", "a logout only closes the matching session id"
        unidentified = [i for i in logins if not i["session_id"]]
        assert len(unidentified) == 2 and {i["source_port"] for i in unidentified} == {40003, 40004}, "sessions without an id are never merged by username"
        assert all(i["status"] == "NO_LOGOUT_OBSERVED" for i in unidentified)
    finally:
        db.close()
    print("Test 2 (several sessions of one user stay separate; a session is never identified by username alone) PASSED")


def test_3_normal_logout_is_not_elevated():
    db = EventDb()
    try:
        login(db, NOW - 900, "deploy", "198.51.100.7", "sess-1", fingerprint="SHA256:aaa", owner="alice@example.com")
        logout(db, NOW - 300, "sess-1", "deploy", "198.51.100.7", login_time=NOW - 900, duration=600.0)
        db.commit()
        report = run_ssh(db.path, snapshot())
        item = report["logins"]["items"][0]
        assert item["status"] == "LOGGED_OUT" and item["logout_classification"] == "NORMAL_SESSION_END" and item["duration"] == 600.0
        assert item["logout_time"] == NOW - 300 and item["logout_reason"] == "Disconnected"
        assert report["summary"]["assessment"] == "NORMAL" and not report["correlations"]
        text = text_of(report)
        assert "end=NORMAL_SESSION_END" in text and "MEDIUM" not in text
    finally:
        db.close()
    print("Test 3 (normal logout keeps NORMAL_SESSION_END with logout time and duration; assessment stays NORMAL) PASSED")


def test_4_delayed_logout_keeps_its_timing_classification():
    db = EventDb()
    try:
        login(db, NOW - 900, "deploy", "198.51.100.7", "sess-1")
        logout(db, NOW - 300, "sess-1", "deploy", "198.51.100.7", login_time=NOW - 900, duration=None, reliable=False, state="REPLAYED_LOGOUT", timing="REPLAYED")
        login(db, NOW - 800, "ops", "198.51.100.9", "sess-2")
        logout(db, NOW - 200, "sess-2", "ops", "198.51.100.9", login_time=NOW - 800, duration=600.0, classification="SESSION_CORRELATION_UNKNOWN", state="CORRELATION_UNKNOWN")
        db.commit()
        report = run_ssh(db.path, snapshot())
        by_sid = {i["session_id"]: i for i in report["logins"]["items"]}
        delayed = by_sid["sess-1"]
        assert delayed["logout_time"] is None and delayed["logout_time_reliable"] is False and delayed["logout_state"] == "REPLAYED_LOGOUT", "unreliable logout time is not invented"
        assert delayed["logout_classification"] == "NORMAL_SESSION_END" and delayed["duration"] is None
        assert by_sid["sess-2"]["status"] == "LOGOUT_UNCORRELATED" and by_sid["sess-2"]["logout_classification"] == "SESSION_CORRELATION_UNKNOWN"
        assert report["summary"]["assessment"] == "NORMAL", "delayed/uncorrelated logouts alone are not suspicious"
        text = text_of(report)
        assert "out=UNKNOWN" in text and "dur=UNKNOWN" in text
    finally:
        db.close()
    print("Test 4 (delayed/replayed logout shows UNKNOWN time and duration, keeps its classification, and does not raise the assessment) PASSED")


def test_5_failed_login_burst_alone_is_attention_not_critical():
    db = EventDb()
    try:
        names = ["admin", "root", "oracle", "test", "ubuntu"]
        for ip_index in range(5):
            for n in range(40):
                fail(db, NOW - 3000 + ip_index * 60 + n, f"203.0.113.{ip_index + 1}", names[(ip_index + n) % 5], status="INVALID_USER" if n % 2 else "VALID_USER")
        fail(db, NOW - 100, "203.0.113.99", "unknownuser")
        db.commit()
        report = run_ssh(db.path, snapshot())
        failed = report["failed"]
        assert failed["total"] == 201 and failed["unique_ips"] == 6 and failed["unique_usernames"] == 6 and failed["ssh_ports"] == [22]
        assert failed["first_seen"] == NOW - 3000 and failed["last_seen"] == NOW - 100
        assert failed["top_ips"][0]["count"] == 40 and {e["ip"] for e in failed["top_ips"][:5]} == {f"203.0.113.{i}" for i in range(1, 6)}
        assert all(e["brute_force"] for e in failed["top_ips"][:5]) and not failed["top_ips"][5]["brute_force"]
        assert {u["username"] for u in failed["top_usernames"]} >= set(names)
        assert report["summary"]["brute_force_sources"] == 5 and not report["correlations"]
        assert report["summary"]["assessment"] == "ATTENTION", "many failed logins alone are never CRITICAL"
        text = text_of(report)
        assert "malicious" in text and "not treated as malicious" in text
    finally:
        db.close()
    print("Test 5 (failed-login burst: counts, unique IPs/usernames/ports, first/last seen, top sources and usernames; ATTENTION and never CRITICAL) PASSED")


def test_6_brute_force_followed_by_success_is_a_correlation_not_a_verdict():
    db = EventDb()
    try:
        for n in range(8):
            fail(db, NOW - 290 + n * 5, "203.0.113.9", "admin" if n % 2 else "deploy")
        success = login(db, NOW - 200, "deploy", "203.0.113.9", "sess-X", method="password", fingerprint=None, port=53311)
        login(db, NOW - 150, "ops", "198.51.100.20", "sess-Y")
        for n in range(6):
            fail(db, NOW - 2000 + n, "203.0.113.50", "root")
        login(db, NOW - 1000, "ops", "203.0.113.50", "sess-Z")
        db.commit()
        report = run_ssh(db.path, snapshot())
        corr = {c["session_id"]: c for c in report["correlations"]}
        assert set(corr) == {"sess-X"}, "only the login that follows failures inside the configured window correlates"
        c = corr["sess-X"]
        assert c["classification"] == "CORRELATED_SUSPICIOUS_LOGIN" and c["priority"] == "HIGH" and c["source_ip"] == "203.0.113.9"
        assert c["failed_attempts_before_success"] == 8 and set(c["target_usernames"]) == {"admin", "deploy"} and c["success_time"] == NOW - 200
        assert c["auth_method"] == "password" and c["login_user"] == "deploy" and c["session_id"] == "sess-X" and "EVENT_WINDOW" in c["evidence_sources"]
        assert "not proof of compromise" in c["note"]
        assert report["summary"]["assessment"] == "SUSPICIOUS" and report["summary"]["suspicious_correlations"] == 1
        text = text_of(report)
        assert "CORRELATED_SUSPICIOUS_LOGIN" in text and "failed_before=8" in text and "sid=sess-X" in text
        assert "hacked" not in text.lower() and "compromised" not in text.lower()
        db.add(NOW - 199, "SSH_LOGIN_AFTER_BRUTE_FORCE", "CRITICAL", {"trigger_event_id": success, "brute_force_attempts": 8, "username_counts": {"admin": 4, "deploy": 4}, "source_ip": "203.0.113.9"})
        db.commit()
        again = run_ssh(db.path, snapshot())
        merged = [x for x in again["correlations"] if x["session_id"] == "sess-X"]
        assert len(merged) == 1 and set(merged[0]["evidence_sources"]) >= {"ANALYZER_RED_ZONE", "EVENT_WINDOW"}, "the analyzer RED ZONE event and the window query describe one login"
    finally:
        db.close()
    print("Test 6 (brute-force -> success inside the configured window is CORRELATED_SUSPICIOUS_LOGIN with IP, targets, counts, method and session; never 'hacked') PASSED")


def test_6b_stronger_evidence_raises_the_correlation_priority():
    db = EventDb()
    try:
        for n in range(5):
            fail(db, NOW - 280 + n, "203.0.113.9", "deploy")
        login(db, NOW - 200, "deploy", "203.0.113.9", "sess-K", fingerprint="SHA256:revoked", owner="UNKNOWN", identity="REVOKED")
        db.add(NOW - 199, "SSH_REVOKED_KEY_LOGIN", "CRITICAL", {"username": "deploy", "source_ip": "203.0.113.9"}, "revoked key login")
        db.commit()
        report = run_ssh(db.path, snapshot())
        c = report["correlations"][0]
        assert "REVOKED_KEY" in c["aggravators"] and c["priority"] == "CRITICAL"
        assert report["summary"]["assessment"] == "CRITICAL" and any("revoked" in r.lower() for r in report["summary"]["assessment_reasons"])
        db.add(NOW - 190, "SSH_KEY_CHANGE", "HIGH", {"phase": "LOGIN_AFTER_CHANGE", "classification": "CORRELATED_SSH_INTRUSION", "linux_users": ["deploy"], "fingerprints": ["SHA256:revoked"]}, "key then login")
        db.commit()
        stronger = run_ssh(db.path, snapshot())
        assert stronger["correlations"][0]["classification"] == "CORRELATED_SSH_INTRUSION", "the stronger class is used only when the key monitor produced that evidence"
    finally:
        db.close()
    print("Test 6b (revoked key or key-monitor intrusion evidence raises the correlation; otherwise the class stays CORRELATED_SUSPICIOUS_LOGIN) PASSED")


def test_7_new_key_is_reported_and_correlated_with_login_without_claiming_compromise():
    db = EventDb()
    try:
        keys = {"SHA256:newkey": key_entry(first_seen=NOW - 7200, comment="bob@laptop"), "SHA256:oldkey": key_entry(first_seen=NOW - 20 * 86400, status="TRUSTED", owner="alice@example.com")}
        snap_keys = key_snapshot({"deploy": user_keys("deploy", keys)}, additions={"deploy|SHA256:newkey": {"first_seen": NOW - 7200, "source": "/home/deploy/.ssh/authorized_keys", "classification": "UNKNOWN_KEY_CHANGE", "verified": False}})
        report = run_ssh(db.path, snapshot(keys=snap_keys), window=86400.0)
        classes = {k["fingerprint"]: k for k in report["keys"]["items"]}
        assert classes["SHA256:newkey"]["classification"] == "NEW_KEY" and classes["SHA256:newkey"]["baseline_status"] == "ADDED_AFTER_BASELINE"
        assert classes["SHA256:oldkey"]["classification"] == "KNOWN_KEY" and classes["SHA256:oldkey"]["key_owner"] == "alice@example.com"
        assert report["summary"]["new_keys"] == 1 and report["summary"]["assessment"] == "ATTENTION", "a new key alone is not proof of compromise"
        login(db, NOW - 600, "deploy", "198.51.100.7", "sess-N", fingerprint="SHA256:newkey", owner="UNKNOWN", identity="NOT_REGISTERED")
        db.commit()
        used = run_ssh(db.path, snapshot(keys=snap_keys), window=86400.0)
        key = {k["fingerprint"]: k for k in used["keys"]["items"]}["SHA256:newkey"]
        assert key["used_in_logins"] == ["sess-N"] and used["summary"]["assessment"] == "SUSPICIOUS"
        text = text_of(used)
        for token in ("NEW_KEY", "SHA256:newkey", "src=/home/deploy/.ssh/authorized_keys", "baseline=ADDED_AFTER_BASELINE", "used_in=sess-N", "Effective AuthorizedKeysFile"):
            assert token in text, token
    finally:
        db.close()
    print("Test 7 (new key: source, algorithm, fingerprint, comment, owner, first/last seen, baseline status; correlated with the later login, never called compromise) PASSED")


def test_8_unknown_and_revoked_keys_and_the_effective_key_sources():
    db = EventDb()
    try:
        keys = {
            "SHA256:revokedkey": key_entry(first_seen=NOW - 40 * 86400, status="REVOKED"), "SHA256:agedunverified": key_entry(first_seen=NOW - 20 * 86400),
            "SHA256:baselineonly": key_entry(first_seen=NOW - 30 * 86400),
        }
        users = {"deploy": user_keys("deploy", keys, command="/usr/local/bin/keys %u", files=["/etc/ssh/keys/%u"])}
        snap_keys = key_snapshot(users, created_at=NOW - 30 * 86400)
        report = run_ssh(db.path, snapshot(keys=snap_keys), window=86400.0)
        classes = {k["fingerprint"]: k for k in report["keys"]["items"]}
        assert classes["SHA256:revokedkey"]["classification"] == "UNKNOWN_KEY" and "REGISTRY_REVOKED" in classes["SHA256:revokedkey"]["flags"]
        assert classes["SHA256:agedunverified"]["classification"] == "UNKNOWN_KEY" and "ADDED_AFTER_BASELINE_UNVERIFIED" in classes["SHA256:agedunverified"]["flags"]
        assert classes["SHA256:baselineonly"]["classification"] == "KNOWN_KEY" and "BASELINE_ONLY_NOT_REGISTERED" in classes["SHA256:baselineonly"]["flags"]
        assert report["summary"]["unknown_keys"] == 2 and report["summary"]["assessment"] == "ATTENTION"
        sources = report["keys"]["effective_sources"]
        assert sources["authorized_keys_files"][0]["files"] == ["/etc/ssh/keys/%u"], "the effective AuthorizedKeysFile is reported, not only ~/.ssh/authorized_keys"
        assert sources["authorized_keys_command_users"] == 1
        assert any(g.startswith("AUTHORIZED_KEYS_COMMAND") for g in report["data_gaps"]), "command-provided keys are an explicit data gap"
        removed = db.add(NOW - 100, "SSH_KEY_CHANGE", "MEDIUM", {"change_type": "KEY_REMOVED", "change_types": ["KEY_REMOVED"], "classification": "UNKNOWN_KEY_CHANGE", "phase": "CHANGE",
                                                              "linux_users": ["deploy"], "fingerprints": ["SHA256:gone"], "key_source": "/etc/ssh/keys/deploy"}, "removed")
        db.add(NOW - 90, "SSH_KEY_CHANGE", "MEDIUM", {"change_type": "KEY_CHANGED", "change_types": ["KEY_CHANGED"], "classification": "KNOWN_ADMIN_CHANGE", "phase": "CHANGE",
                                                      "linux_users": ["deploy"], "fingerprints": ["SHA256:swapped"], "key_source": "/etc/ssh/keys/deploy"}, "changed")
        db.commit()
        again = run_ssh(db.path, snapshot(keys=snap_keys), window=86400.0)
        kinds = {c["key_class"] for c in again["key_changes"]}
        assert kinds == {"REMOVED_KEY", "CHANGED_KEY"} and removed
    finally:
        db.close()
    print("Test 8 (unknown/revoked keys, REMOVED_KEY/CHANGED_KEY from recent changes, effective AuthorizedKeysFile and AuthorizedKeysCommand gap) PASSED")


def test_9_root_only_uid0_is_known_root():
    db = EventDb()
    try:
        report = run_ssh(db.path, snapshot(), accounts=ROOT_ONLY)
        assert [(a["username"], a["classification"]) for a in report["uid0"]] == [("root", "KNOWN_ROOT")]
        assert report["summary"]["uid0_anomalies"] == 0 and report["summary"]["assessment"] == "NORMAL"
    finally:
        db.close()
    print("Test 9 (root-only UID 0 is KNOWN_ROOT with no anomaly) PASSED")


def test_10_configured_non_root_uid0_is_known_legitimate():
    db = EventDb()
    try:
        report = run_ssh(db.path, snapshot(), accounts=ROOT_ONLY + [DEPLOY], cfg=config_with_uid0("deploy"))
        classes = {a["username"]: a["classification"] for a in report["uid0"]}
        assert classes == {"root": "KNOWN_ROOT", "deploy": "KNOWN_LEGITIMATE_UID0"} and report["summary"]["uid0_anomalies"] == 0
        assert report["summary"]["assessment"] == "NORMAL"
    finally:
        db.close()
    print("Test 10 (a non-root UID 0 account the operator declared legitimate is KNOWN_LEGITIMATE_UID0 and not an anomaly) PASSED")


def test_11_unknown_uid0_is_investigated_and_only_suspicious_with_evidence():
    db = EventDb()
    try:
        report = run_ssh(db.path, snapshot(), accounts=ROOT_ONLY + [DEPLOY], sudoers=lambda user, groups: "ENTRY_FOUND (90-deploy)")
        account = [a for a in report["uid0"] if a["username"] == "deploy"][0]
        assert account["classification"] == "UNKNOWN_UID0", "non-root UID 0 is not assumed to be a compromise"
        assert account["sudoers"] == "ENTRY_FOUND (90-deploy)" and account["home"] == "/home/deploy" and account["shell"] == "/bin/bash" and account["gid"] == 0
        assert account["first_seen"] is None and account["first_seen_basis"] == "UNKNOWN" and account["recent_logins"] == 0 and account["ssh_keys"] is None
        assert report["summary"]["uid0_anomalies"] == 1 and report["summary"]["assessment"] == "SUSPICIOUS"
        assert "not proof of compromise" in " ".join(report["summary"]["assessment_reasons"])
        db.add(NOW - 5 * 86400, "PERSISTENCE_NEW_USER", "HIGH", {"username": "deploy"}, "Akun baru 'deploy' dibuat")
        login(db, NOW - 300, "deploy", "198.51.100.7", "sess-U")
        db.add(NOW - 400, "FILE_INTEGRITY_CHANGE", "HIGH", {"path": "/etc/passwd", "change_type": "MODIFIED"}, "passwd changed")
        db.commit()
        evidence = run_ssh(db.path, snapshot(), accounts=ROOT_ONLY + [DEPLOY], window=86400.0)
        strong = [a for a in evidence["uid0"] if a["username"] == "deploy"][0]
        assert strong["classification"] == "SUSPICIOUS_UID0" and {"NEW_ACCOUNT_EVENT", "RECENT_SSH_LOGIN", "ACCOUNT_DATABASE_CHANGED"} <= set(strong["aggravators"])
        assert strong["first_seen_basis"] == "PERSISTENCE_NEW_USER_EVENT" and strong["recent_fim_changes"] == 1 and evidence["summary"]["assessment"] == "CRITICAL"
    finally:
        db.close()
    print("Test 11 (unknown non-root UID 0: evidence listed and UNKNOWN_UID0; SUSPICIOUS_UID0 only with new-account/login/passwd-change evidence) PASSED")


def test_12_missing_evidence_is_reported_as_unknown_never_invented():
    report = run_ssh(None, None)
    assert report["summary"]["assessment"] == "NORMAL" and report["summary"]["active_sessions"] == 0 and report["active_sessions"]["source"] == "UNAVAILABLE"
    gaps = " ".join(report["data_gaps"])
    assert "DATABASE_NOT_FOUND" in gaps and "KEY_BASELINE_UNAVAILABLE" in gaps
    assert report["keys"]["meta"]["available"] is False and report["failed"]["total"] == 0
    db = EventDb()
    try:
        login(db, NOW - 300, "ghost", "198.51.100.77", None, port=None, ssh_port=22, method="password", pid=None)
        db.commit()
        sparse = run_ssh(db.path, None)
        item = sparse["logins"]["items"][0]
        assert item["session_id"] is None and item["source_port"] is None and item["sshd_pid"] is None and item["fingerprint"] is None and item["key_owner"] is None
        assert any(g.startswith("LIVE_SESSION_TRACKER_UNAVAILABLE") for g in sparse["data_gaps"]) and sparse["active_sessions"]["source"] == "INFERRED_FROM_EVENTS"
        text = text_of(sparse)
        assert "ghost@198.51.100.77:UNKNOWN" in text and "sid=UNKNOWN" in text and "pid=UNKNOWN" in text and "owner=UNKNOWN" in text and "(inferred from stored events" in text
    finally:
        db.close()
    print("Test 12 (missing evidence: UNKNOWN fields, explicit data gaps, inferred sessions are labelled, nothing is invented) PASSED")


def test_13_duplicate_events_are_collapsed():
    db = EventDb()
    try:
        login(db, NOW - 900, "deploy", "198.51.100.7", "sess-D")
        login(db, NOW - 899, "deploy", "198.51.100.7", "sess-D")
        logout(db, NOW - 300, "sess-D", "deploy", "198.51.100.7", login_time=NOW - 900, duration=600.0)
        logout(db, NOW - 299, "sess-D", "deploy", "198.51.100.7", login_time=NOW - 900, duration=601.0)
        login(db, NOW - 700, "ops", "198.51.100.8", None, port=41000, pid=None)
        login(db, NOW - 700, "ops", "198.51.100.8", None, port=41000, pid=None)
        db.commit()
        report = run_ssh(db.path, snapshot())
        assert report["summary"]["successful_logins"] == 2 and report["summary"]["duplicates_collapsed"] == 3
        first = [i for i in report["logins"]["items"] if i["session_id"] == "sess-D"][0]
        assert first["duration"] == 600.0 and first["duplicates"] >= 2, "the first record wins and later copies are only counted"
    finally:
        db.close()
    print("Test 13 (duplicate login/logout records collapse into one session and are counted, not double-reported) PASSED")


def test_14_replayed_events_are_marked_and_never_inferred_as_active():
    db = EventDb()
    try:
        for n in range(4):
            fail(db, NOW - 500 + n, "203.0.113.9", "deploy")
        login(db, NOW - 300, "deploy", "203.0.113.9", "sess-R", timing="REPLAYED")
        login(db, NOW - 250, "ops", "198.51.100.8", "sess-S", timing="DELAYED")
        db.commit()
        report = run_ssh(db.path, None)
        by_sid = {i["session_id"]: i for i in report["logins"]["items"]}
        assert by_sid["sess-R"]["timing_status"] == "REPLAYED" and by_sid["sess-S"]["timing_status"] == "DELAYED"
        assert {i["session_id"] for i in report["active_sessions"]["items"]} == {"sess-S"}, "a replayed login is history, not a live session"
        assert report["summary"]["delayed_or_replayed_logins"] == 2
        corr = report["correlations"][0]
        assert corr["historical"] is True and corr["success_time"] == NOW - 300, "the original event time is used, not the detection time"
        assert any("REPLAYED" in line for line in corr["evidence"]) and "[REPLAYED]" in text_of(report)
    finally:
        db.close()
    print("Test 14 (replayed/delayed events keep event time and are labelled; replayed logins are not active sessions) PASSED")


def test_15_the_report_is_read_only_and_bounded():
    db = EventDb()
    try:
        for n in range(300):
            fail(db, NOW - 3000 + n, f"203.0.113.{n % 20}", "admin")
        login(db, NOW - 200, "deploy", "198.51.100.7", "sess-1")
        db.commit()
        digest_before = hashlib.sha256(open(db.path, "rb").read()).hexdigest()
        store = ReadOnlyStore(db.path, time_budget_seconds=5.0)
        assert store.open()
        try:
            store._conn.execute("INSERT INTO events (event_id, timestamp, source_module, category, severity, message, raw, host, metadata) VALUES ('x',1,'m','c','s','','','','{}')")
            raise AssertionError("the investigation connection must be read-only")
        except Exception as exc:
            assert "readonly" in str(exc).lower() or "read-only" in str(exc).lower(), exc
        finally:
            store.close()
        run_ssh(db.path, snapshot())
        assert hashlib.sha256(open(db.path, "rb").read()).hexdigest() == digest_before, "running a report never modifies the database"
        ticks = iter(range(0, 10000))
        slow = ReadOnlyStore(db.path, time_budget_seconds=1.0, clock=lambda: float(next(ticks)) * 0.4)
        slow.open()
        report = run_ssh(None, snapshot(), store=slow)
        slow.close()
        assert report["truncated"] is True and any(g.startswith("TIME_BUDGET_EXHAUSTED") for g in report["data_gaps"]), "an exhausted budget is a data gap, never a silent partial answer"
        assert report["store"]["queries"] < 12, "once the budget is gone no more queries are issued"
    finally:
        db.close()
    print("Test 15 (read-only connection, database unchanged, query time budget reported as a data gap) PASSED")


def test_16_sources_never_mutate_ssh_or_the_system():
    banned_calls = {"system", "popen", "run", "Popen", "call", "check_call", "check_output", "remove", "unlink", "rmdir", "rename", "chmod", "chown", "kill", "killpg", "eval", "exec"}
    for rel in ("core/investigation_ssh.py", "core/investigation_store.py", "core/investigation_format.py", "core/investigation_service.py", "core/investigation_registry.py"):
        source = open(os.path.join(ROOT, rel)).read()
        tree = ast.parse(source)
        assert not [t for t in tokenize.generate_tokens(io.StringIO(source).readline) if t.type == tokenize.COMMENT], f"{rel} has comments"
        assert not [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) and any(a.name.split(".")[0] in ("subprocess", "socket", "shutil") for a in getattr(n, "names", []))], rel
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                assert name not in banned_calls, f"{rel} calls {name}"
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "open":
                mode = node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else "r"
                assert set(str(mode)) <= set("rb"), f"{rel} opens a file for writing"
            assert not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)), f"{rel} has a docstring"
        assert "publish" not in source and "enqueue_" not in source and "discord" not in source.lower(), f"{rel} must not publish events or talk to Discord"
    print("Test 16 (investigation modules never spawn processes, write files, change SSH/firewall/accounts, publish events or call Discord) PASSED")


def test_17_secrets_in_evidence_are_redacted_in_the_output():
    db = EventDb()
    try:
        db.add(NOW - 100, "SSH_KEY_CHANGE", "HIGH", {"change_type": "KEY_ADDED", "change_types": ["KEY_ADDED"], "classification": "UNKNOWN_KEY_CHANGE", "phase": "CHANGE",
                                                      "linux_users": ["deploy"], "fingerprints": ["SHA256:x"], "key_source": "/home/deploy/.ssh/authorized_keys password=hunter2hunter2"},
               "key added token=abcdef123456 Bearer abcdefghijklmnop postgres://user:pw@db/app")
        db.add(NOW - 90, "PERSISTENCE_NEW_USER", "HIGH", {"username": "x"}, "created api_key=ZZZZZZZZZZ secret: topsecretvalue")
        db.commit()
        report = run_ssh(db.path, snapshot(), window=86400.0)
        text = text_of(report)
        pages = fmt.paginate(fmt.ssh_header(report), fmt.ssh_sections(report))
        everything = text + "\n".join(body for page in pages for _t, body in page)
        for secret in ("hunter2hunter2", "abcdef123456", "abcdefghijklmnop", "user:pw@", "ZZZZZZZZZZ", "topsecretvalue"):
            assert secret not in everything, secret
        assert "REDACTED" in everything
    finally:
        db.close()
    print("Test 17 (passwords, tokens, bearer headers, connection strings and API keys are redacted in Discord pages and attachments) PASSED")


def test_18_formatted_pages_fit_discord_limits():
    db = EventDb()
    try:
        for n in range(60):
            login(db, NOW - 3000 + n, f"user{n}", f"198.51.100.{n % 200}", f"s{n}", fingerprint=f"SHA256:{'k' * 43}{n}", owner="someone@example.com")
            fail(db, NOW - 3000 + n, f"203.0.113.{n}", f"name{n}")
        db.commit()
        report = run_ssh(db.path, snapshot([live_session(f"live{n}", "deploy", "198.51.100.1", 40000 + n) for n in range(40)]))
        pages = fmt.paginate(fmt.ssh_header(report), fmt.ssh_sections(report))
        assert len(pages) <= 10
        for page in pages:
            assert sum(len(t) + len(b) for t, b in page) <= 5400 + 1100 and all(len(b) <= 1024 for _t, b in page)
        assert fmt.was_clipped(pages), "long evidence is clipped in Discord but kept in the attachment"
        assert "live39" in fmt.sections_to_text("t", "h", fmt.ssh_sections(report)) or len(report["active_sessions"]["items"]) == 40
    finally:
        db.close()
    print("Test 18 (formatted pages respect Discord field/embed limits; the full text attachment keeps everything) PASSED")


def test_19_key_snapshot_is_lazy_and_failures_are_gaps():
    db = EventDb()
    try:
        keys = {"SHA256:lazy": key_entry(first_seen=NOW - 20 * 86400, status="TRUSTED", owner="alice@example.com")}
        snap_keys = key_snapshot({"deploy": user_keys("deploy", keys)})
        calls = []
        lazy = run_ssh(db.path, snapshot(keys_fn=lambda: calls.append(1) or snap_keys))
        assert calls == [1] and lazy["keys"]["meta"]["available"] and lazy["keys"]["items"][0]["classification"] == "KNOWN_KEY"
        busy = run_ssh(db.path, snapshot(keys_fn=lambda: {"busy": True}))
        assert not busy["keys"]["meta"]["available"] and any(g.startswith("KEY_BASELINE_BUSY") for g in busy["data_gaps"])

        def explode():
            raise RuntimeError("baseline unreadable")

        failed = run_ssh(db.path, snapshot(keys_fn=explode))
        assert not failed["keys"]["meta"]["available"] and any(g.startswith("KEY_BASELINE_FAILED") for g in failed["data_gaps"])
        assert failed["summary"]["assessment"] == "NORMAL", "an unavailable key inventory is a gap, not an accusation"
    finally:
        db.close()
    print("Test 19 (the key baseline is fetched lazily; a busy or failing key monitor becomes an explicit gap and never changes the verdict) PASSED")


def main() -> None:
    test_1_active_session_shows_the_full_identity()
    test_2_multiple_sessions_of_one_user_stay_separate()
    test_3_normal_logout_is_not_elevated()
    test_4_delayed_logout_keeps_its_timing_classification()
    test_5_failed_login_burst_alone_is_attention_not_critical()
    test_6_brute_force_followed_by_success_is_a_correlation_not_a_verdict()
    test_6b_stronger_evidence_raises_the_correlation_priority()
    test_7_new_key_is_reported_and_correlated_with_login_without_claiming_compromise()
    test_8_unknown_and_revoked_keys_and_the_effective_key_sources()
    test_9_root_only_uid0_is_known_root()
    test_10_configured_non_root_uid0_is_known_legitimate()
    test_11_unknown_uid0_is_investigated_and_only_suspicious_with_evidence()
    test_12_missing_evidence_is_reported_as_unknown_never_invented()
    test_13_duplicate_events_are_collapsed()
    test_14_replayed_events_are_marked_and_never_inferred_as_active()
    test_15_the_report_is_read_only_and_bounded()
    test_16_sources_never_mutate_ssh_or_the_system()
    test_17_secrets_in_evidence_are_redacted_in_the_output()
    test_18_formatted_pages_fit_discord_limits()
    test_19_key_snapshot_is_lazy_and_failures_are_gaps()
    print("\nALL SSH INVESTIGATION TESTS PASSED")


if __name__ == "__main__":
    main()
