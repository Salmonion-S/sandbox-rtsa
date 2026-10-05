import asyncio
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

import yaml

from core import lb_validation as v


def synthetic(inject=1010.0, restore=1020.0, rate=10.0, outage=1.3, recover_after=1.5, end=1030.0):
    samples, t, index = [], 1000.0, 0
    while t < end:
        origin = "server1" if index % 2 == 0 else "server2"
        if origin == "server2" and inject <= t < inject + outage:
            samples.append(v.Sample(t, False, 0, 5000.0, "", "timeout"))
        elif origin == "server2" and inject + outage <= t < restore + recover_after:
            origin = "server1"
            samples.append(v.Sample(t, True, 200, 40.0, origin))
        else:
            samples.append(v.Sample(t, True, 200, 30.0 + (index % 7), origin))
        t += 1.0 / rate
        index += 1
    return samples


def test_1_percentiles_classes_and_measured_shares():
    values = [float(i) for i in range(1, 101)]
    assert v.percentile(values, 50) == 50 and v.percentile(values, 95) == 95 and v.percentile(values, 99) == 99
    assert v.percentile([], 50) is None and v.percentile([7.0], 99) == 7.0
    rows = (
        [v.Sample(1.0 + i, True, 200, 10.0 * (i + 1), "server1") for i in range(6)]
        + [v.Sample(10.0 + i, True, 200, 20.0, "server2") for i in range(2)]
        + [v.Sample(20.0, True, 404, 5.0, "")]
        + [v.Sample(21.0, False, 502, 5.0, "")]
        + [v.Sample(22.0, False, 0, 5000.0, "", "timeout")]
        + [v.Sample(23.0, False, 0, 3.0, "", "ClientConnectorError")]
    )
    summary = v.summarize(rows)
    assert summary["http_classes"] == {"2xx": 8, "4xx": 1, "5xx": 1, "timeout": 1, "connection_error": 1}
    assert summary["failed_requests"] == 3 and summary["ratio_5xx"] == round(1 / 12, 4)
    assert summary["origins"]["server1"]["measured_share"] == 0.75 and summary["origins"]["server2"]["measured_share"] == 0.25
    assert summary["unidentified_requests"] == 4
    assert "not a configured weight" in summary["share_basis"]
    assert 5000.0 not in [summary["latency_ms"]["max"]] and summary["latency_ms"]["max"] == 60.0
    assert v.summarize([]) == {"requests": 0, "status": "INSUFFICIENT_DATA"}
    print("Test 1 (nearest-rank percentiles, HTTP classes, timeouts excluded from latency, shares measured from origin markers only) PASSED")


def test_2_failover_timeline_is_derived_from_the_request_stream():
    samples = synthetic()
    timeline = v.failover_timeline(samples, 1010.0, 1020.0, "server2")
    failed = [s for s in samples if not s.ok]
    assert timeline["failed_request_count"] == len(failed) and 5 <= len(failed) <= 8
    assert timeline["first_failed_request_at"] == failed[0].t and timeline["last_failed_request_at"] == failed[-1].t
    assert timeline["failure_detected_source"] == "first failed request"
    assert timeline["failure_detection_ms"] == round((failed[0].t - 1010.0) * 1000, 1)
    assert timeline["traffic_recovery_ms"] == round((failed[-1].t - 1010.0) * 1000, 1)
    assert timeline["first_successful_request_at"] > failed[0].t
    assert timeline["origin_removed_at"] == failed[-1].t and timeline["origin_removed_source"].startswith("request stream")
    assert timeline["served_by_failed_origin_after_removal"] is False and timeline["traffic_continued"] is True
    assert timeline["origin_restored_at"] == 1020.0
    assert timeline["recovery_detected_at"] is not None and 1.4 <= timeline["origin_recovery_ms"] / 1000 <= 1.8
    assert timeline["peak_5xx_in_window"] == 0
    assert timeline["requests_during_failure"] > 50
    assert "zero downtime is not claimed" in timeline["note"]
    operator = v.failover_timeline(samples, 1010.0, 1020.0, "server2", detected_at=1010.4, removed_at=1011.6)
    assert operator["failure_detection_ms"] == 400.0 and operator["origin_removal_ms"] == 1600.0
    assert operator["failure_detected_source"] == operator["origin_removed_source"] == "operator-supplied"
    unmarked = [v.Sample(s.t, s.ok, s.status, s.ms, "", s.error) for s in samples]
    blind = v.failover_timeline(unmarked, 1010.0, 1020.0, "server2")
    assert blind["origin_removed_at"] is None and blind["origin_removed_source"] == "NOT_OBSERVED"
    print("Test 2 (failure/removal/recovery stamps and failed-request count come from the measured stream; operator stamps are labelled; no marker = NOT_OBSERVED) PASSED")


def test_3_peak_5xx_uses_a_sliding_window_and_phases_split_correctly():
    rows = [v.Sample(100.0 + i * 0.1, False, 502, 10.0, "") for i in range(5)] + [v.Sample(110.0, False, 503, 10.0, "")]
    assert v._peak_5xx(rows, 1.0) == 5 and v._peak_5xx([], 1.0) == 0
    many = [v.Sample(i * 0.125, False, 500, 1.0, "") for i in range(20000)]
    started = time.time()
    assert v._peak_5xx(many, 1.0) == 8
    assert time.time() - started < 1.0
    samples = synthetic()
    phases = v.split_phases(samples, 1010.0, 1020.0)
    assert len(phases["before"]) + len(phases["during"]) + len(phases["after"]) == len(samples)
    assert all(s.t < 1010.0 for s in phases["before"]) and all(1010.0 <= s.t < 1020.0 for s in phases["during"])
    assert v.split_phases(samples, None, None)["during"] == []
    print("Test 3 (5xx peak in a rolling window in O(n); before/during/after phases partition the samples) PASSED")


def good_evidence():
    return {
        "origins": ["server1", "server2"],
        "checks": {key: {"status": "PASS", "evidence": f"{key} verified"} for key in (
            "rtsa_singleton", "baseline_captured", "server2_pm2", "server2_postgres", "test_hostname", "both_origins_healthy",
            "recovery_works", "rollback_works",
        )},
        "measurements": {
            "active_active": {"origins": {"server1": {"requests": 520, "measured_share": 0.52}, "server2": {"requests": 480, "measured_share": 0.48}}, "latency_ms": {"p95": 120.0}},
            "host": {"active_active": {"cpu_total_percent": {"p95": 41.0}}, "failure": {"cpu_total_percent": {"p95": 55.0}}},
            "db": {"max_active_connections": 40, "max_connections": 200},
        },
        "pool_gate": {"pool_safety": "PASS", "reasons": ["all scenarios fit the budget"]},
        "failover": {
            "server2_application": {"timeline": v.failover_timeline(synthetic(), 1010.0, 1020.0, "server2")},
            "server1_application": {"timeline": v.failover_timeline(synthetic(), 1010.0, 1020.0, "server2")},
            "server2_node": {"status": "BLOCKED", "reason": "node-level failure was not approved"},
        },
    }


def status_map(items):
    return {i.item_id: i.status for i in items}


def test_4_gate_never_invents_thresholds_or_passes_on_missing_data():
    empty = v.evaluate_gate({}, v.Thresholds())
    states = status_map(empty)
    assert list(states) == list(v.CHECKLIST_IDS) and len(states) == 17
    assert all(s in (v.INSUFFICIENT_DATA, v.BLOCKED) for s in states.values()), states
    assert states["server2_node_failure"] == v.BLOCKED
    assert v.final_status(empty) == v.FINAL_INCOMPLETE
    items = v.evaluate_gate(good_evidence(), v.Thresholds())
    states = status_map(items)
    for key in ("no_5xx_spike", "db_within_limits", "cpu_within_limits", "latency_within_threshold"):
        assert states[key] == v.THRESHOLD_NOT_DEFINED, (key, states[key])
    detail = {i.item_id: i.evidence for i in items}
    assert "none is invented" in detail["cpu_within_limits"] and "measured" in detail["cpu_within_limits"]
    assert states["traffic_both_origins"] == v.PASS and states["server2_app_failure"] == v.PASS
    assert states["server2_node_failure"] == v.BLOCKED
    assert v.final_status(items) == v.FINAL_INCOMPLETE
    print("Test 4 (no evidence = INSUFFICIENT_DATA/BLOCKED; measured values without a defined threshold = THRESHOLD_NOT_DEFINED; the gate is never STABLE then) PASSED")


def test_5_gate_with_defined_thresholds_passes_or_fails_on_the_measurement():
    evidence = good_evidence()
    evidence["failover"]["server2_node"] = {"timeline": v.failover_timeline(synthetic(), 1010.0, 1020.0, "server2")}
    base = v.Thresholds()
    thresholds = v.thresholds_from_evidence(base, {
        "max_5xx_ratio": {"value": 0.05, "source": "agreed test SLO"},
        "max_p95_latency_ms": {"value": 800, "source": "agreed test SLO"},
        "cpu_percent": {"value": 70, "source": "ops runbook"},
        "db_connection_ratio": {"value": 0.8, "source": "ops runbook"},
        "max_p99_latency_ms": {"value": 5, "source": ""},
    })
    assert thresholds.max_p99_latency_ms.value is None, "a threshold without a stated source is not accepted"
    items = v.evaluate_gate(evidence, thresholds)
    assert all(i.status == v.PASS for i in items), [i.to_dict() for i in items if i.status != v.PASS]
    assert v.final_status(items) == v.FINAL_STABLE
    evidence["measurements"]["host"]["failure"]["cpu_total_percent"]["p95"] = 91.0
    evidence["measurements"]["db"]["max_active_connections"] = 190
    evidence["measurements"]["active_active"]["origins"]["server2"]["requests"] = 0
    items = v.evaluate_gate(evidence, thresholds)
    states = status_map(items)
    assert states["cpu_within_limits"] == v.FAIL and states["db_within_limits"] == v.FAIL and states["traffic_both_origins"] == v.FAIL
    assert v.final_status(items) == v.FINAL_NOT_STABLE
    print("Test 5 (with sourced thresholds the same measurements PASS; a measured breach or an origin with no traffic is FAIL and the gate is NOT_STABLE) PASSED")


def test_6_failover_scenarios_are_judged_on_evidence_not_assumed():
    evidence = good_evidence()
    broken = v.failover_timeline([s for s in synthetic() if not (1010.0 <= s.t < 1020.0) or not s.ok], 1010.0, 1020.0, "server2")
    assert broken["traffic_continued"] is False or broken["requests_during_failure"] < 100
    still_serving = [v.Sample(s.t, s.ok, s.status, s.ms, s.origin, s.error) for s in synthetic()]
    still_serving += [v.Sample(1015.0, True, 200, 20.0, "server2")]
    leaking = v.failover_timeline(still_serving, 1010.0, 1020.0, "server2", removed_at=1012.0)
    assert leaking["served_by_failed_origin_after_removal"] is True
    evidence["failover"]["server2_application"] = {"timeline": leaking}
    states = status_map(v.evaluate_gate(evidence, v.Thresholds()))
    assert states["server2_app_failure"] == v.FAIL
    evidence["failover"]["server1_application"] = {"timeline": {"requests_during_failure": 0}}
    assert status_map(v.evaluate_gate(evidence, v.Thresholds()))["server1_app_failure"] == v.INSUFFICIENT_DATA
    evidence["failover"]["server1_application"] = {"status": "BLOCKED", "reason": "Server1 PostgreSQL is authoritative: full-node shutdown not approved"}
    gate = {i.item_id: i for i in v.evaluate_gate(evidence, v.Thresholds())}
    assert gate["server1_app_failure"].status == v.BLOCKED and "not approved" in gate["server1_app_failure"].evidence
    print("Test 6 (a failed origin that keeps answering after removal is FAIL, a scenario with no requests is INSUFFICIENT_DATA, an unapproved scenario stays BLOCKED) PASSED")


def test_7_thresholds_come_from_explicit_project_config_only():
    with open(os.path.join(_REPO_ROOT, "config", "config.yaml")) as handle:
        raw = yaml.safe_load(handle)
    thresholds = v.thresholds_from_config(raw)
    assert thresholds.cpu_percent.value == raw["modules"]["health_monitor"]["cpu_alert_threshold"]
    assert thresholds.cpu_percent.source == "config:modules.health_monitor.cpu_alert_threshold"
    assert thresholds.db_connection_ratio.value == raw["load_balancing"]["safety"]["db_connection_budget_ratio"]
    assert thresholds.max_5xx_ratio.value is None and thresholds.max_p95_latency_ms.value is None, "the project defines no 5xx or latency SLO"
    assert v.thresholds_from_config({}).cpu_percent.value is None
    assert v.thresholds_from_config({"modules": {"health_monitor": {"cpu_alert_threshold": True}}}).cpu_percent.value is None
    print("Test 7 (CPU/memory/DB thresholds are read only from keys the project config defines; 5xx and latency stay undefined instead of invented) PASSED")


def test_8_report_redacts_secrets_and_states_no_deploy():
    evidence = good_evidence()
    evidence.update({
        "server_identity": "server2", "hostname": "lb-test.example.invalid", "origins": ["server1", "server2"],
        "cloudflare": {"pool_ids": ["abc"], "api_token": "cf-super-secret-token-value", "note": "Bearer abcdefghijklmnop012345"},
        "db_architecture": "PRIMARY_SHARED postgresql://app_user:SuperSecretPw@10.0.0.5:5432/appdb",
        "pm2": {"apps": ["disdik"], "DB_PASSWORD": "hunter2hunter2"},
    })
    report = v.build_report(evidence, v.Thresholds(), generated_at=1790000000.0)
    text = v.render_markdown(report) + json.dumps(report)
    for secret in ("cf-super-secret-token-value", "SuperSecretPw", "hunter2hunter2", "abcdefghijklmnop012345"):
        assert secret not in text, secret
    assert "[REDACTED]" in text and "app_user" not in text
    assert report["production_deploy"] == "NO" and "PRODUCTION_DEPLOY=NO" in v.render_markdown(report)
    assert report["facts"]["bgp_prerequisites"] == "NOT_OBSERVED" and report["facts"]["nginx_upstreams"] == "NOT_OBSERVED"
    assert report["final_factual_status"] == v.FINAL_INCOMPLETE and "server2_node_failure" in report["blocked_or_missing"]
    assert report["thresholds"]["max_5xx_ratio"]["source"] == "NOT_DEFINED"
    print("Test 8 (secrets, DSN credentials and bearer tokens never reach the report; missing facts say NOT_OBSERVED; PRODUCTION_DEPLOY=NO) PASSED")


class Origin(BaseHTTPRequestHandler):
    counter = {"n": 0, "redirect_target_hits": 0}
    lock = threading.Lock()

    def do_GET(self):
        with Origin.lock:
            Origin.counter["n"] += 1
            index = Origin.counter["n"]
        if self.path == "/slow":
            time.sleep(2.0)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/target")
            self.end_headers()
            return
        if self.path == "/target":
            with Origin.lock:
                Origin.counter["redirect_target_hits"] += 1
        body = json.dumps({"status": "ok", "server_identity": "server1" if index % 2 else "server2"}).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-RTSA-Origin", "server1" if index % 2 else "server2")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def log_message(self, *args):
        return None


def serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_9_probe_measures_origins_and_is_bounded_and_read_only():
    server = serve()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        samples = asyncio.run(v.probe(base + "/", 3.0, 10.0, origin_header="X-RTSA-Origin", allow_local=True))
        assert 25 <= len(samples) <= 33, len(samples)
        summary = v.summarize(samples)
        assert set(summary["origins"]) == {"server1", "server2"} and summary["failed_requests"] == 0
        assert all(0.3 < o["measured_share"] < 0.7 for o in summary["origins"].values())
        by_json = asyncio.run(v.probe(base + "/", 1.0, 5.0, origin_field="server_identity", allow_local=True))
        assert {s.origin for s in by_json} <= {"server1", "server2"} and all(s.origin for s in by_json)
        started = time.time()
        capped = asyncio.run(v.probe(base + "/", 2.0, 1000.0, allow_local=True))
        assert len(capped) <= int(v.MAX_RATE * 2.0) + 3 and time.time() - started < 8.0
        timed = asyncio.run(v.probe(base + "/slow", 1.0, 2.0, timeout=0.5, allow_local=True))
        assert timed and all(s.error == "timeout" and not s.ok for s in timed)
        before = Origin.counter["redirect_target_hits"]
        redirected = asyncio.run(v.probe(base + "/redirect", 1.0, 3.0, allow_local=True))
        assert all(s.status == 302 for s in redirected) and Origin.counter["redirect_target_hits"] == before
    finally:
        server.shutdown()
    refused = {}
    for url in ("ftp://example.com/", "http://user:pw@example.com/", "http://127.0.0.1/", "http://10.0.0.5/", "http://169.254.169.254/latest", "http:///x"):
        target, error = v.validate_probe_url(url)
        assert target is None and error, url
        refused[url] = error
    source = open(os.path.join(_REPO_ROOT, "core", "lb_validation.py")).read()
    for forbidden in ("session.post", "session.put", "session.delete", "session.patch", "allow_redirects=True", "shell=True", "os.system", "subprocess"):
        assert forbidden not in source, forbidden
    print("Test 9 (probe: GET only, no redirects, rate/duration/timeout capped, origin from header or JSON, loopback/private/credential URLs refused) PASSED")


def test_10_host_sampler_is_bounded_and_summarized():
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "host.jsonl")
        rows = v.sample_host(2.5, 0.1, out)
        assert 2 <= len(rows) <= 3, "the interval is clamped to at least one second"
        for key in ("cpu_total", "cpu_cores", "load1", "mem_percent", "swap_percent", "net_recv_bps", "disk_read_bps", "process_count"):
            assert key in rows[0], key
        summary = v.host_summary(v.load_rows(out))
        assert summary["samples"] == len(rows) and summary["cpu_total_percent"]["max"] is not None
        assert v.host_summary([]) == {"status": "INSUFFICIENT_DATA"}
    print("Test 10 (host CPU/per-core/load/memory/swap/network/disk sampler: interval clamped, JSONL written, summary computed, empty = INSUFFICIENT_DATA) PASSED")


def test_11_cli_analyze_gate_report_and_refusal():
    with tempfile.TemporaryDirectory() as tmp:
        samples_path = os.path.join(tmp, "samples.jsonl")
        with open(samples_path, "w") as handle:
            for sample in synthetic():
                handle.write(json.dumps(sample.to_dict()) + "\n")
        run = lambda *args: subprocess.run([sys.executable, "-m", "core.lb_validation", *args], cwd=_REPO_ROOT, capture_output=True, text=True, timeout=60)
        out = run("analyze", "--samples", samples_path, "--inject-at", "1010", "--restore-at", "1020", "--failed-origin", "server2")
        assert out.returncode == 0
        data = json.loads(out.stdout)
        assert data["overall"]["requests"] > 250 and data["timeline"]["failed_request_count"] > 0 and set(data["phases"]) == {"before", "during", "after"}
        evidence_path = os.path.join(tmp, "evidence.json")
        with open(evidence_path, "w") as handle:
            json.dump({"checks": {}}, handle)
        gate = run("gate", "--evidence", evidence_path)
        assert gate.returncode == 2 and json.loads(gate.stdout)["final_factual_status"] == "INCOMPLETE"
        with_config = run("gate", "--evidence", evidence_path, "--rtsa-config", os.path.join(_REPO_ROOT, "config", "config.yaml"))
        assert with_config.returncode == 2
        report_path = os.path.join(tmp, "report.md")
        made = run("report", "--evidence", evidence_path, "--out", report_path)
        assert made.returncode == 0 and "PRODUCTION_DEPLOY=NO" in open(report_path).read()
        refused = run("probe", "--url", "http://10.1.2.3/", "--out", os.path.join(tmp, "x.jsonl"), "--duration", "1")
        assert refused.returncode == 2 and "refused" in refused.stderr and not os.path.exists(os.path.join(tmp, "x.jsonl"))
    print("Test 11 (CLI: analyze prints the timeline, gate exits 2 on incomplete evidence, report writes PRODUCTION_DEPLOY=NO, a private probe target is refused with exit 2) PASSED")


def main():
    test_1_percentiles_classes_and_measured_shares()
    test_2_failover_timeline_is_derived_from_the_request_stream()
    test_3_peak_5xx_uses_a_sliding_window_and_phases_split_correctly()
    test_4_gate_never_invents_thresholds_or_passes_on_missing_data()
    test_5_gate_with_defined_thresholds_passes_or_fails_on_the_measurement()
    test_6_failover_scenarios_are_judged_on_evidence_not_assumed()
    test_7_thresholds_come_from_explicit_project_config_only()
    test_8_report_redacts_secrets_and_states_no_deploy()
    test_9_probe_measures_origins_and_is_bounded_and_read_only()
    test_10_host_sampler_is_bounded_and_summarized()
    test_11_cli_analyze_gate_report_and_refusal()
    print("\nALL LB VALIDATION TESTS PASSED")


if __name__ == "__main__":
    main()
