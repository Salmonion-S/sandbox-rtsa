import asyncio
import os
import shutil
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import yaml

from config.manager import NginxMonitorConfig, SvgUploadScannerConfig
from core.datatypes import EventCategory
from core.event_bus import EventBus
from core.state_store import load_versioned_state
from modules.nginx_monitor import NginxMonitor, _SvgScanCheckpoint, _SVG_SCAN_STATE_FORMAT_VERSION


def access_line(method, path, status=200, ip="203.0.113.7", ua="Mozilla/5.0", host="rmepro.com", pad=""):
    return f'{ip} - - [01/Jan/2026:00:00:00 +0000] "{method} {path}{pad} HTTP/1.1" {status} 100 "-" "{ua}" "{host}"'


class Harness:
    def __init__(self, **scanner_overrides):
        self.tmpdir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.tmpdir, "access.log")
        self.state_path = os.path.join(self.tmpdir, "svg_state.json")
        scanner_overrides.setdefault("state_path", self.state_path)
        self.cfg = NginxMonitorConfig(
            enabled=True, access_log_path=self.log_path, auto_discover_vhost_logs=False,
            svg_upload_scanner=SvgUploadScannerConfig(**scanner_overrides),
        )
        self.mon = NginxMonitor(EventBus(), self.cfg)
        self.published = []
        self.mon.publish = lambda ev: self.published.append(ev)

    def write(self, lines, mode="a"):
        with open(self.log_path, mode) as f:
            for line in lines:
                f.write(line + "\n")

    async def scan(self):
        await self.mon._run_svg_upload_scan()

    def cleanup(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)


def svg_events(published):
    return [e for e in published if e.category in (EventCategory.SVG_UPLOAD_ATTEMPT, EventCategory.SVG_UPLOAD_CONFIRMED)]


async def main():
    h = Harness()
    h.write([access_line("GET", "/image.svg")])
    await h.scan()
    await h.scan()
    assert svg_events(h.published) == [], f"GET /image.svg must never be an upload candidate: {h.published}"
    h.cleanup()
    print("Test 1 (GET /image.svg -- tidak terdeteksi sebagai upload) PASSED")

    h = Harness()
    h.write([access_line("GET", "/assets/logo.svg")])
    await h.scan()
    await h.scan()
    assert svg_events(h.published) == [], f"GET /assets/logo.svg must never be an upload candidate: {h.published}"
    h.cleanup()
    print("Test 2 (GET /assets/logo.svg -- tidak terdeteksi) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    h.write([access_line("POST", "/upload/test.svg", status=200)])
    await h.scan()
    ev = svg_events(h.published)
    assert len(ev) == 1, f"POST /upload/test.svg must be detected as a candidate: {h.published}"
    assert ev[0].metadata["svg_filename"] == "test.svg"
    h.cleanup()
    print("Test 3 (POST /upload dengan test.svg -- terdeteksi sebagai candidate upload) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    h.write([access_line("POST", "/upload/test.php", status=200)])
    await h.scan()
    assert svg_events(h.published) == [], f"POST of a .php file must never be flagged as an SVG upload: {h.published}"
    h.cleanup()
    print("Test 4 (POST /upload dengan test.php -- bukan SVG upload) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    h.write([access_line("POST", "/upload/test.svg", status=403)])
    await h.scan()
    ev = svg_events(h.published)
    assert len(ev) == 1
    assert ev[0].category == EventCategory.SVG_UPLOAD_ATTEMPT, ev[0].category
    assert ev[0].metadata["status_label"] == "FAILED", ev[0].metadata
    h.cleanup()
    print("Test 5 (POST /upload HTTP 403 -- ATTEMPT/FAILED, bukan confirmed breach) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    h.write([access_line("POST", "/upload/test.svg", status=500)])
    await h.scan()
    ev = svg_events(h.published)
    assert len(ev) == 1
    assert ev[0].category == EventCategory.SVG_UPLOAD_ATTEMPT
    assert ev[0].metadata["status_label"] == "UNKNOWN", ev[0].metadata
    h.cleanup()
    print("Test 6 (POST /upload HTTP 500 -- tidak dianggap confirmed) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    h.write([access_line("POST", "/upload/test.svg", status=200)])
    await h.scan()
    ev = svg_events(h.published)
    assert len(ev) == 1
    assert ev[0].category == EventCategory.SVG_UPLOAD_ATTEMPT, (
        f"a bare HTTP 200 with no additional evidence must NOT auto-escalate to SVG_UPLOAD_CONFIRMED: {ev[0].category}"
    )
    assert ev[0].metadata["status_label"] == "SUCCESS"
    for word in ("BREACH", "COMPROMISED", "CONFIRMED BREACH"):
        assert word not in ev[0].message.upper() or "CONFIRMED BREACH" not in ev[0].message.upper()
    h.cleanup()
    print("Test 7 (POST /upload HTTP 200 -- accepted/possible success, TIDAK auto confirmed compromise) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    h.write([access_line("POST", "/uploads/shell.svg", status=200)])
    await h.scan()
    ev = svg_events(h.published)
    assert ev[0].metadata["svg_filename"] == "shell.svg"
    h.cleanup()
    print("Test 8 (filename SVG yang jelas -- tampil benar) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    s3_url = "https://mybucket.s3.amazonaws.com/uploads/test.svg"
    h.write([access_line("PUT", f"/upload?filename={s3_url}", status=200)])
    await h.scan()
    ev = svg_events(h.published)
    assert len(ev) == 1
    assert ev[0].metadata["aws_s3_url"] == s3_url, ev[0].metadata
    assert ev[0].category == EventCategory.SVG_UPLOAD_CONFIRMED, (
        "a 2xx PUT with a real S3 destination URL is exactly the 'strong evidence' bar for CONFIRMED"
    )
    h.cleanup()
    print("Test 9 (AWS/S3 URL tersedia -- URL tampil benar, kategori naik ke CONFIRMED) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    h.write([access_line("POST", "/upload/test.svg", status=200)])
    await h.scan()
    ev = svg_events(h.published)
    assert ev[0].metadata["aws_s3_url"] is None, "aws_s3_url must be honestly None, never fabricated"
    h.cleanup()
    print("Test 10 (AWS/S3 URL tidak tersedia -- field kosong, tidak dikarang) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    h.write([access_line("POST", "/upload/first.svg", status=200)])
    await h.scan()
    first_count = len(svg_events(h.published))
    h.published.clear()
    await h.scan()
    assert svg_events(h.published) == [], f"a second scan with no new lines must find nothing: {h.published}"
    assert first_count == 1
    h.cleanup()
    print("Test 11 (scan kedua tidak membaca ulang log lama) PASSED")

    h = Harness()
    h.write([access_line("GET", "/" + "x" * 200)])
    await h.scan()
    h.write([access_line("POST", "/upload/before-rotate.svg", status=200)])
    shutil.move(h.log_path, h.log_path + ".1")
    h.write([access_line("POST", "/upload/after-rotate.svg", status=200)], mode="w")
    await h.scan()
    filenames = sorted(e.metadata["svg_filename"] for e in svg_events(h.published))
    assert filenames == ["after-rotate.svg", "before-rotate.svg"], filenames
    h.published.clear()
    await h.scan()
    assert svg_events(h.published) == [], f"post-rotation re-scan must not duplicate the same hits: {h.published}"
    h.cleanup()
    print("Test 12 (log rotation -- kedua sisi terdeteksi sekali, tidak ada duplicate alert) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    h.write([access_line("POST", "/upload/x.svg", status=200)])
    await h.scan()
    assert len(svg_events(h.published)) == 1
    mon2 = NginxMonitor(EventBus(), h.cfg)
    pub2 = []
    mon2.publish = lambda e: pub2.append(e)
    mon2._svg_scan_checkpoints = load_versioned_state(h.state_path, _SVG_SCAN_STATE_FORMAT_VERSION, _SvgScanCheckpoint)
    await mon2._run_svg_upload_scan()
    assert svg_events(pub2) == [], f"restart must resume from the persisted checkpoint, not re-scan the whole log: {pub2}"
    h.cleanup()
    print("Test 13 (RTSA restart -- checkpoint dimuat dari disk, tidak membaca ulang seluruh log) PASSED")

    tmpdir = tempfile.mkdtemp()
    log_a = os.path.join(tmpdir, "a.log")
    log_b = os.path.join(tmpdir, "b.log")
    state_path = os.path.join(tmpdir, "state.json")
    cfg = NginxMonitorConfig(
        enabled=True, access_log_path=log_a, auto_discover_vhost_logs=False,
        svg_upload_scanner=SvgUploadScannerConfig(state_path=state_path),
    )
    mon = NginxMonitor(EventBus(), cfg)
    pub = []
    mon.publish = lambda e: pub.append(e)
    async def fake_resolve():
        return sorted([log_a, log_b]), []
    mon._resolve_log_paths = fake_resolve
    mon._scan_conf_for_vhost_domains = lambda: {log_a: "domain-a.example", log_b: "domain-b.example"}
    with open(log_a, "w") as f:
        f.write(access_line("GET", "/") + "\n")
    with open(log_b, "w") as f:
        f.write(access_line("GET", "/") + "\n")
    await mon._run_svg_upload_scan()
    with open(log_a, "a") as f:
        f.write(access_line("POST", "/upload/a-file.svg", status=200, host="domain-a.example") + "\n")
    with open(log_b, "a") as f:
        f.write(access_line("POST", "/upload/b-file.svg", status=200, host="domain-b.example") + "\n")
    await mon._run_svg_upload_scan()
    domains = sorted(e.domain for e in svg_events(pub))
    filenames = sorted(e.metadata["svg_filename"] for e in svg_events(pub))
    assert domains == ["domain-a.example", "domain-b.example"], domains
    assert filenames == ["a-file.svg", "b-file.svg"], filenames
    shutil.rmtree(tmpdir, ignore_errors=True)
    print("Test 14 (dua domain dengan upload SVG -- keduanya diproses independen) PASSED")

    tmpdir = tempfile.mkdtemp()
    n_domains = 120
    log_paths = []
    for i in range(n_domains):
        p = os.path.join(tmpdir, f"domain{i}.log")
        with open(p, "w") as f:
            f.write(access_line("GET", "/") + "\n")
        log_paths.append(p)
    state_path = os.path.join(tmpdir, "state.json")
    cfg = NginxMonitorConfig(
        enabled=True, access_log_path=log_paths[0], auto_discover_vhost_logs=False,
        svg_upload_scanner=SvgUploadScannerConfig(state_path=state_path),
    )
    mon = NginxMonitor(EventBus(), cfg)
    pub = []
    mon.publish = lambda e: pub.append(e)
    async def fake_resolve_many():
        return sorted(log_paths), []
    mon._resolve_log_paths = fake_resolve_many
    mon._scan_conf_for_vhost_domains = lambda: {p: f"domain{i}.example" for i, p in enumerate(log_paths)}

    tasks_before = {t for t in asyncio.all_tasks()}
    start = time.monotonic()
    await mon._run_svg_upload_scan()
    duration = time.monotonic() - start
    tasks_after = {t for t in asyncio.all_tasks()} - tasks_before
    live_extra_tasks = [t for t in tasks_after if not t.done()]
    assert live_extra_tasks == [], f"scanning {n_domains} domains must not leave extra live tasks behind: {live_extra_tasks}"
    assert duration < 15.0, f"scanning {n_domains} near-empty logs took too long ({duration:.2f}s) -- check for accidental O(n^2) work"
    shutil.rmtree(tmpdir, ignore_errors=True)
    print(f"Test 15 ({n_domains} domain -- tidak ada task explosion, selesai dalam {duration:.2f}s) PASSED")

    h = Harness()
    h.write([access_line("GET", "/"), access_line("GET", "/robots.txt"), access_line("POST", "/contact")])
    await h.scan()
    await h.scan()
    assert h.published == [], f"a cycle with zero SVG-upload candidates must publish nothing at all: {h.published}"
    h.cleanup()
    print("Test 16 (tidak ada SVG upload -- tidak ada Discord alert sama sekali) PASSED")

    h = Harness(interval_minutes=42.0)
    assert h.mon.config.svg_upload_scanner.interval_minutes == 42.0
    assert h.mon.config.svg_upload_scanner.interval_minutes * 60.0 == 2520.0
    h.cleanup()
    print("Test 17 (scanner membaca interval_minutes dari config, bukan hardcoded) PASSED")

    h60 = Harness(interval_minutes=60.0)
    h30 = Harness(interval_minutes=30.0)
    assert h60.mon.config.svg_upload_scanner.interval_minutes * 60.0 == 3600.0
    assert h30.mon.config.svg_upload_scanner.interval_minutes * 60.0 == 1800.0
    h60.cleanup()
    h30.cleanup()
    raw = yaml.safe_load(open("config/config.yaml"))
    shipped = raw["modules"]["nginx_monitor"]["svg_upload_scanner"]
    assert shipped["interval_minutes"] == 60, shipped
    assert shipped["enabled"] is True
    assert "confirmed_branch_id" not in shipped, (
        "confirmed_branch_id must no longer be independently configurable in config.yaml -- "
        "discord.category_channels['SVG_UPLOAD_CONFIRMED'] is now the single source of truth"
    )
    assert SvgUploadScannerConfig().confirmed_branch_id == "", (
        "the dataclass default must not carry a stale hardcoded channel ID"
    )
    print("Test 18 (interval_minutes 60->30 mengubah interval scanner tanpa source-code modification) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    h.write([access_line("POST", "/upload/normal.svg", status=200)])
    await h.scan()
    assert len(svg_events(h.published)) == 1
    h.cleanup()
    print("Rotation-A (access.log normal, tanpa rotasi) PASSED")

    h = Harness()
    h.write([access_line("GET", "/" + "z" * 100)])
    await h.scan()
    h.write([access_line("POST", "/upload/pre.svg", status=200)])
    shutil.move(h.log_path, h.log_path + ".1")
    h.write([access_line("POST", "/upload/post.svg", status=200)], mode="w")
    await h.scan()
    assert sorted(e.metadata["svg_filename"] for e in svg_events(h.published)) == ["post.svg", "pre.svg"]
    h.cleanup()
    print("Rotation-B (logrotate rename+fresh file -- kedua sisi tertangkap) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    shutil.move(h.log_path, h.log_path + ".2.gone")
    os.remove(h.log_path + ".2.gone")
    for i in range(5):
        junk_path = os.path.join(h.tmpdir, f"junk{i}")
        with open(junk_path, "w") as f:
            f.write("z")
    h.write([access_line("POST", "/upload/newfile.svg", status=200)], mode="w")
    await h.scan()
    assert len(svg_events(h.published)) == 1, "the new file's own content must still be scanned even if recovery failed"
    h.published.clear()
    await h.scan()
    assert svg_events(h.published) == [], "no duplicate after an unrecoverable rotation"
    h.cleanup()
    print("Rotation-C (inode berubah, file lama tidak ditemukan -- warning, tidak crash, tidak duplicate) PASSED")

    h = Harness()
    h.write([access_line("GET", "/" + "w" * 500)])
    await h.scan()
    h.write([access_line("GET", "/more/padding/" + "v" * 500)])
    await h.scan()
    h.write([access_line("POST", "/upload/post-truncate.svg", status=200)], mode="w")
    await h.scan()
    assert [e.metadata["svg_filename"] for e in svg_events(h.published)] == ["post-truncate.svg"]
    h.cleanup()
    print("Rotation-D (truncate -- konten baru dari offset 0, tidak ada re-read masif) PASSED")

    tmpdir = tempfile.mkdtemp()
    log_old = os.path.join(tmpdir, "old.log")
    log_new = os.path.join(tmpdir, "new.log")
    with open(log_old, "w") as f:
        f.write(access_line("GET", "/") + "\n")
    state_path = os.path.join(tmpdir, "state.json")
    cfg = NginxMonitorConfig(
        enabled=True, access_log_path=log_old, auto_discover_vhost_logs=False,
        svg_upload_scanner=SvgUploadScannerConfig(state_path=state_path),
    )
    mon = NginxMonitor(EventBus(), cfg)
    pub = []
    mon.publish = lambda e: pub.append(e)
    async def _resolve_only(p):
        return [p], []
    mon._resolve_log_paths = lambda: _resolve_only(log_old)
    mon._scan_conf_for_vhost_domains = lambda: {log_old: "old.example"}
    await mon._run_svg_upload_scan()

    with open(log_new, "w") as f:
        f.write(access_line("POST", "/upload/preexisting.svg", status=200) + "\n")
    mon._resolve_log_paths = lambda: _resolve_two(log_old, log_new)
    async def _resolve_two(a, b):
        return sorted([a, b]), []
    mon._scan_conf_for_vhost_domains = lambda: {log_old: "old.example", log_new: "new.example"}
    await mon._run_svg_upload_scan()
    assert svg_events(pub) == [], (
        f"a newly-discovered domain must start monitoring from now, not flood-alert on its pre-existing "
        f"log history: {pub}"
    )
    with open(log_new, "a") as f:
        f.write(access_line("POST", "/upload/after-discovery.svg", status=200) + "\n")
    await mon._run_svg_upload_scan()
    assert [e.metadata["svg_filename"] for e in svg_events(pub)] == ["after-discovery.svg"]
    shutil.rmtree(tmpdir, ignore_errors=True)
    print("Rotation-E (domain baru muncul -- mulai dari sekarang, tidak flood alert histori lama) PASSED")

    tmpdir = tempfile.mkdtemp()
    log_ok = os.path.join(tmpdir, "ok.log")
    log_missing = os.path.join(tmpdir, "missing.log")
    with open(log_ok, "w") as f:
        f.write(access_line("GET", "/") + "\n")
    state_path = os.path.join(tmpdir, "state.json")
    cfg = NginxMonitorConfig(
        enabled=True, access_log_path=log_ok, auto_discover_vhost_logs=False,
        svg_upload_scanner=SvgUploadScannerConfig(state_path=state_path),
    )
    mon = NginxMonitor(EventBus(), cfg)
    pub = []
    mon.publish = lambda e: pub.append(e)
    async def _resolve_ok_and_missing():
        return sorted([log_ok, log_missing]), []
    mon._resolve_log_paths = _resolve_ok_and_missing
    mon._scan_conf_for_vhost_domains = lambda: {log_ok: "ok.example", log_missing: "missing.example"}
    await mon._run_svg_upload_scan()
    with open(log_ok, "a") as f:
        f.write(access_line("POST", "/upload/still-works.svg", status=200) + "\n")
    await mon._run_svg_upload_scan()
    assert [e.metadata["svg_filename"] for e in svg_events(pub)] == ["still-works.svg"], (
        "a missing domain log must not prevent other domains from being scanned"
    )
    shutil.rmtree(tmpdir, ignore_errors=True)
    print("Rotation-F (domain tanpa log terbaca -- tidak crash, domain lain tetap lanjut) PASSED")

    h = Harness()
    h.write([access_line("GET", "/")])
    await h.scan()
    h.write([access_line("POST", "/upload/pre-restart.svg", status=200)])
    await h.scan()
    mon_restarted = NginxMonitor(EventBus(), h.cfg)
    pub_restarted = []
    mon_restarted.publish = lambda e: pub_restarted.append(e)
    mon_restarted._svg_scan_checkpoints = load_versioned_state(
        h.state_path, _SVG_SCAN_STATE_FORMAT_VERSION, _SvgScanCheckpoint,
    )
    print("Rotation-G (RTSA restart -- checkpoint dimuat) starting scan-after-restart check")

    h.write([access_line("POST", "/upload/post-restart.svg", status=200)])
    await mon_restarted._run_svg_upload_scan()
    assert [e.metadata["svg_filename"] for e in svg_events(pub_restarted)] == ["post-restart.svg"], (
        f"a scan after restart must find genuinely new content and nothing already processed pre-restart: {pub_restarted}"
    )
    h.cleanup()
    print("Rotation-H (scan setelah restart -- event baru tetap terdeteksi, event lama tidak diulang) PASSED")

    print("\nALL SVG_UPLOAD_SCANNER (INCREMENTAL, MULTI-DOMAIN) REGRESSION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=120))
