import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import shutil
import tempfile
from pathlib import Path

from config.manager import HtmlInjectionDetectorConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from modules.html_injection_detector import HtmlInjectionDetector

BASE = os.path.join(tempfile.gettempdir(), "rtsa_html_injection_test")

CLEAN_HOMEPAGE = """\
<!DOCTYPE html>
<html>
<head><title>My Site</title></head>
<body>
  <h1>Welcome</h1>
  <script src="/assets/app.js"></script>
</body>
</html>
"""

CLEAN_HOMEPAGE_REFORMATTED = """\
<!DOCTYPE html>
<html>
<head>
  <title>My Site</title>
</head>
<body>
  <h1>Welcome to my site!</h1>
  <script src="/assets/app.js"></script>
</body>
</html>
"""

HIDDEN_IFRAME_INJECTION = """\
<!DOCTYPE html>
<html>
<head><title>My Site</title></head>
<body>
  <h1>Welcome</h1>
  <script src="/assets/app.js"></script>
  <iframe src="http://evil.example/payload" style="display:none"></iframe>
</body>
</html>
"""

EXTERNAL_SCRIPT_INJECTION = """\
<!DOCTYPE html>
<html>
<head><title>My Site</title></head>
<body>
  <h1>Welcome</h1>
  <script src="/assets/app.js"></script>
  <script src="http://evil.example/malicious.js"></script>
</body>
</html>
"""

META_REFRESH_INJECTION = """\
<!DOCTYPE html>
<html>
<head>
  <title>My Site</title>
  <meta http-equiv="refresh" content="0;url=http://evil.example/phish">
</head>
<body>
  <h1>Welcome</h1>
  <script src="/assets/app.js"></script>
</body>
</html>
"""

NON_ENTRYPOINT_HTML = """\
<!DOCTYPE html>
<html><body><iframe src="http://evil.example" style="display:none"></iframe></body></html>
"""


def make_detector(baseline_path, min_confidence=20):
    bus = EventBus()
    config = HtmlInjectionDetectorConfig(
        enabled=True,
        min_confidence_to_report=min_confidence,
        baseline_state_path=str(baseline_path),
    )
    detector = HtmlInjectionDetector(bus, config)
    detector._baseline = {}
    return detector


def make_event(path, project="testproject", change_type="modified"):
    return BaseEvent(
        source_module="file_integrity_detector",
        category=EventCategory.FILE_INTEGRITY_CHANGE,
        severity=Severity.INFO,
        message="test",
        metadata={
            "target_class": "configs",
            "change_type": change_type,
            "path": path,
            "project": project,
        },
    )


async def main():
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)

    published = []

    project_dir = Path(BASE) / "s1"
    project_dir.mkdir(parents=True)
    index_path = project_dir / "index.html"
    index_path.write_text(CLEAN_HOMEPAGE, encoding="utf-8")
    detector = make_detector(Path(BASE) / "s1_baseline.json")
    detector.publish = lambda ev: published.append(ev)
    await detector._on_file_changed(make_event(str(index_path), change_type="created"))
    assert not published, f"first-ever scan must not publish anything: {published}"
    assert str(index_path) in detector._baseline
    print("Scenario 1 (first-ever scan silently baselines, zero alerts) PASSED")

    published.clear()
    index_path.write_text(CLEAN_HOMEPAGE_REFORMATTED, encoding="utf-8")
    await detector._on_file_changed(make_event(str(index_path)))
    assert not published, f"ordinary formatting/content change must not become CRITICAL: {published}"
    print("Scenario 2 (normal formatting change does not alert) PASSED")

    published.clear()
    index_path.write_text(HIDDEN_IFRAME_INJECTION, encoding="utf-8")
    await detector._on_file_changed(make_event(str(index_path)))
    assert len(published) == 1, f"a genuinely new injection signature must alert: {published}"
    ev = published[0]
    assert "hidden_iframe" in ev.metadata["evidence"], ev.metadata
    assert ev.metadata["confidence"] >= 20
    assert ev.metadata["project"] == "testproject"
    assert ev.metadata["related_file"] == str(index_path)
    print("Scenario 3 (new hidden-iframe signature triggers alert with evidence) PASSED")

    published.clear()
    index_path.write_text(HIDDEN_IFRAME_INJECTION, encoding="utf-8")
    await detector._on_file_changed(make_event(str(index_path)))
    assert not published, f"an already-baselined signature must not re-alert on every scan: {published}"
    print("Scenario 4 (repeat of already-known signature does not re-alert) PASSED")

    published.clear()
    index_path.write_text(META_REFRESH_INJECTION, encoding="utf-8")
    await detector._on_file_changed(make_event(str(index_path)))
    assert len(published) == 1, f"a second, distinct new signature must still alert: {published}"
    assert "meta_refresh_redirect" in published[0].metadata["evidence"]
    print("Scenario 5 (second distinct new signature alerts independently) PASSED")

    published.clear()
    index_path.write_text(EXTERNAL_SCRIPT_INJECTION, encoding="utf-8")
    await detector._on_file_changed(make_event(str(index_path)))
    assert not published, (
        f"a single low-weight external_script_tag signal alone must be suppressed "
        f"below the reporting threshold, not treated as a confirmed injection: {published}"
    )
    print("Scenario 5b (lone low-signal external_script_tag suppressed below threshold) PASSED")

    published.clear()
    other_dir = Path(BASE) / "s6"
    other_dir.mkdir(parents=True)
    other_html = other_dir / "about.html"
    other_html.write_text(NON_ENTRYPOINT_HTML, encoding="utf-8")
    detector6 = make_detector(Path(BASE) / "s6_baseline.json")
    detector6.publish = lambda ev: published.append(ev)
    await detector6._on_file_changed(make_event(str(other_html)))
    assert not published, f"a non-entrypoint HTML file must never be scanned: {published}"
    assert str(other_html) not in detector6._baseline
    print("Scenario 6 (non-entrypoint .html file is ignored) PASSED")

    published.clear()
    htm_dir = Path(BASE) / "s7"
    htm_dir.mkdir(parents=True)
    htm_path = htm_dir / "index.htm"
    htm_path.write_text(CLEAN_HOMEPAGE, encoding="utf-8")
    detector7 = make_detector(Path(BASE) / "s7_baseline.json")
    detector7.publish = lambda ev: published.append(ev)
    await detector7._on_file_changed(make_event(str(htm_path), change_type="created"))
    assert str(htm_path) in detector7._baseline, "index.htm must be recognized as an entrypoint"
    print("Scenario 7 (index.htm recognized as entrypoint) PASSED")

    published.clear()
    detector8 = make_detector(Path(BASE) / "s8_baseline.json")
    detector8.publish = lambda ev: published.append(ev)
    await detector8._on_file_changed(make_event(str(index_path), change_type="deleted"))
    assert not published
    assert str(index_path) not in detector8._baseline
    print("Scenario 8 (deleted change_type is ignored, not scanned) PASSED")

    baseline_path = Path(BASE) / "s9_baseline.json"
    detector9a = make_detector(baseline_path)
    detector9a.publish = lambda ev: published.append(ev)
    p9 = Path(BASE) / "s9"; p9.mkdir(parents=True)
    idx9 = p9 / "index.html"
    idx9.write_text(CLEAN_HOMEPAGE, encoding="utf-8")
    await detector9a._on_file_changed(make_event(str(idx9), change_type="created"))

    from core.state_store import load_versioned_state
    from modules.html_injection_detector import _HtmlBaselineEntry, _BASELINE_FORMAT_VERSION
    reloaded = load_versioned_state(str(baseline_path), _BASELINE_FORMAT_VERSION, _HtmlBaselineEntry)
    assert str(idx9) in reloaded, "baseline must persist to disk for the next process start"
    print("Scenario 9 (baseline persists to disk and reloads) PASSED")

    print("\nALL HTML INJECTION DETECTOR TESTS PASSED")


asyncio.run(main())
