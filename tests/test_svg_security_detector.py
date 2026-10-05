import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import shutil
import tempfile
from pathlib import Path

from config.manager import SvgSecurityDetectorConfig
from core.datatypes import BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from modules.svg_security_detector import SvgSecurityDetector

BASE = os.path.join(tempfile.gettempdir(), "rtsa_svg_security_test")

BENIGN_ICON_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <path d="M12 2L2 7l10 5 10-5-10-5z" fill="currentColor"/>
</svg>
"""

BENIGN_ICON_SVG_REFORMATTED = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <path
    d="M12 2L2 7l10 5 10-5-10-5z"
    fill="currentColor"
  />
</svg>
"""

MALICIOUS_SCRIPT_ONLOAD_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">
  <script>eval(atob("YWxlcnQoMSk="))</script>
</svg>
"""

IFRAME_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="100" height="100">
    <iframe xmlns="http://www.w3.org/1999/xhtml" src="http://evil.example/payload"></iframe>
  </foreignObject>
</svg>
"""

WEAK_EXTERNAL_ONLY_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="https://cdn.example.com/icon.png"/>
</svg>
"""

JAVASCRIPT_URI_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg">
  <a href="javascript:alert(document.cookie)"><rect width="10" height="10"/></a>
</svg>
"""


def make_detector(baseline_path, min_confidence=20):
    bus = EventBus()
    config = SvgSecurityDetectorConfig(
        enabled=True,
        min_confidence_to_report=min_confidence,
        baseline_state_path=str(baseline_path),
    )
    detector = SvgSecurityDetector(bus, config)
    detector._baseline = {}
    return detector


def make_event(path, project="testproject", change_type="modified", target_class="uploads"):
    return BaseEvent(
        source_module="file_integrity_detector",
        category=EventCategory.FILE_INTEGRITY_CHANGE,
        severity=Severity.INFO,
        message="test",
        metadata={
            "target_class": target_class,
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
    svg_path = project_dir / "logo.svg"
    svg_path.write_text(BENIGN_ICON_SVG, encoding="utf-8")
    detector = make_detector(Path(BASE) / "s1_baseline.json")
    detector.publish = lambda ev: published.append(ev)
    await detector._on_file_changed(make_event(str(svg_path), change_type="created"))
    assert not published, f"first-ever scan must not publish anything: {published}"
    assert str(svg_path) in detector._baseline
    print("Scenario 1 (first-ever scan silently baselines, zero alerts) PASSED")

    published.clear()
    svg_path.write_text(BENIGN_ICON_SVG_REFORMATTED, encoding="utf-8")
    await detector._on_file_changed(make_event(str(svg_path)))
    assert not published, f"a plain static SVG with no markers must never alert: {published}"
    print("Scenario 2 (plain static SVG stays EXPECTED, no alert) PASSED")

    published.clear()
    svg_path.write_text(MALICIOUS_SCRIPT_ONLOAD_SVG, encoding="utf-8")
    await detector._on_file_changed(make_event(str(svg_path)))
    assert len(published) == 1, f"script+onload+obfuscated-eval combo must alert: {published}"
    ev = published[0]
    assert "svg_script_tag" in ev.metadata["evidence"], ev.metadata
    assert "svg_event_handler" in ev.metadata["evidence"], ev.metadata
    assert "svg_obfuscated_js" in ev.metadata["evidence"], ev.metadata
    assert ev.metadata["confidence"] >= 70, "script+event-handler+obfuscation combo must reach CRITICAL-tier confidence"
    assert ev.severity == Severity.CRITICAL
    assert ev.metadata["project"] == "testproject"
    assert ev.metadata["related_file"] == str(svg_path)
    print("Scenario 3 (script+onload+obfuscated-eval SVG alerts CRITICAL with full evidence) PASSED")

    published.clear()
    svg_path.write_text(MALICIOUS_SCRIPT_ONLOAD_SVG, encoding="utf-8")
    await detector._on_file_changed(make_event(str(svg_path)))
    assert not published, f"an already-baselined signature set must not re-alert on every scan: {published}"
    print("Scenario 4 (repeat of already-known malicious content does not re-alert) PASSED")

    published.clear()
    svg_path.write_text(IFRAME_SVG, encoding="utf-8")
    await detector._on_file_changed(make_event(str(svg_path)))
    assert len(published) == 1, f"a second, distinct new signature (iframe/foreignObject) must still alert: {published}"
    assert "svg_iframe_embed" in published[0].metadata["evidence"]
    assert "svg_foreignobject_html" in published[0].metadata["evidence"]
    print("Scenario 5 (distinct new iframe/foreignObject signature alerts independently) PASSED")

    published.clear()
    weak_dir = Path(BASE) / "s6"
    weak_dir.mkdir(parents=True)
    weak_path = weak_dir / "banner.svg"
    weak_path.write_text(BENIGN_ICON_SVG, encoding="utf-8")
    detector6 = make_detector(Path(BASE) / "s6_baseline.json")
    detector6.publish = lambda ev: published.append(ev)
    await detector6._on_file_changed(make_event(str(weak_path), change_type="created"))
    published.clear()
    weak_path.write_text(WEAK_EXTERNAL_ONLY_SVG, encoding="utf-8")
    await detector6._on_file_changed(make_event(str(weak_path)))
    assert not published, (
        f"a single low-weight external-resource-only signal must be suppressed below the "
        f"reporting threshold, not treated as a confirmed malicious SVG: {published}"
    )
    print("Scenario 6 (lone low-signal external resource ref suppressed below threshold) PASSED")

    published.clear()
    js_uri_dir = Path(BASE) / "s7"
    js_uri_dir.mkdir(parents=True)
    js_uri_path = js_uri_dir / "clickable.svg"
    js_uri_path.write_text(BENIGN_ICON_SVG, encoding="utf-8")
    detector7 = make_detector(Path(BASE) / "s7_baseline.json")
    detector7.publish = lambda ev: published.append(ev)
    await detector7._on_file_changed(make_event(str(js_uri_path), change_type="created"))
    published.clear()
    js_uri_path.write_text(JAVASCRIPT_URI_SVG, encoding="utf-8")
    await detector7._on_file_changed(make_event(str(js_uri_path)))
    assert len(published) == 1, f"a javascript: URI must alert on its own: {published}"
    assert "svg_javascript_uri" in published[0].metadata["evidence"]
    print("Scenario 7 (javascript: URI alone is enough to alert) PASSED")

    published.clear()
    non_svg_dir = Path(BASE) / "s8"
    non_svg_dir.mkdir(parents=True)
    non_svg_path = non_svg_dir / "notes.txt"
    non_svg_path.write_text(MALICIOUS_SCRIPT_ONLOAD_SVG, encoding="utf-8")
    detector8 = make_detector(Path(BASE) / "s8_baseline.json")
    detector8.publish = lambda ev: published.append(ev)
    await detector8._on_file_changed(make_event(str(non_svg_path), change_type="created"))
    assert not published, f"a non-.svg file must never be scanned by this detector: {published}"
    assert str(non_svg_path) not in detector8._baseline
    print("Scenario 8 (non-.svg file is ignored regardless of content) PASSED")

    published.clear()
    detector9 = make_detector(Path(BASE) / "s9_baseline.json")
    detector9.publish = lambda ev: published.append(ev)
    await detector9._on_file_changed(make_event(str(svg_path), target_class="configs"))
    assert not published, f"an event outside php_source/uploads target_class must be ignored: {published}"
    assert str(svg_path) not in detector9._baseline
    print("Scenario 9 (target_class outside php_source/uploads is ignored) PASSED")

    published.clear()
    detector10 = make_detector(Path(BASE) / "s10_baseline.json")
    detector10.publish = lambda ev: published.append(ev)
    await detector10._on_file_changed(make_event(str(svg_path), change_type="deleted"))
    assert not published
    assert str(svg_path) not in detector10._baseline
    print("Scenario 10 (deleted change_type is ignored, not scanned) PASSED")

    baseline_path = Path(BASE) / "s11_baseline.json"
    detector11a = make_detector(baseline_path)
    detector11a.publish = lambda ev: published.append(ev)
    p11 = Path(BASE) / "s11"; p11.mkdir(parents=True)
    svg11 = p11 / "icon.svg"
    svg11.write_text(BENIGN_ICON_SVG, encoding="utf-8")
    await detector11a._on_file_changed(make_event(str(svg11), change_type="created", target_class="php_source"))

    from core.state_store import load_versioned_state
    from modules.svg_security_detector import _SvgBaselineEntry, _BASELINE_FORMAT_VERSION
    reloaded = load_versioned_state(str(baseline_path), _BASELINE_FORMAT_VERSION, _SvgBaselineEntry)
    assert str(svg11) in reloaded, "baseline must persist to disk for the next process start"
    print("Scenario 11 (baseline persists to disk and reloads; php_source target_class accepted) PASSED")

    print("\nALL SVG SECURITY DETECTOR TESTS PASSED")


asyncio.run(main())
