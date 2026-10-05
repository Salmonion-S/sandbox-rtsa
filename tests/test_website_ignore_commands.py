import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio
import tempfile
import time
from pathlib import Path

import yaml

import core.cloudpanel_resolver as cloudpanel_resolver
import modules.website_monitor as website_monitor_module
from config.manager import (
    CloudflareConfig, DiscordConfig, ModulesConfig, RTSAConfig, WebsiteMonitorConfig,
)
from core.cloudpanel_resolver import CloudPanelAsset
from core.datatypes import EventCategory
from core.event_bus import EventBus
from core.website_check import WebsiteCheckResult, diagnose
from core.website_ignore import IGNORE_KEY, IgnoreDomainStore, normalize_domain
from discord_integration.bot import RTSABot
from modules.website_monitor import WebsiteMonitor, classify_root_cause, root_cause_confidence


class FakeDb:
    def __init__(self):
        self.actions = []

    def enqueue_action(self, payload, result=""):
        self.actions.append((payload, result))

    def enqueue_incident_create(self, **k): pass

    def enqueue_incident_update(self, *a, **k): pass


def make_bot(ignore_path: str = "", authorized: bool = True) -> RTSABot:
    cfg = RTSAConfig(
        modules=ModulesConfig(
            website_monitor=WebsiteMonitorConfig(enabled=True, ignore_domains_path=ignore_path),
        ),
        cloudflare=CloudflareConfig(enabled=False),
    )
    bot = RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)
    bot._authorized = authorized
    return bot


def result_502(domain: str = "app.example") -> WebsiteCheckResult:
    return WebsiteCheckResult(domain=domain, scheme="https", condition="http_down", status_code=502)


def write_ignore_file(path: Path, domains, extra=None) -> None:
    document = {"ignore_domains": list(domains)}
    if extra:
        document.update(extra)
    path.write_text(yaml.safe_dump(document, default_flow_style=False, sort_keys=False), encoding="utf-8")


async def classification_tests() -> None:
    assert classify_root_cause(result_502(), True, None) == "PM2_DOWN"
    assert root_cause_confidence("PM2_DOWN") == "CONFIRMED"
    print("C1 (HTTP 502 + PM2 confirmed stopped -> PM2_DOWN at CONFIRMED confidence) PASSED")

    unknown_cause = classify_root_cause(result_502(), None, None)
    assert unknown_cause == "HTTP_FAILURE_UNCLASSIFIED", unknown_cause
    assert unknown_cause not in ("PM2_DOWN", "BACKEND_DOWN"), (
        "'RTSA has no PM2 evidence' must never be rendered as a confirmed backend failure"
    )
    assert root_cause_confidence(unknown_cause) == "LOW"
    print("C2 (HTTP 502 + PM2 mapping unknown -> uncertainty verdict at LOW confidence) PASSED")

    refused = WebsiteCheckResult(
        domain="app.example", scheme="https", condition="connection_refused", status_code=None,
    )
    assert classify_root_cause(refused, None, None) == "NGINX_DOWN"
    assert classify_root_cause(refused, None, True) == "REMOTE_PROBE_FAILURE", (
        "nginx confirmed up locally means the probe path failed, not the backend"
    )
    print("C3 (upstream/connection failure -> NGINX_DOWN, or REMOTE_PROBE_FAILURE when nginx is locally up) PASSED")

    degraded = classify_root_cause(result_502(), False, True)
    assert degraded == "BACKEND_DEGRADED", degraded
    assert root_cause_confidence(degraded) == "MEDIUM"
    print("C4 (HTTP 502 + nginx reachable + PM2 confirmed up -> BACKEND_DEGRADED at MEDIUM confidence) PASSED")

    bus = EventBus()
    wm = WebsiteMonitor(bus, WebsiteMonitorConfig(enabled=True, down_confirmation_checks=1))
    original_resolve = cloudpanel_resolver.resolve_domain

    async def exploding_resolve(domain):
        raise RuntimeError("cloudpanel resolver unavailable")

    cloudpanel_resolver.resolve_domain = exploding_resolve
    try:
        raised = False
        try:
            await wm._evaluate("boom.example", result_502("boom.example"))
        except RuntimeError:
            raised = True
        assert raised, "sanity: the injected discovery failure must genuinely reach _evaluate"
        await wm._check_one_domain("boom.example")
    finally:
        cloudpanel_resolver.resolve_domain = original_resolve
        await bus.shutdown()
    print("C5 (PM2/project discovery failure is contained per-domain and never crashes the monitor) PASSED")

    bus = EventBus()
    wm = WebsiteMonitor(bus, WebsiteMonitorConfig(enabled=True))
    wm._pm2_down_processes["owner-a"].add("app-a")
    asset_a = CloudPanelAsset(
        domain="a.example", linux_user="owner-a", project_root="/home/owner-a",
        htdocs_path="/home/owner-a/htdocs/a.example", nginx_vhost=None,
        pm2_user="owner-a", discovered_at=time.time(),
    )
    asset_b = CloudPanelAsset(
        domain="b.example", linux_user="owner-b", project_root="/home/owner-b",
        htdocs_path="/home/owner-b/htdocs/b.example", nginx_vhost=None,
        pm2_user="owner-b", discovered_at=time.time(),
    )
    obs_a = wm._pm2_observation(asset_a)
    obs_b = wm._pm2_observation(asset_b)
    assert obs_a.state == "CONFIRMED_DOWN" and obs_a.linux_user == "owner-a"
    assert obs_b.state == "UNKNOWN" and obs_b.reason_code == "DOMAIN_PROCESS_MAPPING_UNKNOWN", (
        "a second Linux user with no PM2 evidence must stay UNKNOWN rather than inherit owner-a's state"
    )
    await bus.shutdown()
    print("C6 (multi-user PM2 discovery resolves per project owner, no cross-user leakage) PASSED")

    assert classify_root_cause(result_502(), True, None) == "PM2_DOWN"
    stopped_text = diagnose(result_502(), pm2_down=True)
    assert "stopped" in stopped_text.lower() or "offline" in stopped_text.lower()
    unknown_text = diagnose(result_502(), pm2_down=None)
    assert "could not" in unknown_text.lower() and "stopped" not in unknown_text.lower()
    print("C7 (existing confirmed-PM2 project behaviour remains compatible) PASSED")


async def ignoredm_tests() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ignore_path = Path(tmp) / "ignore-domains-test.yaml"
        write_ignore_file(ignore_path, ["already.example.com"])
        bot = make_bot(str(ignore_path))

        message = await bot._set_domain_ignored("new.example.com", ignored=True, requested_by="tester")
        assert "Domain Monitoring Disabled" in message, message
        assert "new.example.com" in yaml.safe_load(ignore_path.read_text())["ignore_domains"]
        print("I1 (/ignoredm adds a valid domain to the persistent ignore list) PASSED")

        repeat = await bot._set_domain_ignored("new.example.com", ignored=True, requested_by="tester")
        assert "Already Disabled" in repeat, repeat
        entries = yaml.safe_load(ignore_path.read_text())["ignore_domains"]
        assert entries.count("new.example.com") == 1, f"duplicate entry written: {entries}"
        print("I2 (/ignoredm duplicate add is idempotent, never writes a second entry) PASSED")

        for variant in ("HTTPS://Norm.Example.COM/", "http://norm.example.com", "norm.example.com/"):
            assert normalize_domain(variant).value == "norm.example.com", variant
        await bot._set_domain_ignored("HTTPS://Norm.Example.COM/", ignored=True, requested_by="tester")
        again = await bot._set_domain_ignored("norm.example.com", ignored=True, requested_by="tester")
        assert "Already Disabled" in again, (
            "a differently-spelled form of the same domain must resolve to the existing entry"
        )
        print("I3 (/ignoredm normalization: scheme, case and trailing slash resolve to one canonical value) PASSED")

        before = ignore_path.read_text()
        for bad in ("", "   ", "example.com/admin", "user:pass@example.com", "*.example.com",
                    "example.com; rm -rf /", "example.com:8080", "ftp://example.com", "10.0.0.5"):
            reply = await bot._set_domain_ignored(bad, ignored=True, requested_by="tester")
            assert reply.startswith("❌"), f"input {bad!r} should have been rejected, got: {reply!r}"
        assert ignore_path.read_text() == before, "a rejected input must never modify the ignore file"
        print("I4 (/ignoredm rejects empty, path, credential, wildcard, shell, port, scheme and IP input) PASSED")

        reloaded = IgnoreDomainStore(str(ignore_path)).load()
        assert "new.example.com" in reloaded and "already.example.com" in reloaded
        print("I5 (/ignoredm state persists on disk and reloads intact) PASSED")

        bus = EventBus()
        wm = WebsiteMonitor(bus, WebsiteMonitorConfig(
            enabled=True, auto_discover=False, down_confirmation_checks=1,
            domains=["kept.example.com", "muted.example.com"],
        ))
        await wm._maybe_refresh_discovery()
        assert set(wm._domains) == {"kept.example.com", "muted.example.com"}
        wm.reload_config(WebsiteMonitorConfig(
            enabled=True, auto_discover=False, down_confirmation_checks=1,
            domains=["kept.example.com", "muted.example.com"],
            ignore_domains=["muted.example.com"],
        ))
        assert wm._domains == ["kept.example.com"], wm._domains
        collected = []

        async def collector(event):
            collected.append(event)

        sub = await bus.subscribe("ignore_collector", collector, categories=None)
        for domain in wm._domains:
            await wm._evaluate(domain, WebsiteCheckResult(
                domain=domain, scheme="https", condition="http_down", status_code=502,
            ))
        await sub.queue.join()
        assert any(
            e.category == EventCategory.WEBSITE_DOWN and "kept.example.com" in e.metadata.get("domains", [])
            for e in collected
        ), "the still-monitored sibling domain must still be able to raise WEBSITE_DOWN"
        collected[:] = [e for e in collected if "muted.example.com" in str(e.metadata)]
        down_events = [e for e in collected if e.category == EventCategory.WEBSITE_DOWN]
        assert not down_events, "an ignored domain must not be checked at all, so no WEBSITE_DOWN can be raised"
        print("I6 (an ignored domain is dropped from the monitored list -- no new WEBSITE_DOWN incident) PASSED")

        assert "kept.example.com" in wm._domains
        assert "muted.example.com" not in wm._domains
        await bus.shutdown()
        print("I7 (unrelated domains remain monitored when one domain is ignored) PASSED")

        import inspect
        source = inspect.getsource(RTSABot._register_commands)
        ignoredm_block = source.split('name="ignoredm"', 1)[1].split("@tree.command", 1)[0]
        monit_block = source.split('name="monit"', 1)[1].split("@tree.command", 1)[0]
        for label, block in (("/ignoredm", ignoredm_block), ("/monit", monit_block)):
            assert "_authorized_interaction(interaction, critical=True)" in block, (
                f"{label} must reuse the existing critical-command authorization gate"
            )
            assert "Tidak memiliki izin" in block, f"{label} must refuse unauthorized callers"
        print("I8 (/ignoredm and /monit enforce the existing critical-command authorization gate) PASSED")


async def monit_tests() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ignore_path = Path(tmp) / "ignore-domains-test.yaml"
        write_ignore_file(
            ignore_path, ["muted.example.com", "other.example.com"],
            extra={"unrelated_key": {"keep": "me"}},
        )
        bot = make_bot(str(ignore_path))

        message = await bot._set_domain_ignored("muted.example.com", ignored=False, requested_by="tester")
        assert "Domain Monitoring Enabled" in message, message
        entries = yaml.safe_load(ignore_path.read_text())["ignore_domains"]
        assert "muted.example.com" not in entries
        print("M1 (/monit removes the domain from the ignore list) PASSED")

        bus = EventBus()
        wm = WebsiteMonitor(bus, WebsiteMonitorConfig(
            enabled=True, auto_discover=False, domains=["muted.example.com"],
            ignore_domains=["muted.example.com"],
        ))
        await wm._maybe_refresh_discovery()
        assert wm._domains == []
        wm.reload_config(WebsiteMonitorConfig(
            enabled=True, auto_discover=False, domains=["muted.example.com"], ignore_domains=[],
        ))
        await wm._maybe_refresh_discovery()
        assert wm._domains == ["muted.example.com"], wm._domains
        print("M2 (/monit resumes monitoring without an RTSA restart) PASSED")

        state = wm._states.get("muted.example.com")
        assert state is None, (
            "an un-ignored domain must start from a clean state so it cannot inherit a stale "
            "down-streak and alert immediately"
        )
        await bus.shutdown()
        print("M3 (a newly re-monitored domain starts clean and cannot fire a stale alert) PASSED")

        idempotent = await bot._set_domain_ignored("never-ignored.example.com", ignored=False, requested_by="tester")
        assert "Already Enabled" in idempotent, idempotent
        assert not idempotent.startswith("❌")
        print("M4 (/monit on a non-ignored domain returns an idempotent response, not an error) PASSED")

        document = yaml.safe_load(ignore_path.read_text())
        assert document["ignore_domains"] == ["other.example.com"], document
        assert document["unrelated_key"] == {"keep": "me"}, (
            "an unrelated top-level key in the ignore file must survive the rewrite"
        )
        print("M5 (/monit persists the change and preserves unrelated domains and YAML keys) PASSED")

        reload_calls = []

        async def fake_reload():
            reload_calls.append(time.time())
            return {"success": True, "reloaded_modules": ["website_monitor"], "skipped_modules": []}

        bot._reload_config_fn = fake_reload
        refreshed = await bot._set_domain_ignored("other.example.com", ignored=False, requested_by="tester")
        assert len(reload_calls) == 1, "a successful change must trigger exactly one config reload"
        assert "reload" in refreshed.lower()
        print("M6 (runtime refresh goes through the existing config-reload path, exactly once) PASSED")

        async def failing_reload():
            raise RuntimeError("reload exploded")

        bot._reload_config_fn = failing_reload
        write_ignore_file(ignore_path, ["temp.example.com"])
        degraded = await bot._set_domain_ignored("temp.example.com", ignored=False, requested_by="tester")
        assert "tersimpan permanen" in degraded and "⚠️" in degraded, degraded
        assert yaml.safe_load(ignore_path.read_text())["ignore_domains"] == []
        print("M6b (a failed runtime reload is reported honestly, persisted change is not lost) PASSED")


async def scope_tests() -> None:
    import inspect
    for module_name in ("modules.fim_detector", "modules.nginx_monitor", "modules.process_anomaly_detector"):
        try:
            module = __import__(module_name, fromlist=["*"])
        except Exception:
            continue
        source = inspect.getsource(module)
        assert "ignore_domains" not in source, (
            f"{module_name} must not consult the Website Monitor ignore list -- ignoring a domain "
            f"may never disable FIM, web-attack or process detection"
        )
    print("S1 (ignore list never reaches FIM / web-attack / process detection) PASSED")

    filtered = website_monitor_module._filter_ignored_domains(
        ["a.example.com", "b.example.com"], ["a.example.com"],
    )
    assert filtered == ["b.example.com"], (
        "exactly the requested normalized domain is ignored -- siblings in the same project stay monitored"
    )
    print("S2 (ignoring one domain never auto-ignores sibling domains in the same project) PASSED")

    store_source = inspect.getsource(IgnoreDomainStore)
    assert "IGNORE_KEY" in store_source and IGNORE_KEY == "ignore_domains"
    bot_source = inspect.getsource(RTSABot._set_domain_ignored)
    assert "IgnoreDomainStore" not in bot_source or "_ignore_domain_store" in bot_source
    assert "ignore_domains_path" in inspect.getsource(RTSABot._ignore_domain_store), (
        "the commands must write the same external file the config loader reads, not a second list"
    )
    print("S3 (/ignoredm and /monit reuse the existing external ignore file, no second source) PASSED")


async def main() -> None:
    await classification_tests()
    await ignoredm_tests()
    await monit_tests()
    await scope_tests()
    print("\nALL WEBSITE MONITOR IGNORE/CLASSIFICATION TESTS PASSED")


asyncio.run(main())
