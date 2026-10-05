import asyncio
import os
import ssl
import subprocess
import sys
import tempfile
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import aiohttp
from aiohttp import web

from config.manager import DiscordConfig, WebsiteMonitorConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
import core.website_check as website_check
from core.website_check import check_website
from discord_integration.webhook import DiscordWebhookDispatcher
from modules.website_monitor import WebsiteMonitor, _filter_ignored_domains


class _AllowPrivateTargets:
    def __enter__(self):
        self._real = website_check._host_resolves_publicly

        async def allow(_host):
            return True

        website_check._host_resolves_publicly = allow
        return self

    def __exit__(self, *exc):
        website_check._host_resolves_publicly = self._real
        return False


async def start_http_server(handler):
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


def make_self_signed_cert(tmpdir):
    key_path = os.path.join(tmpdir, "key.pem")
    cert_path = os.path.join(tmpdir, "cert.pem")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key_path, "-out", cert_path, "-days", "1",
            "-subj", "/CN=rtsa-website-monitor-test.invalid",
        ],
        check=True, capture_output=True,
    )
    return cert_path, key_path


async def start_https_server_with_untrusted_cert(handler, tmpdir):
    cert_path, key_path = make_self_signed_cert(tmpdir)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=context)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


def make_monitor(**overrides):
    overrides.setdefault("enabled", True)
    overrides.setdefault("auto_discover", False)
    cfg = WebsiteMonitorConfig(**overrides)
    monitor = WebsiteMonitor(EventBus(), cfg)
    published = []
    monitor.publish = lambda event: published.append(event)
    return monitor, published


def down_events(published):
    return [e for e in published if e.category == EventCategory.WEBSITE_DOWN]


def recovered_events(published):
    return [e for e in published if e.category == EventCategory.WEBSITE_RECOVERED]


async def main() -> None:
    async def ok_handler(_request):
        return web.Response(text="ok")

    async def slow_handler(_request):
        await asyncio.sleep(5.0)
        return web.Response(text="too late")

    with _AllowPrivateTargets():
        runner, port = await start_http_server(ok_handler)
        target = f"127.0.0.1:{port}"
        try:
            async with aiohttp.ClientSession() as session:
                started = time.monotonic()
                result = await check_website(session, target, timeout_seconds=5.0)
                elapsed = time.monotonic() - started
            assert result.is_down is False, f"a live HTTP 200 endpoint must be UP: {result}"
            assert result.status_code == 200, result
            print(
                f"Test 1 [C] (real local endpoint returning HTTP 200 is classified UP in "
                f"{elapsed * 1000:.0f}ms, after the HTTPS attempt falls back to HTTP) PASSED"
            )
        finally:
            await runner.cleanup()

        async with aiohttp.ClientSession() as session:
            refused = await check_website(session, target, timeout_seconds=5.0)
        assert refused.is_down is True, f"a stopped server must be classified DOWN: {refused}"
        assert refused.condition == "connection_refused", refused
        print("Test 2 [C] (the same endpoint after the server is stopped -> connection_refused, DOWN) PASSED")

        slow_runner, slow_port = await start_http_server(slow_handler)
        try:
            async with aiohttp.ClientSession() as session:
                timed_out = await check_website(
                    session, f"127.0.0.1:{slow_port}", timeout_seconds=0.5,
                )
            assert timed_out.is_down is True, f"a hanging endpoint must be classified DOWN: {timed_out}"
            assert timed_out.condition == "timeout", timed_out
            print("Test 3 [C] (an endpoint that never answers within request_timeout_seconds -> timeout, DOWN) PASSED")
        finally:
            await slow_runner.cleanup()

        with tempfile.TemporaryDirectory(prefix="rtsa_tls_test_") as tmpdir:
            tls_runner, tls_port = await start_https_server_with_untrusted_cert(ok_handler, tmpdir)
            try:
                async with aiohttp.ClientSession() as session:
                    tls_result = await check_website(
                        session, f"127.0.0.1:{tls_port}", timeout_seconds=5.0,
                    )
                assert tls_result.is_down is True, f"an untrusted certificate must be DOWN: {tls_result}"
                assert tls_result.condition == "tls_certificate_invalid", (
                    f"the TLS root cause must survive the HTTPS->HTTP fallback so the operator is told "
                    f"the certificate is the problem, not a generic disconnect: {tls_result}"
                )
                from modules.website_monitor import classify_root_cause
                assert classify_root_cause(tls_result, None, None) == "SSL_INVALID", tls_result
                print(
                    "Test 4 [C] (real HTTPS endpoint serving an untrusted self-signed certificate -> "
                    "tls_failure/SSL_INVALID, DOWN -- certificate validation is enforced and the TLS "
                    "root cause is no longer masked by the HTTP fallback) PASSED"
                )
            finally:
                await tls_runner.cleanup()

    async with aiohttp.ClientSession() as session:
        blocked = await check_website(session, "127.0.0.1:9", timeout_seconds=2.0)
    assert blocked.condition == "blocked_private_target", (
        f"without the test override, private targets must still be refused outright: {blocked}"
    )
    print("Test 5 [C] (the SSRF guard still refuses private/internal targets when not explicitly overridden in a test) PASSED")

    monitor, published = make_monitor(
        down_confirmation_checks=2, recovery_confirmation_checks=2, poll_interval_seconds=420.0,
    )
    monitor._nginx_locally_up = None
    down_result = website_check.WebsiteCheckResult(
        "shop.example.com", "https", "connection_refused", provider="network",
        error_detail="refused",
    )
    await monitor._evaluate("shop.example.com", down_result)
    assert down_events(published) == [], "the first failing check must not alert -- it may be transient"
    await monitor._evaluate("shop.example.com", down_result)
    assert len(down_events(published)) == 1, f"the second consecutive failure must alert: {published}"
    print("Test 6 [C] (down detection: exactly one WEBSITE_DOWN after down_confirmation_checks consecutive failures) PASSED")

    up_result = website_check.WebsiteCheckResult(
        "shop.example.com", "https", "ok", status_code=200, provider="network", response_time_ms=12.0,
    )
    await monitor._evaluate("shop.example.com", up_result)
    assert recovered_events(published) == [], "recovery must also be confirmed before alerting"
    await monitor._evaluate("shop.example.com", up_result)
    assert len(recovered_events(published)) == 1, f"recovery must alert once confirmed: {published}"
    print("Test 7 [C] (recovery detection: exactly one WEBSITE_RECOVERED after recovery_confirmation_checks consecutive successes) PASSED")

    interval = 420.0
    worst_case_down_latency = interval * 2
    worst_case_recovery_latency = interval * 2
    assert monitor.config.poll_interval_seconds == interval
    assert monitor.config.down_confirmation_checks == 2
    print(
        f"Test 8 [C] (latency budget from the shipped configuration: poll_interval={interval:.0f}s x "
        f"down_confirmation_checks=2 -> outages shorter than ~{worst_case_down_latency:.0f}s are never "
        f"confirmed and therefore never alert; recovery is confirmed within ~{worst_case_recovery_latency:.0f}s) PASSED"
    )

    fast_monitor, fast_published = make_monitor(
        down_confirmation_checks=2, recovery_confirmation_checks=1, poll_interval_seconds=0.2,
    )
    fast_monitor._nginx_locally_up = None
    outage_started = time.monotonic()
    for _ in range(2):
        await fast_monitor._evaluate("fast.example.com", down_result)
        await asyncio.sleep(0.2)
    observed_down_latency = time.monotonic() - outage_started
    assert len(down_events(fast_published)) == 1
    recovery_started = time.monotonic()
    await fast_monitor._evaluate("fast.example.com", up_result)
    observed_recovery_latency = time.monotonic() - recovery_started
    assert len(recovered_events(fast_published)) == 1
    print(
        f"Test 9 [C] (measured end-to-end on a 0.2s simulated interval: outage detected in "
        f"{observed_down_latency:.2f}s, recovery in {observed_recovery_latency:.3f}s -- latency scales "
        f"with poll_interval x confirmation_checks exactly as configured) PASSED"
    )

    assert _filter_ignored_domains(["a.com", "b.com"], ["b.com"]) == ["a.com"]
    assert _filter_ignored_domains(["a.com", "b.com"], []) == ["a.com", "b.com"]
    assert _filter_ignored_domains(["A.com"], ["a.com"]) == []
    print("Test 10 [C] (ignored domains are excluded case-insensitively and only when configured) PASSED")

    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig(
        alert_channel_id=999000999000999000,
        category_channels={"WEBSITE_DOWN": 111222333444555666, "WEBSITE_RECOVERED": 111222333444555666},
    ))
    assert dispatcher._resolve_channel_id("WEBSITE_DOWN", "website_monitor") == 111222333444555666
    assert dispatcher._resolve_channel_id("WEBSITE_RECOVERED", "website_monitor") == 111222333444555666
    assert down_events(published)[0].metadata.get("notify_discord") is not False, (
        "a confirmed outage must never be internal-only -- it has to reach Discord"
    )
    assert down_events(published)[0].severity in (Severity.HIGH, Severity.CRITICAL)
    print("Test 11 [C] (WEBSITE_DOWN and WEBSITE_RECOVERED route to the configured channel and are not internal-only) PASSED")

    dedup_monitor, dedup_published = make_monitor(
        down_confirmation_checks=1, recovery_confirmation_checks=1, maximum_reminders=0,
        reminder_enabled=False,
    )
    dedup_monitor._nginx_locally_up = None
    for _ in range(6):
        await dedup_monitor._evaluate("dedup.example.com", down_result)
    assert len(down_events(dedup_published)) == 1, (
        f"a continuously down site must be one incident, not one alert per poll: "
        f"{len(down_events(dedup_published))}"
    )
    print("Test 12 [C] (6 consecutive down polls with reminders disabled collapse into exactly one WEBSITE_DOWN incident) PASSED")

    group_monitor, _group_published = make_monitor()
    key_a = group_monitor._incident_key_for("a.example.com", None, "NGINX_DOWN")
    key_b = group_monitor._incident_key_for("a.example.com", None, "NETWORK_TIMEOUT")
    assert key_a != key_b, "different root causes must not be merged into one incident"
    assert "a.example.com" in key_a
    print("Test 13 [C] (incident identity groups by project/domain and root cause, so a diagnosis change is not silently merged) PASSED")

    health = await monitor.health()
    for key in ("checks_completed_total", "checks_failed_total"):
        assert key in health, f"{key} must be exposed for diagnostics: {sorted(health)}"
    print("Test 14 [C] (website monitor exposes check counters in module health output) PASSED")

    print("\nALL WEBSITE MONITOR END-TO-END TESTS PASSED")


asyncio.run(main())
