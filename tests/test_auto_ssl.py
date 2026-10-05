from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Sequence, Tuple
from unittest import mock

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import discord

from config.manager import (
    AutoSslConfig, CloudflareConfig, ConfigValidationError, DiscordConfig, ModulesConfig, ResponseEngineConfig,
    RTSAConfig,
)
from core.auto_ssl import (
    PROBE_HANDSHAKE_FAILED, PROBE_OK, PROBE_REFUSED, RESULT_BLOCKED, RESULT_BLOCKED_DETECTION_ONLY,
    RESULT_DRY_RUN, RESULT_FAILED, RESULT_NO_REPAIR_NEEDED, RESULT_SKIPPED_ATTEMPTS, RESULT_SKIPPED_BUSY,
    RESULT_SKIPPED_COOLDOWN, RESULT_SKIPPED_DISABLED, RESULT_SKIPPED_NOT_CONFIRMED, RESULT_SKIPPED_NOT_SSL,
    RESULT_SSL_RECOVERED_STILL_DOWN, RESULT_SUCCESS, AuditRecord, AutoSslController, AutoSslPorts,
    AutoSslStateStore, BackupHandle, CertbotLineage, CertificateFacts, CommandResult, OriginTlsProbe,
    RecheckOutcome, sanitize_output,
)
from core.datatypes import ActionType, BaseEvent, EventCategory, Severity
from core.event_bus import EventBus
from core.nginx_vhost_inspect import VhostServerBlock
from discord_integration.bot import RTSABot

NOW = 1_800_000_000.0
DOMAIN = "shop.example.com"
DAY = 86400.0


class Clock:
    def __init__(self, start: float = NOW) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t


def facts(days_left: float, domain: str = DOMAIN, issuer: str = "Let's Encrypt (R3)") -> CertificateFacts:
    return CertificateFacts(
        subject_cn=domain, issuer=issuer, not_before=NOW - 60 * DAY, not_after=NOW + days_left * DAY,
        sans=(domain,), source="origin-handshake",
    )


def probe(days_left: Optional[float] = 30.0, *, domain: str = DOMAIN, outcome: str = PROBE_OK,
          trusted: Optional[bool] = True) -> OriginTlsProbe:
    if outcome != PROBE_OK:
        return OriginTlsProbe(outcome=outcome, detail="x")
    return OriginTlsProbe(outcome=PROBE_OK, host="127.0.0.1", facts=facts(days_left, domain), chain_trusted=trusted)


def vhost_block(path: str = "/etc/nginx/sites-enabled/shop.example.com.conf", cert: Optional[str] = None) -> VhostServerBlock:
    return VhostServerBlock(
        path=path, real_path=path, server_names=(DOMAIN,), listens=("443 ssl",), has_ssl_listen=True,
        ssl_certificate=cert, ssl_certificate_key=None, proxy_pass=None, fastcgi_pass=None, root=None, includes=(),
    )


class FakePorts(AutoSslPorts):
    def __init__(self) -> None:
        self.asset: Optional[Any] = SimpleNamespace(
            linux_user="shopuser", htdocs_path="/home/shopuser/htdocs/shop.example.com",
            project_root="/home/shopuser", pm2_user="shopuser",
        )
        self.blocks: List[VhostServerBlock] = [vhost_block()]
        self.probes: List[OriginTlsProbe] = [probe(-3.0)]
        self.lineages: Tuple[Optional[bool], List[CertbotLineage], str] = (True, [], "")
        self.binaries: Dict[str, str] = {"clpctl": "/usr/bin/clpctl", "certbot": "/usr/bin/certbot"}
        self.command_result = CommandResult(0, "ok")
        self.command_side_effect = None
        self.commands: List[Tuple[Tuple[str, ...], float]] = []
        self.nginx_tests: List[Tuple[bool, str]] = [(True, "ok")]
        self.nginx_test_calls = 0
        self.reload_result: Tuple[bool, str] = (True, "reloaded")
        self.reload_calls = 0
        self.nginx_is_active: Optional[bool] = True
        self.digest = "digest-before"
        self.restore_calls: List[BackupHandle] = []
        self.restore_error: Optional[str] = None
        self.backups: List[str] = []
        self.claimed: set = set()
        self.claim_ok = True
        self.mutations = True
        self.recheck = RecheckOutcome(healthy=True, last_probe_ok=True, status_text="HTTP 200")
        self.recheck_calls: List[str] = []
        self.notes: Dict[str, Optional[Dict[str, Any]]] = {}
        self.diagnosed: List[Tuple[str, str]] = []
        self.published: List[BaseEvent] = []
        self.audits: List[AuditRecord] = []
        self.probe_calls = 0

    async def resolve_asset(self, domain): return self.asset
    async def find_vhosts(self, domain): return list(self.blocks)
    async def certbot_lineages(self, domain): return self.lineages

    async def probe_origin(self, domain):
        index = min(self.probe_calls, len(self.probes) - 1)
        self.probe_calls += 1
        return self.probes[index]

    def which(self, binary): return self.binaries.get(binary)

    async def run_command(self, argv, timeout):
        self.commands.append((tuple(argv), timeout))
        if self.command_side_effect:
            self.command_side_effect()
        return self.command_result

    async def backup_file(self, path):
        self.backups.append(path)
        return BackupHandle(path=path, backup_path=path + ".bak", digest=self.digest, original_bytes=b"orig")

    async def file_digest(self, path): return self.digest

    async def restore_file(self, handle):
        self.restore_calls.append(handle)
        if self.restore_error is None:
            self.digest = handle.digest
        return self.restore_error

    async def nginx_test(self):
        index = min(self.nginx_test_calls, len(self.nginx_tests) - 1)
        self.nginx_test_calls += 1
        return self.nginx_tests[index]

    async def nginx_reload(self, requested_by):
        self.reload_calls += 1
        return self.reload_result

    async def nginx_active(self): return self.nginx_is_active

    def claim_domain(self, domain):
        if not self.claim_ok or domain in self.claimed:
            return False
        self.claimed.add(domain)
        return True

    def release_domain(self, domain): self.claimed.discard(domain)
    def mutations_allowed(self): return self.mutations

    async def recheck_website(self, domain):
        self.recheck_calls.append(domain)
        return self.recheck

    def register_recovery_note(self, domain, note): self.notes[domain] = note

    async def diagnose_still_down(self, domain, ssl_state):
        self.diagnosed.append((domain, ssl_state))
        return BaseEvent(
            source_module="auto_ssl", category=EventCategory.WEBSITE_STILL_DOWN, severity=Severity.HIGH,
            message="WEBSITE_STILL_DOWN", metadata={"domain": domain, "ssl_state": ssl_state},
        )

    def publish(self, event): self.published.append(event)
    def audit(self, record): self.audits.append(record)

    def categories(self) -> List[str]:
        return [event.category.value for event in self.published]


def down_event(root_cause: str = "SSL_INVALID", status_code: Optional[int] = 526, *, domains: Optional[List[str]] = None,
               first_detected_at: float = NOW - 900, check_count: int = 3, confirm: int = 3,
               is_reminder: bool = False, condition: str = "cloudflare_down") -> BaseEvent:
    domains = domains or [DOMAIN]
    return BaseEvent(
        source_module="website_monitor", category=EventCategory.WEBSITE_DOWN, severity=Severity.HIGH,
        message="WEBSITE_DOWN", metadata={
            "domain": domains[0], "domains": domains, "root_cause": root_cause, "status_code": status_code,
            "condition": condition, "incident_key": f"shopuser:{root_cause}", "first_detected_at": first_detected_at,
            "check_count": check_count, "down_confirmation_checks": confirm, "is_reminder": is_reminder,
        },
    )


def make_controller(tmp: str, *, cfg: Optional[AutoSslConfig] = None, ports: Optional[FakePorts] = None,
                    clock: Optional[Clock] = None, enable: bool = True):
    clock = clock or Clock()
    cfg = cfg or AutoSslConfig(state_path=os.path.join(tmp, "auto_ssl_state.json"))
    ports = ports or FakePorts()
    state = AutoSslStateStore(cfg.state_path, clock=clock)
    controller = AutoSslController(lambda: cfg, state, ports, clock=clock, monotonic=clock)
    if enable:
        state.set_runtime_enabled(True, "tester")
    return controller, ports, state, clock


async def run(controller: AutoSslController, event: BaseEvent) -> List[Tuple[str, str]]:
    return await controller.handle_website_down(event)


async def test_1_off_is_alert_only() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        controller, ports, _state, _ = make_controller(tmp, enable=False)
        assert controller.is_enabled() is False
        assert controller.schedule(down_event()) is None, "disabled controller must not even schedule a task"
        outcomes = await run(controller, down_event())
        assert outcomes == [(DOMAIN, RESULT_SKIPPED_DISABLED)], outcomes
        assert not ports.commands and not ports.published and not ports.audits and ports.reload_calls == 0
    print("Test 1 (Auto SSL OFF -> alert only, no command/publish/audit/reload) PASSED")


async def test_2_on_confirmed_failure_repairs() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(-3.0), probe(80.0)]
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_SUCCESS)], outcomes
        assert len(ports.commands) == 1
        argv, timeout = ports.commands[0]
        assert argv == ("/usr/bin/clpctl", "lets-encrypt:install:certificate", f"--domainName={DOMAIN}"), argv
        assert timeout == controller.config.command_timeout_seconds
        assert ports.reload_calls == 1 and ports.nginx_test_calls >= 1
        assert ports.recheck_calls == [DOMAIN]
        assert ports.published == [], "a successful repair must not publish a failure/still-down alert"
    print("Test 2 (Auto SSL ON + confirmed SSL failure -> repair attempted via CloudPanel, argv-only) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        cert_path = os.path.join(tmp, "fullchain.pem")
        open(cert_path, "w").close()
        ports = FakePorts()
        ports.asset = None
        ports.blocks = [vhost_block(cert=cert_path)]
        ports.lineages = (True, [CertbotLineage("shop-lineage", (DOMAIN,), cert_path, "2026-01-01", "INVALID: EXPIRED")], "")
        ports.probes = [probe(-3.0), probe(80.0)]
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("ORIGIN_TLS_HANDSHAKE_FAILURE", 525))
        assert outcomes == [(DOMAIN, RESULT_SUCCESS)], outcomes
        argv, _timeout = ports.commands[0]
        assert argv[:4] == ("/usr/bin/certbot", "renew", "--cert-name", "shop-lineage"), argv
        assert "--non-interactive" in argv
        assert not any(part in ("sh", "bash", "-c") for part in argv)
    print("Test 2b (non-CloudPanel domain -> Certbot renew of the lineage that owns the vhost certificate) PASSED")


async def test_3_plain_502_no_certbot() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        for root_cause, status in (("BACKEND_DEGRADED", 502), ("HTTP_FAILURE_UNCLASSIFIED", 503), ("PROJECT_DOWN", 500)):
            controller, ports, _s, _ = make_controller(tmp)
            outcomes = await run(controller, down_event(root_cause, status))
            assert outcomes == [(DOMAIN, RESULT_SKIPPED_NOT_SSL)], (root_cause, outcomes)
            assert not ports.commands and ports.probe_calls == 0 and ports.reload_calls == 0
    print("Test 3 (plain 502/503/500 -> no Certbot, no origin probe, no reload) PASSED")


async def test_4_backend_down_no_certbot() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        for root_cause, status in (("PM2_DOWN", 502), ("NGINX_DOWN", 521), ("REMOTE_PROBE_FAILURE", 521)):
            controller, ports, _s, _ = make_controller(tmp)
            outcomes = await run(controller, down_event(root_cause, status))
            assert outcomes == [(DOMAIN, RESULT_SKIPPED_NOT_SSL)], (root_cause, outcomes)
            assert not ports.commands and ports.probe_calls == 0
    print("Test 4 (backend down / PM2 down / nginx down -> no Certbot) PASSED")


async def test_5_dns_failure_no_certbot() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        for root_cause in ("DNS_FAILURE", "NETWORK_TIMEOUT", "BLOCKED_PRIVATE_TARGET"):
            controller, ports, _s, _ = make_controller(tmp)
            outcomes = await run(controller, down_event(root_cause, None, condition="dns_failure"))
            assert outcomes == [(DOMAIN, RESULT_SKIPPED_NOT_SSL)], (root_cause, outcomes)
            assert not ports.commands
    print("Test 5 (DNS failure / network timeout -> no Certbot) PASSED")


async def test_6_cloudflare_525_valid_origin_no_blind_renewal() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(60.0)]
        controller, ports, state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("ORIGIN_TLS_HANDSHAKE_FAILURE", 525))
        assert outcomes == [(DOMAIN, RESULT_NO_REPAIR_NEEDED)], outcomes
        assert not ports.commands, "a valid origin certificate must never be 'renewed' blindly"
        assert ports.reload_calls == 0
        assert ports.diagnosed == [(DOMAIN, "VALID (no repair needed)")], ports.diagnosed
        assert ports.categories() == ["WEBSITE_STILL_DOWN"], ports.categories()
        entry = state.last_result(DOMAIN)
        assert entry and entry["last_result"] == RESULT_NO_REPAIR_NEEDED and entry.get("attempts", 0) == 0
    print("Test 6 (Cloudflare 525 + valid origin certificate -> no renewal, post-SSL diagnosis instead) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(outcome=PROBE_REFUSED)]
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("ORIGIN_TLS_HANDSHAKE_FAILURE", 525))
        assert outcomes == [(DOMAIN, RESULT_NO_REPAIR_NEEDED)] and not ports.commands
        assert ports.diagnosed and "no TLS listener" in ports.diagnosed[0][1]
    print("Test 6b (origin has no TLS listener -> not a certificate problem, no renewal) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(outcome=PROBE_HANDSHAKE_FAILED)]
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("ORIGIN_TLS_HANDSHAKE_FAILURE", 525))
        assert outcomes == [(DOMAIN, RESULT_BLOCKED)] and not ports.commands
        assert ports.categories() == ["SSL_AUTO_REPAIR_FAILED"]
        assert "renewing the certificate would not fix this" in ports.published[0].message
    print("Test 6c (origin TLS configuration problem -> blocked with manual guidance, no renewal) PASSED")


async def test_7_expired_certificate_renews() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(-10.0), probe(85.0)]
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("ORIGIN_TLS_HANDSHAKE_FAILURE", 525))
        assert outcomes == [(DOMAIN, RESULT_SUCCESS)] and len(ports.commands) == 1
        note = ports.notes[DOMAIN]
        assert note and note["method"] == "cloudpanel" and note["issuer"] == "Let's Encrypt (R3)"
        assert "d left" in note["new_expiry"] and note["verification"].startswith("PASS")
        assert note["previous_failure"].startswith("ORIGIN_TLS_HANDSHAKE_FAILURE")
    print("Test 7 (expired origin certificate -> renewal, recovery note carries issuer/new expiry/method) PASSED")


async def test_8_nginx_test_failure_no_reload_and_rollback() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(-3.0)]
        ports.nginx_tests = [(False, "nginx: [emerg] bad directive"), (True, "ok")]

        def _tool_edits_vhost() -> None:
            ports.digest = "digest-after-repair-edit"

        ports.command_side_effect = _tool_edits_vhost
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_FAILED)], outcomes
        assert ports.reload_calls == 0, "nginx -t failure must never be followed by a reload"
        assert len(ports.restore_calls) == 1 and ports.restore_calls[0].path.endswith("shop.example.com.conf")
        failure = ports.published[0]
        assert failure.category == EventCategory.SSL_AUTO_REPAIR_FAILED
        assert failure.metadata["stage"] == "nginx-test" and failure.metadata["nginx_test"] == "FAIL"
        assert failure.metadata["rollback"].startswith("SUCCESS")
        assert "Next Manual Action" in failure.message and "Rollback:" in failure.message
    print("Test 8 (nginx -t failure -> no reload, vhost restored from backup, SSL_AUTO_REPAIR_FAILED) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.nginx_tests = [(False, "nginx: [emerg] bad directive")]
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        await run(controller, down_event("SSL_INVALID", 526))
        assert ports.reload_calls == 0 and not ports.restore_calls
        assert ports.published[0].metadata["rollback"].startswith("NOT NEEDED")
    print("Test 8b (nginx -t failure but vhost untouched by the repair -> nothing to roll back, still no reload) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.reload_result = (False, "reload failed")
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_FAILED)]
        assert ports.published[0].metadata["stage"] == "reload"
    print("Test 8c (reload failure -> SSL_AUTO_REPAIR_FAILED at stage=reload) PASSED")


async def test_9_certbot_failure_alerts() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cert_path = os.path.join(tmp, "fullchain.pem")
        open(cert_path, "w").close()
        ports = FakePorts()
        ports.asset = None
        ports.blocks = [vhost_block(cert=cert_path)]
        ports.lineages = (True, [CertbotLineage("shop-lineage", (DOMAIN,), cert_path, None, None)], "")
        ports.command_result = CommandResult(1, "Challenge failed for domain shop.example.com token=SECRETVALUE123")
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_FAILED)]
        failure = ports.published[0]
        assert failure.category == EventCategory.SSL_AUTO_REPAIR_FAILED
        assert failure.metadata["stage"] == "repair" and failure.metadata["method"] == "certbot"
        assert failure.metadata["exit_status"] == "1" and failure.metadata["nginx_test"] == "NOT RUN"
        assert ports.reload_calls == 0
        assert "SECRETVALUE123" not in failure.message, "secrets in tool output must never reach Discord"
        for label in ("Stage:", "Method:", "Exit Status:", "Nginx Test:", "Verification:", "Rollback:", "Next Manual Action:"):
            assert label in failure.message, label
    print("Test 9 (Certbot failure -> SSL_AUTO_REPAIR_FAILED with stage/method/exit status/nginx test/rollback, secrets redacted) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.command_result = CommandResult(None, "", timed_out=True)
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        await run(controller, down_event("SSL_INVALID", 526))
        assert ports.published[0].metadata["exit_status"] == "timeout"
    print("Test 9b (renewal command timeout -> failure alert with exit status 'timeout') PASSED")


async def test_10_successful_repair_recovers_via_existing_lifecycle() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(-3.0), probe(85.0)]
        ports.recheck = RecheckOutcome(healthy=True, last_probe_ok=True, status_text="HTTP 200")
        controller, ports, state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_SUCCESS)]
        assert ports.notes[DOMAIN] is not None, "the recovery note must stay registered for the existing recovery alert"
        assert ports.recheck_calls == [DOMAIN], "verification goes through the website monitor's own state machine"
        assert not ports.categories(), "AutoSSL itself never publishes WEBSITE_RECOVERED (no second recovery engine)"
        results = [a.result for a in ports.audits]
        assert results[0] == "IN_PROGRESS" and results[-1] == RESULT_SUCCESS, results
        assert state.last_result(DOMAIN)["last_result"] == RESULT_SUCCESS
    print("Test 10 (successful repair -> website monitor lifecycle confirms recovery; note registered; audit start+final) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(-3.0), probe(85.0)]
        ports.recheck = RecheckOutcome(healthy=False, last_probe_ok=False, status_text="HTTP 502 Bad Gateway",
                                       condition="http_down", status_code=502)
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_SSL_RECOVERED_STILL_DOWN)], outcomes
        assert ports.diagnosed == [(DOMAIN, "RECOVERED / VALID")]
        assert ports.categories() == ["WEBSITE_STILL_DOWN"]
        assert ports.notes[DOMAIN] is None, "a still-down site must not keep an 'SSL repaired' note for a later recovery"
    print("Test 10b (SSL fixed but website still down -> post-SSL root-cause diagnosis, note cleared) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(-3.0), probe(85.0)]
        ports.recheck = RecheckOutcome(healthy=False, last_probe_ok=True, status_text="HTTP 200")
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_SUCCESS)] and not ports.diagnosed
        assert ports.notes[DOMAIN] is not None
    print("Test 10c (site responding but recovery confirmation pending -> no false 'still down' alert) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(-3.0), probe(-3.0)]
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_FAILED)]
        assert ports.published[0].metadata["stage"] == "verification"
        assert not ports.recheck_calls, "no recovery claim when the certificate is still bad"
    print("Test 10d (renewal 'succeeded' but certificate still expired -> verification failure, no recovery claim) PASSED")


async def test_11_repeated_incident_cooldown() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(-3.0), probe(85.0)]
        controller, ports, _state, clock = make_controller(tmp, ports=ports)
        first = await run(controller, down_event("SSL_INVALID", 526, first_detected_at=NOW - 900))
        assert first == [(DOMAIN, RESULT_SUCCESS)] and len(ports.commands) == 1

        ports.probes = [probe(-3.0), probe(85.0)]
        ports.probe_calls = 0
        clock.t += 600
        again_new_incident = await run(controller, down_event("SSL_INVALID", 526, first_detected_at=clock.t - 30))
        assert again_new_incident == [(DOMAIN, RESULT_SKIPPED_COOLDOWN)], again_new_incident
        reminder = await run(controller, down_event("SSL_INVALID", 526, first_detected_at=NOW - 900, is_reminder=True))
        assert reminder == [(DOMAIN, RESULT_SKIPPED_COOLDOWN)], reminder
        assert len(ports.commands) == 1, "cooldown must prevent any second renewal"

        clock.t += 4000
        same_incident_after_cooldown = await run(controller, down_event("SSL_INVALID", 526, first_detected_at=NOW - 900))
        assert same_incident_after_cooldown == [(DOMAIN, RESULT_SKIPPED_ATTEMPTS)], same_incident_after_cooldown
        assert len(ports.commands) == 1, "one incident must never trigger a renewal loop (max_attempts=1)"

        new_incident_after_cooldown = await run(controller, down_event("SSL_INVALID", 526, first_detected_at=clock.t - 60))
        assert new_incident_after_cooldown == [(DOMAIN, RESULT_SUCCESS)], new_incident_after_cooldown
        assert len(ports.commands) == 2
    print("Test 11 (repeated incident -> per-domain cooldown, per-incident attempt cap, new incident allowed after cooldown) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        cfg = AutoSslConfig(state_path=os.path.join(tmp, "s.json"))
        first_ctrl, ports, state, clock = make_controller(tmp, cfg=cfg)
        ports.command_result = CommandResult(1, "boom")
        await run(first_ctrl, down_event("SSL_INVALID", 526))
        assert len(ports.commands) == 1
        state.save()
        reloaded = AutoSslStateStore(cfg.state_path, clock=clock)
        reloaded.load()
        assert reloaded.gate(DOMAIN, "shopuser:SSL_INVALID@%d" % int(NOW - 900), cfg.cooldown_seconds, 1) == RESULT_SKIPPED_COOLDOWN
        assert reloaded.runtime_enabled is True and reloaded.updated_by == "tester"
    print("Test 11b (cooldown + runtime toggle survive a restart via the persisted state file) PASSED")


async def test_12_autossl_off_disables() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        controller, ports, state, _ = make_controller(tmp)
        assert controller.is_enabled() is True
        await controller.set_enabled(False, "operator#1")
        assert controller.is_enabled() is False and state.updated_by == "operator#1"
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_SKIPPED_DISABLED)] and not ports.commands
        assert controller.schedule(down_event()) is None
    print("Test 12 (/autossl off -> next automatic repair is skipped, override persisted) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(-3.0), probe(85.0)]
        controller, ports, _state, _ = make_controller(tmp, ports=ports)
        await controller._repair_lock.acquire()
        task = asyncio.create_task(run(controller, down_event("SSL_INVALID", 526)))
        await asyncio.sleep(0.05)
        await controller.set_enabled(False, "operator#2")
        controller._repair_lock.release()
        outcomes = await task
        assert outcomes == [(DOMAIN, RESULT_SKIPPED_DISABLED)] and not ports.commands, outcomes
    print("Test 12b (turned off while queued behind another repair -> aborted before any command runs) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        controller, ports, _state, _ = make_controller(tmp)
        started = asyncio.Event()
        finish = asyncio.Event()
        original = ports.run_command

        async def slow_command(argv, timeout):
            started.set()
            await finish.wait()
            return await original(argv, timeout)

        ports.run_command = slow_command
        ports.probes = [probe(-3.0), probe(85.0)]
        task = asyncio.create_task(run(controller, down_event("SSL_INVALID", 526)))
        await started.wait()
        assert controller.repair_in_flight is True
        await controller.set_enabled(False, "operator#3")
        finish.set()
        outcomes = await task
        assert outcomes == [(DOMAIN, RESULT_SUCCESS)], "an in-flight repair must finish safely, not be killed"
    print("Test 12c (/autossl off during an in-flight repair -> that repair finishes safely) PASSED")


def _make_bot(detection_only: bool = False, state_path: Optional[str] = None):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=detection_only), modules=ModulesConfig(),
        cloudflare=CloudflareConfig(enabled=False),
        auto_ssl=AutoSslConfig(state_path=state_path or "/tmp/auto_ssl_test_state.json"),
    )
    disc = DiscordConfig(enabled=True, admin_role_ids=[10], critical_command_role_ids=[20])

    class FakeDb:
        def __init__(self):
            self.actions = []

        def enqueue_action(self, action, result="pending"):
            self.actions.append((action, result))

        def enqueue_incident_create(self, **_k):
            pass

    bot = RTSABot(disc, cfg, EventBus(), db_worker=FakeDb(), supervisor=None)
    return bot


class _Role:
    def __init__(self, role_id): self.id = role_id


class _Followup:
    def __init__(self): self.sent = []
    async def send(self, content=None, *, embed=None, ephemeral=True, **_k): self.sent.append((content, embed))


class _Response:
    def __init__(self): self.sent = []; self.deferred = False
    async def send_message(self, content=None, *, ephemeral=True, **_k): self.sent.append(content)
    async def defer(self, ephemeral=True): self.deferred = True
    def is_done(self): return self.deferred or bool(self.sent)


def _interaction(role_ids, name="tester#0001"):
    member = mock.Mock(spec=discord.Member)
    member.roles = [_Role(r) for r in role_ids]
    member.id = 5
    member.__str__ = mock.Mock(return_value=name)
    interaction = SimpleNamespace(user=member, response=_Response(), followup=_Followup())
    return interaction


async def test_13_unauthorized_command_denied() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bot = _make_bot(state_path=os.path.join(tmp, "s.json"))
        callback = bot.tree.get_command("autossl").callback

        stranger = _interaction([999])
        await callback(stranger, "on")
        assert stranger.response.sent and "Tidak memiliki izin" in stranger.response.sent[0]
        assert bot._auto_ssl.is_enabled() is False and bot._auto_ssl_state.runtime_enabled is None
        assert not bot.db_worker.actions, "a denied command must leave no audit-worthy state change"

        admin_only = _interaction([10])
        await callback(admin_only, "on")
        assert admin_only.response.sent and "Tidak memiliki izin" in admin_only.response.sent[0], (
            "toggling requires the CRITICAL role, an admin-only role is not enough"
        )
        assert bot._auto_ssl.is_enabled() is False

        stranger_off = _interaction([999])
        await callback(stranger_off, "off")
        assert "Tidak memiliki izin" in stranger_off.response.sent[0]

        stranger_status = _interaction([999])
        await callback(stranger_status, None)
        assert "Tidak memiliki izin" in stranger_status.response.sent[0]
    print("Test 13 (unauthorized /autossl on|off|status -> denied, no state change, no audit) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        bot = _make_bot(state_path=os.path.join(tmp, "s.json"))
        callback = bot.tree.get_command("autossl").callback
        boss = _interaction([20])
        await callback(boss, "on")
        assert bot._auto_ssl.is_enabled() is True
        embed = boss.followup.sent[0][1]
        assert "ENABLED" in embed.title
        assert any(a[0]["action_type"] == ActionType.AUTO_SSL_TOGGLE.value or a[0]["action_type"] == ActionType.AUTO_SSL_TOGGLE
                   for a in bot.db_worker.actions)

        viewer = _interaction([10])
        await callback(viewer, None)
        status_embed = viewer.followup.sent[0][1]
        assert "Auto SSL Status" in status_embed.title
        text = " ".join(f"{f.name} {f.value}" for f in status_embed.fields)
        assert "ENABLED" in text and "runtime override" in text

        off = _interaction([20])
        await callback(off, "off")
        assert bot._auto_ssl.is_enabled() is False and "DISABLED" in off.followup.sent[0][1].title
        assert os.path.exists(os.path.join(tmp, "s.json")), "toggle must be persisted"

        blocked_bot = _make_bot(detection_only=True, state_path=os.path.join(tmp, "s2.json"))
        blocked = _interaction([20])
        await blocked_bot.tree.get_command("autossl").callback(blocked, "on")
        assert blocked_bot._auto_ssl.is_enabled() is False, "detection-only mode must refuse to enable auto repair"
    print("Test 13b (authorized toggle persists + audits; status readable by admin; detection-only refuses 'on') PASSED")


async def test_14_defaults_and_safety_rails() -> None:
    cfg = AutoSslConfig()
    assert (cfg.enabled, cfg.dry_run, cfg.max_attempts, cfg.cooldown_seconds) == (False, False, 1, 3600.0)
    assert (cfg.require_confirmed_ssl_failure, cfg.verify_after_repair, cfg.allow_certbot, cfg.allow_cloudpanel_repair) == (
        True, True, True, True)
    print("Test 14 (default config is exactly the specified one; Auto SSL disabled by default) PASSED")

    from config.manager import ConfigManager
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "c.yaml")
        with open(path, "w") as handle:
            handle.write("auto_ssl:\n  cooldown_seconds: 0\n")
        try:
            ConfigManager(path)
        except ConfigValidationError as exc:
            assert "cooldown_seconds" in str(exc)
        else:
            raise AssertionError("cooldown_seconds=0 must be rejected (anti-loop)")
        with open(path, "w") as handle:
            handle.write("auto_ssl:\n  renewal_command: ['bash', '-c', 'echo hi']\n")
        try:
            ConfigManager(path)
        except ConfigValidationError as exc:
            assert "shell" in str(exc)
        else:
            raise AssertionError("a shell interpreter as renewal_command must be rejected")
    print("Test 14b (config validation rejects cooldown<=0 and shell-interpreter commands) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.mutations = False
        controller, ports, _s, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_BLOCKED_DETECTION_ONLY)] and not ports.commands
    print("Test 14c (detection-only mode -> repair blocked, audited, nothing executed) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        controller, ports, _s, _ = make_controller(tmp)
        outcomes = await run(controller, down_event("SSL_INVALID", 526, check_count=1, confirm=3))
        assert outcomes == [(DOMAIN, RESULT_SKIPPED_NOT_CONFIRMED)] and not ports.commands
        lax = AutoSslConfig(state_path=os.path.join(tmp, "l.json"), require_confirmed_ssl_failure=False)
        controller2, ports2, _s2, _ = make_controller(tmp, cfg=lax)
        outcomes = await run(controller2, down_event("SSL_INVALID", 526, check_count=1, confirm=3))
        assert outcomes[0][1] != RESULT_SKIPPED_NOT_CONFIRMED
    print("Test 14d (require_confirmed_ssl_failure gates on the monitor's own confirmation count) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.claimed.add(DOMAIN)
        controller, ports, _s, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_SKIPPED_BUSY)] and not ports.commands
    print("Test 14e (domain busy with another nginx/SSL operation -> single-flight skip) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.blocks = []
        controller, ports, _s, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_BLOCKED)] and not ports.commands
        assert ports.categories() == ["NGINX_VHOST_MISSING"]
        assert f"/newvhost {DOMAIN}" in ports.published[0].message
        assert ports.published[0].metadata["root_cause"] == "VHOST_MISSING"
    print("Test 14f (no vhost for the domain -> STOP, NGINX_VHOST_MISSING with /newvhost action, no repair) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.blocks = [vhost_block("/etc/nginx/sites-enabled/a.conf"), vhost_block("/etc/nginx/sites-enabled/b.conf")]
        controller, ports, _s, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_BLOCKED)] and not ports.commands
        assert "ambiguous" in ports.published[0].metadata["reason"]
    print("Test 14g (domain defined in two nginx files -> ambiguous mapping, STOP) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.asset = None
        controller, ports, _s, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_BLOCKED)] and not ports.commands
        assert ports.published[0].metadata["stage"] == "planning"
        assert "/fixssl" in ports.published[0].metadata["next_action"]
    print("Test 14h (no CloudPanel, no Certbot lineage, no renewal_command -> blocked at planning, never invents a method) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(-3.0)]
        ports.asset = None
        ports.blocks = [vhost_block(cert="/etc/ssl/custom/shop.crt")]
        ports.lineages = (True, [CertbotLineage("other", (DOMAIN,), "/etc/letsencrypt/live/other/fullchain.pem", None, None)], "")
        controller, ports, _s, _ = make_controller(tmp, ports=ports)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_BLOCKED)] and not ports.commands, (
            "a Certbot lineage that does not own the vhost's certificate must not be renewed"
        )
    print("Test 14i (vhost certificate not owned by any Certbot lineage -> Certbot NOT used) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        cfg = AutoSslConfig(state_path=os.path.join(tmp, "d.json"), dry_run=True)
        controller, ports, state, _ = make_controller(tmp, cfg=cfg)
        outcomes = await run(controller, down_event("SSL_INVALID", 526))
        assert outcomes == [(DOMAIN, RESULT_DRY_RUN)] and not ports.commands and ports.reload_calls == 0
        assert ports.categories() == ["SSL_AUTO_REPAIR_DRY_RUN"] and not ports.backups
        entry = state.last_result(DOMAIN)
        assert entry.get("attempts", 0) == 0, "a dry run must not consume the real attempt budget"
        again = await run(controller, down_event("SSL_INVALID", 526))
        assert again == [(DOMAIN, RESULT_SKIPPED_COOLDOWN)], "dry-run reports are rate limited too"
    print("Test 14j (dry_run -> plan reported, nothing executed, attempt budget untouched) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        ports = FakePorts()
        ports.probes = [probe(-3.0), probe(85.0)]
        ports.blocks = [vhost_block()]
        controller, ports, _s, _ = make_controller(tmp, ports=ports)
        multi = down_event("SSL_INVALID", 526, domains=[DOMAIN, "b.example.com", "c.example.com"])
        controller.config
        limited = AutoSslConfig(state_path=os.path.join(tmp, "m.json"), max_domains_per_incident=2)
        controller_limited, ports2, _s2, _ = make_controller(tmp, cfg=limited)
        ports2.blocks = [vhost_block()]
        ports2.probes = [probe(-3.0), probe(85.0)]
        outcomes = await run(controller_limited, multi)
        assert len(outcomes) == 2, "max_domains_per_incident bounds the work done for one incident"
    print("Test 14k (multi-domain incident -> bounded by max_domains_per_incident) PASSED")

    assert "PRIVATE KEY" not in sanitize_output("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")
    assert "Bearer abc" not in sanitize_output("Authorization: Bearer abc123456")
    assert "hunter2" not in sanitize_output("password=hunter2")
    print("Test 14l (output sanitiser strips private keys, bearer tokens and password/token assignments) PASSED")


async def test_15_bus_wiring_and_reload() -> None:
    import discord_integration.bot as bot_module

    with tempfile.TemporaryDirectory() as tmp:
        bot = _make_bot(state_path=os.path.join(tmp, "s.json"))
        fake = FakePorts()

        def real_time_probe(days_left: float) -> OriginTlsProbe:
            now = time.time()
            return OriginTlsProbe(PROBE_OK, host="127.0.0.1", chain_trusted=True, facts=CertificateFacts(
                DOMAIN, "Let's Encrypt (R3)", now - 60 * DAY, now + days_left * DAY, (DOMAIN,)))

        fake.probes = [real_time_probe(-3.0), real_time_probe(85.0)]
        bot._auto_ssl.ports = fake
        await bot._auto_ssl.set_enabled(True, "tester")
        await bot.bus.subscribe(
            bot_module._AUTO_SSL_SUBSCRIBER, bot._on_website_down_for_auto_ssl, categories=[EventCategory.WEBSITE_DOWN],
        )
        try:
            await bot.bus.publish(down_event("BACKEND_DEGRADED", 502))
            await asyncio.sleep(0.15)
            assert not fake.commands and not bot._auto_ssl._tasks, "a plain 502 must not even schedule a task"

            await bot.bus.publish(BaseEvent(
                source_module="website_monitor", category=EventCategory.SERVICE_DOWN, severity=Severity.HIGH,
                message="x", metadata={"root_cause": "SSL_INVALID"},
            ))
            await asyncio.sleep(0.1)
            assert not fake.commands, "only WEBSITE_DOWN events are ever considered"

            await bot.bus.publish(down_event("SSL_INVALID", 526))
            for _ in range(100):
                await asyncio.sleep(0.05)
                if fake.commands and not bot._auto_ssl._tasks:
                    break
            assert len(fake.commands) == 1 and fake.recheck_calls == [DOMAIN]
        finally:
            await bot.bus.unsubscribe(bot_module._AUTO_SSL_SUBSCRIBER)
            await bot._auto_ssl.close()

        assert bot._auto_ssl.config.cooldown_seconds == 3600.0
        reloaded = RTSAConfig(auto_ssl=AutoSslConfig(cooldown_seconds=10.0, state_path=os.path.join(tmp, "s.json")))
        bot.apply_reloaded_config(reloaded)
        assert bot._auto_ssl.config.cooldown_seconds == 10.0, "config hot reload must reach the running controller"
        assert bot._auto_ssl.is_enabled() is True, "the persisted runtime override survives a config reload"
    print("Test 15 (event bus wiring: only eligible WEBSITE_DOWN schedules a repair task; config hot-reload applies) PASSED")


async def main() -> None:
    await test_1_off_is_alert_only()
    await test_2_on_confirmed_failure_repairs()
    await test_3_plain_502_no_certbot()
    await test_4_backend_down_no_certbot()
    await test_5_dns_failure_no_certbot()
    await test_6_cloudflare_525_valid_origin_no_blind_renewal()
    await test_7_expired_certificate_renews()
    await test_8_nginx_test_failure_no_reload_and_rollback()
    await test_9_certbot_failure_alerts()
    await test_10_successful_repair_recovers_via_existing_lifecycle()
    await test_11_repeated_incident_cooldown()
    await test_12_autossl_off_disables()
    await test_13_unauthorized_command_denied()
    await test_14_defaults_and_safety_rails()
    await test_15_bus_wiring_and_reload()
    print("\nALL AUTO SSL TESTS PASSED")


asyncio.run(main())
