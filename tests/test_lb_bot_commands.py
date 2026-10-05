from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

_TESTS = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_TESTS)
sys.path.insert(0, _TESTS)
sys.path.insert(0, _REPO)
os.chdir(_REPO)

import discord
from aiohttp import web

from _lb_fakes import DOMAIN, Env, make_config, make_report, origin_ips
from config.manager import CloudflareConfig, DiscordConfig, ResponseEngineConfig, RTSAConfig
from core.datatypes import ActionType
from core.event_bus import EventBus
from core.lb_cloudflare import CfGateway
from core.lb_model import OpStatus
from core.lb_state import LbStateStore
from discord_integration.bot import RTSABot


class FakeDb:
    def __init__(self) -> None:
        self.actions = []

    def enqueue_action(self, action, result="pending"):
        self.actions.append((action, result))

    def enqueue_incident_create(self, **_k):
        pass


class _Role:
    def __init__(self, role_id):
        self.id = role_id


class _Resp:
    def __init__(self):
        self.sent = []
        self.deferred = False

    async def send_message(self, content=None, **_k):
        self.sent.append(content)

    async def defer(self, ephemeral=True):
        self.deferred = True


class _Follow:
    def __init__(self):
        self.sent = []

    async def send(self, content=None, *, embed=None, view=None, ephemeral=True, **_k):
        self.sent.append(SimpleNamespace(content=content, embed=embed, view=view))


def interaction(role_ids, user_id=7):
    member = mock.Mock(spec=discord.Member)
    member.id = user_id
    member.roles = [_Role(r) for r in role_ids]
    member.__str__ = mock.Mock(return_value="tester#1")
    edits = []

    async def edit_original_response(**kw):
        edits.append(kw)

    return SimpleNamespace(user=member, response=_Resp(), followup=_Follow(), edit_original_response=edit_original_response, edits=edits)


def make_bot(tmp: str, n: int = 3, **cfg_kwargs):
    cfg = RTSAConfig(cloudflare=CloudflareConfig(enabled=False), response_engine=ResponseEngineConfig(detection_only=False))
    bot = RTSABot(DiscordConfig(enabled=True, admin_role_ids=[10], critical_command_role_ids=[20]), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)
    env = Env(n, state_dir=tmp, cfg=make_config(n, **cfg_kwargs))
    ctx = bot.lb_service.ctx
    ctx.cfg = env.cfg
    ctx.ports = env.ports
    ctx.gateway = CfGateway(env.cf, env.metrics, 4)
    ctx.store = env.store
    ctx.metrics = env.metrics
    ctx.locks = env.ctx.locks
    bot.lb_service.store = env.store
    bot.lb_service.ports = env.ports
    return bot, env


async def run_command(bot, name, user, *args):
    command = bot.tree.get_command(name)
    await command.callback(user, *args)


async def test_1_registration_and_rbac() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bot, env = make_bot(tmp)
        for name in ("genloadbalance", "addloadbalance", "cekloadbalance", "dbgenbalance"):
            command = bot.tree.get_command(name)
            assert command is not None and 0 < len(command.description) <= 100, name
        params = {p.name for p in bot.tree.get_command("genloadbalance").parameters}
        assert {"domain", "origins", "dry_run", "apply", "prune"} <= params
        mutation_calls = {
            "genloadbalance": (DOMAIN, origin_ips(3), False, True, False), "addloadbalance": (DOMAIN, True), "dbgenbalance": (DOMAIN, ""),
        }
        for name, args in mutation_calls.items():
            for roles, label in (([999], "stranger"), ([10], "admin without critical role")):
                user = interaction(roles)
                await run_command(bot, name, user, *args)
                assert "Tidak memiliki izin" in user.response.sent[0] and not user.followup.sent, (name, label)
        assert env.cf.calls == [] and env.ports.prepare_calls == [], "unauthorized callers reach nothing"
        stranger = interaction([999])
        await run_command(bot, "cekloadbalance", stranger, DOMAIN)
        assert "Tidak memiliki izin" in stranger.response.sent[0]
        reader = interaction([10])
        await run_command(bot, "cekloadbalance", reader, DOMAIN)
        assert reader.followup.sent and reader.followup.sent[0].embed.title == "RTSA — LOAD BALANCE STATUS"
        assert env.cf.mutations() == [], "/cekloadbalance is read-only"
    print("Test 1 (four commands registered within Discord limits; mutation commands need the critical role, /cekloadbalance the normal admin role) PASSED")


async def test_2_genloadbalance_dry_run_is_default() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bot, env = make_bot(tmp)
        user = interaction([20])
        await run_command(bot, "genloadbalance", user, DOMAIN, origin_ips(3), False, False, False)
        embed = user.followup.sent[0].embed
        assert "DRY RUN" in embed.title and user.followup.sent[0].view is None
        names = [f.name for f in embed.fields]
        for expected in ("Current state", "Cloudflare changes", "Origin changes", "DATABASE changes", "NGINX changes", "Risk", "Rollback plan"):
            assert expected in names, expected
        assert env.cf.mutations() == [], "no apply flag: the default is a plan only"
        both = interaction([20])
        await run_command(bot, "genloadbalance", both, DOMAIN, origin_ips(3), True, True, False)
        assert "DRY RUN" in both.followup.sent[0].embed.title and env.cf.mutations() == [], "--dry-run wins over --apply"
        flagged = interaction([20])
        await run_command(bot, "genloadbalance", flagged, f"{DOMAIN} --dry-run", origin_ips(3), False, True, False)
        assert "DRY RUN" in flagged.followup.sent[0].embed.title and env.cf.mutations() == []
        invalid = interaction([20])
        calls_before = len(env.cf.calls)
        await run_command(bot, "genloadbalance", invalid, DOMAIN, f"{origin_ips(3)} --nuke", False, False, False)
        assert "tidak valid" in invalid.followup.sent[0].embed.description and len(env.cf.calls) == calls_before
        hostile = interaction([20])
        await run_command(bot, "genloadbalance", hostile, DOMAIN, "169.254.169.254 127.0.0.1", False, False, False)
        assert "BLOCKED" in " ".join(f.value for f in hostile.followup.sent[0].embed.fields)
        assert env.ports.tcp_calls == 9, "only the three legitimate dry runs probed their 3 origins each; hostile targets were never probed"
        assert env.store.last_audit()["kind"] == "genloadbalance"
    print("Test 2 (/genloadbalance without apply is a dry run; --dry-run beats --apply; unknown flags and hostile targets are refused) PASSED")


async def resolve_confirmation(user, task, press) -> None:
    for _ in range(200):
        if user.followup.sent and user.followup.sent[-1].view is not None:
            break
        await asyncio.sleep(0.01)
    view = user.followup.sent[-1].view
    assert view is not None, "the apply path must show the existing Confirm/Cancel view"
    assert view.timeout is not None and view.timeout > 0
    if press == "confirm":
        await view.confirm.callback(user)
    elif press == "cancel":
        await view.cancel.callback(user)
    elif press == "stranger":
        other = interaction([20], user_id=999)
        assert await view.interaction_check(other) is False
        await view.cancel.callback(user)
    await task


async def test_3_apply_requires_confirmation_button() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bot, env = make_bot(tmp)
        user = interaction([20])
        task = asyncio.create_task(run_command(bot, "genloadbalance", user, DOMAIN, origin_ips(3), False, True, False))
        await resolve_confirmation(user, task, "cancel")
        assert env.cf.mutations() == [] and "tidak ada mutation" in user.edits[-1]["content"]
        timed_out = interaction([20])
        bot.lb_service.ctx.cfg = make_config(3, confirmation_ttl_seconds=0.05)
        task = asyncio.create_task(run_command(bot, "genloadbalance", timed_out, DOMAIN, origin_ips(3), False, True, False))
        for _ in range(200):
            if timed_out.followup.sent and timed_out.followup.sent[-1].view is not None:
                break
            await asyncio.sleep(0.01)
        timed_out.followup.sent[-1].view._start_listening_from_store(SimpleNamespace(remove_view=lambda view: None))
        await asyncio.wait_for(task, timeout=5.0)
        assert env.cf.mutations() == [] and "kadaluarsa" in timed_out.edits[-1]["content"], "an unanswered confirmation expires without any mutation"
        bot.lb_service.ctx.cfg = make_config(3)
        guarded = interaction([20])
        task = asyncio.create_task(run_command(bot, "genloadbalance", guarded, DOMAIN, origin_ips(3), False, True, False))
        await resolve_confirmation(guarded, task, "stranger")
        assert env.cf.mutations() == [], "only the operator who ran the command can confirm"
        confirmed = interaction([20])
        task = asyncio.create_task(run_command(bot, "genloadbalance", confirmed, DOMAIN, origin_ips(3), False, True, False))
        await resolve_confirmation(confirmed, task, "confirm")
        final = confirmed.edits[-1]["embed"]
        assert final.title == "RTSA — LOAD BALANCE APPLIED", final.title
        assert (len(env.cf.monitors), len(env.cf.pools), len(env.cf.lbs)) == (1, 1, 1)
        again = interaction([20])
        await run_command(bot, "genloadbalance", again, DOMAIN, origin_ips(3), False, True, False)
        assert again.followup.sent[0].embed.title == "RTSA — LOAD BALANCE UP TO DATE" and again.followup.sent[0].view is None, "an already-applied state needs no confirmation"
        assert bot.db_worker.actions == [], "the fake ports are used in this test; BotLbPorts.audit is covered separately"
    print("Test 3 (--apply shows the existing Confirm/Cancel view; cancel, timeout and a stranger's click change nothing; confirm applies once) PASSED")


async def test_4_apply_blocked_states_need_no_confirmation_and_change_nothing() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bot, env = make_bot(tmp)
        env.cf.dns.append({"id": "d1", "name": DOMAIN, "type": "A", "content": "198.51.100.7", "proxied": True})
        user = interaction([20])
        await run_command(bot, "genloadbalance", user, DOMAIN, origin_ips(3), False, True, False)
        sent = user.followup.sent[0]
        assert sent.view is None and "DNS_CONFLICT" in " ".join(f.value for f in sent.embed.fields)
        assert env.cf.mutations() == []
        env.cf.dns.clear()
        detect = interaction([20])
        bot._detection_only = lambda: True
        task = asyncio.create_task(run_command(bot, "genloadbalance", detect, DOMAIN, origin_ips(3), False, True, False))
        await resolve_confirmation(detect, task, "confirm")
        assert env.cf.mutations() == []
        assert "detection" in str(detect.edits[-1].get("content")).lower()
    print("Test 4 (blocked plans show the blocker without a confirm button; detection-only mode refuses to mutate even after confirmation) PASSED")


async def test_5_addloadbalance_and_dbgenbalance_commands() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bot, env = make_bot(tmp)
        env.ports.local_report_factory = lambda domain, op: make_report("server1", vhost_state="PRESENT" if env.ports.prepare_calls else "MISSING", blockers=[] if env.ports.prepare_calls else ["NGINX_VHOST_MISSING"])
        dry = interaction([20])
        await run_command(bot, "addloadbalance", dry, DOMAIN, False)
        embed = dry.followup.sent[0].embed
        assert "DRY RUN" in embed.title and env.ports.prepare_calls == [] and env.cf.calls == []
        names = [f.name for f in embed.fields]
        assert "Local origin" in names and "Desired vs actual" in names and "Planned actions" in names and "Cloudflare" in names
        user = interaction([20])
        task = asyncio.create_task(run_command(bot, "addloadbalance", user, DOMAIN, True))
        await resolve_confirmation(user, task, "cancel")
        assert env.ports.prepare_calls == [] and "tidak ada mutation" in user.edits[-1]["content"]
        confirmed = interaction([20])
        task = asyncio.create_task(run_command(bot, "addloadbalance", confirmed, DOMAIN, True))
        await resolve_confirmation(confirmed, task, "confirm")
        assert env.ports.prepare_calls == [False] and env.cf.calls == []
        assert confirmed.edits[-1]["embed"].title == "RTSA — ADD LOAD BALANCE"
        assert len(env.ports.published_reports) == 1
        db = interaction([20])
        await run_command(bot, "dbgenbalance", db, DOMAIN, "")
        assert db.followup.sent[0].embed.title == "RTSA — DATABASE BALANCE REPORT"
        assert any("DB connectivity is not DB load balancing" in f.value for f in db.followup.sent[0].embed.fields)
        bad = interaction([20])
        await run_command(bot, "dbgenbalance", bad, "../../etc", "")
        assert "tidak valid" in str(bad.followup.sent[0].embed.description) or bad.followup.sent[0].embed.fields
        multi = interaction([20])
        await run_command(bot, "dbgenbalance", multi, DOMAIN, "MULTI_PRIMARY")
        assert any("MULTI_PRIMARY" in f.value for f in multi.followup.sent[0].embed.fields)
    print("Test 5 (/addloadbalance dry-run/confirm/apply never touches Cloudflare; /dbgenbalance reports DB architecture and refuses nothing silently) PASSED")


async def test_6_cekloadbalance_command_output() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bot, env = make_bot(tmp)
        orchestrator = bot.lb_service.orchestrator
        result = await orchestrator.genloadbalance(DOMAIN, origin_ips(3), operator="t", apply=True, confirmed=True)
        assert result.status == OpStatus.SUCCESS
        env.cf.unhealthy_addresses.add("203.0.113.13")
        bot.lb_service.monitor.invalidate(DOMAIN)
        env.ports.mono += 100
        user = interaction([10])
        await run_command(bot, "cekloadbalance", user, DOMAIN)
        embed = user.followup.sent[0].embed
        text = embed.description
        assert "Server1 203.0.113.11 -> HEALTHY / SERVING" in text and "Server3 203.0.113.13 -> UNHEALTHY / NOT SERVING" in text
        assert "Overall: DEGRADED" in text and embed.color.value == 0xF39C12
        invalid = interaction([10])
        await run_command(bot, "cekloadbalance", invalid, "../../x")
        assert "Domain tidak valid" in invalid.followup.sent[0].embed.description
        unknown = interaction([10])
        await run_command(bot, "cekloadbalance", unknown, "other.example.com")
        assert "NOT_CONFIGURED" in unknown.followup.sent[0].embed.description
    print("Test 6 (/cekloadbalance renders per-server status, colours DEGRADED, rejects hostile domains, reports unmanaged domains as NOT_CONFIGURED) PASSED")


async def test_7_audit_mapping_and_lifecycle() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bot = RTSABot(DiscordConfig(enabled=True, admin_role_ids=[10], critical_command_role_ids=[20]), RTSAConfig(cloudflare=CloudflareConfig(enabled=False)),
                      EventBus(), db_worker=FakeDb(), supervisor=None)
        ports = bot.lb_service.ports
        for kind, expected in (("genloadbalance", ActionType.GENLOADBALANCE), ("addloadbalance", ActionType.ADDLOADBALANCE), ("dbgenbalance", ActionType.DBGENBALANCE)):
            ports.audit({"kind": kind, "domain": DOMAIN, "operator": "tester#1", "ok": True, "status": "SUCCESS", "dry_run": False, "operation_id": "abc", "rollback": "NOT APPLICABLE", "previous_state": "x"})
            action, result = bot.db_worker.actions[-1]
            assert action["action_type"] in (expected, expected.value) and result == "SUCCESS" and action["target"] == DOMAIN
        ports.audit({"kind": "genloadbalance", "domain": DOMAIN, "operator": "t", "ok": False, "status": "ROLLED_BACK", "dry_run": False, "operation_id": "abc", "rollback": "COMPLETE", "previous_state": "x"})
        assert bot.db_worker.actions[-1][1] == "FAILED:ROLLED_BACK"
        events = []
        bot.bus.publish_nowait = events.append
        from core.datatypes import BaseEvent, EventCategory, Severity

        ports.publish(BaseEvent(source_module="load_balancer", category=EventCategory.LB_ORIGIN_DOWN, severity=Severity.HIGH, message="x"))
        assert events and events[0].category == EventCategory.LB_ORIGIN_DOWN
        assert ports.mutations_allowed() == (not bot._detection_only()), "mutations follow the global detection-only switch"
        service = bot.lb_service
        assert service._task is None
        await service.start()
        assert service._task is None, "load_balancing.enabled=false starts no poller"
        enabled_cfg = make_config(3)
        service.apply_config(enabled_cfg)
        service.ctx.store = LbStateStore(os.path.join(tmp, "s.json"))
        service.orchestrator.ctx = service.ctx
        await service.start()
        assert service._task is not None and not service._task.done()
        await service.stop()
        assert service._task is None
        from config.manager import RTSAConfig as _Cfg

        new = _Cfg(cloudflare=CloudflareConfig(enabled=False))
        bot.apply_reloaded_config(new)
        assert service.ctx.cfg is new.load_balancing
    print("Test 7 (audit ActionTypes GENLOADBALANCE/ADDLOADBALANCE/DBGENBALANCE, event publishing through the bus, poller only when enabled, hot reload) PASSED")


async def make_http_server():
    seen = []

    async def health(request):
        seen.append(request.headers.get("Host"))
        return web.Response(text='{"status":"ok"}')

    async def leak(request):
        return web.Response(text="DB_PASSWORD=hunter2hunter2\nAPP_KEY=abc")

    async def redirect(request):
        raise web.HTTPFound("/healthz")

    async def broken(request):
        return web.Response(status=502, text="bad gateway")

    app = web.Application()
    app.router.add_get("/healthz", health)
    app.router.add_get("/leak", leak)
    app.router.add_get("/redir", redirect)
    app.router.add_get("/broken", broken)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port, seen


async def test_8_real_probes_are_ssrf_safe_and_classify_responses() -> None:
    bot = RTSABot(DiscordConfig(enabled=True), RTSAConfig(cloudflare=CloudflareConfig(enabled=False)), EventBus(), db_worker=FakeDb(), supervisor=None)
    ports = bot.lb_service.ports
    runner, port, seen = await make_http_server()
    try:
        for target in ("127.0.0.1", "169.254.169.254", "0.0.0.0", "::1"):
            tcp = await ports.tcp_probe(target, port, 1.0)
            assert not tcp.ok and "FORBIDDEN_TARGET" in tcp.reason, target
            http = await ports.http_probe(target, port, "http", DOMAIN, "/healthz", 1.0, True)
            assert not http.ok and "FORBIDDEN_TARGET" in http.reason and http.status is None, target
            tls = await ports.tls_probe(target, port, DOMAIN, 1.0)
            assert not tls.ok and "FORBIDDEN_TARGET" in tls.detail
        assert seen == [], "a forbidden target is never contacted"
        ok = await ports.http_probe("127.0.0.1", port, "http", DOMAIN, "/healthz", 2.0, True, loopback_ok=True)
        assert ok.ok and ok.status == 200 and ok.latency_ms is not None and not ok.leak
        assert seen == [f"{DOMAIN}:{port}"], "the probe sends the domain Host header, not the origin address"
        leak = await ports.http_probe("127.0.0.1", port, "http", DOMAIN, "/leak", 2.0, True, loopback_ok=True)
        assert not leak.ok and leak.leak == "credential" and leak.status == 200, "a 200 that exposes secrets is unhealthy"
        redirect = await ports.http_probe("127.0.0.1", port, "http", DOMAIN, "/redir", 2.0, True, loopback_ok=True)
        assert not redirect.ok and redirect.status == 302, "redirects are not followed"
        broken = await ports.http_probe("127.0.0.1", port, "http", DOMAIN, "/broken", 2.0, True, loopback_ok=True)
        assert not broken.ok and broken.status == 502
        refused = await ports.http_probe("127.0.0.1", 1, "http", DOMAIN, "/healthz", 1.0, True, loopback_ok=True)
        assert not refused.ok and refused.status is None
        loop = asyncio.get_running_loop()

        async def evil_dns(host, port, **kw):
            return [(2, 1, 6, "", ("169.254.169.254", port))]

        async def loopback_dns(host, port, **kw):
            return [(2, 1, 6, "", ("127.0.0.1", port))]

        for resolver in (evil_dns, loopback_dns):
            with mock.patch.object(loop, "getaddrinfo", resolver):
                tcp = await ports.tcp_probe("origin.example.net", port, 1.0)
                assert not tcp.ok and "FORBIDDEN_TARGET" in tcp.reason, "a hostname that resolves to a forbidden address is never dialled"
                http = await ports.http_probe("origin.example.net", port, "http", DOMAIN, "/healthz", 1.0, True)
                assert not http.ok and "FORBIDDEN_TARGET" in http.reason
                tls = await ports.tls_probe("origin.example.net", port, DOMAIN, 1.0)
                assert not tls.ok and "FORBIDDEN_TARGET" in tls.detail
        assert seen == [f"{DOMAIN}:{port}"], "nothing new was contacted"
        assert ports.local_server_id() == "" or isinstance(ports.local_server_id(), str)
        assert (await ports.resolve_dns("no-such-host.invalid", 1.0)) == []
        assert ports.report_key() is None
        with mock.patch.dict(os.environ, {bot.lb_service.ctx.cfg.report_key_env_var: "k" * 32}):
            assert ports.report_key() == b"k" * 32
        with mock.patch.dict(os.environ, {bot.lb_service.ctx.cfg.report_key_env_var: "short"}):
            assert ports.report_key() is None, "a short key is not accepted"
    finally:
        await runner.cleanup()
    print("Test 8 (real probes: loopback/link-local/unspecified targets are never contacted; Host header is the domain; leaks, redirects and 5xx are unhealthy) PASSED")


async def main() -> None:
    for test in (
        test_1_registration_and_rbac, test_2_genloadbalance_dry_run_is_default, test_3_apply_requires_confirmation_button,
        test_4_apply_blocked_states_need_no_confirmation_and_change_nothing, test_5_addloadbalance_and_dbgenbalance_commands,
        test_6_cekloadbalance_command_output, test_7_audit_mapping_and_lifecycle, test_8_real_probes_are_ssrf_safe_and_classify_responses,
    ):
        await test()
    print("\nALL LOAD BALANCER BOT COMMAND TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
