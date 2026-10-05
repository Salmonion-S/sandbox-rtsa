import asyncio
import os
import sys
import tempfile
from types import SimpleNamespace

_TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _TESTS)

from _lb_bgp_fakes import DOMAIN, World
from test_lb_bot_commands import interaction, make_bot, resolve_confirmation, run_command
from config.manager import LbDomainConfig
from core.lb_bgp_model import ServiceState
from _lb_bgp_fakes import run_ticks


def attach(bot, world):
    bot.lb_service.bgp = SimpleNamespace(
        orchestrator=world.orchestrator, handles=lambda d: world.status.service_for(d) is not None,
        status=world.status, ports=world.ports,
    )


def fields(embed):
    return {f.name: f.value for f in embed.fields}


async def test_1_mode_selection_and_rbac():
    with tempfile.TemporaryDirectory() as tmp:
        bot, env = make_bot(tmp)
        world = World(tempfile.mkdtemp())
        attach(bot, world)
        assert bot._lb_mode("example.com") == ("bgp_ecmp", "")
        assert bot._lb_mode("example.com --bgp-ecmp") == ("bgp_ecmp", "")
        assert bot._lb_mode("example.com --cloudflare") == ("cloudflare", "")
        assert bot._lb_mode("other.example.net") == ("cloudflare", "")
        assert bot._lb_mode("example.com --bgp-ecmp --cloudflare")[1]
        env.cfg.domains.append(LbDomainConfig(domain=DOMAIN))
        mode, error = bot._lb_mode("example.com")
        assert mode == "" and "dua konfigurasi" in error
        assert bot._lb_mode("example.com --bgp-ecmp") == ("bgp_ecmp", "")
        for name, args in (("genloadbalance", (f"{DOMAIN} --bgp-ecmp", "", False, False, False)), ("addloadbalance", (f"{DOMAIN} --bgp-ecmp", True))):
            for roles in ([999], [10]):
                user = interaction(roles)
                await run_command(bot, name, user, *args)
                assert "Tidak memiliki izin" in user.response.sent[0] and not user.followup.sent, (name, roles)
        user = interaction([999])
        await run_command(bot, "cekloadbalance", user, f"{DOMAIN} --bgp-ecmp")
        assert "Tidak memiliki izin" in user.response.sent[0]
        for name in ("genloadbalance", "addloadbalance", "cekloadbalance"):
            assert len(bot.tree.get_command(name).description) <= 100
    print("Test 1 (mode selection: explicit flags, automatic by configuration, ambiguity refused; the same RBAC as the Cloudflare commands) PASSED")


async def test_2_gen_and_cek_through_discord():
    with tempfile.TemporaryDirectory() as tmp:
        bot, env = make_bot(tmp)
        world = World(tempfile.mkdtemp(), attest=False)
        attach(bot, world)
        await world.node.controller.start()
        user = interaction([20])
        await run_command(bot, "genloadbalance", user, f"{DOMAIN} --bgp-ecmp", "node1 node2", False, False, False)
        embed = user.followup.sent[0].embed
        assert "BGP + ECMP" in embed.title and "DRY RUN" in embed.title and "LOAD BALANCER PLAN" in embed.description
        names = [f.name for f in embed.fields]
        for expected in ("Feasibility checks", "DRY RUN: would create", "Would NOT change", "Reference FRR config (not applied)"):
            assert expected in names, expected
        assert env.cf.calls == [], "the BGP mode never touches Cloudflare"
        assert world.node.speaker.announce_calls == 0
        applied = interaction([20])
        await run_command(bot, "genloadbalance", applied, f"{DOMAIN} --bgp-ecmp", "", False, True, False)
        assert "per node" in fields(applied.followup.sent[0].embed)["Result"]
        bad = interaction([20])
        await run_command(bot, "genloadbalance", bad, f"{DOMAIN} --bgp-ecmp", "node1 10.9.9.9", False, False, False)
        assert "Argumen/konfigurasi tidak valid" in bad.followup.sent[0].embed.description
        worse = interaction([20])
        await run_command(bot, "genloadbalance", worse, f"{DOMAIN} --bgp-ecmp --nuke", "", False, False, False)
        assert "Argumen tidak valid" in worse.followup.sent[0].embed.description
        reader = interaction([10])
        await run_command(bot, "cekloadbalance", reader, f"{DOMAIN} --bgp-ecmp")
        embed = reader.followup.sent[0].embed
        assert "BGP + ECMP" in embed.title and "State ladder" in embed.description and "TRAFFIC_OBSERVED" in embed.description
        none = interaction([10])
        await run_command(bot, "cekloadbalance", none, "unknown.example.org --bgp-ecmp")
        assert "not configured" in none.followup.sent[0].embed.description
    print("Test 2 (Discord: /genloadbalance --bgp-ecmp dry run, per-node apply refusal, hostile input, /cekloadbalance ladder; Cloudflare untouched) PASSED")


async def test_3_addloadbalance_confirmation_flow():
    with tempfile.TemporaryDirectory() as tmp:
        bot, env = make_bot(tmp)
        world = World(tempfile.mkdtemp())
        attach(bot, world)
        await world.node.controller.start()
        for n in ("node2", "node3"):
            world.router.set_advertised(n, True)
        preview = interaction([20])
        await run_command(bot, "addloadbalance", preview, f"{DOMAIN} --bgp-ecmp", False)
        assert "DRY RUN" in preview.followup.sent[0].embed.title and world.node.controller.desired == "DISABLED"
        user = interaction([20])
        task = asyncio.create_task(run_command(bot, "addloadbalance", user, f"{DOMAIN} --bgp-ecmp --apply", False))
        await resolve_confirmation(user, task, "cancel")
        assert world.node.controller.desired == "DISABLED", "cancel changes nothing"
        user = interaction([20])
        task = asyncio.create_task(run_command(bot, "addloadbalance", user, f"{DOMAIN} --bgp-ecmp --apply", False))
        await resolve_confirmation(user, task, "stranger")
        assert world.node.controller.desired == "DISABLED", "only the operator who ran the command can confirm"
        user = interaction([20])
        task = asyncio.create_task(run_command(bot, "addloadbalance", user, f"{DOMAIN} --bgp-ecmp --apply", False))
        await resolve_confirmation(user, task, "confirm")
        assert world.node.controller.desired == "ENABLED" and world.node.speaker.announce_calls == 0
        assert user.edits and "ADD LOAD BALANCE" in user.edits[-1]["embed"].title and user.edits[-1]["embed"].title.endswith("(BGP + ECMP)")
        blocked = World(tempfile.mkdtemp(), apply_enabled=False)
        attach(bot, blocked)
        await blocked.node.controller.start()
        user = interaction([20])
        await run_command(bot, "addloadbalance", user, f"{DOMAIN} --bgp-ecmp --apply", False)
        assert user.followup.sent and "apply_enabled is false" in fields(user.followup.sent[0].embed)["Result"] and user.followup.sent[0].view is None
        assert blocked.node.controller.desired == "DISABLED"
    print("Test 3 (Discord /addloadbalance --apply: preview, cancel, foreign confirm refused, confirm enables; shadow mode never asks) PASSED")


async def test_4_drain_flag_through_discord():
    with tempfile.TemporaryDirectory() as tmp:
        bot, env = make_bot(tmp)
        world = World(tempfile.mkdtemp())
        attach(bot, world)
        await world.node.controller.start()
        await world.node.controller.request_enable("seed")
        for n in ("node2", "node3"):
            world.router.set_advertised(n, True)
        await run_ticks([world.node], 60.0)
        assert world.node.controller.fsm.state == ServiceState.ACTIVE
        user = interaction([20])
        await run_command(bot, "addloadbalance", user, f"{DOMAIN} --bgp-ecmp --drain", False)
        assert "DRY RUN" in user.followup.sent[0].embed.title, "--drain without --apply is only a preview"
        assert world.node.controller.desired == "ENABLED"
        user = interaction([20])
        task = asyncio.create_task(run_command(bot, "addloadbalance", user, f"{DOMAIN} --bgp-ecmp --drain --apply", False))
        await resolve_confirmation(user, task, "confirm")
        assert world.node.controller.desired == "DRAINED"
    print("Test 4 (Discord: --drain is a preview until --apply and a confirmation; then the node drains) PASSED")


async def test_5_existing_cloudflare_path_is_unchanged():
    with tempfile.TemporaryDirectory() as tmp:
        bot, env = make_bot(tmp)
        attach(bot, World(tempfile.mkdtemp()))
        from _lb_fakes import origin_ips

        user = interaction([20])
        await run_command(bot, "genloadbalance", user, "shop.example.net", origin_ips(3), False, False, False)
        assert "DRY RUN" in user.followup.sent[0].embed.title and "BGP" not in user.followup.sent[0].embed.title
        reader = interaction([10])
        await run_command(bot, "cekloadbalance", reader, "shop.example.net")
        assert reader.followup.sent[0].embed.title == "RTSA — LOAD BALANCE STATUS"
    print("Test 5 (domains that are not BGP services still follow the unchanged Cloudflare load balancer path) PASSED")


async def main():
    await test_1_mode_selection_and_rbac()
    await test_2_gen_and_cek_through_discord()
    await test_3_addloadbalance_confirmation_flow()
    await test_4_drain_flag_through_discord()
    await test_5_existing_cloudflare_path_is_unchanged()
    print("\nALL BGP DISCORD COMMAND TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
