from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, List, Optional, Tuple

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import main as main_module
import core.discord_gateway_health as gateway_health_module
from core.datatypes import BaseEvent, EventCategory, Severity
from core.discord_gateway_health import (
    STATE_CONNECTING, STATE_DISCONNECTED, STATE_READY, STATE_RECONNECTING, DiscordGatewayHealth,
)
from core.event_bus import EventBus


class _FakeConfigManager:
    def resolve_secret(self, _env_var: str) -> str:
        return "fake-token-not-real"


class _FakeDiscordConfig:
    bot_token_env_var = "DISCORD_BOT_TOKEN"


class _FakeConfig:
    discord = _FakeDiscordConfig()


class _FakeWebhookDispatcher:
    def __init__(self) -> None:
        self.bot = None
        self.set_bot_calls: List[Any] = []

    def set_bot(self, bot: Any) -> None:
        self.bot = bot
        self.set_bot_calls.append(bot)


class _FakeEngine:

    def __init__(self) -> None:
        self.config_manager = _FakeConfigManager()
        self.config = _FakeConfig()
        self.bus = EventBus()
        self.db_worker = object()
        self.supervisor = object()
        self.webhook_dispatcher = _FakeWebhookDispatcher()
        self._discord_bot_had_failure = False

    async def reload_config(self):
        return {}


class _ScriptedBot:

    instances: List["_ScriptedBot"] = []

    def __init__(self, *args, **kwargs) -> None:
        self._closed = False
        self.close_calls = 0
        self.close_raises: Optional[BaseException] = None
        _ScriptedBot.instances.append(self)

    def is_closed(self) -> bool:
        return self._closed

    def is_ready(self) -> bool:
        return False

    async def start(self, token: str) -> None:
        raise TimeoutError("Gateway connect timed out after 60s")

    async def close(self) -> None:
        self.close_calls += 1
        if self.close_raises is not None:
            exc = self.close_raises
            self._closed = False
            raise exc
        self._closed = True


def _install_fake_bot(monkeypatch_target, bot_cls) -> None:
    import discord_integration.bot as bot_module
    monkeypatch_target["orig"] = bot_module.RTSABot
    bot_module.RTSABot = bot_cls


def _restore_bot(monkeypatch_target) -> None:
    import discord_integration.bot as bot_module
    bot_module.RTSABot = monkeypatch_target["orig"]


async def main() -> None:
    orig_base = main_module._DISCORD_BASE_BACKOFF_SECONDS
    orig_max = main_module._DISCORD_MAX_BACKOFF_SECONDS
    orig_stable = main_module._DISCORD_STABLE_SESSION_SECONDS
    main_module._DISCORD_BASE_BACKOFF_SECONDS = 0.02
    main_module._DISCORD_MAX_BACKOFF_SECONDS = 0.08
    main_module._DISCORD_STABLE_SESSION_SECONDS = 0.05

    try:
        gateway_health_module._health = DiscordGatewayHealth()
        _ScriptedBot.instances = []

        class _CloseAlwaysFailsBot(_ScriptedBot):
            async def close(self) -> None:
                self.close_calls += 1
                raise AttributeError("'NoneType' object has no attribute 'sequence'")

        mp: dict = {}
        _install_fake_bot(mp, _CloseAlwaysFailsBot)
        engine = _FakeEngine()
        component_errors: List[BaseEvent] = []
        await engine.bus.subscribe(
            "sink", lambda e: component_errors.append(e) or asyncio.sleep(0),
            categories=[EventCategory.RTSA_COMPONENT_ERROR],
        )
        task = asyncio.create_task(main_module.RTSAEngine._run_discord_bot(engine))
        await asyncio.sleep(0.3)
        assert not task.done(), (
            "the reconnect loop must still be alive and retrying after several close()-time "
            "exceptions -- if this fails, the exact production bug (silent task death) has regressed"
        )
        assert len(_ScriptedBot.instances) >= 2, (
            f"expected multiple reconnect attempts (new RTSABot instances), got {len(_ScriptedBot.instances)}"
        )
        assert all(b.close_calls >= 1 for b in _ScriptedBot.instances[:-1]), "close() must still be attempted every cycle"
        health = gateway_health_module.get_discord_gateway_health()
        assert health.last_error_type == "TimeoutError", (
            f"the ORIGINAL Gateway timeout must remain the recorded cause, not the close()-time "
            f"AttributeError -- got {health.last_error_type}"
        )
        assert any(e.metadata.get("exception_type") == "TimeoutError" for e in component_errors), component_errors
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=2.0)
        except asyncio.CancelledError:
            pass
        _restore_bot(mp)
        print(
            "Test 1 (KEY FIX: bot.close() raising the exact production secondary AttributeError "
            "never kills the reconnect loop -- it keeps retrying, and the original TimeoutError is "
            "preserved as the recorded root cause) PASSED"
        )

        gateway_health_module._health = DiscordGatewayHealth()
        _ScriptedBot.instances = []

        class _SlowConnectCloseFailsBot(_ScriptedBot):
            async def start(self, token: str) -> None:
                await asyncio.sleep(10.0)

            async def close(self) -> None:
                self.close_calls += 1
                raise AttributeError("'NoneType' object has no attribute 'sequence'")

        mp2: dict = {}
        _install_fake_bot(mp2, _SlowConnectCloseFailsBot)
        engine2 = _FakeEngine()
        task2 = asyncio.create_task(main_module.RTSAEngine._run_discord_bot(engine2))
        await asyncio.sleep(0.05)
        task2.cancel()
        try:
            await asyncio.wait_for(task2, timeout=2.0)
            raised_cancelled = False
        except asyncio.CancelledError:
            raised_cancelled = True
        assert raised_cancelled, (
            "cancelling the reconnect loop must propagate CancelledError cleanly, even when the "
            "cleanup close() call inside `finally` also fails -- it must never be silently swallowed "
            "or replaced by the close()-time exception"
        )
        _restore_bot(mp2)
        print("Test 2 (CancelledError propagates cleanly for clean shutdown, even when cleanup close() also fails) PASSED")

        gateway_health_module._health = DiscordGatewayHealth()
        _ScriptedBot.instances = []
        recorded_delays: List[float] = []
        orig_mark_reconnecting = DiscordGatewayHealth.mark_reconnecting

        def _spy_mark_reconnecting(self, attempt, delay_seconds):
            recorded_delays.append(delay_seconds)
            return orig_mark_reconnecting(self, attempt, delay_seconds)

        DiscordGatewayHealth.mark_reconnecting = _spy_mark_reconnecting

        mp3: dict = {}
        _install_fake_bot(mp3, _ScriptedBot)
        engine3 = _FakeEngine()
        task3 = asyncio.create_task(main_module.RTSAEngine._run_discord_bot(engine3))
        await asyncio.sleep(0.4)
        task3.cancel()
        try:
            await asyncio.wait_for(task3, timeout=2.0)
        except asyncio.CancelledError:
            pass
        DiscordGatewayHealth.mark_reconnecting = orig_mark_reconnecting
        _restore_bot(mp3)

        assert len(recorded_delays) >= 3, recorded_delays
        assert len(set(recorded_delays)) > 1, (
            f"successive backoff delays must not be identical -- jitter is missing, got {recorded_delays}"
        )
        base = main_module._DISCORD_BASE_BACKOFF_SECONDS
        maxd = main_module._DISCORD_MAX_BACKOFF_SECONDS
        expected_deterministic = base
        for d in recorded_delays:
            lower = expected_deterministic * 0.80
            upper = min(expected_deterministic, maxd) * 1.20
            assert lower <= d <= upper, (
                f"jittered delay {d} outside the expected +/-15%% band around {expected_deterministic} "
                f"(bounded at max {maxd})"
            )
            expected_deterministic = min(expected_deterministic * 2, maxd)
        print(
            "Test 3 (reconnect backoff is jittered -- successive delays differ, but each stays within "
            "the +/-15% band around the deterministic exponential progression, bounded at max backoff) PASSED"
        )

        gateway_health_module._health = DiscordGatewayHealth()
        _ScriptedBot.instances = []
        call_count = {"n": 0}

        class _StableAfterTwoFailuresBot(_ScriptedBot):
            async def start(self, token: str) -> None:
                call_count["n"] += 1
                if call_count["n"] <= 2:
                    raise TimeoutError("Gateway connect timed out after 60s")
                await asyncio.sleep(main_module._DISCORD_STABLE_SESSION_SECONDS * 3)
                raise TimeoutError("Gateway connect timed out after 60s")

        mp4: dict = {}
        _install_fake_bot(mp4, _StableAfterTwoFailuresBot)
        engine4 = _FakeEngine()
        recovered_events: List[BaseEvent] = []
        await engine4.bus.subscribe(
            "sink2", lambda e: recovered_events.append(e) or asyncio.sleep(0),
            categories=[EventCategory.RTSA_COMPONENT_RECOVERED],
        )
        recorded_delays4: List[float] = []
        DiscordGatewayHealth.mark_reconnecting = _spy_mark_reconnecting_factory = (
            lambda self, attempt, delay_seconds: (recorded_delays4.append(delay_seconds), orig_mark_reconnecting(self, attempt, delay_seconds))[1]
        )
        task4 = asyncio.create_task(main_module.RTSAEngine._run_discord_bot(engine4))
        await asyncio.sleep(main_module._DISCORD_STABLE_SESSION_SECONDS * 6)
        task4.cancel()
        try:
            await asyncio.wait_for(task4, timeout=2.0)
        except asyncio.CancelledError:
            pass
        DiscordGatewayHealth.mark_reconnecting = orig_mark_reconnecting
        _restore_bot(mp4)

        assert len(recorded_delays4) >= 3, recorded_delays4
        assert recorded_delays4[0] < recorded_delays4[1], "backoff must grow across the first two failures"
        post_stable_delay = recorded_delays4[-1]
        assert post_stable_delay <= main_module._DISCORD_BASE_BACKOFF_SECONDS * 1.20, (
            f"backoff must reset to base after a session survives the stable threshold, got {post_stable_delay}"
        )
        assert len(recovered_events) == 1, recovered_events
        print(
            "Test 4 (a session surviving the stable-session threshold resets backoff to base and "
            "fires exactly one RTSA_COMPONENT_RECOVERED event) PASSED"
        )
    finally:
        main_module._DISCORD_BASE_BACKOFF_SECONDS = orig_base
        main_module._DISCORD_MAX_BACKOFF_SECONDS = orig_max
        main_module._DISCORD_STABLE_SESSION_SECONDS = orig_stable

    gateway_health_module._health = DiscordGatewayHealth()
    from discord_integration.bot import RTSABot

    class _FakeUser:
        def __str__(self) -> str:
            return "RTSA#1234"

    class _FakeBotInstance:
        pass

    bot_instance = _FakeBotInstance()
    bot_instance.user = _FakeUser()
    bot_instance.guilds = [object(), object()]
    bot_instance.config = _FakeDiscordConfig()
    bot_instance.config.alert_channel_id = None
    bot_instance.config.category_channels = {}

    await RTSABot.on_ready(bot_instance)
    health = gateway_health_module.get_discord_gateway_health()
    assert health.state == STATE_READY
    assert health.bot_user == "RTSA#1234" and health.guild_count == 2
    print("Test 5a (on_ready marks gateway health READY with bot user + guild count) PASSED")

    await RTSABot.on_disconnect(bot_instance)
    assert gateway_health_module.get_discord_gateway_health().state == STATE_DISCONNECTED
    print("Test 5b (on_disconnect marks gateway health DISCONNECTED) PASSED")

    await RTSABot.on_resumed(bot_instance)
    assert gateway_health_module.get_discord_gateway_health().state == STATE_READY
    print("Test 5c (on_resumed marks gateway health READY again -- a resumed session, not a full reconnect) PASSED")

    from discord_integration.webhook import DiscordWebhookDispatcher
    from config.manager import DiscordConfig

    gateway_health_module._health = DiscordGatewayHealth()
    gateway_health_module.get_discord_gateway_health().mark_reconnecting(3, 20.0)
    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig(enabled=True, alert_channel_id=1), detection_only=False)
    snap = dispatcher.get_outbound_health()
    assert snap["bot_present"] is False
    assert snap["bot_ready"] is False
    assert snap["gateway_state"] == STATE_RECONNECTING
    assert snap["gateway_reconnect_count"] == 3
    print("Test 6 (get_outbound_health() exposes REST-independent Gateway state -- bot_present/bot_ready/gateway_state distinct) PASSED")

    main_source = open("main.py").read()
    load_modules_idx = main_source.index("await self._load_modules()")
    bot_task_idx = main_source.index("self.discord_bot_task = asyncio.create_task")
    assert load_modules_idx < bot_task_idx, (
        "RTSA modules must be loaded BEFORE the Discord bot task starts -- startup must never block on Discord"
    )
    print("Test 7 (RTSA module loading happens before the Discord bot task is created -- startup never blocks on Discord) PASSED")

    error_reporting_source = open("core/error_reporting.py").read()
    assert "_run_discord_bot" not in error_reporting_source
    assert "RTSABot" not in error_reporting_source
    assert "bot.start(" not in error_reporting_source
    print("Test 8 (component-error reporting never calls back into the Discord bot/reconnect loop -- no recursive offline-alert loop) PASSED")

    import subprocess
    grep = subprocess.run(
        ["grep", "-rn", "class RTSABot(discord", "discord_integration/", "modules/", "core/"],
        capture_output=True, text=True, cwd=_REPO_ROOT,
    )
    matches = [line for line in grep.stdout.splitlines() if line.strip()]
    assert len(matches) == 1, f"expected exactly one discord.Client subclass, found: {matches}"
    print("Test 9 (exactly one Discord bot/Gateway lifecycle class exists in the codebase) PASSED")

    print("\nALL DISCORD GATEWAY RECONNECT TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
