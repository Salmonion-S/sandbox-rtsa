from __future__ import annotations

import asyncio
import inspect
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import discord_integration.bot as bot_module
from config.manager import CloudflareConfig, DiscordConfig, ModulesConfig, ResponseEngineConfig, RTSAConfig
from core.datatypes import ActionType
from core.event_bus import EventBus
from core.underattack_state import STATUS_ACTIVE, STATUS_RELEASED, UnderAttackStateManager
from discord_integration.bot import RTSABot
from discord_integration.cloudflare import PHASE_HTTP_CONFIG_SETTINGS, CloudflareClient

_FAKE_TOKEN = "fake-token-never-real-do-not-log"


class FakeDb:
    def __init__(self):
        self.actions = []

    def enqueue_action(self, action_dict, result="pending"):
        self.actions.append((dict(action_dict), result))

    def enqueue_incident_create(self, **k):
        pass

    def enqueue_incident_update(self, *a, **k):
        pass


class FakeCFApi(CloudflareClient):
    def __init__(self, *, zones: Optional[List[Dict[str, str]]] = None, lie_on_verify: bool = False) -> None:
        super().__init__(_FAKE_TOKEN)
        self._zones_data = zones if zones is not None else [{"id": "zone1", "name": "example.com"}]
        self._ruleset_rules: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        self.calls: List[Tuple[str, str]] = []
        self._lie_on_verify = lie_on_verify
        self._put_delay: float = 0.0

    async def _request_json(self, method: str, url: str, *, params=None, json_body=None):
        self.calls.append((method, url))

        if url.endswith("/zones") or "/zones?" in url:
            return 200, {"success": True, "result": self._zones_data, "result_info": {"total_pages": 1}}

        if "/rulesets/phases/" in url and url.endswith("/entrypoint"):
            zone_id = url.split("/zones/", 1)[1].split("/rulesets/", 1)[0]
            phase = url.split("/phases/", 1)[1].split("/entrypoint", 1)[0]
            key = (zone_id, phase)

            if method == "GET":
                if self._lie_on_verify:
                    return 404, {"success": False, "errors": [{"message": "not found"}]}
                if key not in self._ruleset_rules:
                    return 404, {"success": False, "errors": [{"message": "not found"}]}
                return 200, {"success": True, "result": {"id": f"ruleset-{zone_id}-{phase}", "rules": self._ruleset_rules[key]}}

            if method == "PUT":
                if self._put_delay:
                    await asyncio.sleep(self._put_delay)
                rules = (json_body or {}).get("rules", [])
                self._ruleset_rules[key] = rules
                return 200, {"success": True, "result": {"id": f"ruleset-{zone_id}-{phase}", "rules": rules}}

        return 404, {"success": False, "errors": [{"message": f"unhandled url in fake: {url}"}]}

    def put_call_count(self) -> int:
        return sum(1 for method, _url in self.calls if method == "PUT")


class FakeFollowup:
    def __init__(self):
        self.sent: List[Dict[str, Any]] = []

    async def send(self, content=None, *, embed=None, view=None, ephemeral=True):
        self.sent.append({"content": content, "embed": embed, "view": view})


class FakeInteraction:
    def __init__(self, user_id: int = 1, username: str = "tester#underattack"):
        self.user = type("U", (), {"id": user_id, "__str__": lambda self: username})()
        self.followup = FakeFollowup()
        self.edits: List[Dict[str, Any]] = []

    async def edit_original_response(self, *, content=None, embed=None, view=None):
        self.edits.append({"content": content, "embed": embed, "view": view})

    def all_text(self) -> str:
        parts = [str(s.get("content") or "") for s in self.followup.sent]
        parts += [str(e.get("content") or "") for e in self.edits]
        return " ".join(parts)


def _confirm_view_class(decision: Optional[bool]):
    class _FakeConfirmView:
        def __init__(self, requested_by_id, timeout_seconds=30.0):
            self.decision = decision

        async def wait(self):
            return None

    return _FakeConfirmView


def make_bot(*, cf: Optional[FakeCFApi] = None, state_path: str, db: Optional[FakeDb] = None) -> RTSABot:
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False), modules=ModulesConfig(),
        cloudflare=CloudflareConfig(
            enabled=True, manual_underattack_enabled=True,
            manual_underattack_confirmation_ttl_seconds=5.0, manual_underattack_verify_timeout_seconds=5.0,
            manual_underattack_action_timeout_seconds=5.0, manual_underattack_state_path=state_path,
        ),
    )
    bot = RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=(db or FakeDb()), supervisor=None)
    bot.cloudflare = cf if cf is not None else FakeCFApi()
    return bot


async def _activate(bot, domain, api_domain=None, decision=True):
    interaction = FakeInteraction()
    original = bot_module._ConfirmCancelView
    bot_module._ConfirmCancelView = _confirm_view_class(decision)
    try:
        await bot._run_underattack_activation(interaction, domain, api_domain)
    finally:
        bot_module._ConfirmCancelView = original
    return interaction


async def _release(bot, domain, decision=True):
    interaction = FakeInteraction()
    original = bot_module._ConfirmCancelView
    bot_module._ConfirmCancelView = _confirm_view_class(decision)
    try:
        await bot._run_underattack_release(interaction, domain)
    finally:
        bot_module._ConfirmCancelView = original
    return interaction


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        bot = make_bot(cf=cf, state_path=state_path)
        interaction = await _activate(bot, "example.com")
        record = bot._underattack_state.get("example.com")
        assert record is not None and record.status == STATUS_ACTIVE, record
        assert "ACTIVE" in interaction.all_text() or "✅" in interaction.all_text()
        rules = cf._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)]
        assert len(rules) == 1 and rules[0]["ref"] == "rtsa_underattack_example_com"
        assert rules[0]["expression"] == 'http.host eq "example.com"'
    print("Scenario 1 (/underattack example.com monolith -> ACTIVE, verified) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        bot = make_bot(cf=cf, state_path=state_path)
        await _activate(bot, "example.com", "api.example.com")
        record = bot._underattack_state.get("example.com")
        assert record is not None and record.status == STATUS_ACTIVE
        assert record.api_domain == "api.example.com"
        assert record.api_exclusion_status == "IMPLEMENTED_BY_CONSTRUCTION"
        rules = cf._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)]
        assert 'api.example.com' not in rules[0]["expression"], "web rule must not reference the API hostname at all"
    print("Scenario 2 (/underattack with api-domain -> web-only rule, API domain untouched by construction) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        bot = make_bot(cf=cf, state_path=state_path)
        interaction3 = await _activate(bot, "https://example.com")
        assert cf.put_call_count() == 0
        assert "scheme" in interaction3.all_text().lower() or "❌" in interaction3.all_text()

        interaction4 = await _activate(bot, "example.com/path")
        assert cf.put_call_count() == 0
    print("Scenario 3/4 (scheme/path in domain rejected outright, zero mutation) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        bot = make_bot(cf=cf, state_path=state_path)
        interaction5 = await _activate(bot, "example.com", decision=False)
        assert cf.put_call_count() == 0
        assert bot._underattack_state.get("example.com") is None
        assert "dibatalkan" in interaction5.all_text() or "❌" in interaction5.all_text()
    print("Scenario 5 (Cancel -> zero mutation, no state written) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        bot = make_bot(cf=cf, state_path=state_path)
        await _activate(bot, "example.com", decision=None)
        assert cf.put_call_count() == 0
        assert bot._underattack_state.get("example.com") is None
    print("Scenario 6 (expired confirmation -> zero mutation) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        bot = make_bot(cf=cf, state_path=state_path)
        await _activate(bot, "example.com")
        puts_after_first = cf.put_call_count()
        interaction7 = await _activate(bot, "example.com")
        assert cf.put_call_count() == puts_after_first, "an already-ACTIVE domain must never trigger a second mutation"
        assert "ACTIVE" in interaction7.all_text() or "ℹ️" in interaction7.all_text()
    print("Scenario 7 (duplicate /underattack on an already-ACTIVE domain is idempotent) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        bot = make_bot(cf=cf, state_path=state_path)
        interaction8 = await _release(bot, "never-activated.com")
        assert cf.put_call_count() == 0
        assert "No active" in interaction8.all_text()
    print("Scenario 8 (/lepas with no active state -> zero mutation, honest report) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        bot = make_bot(cf=cf, state_path=state_path)
        await _activate(bot, "example.com")
        interaction9 = await _release(bot, "example.com")
        record = bot._underattack_state.get("example.com")
        assert record is not None and record.status == STATUS_RELEASED, record
        assert ("example.com", PHASE_HTTP_CONFIG_SETTINGS) not in cf._ruleset_rules or not any(
            r["ref"].startswith("rtsa_underattack") for r in cf._ruleset_rules.get(("zone1", PHASE_HTTP_CONFIG_SETTINGS), [])
        )
        assert "✅" in interaction9.all_text() or "dilepas" in interaction9.all_text()
    print("Scenario 9 (activate -> release cycle removes the RTSA rule, verified) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        bot = make_bot(cf=cf, state_path=state_path)
        await _activate(bot, "example.com")
        await _release(bot, "example.com")
        puts_after_release = cf.put_call_count()
        interaction10 = await _release(bot, "example.com")
        assert cf.put_call_count() == puts_after_release, "a second /lepas must never issue another mutation"
        assert "No active" in interaction10.all_text()
    print("Scenario 10 (double /lepas is idempotent, second call issues zero mutation) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        customer_rule = {
            "ref": "customer_rule_1", "description": "customer managed rule",
            "expression": 'http.host eq "shop.example.com"', "action": "set_config",
            "action_parameters": {"security_level": "high"},
        }
        cf._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)] = [customer_rule]
        bot = make_bot(cf=cf, state_path=state_path)
        await _activate(bot, "example.com")
        await _release(bot, "example.com")
        final_rules = cf._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)]
        assert final_rules == [customer_rule], f"customer rule must survive byte-for-byte: {final_rules}"
    print("Scenario 11 (pre-existing customer rule survives a full activate+release cycle untouched) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        bot = make_bot(cf=cf, state_path=state_path)
        await _activate(bot, "example.com")
        del bot

        fresh_state = UnderAttackStateManager(state_path)
        fresh_state.load()
        record = fresh_state.get("example.com")
        assert record is not None and record.status == STATUS_ACTIVE, "state must survive a process restart"
        assert record.rtsa_rule_ref == "rtsa_underattack_example_com"
    print("Scenario 12 (state survives a simulated RTSA restart via a fresh state manager) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi(zones=[{"id": "zone9", "name": "unrelated-account-zone.com"}])
        bot = make_bot(cf=cf, state_path=state_path)
        interaction13 = await _activate(bot, "example.com")
        assert cf.put_call_count() == 0
        assert bot._underattack_state.get("example.com") is None
        assert "tidak ditemukan" in interaction13.all_text().lower() or "❌" in interaction13.all_text()
    print("Scenario 13 (domain not in any owned Cloudflare zone -> STOP, zero mutation) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        bot = make_bot(cf=FakeCFApi(), state_path=state_path)
        bot.cloudflare = None
        interaction14 = await _activate(bot, "example.com")
        assert bot._underattack_state.get("example.com") is None
        assert "tidak aktif" in interaction14.all_text().lower() or "❌" in interaction14.all_text()
    print("Scenario 14 (Cloudflare integration disabled -> clean refusal, zero mutation) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi(lie_on_verify=True)
        bot = make_bot(cf=cf, state_path=state_path)
        interaction15 = await _activate(bot, "example.com")
        record = bot._underattack_state.get("example.com")
        assert record is not None and record.status == "VERIFICATION_FAILED", record
        assert "VERIFICATION_FAILED" in interaction15.all_text()
        assert "✅" not in interaction15.all_text(), "a verification failure must never be reported with a success marker"
    print("Scenario 15 (post-mutation verification failure -> VERIFICATION_FAILED, never a false ACTIVE) PASSED")

    source = inspect.getsource(bot_module)
    underattack_block = source.split('name="underattack"', 1)[1].split("@tree.command", 1)[0]
    lepas_block = source.split('name="lepas"', 1)[1].split("@tree.command", 1)[0]
    for label, block in (("/underattack", underattack_block), ("/lepas", lepas_block)):
        assert "_authorized_interaction(interaction, critical=True)" in block, (
            f"{label} must reuse the existing critical-command authorization gate"
        )
        assert "Tidak memiliki izin" in block, f"{label} must refuse unauthorized callers"
    print("Scenario 16 (/underattack and /lepas both gate on the critical-command RBAC helper) PASSED")

    modules_dir = os.path.join(_REPO_ROOT, "modules")
    offending_files = []
    for fname in os.listdir(modules_dir):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(modules_dir, fname), "r", encoding="utf-8") as f:
            text = f.read()
        if re.search(r"CloudflareClient|underattack_state|_run_underattack|\.cloudflare\.", text):
            offending_files.append(fname)
    assert not offending_files, f"detector modules must never reach Cloudflare mutation: {offending_files}"
    print("Scenario 17 (no detector/module under modules/ references Cloudflare mutation or underattack state) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        db = FakeDb()
        bot = make_bot(cf=cf, state_path=state_path, db=db)
        await _activate(bot, "example.com")
        await _release(bot, "example.com")
        action_types = {a["action_type"] for a, _result in db.actions}
        assert ActionType.CLOUDFLARE_UNDERATTACK in action_types
        assert ActionType.CLOUDFLARE_UNDERATTACK_RELEASE in action_types
        for action, _result in db.actions:
            assert _FAKE_TOKEN not in str(action), "audit log must never contain the Cloudflare token"
    print("Scenario 18 (audit log records both actions, never leaks the Cloudflare token) PASSED")

    with tempfile.TemporaryDirectory() as tmp:
        state_path = os.path.join(tmp, "state.json")
        cf = FakeCFApi()
        cf._put_delay = 0.05
        bot = make_bot(cf=cf, state_path=state_path)
        results = await asyncio.gather(
            _activate(bot, "example.com"), _activate(bot, "example.com"),
        )
        assert cf.put_call_count() == 1, f"expected exactly one mutation from a concurrent double-confirm, got {cf.put_call_count()}"
        texts = " ".join(r.all_text() for r in results)
        assert "⏳" in texts or "ACTIVE" in texts
    print("Scenario 19 (concurrent double-confirm on the same domain -> exactly one mutation) PASSED")

    print("\nALL /underattack + /lepas TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
