import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import asyncio
import shutil
import tempfile

from config.manager import (
    BanPolicyConfig, CloudflareConfig, DiscordConfig, ModulesConfig, ResponseEngineConfig, RTSAConfig,
)
from core.ban_state import (
    BAN_APPLIED_UNVERIFIED, BAN_EXPIRED, BAN_FAILED, BAN_VERIFIED, BanRecord, BanStateManager,
)
from core.event_bus import EventBus
from core.fs_discovery import detect_real_ip_configured
from core.ip_normalization import (
    CONFIDENCE_HIGH, CONFIDENCE_LOW, SOURCE_AMBIGUOUS_NON_EDGE, SOURCE_CLOUDFLARE_EDGE_UNRESOLVED,
    SOURCE_DIRECT, SOURCE_REALIP_TRUSTED, normalize_request_ip,
)
from discord_integration.bot import RTSABot
from discord_integration.cloudflare import CloudflareClient


class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass
    def enqueue_ban(self, *a, **k): pass
    def enqueue_cloudflare_rules_created(self, *a, **k): pass
    def enqueue_cloudflare_rules_removed(self, *a, **k): pass


class FakeProc:
    def __init__(self, returncode):
        self.returncode = returncode

    async def communicate(self):
        return b"", b""

    def kill(self):
        pass

    async def wait(self):
        pass


class FakeCloudflare:
    def __init__(self):
        self.block_all_calls = 0
        self.block_zone_calls = 0
        self.verify_calls = 0
        self.block_result = (True, "ok", [{"zone_id": "z1", "zone_name": "example.com", "rule_id": "r1"}])
        self.verify_result = True
        self.zones_for_domain = []

    async def block_ip_all_zones(self, ip, note=""):
        self.block_all_calls += 1
        return self.block_result

    async def block_ip_zones(self, zones, ip, note=""):
        self.block_zone_calls += 1
        return self.block_result

    async def resolve_zones_for_domain(self, domain):
        return self.zones_for_domain

    async def verify_ip_blocked(self, rule_refs, ip):
        self.verify_calls += 1
        return self.verify_result

    async def unblock_rule_refs(self, refs):
        return True, "ok"

    async def unblock_ip_all_zones(self, ip):
        return True, "ok"

    async def close(self):
        pass


def make_bot(*, ban_policy=None):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(detection_only=False),
        modules=ModulesConfig(),
        cloudflare=CloudflareConfig(enabled=False),
        ban_policy=ban_policy or BanPolicyConfig(),
    )
    bot = RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)
    bot.cloudflare = FakeCloudflare()
    bot.config_cloudflare_fail_open = False
    return bot


def _patch_subprocess(check_returncode=1, action_returncode=0):
    calls = []

    async def fake_create_subprocess_exec(*args, **kwargs):
        calls.append(args)
        if args[1] == "-C":
            return FakeProc(check_returncode)
        return FakeProc(action_returncode)

    return calls, fake_create_subprocess_exec


async def main() -> None:
    edge_result = normalize_request_ip("172.64.1.5", real_ip_configured=None)
    assert edge_result.ip_source == SOURCE_CLOUDFLARE_EDGE_UNRESOLVED
    assert edge_result.confidence == CONFIDENCE_LOW
    assert edge_result.is_cloudflare_request is True
    assert edge_result.client_ip == "172.64.1.5", "must never fabricate a different client_ip"
    print("Scenario 1 (Cloudflare edge connection IP correctly identified, never fabricated a better IP) PASSED")

    trusted_result = normalize_request_ip("203.0.113.9", real_ip_configured=True)
    assert trusted_result.ip_source == SOURCE_REALIP_TRUSTED
    assert trusted_result.confidence == CONFIDENCE_HIGH
    assert trusted_result.is_cloudflare_request is True
    print("Scenario 1b (real_ip_header configured: correctly resolved client IP, HIGH confidence) PASSED")

    direct_result = normalize_request_ip("198.51.100.4", real_ip_configured=None, domain_is_cloudflare_proxied=None)
    assert direct_result.ip_source == SOURCE_DIRECT
    assert direct_result.confidence == CONFIDENCE_HIGH
    assert direct_result.is_cloudflare_request is False
    assert direct_result.origin_bypass_suspected is False
    print(
        "Scenario 2 (direct-to-origin connection: connection_ip trusted as-is -- a spoofed "
        "XFF/CF-Connecting-IP header has zero effect since normalize_request_ip never reads "
        "any header, only the real connection_ip) PASSED"
    )

    bypass_result = normalize_request_ip(
        "198.51.100.4", real_ip_configured=False, domain_is_cloudflare_proxied=True,
    )
    assert bypass_result.origin_bypass_suspected is True
    assert bypass_result.ip_source == SOURCE_AMBIGUOUS_NON_EDGE
    assert bypass_result.is_cloudflare_request is None, "genuinely ambiguous cases must never assert a false certainty"
    print("Scenario 12 (origin bypass suspected: non-edge IP hitting a domain expected to be Cloudflare-proxied) PASSED")

    tmp_dir = tempfile.mkdtemp(prefix="rtsa_realip_test_")
    own_conf = os.path.join(tmp_dir, "site-own.conf")
    with open(own_conf, "w") as f:
        f.write("server { set_real_ip_from 173.245.48.0/20; real_ip_header CF-Connecting-IP; }")
    assert detect_real_ip_configured(own_conf) is True

    include_target = os.path.join(tmp_dir, "cloudflare.conf")
    with open(include_target, "w") as f:
        f.write("set_real_ip_from 173.245.48.0/20;\nreal_ip_header CF-Connecting-IP;\n")
    include_conf = os.path.join(tmp_dir, "site-include.conf")
    with open(include_conf, "w") as f:
        f.write(f"server {{ include {include_target}; }}")
    assert detect_real_ip_configured(include_conf) is True

    bare_conf = os.path.join(tmp_dir, "site-bare.conf")
    with open(bare_conf, "w") as f:
        f.write("server { listen 443 ssl; server_name example.com; }")
    assert detect_real_ip_configured(bare_conf) is False

    assert detect_real_ip_configured(os.path.join(tmp_dir, "does-not-exist.conf")) is None
    print("Scenario 1c (real_ip_header static detection: own file, include file, absent, unreadable) PASSED")

    class FakeCFApi(CloudflareClient):
        def __init__(self):
            super().__init__("fake-token")
            self.create_calls = 0

        async def _request_json(self, method, url, *, params=None, json_body=None):
            if method == "POST":
                self.create_calls += 1
                if self.create_calls == 1:
                    return 200, {"success": True, "result": {"id": "rule-abc"}}
                return 400, {"success": False, "errors": [{"code": 10009, "message": "already exists"}]}
            if method == "GET":
                return 200, {"success": True, "result": [{"id": "rule-abc"}]}
            return 200, {"success": True}

    fake_api = FakeCFApi()
    ok1, msg1, rule_id1 = await fake_api._block_ip("zone1", "192.0.2.10")
    ok2, msg2, rule_id2 = await fake_api._block_ip("zone1", "192.0.2.10")
    assert ok1 is True and ok2 is True
    assert rule_id1 == "rule-abc" and rule_id2 == "rule-abc", "duplicate ban must reuse the existing rule id, never create a second rule"
    assert fake_api.create_calls == 2, "both attempts do call the API (that's Cloudflare's own dedup, not skipped client-side)"
    print("Scenario 7 (duplicate ban against Cloudflare reuses the existing rule, never creates a duplicate) PASSED")

    verified = await fake_api.verify_ip_blocked([{"zone_id": "zone1", "rule_id": "rule-abc"}], "192.0.2.10")
    assert verified is True
    print("Scenario 5 (Cloudflare API success: rule creation + read-back verification both succeed) PASSED")

    class FakeCFApiDown(CloudflareClient):
        def __init__(self):
            super().__init__("fake-token")

        async def _request_json(self, method, url, *, params=None, json_body=None):
            return 500, {"success": False, "errors": [{"message": "internal error"}]}

    fake_api_down = FakeCFApiDown()
    ok_down, msg_down, rule_down = await fake_api_down._block_ip("zone1", "192.0.2.11")
    assert ok_down is False and rule_down is None
    print("Scenario 6 (Cloudflare API failure surfaces as a failed block, never silently treated as success) PASSED")

    bot = make_bot()
    calls, fake_exec = _patch_subprocess()
    orig_exec = asyncio.create_subprocess_exec
    orig_which = shutil.which
    asyncio.create_subprocess_exec = fake_exec
    shutil.which = lambda name: f"/usr/sbin/{name}"
    try:
        result = await bot._ban_ip("203.0.113.50", reason="test", requested_by="tester", severity="HIGH")
        assert "berhasil di-ban" in result, result
        assert any(c[0].endswith("/iptables") for c in calls), "IPv4 must use the iptables binary"
        active = bot._ban_state.get_active("203.0.113.50")
        assert active is not None
        assert active.status in (BAN_VERIFIED, BAN_APPLIED_UNVERIFIED)
        assert active.expires_at is not None and active.expires_at > time.time()
        expected_ttl = bot.rtsa_config.ban_policy.ttl_seconds_by_severity["HIGH"]
        assert abs((active.expires_at - active.banned_at) - expected_ttl) < 1.0
        print("Scenario 3 (IPv4 ban: iptables + Cloudflare applied, TTL from severity, lifecycle state recorded) PASSED")

        cf_calls_before = bot.cloudflare.block_all_calls
        result2 = await bot._ban_ip("203.0.113.50", reason="test again", requested_by="tester2", severity="HIGH")
        assert "sudah aktif diban" in result2, result2
        assert bot.cloudflare.block_all_calls == cf_calls_before, (
            "an active ban must never trigger a second Cloudflare API call"
        )
        print("Scenario 8 (active ban never re-triggers the Cloudflare API) PASSED")

        active.expires_at = time.time() - 1.0
        expired = bot._ban_state.sweep_expired(time.time())
        assert len(expired) == 1 and expired[0].ip == "203.0.113.50"
        assert expired[0].status == BAN_EXPIRED
        print("Scenario 9 (ban TTL expiration correctly detected by the sweep) PASSED")

        bot_v6 = make_bot()
        calls_v6, fake_exec_v6 = _patch_subprocess()
        asyncio.create_subprocess_exec = fake_exec_v6
        result_v6 = await bot_v6._ban_ip("2001:db8::dead:beef", reason="test", requested_by="tester", severity="LOW")
        assert "berhasil di-ban" in result_v6, result_v6
        assert any(c[0].endswith("/ip6tables") for c in calls_v6), "IPv6 must use the ip6tables binary, never iptables"
        active_v6 = bot_v6._ban_state.get_active("2001:db8::dead:beef")
        assert active_v6 is not None
        print("Scenario 4 (IPv6 ban correctly uses ip6tables, never string-compares the address) PASSED")

        bot_fail = make_bot()
        bot_fail.cloudflare.block_result = (False, "boom", [])
        bot_fail.config_cloudflare_fail_open = False
        calls_fail, fake_exec_fail = _patch_subprocess()
        asyncio.create_subprocess_exec = fake_exec_fail
        result_fail = await bot_fail._ban_ip("203.0.113.60", reason="test", requested_by="tester", severity="MEDIUM")
        assert "BAN_FAILED" in result_fail, result_fail
        failed_record = bot_fail._ban_state.get("203.0.113.60")
        assert failed_record is not None and failed_record.status == BAN_FAILED
        assert failed_record.is_active() is False
        print("Scenario 6b (Cloudflare failure with fail_open=False: BAN_FAILED, never claimed as success) PASSED")
    finally:
        asyncio.create_subprocess_exec = orig_exec
        shutil.which = orig_which

    state = BanStateManager()
    now = time.time()
    state.put(BanRecord(
        ip="198.51.100.9", reason="attack", severity="HIGH", scope="GLOBAL", domain="example.com",
        banned_by="tester", banned_at=now, expires_at=now + 3600, status=BAN_APPLIED_UNVERIFIED,
    ))
    r1 = state.record_post_ban_request("198.51.100.9", now + 5)
    r2 = state.record_post_ban_request("198.51.100.9", now + 10)
    assert r1 is not None and r2 is not None
    assert r2.post_ban_request_count == 2
    assert r2.first_post_ban_request_at == now + 5
    assert r2.last_post_ban_request_at == now + 10
    assert state.record_post_ban_request("203.0.113.99", now) is None, "an IP with no active ban must return None"
    print("Scenario 10 (post-ban requests from a banned IP are tracked: count, first/last seen) PASSED")

    from core.datatypes import BaseEvent, EventCategory, Severity
    from discord_integration.webhook import DiscordWebhookDispatcher

    class _FakeBotWithBanState:
        def __init__(self, ban_state):
            self._ban_state = ban_state

    dispatcher = DiscordWebhookDispatcher(EventBus(), DiscordConfig())
    dispatcher.set_bot(_FakeBotWithBanState(state))
    attack_event = BaseEvent(
        source_module="nginx_monitor", category=EventCategory.WEB_ATTACK_SCAN, severity=Severity.MEDIUM,
        message="scan", raw="",
        metadata={"source_ip": "198.51.100.9", "domain": "example.com", "ip_source": "CLOUDFLARE_EDGE_UNVERIFIED"},
    )
    suppress1, bypass_event = dispatcher._check_ban_bypass(attack_event)
    assert suppress1 is True and bypass_event is not None
    assert bypass_event.category == EventCategory.BAN_BYPASS_DETECTED
    assert bypass_event.metadata["ip"] == "198.51.100.9"
    assert bypass_event.metadata["post_ban_request_count"] == 3, "the event that triggered the alert must itself count"

    suppress2, bypass_event2 = dispatcher._check_ban_bypass(attack_event)
    assert suppress2 is True and bypass_event2 is None, "a second bypass alert must never fire for the same ban"

    unrelated_event = BaseEvent(
        source_module="nginx_monitor", category=EventCategory.WEB_ATTACK_SCAN, severity=Severity.MEDIUM,
        message="scan", raw="", metadata={"source_ip": "8.8.8.8"},
    )
    suppress3, bypass_event3 = dispatcher._check_ban_bypass(unrelated_event)
    assert suppress3 is False and bypass_event3 is None, "an IP with no active ban must be processed normally"
    print("Scenario 11 (BAN_BYPASS_DETECTED fires exactly once per active ban, unrelated IPs unaffected) PASSED")

    print("\nALL BAN ENFORCEMENT PIPELINE TESTS PASSED")


asyncio.run(main())
