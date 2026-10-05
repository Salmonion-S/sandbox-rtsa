from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from discord_integration.cloudflare import (
    ACTION_SET_CONFIG, PHASE_HTTP_CONFIG_SETTINGS, CloudflareClient,
)


class FakeCFApi(CloudflareClient):

    def __init__(self, *, zones: Optional[List[Dict[str, str]]] = None) -> None:
        super().__init__("fake-token-not-real")
        self._zones_data = zones if zones is not None else [{"id": "zone1", "name": "example.com"}]
        self._ruleset_rules: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        self.calls: List[Tuple[str, str]] = []
        self.fail_get_phase: bool = False
        self.fail_put_phase: bool = False

    async def _request_json(
        self, method: str, url: str, *, params=None, json_body=None,
    ) -> Tuple[Optional[int], Dict[str, Any]]:
        self.calls.append((method, url))

        if url.endswith("/zones") or "/zones?" in url:
            return 200, {"success": True, "result": self._zones_data, "result_info": {"total_pages": 1}}

        if "/rulesets/phases/" in url and url.endswith("/entrypoint"):
            zone_id = url.split("/zones/", 1)[1].split("/rulesets/", 1)[0]
            phase = url.split("/phases/", 1)[1].split("/entrypoint", 1)[0]
            key = (zone_id, phase)

            if method == "GET":
                if self.fail_get_phase:
                    return 500, {"success": False, "errors": [{"message": "simulated fetch failure"}]}
                if key not in self._ruleset_rules:
                    return 404, {"success": False, "errors": [{"message": "not found"}]}
                return 200, {"success": True, "result": {"id": f"ruleset-{zone_id}-{phase}", "rules": self._ruleset_rules[key]}}

            if method == "PUT":
                if self.fail_put_phase:
                    return 500, {"success": False, "errors": [{"message": "simulated write failure"}]}
                rules = (json_body or {}).get("rules", [])
                self._ruleset_rules[key] = rules
                return 200, {"success": True, "result": {"id": f"ruleset-{zone_id}-{phase}", "rules": rules}}

        return 404, {"success": False, "errors": [{"message": f"unhandled url in fake: {url}"}]}

    def put_call_count(self) -> int:
        return sum(1 for method, url in self.calls if method == "PUT")


def _under_attack_rule(ref: str = "rtsa_underattack_example_com") -> Dict[str, Any]:
    return {
        "ref": ref, "description": "RTSA emergency protection (example.com)",
        "expression": 'http.host eq "example.com"', "action": ACTION_SET_CONFIG,
        "action_parameters": {"security_level": "under_attack"},
    }


async def main() -> None:
    cf = FakeCFApi()
    result = await cf.upsert_config_rule(
        "zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com",
        expression='http.host eq "example.com"', description="RTSA emergency protection (example.com)",
        action_parameters={"security_level": "under_attack"},
    )
    assert result.ok, result.message
    assert result.preserved_rule_count == 0
    rules_after = cf._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)]
    assert len(rules_after) == 1
    assert rules_after[0]["ref"] == "rtsa_underattack_example_com"
    assert rules_after[0]["action_parameters"]["security_level"] == "under_attack"
    print("Scenario 1 (upsert on empty phase creates ruleset with exactly one RTSA rule) PASSED")

    cf2 = FakeCFApi()
    unrelated = {
        "ref": "some_other_admin_rule", "description": "unrelated user rule",
        "expression": 'http.host eq "other.example.com"', "action": ACTION_SET_CONFIG,
        "action_parameters": {"security_level": "essentially_off"},
    }
    cf2._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)] = [unrelated]
    result2 = await cf2.upsert_config_rule(
        "zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com",
        expression='http.host eq "example.com"', description="RTSA emergency protection (example.com)",
        action_parameters={"security_level": "under_attack"},
    )
    assert result2.ok, result2.message
    assert result2.preserved_rule_count == 1
    rules_after2 = cf2._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)]
    assert len(rules_after2) == 2
    refs = {r["ref"] for r in rules_after2}
    assert refs == {"some_other_admin_rule", "rtsa_underattack_example_com"}
    unrelated_after = next(r for r in rules_after2 if r["ref"] == "some_other_admin_rule")
    assert unrelated_after == unrelated, "unrelated rule must be preserved byte-for-byte"
    print("Scenario 2 (upsert preserves an unrelated existing rule exactly, appends RTSA rule) PASSED")

    cf3 = FakeCFApi()
    await cf3.upsert_config_rule(
        "zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com",
        expression='http.host eq "example.com"', description="first",
        action_parameters={"security_level": "under_attack"},
    )
    result3b = await cf3.upsert_config_rule(
        "zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com",
        expression='http.host eq "example.com"', description="second (update)",
        action_parameters={"security_level": "under_attack"},
    )
    assert result3b.ok, result3b.message
    rules_after3 = cf3._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)]
    assert len(rules_after3) == 1, f"expected exactly one rule after idempotent re-run, got {len(rules_after3)}"
    assert rules_after3[0]["description"] == "second (update)"
    print("Scenario 3 (repeated upsert with same ref updates in place, never duplicates) PASSED")

    cf4 = FakeCFApi()
    other_rule = {
        "ref": "customer_rule_1", "description": "customer managed rule",
        "expression": 'http.host eq "shop.example.com"', "action": ACTION_SET_CONFIG,
        "action_parameters": {"security_level": "high"},
    }
    cf4._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)] = [other_rule, _under_attack_rule()]
    result4 = await cf4.remove_config_rule("zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com")
    assert result4.ok, result4.message
    rules_after4 = cf4._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)]
    assert len(rules_after4) == 1
    assert rules_after4[0] == other_rule
    print("Scenario 4 (remove_config_rule deletes only the RTSA rule, preserves the customer rule) PASSED")

    cf5 = FakeCFApi()
    cf5._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)] = [other_rule]
    put_calls_before = cf5.put_call_count()
    result5 = await cf5.remove_config_rule("zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com")
    assert result5.ok, result5.message
    assert result5.rule is None
    assert cf5.put_call_count() == put_calls_before, "removing a nonexistent rule must never issue a PUT"
    print("Scenario 5 (removing a nonexistent RTSA rule is an idempotent no-op, no PUT issued) PASSED")

    cf6 = FakeCFApi()
    cf6._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)] = [other_rule]
    cf6.fail_get_phase = True
    result6 = await cf6.upsert_config_rule(
        "zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com",
        expression='http.host eq "example.com"', description="x",
        action_parameters={"security_level": "under_attack"},
    )
    assert not result6.ok
    assert cf6.put_call_count() == 0, "a failed read must never be followed by a write"
    print("Scenario 6 (fetch failure -> upsert_config_rule refuses to mutate, zero PUT calls) PASSED")

    cf7 = FakeCFApi()
    cf7._ruleset_rules[("zone1", PHASE_HTTP_CONFIG_SETTINGS)] = [other_rule, _under_attack_rule()]
    cf7.fail_get_phase = True
    result7 = await cf7.remove_config_rule("zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com")
    assert not result7.ok
    assert cf7.put_call_count() == 0, "a failed read must never be followed by a write during rollback either"
    print("Scenario 7 (fetch failure -> remove_config_rule refuses to mutate, zero PUT calls) PASSED")

    cf8 = FakeCFApi()
    fetched8 = await cf8.get_ruleset_phase_entrypoint("zone1", PHASE_HTTP_CONFIG_SETTINGS)
    assert fetched8.ok is True
    assert fetched8.exists is False
    assert fetched8.rules == []
    print("Scenario 8 (never-created phase -> ok=True/exists=False, distinct from a fetch failure) PASSED")

    cf9 = FakeCFApi(zones=[{"id": "zone1", "name": "example.com"}, {"id": "zone2", "name": "other.com"}])
    zone9 = await cf9.resolve_single_zone_for_domain("example.com")
    assert zone9 is not None and zone9["id"] == "zone1"
    print("Scenario 9 (resolve_single_zone_for_domain: exact match) PASSED")

    zone10 = await cf9.resolve_single_zone_for_domain("admin.example.com")
    assert zone10 is not None and zone10["id"] == "zone1"
    print("Scenario 10 (resolve_single_zone_for_domain: subdomain resolves to owning zone) PASSED")

    zone11 = await cf9.resolve_single_zone_for_domain("not-on-this-account.com")
    assert zone11 is None
    print("Scenario 11 (unrelated domain resolves to no zone -> caller must STOP) PASSED")

    cf12 = FakeCFApi()
    await cf12.upsert_config_rule(
        "zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com",
        expression='http.host eq "example.com"', description="x",
        action_parameters={"security_level": "under_attack"},
    )
    found = await cf12.get_config_rule("zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com")
    assert found is not None and found["action_parameters"]["security_level"] == "under_attack"
    await cf12.remove_config_rule("zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com")
    found_after_removal = await cf12.get_config_rule("zone1", phase=PHASE_HTTP_CONFIG_SETTINGS, ref="rtsa_underattack_example_com")
    assert found_after_removal is None
    print("Scenario 12 (get_config_rule verifies presence after upsert, absence after removal) PASSED")

    print("\nALL CLOUDFLARE CONFIG RULE TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
