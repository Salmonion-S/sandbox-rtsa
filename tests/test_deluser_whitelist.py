import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

import pwd
import yaml

from config.manager import (
    CloudflareConfig, DiscordConfig, HostPersistenceDetectorConfig, ModulesConfig,
    ResponseEngineConfig, RTSAConfig,
)
from core.event_bus import EventBus
from discord_integration.bot import RTSABot, _DELUSER_WELL_KNOWN_SYSTEM_USERNAMES

class FakeDb:
    def enqueue_action(self, *a, **k): pass
    def enqueue_incident_create(self, **k): pass
    def enqueue_incident_update(self, *a, **k): pass

def make_bot(whitelist_user=None, protect_users=None):
    cfg = RTSAConfig(
        response_engine=ResponseEngineConfig(
            detection_only=False,
            whitelist_user=["newusproud"] if whitelist_user is None else whitelist_user,
        ),
        modules=ModulesConfig(
            host_persistence_detector=HostPersistenceDetectorConfig(
                auto_remediate_protect_users=(
                    ["newusproud", "root"] if protect_users is None else protect_users
                ),
            ),
        ),
        cloudflare=CloudflareConfig(enabled=False),
    )
    return RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=FakeDb(), supervisor=None)

def fake_pw(name, uid=1005, gid=1005, home=None, shell="/bin/bash"):
    return pwd.struct_passwd((name, "x", uid, gid, "", home or f"/home/{name}", shell))

def protected_set(bot):
    cfg = bot.rtsa_config
    return (
        set(cfg.response_engine.whitelist_user)
        | set(cfg.modules.host_persistence_detector.auto_remediate_protect_users)
        | _DELUSER_WELL_KNOWN_SYSTEM_USERNAMES
    )

def classify(bot, pw_entry):
    return RTSABot._classify_deluser_system_account(
        pw_entry, bot.rtsa_config.modules.host_persistence_detector.min_real_uid, protected_set(bot),
    )

def main():
    bot = make_bot()

    reasons = classify(bot, fake_pw("newusproud"))
    assert reasons, "newusproud must be refused by /deluser"
    assert any("dilindungi" in r for r in reasons), reasons
    blocks = RTSABot._deluser_hard_block_reasons({"system_account_reasons": reasons})
    assert blocks, "protection must surface as a HARD BLOCK, not merely elevated risk"
    print(f"Scenario 1 (newusproud refused as a hard block; reason: {reasons[0]}) PASSED")

    naked = make_bot(whitelist_user=[], protect_users=[])
    root_reasons = classify(naked, fake_pw("root", uid=0, gid=0, home="/root"))
    assert root_reasons, "root must be refused even with all configurable lists empty"
    assert any("UID 0" in r for r in root_reasons), root_reasons
    print(f"Scenario 2 (root refused with whitelist_user=[] AND protect_users=[]; reason: {root_reasons[0]}) PASSED")

    for svc in ("www-data", "sshd", "daemon"):
        r = classify(naked, fake_pw(svc, uid=33, gid=33, home="/var/www", shell="/usr/sbin/nologin"))
        assert r, f"{svc} must be refused with empty config lists"
    print("Scenario 3 (www-data/sshd/daemon still refused with all config lists empty) PASSED")

    unprotected = classify(naked, fake_pw("newusproud"))
    assert unprotected == [], (
        f"expected an ordinary /home admin account to be deletable once unlisted, got {unprotected}"
        " -- if this fails the whitelist is not what is protecting it"
    )
    print("Scenario 4 (same account IS deletable once removed from both lists -- whitelist is load-bearing) PASSED")

    only_new = make_bot(whitelist_user=["newusproud"], protect_users=[])
    assert classify(only_new, fake_pw("newusproud")), "response_engine.whitelist_user must protect on its own"
    only_old = make_bot(whitelist_user=[], protect_users=["newusproud"])
    assert classify(only_old, fake_pw("newusproud")), "the pre-existing protect list must keep working too"
    print("Scenario 5 (either list alone protects the account -- new option added without breaking the old one) PASSED")

    multi = make_bot(whitelist_user=["newusproud", "deploybot"])
    assert classify(multi, fake_pw("deploybot", uid=1200)), "additional whitelisted names must be honoured"
    assert classify(multi, fake_pw("randomuser", uid=1201)) == [], "unlisted ordinary users stay deletable"
    print("Scenario 6 (multiple whitelist entries honoured; unlisted ordinary users stay deletable) PASSED")

    raw = yaml.safe_load(open("config/config.yaml"))
    shipped = raw["response_engine"]["whitelist_user"]
    assert "newusproud" in shipped, f"config.yaml must ship the super-admin protected: {shipped}"
    assert ResponseEngineConfig().whitelist_user == ["newusproud"], (
        "the dataclass default must also protect it, so a config missing the key is still safe"
    )
    print(f"Scenario 7 (config.yaml ships whitelist_user={shipped}, and the code default matches) PASSED")

    from unittest import mock

    real_bot = make_bot(whitelist_user=["newusproud"], protect_users=[])
    entry = fake_pw("newusproud")
    with mock.patch("pwd.getpwnam", return_value=entry), \
         mock.patch("grp.getgrgid", side_effect=KeyError), \
         mock.patch.object(RTSABot, "_deluser_directory_stats", staticmethod(lambda *a, **k: (False, 0, 0))), \
         mock.patch.object(RTSABot, "_deluser_owned_files_outside_home", staticmethod(lambda *a, **k: (0, []))):
        profile = real_bot._deluser_gather_static_profile("newusproud")
    assert profile.get("exists") is not False, profile
    live_blocks = RTSABot._deluser_hard_block_reasons(profile)
    assert live_blocks and any("dilindungi" in r for r in live_blocks), (
        f"the real /deluser profile path must hard-block a whitelisted account, got {live_blocks}"
    )
    print(f"Scenario 8 (real _deluser_gather_static_profile hard-blocks via response_engine.whitelist_user "
          f"alone: {live_blocks[0]}) PASSED")

    print("\nALL /deluser WHITELIST PROTECTION TESTS PASSED")

main()
