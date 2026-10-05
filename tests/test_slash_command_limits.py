import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import CloudflareConfig, DiscordConfig, RTSAConfig
from core.event_bus import EventBus
from discord_integration.bot import RTSABot

_MAX_NAME_LEN = 32
_MAX_DESCRIPTION_LEN = 100
_MAX_COMMANDS_PER_TREE = 100


def main():
    cfg = RTSAConfig(cloudflare=CloudflareConfig(enabled=False))
    disc_cfg = DiscordConfig(enabled=True)
    bot = RTSABot(disc_cfg, cfg, EventBus(), db_worker=None, supervisor=None)

    commands = bot.tree.get_commands()
    assert commands, "no slash commands registered -- _register_commands() must have run"
    print(f"Scenario 1 ({len(commands)} slash command(s) registered via _register_commands()) PASSED")

    assert len(commands) <= _MAX_COMMANDS_PER_TREE, (
        f"{len(commands)} top-level commands registered, Discord allows only "
        f"{_MAX_COMMANDS_PER_TREE} per scope (guild or global) -- tree.sync() would be rejected"
    )
    print(f"Scenario 2 (command count {len(commands)} is within Discord's {_MAX_COMMANDS_PER_TREE}-per-scope cap) PASSED")

    violations = []
    seen_names = set()
    for cmd in commands:
        name = cmd.name
        if name in seen_names:
            violations.append(f"duplicate command name '{name}'")
        seen_names.add(name)

        if not (1 <= len(name) <= _MAX_NAME_LEN):
            violations.append(f"'{name}': name length {len(name)} outside 1-{_MAX_NAME_LEN}")
        if name != name.lower():
            violations.append(f"'{name}': command names must be lowercase")

        desc = cmd.description or ""
        if len(desc) > _MAX_DESCRIPTION_LEN:
            violations.append(
                f"'{name}': description is {len(desc)} chars, Discord's cap is "
                f"{_MAX_DESCRIPTION_LEN} -- {desc!r}"
            )

        for param in getattr(cmd, "parameters", []) or []:
            pdesc = getattr(param, "description", "") or ""
            if len(pdesc) > _MAX_DESCRIPTION_LEN:
                violations.append(
                    f"'{name}' param '{param.name}': description is {len(pdesc)} chars, "
                    f"cap is {_MAX_DESCRIPTION_LEN} -- {pdesc!r}"
                )

    assert not violations, (
        "one or more slash commands violate Discord's registration limits -- syncing these "
        "would raise CommandSyncFailure at bot startup, and setup_hook() runs BEFORE the bot "
        "connects to the gateway, so this single bad command takes the whole bot offline:\n  "
        + "\n  ".join(violations)
    )
    print(
        f"Scenario 3 (all {len(commands)} commands: unique names, <= {_MAX_NAME_LEN} chars lowercase, "
        f"description/param-description <= {_MAX_DESCRIPTION_LEN} chars) PASSED"
    )

    print("\nALL SLASH COMMAND LIMIT TESTS PASSED")


main()
