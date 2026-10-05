import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig
from core.event_bus import EventBus
from modules.nginx_monitor import NginxMonitor

LOG_FILE = "/var/log/nginx/access.log"


def make_monitor(max_active=5, **overrides):
    kwargs = dict(enabled=True, redirect_chain_window_seconds=999.0, redirect_chain_max_active=max_active)
    kwargs.update(overrides)
    mon = NginxMonitor(EventBus(), NginxMonitorConfig(**kwargs))
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_meta(domain, source):
        return "", {"domain": domain or "example.com"}
    mon._build_web_attack_metadata = fake_meta
    return mon, published


def access_line(ip, method, path, status):
    return f'{ip} - - [19/Aug/2026:12:00:00 +0000] "{method} {path} HTTP/1.1" {status} 123 "-" "curl/8.0"'


async def feed(mon, ip, path, status):
    await mon._process_access_line(access_line(ip, "GET", path, status), LOG_FILE, 1)


async def main() -> None:
    mon, pub = make_monitor(max_active=5)
    for i in range(50):
        await feed(mon, f"9.9.9.{i}", "/wp-login.php", 301)
    assert len(mon._chains) == 5, (
        f"50 unique attacker IPs each starting a redirect chain must never grow _chains past "
        f"redirect_chain_max_active=5, got {len(mon._chains)}"
    )
    assert mon._chains_overflow_total == 45, (
        f"the 45 excess unique-key chain-start attempts must be counted as overflow, not "
        f"silently created anyway, got {mon._chains_overflow_total}"
    )
    print(
        "Scenario 1 (50 unique attacker IPs each starting a redirect chain, "
        "redirect_chain_max_active=5 -- table stays capped, 45 overflow counted) PASSED"
    )

    for chain in mon._chains.values():
        assert not hasattr(chain, "expire_task"), (
            "no per-key asyncio task may exist on a redirect chain state -- expiry must be "
            "handled by the shared sweep, not one-task-per-attacker-key"
        )
    print("Scenario 2 (no per-key asyncio task exists on any redirect chain state) PASSED")

    mon2, pub2 = make_monitor(max_active=1000)
    await feed(mon2, "1.2.3.4", "/wp-login.php", 301)
    key = ("1.2.3.4", "/wp-login.php")
    assert key in mon2._chains
    mon2._chains[key].expires_at -= 9999.0
    await mon2._sweep_chains()
    assert key not in mon2._chains, "a due chain must be removed from the active table once flushed"
    assert len(pub2) == 1
    print("Scenario 3 (a due chain is flushed and published by the shared sweep, then removed) PASSED")

    mon3, pub3 = make_monitor(max_active=1000)
    await feed(mon3, "5.5.5.5", "/wp-login.php", 301)
    await mon3._sweep_chains()
    key3 = ("5.5.5.5", "/wp-login.php")
    assert key3 in mon3._chains, "a chain whose window has NOT elapsed must not be flushed early"
    assert len(pub3) == 0
    print("Scenario 4 (a chain whose window has not elapsed yet is never flushed early) PASSED")

    print("\nALL NGINX REDIRECT CHAIN BOUND TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=30))
