import asyncio
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig
from core.datatypes import EventCategory, Severity
from core.event_bus import EventBus
from modules.nginx_monitor import NginxMonitor

LOG_FILE = "/var/log/nginx/access.log"


def make_monitor(**overrides):
    kwargs = dict(enabled=True, redirect_chain_window_seconds=0.08, redirect_chain_max_hops=4)
    kwargs.update(overrides)
    cfg = NginxMonitorConfig(**kwargs)
    mon = NginxMonitor(EventBus(), cfg)
    published = []
    mon.publish = lambda ev: published.append(ev)

    async def fake_meta(domain, source):
        return "", {"domain": domain or "example.com"}

    mon._build_web_attack_metadata = fake_meta
    return mon, published


def access_line(ip, method, path, status, *, ua="curl/8.0", host=None, xfh=None, scheme=None, location=None):
    line = f'{ip} - - [19/Aug/2026:12:00:00 +0000] "{method} {path} HTTP/1.1" {status} 123 "-" "{ua}"'
    for extra in (host, xfh, scheme, location):
        if extra is not None:
            line += f' "{extra}"'
    return line


async def feed(mon, line, line_no=1):
    await mon._process_access_line(line, LOG_FILE, line_no)


async def main():
    mon, pub = make_monitor()
    await feed(mon, access_line("203.0.113.9", "GET", "/wp-login.php", 301))
    await feed(mon, access_line("203.0.113.9", "GET", "/wp-login.php", 444))
    assert len(pub) == 1, f"expected exactly one chain-result event: {[e.metadata for e in pub]}"
    chain = pub[0].metadata["redirect_chain"]
    assert chain["protection_result"] == "BLOCKED", chain
    assert pub[0].severity == Severity.LOW, pub[0].severity
    assert "444" in chain["followup_request"]
    assert chain["scheme_confirmed"] is False, "scheme was never captured in this log line -- must not be assumed"
    print("Scenario 1 (301 -> 444 same IP/target -> BLOCKED, scheme honestly UNKNOWN) PASSED")

    mon2, pub2 = make_monitor()
    await feed(mon2, access_line("198.51.100.7", "GET", "/wp-login.php", 301))
    assert pub2 == [], "must not publish before the correlation window has a chance to expire"
    await asyncio.sleep(0.15)
    await mon2._sweep_chains()
    assert len(pub2) == 1, pub2
    chain2 = pub2[0].metadata["redirect_chain"]
    assert chain2["protection_result"] == "UNRESOLVED", chain2
    assert "follow-up tidak teramati" in chain2["followup_request"]
    assert "TIDAK diasumsikan aman maupun berbahaya" in chain2["interpretation"]
    print("Scenario 2 (301, no follow-up observed -> UNRESOLVED, exact required wording) PASSED")

    mon3, pub3 = make_monitor()
    await feed(mon3, access_line("203.0.113.20", "GET", "/wp-login.php", 301))
    await feed(mon3, access_line("203.0.113.20", "GET", "/wp-login.php", 200))
    assert len(pub3) == 1
    chain3 = pub3[0].metadata["redirect_chain"]
    assert chain3["protection_result"] == "SERVED", chain3
    assert pub3[0].severity == Severity.CRITICAL, pub3[0].severity
    print("Scenario 3 (301 -> 200 -> SERVED, CRITICAL severity, priority raised) PASSED")

    mon4, pub4 = make_monitor()
    await feed(mon4, access_line("203.0.113.21", "GET", "/wp-login.php", 301))
    await feed(mon4, access_line("203.0.113.21", "GET", "/wp-login.php", 404))
    assert len(pub4) == 1
    assert pub4[0].metadata["redirect_chain"]["protection_result"] == "NOT_FOUND"
    print("Scenario 4 (301 -> 404 -> NOT_FOUND) PASSED")

    mon5, pub5 = make_monitor()
    await feed(mon5, access_line("203.0.113.30", "GET", "/wp-login.php", 301))
    await feed(mon5, access_line("203.0.113.30", "GET", "/xmlrpc.php", 444))
    assert pub5 == [], "a different target from the same IP must not resolve the /wp-login.php chain"
    await asyncio.sleep(0.15)
    await mon5._sweep_chains()
    assert len(pub5) == 1, pub5
    assert pub5[0].metadata["redirect_chain"]["protection_result"] == "UNRESOLVED"
    assert "/wp-login.php" in pub5[0].request_path
    print("Scenario 5 (different path, same IP -- NOT wrongly correlated into the open chain) PASSED")

    mon6, pub6 = make_monitor()
    await feed(mon6, access_line("203.0.113.40", "GET", "/wp-login.php", 301))
    await feed(mon6, access_line("203.0.113.40", "GET", "/wp-login.php", 301))
    await feed(mon6, access_line("203.0.113.40", "GET", "/wp-login.php", 444))
    assert len(pub6) == 1
    chain6 = pub6[0].metadata["redirect_chain"]
    assert chain6["protection_result"] == "BLOCKED"
    assert chain6["hop_count"] == 3
    assert chain6["redirect"].count("301") == 2, chain6["redirect"]
    print("Scenario 6 (301 -> 301 -> 444 multi-hop chain, both redirects listed, still BLOCKED) PASSED")

    mon7, pub7 = make_monitor(redirect_chain_max_hops=3)
    await feed(mon7, access_line("203.0.113.50", "GET", "/wp-login.php", 301))
    await feed(mon7, access_line("203.0.113.50", "GET", "/wp-login.php", 301))
    await feed(mon7, access_line("203.0.113.50", "GET", "/wp-login.php", 301))
    assert len(pub7) == 1, "hitting the hop cap while still redirecting must finalize immediately"
    assert pub7[0].metadata["redirect_chain"]["protection_result"] == "UNRESOLVED"
    assert "melebihi batas" in pub7[0].metadata["redirect_chain"]["interpretation"]
    print("Scenario 7 (redirect loop hits hop cap -- finalized as UNRESOLVED, not tracked forever) PASSED")

    mon8, pub8 = make_monitor()
    await feed(mon8, access_line("203.0.113.60", "GET", "/wp-login.php", 301))
    await feed(mon8, access_line("203.0.113.60", "GET", "/wp-login.php", 444))
    await feed(mon8, access_line("203.0.113.60", "GET", "/wp-login.php", 301))
    await feed(mon8, access_line("203.0.113.60", "GET", "/wp-login.php", 444))
    assert len(pub8) == 1, f"identical repeated chain result must be cooled down, not spammed: {len(pub8)}"
    print("Scenario 8 (duplicate identical chain outcome -- cooled down, not spammed) PASSED")

    mon9, pub9 = make_monitor()
    await feed(mon9, access_line(
        "203.0.113.70", "GET", "/wp-login.php", 301, host="example.com", xfh="-",
        scheme="http", location="https://example.com/wp-login.php",
    ))
    await feed(mon9, access_line(
        "203.0.113.70", "GET", "/wp-login.php", 444, host="example.com", xfh="-",
        scheme="https", location="-",
    ))
    assert len(pub9) == 1
    chain9 = pub9[0].metadata["redirect_chain"]
    assert chain9["scheme_confirmed"] is True, chain9
    assert "https://example.com/wp-login.php" in chain9["redirect"], chain9
    print("Scenario 9 (optional $scheme/$sent_http_location captured -- scheme CONFIRMED, real target shown) PASSED")

    mon10, pub10 = make_monitor()
    await feed(mon10, access_line("203.0.113.80", "GET", "/about-us", 301))
    await feed(mon10, access_line("203.0.113.80", "GET", "/about-us", 200))
    assert pub10 == [], "an ordinary, non-suspicious redirect must never generate a chain alert"
    print("Scenario 10 (benign redirect, no matching signature -- correctly silent) PASSED")

    mon11, pub11 = make_monitor()
    await feed(mon11, access_line("2001:db8::1", "GET", "/xmlrpc.php", 301))
    await feed(mon11, access_line("2001:db8::1", "GET", "/xmlrpc.php", 444))
    assert len(pub11) == 1, pub11
    assert pub11[0].source_ip == "2001:db8::1"
    assert pub11[0].metadata["redirect_chain"]["protection_result"] == "BLOCKED"
    print("Scenario 11 (IPv6 source address correlates identically) PASSED")

    print("\nALL NGINX REDIRECT-CHAIN CORRELATION REGRESSION TESTS PASSED")


asyncio.run(main())
