import asyncio
import ipaddress
import os
import socket
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
os.chdir(_REPO_ROOT)

from config.manager import NginxMonitorConfig
from core.event_bus import EventBus
from core.website_check import _is_public_ip, resolve_pinned_public_ip
from modules.nginx_monitor import NginxMonitor


def make_monitor(**overrides):
    cfg = NginxMonitorConfig(enabled=True, **overrides)
    return NginxMonitor(EventBus(), cfg)


async def main():
    for ip in (
        "127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.5", "169.254.169.254",
        "100.100.100.200", "::1", "fe80::1", "fc00::1", "224.0.0.1",
    ):
        assert _is_public_ip(ip) is False, f"{ip} must be rejected as a fetch target"
    print("Scenario 1 (loopback/RFC1918/link-local/CGNAT/metadata/multicast semua ditolak) PASSED")

    for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
        assert _is_public_ip(ip) is True, f"{ip} must be allowed"
    print("Scenario 2 (IP publik biasa diizinkan) PASSED")

    loop = asyncio.get_running_loop()
    orig_getaddrinfo = loop.getaddrinfo

    async def fake_getaddrinfo_private(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    loop.getaddrinfo = fake_getaddrinfo_private
    try:
        result = await resolve_pinned_public_ip("attacker-controlled.example", 443)
        assert result is None, "a hostname resolving only to a private IP must be rejected"
    finally:
        loop.getaddrinfo = orig_getaddrinfo
    print("Scenario 3 (hostname yang resolve ke IP private -> ditolak, tidak connect) PASSED")

    async def fake_getaddrinfo_mixed(host, port, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
        ]

    loop.getaddrinfo = fake_getaddrinfo_mixed
    try:
        result = await resolve_pinned_public_ip("mixed.example", 443)
        assert result is not None and result[0] == "8.8.8.8", result
    finally:
        loop.getaddrinfo = orig_getaddrinfo
    print("Scenario 4 (hostname dengan campuran A record -- pilih yang publik) PASSED")

    mon = make_monitor()
    import modules.nginx_monitor as nginx_monitor_module
    orig_resolve = nginx_monitor_module.resolve_pinned_public_ip

    async def fake_resolve_none(host, port):
        return None

    nginx_monitor_module.resolve_pinned_public_ip = fake_resolve_none
    try:
        result = await mon._fetch("attacker-rebind.example", "/etc/passwd")
        assert result is None, "a domain with no public resolution must never be fetched"
    finally:
        nginx_monitor_module.resolve_pinned_public_ip = orig_resolve
    print("Scenario 5 (_fetch menolak sebelum membuka koneksi apa pun ke domain non-publik) PASSED")

    default_cfg = NginxMonitorConfig(enabled=True)
    assert default_cfg.verify_fetch_timeout_seconds == 5.0
    assert default_cfg.verify_fetch_max_bytes == 65536
    custom_cfg = NginxMonitorConfig(enabled=True, verify_fetch_timeout_seconds=2.0, verify_fetch_max_bytes=4096)
    assert custom_cfg.verify_fetch_timeout_seconds == 2.0
    assert custom_cfg.verify_fetch_max_bytes == 4096
    print("Scenario 6 (timeout & response-size limit configurable, default aman) PASSED")

    mon_disabled = make_monitor(response_validation_enabled=False)
    verdict, evidence, content_type = await mon_disabled._classify_response("example.com", "/x")
    assert verdict == "validation_disabled"
    assert evidence is None and content_type is None
    print("Scenario 7 (response_validation_enabled=false -- tidak ada fetch, verdict eksplisit) PASSED")

    print("\nALL SSRF-SAFE VERIFICATION TESTS PASSED")


asyncio.run(asyncio.wait_for(main(), timeout=60))
