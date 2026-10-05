from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.manager import AutoVhostConfig
from core import vhost_recovery as vr
from core.auto_ssl import RecheckOutcome
from core.nginx_vhost_inspect import find_vhost_blocks

NOW = time.time()
USER = "shopuser"


class NvEnv:
    def __init__(self, tmp: str) -> None:
        self.tmp = tmp
        self.enabled = os.path.join(tmp, "nginx", "sites-enabled")
        self.available = os.path.join(tmp, "nginx", "sites-available")
        self.confd = os.path.join(tmp, "nginx", "conf.d")
        self.home = os.path.join(tmp, "home")
        self.php = os.path.join(tmp, "php")
        self.ssl = os.path.join(tmp, "ssl")
        for directory in (self.enabled, self.confd, self.home, os.path.join(self.php, "8.2", "fpm", "pool.d"), self.ssl):
            os.makedirs(directory, exist_ok=True)
        Path(self.tmp, "nginx", "fastcgi_params").write_text("fastcgi_param X y;\n")
        self.cfg = AutoVhostConfig(
            sites_available_directory=self.available, sites_enabled_directory=self.enabled, home_root=self.home,
            php_fpm_pool_glob=os.path.join(self.php, "*", "fpm", "pool.d", "*.conf"), ssl_certificate_directories=[self.ssl],
        )

    def project(self, user: str = USER, domain: str = "example.com", files: Optional[Dict[str, str]] = None) -> str:
        root = os.path.join(self.home, user, "htdocs", domain)
        os.makedirs(root, exist_ok=True)
        for name, content in (files or {}).items():
            path = os.path.join(root, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            Path(path).write_text(content)
        return root

    def snapshot(self) -> Dict[str, Tuple[str, Any]]:
        state: Dict[str, Tuple[str, Any]] = {}
        for base in (self.enabled, self.available, self.confd):
            if not os.path.isdir(base):
                continue
            for name in sorted(os.listdir(base)):
                path = os.path.join(base, name)
                if os.path.islink(path):
                    state[path] = ("link", os.readlink(path))
                else:
                    st = os.stat(path)
                    state[path] = ("file", (Path(path).read_bytes(), st.st_ino, st.st_mtime_ns))
        return state


class NvPorts(vr.VhostPorts):
    def __init__(self, env: NvEnv, domain: str = "example.com") -> None:
        self.env = env
        self.asset: Optional[Any] = SimpleNamespace(
            domain=domain, linux_user=USER, project_root=os.path.join(env.home, USER),
            htdocs_path=os.path.join(env.home, USER, "htdocs", domain), pm2_user=USER, nginx_vhost=None,
        )
        self.pm2: Optional[List[Dict[str, Any]]] = None
        self.listening: Dict[int, List[int]] = {}
        self.live_tests: List[Tuple[bool, str]] = [(True, "ok")]
        self.live_test_calls = 0
        self.candidate_result: Tuple[bool, str] = (True, "ok")
        self.reload_results: List[Tuple[bool, str]] = [(True, "reloaded")]
        self.reload_calls = 0

    async def resolve_asset(self, domain): return self.asset

    async def find_references(self, domain):
        blocks = []
        for directory in (self.env.enabled, self.env.confd):
            blocks.extend(find_vhost_blocks(directory, domain))
        return blocks

    def pm2_processes(self, user): return self.pm2
    def listening_ports(self, pid): return self.listening.get(pid, [])
    async def certbot_lineages(self, domain): return (True, [], "")
    async def certificate_file_facts(self, path): return None

    async def nginx_test(self):
        index = min(self.live_test_calls, len(self.live_tests) - 1)
        self.live_test_calls += 1
        return self.live_tests[index]

    async def nginx_test_candidate(self, candidate_path):
        return self.candidate_result

    async def nginx_reload(self, requested_by):
        index = min(self.reload_calls, len(self.reload_results) - 1)
        self.reload_calls += 1
        return self.reload_results[index]

    async def nginx_active(self): return True
    async def verify_website(self, domain, expect_https): return (True, "HTTP 200 OK, 40 ms", 40.0)
    async def recheck_website(self, domain): return RecheckOutcome(healthy=True, last_probe_ok=True)
    def mutations_allowed(self): return True
    def audit(self, record): return None
    def now(self): return NOW
