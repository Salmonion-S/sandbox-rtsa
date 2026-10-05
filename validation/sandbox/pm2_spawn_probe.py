from __future__ import annotations

import argparse
import asyncio
import json
import os
import pwd
import subprocess
import sys
import time
from typing import Dict


def daemons() -> Dict[str, int]:
    out: Dict[str, int] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as handle:
                cmd = handle.read().replace(b"\0", b" ").decode(errors="replace")
            if "God Daemon" not in cmd:
                continue
            with open(f"/proc/{entry}/status", "r", encoding="utf-8") as handle:
                fields = dict(line.split(":", 1) for line in handle if ":" in line)
            user = pwd.getpwuid(int(fields["Uid"].split()[0])).pw_name
            out[user] = out.get(user, 0) + int(fields.get("VmRSS", "0 kB").split()[0])
        except (OSError, KeyError, ValueError):
            continue
    return out


def kill_daemon(user: str) -> None:
    info = pwd.getpwnam(user)
    env = {"HOME": info.pw_dir, "USER": user, "PATH": "/opt/node22/bin:/usr/bin:/bin", "PM2_HOME": os.path.join(info.pw_dir, ".pm2")}
    subprocess.run(["setpriv", f"--reuid={info.pw_uid}", f"--regid={info.pw_gid}", "--init-groups", "--", "/opt/node22/bin/pm2", "kill"],
                   env=env, capture_output=True, timeout=60)


async def run(install: str, label: str) -> Dict[str, object]:
    sys.path.insert(0, install)
    from config.manager import CloudflareConfig, DiscordConfig, RTSAConfig
    from core.event_bus import EventBus
    from discord_integration.bot import RTSABot

    class Db:
        db_path = ":memory:"

        def __getattr__(self, name: str):
            return lambda *args, **kwargs: None

    bot = RTSABot(DiscordConfig(enabled=True), RTSAConfig(cloudflare=CloudflareConfig(enabled=False)), EventBus(), db_worker=Db(), supervisor=None)
    before = daemons()
    t0 = time.time()
    rows = await bot._cekpm2()
    elapsed = time.time() - t0
    after = daemons()
    spawned = sorted(set(after) - set(before))
    statuses: Dict[str, int] = {}
    for r in rows:
        statuses[r.status] = statuses.get(r.status, 0) + 1
    for user in spawned:
        kill_daemon(user)
    return {
        "label": label, "install": install, "users_reported": len(rows), "statuses": statuses, "elapsed_s": round(elapsed, 1),
        "daemons_before": len(before), "daemons_after": len(after), "daemons_spawned_by_cekpm2": len(spawned),
        "rss_mb_spawned": round(sum(after[u] for u in spawned) / 1024.0, 1), "cleaned_up": len(spawned) - len(set(daemons()) - set(before)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--install", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    result = asyncio.run(run(args.install, args.label))
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=1)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
