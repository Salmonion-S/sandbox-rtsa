from __future__ import annotations

import json
import os
import sys
import threading
import time
from typing import Any, Dict, List, Optional

INSTALL = os.environ.get("RTSA_LAB_INSTALL", "/var/lab-rtsa/rtsa")
ALERTS = os.environ.get("RTSA_LAB_ALERTS", "/var/lab-rtsa/run/alerts.jsonl")
sys.path.insert(0, INSTALL)
os.chdir(INSTALL)

_LOCK = threading.Lock()


def _embed_dict(embed: Any) -> Dict[str, Any]:
    footer = getattr(embed, "footer", None)
    color = getattr(embed, "color", None)
    return {
        "title": getattr(embed, "title", None), "description": getattr(embed, "description", None),
        "fields": [[f.name, f.value] for f in (getattr(embed, "fields", None) or [])],
        "footer": getattr(footer, "text", None) if footer is not None else None,
        "color": getattr(color, "value", None) if color is not None else None,
    }


def _record(kind: str, channel_id: int, message_id: int, content: Optional[str], embeds: Optional[List[Any]], view: Any) -> None:
    row = {
        "t": time.time(), "kind": kind, "channel_id": channel_id, "message_id": message_id, "content": content,
        "embeds": [_embed_dict(e) for e in (embeds or [])],
        "buttons": [{"label": getattr(c, "label", None), "custom_id": getattr(c, "custom_id", None)} for c in (getattr(view, "children", None) or [])],
    }
    with _LOCK, open(ALERTS, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, default=str) + "\n")


class _Message:
    def __init__(self, channel: "_Channel", message_id: int) -> None:
        self.channel = channel
        self.id = message_id

    async def edit(self, content: Optional[str] = None, embeds: Optional[List[Any]] = None, view: Any = None, **kwargs: Any) -> "_Message":
        _record("edit", self.channel.id, self.id, content, embeds, view)
        return self


class _Channel:
    counter = [100000]

    def __init__(self, channel_id: int) -> None:
        self.id = channel_id
        self.name = f"lab-{channel_id}"

    async def send(self, content: Optional[str] = None, embeds: Optional[List[Any]] = None, view: Any = None, **kwargs: Any) -> _Message:
        _Channel.counter[0] += 1
        message_id = _Channel.counter[0]
        if kwargs.get("embed") is not None:
            embeds = list(embeds or []) + [kwargs["embed"]]
        _record("send", self.id, message_id, content, embeds, view)
        return _Message(self, message_id)

    async def fetch_message(self, message_id: int) -> _Message:
        return _Message(self, message_id)


class _CaptureBot:
    def __init__(self) -> None:
        from core.ban_state import BanStateManager
        self._channels: Dict[int, _Channel] = {}
        self._ban_state = BanStateManager()
        self.user = None

    def get_channel(self, channel_id: int) -> _Channel:
        return self._channels.setdefault(channel_id, _Channel(channel_id))

    async def fetch_channel(self, channel_id: int) -> _Channel:
        return self.get_channel(channel_id)

    def is_ready(self) -> bool:
        return True


def main() -> None:
    import discord_integration.webhook as webhook
    original_start = webhook.DiscordWebhookDispatcher.start
    original_set_bot = webhook.DiscordWebhookDispatcher.set_bot

    async def start(self: Any) -> None:
        await original_start(self)
        original_set_bot(self, _CaptureBot())

    def set_bot(self: Any, bot: Any) -> None:
        original_set_bot(self, bot if bot is not None else _CaptureBot())

    webhook.DiscordWebhookDispatcher.start = start
    webhook.DiscordWebhookDispatcher.set_bot = set_bot
    import main as rtsa_main

    async def no_gateway(self: Any) -> None:
        return None

    rtsa_main.RTSAEngine._run_discord_bot = no_gateway
    sys.argv = [os.path.join(INSTALL, "main.py")]
    rtsa_main.main()


if __name__ == "__main__":
    main()
