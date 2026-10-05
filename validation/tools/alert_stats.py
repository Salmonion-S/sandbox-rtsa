from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional


def load(path: str, start: Optional[float], end: Optional[float]) -> List[Dict[str, Any]]:
    rows = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if start is not None and row["t"] < start:
                    continue
                if end is not None and row["t"] > end:
                    continue
                rows.append(row)
    except OSError:
        pass
    return rows


def headline(row: Dict[str, Any]) -> str:
    for embed in row.get("embeds") or []:
        if embed.get("title"):
            return re.sub(r"\d+", "#", embed["title"])[:90]
    return re.sub(r"\d+", "#", (row.get("content") or "")[:90])


def summarize(rows: List[Dict[str, Any]], channel_names: Dict[int, str]) -> Dict[str, Any]:
    sends = [r for r in rows if r["kind"] == "send"]
    edits = [r for r in rows if r["kind"] == "edit"]
    by_channel = Counter(channel_names.get(r["channel_id"], str(r["channel_id"])) for r in sends)
    by_title = Counter(headline(r) for r in sends)
    per_minute: Dict[int, int] = defaultdict(int)
    for r in sends:
        per_minute[int(r["t"] // 60)] += 1
    peak = max(per_minute.values()) if per_minute else 0
    text_keys = Counter(json.dumps(r.get("embeds"), sort_keys=True) for r in sends)
    exact_dupes = sum(c - 1 for c in text_keys.values() if c > 1)
    buttons = Counter(b.get("custom_id", "").split(":")[1] if (b.get("custom_id") or "").startswith("rtsa_action:") else "other" for r in sends for b in r.get("buttons") or [])
    span = (rows[-1]["t"] - rows[0]["t"]) if len(rows) > 1 else 0
    return {
        "sends": len(sends), "edits": len(edits), "span_s": round(span, 1), "peak_sends_per_minute": peak, "exact_duplicate_sends": exact_dupes,
        "by_channel": dict(by_channel.most_common()), "by_title": dict(by_title.most_common(40)), "buttons": dict(buttons.most_common()),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--alerts", default="/var/lab-rtsa/run/alerts.jsonl")
    parser.add_argument("--channels", default="/var/lab-rtsa/rtsa/config/discord-server1.yaml")
    parser.add_argument("--start", type=float)
    parser.add_argument("--end", type=float)
    parser.add_argument("--out", default="")
    args = parser.parse_args()
    names: Dict[int, str] = {}
    try:
        import yaml
        with open(args.channels, "r", encoding="utf-8") as handle:
            cfg = yaml.safe_load(handle)
        names = {int(v): k for k, v in (cfg.get("category_channels") or {}).items()}
        names[int(cfg.get("alert_channel_id", 1))] = "alert_channel_id(default)"
    except (OSError, ValueError, ImportError):
        pass
    result = summarize(load(args.alerts, args.start, args.end), names)
    text = json.dumps(result, indent=1, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
    print(text)


if __name__ == "__main__":
    main()
