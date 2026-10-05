from __future__ import annotations

import glob
import json
import os
import sys
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RESULTS = os.path.join(ROOT, "validation", "results")
CASE_DIR = os.path.join(RESULTS, "command_campaign")
INVENTORY = os.path.join(ROOT, "validation", "RTSA_FULL_INVENTORY.json")

EFFECT_KINDS = {
    "SUBPROCESS", "SUBPROCESS_SYNC", "SUBPROCESS_SHELL", "FS_WRITE", "FS_DELETE", "FS_RENAME", "FS_CHMOD", "FS_CHOWN", "FS_LINK", "FS_MKDIR", "FS_UTIME", "FS_XATTR",
    "KILL", "NETWORK", "DNS", "NET_UNIX", "PROCESS_SPAWN", "PROCESS_STATE", "DB_WRITE", "DB_OPEN", "FS_WRITE_SANDBOX", "FS_DELETE_SANDBOX", "FS_RENAME_SANDBOX",
}
HARD_FLAGS = {"SHELL_INJECTION", "OPTION_INJECTION", "PATH_FROM_INPUT_TRAVERSAL", "SECRET_IN_REPLY", "PRIVDROP_WITHOUT_ENV"}
NOTE_FLAGS = {"PATH_FROM_INPUT", "NETWORK_FROM_INPUT"}
INFO_FLAGS = {"ROLE_MENTION_ECHOED", "EVERYONE_MENTION_ECHOED", "STORED_INPUT", "PAYLOAD_IN_ARGV", "SHELL_ARG_QUOTED"}


def effects(case: Dict[str, Any]) -> int:
    return sum(v for k, v in (case.get("side_effects") or {}).items() if k in EFFECT_KINDS)


def tier(inv_cmd: Dict[str, Any]) -> str:
    auth = inv_cmd.get("auth_effective", "")
    if auth == "NONE":
        return "none"
    if auth.endswith("critical") or auth == "critical":
        return "critical"
    if "direct" in auth:
        return "admin"
    return auth


def summarize_command(name: str, data: Dict[str, Any], inv_cmd: Dict[str, Any]) -> Dict[str, Any]:
    cases = data.get("cases", [])
    by_id = {c["id"]: c for c in cases}
    t = tier(inv_cmd)
    deny_callers = ["caller:no_roles_configured", "caller:unauthorized", "caller:dm_user"]
    if t == "critical":
        deny_callers.append("caller:admin_only")
    notes: List[str] = []
    failures: List[str] = []
    unauth_effects = 0
    unauth_state = "DENIED"
    for cid in deny_callers:
        c = by_id.get(cid)
        if c is None:
            continue
        n = effects(c)
        if t == "none":
            mut = c.get("mutations") or []
            unauth_effects += len(mut)
            if mut:
                unauth_state = "FAIL"
                failures.append(f"{cid} reached mutating sinks without any role check: {mut[:3]}")
            elif unauth_state != "FAIL":
                unauth_state = "OPEN (no role check, read-only)"
            continue
        unauth_effects += n
        if not c.get("denied") or n:
            unauth_state = "FAIL"
            failures.append(f"{cid}: denied={c.get('denied')} side_effects={c.get('side_effects')} reply={[r['text'][:80] for r in c.get('replies', [])[:1]]}")
    if t == "admin":
        c = by_id.get("caller:admin_only")
        if c and c.get("denied"):
            notes.append("admin_only caller denied although the static tier is admin")
    hard = set()
    soft = set()
    info = set()
    input_cases = [c for c in cases if c["id"].startswith("input:")]
    rejected = 0
    for c in input_cases:
        flags = set(c.get("flags") or [])
        hard |= flags & HARD_FLAGS
        soft |= flags & NOTE_FLAGS
        info |= flags & INFO_FLAGS
        if not (c.get("mutations")) and not (flags & (HARD_FLAGS | {"PATH_FROM_INPUT", "PAYLOAD_IN_ARGV", "NETWORK_FROM_INPUT"})):
            rejected += 1
    for c in cases:
        hard |= set(c.get("flags") or []) & {"SECRET_IN_REPLY", "PRIVDROP_WITHOUT_ENV"}
    if hard:
        for c in input_cases:
            bad = set(c.get("flags") or []) & HARD_FLAGS
            if bad:
                failures.append(f"{c['id']}: {sorted(bad)} mutations={c.get('mutations', [])[:2]}")
    injection = "SAFE" if not hard else "FAIL: " + ",".join(sorted(hard))
    if soft and not hard:
        injection = "SAFE (notes: " + ",".join(sorted(soft)) + ")"
    crit = by_id.get("caller:critical") or {}
    dro = by_id.get("caller:critical_detection_only") or {}
    crit_mut = crit.get("mutations") or []
    dro_mut = dro.get("mutations") or []
    if not crit_mut and not dro_mut:
        detection_only = "N/A (no mutation on valid input)"
    elif dro_mut:
        detection_only = "VIOLATED"
        failures.append(f"detection_only=true still executed: {dro_mut[:4]}")
    else:
        detection_only = "RESPECTED"
    confirm_case = by_id.get("confirm:other_user_then_cancel") or {}
    clicks = confirm_case.get("clicks") or []
    other = [k for k in clicks if k.get("click") == "other_user_confirm"]
    if not other:
        confirm = "-"
    elif all(k.get("interaction_check") is False for k in other):
        confirm = "ENFORCED"
    else:
        confirm = "FAIL"
        failures.append(f"another member could confirm: {other[:1]} mutations={confirm_case.get('mutations')}")
    conc = by_id.get("concurrency:x2") or {}
    conc_mut = conc.get("mutations") or []
    crit_sub = sum(v for k, v in (crit.get("side_effects") or {}).items() if k.startswith("SUBPROCESS"))
    conc_sub = sum(v for k, v in (conc.get("side_effects") or {}).items() if k.startswith("SUBPROCESS"))
    if not crit_mut:
        concurrency = "-"
    elif conc_sub >= 2 * crit_sub and crit_sub > 0:
        concurrency = "BOTH EXECUTED"
    else:
        concurrency = "SERIALIZED/COALESCED"
    comp_rows = data.get("components") or []
    comp_fail = [r for r in comp_rows if r["clicker"] == "other_guild_member" and r.get("interaction_check") is not False and r.get("mutations")]
    comp_open = [r for r in comp_rows if r["clicker"] == "other_guild_member" and r.get("interaction_check") is not False and not r.get("mutations")]
    for r in comp_fail:
        failures.append(f"button {r['view']}/{r['button']} executed for another guild member: {r['mutations'][:2]}")
    components = "-" if not comp_rows else ("FAIL" if comp_fail else ("REQUESTER-ONLY" if not comp_open else f"OPEN READ-ONLY x{len(comp_open)}"))
    robustness = {"exceptions": 0, "timeouts": 0, "no_response": 0, "protocol": 0, "lock_leaks": 0}
    exc_examples = []
    for c in cases:
        if c["outcome"] == "EXCEPTION":
            robustness["exceptions"] += 1
            exc_examples.append(f"{c['id']}: {c.get('error')}")
        elif c["outcome"] == "TIMEOUT":
            robustness["timeouts"] += 1
        if "NO_RESPONSE" in (c.get("protocol") or []):
            robustness["no_response"] += 1
        if [p for p in (c.get("protocol") or []) if p != "NO_RESPONSE"]:
            robustness["protocol"] += 1
        if c.get("lock_leaks"):
            robustness["lock_leaks"] += 1
    if robustness["lock_leaks"]:
        failures.append(f"lock leaked after {robustness['lock_leaks']} case(s)")
    if robustness["exceptions"]:
        notes.append(f"unhandled exceptions: {exc_examples[:3]}")
    logged = []
    for c in cases:
        for err in c.get("logged_errors") or []:
            logged.append(f"{c['id']}: {err}")
    robustness["logged_errors"] = len(logged)
    if logged:
        notes.append(f"errors logged by RTSA during {len(logged)} case(s), e.g. {logged[:2]}")
    valid_errors = [e for e in (crit.get("logged_errors") or [])] if crit else []
    if robustness["timeouts"]:
        notes.append(f"timeouts: {[c['id'] for c in cases if c['outcome'] == 'TIMEOUT'][:4]}")
    if failures:
        verdict = "FAIL"
    elif robustness["exceptions"] or robustness["timeouts"] or robustness["no_response"] or robustness["protocol"] or soft or valid_errors:
        verdict = "PASS WITH NOTES"
    else:
        verdict = "PASS"
    ack = [c.get("first_ack_s") for c in cases if c.get("first_ack_s") is not None]
    return {
        "tier": t, "cases": len(cases), "unauthorized": unauth_state, "side_effects_unauthorized": unauth_effects, "injection": injection,
        "input_cases": len(input_cases), "input_rejected_or_inert": rejected, "detection_only": detection_only, "confirm_gate": confirm, "concurrency": concurrency,
        "components": components, "robustness": robustness, "max_first_ack_s": max(ack) if ack else None, "verdict": verdict, "failures": failures, "notes": notes,
        "valid_reply": [r["text"][:200] for r in crit.get("replies", [])[:3]], "valid_mutations": crit_mut[:6], "valid_errors": valid_errors[:3],
        "valid_outcome": (crit.get("replies") or [{"text": ""}])[-1]["text"].replace("\n", " ")[:110], "info_flags": sorted(info),
    }


def summarize_alerts(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        a = out.setdefault(r["action"], {"cases": 0, "unauthorized": "DENIED", "detection_only": "-", "protected_target": "-", "replay_same_process": "-", "replay_after_restart": "-",
                                         "exceptions": 0, "failures": [], "notes": []})
        a["cases"] += 1
        if r["outcome"] == "EXCEPTION":
            a["exceptions"] += 1
            a["notes"].append(f"{r['event_id']}/{r['caller']}/{r['phase']}: {r.get('error')}")
        mut = r.get("mutations") or []
        n = sum(v for k, v in (r.get("side_effects") or {}).items() if k in EFFECT_KINDS)
        if r["caller"] in ("unauthorized", "dm_user", "admin_only") and r["phase"] == "first":
            if not r.get("denied") or n:
                a["unauthorized"] = "FAIL"
                a["failures"].append(f"{r['caller']} not denied: effects={r.get('side_effects')} reply={r.get('replies', [])[:1]}")
        if r["detection_only"] and r["phase"] == "first":
            if mut:
                a["detection_only"] = "VIOLATED"
                a["failures"].append(f"detection_only=true still executed: {mut[:3]}")
            elif a["detection_only"] == "-":
                a["detection_only"] = "RESPECTED"
        if r["event_id"].endswith("-protected") and r["phase"] == "first":
            replies_text = " ".join(r.get("replies") or [])
            if mut and ("Refused" in replies_text or "dilindungi" in replies_text):
                a["protected_target"] = "GUARDED: refused, executes only after a second explicit force confirmation"
            elif mut:
                a["protected_target"] = "EXECUTED: " + "; ".join(mut[:2])
            else:
                a["protected_target"] = "REFUSED/NO-OP: " + (r.get("replies") or [""])[0][:80]
        if r["phase"] in ("replay_same_process", "replay_after_restart") and r["event_id"].endswith("-ip"):
            a[r["phase"]] = ("RE-EXECUTED: " + "; ".join(mut[:2])) if mut else ("REJECTED: " + (r.get("replies") or [""])[0][:70])
    for a in out.values():
        a["verdict"] = "FAIL" if a["failures"] else ("PASS WITH NOTES" if a["exceptions"] or str(a["replay_after_restart"]).startswith("RE-EXECUTED") or str(a["protected_target"]).startswith("EXECUTED") else "PASS")
    return out


def main() -> None:
    try:
        with open(INVENTORY, "r", encoding="utf-8") as handle:
            inv = {c["name"]: c for c in json.load(handle)["commands"]}
    except (OSError, ValueError):
        print("inventory missing")
        sys.exit(1)
    commands: Dict[str, Any] = {}
    alerts: Dict[str, Any] = {}
    missing = []
    for name in sorted(inv):
        path = os.path.join(CASE_DIR, f"{name}.json")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            missing.append(name)
            continue
        commands[name] = summarize_command(name, data, inv[name])
    alert_path = os.path.join(CASE_DIR, "alerts.json")
    if os.path.exists(alert_path):
        with open(alert_path, "r", encoding="utf-8") as handle:
            alerts = summarize_alerts(json.load(handle).get("alert_cases", []))
    totals = {
        "commands_discovered": len(inv), "commands_tested": len(commands), "commands_missing_results": missing,
        "cases": sum(c["cases"] for c in commands.values()), "alert_cases": sum(a["cases"] for a in alerts.values()),
        "verdicts": {v: sum(1 for c in commands.values() if c["verdict"] == v) for v in ("PASS", "PASS WITH NOTES", "FAIL")},
        "alert_verdicts": {v: sum(1 for a in alerts.values() if a["verdict"] == v) for v in ("PASS", "PASS WITH NOTES", "FAIL")},
        "case_files": sorted(os.path.basename(p) for p in glob.glob(os.path.join(CASE_DIR, "*.json"))).__len__(),
    }
    with open(os.path.join(RESULTS, "command_campaign.json"), "w", encoding="utf-8") as handle:
        json.dump({"totals": totals, "commands": commands, "alerts": alerts}, handle, indent=1)
    print(json.dumps(totals, indent=1))


if __name__ == "__main__":
    main()
