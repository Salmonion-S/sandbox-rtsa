from __future__ import annotations

import ast
import glob
import json
import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

from repo_index import ROOT, SINK_EVAL, SINK_SHELL, RepoIndex, summarize_sinks

OUT_DIR = os.path.join(ROOT, "validation")
BOT = "discord_integration/bot.py"
WEBHOOK = "discord_integration/webhook.py"
_ACTION_ID = re.compile(r"rtsa_action:([A-Za-z0-9_]+):")
_SLEEP_CONST = re.compile(r"asyncio\.sleep\(\s*([0-9.]+)\s*\)")


def _dec_call(node: ast.AST, name: str) -> Optional[ast.Call]:
    for dec in getattr(node, "decorator_list", []):
        if isinstance(dec, ast.Call) and ast.unparse(dec.func).endswith(name):
            return dec
    return None


def _kw(call: ast.Call, name: str) -> Optional[ast.AST]:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _const(node: Optional[ast.AST]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    return None


def runtime_commands() -> Dict[str, Dict[str, Any]]:
    from config.manager import CloudflareConfig, DiscordConfig, RTSAConfig
    from core.event_bus import EventBus
    from discord_integration.bot import RTSABot

    cfg = RTSAConfig(cloudflare=CloudflareConfig(enabled=False))
    bot = RTSABot(DiscordConfig(enabled=True), cfg, EventBus(), db_worker=None, supervisor=None)
    out: Dict[str, Dict[str, Any]] = {}
    for command in bot.tree.walk_commands():
        params = []
        for p in getattr(command, "parameters", []):
            params.append({
                "name": p.name, "type": str(p.type).replace("AppCommandOptionType.", ""), "required": bool(p.required),
                "choices": [c.name for c in getattr(p, "choices", [])] or None, "max_length": getattr(p, "max_length", None), "description": p.description,
            })
        out[command.qualified_name] = {"description": command.description, "parameters": params, "kind": type(command).__name__}
    return out


def static_commands(index: RepoIndex) -> List[Dict[str, Any]]:
    tree = index.trees[BOT]
    register = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_register_commands":
            register = node
            break
    if register is None:
        return []
    commands: List[Dict[str, Any]] = []
    for node in ast.walk(register):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node is register:
            continue
        call = _dec_call(node, ".command")
        if call is None:
            continue
        name = _const(_kw(call, "name")) or node.name
        description = _const(_kw(call, "description")) or ""
        describe = _dec_call(node, "describe")
        described = {kw.arg: _const(kw.value) for kw in describe.keywords} if describe else {}
        choices = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and ast.unparse(dec.func).endswith("choices"):
                choices.append(ast.unparse(dec))
        params = []
        args = node.args.args[1:]
        defaults = [None] * (len(args) - len(node.args.defaults)) + list(node.args.defaults)
        for arg, default in zip(args, defaults):
            params.append({
                "name": arg.arg, "annotation": ast.unparse(arg.annotation) if arg.annotation else "", "required": default is None,
                "default": ast.unparse(default) if default is not None else None, "description": described.get(arg.arg, ""),
            })
        auth: List[str] = []
        auth_lines: List[int] = []
        has_defer = False
        first_defer_line = 0
        views: Set[str] = set()
        locks: Set[str] = set()
        called: List[str] = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                text = ast.unparse(sub.func)
                if text.endswith("_authorized_interaction"):
                    critical = any(kw.arg == "critical" and _const(kw.value) is True for kw in sub.keywords)
                    auth.append("critical" if critical else "admin")
                    auth_lines.append(sub.lineno)
                if text.endswith("is_authorized") or text.endswith("_is_authorized"):
                    auth.append("direct:" + ast.unparse(sub)[:60])
                    auth_lines.append(sub.lineno)
                if text.endswith("response.defer"):
                    has_defer = True
                    first_defer_line = first_defer_line or sub.lineno
                if re.search(r"_try_claim|ActionLock|acquire|_lock", text):
                    locks.add(text)
                if text.startswith("self._"):
                    called.append(text.split(".", 1)[1])
            if isinstance(sub, ast.Call) and "View(" in ast.unparse(sub.func) + "(":
                views.add(ast.unparse(sub.func))
            if isinstance(sub, ast.AsyncWith):
                for item in sub.items:
                    txt = ast.unparse(item.context_expr)
                    if "lock" in txt.lower():
                        locks.add(txt)
        commands.append({
            "name": name, "function": node.name, "line": node.lineno, "description": description, "parameters": params, "choices": choices,
            "auth": sorted(set(auth)) or ["NONE"], "auth_before_defer": bool(auth_lines and (not first_defer_line or min(auth_lines) < first_defer_line)),
            "defers": has_defer, "views": sorted(views), "locks": sorted(locks), "helpers": sorted(set(called))[:12],
        })
    return commands


def command_sinks(index: RepoIndex, commands: List[Dict[str, Any]]) -> None:
    for command in commands:
        key = f"{BOT}::RTSABot._register_commands.{command['function']}"
        if key not in index.funcs:
            command["sinks"] = {"error": "function not indexed"}
            continue
        sinks = index.sinks_for(key, depth=7)
        command["sinks"] = summarize_sinks(sinks)
        reach = index.reachable(key, depth=7)
        command["reachable_functions"] = len(reach)
        via: List[str] = []
        for fkey, level in sorted(reach.items(), key=lambda kv: kv[1]):
            if fkey == key or level > 3:
                continue
            info = index.funcs[fkey]
            lines = index.sources[info.file].splitlines()[info.lineno - 1:info.end_lineno]
            body = "\n".join(lines)
            if re.search(r"_authorized_interaction\(", body):
                tier = "critical" if re.search(r"_authorized_interaction\([^)]*critical\s*=\s*True", body) else "admin"
                via.append(f"{info.qualname.split('.')[-1]}:{tier}")
            elif re.search(r"\b_is_authorized\(", body):
                via.append(f"{info.qualname.split('.')[-1]}:direct")
        command["auth_via_helpers"] = via[:6]
        if command["auth"] == ["NONE"] and via:
            command["auth"] = ["via-helper:" + via[0]]
        command["auth_effective"] = "NONE" if command["auth"] == ["NONE"] else ",".join(command["auth"])


def components(index: RepoIndex) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rel in ("discord_integration/bot.py", "discord_integration/webhook.py", "discord_integration/vhost_ports.py", "discord_integration/lb_bot_ports.py", "discord_integration/auto_ssl_ports.py", "discord_integration/lb_bgp_ports.py", "discord_integration/correlation_alert.py", "discord_integration/credential_rotation.py", "discord_integration/cloudflare.py"):
        tree = index.trees.get(rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = [ast.unparse(b) for b in node.bases]
            if not any("ui.View" in b or "ui.Select" in b or "ui.Modal" in b or b.endswith("View") for b in bases):
                continue
            buttons = []
            check = None
            timeout = None
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    dec = _dec_call(item, "ui.button")
                    if dec is not None:
                        key = f"{rel}::{node.name}.{item.name}"
                        sinks = summarize_sinks(index.sinks_for(key, depth=6)) if key in index.funcs else {}
                        buttons.append({"method": item.name, "label": _const(_kw(dec, "label")), "style": ast.unparse(_kw(dec, "style")) if _kw(dec, "style") else None,
                                        "custom_id": _const(_kw(dec, "custom_id")), "sinks": sinks.get("kinds", {})})
                    if item.name == "interaction_check":
                        check = ast.unparse(item)[:400]
                    if item.name == "__init__":
                        for sub in ast.walk(item):
                            if isinstance(sub, ast.Call) and ast.unparse(sub.func) == "super().__init__":
                                tv = _kw(sub, "timeout")
                                timeout = ast.unparse(tv) if tv is not None else None
                    for sub in ast.walk(item):
                        if isinstance(sub, ast.Call) and ast.unparse(sub.func).endswith("ui.Button"):
                            buttons.append({"method": f"{item.name} (dynamic)", "label": ast.unparse(_kw(sub, "label")) if _kw(sub, "label") else None, "style": None,
                                            "custom_id": ast.unparse(_kw(sub, "custom_id")) if _kw(sub, "custom_id") else None, "sinks": {}})
            out.append({"class": node.name, "file": rel, "line": node.lineno, "bases": bases, "timeout": timeout, "buttons": buttons, "has_interaction_check": check is not None,
                        "interaction_check": check})
    return out


def alert_actions(index: RepoIndex) -> Dict[str, Any]:
    emitted: Dict[str, List[int]] = defaultdict(list)
    for rel in (WEBHOOK, BOT):
        for number, line in enumerate(index.sources[rel].splitlines(), 1):
            for match in _ACTION_ID.finditer(line):
                emitted[match.group(1)].append(number if rel == WEBHOOK else -number)
    handled: Set[str] = set()
    tree = index.trees[BOT]
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "on_interaction":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Compare) and isinstance(sub.left, ast.Name) and sub.left.id == "action":
                    for comp in sub.comparators:
                        if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                            handled.add(comp.value)
                        elif isinstance(comp, (ast.Tuple, ast.List, ast.Set)):
                            for elt in comp.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    handled.add(elt.value)
    action_tables: Dict[str, List[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and re.search(r"ACTION", target.id) and isinstance(node.value, (ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Call)):
                    consts = [n.value for n in ast.walk(node.value) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
                    action_tables[target.id] = consts[:50]
    return {
        "emitted": {k: sorted(set(abs(x) for x in v)) for k, v in sorted(emitted.items())}, "handled_in_on_interaction": sorted(handled),
        "emitted_but_not_directly_handled": sorted(set(emitted) - handled), "handled_but_never_emitted": sorted(handled - set(emitted)), "action_tables": action_tables,
    }


def modules(index: RepoIndex) -> List[Dict[str, Any]]:
    main_tree = index.trees["main.py"]
    config_attr: Dict[str, str] = {}
    for node in ast.walk(main_tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_MODULE_CONFIG_ATTR" for t in node.targets) and isinstance(node.value, ast.Dict):
            for k, v in zip(node.value.keys, node.value.values):
                config_attr[_const(k)] = _const(v)
    out: List[Dict[str, Any]] = []
    category_pattern = re.compile(r"EventCategory\.([A-Z0-9_]+)")
    for rel in index.files:
        if not rel.startswith("modules/") or rel.endswith("base.py") or rel.endswith("__init__.py"):
            continue
        tree = index.trees[rel]
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            bases = [ast.unparse(b) for b in node.bases]
            if not any("BaseModule" in b for b in bases):
                continue
            module_name = None
            enabled_default = None
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name) and target.id == "module_name":
                            module_name = _const(item.value)
                        if isinstance(target, ast.Name) and target.id == "enabled_by_default":
                            enabled_default = _const(item.value)
            source = index.sources[rel]
            segment = "\n".join(source.splitlines()[node.lineno - 1:node.end_lineno])
            subs: Set[str] = set()
            for call in ast.walk(node):
                if isinstance(call, ast.Call) and ast.unparse(call.func).endswith(".subscribe"):
                    for kw in call.keywords:
                        if kw.arg == "categories":
                            subs.update(category_pattern.findall(ast.unparse(kw.value)))
                            if isinstance(kw.value, ast.Name):
                                subs.add(f"<{kw.value.id}>")
            for assign in tree.body:
                if isinstance(assign, ast.Assign) and any(isinstance(t, ast.Name) and f"<{t.id}>" in subs for t in assign.targets):
                    subs.discard(f"<{assign.targets[0].id}>")
                    subs.update(category_pattern.findall(ast.unparse(assign.value)))
            published: Set[str] = set()
            for call in ast.walk(node):
                if isinstance(call, ast.Call):
                    for kw in call.keywords:
                        if kw.arg == "category":
                            published.update(category_pattern.findall(ast.unparse(kw.value)))
            mentions = set(category_pattern.findall(segment))
            sinks = defaultdict(int)
            executables: Set[str] = set()
            shell_sites: List[str] = []
            for key, info in index.funcs.items():
                if info.file == rel and info.cls == node.name:
                    for sink in info.sinks:
                        sinks[sink.kind] += 1
                        if sink.executable:
                            executables.add(sink.executable)
                        if sink.kind in (SINK_SHELL, SINK_EVAL):
                            shell_sites.append(f"{rel}:{sink.line}")
            sleeps = sorted({float(x) for x in _SLEEP_CONST.findall(segment)})
            out.append({
                "class": node.name, "file": rel, "line": node.lineno, "module_name": module_name, "enabled_by_default": enabled_default, "config_attr": config_attr.get(module_name),
                "loc": node.end_lineno - node.lineno + 1, "subscribes": sorted(subs), "publishes_category_kw": sorted(published), "mentions_categories": sorted(mentions),
                "sink_counts": dict(sinks), "executables": sorted(executables), "shell_or_eval_sites": shell_sites, "sleep_constants": sleeps,
                "create_task_sites": segment.count("create_task("),
            })
    return out


def runtime_modules() -> List[Dict[str, Any]]:
    import importlib
    from pathlib import Path as P
    main = importlib.import_module("main")
    found = main.discover_modules(["modules"], P(ROOT))
    return [{"name": name, "class": f"{cls.__module__}.{cls.__name__}", "enabled_by_default": getattr(cls, "enabled_by_default", None),
             "api_version": getattr(getattr(cls, "manifest", None), "api_version", None)} for name, cls in sorted(found.items())]


def core_components(index: RepoIndex) -> List[Dict[str, Any]]:
    importers: Dict[str, Set[str]] = defaultdict(set)
    for rel, imports in index.imports.items():
        for target in imports.values():
            mod = target
            while mod:
                if mod in index.module_files:
                    importers[index.module_files[mod]].add(rel)
                    break
                mod = mod.rpartition(".")[0]
    out = []
    for rel in index.files:
        if not rel.startswith(("core/", "database/", "config/")):
            continue
        funcs = [f for f in index.funcs.values() if f.file == rel]
        sinks = defaultdict(int)
        executables: Set[str] = set()
        shell_sites: List[str] = []
        for f in funcs:
            for s in f.sinks:
                sinks[s.kind] += 1
                if s.executable:
                    executables.add(s.executable)
                if s.kind in (SINK_SHELL, SINK_EVAL):
                    shell_sites.append(f"{rel}:{s.line}")
        source = index.sources[rel]
        classes = [c["name"] for c in index.classes.values() if c["file"] == rel and "." not in c["qualname"]]
        out.append({
            "file": rel, "loc": source.count("\n") + 1, "classes": classes[:12], "functions": len(funcs), "imported_by": sorted(importers.get(rel, set()))[:15],
            "imported_by_count": len(importers.get(rel, set())), "sink_counts": dict(sinks), "executables": sorted(executables), "shell_or_eval_sites": shell_sites,
            "state_paths": sorted(set(re.findall(r"""["'](/(?:opt|var|etc|tmp|home|run|proc|sys)[^"'\s]*)["']""", source)))[:12],
        })
    return out


def event_categories(index: RepoIndex) -> Dict[str, Any]:
    tree = index.trees["core/datatypes.py"]
    members: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "EventCategory":
            for item in node.body:
                if isinstance(item, ast.Assign) and isinstance(item.targets[0], ast.Name):
                    members.append(item.targets[0].id)
    pattern = {m: re.compile(r"EventCategory\.%s\b" % m) for m in members}
    producers: Dict[str, Set[str]] = defaultdict(set)
    for rel, source in index.sources.items():
        if rel in ("core/datatypes.py",):
            continue
        for member, regex in pattern.items():
            if regex.search(source):
                producers[member].add(rel)
    webhook_src = index.sources[WEBHOOK]
    routed = {m for m in members if re.search(r"EventCategory\.%s\b" % m, webhook_src)}
    return {
        "count": len(members), "members": members,
        "referenced_in": {m: sorted(producers.get(m, set()))[:8] for m in members}, "unreferenced": [m for m in members if not producers.get(m)],
        "referenced_in_webhook": sorted(routed),
    }


def config_surface(index: RepoIndex) -> Dict[str, Any]:
    tree = index.trees["config/manager.py"]
    classes = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            fields = []
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    fields.append({"name": item.target.id, "type": ast.unparse(item.annotation), "default": ast.unparse(item.value) if item.value is not None else None})
            classes[node.name] = fields
    state_fields = []
    for cls, fields in classes.items():
        for f in fields:
            if re.search(r"(state|path|dir|file|db)_?(path|dir|file)?$|_path$|_dir$", f["name"]) and f["default"] and f["default"].startswith(("'/", '"/')):
                state_fields.append({"class": cls, "field": f["name"], "default": f["default"].strip("'\"")})
    return {"config_classes": len(classes), "total_fields": sum(len(v) for v in classes.values()), "state_path_fields": state_fields}


def polling_and_tasks(index: RepoIndex) -> Dict[str, Any]:
    fast: List[Dict[str, Any]] = []
    tasks: List[Dict[str, Any]] = []
    for rel, source in index.sources.items():
        for number, line in enumerate(source.splitlines(), 1):
            m = _SLEEP_CONST.search(line)
            if m and float(m.group(1)) <= 2.0:
                fast.append({"file": rel, "line": number, "seconds": float(m.group(1))})
            if "create_task(" in line or "ensure_future(" in line:
                tasks.append({"file": rel, "line": number, "code": line.strip()[:110]})
    return {"fast_sleeps_le_2s": fast, "task_spawn_sites": tasks}


def test_map(index: RepoIndex, commands: List[Dict[str, Any]], mods: List[Dict[str, Any]], cores: List[Dict[str, Any]]) -> Dict[str, Any]:
    tests = sorted(glob.glob(os.path.join(ROOT, "tests", "*.py")))
    sources: Dict[str, str] = {}
    for path in tests:
        with open(path, "r", encoding="utf-8") as handle:
            sources[os.path.relpath(path, ROOT)] = handle.read()
    suite = {k: v for k, v in sources.items() if os.path.basename(k).startswith("test_")}
    coverage_modules: Dict[str, List[str]] = {}
    for mod in mods:
        stem = os.path.basename(mod["file"])[:-3]
        hits = [t for t, s in suite.items() if re.search(r"modules\.%s\b|from modules import .*\b%s\b|\b%s\b" % (stem, stem, mod["class"]), s)]
        coverage_modules[mod["module_name"] or stem] = sorted(hits)
    coverage_core: Dict[str, List[str]] = {}
    for core in cores:
        stem = core["file"][:-3].replace("/", ".")
        short = os.path.basename(core["file"])[:-3]
        hits = [t for t, s in suite.items() if re.search(r"\b%s\b" % re.escape(stem), s) or re.search(r"from %s import|import %s\b" % (re.escape(stem.rpartition('.')[0]), re.escape(short)), s)]
        coverage_core[core["file"]] = sorted(hits)
    coverage_commands: Dict[str, List[str]] = {}
    for command in commands:
        name = command["name"]
        hits = [t for t, s in suite.items() if re.search(r"""/%s\b|["']%s["']|_%s_command|\b%s\(""" % (re.escape(name), re.escape(name), re.escape(name), re.escape(command["function"])), s)]
        coverage_commands[name] = sorted(hits)
    lab = [t for t in sources if os.path.basename(t).startswith("lab_")]
    return {
        "test_files": len(suite), "lab_files": lab, "helper_files": [t for t in sources if os.path.basename(t).startswith("_")],
        "commands": coverage_commands, "modules": coverage_modules, "core": coverage_core,
        "mock_heavy_hint": {t: s.count("Mock(") + s.count("MagicMock(") + s.count("monkeypatch") + s.count("lambda ") for t, s in suite.items() if "Mock" in s},
    }


def main() -> None:
    index = RepoIndex()
    runtime = runtime_commands()
    commands = static_commands(index)
    command_sinks(index, commands)
    static_names = {c["name"] for c in commands}
    comps = components(index)
    actions = alert_actions(index)
    mods = modules(index)
    cores = core_components(index)
    runtime_mods = runtime_modules()
    cats = event_categories(index)
    cfg = config_surface(index)
    loops = polling_and_tasks(index)
    tests = test_map(index, commands, mods, cores)
    for c in commands:
        rt = runtime.get(c["name"])
        c["runtime_registered"] = rt is not None
        if rt:
            c["runtime_parameters"] = rt["parameters"]
    inventory: Dict[str, Any] = {
        "generated_from": "AST + runtime discovery of the checked-out repository (no manual entries)",
        "git_head": os.popen("git -C %s rev-parse HEAD" % ROOT).read().strip(),
        "counts": {
            "source_files": len(index.files), "functions": len(index.funcs), "classes": len(index.classes), "slash_commands_static": len(commands), "slash_commands_runtime": len(runtime),
            "ui_view_classes": len(comps), "alert_actions_emitted": len(actions["emitted"]), "modules_static": len(mods), "modules_runtime": len(runtime_mods),
            "core_files": len([c for c in cores if c["file"].startswith("core/")]), "event_categories": cats["count"], "test_files": tests["test_files"],
        },
        "command_discovery_consistent": static_names == set(runtime),
        "commands_only_static": sorted(static_names - set(runtime)), "commands_only_runtime": sorted(set(runtime) - static_names),
        "commands": commands, "ui_components": comps, "alert_actions": actions, "modules": mods, "modules_runtime": runtime_mods, "core_components": cores,
        "event_categories": cats, "config": cfg, "polling_and_tasks": loops, "tests": tests,
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "RTSA_FULL_INVENTORY.json"), "w", encoding="utf-8") as handle:
        json.dump(inventory, handle, indent=1, sort_keys=False)
    print(json.dumps(inventory["counts"], indent=1))
    print("consistent:", inventory["command_discovery_consistent"], inventory["commands_only_static"], inventory["commands_only_runtime"])


if __name__ == "__main__":
    main()
