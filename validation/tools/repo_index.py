from __future__ import annotations

import ast
import glob
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOURCE_DIRS = ("core", "modules", "database", "discord_integration", "config", ".")
EXCLUDE_PREFIXES = ("validation/", "tests/", "plugins/")

SINK_SHELL = "SHELL"
SINK_SUBPROCESS = "SUBPROCESS"
SINK_EVAL = "EVAL"
SINK_FS_WRITE = "FS_WRITE"
SINK_FS_DELETE = "FS_DELETE"
SINK_NETWORK = "NETWORK"
SINK_DB_WRITE = "DB_WRITE"
SINK_PROC_CONTROL = "PROC_CONTROL"
SINK_SUDO = "SUDO"
SINK_TASK = "TASK_SPAWN"
SINK_THREAD = "THREAD_POOL"

_SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}
_FS_WRITE_ATTRS = {"write_text", "write_bytes", "touch", "mkdir", "symlink_to", "chmod", "chown", "rename", "replace"}
_FS_DELETE_ATTRS = {"unlink", "rmdir", "rmtree", "remove", "removedirs"}
_FS_WRITE_FUNCS = {"atomic_write_json", "makedirs", "mkdir", "chmod", "chown", "lchown", "rename", "replace", "symlink", "copy", "copy2", "copyfile", "copytree", "move", "utime", "truncate"}
_NET_ATTRS = {"urlopen", "create_connection", "getaddrinfo", "ClientSession", "open_connection", "start_server", "create_server"}
_NET_METHODS = {"get", "post", "put", "delete", "patch", "head", "request"}
_PROC_ATTRS = {"kill", "terminate", "killpg", "send_signal"}
_TASK_ATTRS = {"create_task", "ensure_future"}
_THREAD_NAMES = {"Thread", "ThreadPoolExecutor", "ProcessPoolExecutor", "Process"}


@dataclass
class Sink:
    kind: str
    line: int
    detail: str = ""
    executable: str = ""
    dynamic: bool = False


@dataclass
class FuncInfo:
    file: str
    qualname: str
    lineno: int
    end_lineno: int
    cls: str = ""
    sinks: List[Sink] = field(default_factory=list)
    calls: List[Tuple[str, str, int]] = field(default_factory=list)
    is_async: bool = False
    decorators: List[str] = field(default_factory=list)
    params: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.file}::{self.qualname}"


def iter_source_files() -> List[str]:
    out: List[str] = []
    for directory in SOURCE_DIRS:
        pattern = os.path.join(ROOT, directory, "*.py")
        for path in sorted(glob.glob(pattern)):
            rel = os.path.relpath(path, ROOT)
            if rel.startswith(EXCLUDE_PREFIXES):
                continue
            out.append(rel)
    return sorted(set(out))


def module_name_of(rel: str) -> str:
    return rel[:-3].replace("/", ".")


def _const_str(node: ast.AST) -> Optional[str]:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _is_dynamic(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_is_dynamic(e) for e in node.elts)
    if isinstance(node, ast.Starred):
        return True
    return True


def _first_executable(node: ast.AST) -> str:
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        first = node.elts[0]
        const = _const_str(first)
        if const is not None:
            return os.path.basename(const)
        if isinstance(first, ast.Starred):
            return ""
        if isinstance(first, ast.Name):
            return f"${first.id}"
        return "<dynamic>"
    const = _const_str(node)
    if const is not None:
        return os.path.basename(const.split()[0]) if const.split() else ""
    return ""


def _contains_sudo(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and sub.value == "sudo":
            return True
    return False


def _open_mode(call: ast.Call) -> str:
    mode = ""
    if len(call.args) > 1 and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str):
        mode = call.args[1].value
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            mode = kw.value.value
    return mode


def _dotted(node: ast.AST) -> str:
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        inner = _dotted(node.func)
        if inner:
            parts.append(inner + "()")
    return ".".join(reversed(parts))


class _FuncVisitor(ast.NodeVisitor):
    def __init__(self, info: FuncInfo, sql_write: re.Pattern) -> None:
        self.info = info
        self.sql_write = sql_write

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._classify(node)
        self.generic_visit(node)

    def _add(self, kind: str, node: ast.AST, detail: str = "", executable: str = "", dynamic: bool = False) -> None:
        self.info.sinks.append(Sink(kind, getattr(node, "lineno", 0), detail, executable, dynamic))

    def _classify(self, node: ast.Call) -> None:
        func = node.func
        dotted = _dotted(func)
        tail = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
        head = dotted.split(".")[0] if dotted else ""
        shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
        if head == "subprocess" and tail in _SUBPROCESS_FUNCS:
            arg = node.args[0] if node.args else None
            kind = SINK_SHELL if shell_true or tail in {"getoutput", "getstatusoutput"} else SINK_SUBPROCESS
            self._add(kind, node, dotted, _first_executable(arg) if arg is not None else "", _is_dynamic(arg) if arg is not None else False)
            if arg is not None and _contains_sudo(arg):
                self._add(SINK_SUDO, node, dotted)
            return
        if tail == "create_subprocess_exec":
            arg = node.args[0] if node.args else None
            exe = ""
            if arg is not None:
                exe = _const_str(arg) or (f"${arg.id}" if isinstance(arg, ast.Name) else "<dynamic>")
                exe = os.path.basename(exe)
            self._add(SINK_SUBPROCESS, node, "asyncio.create_subprocess_exec", exe, any(_is_dynamic(a) for a in node.args))
            if any(_const_str(a) == "sudo" for a in node.args):
                self._add(SINK_SUDO, node, "create_subprocess_exec")
            return
        if tail == "create_subprocess_shell":
            self._add(SINK_SHELL, node, "asyncio.create_subprocess_shell", "", True)
            return
        if head == "os" and tail in {"system", "popen"}:
            self._add(SINK_SHELL, node, dotted, "", True)
            return
        if head == "os" and (tail.startswith("exec") or tail.startswith("spawn")):
            self._add(SINK_SUBPROCESS, node, dotted, "", True)
            return
        if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
            self._add(SINK_EVAL, node, func.id, "", True)
            return
        if isinstance(func, ast.Name) and func.id == "open":
            mode = _open_mode(node)
            if any(ch in mode for ch in "wax+"):
                self._add(SINK_FS_WRITE, node, f"open(mode={mode})", "", node.args and _is_dynamic(node.args[0]))
            return
        if tail in _FS_DELETE_ATTRS and (head in {"os", "shutil"} or isinstance(func, ast.Attribute)):
            self._add(SINK_FS_DELETE, node, dotted, "", True)
            return
        if tail in _FS_WRITE_FUNCS and head in {"os", "shutil", ""}:
            self._add(SINK_FS_WRITE, node, dotted or tail, "", True)
            return
        if tail in _FS_WRITE_ATTRS and isinstance(func, ast.Attribute):
            self._add(SINK_FS_WRITE, node, dotted, "", True)
            return
        if tail in _NET_ATTRS:
            self._add(SINK_NETWORK, node, dotted or tail, "", True)
            return
        if tail in _NET_METHODS and isinstance(func, ast.Attribute) and head in {"session", "client", "http", "requests", "httpx", "self"} and node.args:
            if isinstance(node.args[0], (ast.JoinedStr, ast.Name, ast.Constant)) and (head != "self" or "session" in dotted):
                self._add(SINK_NETWORK, node, dotted, "", True)
            return
        if tail in _PROC_ATTRS:
            self._add(SINK_PROC_CONTROL, node, dotted, "", True)
            return
        if tail in _TASK_ATTRS:
            self._add(SINK_TASK, node, dotted, "", False)
            return
        if tail in _THREAD_NAMES:
            self._add(SINK_THREAD, node, dotted, "", False)
            return
        if tail == "run_in_executor":
            self._add(SINK_THREAD, node, dotted, "", False)
            return
        if tail.startswith("enqueue_"):
            self._add(SINK_DB_WRITE, node, dotted, "", False)
            return
        if tail == "execute" and node.args:
            sql = _const_str(node.args[0])
            if sql is not None and self.sql_write.search(sql):
                self._add(SINK_DB_WRITE, node, "sqlite execute", "", False)
            return


_SQL_WRITE = re.compile(r"^\s*(INSERT|UPDATE|DELETE|REPLACE|DROP|ALTER|CREATE)\b", re.I)


class RepoIndex:
    def __init__(self) -> None:
        self.files: List[str] = iter_source_files()
        self.trees: Dict[str, ast.Module] = {}
        self.sources: Dict[str, str] = {}
        self.funcs: Dict[str, FuncInfo] = {}
        self.by_name: Dict[str, List[str]] = defaultdict(list)
        self.classes: Dict[str, Dict[str, Any]] = {}
        self.imports: Dict[str, Dict[str, str]] = {}
        self.module_files: Dict[str, str] = {}
        for rel in self.files:
            self.module_files[module_name_of(rel)] = rel
        for rel in self.files:
            self._index_file(rel)

    def _index_file(self, rel: str) -> None:
        path = os.path.join(ROOT, rel)
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
        tree = ast.parse(source)
        self.sources[rel] = source
        self.trees[rel] = tree
        imports: Dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports[(alias.asname or alias.name).split(".")[0] if not alias.asname else alias.asname] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        self.imports[rel] = imports
        self._walk_scope(rel, tree, "", "")

    def _walk_scope(self, rel: str, node: ast.AST, prefix: str, cls: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                qual = f"{prefix}{child.name}"
                bases = [_dotted(b) for b in child.bases]
                self.classes[f"{rel}::{qual}"] = {"file": rel, "name": child.name, "qualname": qual, "bases": bases, "lineno": child.lineno, "end": child.end_lineno}
                self._walk_scope(rel, child, qual + ".", child.name)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}{child.name}"
                info = FuncInfo(
                    file=rel, qualname=qual, lineno=child.lineno, end_lineno=child.end_lineno or child.lineno, cls=cls,
                    is_async=isinstance(child, ast.AsyncFunctionDef), decorators=[ast.unparse(d) for d in child.decorator_list],
                )
                for arg in list(child.args.args) + list(child.args.kwonlyargs):
                    info.params.append({"name": arg.arg, "annotation": ast.unparse(arg.annotation) if arg.annotation else ""})
                visitor = _FuncVisitor(info, _SQL_WRITE)
                for stmt in child.body:
                    visitor.visit(stmt)
                self._collect_calls(info, child)
                self.funcs[info.key] = info
                self.by_name[child.name].append(info.key)
                self._walk_scope(rel, child, qual + ".", cls)
            elif isinstance(child, (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For, ast.While)):
                self._walk_scope(rel, child, prefix, cls)

    def _collect_calls(self, info: FuncInfo, fn: ast.AST) -> None:
        skip: Set[int] = set()
        for sub in ast.walk(fn):
            if sub is not fn and isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for inner in ast.walk(sub):
                    skip.add(id(inner))
        for sub in ast.walk(fn):
            if id(sub) in skip or not isinstance(sub, ast.Call):
                continue
            func = sub.func
            if isinstance(func, ast.Name):
                info.calls.append(("name", func.id, sub.lineno))
            elif isinstance(func, ast.Attribute):
                dotted = _dotted(func)
                if dotted.startswith("self."):
                    info.calls.append(("self", func.attr, sub.lineno))
                else:
                    info.calls.append(("attr", dotted, sub.lineno))

    def resolve(self, caller: FuncInfo, kind: str, name: str) -> List[str]:
        imports = self.imports.get(caller.file, {})
        if kind == "self":
            keys = [k for k in self.by_name.get(name, []) if self.funcs[k].file == caller.file and self.funcs[k].cls]
            if not keys:
                keys = [k for k in self.by_name.get(name, []) if self.funcs[k].cls and len(self.by_name[name]) <= 3]
            return keys
        if kind == "name":
            local = [k for k in self.by_name.get(name, []) if self.funcs[k].file == caller.file and not self.funcs[k].cls]
            if local:
                return local
            target = imports.get(name)
            if target and "." in target:
                module, _, symbol = target.rpartition(".")
                rel = self.module_files.get(module)
                if rel:
                    hits = [k for k in self.by_name.get(symbol, []) if self.funcs[k].file == rel]
                    if hits:
                        return hits
                    cls_hits = [k for k in self.by_name.get("__init__", []) if self.funcs[k].file == rel and self.funcs[k].cls == symbol]
                    return cls_hits
            return []
        parts = name.split(".")
        head, tail = parts[0], parts[-1]
        target = imports.get(head)
        if target:
            module = target
            rel = self.module_files.get(module) or self.module_files.get(".".join(module.split(".")[:-1]))
            if rel is None and len(parts) > 1:
                rel = self.module_files.get(f"{module}")
            if rel:
                hits = [k for k in self.by_name.get(tail, []) if self.funcs[k].file == rel]
                if hits:
                    return hits
        candidates = self.by_name.get(tail, [])
        if 0 < len(candidates) <= 2 and not tail.startswith("__") and tail not in {"get", "set", "add", "run", "start", "stop", "close", "update", "load", "save", "append", "items", "keys", "values", "pop", "send", "write", "read"}:
            return [k for k in candidates if self.funcs[k].cls]
        return []

    def reachable(self, key: str, depth: int = 7) -> Dict[str, int]:
        seen: Dict[str, int] = {key: 0}
        frontier = [key]
        for level in range(1, depth + 1):
            nxt: List[str] = []
            for current in frontier:
                info = self.funcs[current]
                for kind, name, _line in info.calls:
                    for target in self.resolve(info, kind, name):
                        if target not in seen:
                            seen[target] = level
                            nxt.append(target)
            frontier = nxt
            if not frontier:
                break
        return seen

    def sinks_for(self, key: str, depth: int = 7) -> List[Tuple[str, Sink, int]]:
        out: List[Tuple[str, Sink, int]] = []
        for fkey, level in self.reachable(key, depth).items():
            for sink in self.funcs[fkey].sinks:
                out.append((fkey, sink, level))
        return out


def summarize_sinks(items: Iterable[Tuple[str, Sink, int]]) -> Dict[str, Any]:
    kinds: Dict[str, int] = defaultdict(int)
    executables: Set[str] = set()
    shell_sites: List[str] = []
    dynamic_exec: List[str] = []
    examples: Dict[str, List[str]] = defaultdict(list)
    for fkey, sink, level in items:
        kinds[sink.kind] += 1
        if sink.executable:
            executables.add(sink.executable)
        site = f"{fkey.split('::')[0]}:{sink.line}"
        if sink.kind in (SINK_SHELL, SINK_EVAL):
            shell_sites.append(f"{site} {sink.detail}")
        if sink.kind == SINK_SUBPROCESS and sink.dynamic and sink.executable in ("<dynamic>",):
            dynamic_exec.append(site)
        if len(examples[sink.kind]) < 3:
            examples[sink.kind].append(f"{site} {sink.detail}".strip())
    return {
        "kinds": dict(sorted(kinds.items())), "executables": sorted(executables), "shell_or_eval_sites": sorted(set(shell_sites))[:10],
        "dynamic_executable_sites": sorted(set(dynamic_exec))[:10], "examples": {k: v for k, v in examples.items()},
    }
