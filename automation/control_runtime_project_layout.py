"""Offline import-derived project layout metadata; never a trust receipt.

The selector hashes caller-supplied immutable Python source bytes and assigns
fixed regular-file targets below /rnr/project. It performs no filesystem reads,
source execution, image construction, or startup dispatch. Its syntactic import
walk does not prove the full interpreter, standard-library, ELF, or TCB closure.
It follows literal imports under every branch, including function bodies, and
always includes the package initializer. Known dynamic-call spellings are
rejected as a diagnostic guard; aliases, reflection and import hooks can evade
that guard. A returned layout is not proof that dynamic loading is absent.
"""
import ast
from dataclasses import dataclass
import hashlib
import re


ENTRY_MODULE = "automation.control_runtime_handoff"
OPERATIONAL_ENTRY_MODULE = "automation.control_runtime_operational"
_OPERATIONAL_ROOTS=(OPERATIONAL_ENTRY_MODULE,"automation.control_runtime_receiver",
                    "automation.control_runtime_dispatch","automation.control_runtime_consumer")
PROJECT_ROOT = "/rnr/project"
PROJECT_PACKAGE = "automation"
MAX_FILES = 4096
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_DYNAMIC_CALL_NAMES = {"__import__", "eval", "exec", "compile"}
_DYNAMIC_ATTRIBUTE_NAMES = {
    "__import__", "import_module", "exec_module", "module_from_spec",
    "spec_from_file_location", "run_module", "run_path", "reload",
}
_DYNAMIC_IMPORT_FUNCTIONS = {
    "__import__", "eval", "exec", "compile", "import_module",
    "exec_module", "module_from_spec", "spec_from_file_location",
    "run_module", "run_path", "reload",
}


@dataclass(frozen=True)
class ProjectSource:
    path: str
    content: bytes


@dataclass(frozen=True)
class PlacedSource:
    module: str
    source: str
    target: str
    sha256: str
    size: int
    mode: int


@dataclass(frozen=True)
class ProjectLayout:
    entry_module: str
    files: tuple[PlacedSource, ...]
    external_import_roots: tuple[str, ...]


def _module(path):
    if (type(path) is not str or not 1 < len(path) <= 4096
            or not path.startswith(PROJECT_PACKAGE + "/")
            or any(ord(char) < 32 or ord(char) > 126 or char == "\\"
                   for char in path)):
        raise ValueError("noncanonical project source path")
    parts = path.split("/")
    if (len(parts) != 2 or any(part in ("", ".", "..") for part in parts)
            or not parts[1].endswith(".py")):
        raise ValueError("unsupported project source path")
    leaf = parts[1][:-3]
    if leaf == "__init__":
        return PROJECT_PACKAGE
    if _MODULE.fullmatch(leaf) is None:
        raise ValueError("unsupported project module name")
    return PROJECT_PACKAGE + "." + leaf


def _dynamic_aliases(tree):
    aliases = set(_DYNAMIC_CALL_NAMES)
    builtin_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.name == "builtins":
                    builtin_modules.add(item.asname or item.name)
        if isinstance(node, ast.ImportFrom) and node.level == 0:
            module = node.module or ""
            for item in node.names:
                builtin_dynamic = (module == "builtins"
                                   and item.name in _DYNAMIC_CALL_NAMES)
                loader_dynamic = (module in ("importlib", "importlib.util", "runpy")
                                  and item.name in _DYNAMIC_IMPORT_FUNCTIONS)
                if builtin_dynamic or loader_dynamic:
                    aliases.add(item.asname or item.name)
    return aliases, builtin_modules


def _check_dynamic_calls(tree):
    aliases, builtin_modules = _dynamic_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Name) and function.id in aliases:
            raise ValueError("dynamic code or import call is unsupported")
        if isinstance(function, ast.Attribute):
            builtin_call = (function.attr in _DYNAMIC_CALL_NAMES
                            and isinstance(function.value, ast.Name)
                            and function.value.id in builtin_modules)
            if function.attr in _DYNAMIC_ATTRIBUTE_NAMES or builtin_call:
                raise ValueError("dynamic code or import call is unsupported")


def _relative_base(current, level, module):
    if level == 0:
        return module or ""
    in_project_package = (current == PROJECT_PACKAGE
                          or current.startswith(PROJECT_PACKAGE + "."))
    if level != 1 or not in_project_package:
        raise ValueError("relative import leaves fixed project package")
    return PROJECT_PACKAGE + ("." + module if module else "")


def _imports(tree, current, modules):
    edges = set()
    external = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.name == PROJECT_PACKAGE or item.name.startswith(PROJECT_PACKAGE + "."):
                    if item.name not in modules:
                        raise ValueError("missing project module: " + item.name)
                    edges.add(item.name)
                else:
                    external.add(item.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            base = _relative_base(current, node.level, node.module)
            if base == PROJECT_PACKAGE or base.startswith(PROJECT_PACKAGE + "."):
                if node.names and any(item.name == "*" for item in node.names):
                    raise ValueError("project star import is unsupported")
                if base not in modules:
                    raise ValueError("missing project module: " + base)
                edges.add(base)
                if base == PROJECT_PACKAGE:
                    for item in node.names:
                        imported = PROJECT_PACKAGE + "." + item.name
                        if imported not in modules:
                            raise ValueError("missing project module: " + imported)
                        edges.add(imported)
            elif node.level:
                raise ValueError("relative import leaves fixed project package")
            else:
                external.add((node.module or "").split(".", 1)[0])
    return edges, external


def select_project_layout(sources):
    """Select the fixed entry's reachable .py source bytes as data only.

    Input paths name source records; they are never opened. Every reachable
    project import must map to a supplied top-level automation module. The
    resulting hashes and targets describe the supplied bytes only and do not
    attest their filesystem identity, origin, or use by a running interpreter.
    Nested packages and package-attribute imports are outside this flat-module
    profile; from automation import NAME requires a supplied NAME.py module.
    """
    return _select_layout(sources,ENTRY_MODULE,(ENTRY_MODULE,))


def select_operational_project_layout(sources):
    """Fixed operational/lifecycle roots as data, never complete runtime trust.

    Full interpreter/ELF/data and external tools project closure must still be
    assembled and independently verified before execution. No caller roots.
    """
    return _select_layout(sources,OPERATIONAL_ENTRY_MODULE,_OPERATIONAL_ROOTS)


def _select_layout(sources,entry_module,roots):
    if type(sources) is not tuple or not 1 <= len(sources) <= MAX_FILES:
        raise ValueError("bounded immutable project source tuple required")
    modules = {}
    total = 0
    for source in sources:
        if type(source) is not ProjectSource:
            raise ValueError("exact project source record required")
        module = _module(source.path)
        if module in modules:
            raise ValueError("duplicate project module")
        if type(source.content) is not bytes:
            raise ValueError("immutable bytes required")
        size = len(source.content)
        if size > MAX_SOURCE_BYTES:
            raise ValueError("project source byte bound exceeded")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("project source aggregate bound exceeded")
        modules[module] = source
    if PROJECT_PACKAGE not in modules or any(module not in modules for module in roots):
        raise ValueError("fixed project package and entry required")

    parsed = {}
    external = set()
    # Importing a submodule always loads its package first, even when the
    # submodule itself contains no imports that mention the package.
    pending = [*roots, PROJECT_PACKAGE]
    reachable = set()
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        source = modules.get(current)
        if source is None:
            raise ValueError("missing project module: " + current)
        try:
            tree = ast.parse(source.content, filename=source.path)
        except (SyntaxError, UnicodeError, ValueError, RecursionError) as error:
            raise ValueError("invalid project source syntax") from error
        _check_dynamic_calls(tree)
        found, imports = _imports(tree, current, modules)
        reachable.add(current)
        parsed[current] = source
        external.update(imports)
        pending.extend(sorted(found - reachable, reverse=True))

    placed = []
    for current in sorted(reachable):
        source = parsed[current]
        placed.append(PlacedSource(
            module=current,
            source=source.path,
            target=PROJECT_ROOT + "/" + source.path,
            sha256=hashlib.sha256(source.content).hexdigest(),
            size=len(source.content),
            mode=0o444,
        ))
    placed.sort(key=lambda item: item.target)
    return ProjectLayout(entry_module, tuple(placed), tuple(sorted(external)))
