"""Project-specific code requirements, checked against the AST.

These rules exist to keep the hand-written code explicit: no dynamic attribute
access, no dynamic imports, no blanket exception handlers, and no hand-rolled
API routes (those are generated from `openapi.yaml`).

The checks run on the parsed AST rather than on raw text, so an identifier only
counts when it is really *called* - `getattr(x, "y")` is a finding, but the word
"getattr" in a docstring, a comment, or a variable named `getattr_is_banned` is
not. A line may still opt out with a trailing `# allow_motivation: <reason>`.
"""

import ast
import os
from typing import Iterator

import pytest

HACK_BYPASS_TEST = "# allow_motivation: "

# Functions that must never be called.
FORBIDDEN_CALLS = {
    "getattr": "Dynamic attribute access is forbidden; prefer explicit attributes",
    "hasattr": "Dynamic attribute checking is forbidden; prefer explicit attributes",
    "delattr": "Dynamic attribute access is forbidden; prefer explicit attributes",
    "isinstance": "Dynamic type-checking is forbidden.",
    "issubclass": "Dynamic type-checking is forbidden.",
    "importlib.import_module": "Dynamic imports are forbidden; prefer static imports.",
    "__import__": "Dynamic imports are forbidden; prefer static imports.",
}

# The same rules keyed by the last dotted segment, so an imported-and-rebound
# `import_module(...)` is caught as well as `importlib.import_module(...)`.
_FORBIDDEN_CALL_TAILS = {name.rsplit(".", 1)[-1]: issue for name, issue in FORBIDDEN_CALLS.items()}

# Names that must never be imported or referenced.
FORBIDDEN_NAMES = {
    "TYPE_CHECKING": "Avoid ad-hoc type-checking imports in production code",
    "no_type_check": "Marker used to bypass type-checking; not allowed",
}

# Exception types that are too broad to catch.
FORBIDDEN_CATCHES = {
    "Exception": "Too broad exception handler.",
    "BaseException": "Too broad exception handler.",
    "AttributeError": "Catching AttributeError is forbidden, you should know which attributes exist.",
}


def _collect_py_files() -> Iterator[str]:
    """Collect all .py files in the repository, excluding certain directories."""
    repo_root = os.path.dirname(os.path.dirname(__file__))
    ignore_dirs = {".venv", "__pycache__", "tests", "openapi_generated", "data", "build"}
    for dirpath, dirs, filenames in os.walk(repo_root):
        for ignore in ignore_dirs:
            if ignore in dirs:
                dirs.remove(ignore)

        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


PY_FILES = sorted(_collect_py_files())


def _dotted_name(node: ast.expr) -> str:
    """Render `a.b.c` / `a` from an expression, or "" for anything else."""
    parts: list[str] = []
    while type(node) is ast.Attribute:
        parts.append(node.attr)
        node = node.value
    if type(node) is not ast.Name:
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


class _Checker(ast.NodeVisitor):
    """Walk a module and record every rule violation with its line number."""

    def __init__(self, exempt_lines: set[int]) -> None:
        self.exempt_lines = exempt_lines
        self.found: list[tuple[int, str, str]] = []

    def _record(self, node: ast.stmt | ast.expr | ast.excepthandler, matched: str, issue: str) -> None:
        if node.lineno in self.exempt_lines:
            return
        self.found.append((node.lineno, matched, issue))

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted_name(node.func)
        # Match the call both as written and by its final segment, so a
        # `from importlib import import_module` rebinding is caught alongside
        # the dotted `importlib.import_module(...)` spelling.
        if name in FORBIDDEN_CALLS:
            self._record(node, name, FORBIDDEN_CALLS[name])
        elif name.rsplit(".", 1)[-1] in _FORBIDDEN_CALL_TAILS:
            tail = name.rsplit(".", 1)[-1]
            self._record(node, tail, _FORBIDDEN_CALL_TAILS[tail])
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in FORBIDDEN_NAMES:
            self._record(node, node.id, FORBIDDEN_NAMES[node.id])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name in FORBIDDEN_NAMES:
                self._record(node, alias.name, FORBIDDEN_NAMES[alias.name])
        if node.col_offset > 0:
            self._record(node, "import", "All import must be top-level")
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        if node.col_offset > 0:
            self._record(node, "import", "All import must be top-level")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self._record(node, "except:", "Too broad exception handler.")
        else:
            types = node.type.elts if type(node.type) is ast.Tuple else [node.type]
            for exc in types:
                name = _dotted_name(exc)
                if name in FORBIDDEN_CATCHES:
                    self._record(node, f"except {name}", FORBIDDEN_CATCHES[name])
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_route_decorators(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_route_decorators(node)
        self.generic_visit(node)

    def _check_route_decorators(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Reject `@app.get("/api/...")`-style hand-written API routes."""
        for dec in node.decorator_list:
            if type(dec) is not ast.Call:
                continue
            target = _dotted_name(dec.func)
            if not target.startswith(("app.", "root_app.")):
                continue
            for arg in dec.args:
                if type(arg) is ast.Constant and type(arg.value) is str and "/api" in arg.value:
                    self._record(
                        dec,
                        target,
                        "Do not define any routes yourselves, they are generated from openapi.yaml.",
                    )


@pytest.mark.parametrize("path", PY_FILES)
def test_code_requirements(path: str) -> None:
    """Fail if the file at `path` breaks a project code requirement.

    Reporting is per-file so pytest shows a separate test result for every
    checked file which makes it very clear where forbidden usage appears.
    """
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()

    exempt_lines = {i for i, line in enumerate(source.splitlines(), start=1) if HACK_BYPASS_TEST in line}

    checker = _Checker(exempt_lines)
    checker.visit(ast.parse(source, filename=path))

    if checker.found:
        pytest.fail("\n".join(f"{path}:{line}: forbidden '{matched}': {issue}" for line, matched, issue in sorted(checker.found)))
