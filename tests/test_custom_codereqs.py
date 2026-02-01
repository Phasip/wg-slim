import os
from typing import Iterator
import pytest
import re

HACK_BYPASS_TEST = "# allow_motivation: "

# Forbidden names/strings and human-readable reasons.
FORBIDDEN_MAP = {
    "TYPE_CHECKING": "Avoid ad-hoc type-checking imports in production code",
    "no_type_check": "Marker used to bypass type-checking; not allowed",
    "getattr": "Dynamic attribute access is forbidden; prefer explicit attributes",
    "hasattr": "Dynamic attribute checking is forbidden; prefer explicit attributes",
    "isinstance": "Dynamic type-checking is forbidden.",
    "except AttributeError": "Catching AttributeError is forbidden, you should know which attributes exist.",
    "except Exception": "Too broad exception handler.",
    "importlib.import_module": "Dynamic imports are forbidden; prefer static imports.",
    re.compile(r"^ +(from .* )?import .*$", re.MULTILINE): "All import must be top-level",
    re.compile(r".*@app.*api/.*", re.MULTILINE): "Do not define any routes yourselves, they are generated from openapi.yaml.",
}


def _collect_py_files() -> Iterator[str]:
    """Collect all .py files in the repository, excluding certain directories."""
    repo_root = os.path.dirname(os.path.dirname(__file__))
    ignore_dirs = {".venv", "__pycache__", "tests", "openapi_generated"}
    for dirpath, dirs, filenames in os.walk(repo_root):
        for ignore in ignore_dirs:
            if ignore in dirs:
                dirs.remove(ignore)

        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


PY_FILES = _collect_py_files()


@pytest.mark.parametrize("path", PY_FILES)
def test_no_type_checking_imports(path: str) -> None:
    """Fail if the file at `path` contains any banned identifier.

    Reporting is per-file so pytest shows a separate test result for every
    checked file which makes it very clear where forbidden usage appears.
    """
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().splitlines()
        content = [line for line in content if not line.strip().startswith("#")]
        content = [line for line in content if HACK_BYPASS_TEST not in line]
        content = "\n".join(content)
    found = []
    for search, issue in FORBIDDEN_MAP.items():
        matched = None
        if type(search) is str:
            if search in content:
                matched = search
        else:
            m = search.search(content)
            if m:
                matched = m.group(0)
        if matched:
            found.append(f"Forbidden identifier found in {path}: '{matched}': {issue}")

    if found:
        pytest.fail("\n".join(found))
