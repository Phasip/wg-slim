import os
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(__file__))

# Hand-written browser JS. `openapi-client.js` is generated and bundled by
# `make openapi-client`, so it is not checked here.
STATIC_JS = ["static/js/dashboard.js", "static/js/login.js"]


def test_ruff():
    subprocess.check_call([sys.executable, "-m", "ruff", "check", "."])
    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            ".",
            "--select=E501,W291,W293,E402,F401,F821",
        ]
    )


def test_pyright():
    # `--pythonpath` pins the interpreter pyright resolves imports against.
    # Without it pyright picks whatever python is first on PATH, which is not
    # the one holding the generated `openapi_server` / `wgslim_api_client`
    # packages when running from a virtualenv.
    subprocess.check_call([sys.executable, "-m", "pyright", "--pythonpath", sys.executable])


@pytest.mark.parametrize("rel_path", STATIC_JS)
def test_static_js_parses(rel_path: str) -> None:
    """Syntax-check the hand-written browser JS.

    This used to be unreachable: the dashboard script lived inline in
    `templates/dashboard.html`, so a syntax error only showed up as a blank
    page in a browser.
    """
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")

    path = os.path.join(REPO_ROOT, rel_path)
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()

    # dashboard.js is loaded as `<script type="module">`, login.js as a classic
    # script; parse each the way the browser will.
    input_type = "module" if rel_path.endswith("dashboard.js") else "commonjs"
    result = subprocess.run(
        [node, f"--input-type={input_type}", "--check"],
        input=source,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"{rel_path} failed to parse:\n{result.stderr}"
