import subprocess


def test_ruff():
    subprocess.check_call(["ruff", "check", "."])
    subprocess.check_call(
        [
            "ruff",
            "check",
            ".",
            "--select=E501,W291,W293,E402,F401,F821",
        ]
    )


def test_pyright():
    subprocess.check_call(["pyright"])
