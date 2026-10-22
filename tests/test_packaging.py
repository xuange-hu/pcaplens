"""Packaging contract.

Borrowed deliberately from a bug I hit in `vehsec`: a console script was
declared in `[project.scripts]` while its runtime dependencies sat in an
optional extra, so `pip install vehsec && vehsec --help` crashed with
ModuleNotFoundError for every single user. CI missed it because CI installs
`[all]`.

The rule enforced here: for each console script, every third-party module
its target imports *at module scope* must be provided by `dependencies`
(always installed) or by that script's declared extras.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
SRC = ROOT / "src" / "pcaplens"

DIST_TO_IMPORTS = {"mcp": {"mcp"}}

# `pcaplens` must run on a bare install; `pcaplens-mcp` may require [mcp].
SCRIPT_EXTRAS = {
    "pcaplens": set(),
    "pcaplens-mcp": {"mcp"},
}


def _requirement_name(req: str) -> str:
    return re.split(r"[<>=!~\[; ]", req.strip().strip("'\","), 1)[0].strip("'\"")


def _array_body(text: str, header: str) -> list[str]:
    m = re.search(re.escape(header) + r"\s*=\s*\[(.*?)\]", text, re.S)
    if not m:
        return []
    return [a or b for a, b in re.findall(r"'([^']*)'|\"([^\"]*)\"", m.group(1))]


def _load() -> tuple[list[str], dict[str, list[str]]]:
    text = PYPROJECT.read_text(encoding="utf-8")
    base = _array_body(text, "dependencies")
    extras: dict[str, list[str]] = {}
    section = re.search(r"\[project\.optional-dependencies\](.*?)(?=\n\[)", text, re.S)
    if section:
        for name, body in re.findall(r"^(\w+)\s*=\s*\[(.*?)\]", section.group(1), re.S | re.M):
            extras[name] = [a or b for a, b in re.findall(r"'([^']*)'|\"([^\"]*)\"", body)]
    return base, extras


def _module_scope_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in tree.body:
        stmts = [node]
        if isinstance(node, ast.Try):  # mcp 1.x vs 2.x import shim
            stmts = list(node.body) + list(node.orelse)
        for stmt in stmts:
            if isinstance(stmt, ast.Import):
                found.update(n.name.split(".")[0] for n in stmt.names)
            elif isinstance(stmt, ast.ImportFrom) and stmt.module and stmt.level == 0:
                found.add(stmt.module.split(".")[0])
    return {m for m in found if m != "pcaplens" and m not in sys.stdlib_module_names}


BASE, EXTRAS = _load()


@pytest.mark.parametrize("script", sorted(SCRIPT_EXTRAS))
def test_console_script_dependencies_are_installable(script):
    text = PYPROJECT.read_text(encoding="utf-8")
    m = re.search(rf'^{re.escape(script)}\s*=\s*"([^":]+):', text, re.M)
    assert m, f"[project.scripts] has no entry for {script!r}"
    module = m.group(1)
    path = SRC / f"{module.split('.')[-1]}.py"
    assert path.exists(), f"{script!r} points at {module!r}"

    available = {_requirement_name(r) for r in BASE}
    for extra in SCRIPT_EXTRAS[script]:
        assert extra in EXTRAS, f"{script!r} relies on undeclared extra {extra!r}"
        available |= {_requirement_name(r) for r in EXTRAS[extra]}
    available = {DIST_TO_IMPORTS.get(n, {n}).pop() for n in available}

    missing = {i for i in _module_scope_imports(path) if i not in available}
    assert not missing, (
        f"`{script}` imports {sorted(missing)} at module scope but they are not in "
        f"dependencies or its extras; a plain install would crash on startup."
    )


def test_core_has_no_required_dependencies():
    """The zero-dependency promise is a feature; keep CI honest about it."""
    assert BASE == [], f"base dependencies reintroduced: {BASE}"


def test_core_modules_import_without_any_package():
    """Nothing in the core may import a third-party package at module scope."""
    for path in sorted(SRC.glob("*.py")):
        if path.name == "mcp_server.py":
            continue
        assert _module_scope_imports(path) == set(), (
            f"{path.name} imports third-party code at module scope, which breaks "
            "the zero-dependency CLI promise"
        )


def test_scripts_are_all_covered_by_the_contract():
    declared = set(re.findall(r"^(\w[\w-]*)\s*=\s*\"pcaplens\.",
                              PYPROJECT.read_text(encoding="utf-8"), re.M))
    assert declared == set(SCRIPT_EXTRAS), f"update SCRIPT_EXTRAS for {sorted(declared)}"


def test_version_matches_the_package():
    import pcaplens

    declared = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(encoding="utf-8"), re.M)
    assert declared, "no version in pyproject.toml"
    assert declared.group(1) == pcaplens.__version__, "bump both or neither"
