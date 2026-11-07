"""The layering that lets a new harness need no change outside its own package."""

import ast
from pathlib import Path

import pytest

from ai_footprint.harnesses import registry

SRC = Path(__file__).parent.parent / "src" / "ai_footprint"


def _modules(*parts: str) -> list[Path]:
    return sorted((SRC.joinpath(*parts)).rglob("*.py"))


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
    return found


def _outside_harnesses() -> list[Path]:
    return [p for p in _modules() if "harnesses" not in p.relative_to(SRC).parts]


def test_no_module_outside_harnesses_names_a_tool():
    names = set(registry())
    offenders = [
        f"{path.relative_to(SRC)}:{node.lineno} {node.value!r}"
        for path in _outside_harnesses()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Constant) and node.value in names
    ]
    assert offenders == []


def test_no_module_outside_harnesses_imports_a_specific_harness():
    names = set(registry())
    offenders = [
        f"{path.relative_to(SRC)} imports {module}"
        for path in _outside_harnesses()
        for module in _imports(path)
        if module.startswith("ai_footprint.harnesses.") and module.split(".")[2] in names
    ]
    assert offenders == []


@pytest.mark.parametrize(
    ("layer", "forbidden"),
    [
        ("reporting", "ai_footprint.harnesses"),
        ("checks", "ai_footprint.reporting"),
        ("harnesses", "ai_footprint.checks"),
        ("harnesses", "ai_footprint.reporting"),
    ],
)
def test_layers_import_only_downward(layer: str, forbidden: str):
    offenders = [
        f"{path.relative_to(SRC)} imports {module}"
        for path in _modules(layer)
        for module in _imports(path)
        if module == forbidden or module.startswith(f"{forbidden}.")
    ]
    assert offenders == []
