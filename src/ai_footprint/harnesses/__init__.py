"""Supported harnesses, found by scanning this package.

A harness is a subpackage that ships ``profile.toml`` and exposes ``HARNESS``. Nothing
outside this package names a tool: the audit, the checks and the reports iterate the
registry, so adding a subpackage is all it takes to support a new tool.
"""

import importlib
import pkgutil
from functools import cache

from ai_footprint.harnesses.base import Harness


class RegistryError(RuntimeError):
    """Raised when a harness package does not follow the contract."""


@cache
def registry() -> dict[str, Harness]:
    """Every harness by name, in name order.

    Raises:
        RegistryError: A subpackage has no ``HARNESS`` or its name differs from the package.
    """
    found: dict[str, Harness] = {}
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
        if not info.ispkg:
            continue
        module = importlib.import_module(f"{__name__}.{info.name}")
        harness = getattr(module, "HARNESS", None)
        if not isinstance(harness, Harness):
            raise RegistryError(f"{module.__name__} must define HARNESS = Harness(...)")
        if harness.name != info.name:
            raise RegistryError(f"{module.__name__}: HARNESS.name is {harness.name!r}")
        found[harness.name] = harness
    return found


def get(name: str) -> Harness | None:
    """The harness called ``name``, or None for a name no harness has."""
    return registry().get(name)
