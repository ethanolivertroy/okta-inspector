"""Framework analyzer registry."""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from okta_inspector.analyzers.base import FrameworkAnalyzer

_ANALYZER_REGISTRY: dict[str, type[FrameworkAnalyzer]] = {}
_modules_loaded = False


def register_analyzer(cls: type[FrameworkAnalyzer]) -> type[FrameworkAnalyzer]:
    """Class decorator that auto-registers a framework analyzer."""
    _ANALYZER_REGISTRY[cls.name] = cls
    return cls


def _ensure_loaded() -> None:
    """Auto-import all sibling modules so @register_analyzer fires."""
    global _modules_loaded
    if _modules_loaded:
        return
    _modules_loaded = True
    package = importlib.import_module(__name__)
    for info in pkgutil.iter_modules(package.__path__):
        if info.name not in ("base", "common"):
            importlib.import_module(f"{__name__}.{info.name}")


def get_analyzers(names: list[str] | None = None) -> list[FrameworkAnalyzer]:
    """Instantiate analyzers.  Pass *names* to select a subset."""
    _ensure_loaded()
    if names is None:
        return [cls() for cls in _ANALYZER_REGISTRY.values()]
    return [_ANALYZER_REGISTRY[n]() for n in names if n in _ANALYZER_REGISTRY]


def available_frameworks() -> list[str]:
    """Return sorted list of registered framework names."""
    _ensure_loaded()
    return sorted(_ANALYZER_REGISTRY.keys())
