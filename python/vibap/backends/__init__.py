"""Concrete PolicyBackend implementations.

Optional backends remain importable only when their runtime dependencies are
available. NativeBackend is always importable.
"""

from vibap.backends.forbid_rules import (
    ForbidRulesBackend,
    register as register_forbid_rules,
)
from vibap.backends.native import NativeBackend

__all__ = [
    "ForbidRulesBackend",
    "NativeBackend",
    "register_forbid_rules",
]

try:
    from vibap.backends.cedar import CedarBackend, register as register_cedar
except ModuleNotFoundError as exc:  # pragma: no cover - dependency-gated import
    CedarBackend = None  # type: ignore[assignment]

    def register_cedar(_missing: ModuleNotFoundError = exc) -> None:
        raise RuntimeError("cedar backend unavailable: missing optional dependency") from _missing
else:
    __all__.extend(["CedarBackend", "register_cedar"])
